#include "b64_simd.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <omp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define PARALLEL_THRESHOLD (512ULL * 1024)
#define MAX_OMP_THREADS 8
#define STREAM_CHUNK (192ULL * 1024) /* multiple of 3 and 4 */

static int get_omp_threads(void) {
    int n = omp_get_max_threads();
    return n > MAX_OMP_THREADS ? MAX_OMP_THREADS : n;
}

static void write_all_fd(int fd, const char *buf, usize len) {
    usize off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("base64: write error");
            exit(1);
        }
        off += (usize)n;
    }
}

static void write_wrapped_fd(int fd, const char *b64, usize len, usize wrap,
                             usize *col) {
    if (len == 0) {
        return;
    }
    if (wrap == 0) {
        write_all_fd(fd, b64, len);
        return;
    }

    char out_buf[256 * 1024];
    usize out_pos = 0;
    usize i = 0;
    while (i < len) {
        usize avail = wrap - *col;
        usize take = len - i;
        if (take > avail) {
            take = avail;
        }
        if (out_pos + take + 1 > sizeof(out_buf)) {
            write_all_fd(fd, out_buf, out_pos);
            out_pos = 0;
        }
        if (take > sizeof(out_buf) - 1) {
            write_all_fd(fd, b64 + i, take);
        } else {
            memcpy(out_buf + out_pos, b64 + i, take);
            out_pos += take;
        }
        i += take;
        *col += take;
        if (*col == wrap) {
            out_buf[out_pos++] = '\n';
            *col = 0;
        }
    }
    if (out_pos > 0) {
        write_all_fd(fd, out_buf, out_pos);
    }
}

static void encode_stream(FILE *in, int out_fd, usize wrap) {
    char *in_buf = (char *)malloc(STREAM_CHUNK);
    char *b64_buf = (char *)malloc((STREAM_CHUNK / 3) * 4);
    if (!in_buf || !b64_buf) {
        perror("base64: memory exhausted");
        exit(1);
    }

    usize col = 0;
    usize carry = 0;
    bool any_output = false;

    for (;;) {
        usize n = fread(in_buf + carry, 1, STREAM_CHUNK - carry, in);
        usize total = carry + n;
        if (total == 0) {
            break;
        }

        if (feof(in)) {
            usize out_len = ((total + 2) / 3) * 4;
            b64_enc_range(in_buf, b64_buf, total);
            write_wrapped_fd(out_fd, b64_buf, out_len, wrap, &col);
            any_output = true;
            break;
        }

        usize full = (total / 3) * 3;
        if (full > 0) {
            b64_enc_range(in_buf, b64_buf, full);
            write_wrapped_fd(out_fd, b64_buf, (full / 3) * 4, wrap, &col);
            any_output = true;
        }
        carry = total - full;
        if (carry > 0) {
            memmove(in_buf, in_buf + full, carry);
        }
        if (ferror(in)) {
            perror("base64: read error");
            exit(1);
        }
    }

    if (wrap > 0 && any_output && col > 0) {
        write_all_fd(out_fd, "\n", 1);
    }

    free(in_buf);
    free(b64_buf);
}

static void encode_mmap(const char *in_map, usize file_size, int out_fd,
                        bool out_mmap, usize wrap) {
    usize raw_b64_len = ((file_size + 2) / 3) * 4;

    if (out_mmap && wrap == 0) {
        if (ftruncate(out_fd, (off_t)raw_b64_len) != 0) {
            perror("base64: ftruncate error");
            exit(1);
        }
        char *out_map = (char *)mmap(NULL, raw_b64_len, PROT_READ | PROT_WRITE,
                                     MAP_SHARED, out_fd, 0);
        if (out_map != MAP_FAILED) {
            const usize chunk = 24ULL * 1024;
            usize nchunks = (file_size + chunk - 1) / chunk;
            int nthreads = get_omp_threads();

#pragma omp parallel for schedule(static) num_threads(nthreads)
            for (usize c = 0; c < nchunks; ++c) {
                usize start = c * chunk;
                usize len = file_size - start;
                if (len > chunk) {
                    len = chunk;
                }
                b64_enc_range(in_map + start, out_map + (start / 3) * 4, len);
            }
            munmap(out_map, raw_b64_len);
            return;
        }
    }

    char *out_buf = (char *)malloc(raw_b64_len);
    if (!out_buf) {
        perror("base64: memory exhausted");
        exit(1);
    }

    const usize chunk = 24ULL * 1024;
    usize nchunks = (file_size + chunk - 1) / chunk;
    int nthreads = get_omp_threads();

#pragma omp parallel for schedule(static) num_threads(nthreads)
    for (usize c = 0; c < nchunks; ++c) {
        usize start = c * chunk;
        usize len = file_size - start;
        if (len > chunk) {
            len = chunk;
        }
        b64_enc_range(in_map + start, out_buf + (start / 3) * 4, len);
    }

    usize col = 0;
    write_wrapped_fd(out_fd, out_buf, raw_b64_len, wrap, &col);
    if (wrap > 0 && raw_b64_len > 0 && col > 0) {
        write_all_fd(out_fd, "\n", 1);
    }

    free(out_buf);
}

static void decode_tail_or_die(const char *q, usize len, bool require_canon_pad,
                               int out_fd, char *out, usize *out_len) {
    if (len == 0) {
        *out_len = 0;
        return;
    }
    if (len == 1) {
        fprintf(stderr, "base64: invalid input\n");
        exit(1);
    }
    u8 d[4] = {0, 0, 0, 0};
    u32 val = 0;
    for (usize k = 0; k < len; ++k) {
        u8 c = (u8)q[k];
        d[k] = (c < 128) ? b64_dec_lut[c] : 0xFF;
        if (d[k] == 0xFF) {
            fprintf(stderr, "base64: invalid input\n");
            exit(1);
        }
        val = (val << 6) | d[k];
    }
    if (len == 2) {
        out[0] = (char)(val >> 4);
        *out_len = 1;
        if (require_canon_pad && (d[1] & 0x0F) != 0) {
            write_all_fd(out_fd, out, 1);
            fprintf(stderr, "base64: invalid input\n");
            exit(1);
        }
    } else if (len == 3) {
        out[0] = (char)(val >> 10);
        out[1] = (char)(val >> 2);
        *out_len = 2;
        if (require_canon_pad && (d[2] & 0x03) != 0) {
            write_all_fd(out_fd, out, 2);
            fprintf(stderr, "base64: invalid input\n");
            exit(1);
        }
    } else {
        out[0] = (char)(val >> 16);
        out[1] = (char)(val >> 8);
        out[2] = (char)(val);
        *out_len = 3;
    }
}

static void flush_clean_and_tail(char *clean_buf, usize *clean_len, int out_fd,
                                 char *out_buf, bool require_canon_pad) {
    usize full = (*clean_len / 4) * 4;
    if (full > 0) {
        if (b64_dec_clean_range(clean_buf, out_buf, full) != 0) {
            fprintf(stderr, "base64: invalid input\n");
            exit(1);
        }
        write_all_fd(out_fd, out_buf, (full / 4) * 3);
    }
    usize rem = *clean_len - full;
    if (rem > 0) {
        usize tail_out = 0;
        decode_tail_or_die(clean_buf + full, rem, require_canon_pad, out_fd,
                           out_buf, &tail_out);
        if (tail_out > 0) {
            write_all_fd(out_fd, out_buf, tail_out);
        }
    }
    *clean_len = 0;
}

static void decode_stream(FILE *in, int out_fd, bool ignore_garbage) {
    char *raw_buf = (char *)malloc(STREAM_CHUNK);
    char *clean_buf = (char *)malloc(STREAM_CHUNK + 4);
    char *out_buf = (char *)malloc((STREAM_CHUNK / 4) * 3 + 4);
    if (!raw_buf || !clean_buf || !out_buf) {
        perror("base64: memory exhausted");
        exit(1);
    }

    usize clean_len = 0;
    bool need_eq2 = false;

    for (;;) {
        usize n = fread(raw_buf, 1, STREAM_CHUNK, in);
        if (n == 0) {
            if (ferror(in)) {
                perror("base64: read error");
                exit(1);
            }
            break;
        }

        for (usize i = 0; i < n; ++i) {
            u8 c = (u8)raw_buf[i];
            if (c == '\n') {
                continue;
            }
            if (need_eq2) {
                if (c == '=') {
                    need_eq2 = false;
                    flush_clean_and_tail(clean_buf, &clean_len, out_fd, out_buf,
                                         !ignore_garbage);
                    continue;
                }
                if (ignore_garbage) {
                    continue;
                }
                flush_clean_and_tail(clean_buf, &clean_len, out_fd, out_buf, false);
                fprintf(stderr, "base64: invalid input\n");
                exit(1);
            }
            if (c == '=') {
                usize qpos = clean_len % 4;
                if (qpos == 2) {
                    need_eq2 = true;
                    continue;
                }
                if (qpos == 3) {
                    flush_clean_and_tail(clean_buf, &clean_len, out_fd, out_buf,
                                         !ignore_garbage);
                    continue;
                }
                if (ignore_garbage) {
                    continue;
                }
                flush_clean_and_tail(clean_buf, &clean_len, out_fd, out_buf, false);
                fprintf(stderr, "base64: invalid input\n");
                exit(1);
            }
            if (c >= 128 || b64_dec_lut[c] == 0xFF) {
                if (ignore_garbage) {
                    continue;
                }
                flush_clean_and_tail(clean_buf, &clean_len, out_fd, out_buf, false);
                fprintf(stderr, "base64: invalid input\n");
                exit(1);
            }
            clean_buf[clean_len++] = (char)c;
            if (clean_len >= STREAM_CHUNK) {
                usize full = (clean_len / 4) * 4;
                if (b64_dec_clean_range(clean_buf, out_buf, full) != 0) {
                    fprintf(stderr, "base64: invalid input\n");
                    exit(1);
                }
                write_all_fd(out_fd, out_buf, (full / 4) * 3);
                clean_len -= full;
                if (clean_len > 0) {
                    memmove(clean_buf, clean_buf + full, clean_len);
                }
            }
        }
    }

    if (need_eq2) {
        flush_clean_and_tail(clean_buf, &clean_len, out_fd, out_buf, false);
        if (!ignore_garbage) {
            fprintf(stderr, "base64: invalid input\n");
            exit(1);
        }
    } else if (clean_len > 0) {
        flush_clean_and_tail(clean_buf, &clean_len, out_fd, out_buf, false);
    }

    free(raw_buf);
    free(clean_buf);
    free(out_buf);
}

static bool decode_mmap_fast(const char *in_map, usize file_size, int out_fd,
                             bool out_mmap) {
    if (file_size % 4 != 0) {
        return false;
    }

    usize pad = 0;
    usize eff = file_size;
    while (eff > 0 && pad < 2 && in_map[eff - 1] == '=') {
        pad++;
        eff--;
    }
    usize full_in = (eff / 4) * 4;
    usize out_size = (file_size / 4) * 3 - pad;

    char *out_buf = NULL;
    bool mapped_out = false;
    if (out_mmap && out_size > 0) {
        if (ftruncate(out_fd, (off_t)out_size) != 0) {
            perror("base64: ftruncate error");
            exit(1);
        }
        out_buf = (char *)mmap(NULL, out_size, PROT_READ | PROT_WRITE,
                               MAP_SHARED, out_fd, 0);
        if (out_buf != MAP_FAILED) {
            mapped_out = true;
        } else {
            out_buf = NULL;
        }
    }
    if (!out_buf) {
        out_buf = (char *)malloc(out_size > 0 ? out_size : 1);
        if (!out_buf) {
            perror("base64: memory exhausted");
            exit(1);
        }
    }

    const usize chunk = 32ULL * 1024;
    usize nchunks = (full_in + chunk - 1) / chunk;
    int nthreads = get_omp_threads();
    int err_flag = 0;

#pragma omp parallel for schedule(static) num_threads(nthreads) reduction(| : err_flag)
    for (usize c = 0; c < nchunks; ++c) {
        usize start = c * chunk;
        usize len = full_in - start;
        if (len > chunk) {
            len = chunk;
        }
        if (b64_dec_clean_range(in_map + start, out_buf + (start / 4) * 3, len) != 0) {
            err_flag = 1;
        }
    }

    if (err_flag) {
        if (mapped_out) {
            munmap(out_buf, out_size);
        } else {
            free(out_buf);
        }
        return false;
    }

    if (pad > 0) {
        usize tail_out = 0;
        decode_tail_or_die(in_map + full_in, eff - full_in, true, out_fd,
                           out_buf + (full_in / 4) * 3, &tail_out);
    }

    if (mapped_out) {
        munmap(out_buf, out_size);
    } else {
        write_all_fd(out_fd, out_buf, out_size);
        free(out_buf);
    }
    return true;
}

static void print_usage(int status) {
    FILE *out = (status == 0) ? stdout : stderr;
    if (status != 0) {
        fprintf(out, "Try 'base64 --help' for more information.\n");
        exit(status);
    }
    fputs("Usage: base64 [OPTION]... [FILE]\n"
          "Base64 encode or decode FILE, or standard input, to standard output.\n\n"
          "With no FILE, or when FILE is -, read standard input.\n\n"
          "  -d, --decode          decode data\n"
          "  -f, --file=FILE       write output directly to FILE (enables mmap)\n"
          "  -i, --ignore-garbage  when decoding, ignore non-alphabet characters\n"
          "  -w, --wrap=COLS       wrap encoded lines after COLS character (default 76).\n"
          "                          Use 0 to disable line wrapping\n"
          "      --help     display this help and exit\n"
          "      --version  output version information and exit\n",
          out);
    exit(0);
}

int main(int argc, char *argv[]) {
    bool decode = false;
    bool ignore_garbage = false;
    usize wrap = 76;
    const char *outfile = NULL;

    enum { HELP_OPT = 128, VERSION_OPT };
    static const struct option long_opts[] = {
        {"decode", no_argument, NULL, 'd'},
        {"file", required_argument, NULL, 'f'},
        {"ignore-garbage", no_argument, NULL, 'i'},
        {"wrap", required_argument, NULL, 'w'},
        {"help", no_argument, NULL, HELP_OPT},
        {"version", no_argument, NULL, VERSION_OPT},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "df:iw:", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'd':
            decode = true;
            break;
        case 'f':
            outfile = optarg;
            break;
        case 'i':
            ignore_garbage = true;
            break;
        case 'w': {
            char *end = NULL;
            errno = 0;
            unsigned long long val = strtoull(optarg, &end, 10);
            if (errno != 0 || end == optarg || *end != '\0' || optarg[0] == '-') {
                fprintf(stderr, "base64: invalid wrap size: '%s'\n", optarg);
                return 1;
            }
            wrap = (usize)val;
            break;
        }
        case HELP_OPT:
            print_usage(0);
            break;
        case VERSION_OPT:
            puts("base64 (fast_base64) 1.0");
            return 0;
        default:
            print_usage(1);
        }
    }

    const char *infile = NULL;
    if (optind < argc) {
        if (optind + 1 < argc) {
            fprintf(stderr, "base64: extra operand '%s'\n", argv[optind + 1]);
            print_usage(1);
        }
        infile = argv[optind];
    }

    int out_fd = STDOUT_FILENO;
    bool out_mmap = false;
    if (outfile) {
        out_fd = open(outfile, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (out_fd < 0) {
            fprintf(stderr, "base64: %s: %s\n", outfile, strerror(errno));
            return 1;
        }
        out_mmap = true;
    }

    if (!infile || strcmp(infile, "-") == 0) {
        if (decode) {
            decode_stream(stdin, out_fd, ignore_garbage);
        } else {
            encode_stream(stdin, out_fd, wrap);
        }
        if (outfile) {
            close(out_fd);
        }
        return 0;
    }

    int fd = open(infile, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "base64: %s: %s\n", infile, strerror(errno));
        if (outfile) {
            close(out_fd);
        }
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        (usize)st.st_size >= PARALLEL_THRESHOLD) {
        usize fsize = (usize)st.st_size;
        char *in_map = (char *)mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
        if (in_map != MAP_FAILED) {
            posix_madvise(in_map, fsize, POSIX_MADV_SEQUENTIAL);
            if (decode) {
                if (ignore_garbage ||
                    !decode_mmap_fast(in_map, fsize, out_fd, out_mmap)) {
                    munmap(in_map, fsize);
                    FILE *f = fdopen(fd, "rb");
                    if (!f) {
                        perror("base64");
                        close(fd);
                        if (outfile) close(out_fd);
                        return 1;
                    }
                    decode_stream(f, out_fd, ignore_garbage);
                    fclose(f);
                    if (outfile) close(out_fd);
                    return 0;
                }
            } else {
                encode_mmap(in_map, fsize, out_fd, out_mmap, wrap);
            }
            munmap(in_map, fsize);
            close(fd);
            if (outfile) {
                close(out_fd);
            }
            return 0;
        }
    }

    FILE *f = fdopen(fd, "rb");
    if (!f) {
        perror("base64");
        close(fd);
        if (outfile) {
            close(out_fd);
        }
        return 1;
    }
    if (decode) {
        decode_stream(f, out_fd, ignore_garbage);
    } else {
        encode_stream(f, out_fd, wrap);
    }
    fclose(f);
    if (outfile) {
        close(out_fd);
    }
    return 0;
}

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef uint8_t u8;
typedef int8_t i8;
typedef size_t usize;
typedef uint16_t u16;
typedef uint32_t u32;

static const char b64_enc_lut[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
};

static const u8 b64_dec_lut[128] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 62,   0xFF, 0xFF, 0xFF, 63,
    52,   53,   54,   55,   56,   57,   58,   59,   60,   61,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,
    7,    8,    9,    10,   11,   12,   13,   14,   15,   16,   17,   18,
    19,   20,   21,   22,   23,   24,   25,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 26,   27,   28,   29,   30,   31,   32,   33,   34,   35,   36,
    37,   38,   39,   40,   41,   42,   43,   44,   45,   46,   47,   48,
    49,   50,   51,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static inline void enc_pack_u32(const unsigned char *p, char *out) {
    u32 val = ((u32)p[0] << 16) | ((u32)p[1] << 8) | (u32)p[2];
    u32 packed = ((u32)(u8)b64_enc_lut[(val >> 18) & 0x3F]) |
                 ((u32)(u8)b64_enc_lut[(val >> 12) & 0x3F] << 8) |
                 ((u32)(u8)b64_enc_lut[(val >> 6) & 0x3F] << 16) |
                 ((u32)(u8)b64_enc_lut[val & 0x3F] << 24);
    memcpy(out, &packed, 4);
}

#if defined(__AVX2__)
#include <immintrin.h>
#define B64_SIMD_ENC_IN 24
#define B64_SIMD_ENC_LOAD 28
#define B64_SIMD_DEC_IN 32

static inline void b64_enc_simd_block(const char *in, char *out) {
    const __m128i lo128 = _mm_loadu_si128((const __m128i *)in);
    const __m128i hi128 = _mm_loadu_si128((const __m128i *)(in + 12));
    __m256i v = _mm256_set_m128i(hi128, lo128);

    const __m256i shuf = _mm256_set_epi8(
        10, 11, 9, 10, 7, 8, 6, 7, 4, 5, 3, 4, 1, 2, 0, 1,
        10, 11, 9, 10, 7, 8, 6, 7, 4, 5, 3, 4, 1, 2, 0, 1);
    v = _mm256_shuffle_epi8(v, shuf);

    const __m256i t0 = _mm256_and_si256(v, _mm256_set1_epi32(0x0FC0FC00));
    const __m256i t1 = _mm256_mulhi_epu16(t0, _mm256_set1_epi32(0x04000040));
    const __m256i t2 = _mm256_and_si256(v, _mm256_set1_epi32(0x003F03F0));
    const __m256i t3 = _mm256_mullo_epi16(t2, _mm256_set1_epi32(0x01000010));
    const __m256i idx = _mm256_or_si256(t1, t3);

    __m256i res = _mm256_subs_epu8(idx, _mm256_set1_epi8(51));
    const __m256i less = _mm256_and_si256(
        _mm256_cmpgt_epi8(_mm256_set1_epi8(26), idx), _mm256_set1_epi8(13));
    res = _mm256_add_epi8(res, less);

    const __m256i offsets = _mm256_setr_epi8(
        71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -19, -16, 65, 0, 0,
        71, -4, -4, -4, -4, -4, -4, -4, -4, -4, -4, -19, -16, 65, 0, 0);
    const __m256i ascii =
        _mm256_add_epi8(idx, _mm256_shuffle_epi8(offsets, res));

    _mm256_storeu_si256((__m256i *)out, ascii);
}

static inline int b64_dec_simd_block(const char *in, char *out) {
    const __m256i v = _mm256_loadu_si256((const __m256i *)in);

    /* Validate all 32 bytes are in [A-Za-z0-9+/] (Muła/Lemire nibble check) */
    const __m256i hi =
        _mm256_and_si256(_mm256_srli_epi32(v, 4), _mm256_set1_epi8(0x0F));
    const __m256i lo = _mm256_and_si256(v, _mm256_set1_epi8(0x0F));

    const __m256i lo_lut = _mm256_setr_epi8(
        0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x13, 0x1A, 0x1B, 0x1B, 0x1B, 0x1A,
        0x15, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x13, 0x1A, 0x1B, 0x1B, 0x1B, 0x1A);
    const __m256i hi_lut = _mm256_setr_epi8(
        0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
        0x10, 0x10, 0x01, 0x02, 0x04, 0x08, 0x04, 0x08,
        0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10);
    const __m256i eq2f = _mm256_cmpeq_epi8(v, _mm256_set1_epi8(0x2F));
    const __m256i m0 = _mm256_shuffle_epi8(lo_lut, lo);
    const __m256i m1 = _mm256_shuffle_epi8(
        hi_lut, _mm256_add_epi8(hi, _mm256_and_si256(
                                        _mm256_cmpgt_epi8(_mm256_set1_epi8(0x20), v),
                                        _mm256_set1_epi8(8))));
    /* Non-ASCII (>= 0x80) has sign bit set: catch via v < 0 */
    const __m256i non_ascii = _mm256_cmpgt_epi8(_mm256_setzero_si256(), v);
    const __m256i invalid = _mm256_or_si256(
        non_ascii, _mm256_and_si256(_mm256_andnot_si256(eq2f, m0), m1));
    /* Wait: for 0x2F ('/'), eq2f is 0xFF, so andnot clears m0 -> valid;
       for 0x2B ('+'), lo=0xB -> 0x1A & hi=2 -> 0x01 == 0 -> valid!
       Let's verify 0x2E ('.'): lo=0xE -> 0x1B & hi=2 -> 0x01 != 0 -> invalid!
       For 0x20..0x2A: lo=0 -> 0x15 & 0x01 != 0; lo=1..9 -> 0x11 & 0x01 != 0; lo=A -> 0x13 & 0x01 != 0 -> invalid! */
    if (_mm256_movemask_epi8(invalid) != 0) {
        return -1;
    }

    const __m256i shift_lut = _mm256_setr_epi8(
        0, 0, 19, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 19, 4, -65, -65, -71, -71, 0, 0, 0, 0, 0, 0, 0, 0);
    __m256i shift = _mm256_shuffle_epi8(shift_lut, hi);
    shift = _mm256_add_epi8(shift, _mm256_and_si256(eq2f, _mm256_set1_epi8(-3)));

    const __m256i vals = _mm256_add_epi8(v, shift);
    const __m256i merged = _mm256_maddubs_epi16(vals, _mm256_set1_epi32(0x01400140));
    const __m256i packed = _mm256_madd_epi16(merged, _mm256_set1_epi32(0x00011000));

    const __m256i pack_shuf = _mm256_setr_epi8(
        2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1,
        2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1);
    const __m256i bytes = _mm256_shuffle_epi8(packed, pack_shuf);

    const __m128i lo128 = _mm256_castsi256_si128(bytes);
    const __m128i hi128 = _mm256_extracti128_si256(bytes, 1);
    _mm_storel_epi64((__m128i *)out, lo128);
    u32 lo_tail = (u32)_mm_extract_epi32(lo128, 2);
    memcpy(out + 8, &lo_tail, 4);
    _mm_storel_epi64((__m128i *)(out + 12), hi128);
    u32 hi_tail = (u32)_mm_extract_epi32(hi128, 2);
    memcpy(out + 20, &hi_tail, 4);
    return 0;
}

#elif defined(__aarch64__) && defined(__ARM_NEON)
#include <arm_neon.h>
#define B64_SIMD_ENC_IN 48
#define B64_SIMD_ENC_LOAD 48
#define B64_SIMD_DEC_IN 64

static inline void b64_enc_simd_block(const char *in, char *out) {
    uint8x16x3_t raw = vld3q_u8((const uint8_t *)in);
    uint8x16_t i0 = vshrq_n_u8(raw.val[0], 2);
    uint8x16_t i1 = vandq_u8(
        vorrq_u8(vshlq_n_u8(raw.val[0], 4), vshrq_n_u8(raw.val[1], 4)),
        vdupq_n_u8(0x3F));
    uint8x16_t i2 = vandq_u8(
        vorrq_u8(vshlq_n_u8(raw.val[1], 2), vshrq_n_u8(raw.val[2], 6)),
        vdupq_n_u8(0x3F));
    uint8x16_t i3 = vandq_u8(raw.val[2], vdupq_n_u8(0x3F));

    uint8x16x4_t lut = vld1q_u8_x4((const uint8_t *)b64_enc_lut);
    uint8x16x4_t enc;
    enc.val[0] = vqtbl4q_u8(lut, i0);
    enc.val[1] = vqtbl4q_u8(lut, i1);
    enc.val[2] = vqtbl4q_u8(lut, i2);
    enc.val[3] = vqtbl4q_u8(lut, i3);
    vst4q_u8((uint8_t *)out, enc);
}

static inline int b64_dec_simd_block(const char *in, char *out) {
    uint8x16x4_t enc = vld4q_u8((const uint8_t *)in);
    uint8x16_t v0 = enc.val[0], v1 = enc.val[1], v2 = enc.val[2], v3 = enc.val[3];
    /* Validate ASCII < 128 */
    uint8x16_t any_hi = vorrq_u8(vorrq_u8(v0, v1), vorrq_u8(v2, v3));
    if (vmaxvq_u8(any_hi) >= 128) {
        return -1;
    }
    uint8x16x4_t lut_lo = vld1q_u8_x4(b64_dec_lut);
    uint8x16x4_t lut_hi = vld1q_u8_x4(b64_dec_lut + 64);
    uint8x16_t o64 = vdupq_n_u8(64);
    uint8x16_t d0 = vorrq_u8(vqtbl4q_u8(lut_lo, v0), vqtbl4q_u8(lut_hi, vsubq_u8(v0, o64)));
    uint8x16_t d1 = vorrq_u8(vqtbl4q_u8(lut_lo, v1), vqtbl4q_u8(lut_hi, vsubq_u8(v1, o64)));
    uint8x16_t d2 = vorrq_u8(vqtbl4q_u8(lut_lo, v2), vqtbl4q_u8(lut_hi, vsubq_u8(v2, o64)));
    uint8x16_t d3 = vorrq_u8(vqtbl4q_u8(lut_lo, v3), vqtbl4q_u8(lut_hi, vsubq_u8(v3, o64)));
    uint8x16_t any_inv = vorrq_u8(vorrq_u8(d0, d1), vorrq_u8(d2, d3));
    if (vmaxvq_u8(any_inv) >= 64) {
        return -1;
    }
    uint8x16x3_t raw;
    raw.val[0] = vorrq_u8(vshlq_n_u8(d0, 2), vshrq_n_u8(d1, 4));
    raw.val[1] = vorrq_u8(vshlq_n_u8(d1, 4), vshrq_n_u8(d2, 2));
    raw.val[2] = vorrq_u8(vshlq_n_u8(d2, 6), d3);
    vst3q_u8((uint8_t *)out, raw);
    return 0;
}

#elif defined(__ALTIVEC__) && defined(__VSX__)
#include <altivec.h>
#define B64_SIMD_ENC_IN 12
#define B64_SIMD_ENC_LOAD 16

static inline void b64_enc_simd_block(const char *in, char *out) {
    vector unsigned char v = vec_vsx_ld(0, (const unsigned char *)in);
    const vector unsigned char shuf = {
        1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11, 10};
    v = vec_perm(v, v, shuf);
    const vector unsigned int w = (vector unsigned int)v;
    const vector unsigned int mask0 = vec_splats((unsigned int)0x0FC0FC00u);
    const vector unsigned int mask1 = vec_splats((unsigned int)0x003F03F0u);
    const vector unsigned short s0 = (vector unsigned short)vec_and(w, mask0);
    const vector unsigned short s1 = (vector unsigned short)vec_and(w, mask1);
    const vector unsigned short sh_r = {10, 6, 10, 6, 10, 6, 10, 6};
    const vector unsigned short sh_l = {4, 8, 4, 8, 4, 8, 4, 8};
    const vector unsigned char idx =
        (vector unsigned char)vec_or(vec_sr(s0, sh_r), vec_sl(s1, sh_l));

    const vector unsigned char c26 = vec_splats((unsigned char)26);
    const vector unsigned char c52 = vec_splats((unsigned char)52);
    const vector unsigned char c62 = vec_splats((unsigned char)62);
    const vector unsigned char c63 = vec_splats((unsigned char)63);
    vector unsigned char ascii = vec_add(idx, vec_splats((unsigned char)71));
    ascii = vec_sel(ascii, vec_add(idx, vec_splats((unsigned char)65)),
                    vec_cmplt(idx, c26));
    ascii = vec_sel(ascii, vec_sub(idx, vec_splats((unsigned char)4)),
                    vec_cmpge(idx, c52));
    ascii = vec_sel(ascii, vec_splats((unsigned char)'+'), vec_cmpeq(idx, c62));
    ascii = vec_sel(ascii, vec_splats((unsigned char)'/'), vec_cmpeq(idx, c63));
    vec_vsx_st(ascii, 0, (unsigned char *)out);
}

#elif defined(__riscv_vector)
#include <riscv_vector.h>
#define B64_SIMD_RVV 1

static inline usize b64_enc_rvv(const char *in, char *out, usize groups) {
    usize done = 0;
    while (done < groups) {
        size_t vl = __riscv_vsetvl_e8m1(groups - done);
        vuint8m1x3_t raw = __riscv_vlseg3e8_v_u8m1x3(
            (const uint8_t *)(in + done * 3), vl);
        vuint8m1_t b0 = __riscv_vget_v_u8m1x3_u8m1(raw, 0);
        vuint8m1_t b1 = __riscv_vget_v_u8m1x3_u8m1(raw, 1);
        vuint8m1_t b2 = __riscv_vget_v_u8m1x3_u8m1(raw, 2);

        vuint8m1_t i0 = __riscv_vsrl_vx_u8m1(b0, 2, vl);
        vuint8m1_t i1 = __riscv_vand_vx_u8m1(
            __riscv_vor_vv_u8m1(__riscv_vsll_vx_u8m1(b0, 4, vl),
                                __riscv_vsrl_vx_u8m1(b1, 4, vl), vl),
            0x3F, vl);
        vuint8m1_t i2 = __riscv_vand_vx_u8m1(
            __riscv_vor_vv_u8m1(__riscv_vsll_vx_u8m1(b1, 2, vl),
                                __riscv_vsrl_vx_u8m1(b2, 6, vl), vl),
            0x3F, vl);
        vuint8m1_t i3 = __riscv_vand_vx_u8m1(b2, 0x3F, vl);

        vuint8m1_t lut = __riscv_vle8_v_u8m1((const uint8_t *)b64_enc_lut, 64);
        vuint8m1_t e0 = __riscv_vrgather_vv_u8m1(lut, i0, vl);
        vuint8m1_t e1 = __riscv_vrgather_vv_u8m1(lut, i1, vl);
        vuint8m1_t e2 = __riscv_vrgather_vv_u8m1(lut, i2, vl);
        vuint8m1_t e3 = __riscv_vrgather_vv_u8m1(lut, i3, vl);

        vuint8m1x4_t enc = __riscv_vcreate_v_u8m1x4(e0, e1, e2, e3);
        __riscv_vsseg4e8_v_u8m1x4((uint8_t *)(out + done * 4), enc, vl);
        done += vl;
    }
    return done * 3;
}
#endif

static inline void b64_enc_range(const char *in, char *out, usize inSize) {
    const unsigned char *p = (const unsigned char *)in;
    usize i = 0;

#ifdef B64_SIMD_ENC_IN
    for (; i + B64_SIMD_ENC_LOAD <= inSize; i += B64_SIMD_ENC_IN) {
        b64_enc_simd_block(in + i, out + (i / 3) * 4);
    }
#elif defined(B64_SIMD_RVV)
    i = b64_enc_rvv(in, out, inSize / 3);
#endif

    usize limit = (inSize / 3) * 3;
    for (; i < limit; i += 3) {
        enc_pack_u32(p + i, out + (i / 3) * 4);
    }

    usize oi = (limit / 3) * 4;
    usize rem = inSize - limit;
    if (rem == 1) {
        u32 val = (u32)p[limit] << 4;
        out[oi + 0] = b64_enc_lut[(val >> 6) & 0x3F];
        out[oi + 1] = b64_enc_lut[val & 0x3F];
        out[oi + 2] = '=';
        out[oi + 3] = '=';
    } else if (rem == 2) {
        u32 val = ((u32)p[limit] << 10) | ((u32)p[limit + 1] << 2);
        out[oi + 0] = b64_enc_lut[(val >> 12) & 0x3F];
        out[oi + 1] = b64_enc_lut[(val >> 6) & 0x3F];
        out[oi + 2] = b64_enc_lut[val & 0x3F];
        out[oi + 3] = '=';
    }
}

/* Decodes exact multiple-of-4 valid Base64 (no '=' or whitespace inside).
   Returns 0 on success, -1 if an invalid character is encountered. */
static inline int b64_dec_clean_range(const char *in, char *out, usize inSize) {
    usize i = 0;

#ifdef B64_SIMD_DEC_IN
    for (; i + B64_SIMD_DEC_IN <= inSize; i += B64_SIMD_DEC_IN) {
        if (b64_dec_simd_block(in + i, out + (i / 4) * 3) != 0) {
            return -1;
        }
    }
#endif

    for (; i + 4 <= inSize; i += 4) {
        usize oi = (i / 4) * 3;
        u32 val = 0;
        for (usize k = 0; k < 4; ++k) {
            u8 c = (u8)in[i + k];
            if (c >= 128) {
                return -1;
            }
            u8 d = b64_dec_lut[c];
            if (d == 0xFF) {
                return -1;
            }
            val = (val << 6) | d;
        }
        out[oi + 0] = (char)(val >> 16);
        out[oi + 1] = (char)(val >> 8);
        out[oi + 2] = (char)(val);
    }
    return 0;
}

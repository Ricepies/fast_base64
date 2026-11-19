# fast_base64

A GNU-compatible `base64` CLI in C11 with SIMD, OpenMP, and `mmap` acceleration.

## Build

```sh
make
```

## Usage

```sh
./fast_base64 [OPTION]... [FILE]
```

Supports standard GNU `base64` options (`-d`/`--decode`, `-i`/`--ignore-garbage`, `-w`/`--wrap=COLS` defaulting to `76`, `--help`, `--version`, `stdin`/`-`) plus:

- `-f, --file=FILE` — write output directly to `FILE` (enables zero-copy `mmap` output for files $\ge 512\text{ KiB}$)

## Architecture Support

- **x86_64:** AVX2 (`__AVX2__`)
- **ARM64:** NEON (`__aarch64__ && __ARM_NEON`)
- **PPC64LE:** AltiVec/VSX (`__ALTIVEC__ && __VSX__`)
- **RISC-V:** Vector 1.0 (`__riscv_vector`)
- **Fallback:** Portable C11 scalar

## License

GNU Affero General Public License v3.0 (see [LICENSE](LICENSE)).

CC ?= gcc
CFLAGS ?= -std=c11 -D_POSIX_C_SOURCE=200809L -O3 -march=native -fopenmp -Wall -Wextra -Werror

all: fast_base64

fast_base64: main.c b64_simd.h
	$(CC) $(CFLAGS) main.c -o fast_base64

clean:
	rm -f fast_base64

.PHONY: all clean

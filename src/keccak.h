#ifndef KECCAK_H
#define KECCAK_H

#include <inttypes.h>

/* 64 bitwise rotation to left */
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

typedef struct {
	int b, l, w, nr;
} keccak_t;

void compute_rho(int w);

int keccakf(int, uint64_t*);
int keccak(int r, int c, int n, int l, uint8_t* M, uint8_t* O);

void keccak_256_init();
void keccak_256_update(uint8_t* M, int l);
void keccak_256_finalize(uint8_t* O);

#endif

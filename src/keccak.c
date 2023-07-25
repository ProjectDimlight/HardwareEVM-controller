#include "keccak.h"
#include "icm.h"

extern ICMConfig* const icm_config;

/* Round constants */
const uint64_t RC[24] =
{
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
  0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
  0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
  0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
  0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
  0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
  0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

/* Rotation offsets, y vertically, x horizontally: r[y * 5 + x] */
const int rx[25] = {
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14
};

void compute_rho(int w)
{
  int rho[25];

  /* x = y = 0 is zero */
  rho[0] = 0;

  uint32_t x, y, z;
  x = 1; y = 0;

  uint32_t t, n;
  for (t = 0; t < 24; ++t) {
    /* rotation length */
    n = ((t + 1) * (t + 2) / 2) % w;

    rho[y * 5 + x] = n;

    z = (0 * x + 1 * y) % 5;
    y = (2 * x + 3 * y) % 5;
    x = z;
  }
}

void theta(uint64_t* state)
{
  /* Theta */

  uint64_t C[5] = {0, 0, 0, 0, 0};
  uint64_t D[5] = {0, 0, 0, 0, 0};

  int x, y;
  for (x = 0; x < 5; ++x) {
    C[x] = state[x] ^ state[5 + x] ^ state[10 + x] ^ state[15 + x] ^ state[20 + x];
  }

  for (x = 0; x < 5; ++x) {
    /* in order to avoid negative mod values,
      we've replaced "(x - 1) % 5" with "(x + 4) % 5" */
    D[x] = C[(x + 4) % 5] ^ ROTL64(C[(x + 1) % 5], 1);

    for (y = 0; y < 5; ++y) {
      state[y * 5 + x] = state[y * 5 + x] ^ D[x];
    }
  }
}

void rho(uint64_t* state)
{
  /* Rho */
  int x, y;
  for (y = 0; y < 5; ++y) {
    for (x = 0; x < 5; ++x) {
      state[y * 5 + x] = ROTL64(state[y * 5 + x], rx[y * 5 + x]);
    }
  }
}

void pi(uint64_t* state)
{
  /* Pi */
  uint64_t B[25];

  int x, y;
  for (y = 0; y < 5; ++y) {
    for (x = 0; x < 5; ++x) {
      B[y * 5 + x] = state[5 * y + x];
    }
  }
  int u, v;
  for (y = 0; y < 5; ++y) {
    for (x = 0; x < 5; ++x) {
      u = (0 * x + 1 * y) % 5;
      v = (2 * x + 3 * y) % 5;

      state[v * 5 + u] = B[5 * y + x];
    }
  }
}

void chi(uint64_t* state)
{
  /* Chi */
  uint64_t C[5];

  int x, y;
  for (y = 0; y < 5; ++y) {
    for (x = 0; x < 5; ++x) {
      C[x] = state[y * 5 + x] ^ ((~state[y * 5 + ((x + 1) % 5)]) & state[y * 5 + ((x + 2) % 5)]);
    }

    for (x = 0; x < 5; ++x) {
      state[y * 5 + x] = C[x];
    }
  }
}

void iota(uint64_t* state, int i)
{
  /* Iota */
  /* XXX: truncate RC[i] if w < 64 */
  state[0] = state[0] ^ RC[i];
}

/* Keccak-F[b] function */
int keccakf(int rounds, uint64_t* state)
{
  int i;
  for (i = 0; i < rounds; ++i) {
    theta(state);
    rho(state);
    pi(state);
    chi(state);
    iota(state, i);
  }

  return 0;
}

void keccak_256_init() {
  icm_config->keccak_len = 0;
  memset(icm_config->keccak_A, 0, sizeof(icm_config->keccak_A));
  memset(icm_config->keccak_buf, 0, sizeof(icm_config->keccak_buf));
}

void keccak_256_buffer_update() {
  uint64_t* buffer = (uint64_t*)icm_config->keccak_buf;
  for (int i = 0; i < 1088 / 64; i++)
    icm_config->keccak_A[i] ^= buffer[i];
  keccakf(24, icm_config->keccak_A);
}

void keccak_256_update(uint8_t* M, int l) {
  while(1) {
    int len = (1088 / 8) - icm_config->keccak_len;
    if (l >= len) {
      memcpy(icm_config->keccak_buf + icm_config->keccak_len, M, len);
      keccak_256_buffer_update();
      M += len, l -= len, icm_config->keccak_len = 0;
    } else {
      memcpy(icm_config->keccak_buf + icm_config->keccak_len, M, l);
      icm_config->keccak_len += l;
      break;
    }
  }
}

void keccak_256_finalize(uint8_t* O) {
  icm_config->keccak_buf[icm_config->keccak_len] = 0x01;
  icm_config->keccak_buf[1088 / 8 - 1] |= 0x80;
  keccak_256_buffer_update();
  memcpy(O, (uint8_t*)icm_config->keccak_A, sizeof(uint256_t));
}

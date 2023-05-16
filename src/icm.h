// This is the integrity and confidentiality manager
// which will be called by the udp_server

#include "aes.h"
#include "evm_controller.h"
#include "xsecure.h"

typedef uint8_t uint256_t[32];
typedef uint8_t address_t[20];
typedef uint8_t rsa2048_t[256];
typedef uint8_t aes128_t[16];

enum ICMFunc{
  ICM_SLICE,
  ICM_COPY,
  ICM_SWAP
}

typedef struct {
  uint8_t buffer[4096];

  uint256_t block_hash;
  address_t contract_address;

  uint256_t sload_real_key;

  struct AES_ctx aes_inst;
} ICMConfig;

typedef struct {
  uint256_t k;
  uint256_t v;
  address_t a;
} ICMStorageRecord;

#define storage_record_size 85
#define storage_record_count 771
#define storage_padding 1
#define storage_prime 769

typedef struct {
  ICMStorageRecord  record[storage_record_count];
  uint8_t           padding[storage_padding];
  uint8_t           valid[storage_record_count];
} ICMTempStorage;

extern void *icm_raw_data_base         ;   // decrypted packet
extern void *icm_temp_storage_base     ;   // temporary storage
extern void *icm_storage_history_base  ;   // storage history window for dummy request generation
extern void *icm_config_base           ;   // system configuration
extern ICMTempStorage *icm_temp_storage;
extern ICMConfig      *icm_config      ;

void icm_init();
void icm_clear_storage();

// In real implementation, the AES key should be sent as cipher text
// and the hevm_priv_key should be generated internally
// here we just use it as plain text and copy it to the secure memory
// void icm_set_keys(aes128_t user_aes, rsa2048_t user_pub, rsa2048_t user_mod, rsa2048_t hevm_priv, rsa2048_t hevm_pub, rsa2048_t hevm_mod);

// the ECP points to the input buffer where encrypted payload is located at
// the signature type is adaptive
// we use merkle proof for storage and RSA-SHA3 signature for others
// the return value indicates whether the ECP function shoule be called
uint8_t icm_decrypt();

// the payload should be copied to the secure OCM by the ECP handler
// which is always located at icm_raw_data_base
// the encrypted version will be put together with the ECP header in the UDP obuf
// the length should be the entire length (with the ECP header)
void icm_encrypt(uint32_t length);

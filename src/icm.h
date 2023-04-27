// This is the integrity and confidentiality manager
// which will be called by the udp_server

#include "evm_controller.h"
#include "xsecure.h"

typedef uint8_t uint256_t[32];
typedef uint8_t address_t[20];
typedef uint8_t rsa2048_t[256];
typedef uint8_t aes128_t[16];

typedef struct {
  uint256_t block_hash;

  uint256_t sload_real_key;

  XCsuDma     csu_dma_instance;
  XSecure_Aes user_aes_inst;
  XSecure_Rsa user_pub_inst;
  XSecure_Rsa hevm_priv_inst;
  
} ICMConfig;

typedef struct {
  uint256_t k;
  uint256_t v;
} ICMStorageRecord;

typedef struct {
  ICMStorageRecord  record[1008];
  uint8_t           padding[12];
  uint32_t          item_count;
  uint8_t           valid[1008];
} ICMTempStorage;

extern void *icm_raw_data_base       ;   // decrypted packet
extern void *icm_temp_storage_base   ;   // temporary storage
extern void *icm_storage_history_base;   // storage history window for dummy request generation
extern void *icm_config_base         ;   // system configuration

void icm_init();
void icm_clear_storage();

// In real implementation, the AES key should be sent as cipher text
// and the hevm_priv_key should be generated internally
// here we just use it as plain text and copy it to the secure memory
void icm_set_keys(aes128_t user_aes, rsa2048_t user_pub, rsa2048_t user_mod, rsa2048_t hevm_priv, rsa2048_t hevm_mod);

// the ECP points to the input buffer where encrypted payload is located at
// the signature type is adaptive
// we use merkle proof for storage and RSA-SHA3 signature for others
uint8_t icm_decrypt();

// the payload should be copied to the secure OCM by the ECP handler
// which is always located at icm_raw_data_base
// the encrypted version will be put together with the ECP header in the UDP obuf
void icm_encrypt(uint32_t length);

// generates dummy requests for SLOAD to guarantee integrity
// TODO: design protection for SSTORE
void icm_generate_dummy_requests();

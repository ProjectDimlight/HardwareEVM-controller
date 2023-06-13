// This is the integrity and confidentiality manager
// which will be called by the udp_server

#include "evm_controller.h"
#include "aes.h"
// #include "sha3.h"
#include "uECC.h"
// #include "xsecure.h"

typedef uint8_t uint256_t[32];
typedef uint8_t address_t[20];
typedef uint8_t rsa2048_t[256];
typedef uint8_t aes128_t[16];

enum ICMFunc{
  ICM_CLEAR_STORAGE = 1,
  ICM_SET_USER_PUB
};

/*
上一层堆栈 ][ CODE | INPUT | STACK               | MEMORY            | RETURN ] [ 下一层
             定长    定长    变长                   变长                变长        此时上层Memory长度不会变化
                            但最大1k               最大长度任意          由下一层决定
                            并且不需要动态变化       按页管理，动态分配
                            只需要一次性copy出来
*/

typedef struct __OCMStackFrame{
  // metadata
  address_t address;   // caller = last->address
  uint32_t code_length, input_length, memory_length, return_length;
  uint32_t stack_size, pc, gas;
  uint256_t value;

  // RAM pointers
  void *code, *code_sign;
  void *input, *input_sign;
  void *stack, *stack_sign;
  void *memory, *memory_sign;
  void *top;
} OCMStackFrame;

typedef struct {
  uint8_t ocm_mem_page[PAGE_SIZE];
  uint8_t ocm_immutable_page[PAGE_SIZE];
  uint32_t ocm_mem_pte, ocm_immutable_pte;

  ////////////////////////////////////////////

  uint256_t block_hash;
  uint8_t stack_integrity_valid;

  address_t origin;

  ////////////////////////////////////////////

  uint256_t sload_real_key;
  
  ////////////////////////////////////////////

  struct AES_ctx aes_inst;
  
  uECC_Curve curve;
  uint8_t hevm_pub[32], hevm_priv[32]; 
  uint8_t user_pub[32];

  sha3_context sha_inst;

  ////////////////////////////////////////////

  OCMStackFrame call_stack[16];

} ICMConfig;

extern OCMStackFrame *call_frame;

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
// return 1 if the ECP handler function should be callled
uint8_t icm_decrypt();

// the payload should be copied to the secure OCM by the ECP handler
// which is always located at icm_raw_data_base
// the encrypted version will be put together with the ECP header in the UDP obuf
// the length should be the entire length (with the ECP header)
// returns 1 if icm solves the request and can resume, 0 if the request is passed to HOST
uint8_t icm_encrypt(uint32_t length);

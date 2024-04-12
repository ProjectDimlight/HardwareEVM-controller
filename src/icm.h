// This is the integrity and confidentiality manager
// which will be called by the udp_server

#include "evm_controller.h"
#include "aes.h"
#include "keccak.h"
#include "uECC.h"
// #include "xsecure.h"

#define ICM_DEBUG

typedef uint8_t uint256_t[32];
typedef uint8_t address_t[20];
typedef uint8_t *address_p;
typedef uint8_t rsa2048_t[256];
typedef uint8_t aes128_t[16];
typedef uint8_t ecc224_priv_t[28];
typedef uint8_t ecc224_pub_t[56];

enum ICMFunc{
  ICM_FINISH = 0,
  ICM_CLEAR_STORAGE = 1,
  ICM_SET_USER_PUB, 
  ICM_SET_CONTRACT,
  ICM_ACK,
  ICM_CLEAR_BALANCE
};

enum CESMStates{
  CESM_IDLE,
  CESM_WAIT_FOR_CODE_SIZE,
  CESM_WAIT_FOR_PRECOMPILED_INPUT_COPY,
  CESM_WAIT_FOR_PRECOMPILED_EXECUTION,
  CESM_WAIT_FOR_INPUT_COPY,
  CESM_WAIT_FOR_RETURN_COPY,
  CESM_WAIT_FOR_MEMORY_COPY,
  CESM_WAIT_FOR_BALANCE
};

typedef struct __OCMDeployedCodeFrame{
  address_t address;
  uint256_t code_hash;
  uint32_t length;
  uint8_t *code, *code_sign, *top;
} OCMDeployedCodeFrame;

/*
上一层堆栈 ][ CODE | INPUT | STACK               | MEMORY            | RETURN ] [ 下一层
             定长    定长    变长                   变长                变长        此时上层Memory长度不会变化
                            但最大1k               最大长度任意          由下一层决定
                            并且不需要动态变化       按页管理，动态分配
                            只需要一次性copy出来
*/

typedef struct __OCMStackFrame{
  // metadata
  address_t address;            // caller = last->address
  address_p storage_address;    // for DELEGATECALL and CALLCODE
  address_p caller_address;     // for DELEGATECALL
  uint32_t code_length, input_length, memory_length, return_length;
  uint32_t stack_size, ret_offset, ret_size, pc, msize;
  uint64_t gas;
  uint256_t value;
  uint8_t call_end_func, num_of_params;

  // RAM pointers
  OCMDeployedCodeFrame *locally_deployed_contract_code;
  uint8_t *code, *code_sign, *code_mark;
  uint8_t *input, *input_sign, *input_mark;
  uint8_t *stack, *stack_sign;
  uint8_t *memory, *memory_sign;
  uint8_t *top, *sign_top;
} OCMStackFrame;

typedef struct __OCMBalance {
  address_t address;
  uint256_t balance;
} OCMBalance;

typedef struct {
  uint8_t buffer[PAGE_SIZE];
  uint8_t ocm_mem_page[PAGE_SIZE];
  uint8_t ocm_immutable_page[PAGE_SIZE];
  uint32_t ocm_mem_pte, ocm_immutable_pte;
  uint8_t immutable_page_type;
  uint8_t *immutable_page;
  uint8_t *immutable_page_sign;
  uint32_t immutable_page_length;
  uint32_t ext_code_size;

  ////////////////////////////////////////////

  uint8_t integrity_valid;
  uint8_t check_signature_of_immutable_mem;

  ////////////////////////////////////////////

  uint256_t sload_real_key;
  
  ////////////////////////////////////////////

  struct AES_ctx aes_inst;

  uint32_t rng_rec[32];
  
  uECC_Curve curve;
  uint8_t curve_succeed;
  uint8_t hevm_pub[64], hevm_priv[64];
  uint8_t user_pub[64];
  uint8_t zero[64];

  // keccak space
  uint64_t keccak_A[25];
  uint32_t keccak_len;
  uint8_t keccak_buf[1088 / 8];

  ////////////////////////////////////////////

  OCMStackFrame call_stack[32];
  OCMStackFrame *call_frame_pointer;

  OCMDeployedCodeFrame deployed_codes[32];
  OCMDeployedCodeFrame *deployed_codes_pointer, *found_deployed_code;

  OCMBalance local_balance[128];
  OCMBalance *local_balance_pointer;

  ////////////////////////////////////////////

  address_p contract_address_waiting_for_size;
  uint256_t contract_balance_after_transfer;
  uint8_t calling_precompiled;

  ////////////////////////////////////////////

  uint32_t cesm_current_state;
  uint8_t  cesm_ready;

  ////////////////////////////////////////////

  uint8_t icm_ocm_stack_hash[16 * PAGE_SIZE];
  uint8_t icm_ocm_return_sign_tmp[PAGE_SIZE];
  uint8_t icm_ocm_return_has_sign;

  ////////////////////////////////////////////

  uint8_t frame_depth;

} ICMConfig;

typedef struct {
  uint256_t k;
  address_t a;
} ICMStorageRecord;

typedef struct {
  uint256_t v;
  uint8_t depth;
} ICMStorageItem;

#define storage_record_size 117
#define storage_record_count 280
#define storage_prime 277
#define storage_pow2 511

typedef struct {
  /*
  pool: memory pool for storage item
  pos: the remained avaliable position of pool
  head, nxt: linked list for storage item of same (addr, key)
  bel: the hash index of item
  ordered_index: the index of item, ordered by its depth field
  */
  uint32_t          item_count;
  ICMStorageItem    pool[storage_record_count];
  uint32_t          head[storage_record_count], nxt[storage_record_count];
  uint32_t          bel[storage_record_count], pos[storage_record_count];
  uint32_t          ordered_index[storage_record_count];
} ICMStoragePool;

typedef struct {
  ICMStorageRecord  record[storage_record_count];
  ICMStoragePool    pool;
  uint8_t           valid[storage_record_count];
} ICMTempStorage;

extern void * const icm_raw_data_base         ;   // decrypted packet
extern void * const icm_storage_history_base  ;   // storage history window for dummy request generation
extern ICMTempStorage * const icm_temp_storage;
extern ICMConfig      * const icm_config      ;

void icm_debug(void *data, uint32_t length);

void icm_init();
void icm_clear_storage();

void icm_step();
void icm_call_end_state_machine();

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

void reset_udp();
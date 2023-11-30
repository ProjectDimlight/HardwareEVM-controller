#include "udp_server.h"
#include "evm_controller.h"
#include "icm_keys.h"

#define NUMBER_OF_DUMMIES 127
#define PAGE_SIZE 1024
#define SIGNATURE_LENGTH 56
#define SIGNATURE_SIZE 64
#define PAGE_ADDR_W 10
#define PAGE_SIGN_W 6
#define PAGES(x) (x ? (((x - 1) >> PAGE_ADDR_W) + 1) : 0)
#define SELF_ADDRESS ((call_frame + 1)->address)

#define call_frame (icm_config->call_frame_pointer)
#define cesm_state (icm_config->cesm_current_state)

#define ENCRYPTION

// these address spaces are mapped to secure on chip memory
void * const icm_raw_data_base          = (void*)0xFFFC0000ll;   // decrypted packet
void * const icm_temp_storage_base      = (void*)0xFFFC8000ll;   // temporary storage
void * const icm_config_base            = (void*)0xFFFD0000ll;   // system configuration and sensitive data
void * const icm_rt_base                = (void*)0xFFFD6000ll;   // runtime, stack and heap

uint8_t icm_ram_stack[4096 * PAGE_SIZE];
uint8_t icm_ram_return_tmp[16 * PAGE_SIZE];
uint8_t icm_ram_deployed_code[1024 * PAGE_SIZE];

ICMTempStorage * const icm_temp_storage = (ICMTempStorage*)0xFFFC8000ll;
ICMConfig      * const icm_config       = (ICMConfig*)0xFFFD0000ll;

uint8_t zero_page[PAGE_SIZE];

///////////////////////////////////////////////////////////////////

void icm_debug(void *data, uint32_t length) {
  void *out = get_output_buffer();
  uint8_t tmp[16];
  memcpy(tmp, out, 16);
  
  memcpy(out, "dbug", 4);
  memcpy(out + 4, data, length);
  build_outgoing_packet(4 + length);

  memcpy(out, tmp, 16);
}

///////////////////////////////////////////////////////////////////

uint32_t icm_hash(address_t address, uint256_t key) {
  uint32_t ad = *(uint32_t*)(address + 0);
  uint32_t hi = *(uint32_t*)(key + 28);
  uint32_t lo = *(uint32_t*)(key + 0);
  uint32_t hash = (ad % storage_prime);
  hash = (hash * 31 + hi) % storage_prime;
  hash = (hash * 17 + lo) % storage_prime;
  return hash;
}

// returns the index
// if not found, return the first invalid (empty) element
// for insertion, use this as the new index
// for query, 
uint32_t icm_find(uint256_t key) {
  uint32_t hash = icm_hash(call_frame->storage_address, key);
  uint32_t cnt = 0;
  for (;
      cnt < storage_prime &&
      icm_temp_storage->valid[hash] && (
      memcmp(icm_temp_storage->record[hash].a, call_frame->storage_address, sizeof(address_t)) != 0 ||
      memcmp(icm_temp_storage->record[hash].k, key, sizeof(uint256_t)) != 0);
    hash = (hash + 1) % storage_prime, cnt++);

  if (cnt == storage_prime) 
    return storage_prime;
  else 
    return hash;
}

void icm_dump_storage() {
  // dump storage from OCM to HOST
  ECP *res = get_output_buffer();
  //memcpy(res, req, sizeof(ECP));
  res->opcode = COPY;
  res->src = STORAGE;
  res->dest = HOST;
  res->func = 1;
  res->src_offset = 0;
  res->dest_offset = 0;

  uint64_t count = 0, content_length = 4;
  for (uint64_t i = 0; i < storage_prime; i++)
  if (icm_temp_storage->valid[i]) {
    memcpy((res->data) + content_length, &(icm_temp_storage->record[i]), sizeof(ICMStorageRecord));
    count++; content_length += sizeof(ICMStorageRecord);
    icm_temp_storage->valid[i] = 0;
  }
  // finalize: send remaining records
  res->length = content_length;
  *(uint32_t*)res->data = count;

  // encrypt storage elements
  // uint32_t sign_offset = 4 + aes_encrypt(res->data + 4, icm_raw_data_base + 4, content_length - 4);
  // content_length = sign_offset;

  build_outgoing_packet(sizeof(ECP) + content_length);
}

///////////////////////////////////////////////////////////////////

uint32_t page_length(uint32_t length) {
  return PAGES(length) << PAGE_ADDR_W;
}

uint32_t sign_length(uint32_t length) {
  return PAGES(length) << PAGE_SIGN_W;
}

uint32_t mark_length(uint32_t length) {
  return PAGES(length);
}

uint32_t page_offset(uint32_t length) {
  return length & (~0x3ff);
}

uint32_t sign_offset(uint32_t length) {
  return (length >> PAGE_ADDR_W) << PAGE_SIGN_W;
}

uint32_t mark_offset(uint32_t length) {
  return (length >> PAGE_ADDR_W);
}

uint8_t icm_stack_is_empty() {
  return call_frame == icm_config->call_stack;
}

uint8_t icm_stack_is_root() {
  return call_frame == icm_config->call_stack + 1;
}

OCMDeployedCodeFrame *icm_find_locally_deployed_contract_code(address_p addr) {
  for (OCMDeployedCodeFrame *p = icm_config->deployed_codes + 1; p <= icm_config->deployed_codes_pointer; p++) {
    if (memcmp(p->address, addr, 20) == 0) {
      // found
      return p; 
    }
  }
  return NULL;
}

void icm_stack_push(address_t callee_address, address_p callee_storage_address, address_p callee_caller_address, uint32_t code_length, uint32_t input_length, uint64_t gas, uint256_t value, uint256_t balance) {
#ifdef ICM_DEBUG
    icm_debug("call stack push", 15);
#endif

  uint8_t init = 0;
  if (icm_stack_is_empty()) {
    // the 0-th element in the stack is dummy header
    // which stores immutable metadata such as ORIGIN

    // init
    init = 1;
    call_frame->top = icm_ram_stack;
    call_frame->sign_top = icm_config->icm_ocm_stack_hash;

#ifdef ICM_DEBUG
    icm_debug("isroot", 6);
#endif
  } else {
    memcpy_b(&(call_frame->pc), evm_env_pc, 4);
    memcpy_b(&(call_frame->msize), evm_env_msize, 4);
    memcpy_b(&(call_frame->gas), evm_env_gas, 8);
    call_frame->pc ++;  // step to the next inst

    // does not update stack size, because it has been cleared while dumping out stack elements
    
    // no longer need to copy memory sign
    call_frame->top = call_frame->memory + call_frame->memory_length;
    call_frame->sign_top = call_frame->memory_sign + sign_length(call_frame->memory_length);
  }

#ifdef ICM_DEBUG
  icm_debug("pc msize gas load", 17);
#endif
  
  // create a new frame
  void *base = call_frame->top;
  void *sign_base = call_frame->sign_top;
  call_frame++;
  memcpy(call_frame->address, callee_address, sizeof(address_t));
  call_frame->storage_address = callee_storage_address;
  call_frame->caller_address = callee_caller_address;
  call_frame->code_length = code_length;
  call_frame->input_length = input_length;
  call_frame->memory_length = 0;
  call_frame->return_length = 0;
  call_frame->stack_size = 0;
  call_frame->msize = 0;
  call_frame->pc = 0;
  call_frame->gas = gas;
  memcpy_b(call_frame->value, value, sizeof(uint256_t));

#ifdef ICM_DEBUG
  icm_debug("call frame set meta", 19);
#endif

  call_frame->code        = base;
  call_frame->input       = call_frame->code        + page_length(code_length);
  call_frame->stack       = call_frame->input       + page_length(input_length);
  call_frame->memory      = call_frame->stack       + 32 * PAGE_SIZE;
  call_frame->code_sign   = sign_base;
  call_frame->code_mark   = call_frame->code_sign   + sign_length(code_length);
  call_frame->input_sign  = call_frame->code_mark   + mark_length(code_length);
  call_frame->input_mark  = call_frame->input_sign  + sign_length(input_length);
  call_frame->stack_sign  = call_frame->input_mark  + mark_length(input_length);
  call_frame->memory_sign = call_frame->stack_sign  + 32;

#ifdef ICM_DEBUG
  icm_debug("call frame set offset", 21);
#endif

  call_frame->locally_deployed_contract_code = icm_config->found_deployed_code;

  for (char *p = call_frame->code_mark; p < call_frame->input_sign; p ++) {
    *p = 0;
  }
  for (char *p = call_frame->input_mark; p < call_frame->stack_sign; p ++) {
    *p = 0;
  }

#ifdef ICM_DEBUG
  icm_debug("call frame set sign", 19);
#endif

  if (!init) {
    // Set ENV
    memcpy_b(evm_env_code_size,         &(call_frame->code_length), 4);
    memcpy_b(evm_env_calldata_size,     &(call_frame->input_length), 4);
    memcpy_b(evm_env_msize,             &(call_frame->msize), 4);
    memcpy_b(evm_env_pc,                &(call_frame->pc), 4);
    memcpy_b(evm_env_gas,               &(call_frame->gas), 8);
    memcpy_b(evm_env_returndata_size,   &(call_frame->return_length), 4);
    memcpy_b(evm_env_value,               call_frame->value, sizeof(uint256_t));
    if (balance)
      memcpy_b(evm_env_balance,             balance, sizeof(uint256_t));
    
    memcpy_b(evm_env_address, call_frame->storage_address, sizeof(address_t));
    memcpy_b(evm_env_caller,  call_frame->caller_address, sizeof(address_t));

#ifdef ICM_DEBUG
    icm_debug("set env regs", 12);
#endif
  }
}

void icm_stack_pop() {
#ifdef ICM_DEBUG
  icm_debug("call stack pop", 14);
#endif

  call_frame--;

  if (!icm_stack_is_empty()) {
    // No longer need to copy memory sign

    // Recover ENV
    memcpy_b(evm_env_code_size,         &(call_frame->code_length), 4);
    memcpy_b(evm_env_calldata_size,     &(call_frame->input_length), 4);
    // memcpy_b(evm_env_stack_size,        &(call_frame->stack_size), 4);
    memcpy_b(evm_env_msize,             &(call_frame->msize), 4);
    memcpy_b(evm_env_pc,                &(call_frame->pc), 4);
    memcpy_b(evm_env_gas,               &(call_frame->gas), 8);
    memcpy_b(evm_env_returndata_size,   &(call_frame->return_length), 4);
    memcpy_b(evm_env_value,               call_frame->value, sizeof(uint256_t));
    
    memcpy_b(evm_env_address, call_frame->storage_address, sizeof(address_t));
    memcpy_b(evm_env_caller,  call_frame->caller_address, sizeof(address_t));
  }

#ifdef ICM_DEBUG
  icm_debug("recover env regs", 16);
#endif
}

// CALL: stack_push, memcpy (last.mem -> this.input), run
// END:  memcpy (this.mem -> returndata_tmp) , stack_pop, memcpy (returndata_tmp -> this.mem), resume

///////////////////////////////////////////////////////////////////

uint32_t padded_size(uint32_t size, uint32_t block_width) {
  if (size == 0) return 0;
  uint32_t number_of_blocks = (((size - 1) >> block_width) + 1);
  return number_of_blocks << block_width;
}

void aes_decrypt(uint8_t *out, uint8_t *in, uint32_t size) {
#ifdef ICM_DEBUG
  icm_debug("decrypt", 7);
#endif
  AES_ctx_set_iv(&(icm_config->aes_inst), iv);
  size = padded_size(size, 4);
  memcpy(out, in, size);
  AES_CBC_decrypt_buffer(&(icm_config->aes_inst), out, size);
#ifdef ICM_DEBUG
  icm_debug("decrypt finish", 14);
#endif
}

void aes_decrypt_stack(uint8_t *out, uint8_t *in, uint32_t size) {
  AES_ctx_set_iv(&(icm_config->aes_inst), iv);
  memcpy(out, in, size);
  for (uint32_t i = size; i; i -= 32) {
    AES_CBC_decrypt_buffer(&(icm_config->aes_inst), out + i - 32, 32);
  }
}

uint32_t aes_encrypt(uint8_t *out, uint8_t *in, uint32_t size) {
#ifdef ICM_DEBUG
  icm_debug("encrypt", 7);
#endif
  AES_ctx_set_iv(&(icm_config->aes_inst), iv);
  size = padded_size(size, 4);
  AES_CBC_encrypt_buffer(&(icm_config->aes_inst), in, size);
  memcpy(out, in, size);
#ifdef ICM_DEBUG
  icm_debug("encrypt finish", 14);
#endif
  return size;
}

///////////////////////////////////////////////////////////////////

// Integrity check
// User input: signed by user
// User code: signed by user
// Memory contents and call/return data: signed by hash
// Existing code: 
//    - when storing locally: signed by hash
//    - Ethereum network only maintains the merkle proof of the entire code
//    - fetch all code from host
//    - get the merkle hash, and send the hash to user for verification
// Storage: merkle proof
//    - dump-out storage: signed by fpga

void hash_sign(uint8_t *out, uint8_t *data, uint32_t size, uint8_t type, uint64_t nonce, uint8_t *priv_key) {
  keccak_256_init();
  keccak_256_update(data, size);
  keccak_256_update(&type, 1);
  keccak_256_update(&nonce, 8);
  keccak_256_finalize(out);
}

int hash_verify(uint8_t *in, uint8_t *data, uint32_t size, uint8_t type, uint64_t nonce, uint8_t *pub_key) {
  uint8_t hash[32];
  keccak_256_init();
  keccak_256_update(data, size);
  keccak_256_update(&type, 1);
  keccak_256_update(&nonce, 8);
  keccak_256_finalize(hash);
  return memcmp(in, hash, 32) == 0;
}

void hash_sign_page(uint8_t *out, uint8_t *data, uint8_t src, uint32_t src_offset, uint64_t nonce, uint8_t *priv_key) {
  uint8_t hash[32];
  keccak_256_init();
  keccak_256_update(data, PAGE_SIZE);
  keccak_256_update(&src, 1);
  keccak_256_update(&src_offset, 4);
  keccak_256_update(&nonce, 8);
  keccak_256_finalize(out);
}

int hash_verify_page(uint8_t *in, uint8_t *data, uint8_t src, uint32_t src_offset, uint64_t nonce, uint8_t *pub_key) {
  uint8_t hash[32];
  keccak_256_init();
  keccak_256_update(data, PAGE_SIZE);
  keccak_256_update(&src, 1);
  keccak_256_update(&src_offset, 4);
  keccak_256_update(&nonce, 8);
  keccak_256_finalize(hash);
  return memcmp(in, hash, 32) == 0;
}

int ecdsa_rng(uint8_t *dest, unsigned size) {
  volatile uint32_t *p = 0xFF250000;
  for (uint32_t t = 0; t < size; t++) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 4; ++i) {
      val = (val << 2) | ((*p) & 0x3);
    }
    dest[t] = val;
  }
  // icm_debug("rng", 3);
  // icm_debug(&size, 4);
  // icm_debug(dest, size);
  return 1;
}

void ecdsa_sign_page(uint8_t *out, uint8_t *data, uint8_t src, uint32_t src_offset, uint64_t nonce, uint8_t *priv_key) {
  uint8_t hash[32];
  keccak_256_init();
  keccak_256_update(data, PAGE_SIZE);
  keccak_256_update(&src, 1);
  keccak_256_update(&src_offset, 4);
  keccak_256_update(&nonce, 8);
  keccak_256_finalize(hash);
#ifdef ICM_DEBUG
  icm_debug("page hash", 10);
  icm_debug(hash, 32);
#endif
  uint8_t res = uECC_sign(priv_key, hash, 32, out, icm_config->curve);
  icm_debug(out, 64);
}

int ecdsa_verify_page(uint8_t *in, uint8_t *data, uint8_t src, uint32_t src_offset, uint64_t nonce, uint8_t *pub_key) {
  uint8_t hash[32];
  keccak_256_init();
  keccak_256_update(data, PAGE_SIZE);
  keccak_256_update(&src, 1);
  keccak_256_update(&src_offset, 4);
  keccak_256_update(&nonce, 8);
  keccak_256_finalize(hash);
#ifdef ICM_DEBUG
  icm_debug("page hash verify", 17);
  icm_debug(hash, 32);
  icm_debug(in, 64);
#endif
  return uECC_verify(pub_key, hash, 32, in, icm_config->curve);
}

///////////////////////////////////////////////////////////////////

void icm_init() {
  // ZERO
  memset(icm_config->zero, 0, 64);

  // AES
  AES_init_ctx_iv(&(icm_config->aes_inst), user_aes, iv);
  memset(zero_page, 0, sizeof(zero_page));
  aes_encrypt(zero_page, zero_page, PAGE_SIZE);

  // ECDSA
  uECC_set_rng(&ecdsa_rng);
  icm_config->curve = uECC_secp224r1();
  icm_config->curve_succeed = uECC_make_key(icm_config->hevm_pub, icm_config->hevm_priv, icm_config->curve);

  // Stack
  call_frame = icm_config->call_stack;
}

void icm_clear_storage() {
  memset(icm_temp_storage->valid, 0, sizeof(icm_temp_storage->valid));

  icm_config->deployed_codes_pointer = icm_config->deployed_codes;
  icm_config->deployed_codes->top = icm_ram_deployed_code;
}

// [TODO] this function is used only when using address-separated storage strategy
// when using mixed strategy, there will be no swapping-out 
uint8_t icm_check_storage_signature(rsa2048_t sign_c) {
  rsa2048_t sign;
  uint256_t real;

  // decrypt by the public key to get the hash 
  // only the first 32 bytes are valid, remaining should be all 0

  // calculate hash

  // compare, return 1 if valid
  return memcmp(real, sign, sizeof(uint256_t)) == 0;
}

///////////////////////////////////////////////////////////////////

void icm_generate_dummy_requests() {
  
}

void icm_record_history() {
  
}

///////////////////////////////////////////////////////////////////

void icm_code_hash(uint8_t *code_hash_output, uint8_t *code_page, uint32_t code_length) {
  #ifdef ICM_DEBUG
    int show_code = 0;
    if (code_length < 1024) {
      show_code = 1;
      icm_debug("code", 8);
    }
  #endif

  // The code is the content of the returndata
  keccak_256_init();
  // here just test for keccak256 lib, only 1 page code
  for (uint32_t i = 0; i < code_length; i += PAGE_SIZE) {
    uint32_t len = i + PAGE_SIZE < code_length ? PAGE_SIZE : code_length - i;
    aes_decrypt(icm_raw_data_base, code_page, len);
  #ifdef ICM_DEBUG
    if (show_code) {
      icm_debug(icm_raw_data_base, len);
    }
  #endif
    keccak_256_update(icm_raw_data_base, len);
  }
  keccak_256_finalize(code_hash_output);
  
  #ifdef ICM_DEBUG
    icm_debug("codehash", 8);
    icm_debug(code_hash_output, 32);
  #endif
}

// void icm_get_address_for_create(void *address);

void icm_get_address_for_create2(uint8_t *address_output, uint8_t *code_hash, uint8_t *sender_address, uint8_t *salt) {
  keccak_256_init();
  uint8_t head = 0xff;
  keccak_256_update(&head, 1);
  uint8_t reverseAddress[20], *senderAddress = (uint8_t*)sender_address;
  for (int i = 0; i < sizeof(address_t); i++)
    reverseAddress[i] = senderAddress[19 - i];
  keccak_256_update(reverseAddress, sizeof(address_t));
  uint8_t reverseSalt[32];
  for (int i = 0; i < 32; i++)
    reverseSalt[i] = salt[31 - i];
  keccak_256_update(reverseSalt, sizeof(uint256_t));
  keccak_256_update(code_hash, sizeof(uint256_t));
  uint8_t address[32];
  keccak_256_finalize(address);
  for (int i = 0; i < 20; i++)
    address_output[i] = address[31 - i];

#ifdef ICM_DEBUG
  icm_debug("deployaddr", 10);
  icm_debug(address_output, 20);
#endif
}

///////////////////////////////////////////////////////////////////

uint8_t address_is_precompiled(address_p address) {
  for (int i = 1; i < 20; i++) {
    if (address[i] != 0) return 0;
  }
  return 0x1 <= address[0] && address[0] <= 0x9;
}

void icm_switch_contract(address_p address, address_p storage_address, void *value) {
  icm_config->contract_address_waiting_for_size = address;
  ECP *ecp = get_output_buffer();
  ecp->opcode = ICM;
  ecp->src = CONTROL;
  ecp->dest = HOST;
  ecp->func = ICM_SET_CONTRACT;
  ecp->src_offset = 0;
  ecp->dest_offset = 0;
  ecp->length = (sizeof(address_t) << 1) + 32;
  memcpy(ecp->data, address, sizeof(address_t));
  memcpy(ecp->data + sizeof(address_t), storage_address, sizeof(address_t));
  memcpy(ecp->data + (sizeof(address_t) << 1), value, 32);
  build_outgoing_packet(sizeof(ECP) + ecp->length);
}

void icm_call(uint8_t func) {
  // CALL
  // get next level code size
  call_frame->call_end_func = func;
  uint8_t *evm_stack = call_frame->stack;
  cesm_state = CESM_WAIT_FOR_CODE_SIZE;
  icm_config->calling_precompiled = 0;

  if (func == OP_CREATE || func == OP_CREATE2) {
    if (func == OP_CREATE) {
      icm_debug("create not supported", 20);
    }

    // CREATE: code is local, calldata is none
    icm_config->cesm_ready = 1;
    icm_config->immutable_page_length = *(uint32_t*)(evm_stack + 64);  // size
#ifdef ICM_DEBUG
    icm_debug("page_length", 11);
    icm_debug(&(icm_config->immutable_page_length), sizeof(uint32_t));
#endif
  } else {
    address_p address = evm_stack + 32;
    icm_config->cesm_ready = 0;

    if (icm_config->found_deployed_code = icm_find_locally_deployed_contract_code(address)) {
#ifdef ICM_DEBUG
      icm_debug("code found locally", 18);
      icm_debug(&icm_config->found_deployed_code->length, 4);
#endif
      // found locally
      icm_config->ext_code_size = icm_config->found_deployed_code->length;
    } else if (address_is_precompiled(address)) {
#ifdef ICM_DEBUG
      icm_debug("precompiled", 11);
#endif
      icm_config->ext_code_size = 0;
      icm_config->calling_precompiled = 1;
    } else {
#ifdef ICM_DEBUG
      icm_debug("require code length from host", 29);
      icm_debug(address, 20);
#endif
    }

    // call target address, query from host
    // send ICM_SET_CONTRACT
    icm_switch_contract(
      address,
      (func == OP_CALLCODE || func == OP_DELEGATECALL) ? call_frame->storage_address : address,
      (func == OP_CALLCODE || func == OP_CALL) ? evm_stack + 64 : icm_config->zero
    );
  }
}

void icm_end(uint8_t func) {
  // END
  // fetch params
  // the params are located at the front of STACK segment
  call_frame->call_end_func = func;
  uint8_t *evm_stack = call_frame->stack;
  cesm_state = CESM_WAIT_FOR_RETURN_COPY;

  // copy memory as returndata
  icm_config->immutable_page_type = RETURNDATA;
  icm_config->immutable_page = icm_ram_return_tmp;
  icm_config->immutable_page_sign = icm_config->icm_ocm_return_sign_tmp;
  if (func == OP_RETURN || func == OP_REVERT) {
    icm_config->cesm_ready = 0;

    ECP ecp;
    ecp.opcode = COPY;
    ecp.src = OCM_MEM;
    ecp.dest = OCM_IMMUTABLE_MEM;
    ecp.func = 0;
    ecp.src_offset = *(uint32_t*)(evm_stack + 0);
    ecp.dest_offset = 0;
    ecp.length = *(uint32_t*)(evm_stack + 32);
    icm_config->immutable_page_length = (call_frame - 1)->return_length = ecp.length;

    evm_memory_copy(&ecp);
  } else {
    // no need for copy
    icm_config->cesm_ready = 1;
    icm_config->immutable_page_length = (call_frame - 1)->return_length = 0;
  }
}

void icm_tmp_test() {
  uint8_t a[16];
  ecdsa_rng(a, 16);
  icm_debug(a, 16);
  
  /*
  uint8_t data[64], sign[64];
  for (int i = 0; i < 64; i++) {
    data[i] = i;
  }
  ecdsa_sign(sign, data, 64, STACK, 0, icm_config->hevm_priv);
  int res = ecdsa_verify(sign, data, 64, STACK, 0, icm_config->hevm_pub);
  icm_debug("test signature verify", 21);
  icm_debug(&res, 4);
  */
}

void icm_step() {
  icm_config->cesm_ready = 1;
}

void icm_call_end_state_machine() {
  if (cesm_state == CESM_IDLE) {
    // do nothing
    icm_config->cesm_ready = 0;
  } else if (cesm_state == CESM_WAIT_FOR_CODE_SIZE) {
    // CALL
    // wait until code size & balance are received
    if (icm_config->cesm_ready == 0) {
      return;
    }
    // the code length is set
#ifdef ICM_DEBUG
    icm_debug("code size received", 18);
#endif

    uint8_t *evm_stack = call_frame->stack;
    uint64_t gas;
    address_p callee_address, callee_storage_address, callee_caller_address;
    uint8_t *value;
    uint32_t code_length, input_length, offset, size;
    uint8_t func = call_frame->call_end_func;

    if (func == OP_CALL || func == OP_CALLCODE) {
      gas = *(uint64_t*)(evm_stack);
      callee_address = evm_stack + 32;
      callee_storage_address = (func == OP_CALLCODE ? call_frame->storage_address : SELF_ADDRESS);
      callee_caller_address = call_frame->storage_address;
      value = evm_stack + 64;
      code_length = icm_config->ext_code_size;
      input_length = *(uint32_t*)(evm_stack + 32 * 4);
      offset = *(uint32_t*)(evm_stack + 32 * 3);
      size = *(uint32_t*)(evm_stack + 32 * 4);
      call_frame->ret_offset = *(uint32_t*)(evm_stack + 32 * 5);
      call_frame->ret_size = *(uint32_t*)(evm_stack + 32 * 6);
    } else if (func == OP_DELEGATECALL || func == OP_STATICCALL) {
      gas = *(uint64_t*)(evm_stack);
      callee_address = evm_stack + 32;
      callee_storage_address = (func == OP_DELEGATECALL ? call_frame->storage_address : SELF_ADDRESS);
      callee_caller_address = (func == OP_DELEGATECALL ? call_frame->caller_address : call_frame->storage_address);
      if (func == OP_DELEGATECALL) {
        value = evm_env_value;
      } else {
        value = icm_config->zero;
      }
      code_length = icm_config->ext_code_size;
      input_length = *(uint32_t*)(evm_stack + 32 * 3);
      offset = *(uint32_t*)(evm_stack + 32 * 2);
      size = *(uint32_t*)(evm_stack + 32 * 3);
      call_frame->ret_offset = *(uint32_t*)(evm_stack + 32 * 4);
      call_frame->ret_size = *(uint32_t*)(evm_stack + 32 * 5);
    } else { // CREATE, CREATE2
      gas = *(uint64_t*)evm_env_gas;
      callee_address = icm_config->zero;
      callee_storage_address = SELF_ADDRESS;
      callee_caller_address = call_frame->address;
      value = evm_stack;
      code_length = icm_config->immutable_page_length;
      input_length = 0;
      offset = *(uint32_t*)(evm_stack + 32);
      size = *(uint32_t*)(evm_stack + 32 * 2);
      call_frame->ret_offset = 0;
      call_frame->ret_size = 0;
      
      memcpy(icm_config->contract_balance_after_transfer, value, 32);
    }

#ifdef ICM_DEBUG
    icm_debug("call offset", 11);
    icm_debug(&offset, 4);
    icm_debug("call size", 9);
    icm_debug(&size, 4);
#endif

    if (icm_config->calling_precompiled) {
      // no need to push stack
      // just copy params
      void *base = call_frame->top;

      icm_config->immutable_page_type = CALLDATA;
      icm_config->immutable_page = base;
      icm_config->immutable_page_sign = base + page_length(input_length);
      icm_config->immutable_page_length = input_length;

      memcpy_b(&(call_frame->pc), evm_env_pc, 4);
      call_frame->pc++;

      cesm_state = CESM_WAIT_FOR_PRECOMPILED_INPUT_COPY;
    } else {
      // stack push
      icm_stack_push(callee_address, callee_storage_address, callee_caller_address, code_length, input_length, gas, value, icm_config->contract_balance_after_transfer);
#ifdef ICM_DEBUG
      icm_debug("address:", 8);
      icm_debug(callee_address, 20);
      icm_debug(callee_storage_address, 20);
      icm_debug(callee_caller_address, 20);
      
      icm_debug("length:", 7);
      icm_debug(&code_length, 4);
      icm_debug(&input_length, 4);

      icm_debug("value:", 6);
      icm_debug(value, 32);
      icm_debug(icm_config->contract_balance_after_transfer, 32);
#endif

      // copy memory as code (CREATE) or input (CALL)
      if (func == OP_CREATE || func == OP_CREATE2) {  
        icm_config->immutable_page_type = CODE;
        icm_config->immutable_page = call_frame->code;
        icm_config->immutable_page_sign = call_frame->code_sign;
        icm_config->immutable_page_length = call_frame->code_length;
        for (uint32_t i = 0, N = mark_length(call_frame->code_length); i < N; i++)
          call_frame->code_mark[i] = 1 | 2;
      } else {
        icm_config->immutable_page_type = CALLDATA;
        icm_config->immutable_page = call_frame->input;
        icm_config->immutable_page_sign = call_frame->input_sign;  
        icm_config->immutable_page_length = call_frame->input_length;
      }
      cesm_state = CESM_WAIT_FOR_INPUT_COPY;
    }

    icm_config->cesm_ready = 0;
    ECP ecp;
    ecp.opcode = COPY;
    ecp.src = OCM_MEM;
    ecp.dest = OCM_IMMUTABLE_MEM;
    ecp.func = 0;
    ecp.src_offset = offset;
    ecp.dest_offset = 0;
    ecp.length = size;
    evm_memory_copy(&ecp);
  } else if (cesm_state == CESM_WAIT_FOR_PRECOMPILED_INPUT_COPY) {
    // CALL PRECOMPILED
    // wait until copy finish
    if (icm_config->cesm_ready == 0) {
      evm_memory_copy(NULL);
      return;
    }
    
    icm_config->immutable_page_type = RETURNDATA;
    icm_config->immutable_page = icm_ram_return_tmp;
    icm_config->immutable_page_sign = icm_config->icm_ocm_return_sign_tmp;
    icm_config->immutable_page_length = 0;
    
    cesm_state = CESM_WAIT_FOR_PRECOMPILED_EXECUTION;
    icm_config->cesm_ready = 0;

    // Send ICM_FINISH
    ECP *ecp = get_output_buffer();
    ecp->opcode = ICM;
    ecp->src = CONTROL;
    ecp->dest = HOST;
    ecp->func = ICM_FINISH;
    ecp->src_offset = 0;
    ecp->dest_offset = 0;
    ecp->length = 0;
    build_outgoing_packet(sizeof(ECP));
  } else if (cesm_state == CESM_WAIT_FOR_PRECOMPILED_EXECUTION) { 
    // wait until execution finish
    if (icm_config->cesm_ready == 0) {
      return;
    }

    call_frame->return_length = icm_config->immutable_page_length;
    memcpy_b(evm_env_returndata_size, &(call_frame->return_length), 4);

    // Resume
    cesm_state = CESM_WAIT_FOR_MEMORY_COPY;
    if (icm_config->immutable_page_length) {
      icm_config->cesm_ready = 0;

      // Copy results to memory
      ECP ecp;
      ecp.opcode = COPY;
      ecp.src = OCM_IMMUTABLE_MEM;
      ecp.dest = OCM_MEM;
      ecp.func = 0;
      ecp.src_offset = 0;
      ecp.dest_offset = call_frame->ret_offset;
      ecp.length = call_frame->ret_size;
      evm_memory_copy(&ecp);
    } else {
      icm_config->cesm_ready = 1;
    }
  } else if (cesm_state == CESM_WAIT_FOR_INPUT_COPY) {
    // CALL
    // wait until copy finish
    if (icm_config->cesm_ready == 0) {
      evm_memory_copy(NULL);
      return;
    }
    
    OCMStackFrame *caller_frame = call_frame - 1;
    uint8_t func = caller_frame->call_end_func;
    if (func == OP_CREATE || func == OP_CREATE2) {
      uint8_t *salt = (caller_frame->stack + 32 * 3);
      uint8_t *sender_address = caller_frame->address;
      uint256_t code_hash;
      icm_code_hash(code_hash, call_frame->code, call_frame->code_length);
      icm_get_address_for_create2(call_frame->address, code_hash, sender_address, salt);
      memcpy_b(evm_env_address, call_frame->storage_address, sizeof(address_t));

      // transfer call value
      icm_switch_contract(
        call_frame->address,
        call_frame->address,
        caller_frame->stack
      );
    }

#ifdef ICM_DEBUG
    icm_debug("copy input/code ready", 21);
    {
      uint32_t debug_length = PAGE_SIZE;
      if (call_frame->input_length < debug_length)
        debug_length = call_frame->input_length;
      
      uint8_t display_page[1024];
      aes_decrypt(display_page, call_frame->input, debug_length);
      icm_debug(display_page, debug_length);
    }
#endif

    cesm_state = CESM_IDLE;
    // start
    ECP ecp;
    ecp.opcode = CALL;
    ecp.src = HOST;
    ecp.dest = CONTROL;
    ecp.func = (call_frame - 1)->call_end_func;
    ecp.src_offset = 0;
    ecp.dest_offset = 0;
    ecp.length = 0;
    handle_ecp(&ecp);
  } else if (cesm_state == CESM_WAIT_FOR_RETURN_COPY) {
    // END
    // wait until copy finish
    if (icm_config->cesm_ready == 0) {
      evm_memory_copy(NULL);
      return;
    }
#ifdef ICM_DEBUG
    icm_debug("copy return ready", 17);

    {
      uint32_t debug_length = PAGE_SIZE;
      if (icm_config->immutable_page_length < debug_length)
        debug_length = icm_config->immutable_page_length;
      icm_debug("length", 6);
      icm_debug(&debug_length, 4);
      
      uint8_t display_page[1024];
      aes_decrypt(display_page, icm_config->immutable_page, debug_length);
      icm_debug(display_page, debug_length);
    }
#endif

    OCMStackFrame* deployFrame = call_frame - 1;
    uint8_t end_func = call_frame->call_end_func;
    if (deployFrame->call_end_func == OP_CREATE || deployFrame->call_end_func == OP_CREATE2) {
#ifdef ICM_DEBUG
    icm_debug("deploy", 6);
#endif
      // The return value is the code to be deployed
      icm_config->deployed_codes_pointer++;
      uint8_t *salt = (deployFrame->stack + 32 * 3);
      uint8_t *sender_address = deployFrame->address;
      memcpy(icm_config->deployed_codes_pointer->address, call_frame->address, sizeof(address_t));
      icm_code_hash(icm_config->deployed_codes_pointer->code_hash, icm_config->immutable_page, icm_config->immutable_page_length);
      icm_config->deployed_codes_pointer->length    = icm_config->immutable_page_length;
      icm_config->deployed_codes_pointer->code      = (icm_config->deployed_codes_pointer - 1)->top;
      icm_config->deployed_codes_pointer->code_sign = icm_config->deployed_codes_pointer->code      + page_length(icm_config->deployed_codes_pointer->length);
      icm_config->deployed_codes_pointer->top       = icm_config->deployed_codes_pointer->code_sign + sign_length(icm_config->deployed_codes_pointer->length);

      for (uint32_t i = 0, t; (t = i * PAGE_SIZE) < icm_config->deployed_codes_pointer->length; i++) {
        memcpy(icm_config->deployed_codes_pointer->code + t, icm_ram_return_tmp, PAGE_SIZE);
      }
#ifdef ICM_DEBUG
      icm_debug("deploy finish", 13);
#endif
    }

    icm_stack_pop();

    if (icm_stack_is_empty()) {
      cesm_state = CESM_IDLE;

      // Finish
      ECP *ecp = get_output_buffer();
      ecp->opcode = END;
      ecp->src = CONTROL;
      ecp->dest = HOST;
      ecp->func = end_func;
      ecp->src_offset = 0;
      ecp->dest_offset = 0;
      ecp->length = icm_config->immutable_page_length;
      build_outgoing_packet(sizeof(ECP));
#ifdef ICM_DEBUG
    icm_debug("idle", 4);
#endif
    } else {
      // Resume
      cesm_state = CESM_WAIT_FOR_MEMORY_COPY;
      if (icm_config->immutable_page_length) {
        icm_config->cesm_ready = 0;

        // Copy results to memory
        ECP ecp;
        ecp.opcode = COPY;
        ecp.src = OCM_IMMUTABLE_MEM;
        ecp.dest = OCM_MEM;
        ecp.func = 0;
        ecp.src_offset = 0;
        ecp.dest_offset = call_frame->ret_offset;
        ecp.length = call_frame->ret_size;
        evm_memory_copy(&ecp);
      } else {
        icm_config->cesm_ready = 1;
      }
    }
  } else if (cesm_state == CESM_WAIT_FOR_MEMORY_COPY) {
    // END
    // wait until copy finish
    if (icm_config->cesm_ready == 0) {
      evm_memory_copy(NULL);
      return;
    }
#ifdef ICM_DEBUG
    icm_debug("copy memory ready", 17);

    icm_debug(&call_frame->pc, 4);
    icm_debug(&call_frame->stack_size, 4);
#endif

    // Copy back EVM stack
    uint32_t new_stack_size = call_frame->stack_size - call_frame->num_of_params;
    *(uint32_t*)icm_raw_data_base = new_stack_size + 1;
    if (call_frame->call_end_func == OP_CREATE || call_frame->call_end_func == OP_CREATE2) {
      memset(icm_raw_data_base + 4 + 20, 0, 12);
      memcpy(icm_raw_data_base + 4, icm_config->deployed_codes_pointer->address, 20);
    } else {
      // set success
      memset(icm_raw_data_base + 4, 0, 32);
      *(uint8_t*)(icm_raw_data_base + 4) = (call_frame + 1)->call_end_func != OP_REVERT;
    }
    aes_decrypt(icm_raw_data_base + 4 + 32, call_frame->stack + 32 * call_frame->num_of_params, 32 * new_stack_size);
    evm_load_stack(1);

    {
      char tmp[100];
      int len = sprintf(tmp, "depth -- -> %d", call_frame - icm_config->call_stack);
      icm_debug(tmp, len);
    }
    if (!hash_verify(call_frame->stack_sign, icm_raw_data_base + 4 + 32, 32 * new_stack_size, STACK, 0, icm_config->hevm_pub)) {
      icm_debug("stack signature verification failed!", 36);
    }

    if (icm_config->calling_precompiled) {
      memcpy_b(evm_env_pc, &(call_frame->pc), 4);
      icm_config->calling_precompiled = 0; 
    }

    cesm_state = CESM_WAIT_FOR_BALANCE;
    icm_config->cesm_ready = 0;
    icm_switch_contract(
      call_frame->address,
      call_frame->storage_address,
      icm_config->zero
    );
  } else if (cesm_state == CESM_WAIT_FOR_BALANCE) {
    if (icm_config->cesm_ready == 0) {
      return;
    }

#ifdef ICM_DEBUG
    icm_debug("remainning value:", 17);
    icm_debug(icm_config->contract_balance_after_transfer, 32);
#endif

    // set balance
    memcpy_b(evm_env_balance, icm_config->contract_balance_after_transfer, 32);

    // resume
    cesm_state = CESM_IDLE;

    ECP ecp;
    ecp.opcode = CALL;
    ecp.src = HOST;
    ecp.dest = CONTROL;
    ecp.func = OP_RESUME;
    ecp.src_offset = 0;
    ecp.dest_offset = 0;
    ecp.length = 0;
    handle_ecp(&ecp);
  }
}

uint8_t icm_decrypt() {
  ECP *req = get_input_buffer() + 4;

  if (req->opcode == ICM) {
    if (req->func == ICM_CLEAR_STORAGE) {
      icm_clear_storage();
    } else if (req->func == ICM_SET_USER_PUB) {
      uECC_decompress(req->data, icm_config->user_pub, icm_config->curve);

      ECP *res = get_output_buffer();
      res->opcode = ICM;
      res->src = CONTROL;
      res->dest = HOST;
      res->func = ICM_SET_USER_PUB;
      res->src_offset = 0;
      res->dest_offset = 0;
      res->length = 29;
      uECC_compress(icm_config->hevm_pub, res->data, icm_config->curve);

      build_outgoing_packet(sizeof(ECP) + 29);
    } else if (req->func == ICM_SET_CONTRACT) {
      if (icm_config->contract_address_waiting_for_size &&
        memcmp(req->data, icm_config->contract_address_waiting_for_size, 20) == 0) {
        icm_config->contract_address_waiting_for_size = NULL;
        if (icm_config->found_deployed_code == NULL)
          icm_config->ext_code_size = req->length;
        memcpy(icm_config->contract_balance_after_transfer, req->data + 20, 32);
        icm_step();
      }  
    } else if (req->func == ICM_FINISH) {
#ifdef ICM_DEBUG
      icm_debug("received precompiled return value", 33);
      icm_debug(&(icm_config->immutable_page_length), 4);
#endif
      icm_step();
    }
    return 0;
  } else if (req->opcode == DEBUG) {  // only for debug mode, does not encrypt
    // do nothing
    return 1;
  } else if (req->opcode == CALL) {
    icm_tmp_test();

    icm_config->count_storage_records = 0;

    // check integrity, return 0 if failed, and the tx will not run

    // check stack hash
    // starts anew, the stack must be empty
    evm_clear_stack();
#ifdef ICM_DEBUG
    icm_debug("call", 4);
#endif

    // [TODO] check merkle proof of ENV values

    // check passed
    call_frame = icm_config->call_stack;

    memcpy_b(call_frame->address, evm_env_caller, sizeof(address_t));
    call_frame->storage_address = call_frame->address;
    call_frame->caller_address = icm_config->zero;
    call_frame->call_end_func = req->func;

#ifdef ICM_DEBUG
    icm_debug("load", 4);
#endif

    address_t address;
    uint32_t code_length, input_length;
    uint64_t gas;
    uint256_t value;

    memcpy_b(address, evm_env_address, sizeof(address_t));
    icm_config->found_deployed_code = icm_find_locally_deployed_contract_code(address);
    if (icm_config->found_deployed_code) {
      code_length = icm_config->found_deployed_code->length;
    } else {
      memcpy_b(&code_length, evm_env_code_size, 4);
    }
    memcpy_b(&input_length, evm_env_calldata_size, 4);
    memcpy_b(&gas, evm_env_gas, 8);
    memcpy_b(value, evm_env_value, sizeof(uint256_t));

#ifdef ICM_DEBUG
    icm_debug(address, 20);
    icm_debug(&code_length, 4);
    icm_debug(&input_length, 4);
#endif

    icm_stack_push(address, SELF_ADDRESS, call_frame->address, code_length, input_length, gas, value, NULL);

    return 1;
  } else if (req->opcode == END) {
    // External force quit
    reset_udp();
    
    return 1;
  } else {
    if (req->src == STORAGE) { // this request is sent from host
      icm_dump_storage();
      return 0;
    } else if (req->dest == STORAGE) {
      // load storage from host to OCM

      // storage cache-miss swapping response: two phases
      // 0. check in OCM
      //    which is processed locally and will never go through this function
      // 1. if still not found, the host will check in plaintext global storage
      
      // responses of dummy requests should be discarded
      if (memcmp(req->data + 4, icm_config->sload_real_key, sizeof(uint256_t))) {
#ifdef ICM_DEBUG
        icm_debug("dummy sload", 11);
#endif
        return 0;
      }

      // plaintext need not decrypt
      memcpy(icm_raw_data_base, req->data, req->length);
#ifdef ICM_DEBUG
      icm_debug(icm_raw_data_base, req->length);
#endif

      void *base = icm_raw_data_base;
      uint32_t num_of_items = *(uint32_t*)base;
      uint32_t offset = 4;
      icm_config->count_storage_records ++;

      for (uint32_t i = 0; i < num_of_items; i++, offset += 64) {
        uint32_t id = icm_find(base + offset);

        if (id == storage_prime) {
          icm_dump_storage();
          id = icm_find(base + offset);
        }

        // OCM need not encryption
        icm_temp_storage->valid[id] = 1;
        memcpy(&(icm_temp_storage->record[id].k), base + offset + 0 , 32);
        memcpy(&(icm_temp_storage->record[id].v), base + offset + 32, 32);
        memcpy(&(icm_temp_storage->record[id].v_origin), base + offset + 32, 32);
        // also, copy the address of the current contract
        memcpy(&(icm_temp_storage->record[id].a), call_frame->storage_address, sizeof(address_t));

#ifdef ICM_DEBUG
        icm_debug(&(icm_temp_storage->record[id].k), 32);
        icm_debug(&(icm_temp_storage->record[id].v), 32);
#endif
      }

      return 1;
    } else {  // memory like
      // the size of memory pages are always multiples of 16
      // so there is no need to pad content_length
      if (req->dest == ENV) {
        // plain text
        // [TODO] check integrity <del> by merkle tree </del>
        // [TODO] check integrity by USER signature
        memcpy(icm_raw_data_base, req->data, req->length);

#ifdef ICM_DEBUG
    icm_debug("recv env", 8);
#endif
      } else if (req->dest == CODE) { // After internalize, this will be code only
        call_frame->code_mark[mark_offset(req->dest_offset)] = 1 | (req->func ? 2 : 0);

#ifdef ICM_DEBUG
        {
          icm_debug("recv code", 9);
          // show current depth and address
          uint8_t tmp[1024];
          *(uint32_t*)tmp = (call_frame - icm_config->call_stack);
          memcpy(tmp + 4, call_frame->address, 20);
          icm_debug(tmp, 24);
          // show base offset
          icm_debug(&req->dest_offset, 4);
        }
#endif

        // this page is encrypted
        if (req->func) {
          aes_decrypt(icm_raw_data_base, req->data, req->length);
          char sign[64];
          memcpy(sign, req->data + req->length, 56);

          if (req->length < PAGE_SIZE) {
            memset(icm_raw_data_base + req->length, 0, PAGE_SIZE - req->length);
            memcpy(icm_config->buffer, icm_raw_data_base, PAGE_SIZE);
            aes_encrypt(call_frame->code + req->dest_offset, icm_config->buffer, PAGE_SIZE);
          } else {
            memcpy(call_frame->code + req->dest_offset, req->data, PAGE_SIZE);
          }
          // verify user hash
          if (!ecdsa_verify_page(sign, icm_raw_data_base, CODE, req->dest_offset, 0, icm_config->user_pub)) {
            icm_debug("user code page verification failed!", 35);
          }
          
        } else {
          // icm_debug("plaintext code", 14);
          memcpy(icm_raw_data_base, req->data, req->length);
          memset(icm_raw_data_base + req->length, 0, PAGE_SIZE - req->length);
          memcpy(call_frame->code + req->dest_offset, icm_raw_data_base, PAGE_SIZE);
          // [TODO] calculate whole code hash and send back to user
          // [TODO] prefetch
        }
        // icm_debug(icm_raw_data_base, PAGE_SIZE);
      } else if (req->dest == CALLDATA && call_frame == (icm_config->call_stack + 1)) { // After internalize, this will be code only
        call_frame->input_mark[mark_offset(req->dest_offset)] = 1;  // mark as valid
#ifdef ICM_DEBUG
        icm_debug("recv input", 10);
        icm_debug(&req->dest_offset, 4);  
#endif
        aes_decrypt(icm_raw_data_base, req->data, req->length);
        char sign[64];
        memcpy(sign, req->data + req->length, 56);
        if (req->length < PAGE_SIZE) {
          memset(icm_raw_data_base + req->length, 0, PAGE_SIZE - req->length);
          memcpy(icm_config->buffer, icm_raw_data_base, PAGE_SIZE);
          aes_encrypt(call_frame->input + req->dest_offset, icm_config->buffer, PAGE_SIZE);
        } else {
          memcpy(call_frame->input + req->dest_offset, req->data, PAGE_SIZE);
        }

        // verify user hash
        if (!ecdsa_verify_page(sign, icm_raw_data_base, CALLDATA, req->dest_offset, 0, icm_config->user_pub)) {
          icm_debug("user calldata page verification failed!", 39);
        }
      } else if (req->dest == STACK) {
#ifdef ICM_DEBUG
        icm_debug("recv stack", 10);
        icm_debug(req->data + 4, 32);
#endif
        // [TODO] Length has to be 0 or 1
        memcpy(icm_raw_data_base, req->data, req->length);
      } else if (req->dest == RETURNDATA && cesm_state == CESM_WAIT_FOR_PRECOMPILED_EXECUTION) {
#ifdef ICM_DEBUG
        icm_debug("recv precompiled results", 24);
#endif
        if (req->length < PAGE_SIZE) {
          memset(req->data + req->length, 0, PAGE_SIZE - req->length);
        }
        aes_encrypt(icm_config->immutable_page + req->dest_offset, req->data, req->length);
        if (icm_config->immutable_page_length < req->dest_offset + req->length)
          icm_config->immutable_page_length = req->dest_offset + req->length;
        return 0;
      }
      
      return 1;
    }
  }
}

uint8_t icm_encrypt(uint32_t length) {
  ECP *req = get_output_buffer();
  uint32_t content_length = length - sizeof(ECP);

  if (req->opcode == DEBUG) {  // only for debug mode, does not encrypt
    // do nothing
    build_outgoing_packet(length);
    return 1;
  } else if (req->opcode == QUERY) {
    OCMDeployedCodeFrame *p = icm_find_locally_deployed_contract_code(icm_raw_data_base);
    if (p) {
      if (req->func == 0x1b) {
        memcpy(icm_raw_data_base, &(p->length), 4);
        memset(icm_raw_data_base + 4, 0, sizeof(uint256_t) - 4);
#ifdef ICM_DEBUG
        icm_debug("found locally", 13);
        icm_debug(icm_raw_data_base, 32);
#endif
        return 1;
      }
      else if (req->func == 0x1f) {
        memcpy(icm_raw_data_base, p->code_hash, 32);
#ifdef ICM_DEBUG
        icm_debug("found locally", 13);
        icm_debug(icm_raw_data_base, 32);
#endif
        return 1;
      }
    }

    // plaintext params
    memcpy(req->data, icm_raw_data_base, content_length);
    build_outgoing_packet(sizeof(ECP) + content_length);
    return 0;
  } else if (req->opcode == CALL) {
    icm_call(req->func);
    return 0;
  } else if (req->opcode == END) {
    icm_debug("STORAGE cnt:", 12);
    icm_debug(&(icm_config->count_storage_records), 4);
    
    icm_end(req->func);
    return 0;
  } else {
    if (req->src == STORAGE) {
      if (req->opcode == COPY) {
        // copy plaintext storage from HEVM to OCM
        void *base = icm_raw_data_base;
        uint32_t num_of_items = *(uint32_t*)base;
        uint32_t offset = 4;

        for (uint32_t i = 0; i < num_of_items; i++, offset += 64) {
          uint32_t id = icm_find(base + offset);

          if (id == storage_prime) {
            icm_dump_storage();
            id = icm_find(base + offset);
          }

          // OCM need not encryption
          memcpy(&(icm_temp_storage->record[id].k), base + offset + 0 , 32);
          memcpy(&(icm_temp_storage->record[id].v), base + offset + 32, 32);
          // also, copy the address of the current contract
          memcpy(&(icm_temp_storage->record[id].a), call_frame->storage_address, sizeof(address_t));

#ifdef ICM_DEBUG
          icm_debug(&(icm_temp_storage->record[id].k), 32);
          icm_debug(&(icm_temp_storage->record[id].v), 32);
#endif
        }

        // nothing to be sent out
        // and no need for integrity protection
        return 1;
      } else {  // req->opcode == SWAP
        void *base = icm_raw_data_base;

        // before anything else
        // write the swapped-out record into OCM
        uint32_t num_of_items = *(uint32_t*)base;
        base += 4;
        if (num_of_items) {
          uint32_t id = icm_find(base);
          if (id == storage_prime) {
            uint8_t head[16];
            memcpy(head, get_output_buffer(), 16);
            icm_dump_storage();
            memcpy(get_output_buffer(), head, 16);

            id = icm_find(base);
          }
          
#ifdef ICM_DEBUG
          {
            icm_debug("OCM store", 9);
            icm_debug(base, 64);
            icm_debug(call_frame->storage_address, 20);
          }
#endif

          // OCM need no encryption
          icm_temp_storage->valid[id] = 1;
          memcpy(&(icm_temp_storage->record[id].k), base, 64);
          // also, copy the address of the current contract
          memcpy(&(icm_temp_storage->record[id].a), call_frame->storage_address, sizeof(address_t));

          base += 64;
        }

        // storage cache-miss swapping query: two phases
        // 0. check in OCM

        uint32_t id = icm_find(base + 4);
        
#ifdef ICM_DEBUG
        {
          icm_debug("OCM key check", 13);
          icm_debug(base + 4, 32);
          icm_debug(call_frame->storage_address, 20);
        }
#endif

        if (id != storage_prime && icm_temp_storage->valid[id]) {
          // found, do not send output request
          memcpy(icm_raw_data_base, base, 4 + 32);
          memcpy(icm_raw_data_base + 4 + 32, icm_temp_storage->record[id].v, 32);
          
          // evm_load_storage();
          return 1;
        }
        
        // 1. if still not found, generate plaintext dummy requests
        // record 
        memcpy(icm_config->sload_real_key, base + 4, sizeof(uint256_t));

        // since the swapped-out record has been saved in phase 0
        // we are not sending it again, instead set the output num_of_items to 0
        *(uint32_t*)req->data = 0;
        *(uint32_t*)(req->data + 4) = 1;
        req->length = 8 + 32;
        content_length = 8 + 32;

        // [TODO] send dummy requests
        memcpy(req->data + 8, base + 4, 32);
        // set_retry_send();
        build_outgoing_packet(sizeof(ECP) + content_length);
        return 0;
      }
    }
    else {
      // memory-like
      if (req->src == STACK) {
        if (req->func == 1) {
          // params
          // sent as plain text
          call_frame->num_of_params = call_frame->stack_size = *(uint32_t*)icm_raw_data_base;
          memcpy(call_frame->stack, icm_raw_data_base + 4, content_length - 4);
        } else {
          // sign entire stack (except params)
          hash_sign(call_frame->stack_sign, icm_raw_data_base + 4, content_length - 4, STACK, 0, icm_config->hevm_priv);
          {
            char tmp[100];
            int len = sprintf(tmp, "depth %d -> ++", call_frame - icm_config->call_stack);
            icm_debug(tmp, len);
          }

          // encrypt stack elements
          aes_encrypt(call_frame->stack + call_frame->stack_size * 32, icm_raw_data_base + 4, content_length - 4);
          call_frame->stack_size += *(uint32_t*)icm_raw_data_base;
        }
        return 1;
      } else {
#ifdef ICM_DEBUG
        icm_debug("icm swap", 8);
        {
          ECP tmp;
          memcpy(&tmp, req, 16);
          icm_debug(&tmp, 16);
        }
#endif
        uint8_t *target_page, *target_page_sign, *target_page_mark;
        uint32_t target_page_length;
        OCMStackFrame *target_frame;
        uint8_t target_page_type;

        if (req->src == OCM_MEM) {
          if (cesm_state == CESM_WAIT_FOR_INPUT_COPY) {
            target_page = (call_frame - 1)->memory;
            target_page_sign = (call_frame - 1)->memory_sign;
            target_page_length = (call_frame - 1)->memory_length;
            target_frame = (call_frame - 1);
          } else {
            target_page = call_frame->memory;
            target_page_sign = call_frame->memory_sign;
            target_page_length = call_frame->memory_length;
            target_frame = call_frame;
          }
          target_page_type = MEM;
        } else if (req->src == OCM_IMMUTABLE_MEM) {
          target_page = icm_config->immutable_page;
          target_page_sign = icm_config->immutable_page_sign;
          target_page_length = page_length(icm_config->immutable_page_length);
          target_page_type = icm_config->immutable_page_type;
        } else if (req->src == CODE) {
          target_page = call_frame->code;
          target_page_sign = call_frame->code_sign;
          target_page_mark = call_frame->code_mark;
          target_page_length = page_length(call_frame->code_length);
          target_page_type = CODE;
        } else if (req->src == CALLDATA) {
          target_page = call_frame->input;
          target_page_sign = call_frame->input_sign;
          target_page_mark = call_frame->input_mark;
          target_page_length = page_length(call_frame->input_length);
          target_page_type = CALLDATA;
        } else if (req->src == MEM) {
          target_page = call_frame->memory;
          target_page_sign = call_frame->memory_sign;
          target_page_length = call_frame->memory_length;
          target_frame = call_frame;
          target_page_type = MEM;
        }

        // copy to call_stack
        uint32_t cipher_length = 0;
        if (content_length) {
          if (req->src == MEM || req->src == OCM_MEM) {
            uint8_t zero[PAGE_SIZE];
            uint8_t init = 0;
            for (; target_frame->memory_length < req->src_offset; target_frame->memory_length += PAGE_SIZE) {
              memcpy(target_page + target_frame->memory_length, zero_page, PAGE_SIZE);
              if (!init) {
                init = 1;
                memset(zero, 0, PAGE_SIZE);
              }
              hash_sign_page(target_page_sign + sign_offset(target_frame->memory_length), zero, target_page_type, target_frame->memory_length, 0, icm_config->hevm_priv);
#ifdef ICM_DEBUG
              icm_debug(&target_page_type, 1);
              icm_debug(&(target_frame->memory_length), 4);
#endif
            }
            // and the copied out page
            if (target_frame->memory_length == req->src_offset)
              target_page_length = target_frame->memory_length += PAGE_SIZE;
          } else if (req->src == OCM_IMMUTABLE_MEM) {
            if (req->src_offset + PAGE_SIZE > icm_config->immutable_page_length) {
              uint32_t length = icm_config->immutable_page_length - req->src_offset; 
              memset(icm_raw_data_base + length, 0, PAGE_SIZE - length);
            }
          }
          if (req->src == OCM_IMMUTABLE_MEM && cesm_state == CESM_WAIT_FOR_PRECOMPILED_INPUT_COPY) {
#ifdef ICM_DEBUG
            icm_debug("precompiled input copy", 22);
#endif
            ECP *ecp = get_output_buffer();
            ecp->opcode = COPY;
            ecp->src = CALLDATA;
            ecp->dest = HOST;
            ecp->func = 2;
            ecp->src_offset = req->src_offset;
            ecp->dest_offset = req->dest_offset;
            ecp->length = content_length;
            memcpy(ecp->data, icm_raw_data_base, content_length);
            build_outgoing_packet(sizeof(ECP) + content_length);
            return 1;
          }

          int end = req->src == OCM_IMMUTABLE_MEM &&
                    cesm_state == CESM_WAIT_FOR_RETURN_COPY && icm_stack_is_root();

          if (end) {
            // sign with ecdsa
            ecdsa_sign_page(req->data + content_length, icm_raw_data_base, RETURNDATA, req->src_offset, 0, icm_config->hevm_priv);
          } else {
            // sign internally
            hash_sign_page(target_page_sign + sign_offset(req->src_offset), icm_raw_data_base, target_page_type, req->src_offset, 0, icm_config->hevm_priv);
#ifdef ICM_DEBUG
            icm_debug(&target_page_type, 1);
            icm_debug(&(req->src_offset), 4);
            icm_debug(&(target_frame->memory_length), 4);
#endif
          }

          cipher_length = aes_encrypt(target_page + req->src_offset, icm_raw_data_base, content_length);

          if (end) {
            // send out
            ECP *ecp = get_output_buffer();
            ecp->opcode = COPY;
            ecp->src = RETURNDATA;
            ecp->dest = HOST;
            ecp->func = 1;
            ecp->src_offset = req->src_offset;
            ecp->dest_offset = req->dest_offset;
            ecp->length = content_length;
            memcpy(ecp->data, target_page + req->src_offset, cipher_length);

            build_outgoing_packet(sizeof(ECP) + cipher_length + 56);
            return 1;
          }
        }

        // copy back to HEVM
        if (req->opcode == SWAP) {
          if (req->src == CODE || (req->src == CALLDATA && icm_stack_is_root())) {
            // potential buffer overflow attack ?
            if (req->dest_offset >= target_page_length) {
#ifdef ICM_DEBUG
              icm_debug(&(req->dest_offset), 4);
              icm_debug(&target_page_length, 4);
              icm_debug("overflow", 8);
#endif             
              memset(icm_raw_data_base, 0, PAGE_SIZE);
            } else if (target_page_mark[mark_offset(req->dest_offset)] & 1) { // valid
#ifdef ICM_DEBUG
              icm_debug("received", 8);
              icm_debug(icm_raw_data_base, PAGE_SIZE);
#endif
              // [TODO] check signature for calldata
              if (req->src != CODE || target_page_mark[mark_offset(req->dest_offset)] & 2) { // encrypted
                aes_decrypt(icm_raw_data_base, target_page + req->dest_offset, PAGE_SIZE);
              } else {
                // icm_debug("plaintext code", 14);
                memcpy(icm_raw_data_base, target_page + req->dest_offset, PAGE_SIZE);
              }
            } else if (req->src == CODE && icm_config->call_frame_pointer->locally_deployed_contract_code) {
#ifdef ICM_DEBUG
#endif             
              aes_decrypt(icm_raw_data_base, icm_config->call_frame_pointer->locally_deployed_contract_code->code + req->dest_offset, PAGE_SIZE);
            } else {
#ifdef ICM_DEBUG
              icm_debug("send out", 8);
#endif
              // pass out
              // set_retry_send();
              build_outgoing_packet(sizeof(ECP) + cipher_length + 16);
              return 0;
            }
          } else {
            // local
#ifdef ICM_DEBUG
            icm_debug("local", 6);
#endif
            if (req->dest_offset >= target_page_length) {
#ifdef ICM_DEBUG
              icm_debug("overflow", 8);
#endif
              memset(icm_raw_data_base, 0, PAGE_SIZE);
            } else {
#ifdef ICM_DEBUG
              icm_debug(&(req->dest_offset), 4);
              icm_debug(&target_page_length, 4);
              int t = (call_frame - icm_config->call_stack);
              icm_debug(&t, 4);
#endif        
              aes_decrypt(icm_raw_data_base, target_page + req->dest_offset, PAGE_SIZE);
              if (!hash_verify_page(target_page_sign + sign_offset(req->dest_offset), icm_raw_data_base, target_page_type, req->dest_offset, 0, icm_config->hevm_pub)) {
                icm_debug("page signature verification failed!", 35);
                icm_debug(&target_page_type, 1);
                icm_debug(&(req->dest_offset), 4);
                icm_debug(&(target_frame->memory_length), 4);
              }
            }
          } 
        }
      }
      return 1;
    }
  }
}

void prefetch() {
  
}
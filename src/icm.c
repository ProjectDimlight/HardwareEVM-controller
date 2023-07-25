#include "udp_server.h"
#include "evm_controller.h"
#include "icm_keys.h"

#define NUMBER_OF_DUMMIES 127
#define PAGE_SIZE 1024
#define SIGNATURE_LENGTH 56
#define PAGES(x) ((x - 1) / PAGE_SIZE + 1)
#define SELF_ADDRESS ((call_frame + 1)->address)

#define call_frame (icm_config->call_frame_pointer)
#define cesm_state (icm_config->cesm_current_state)

#define ENCRYPTION
// #define VERIFY_SIGNATURE

// these address spaces are mapped to secure on chip memory
void * const icm_raw_data_base          = (void*)0xFFFC0000ll;   // decrypted packet
void * const icm_temp_storage_base      = (void*)0xFFFD0000ll;   // temporary storage
void * const icm_config_base            = (void*)0xFFFE0000ll;   // system configuration and sensitive data
void * const icm_rt_base                = (void*)0xFFFF0000ll;   // runtime, stack and heap

uint8_t icm_ram_stack[4096 * PAGE_SIZE];
uint8_t icm_ram_memory_sign_tmp[64 * PAGE_SIZE];
uint8_t icm_ram_return_tmp[1024 * PAGE_SIZE];
uint8_t icm_ram_return_sign_tmp[64 * PAGE_SIZE];
uint8_t icm_ram_deployed_code[1024 * PAGE_SIZE];

ICMTempStorage * const icm_temp_storage = (ICMTempStorage*)0xFFFD0000ll;
ICMConfig      * const icm_config       = (ICMConfig*)0xFFFE0000ll;

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

///////////////////////////////////////////////////////////////////

uint32_t page_length(uint32_t length) {
  return PAGES(length) * PAGE_SIZE;
}

uint32_t sign_length(uint32_t length) {
  return PAGES(length) * 64;
}

uint32_t page_offset(uint32_t length) {
  return length / PAGE_SIZE * PAGE_SIZE;
}

uint32_t sign_offset(uint32_t length) {
  return length / PAGE_SIZE * 64;
}

uint32_t page_number(uint32_t length) {
  if (length == 0) {
    return 0;
  } else {
    return (length - 1) / PAGE_SIZE + 1;
  }
}

uint8_t icm_stack_is_empty() {
  return call_frame == icm_config->call_stack;
}

uint8_t icm_stack_is_root() {
  return call_frame == icm_config->call_stack + 1;
}

void icm_stack_push(address_t callee_address, address_p callee_storage_address, address_p callee_caller_address, uint32_t code_length, uint32_t input_length, uint64_t gas, uint256_t value) {
  uint8_t init = 0;
  if (icm_stack_is_empty()) {
    // the 0-th element in the stack is dummy header
    // which stores immutable metadata such as ORIGIN

    // init
    init = 1;
    call_frame->top = icm_ram_stack;

#ifdef ICM_DEBUG
    icm_debug("isroot", 6);
#endif
  } else {
    memcpy_b(&(call_frame->pc), evm_env_pc, 4);
    memcpy_b(&(call_frame->msize), evm_env_msize, 4);
    memcpy_b(&(call_frame->gas), evm_env_gas, 4);
    // does not update stack size, because it has been cleared while dumping out stack elements
    
    // copy memory signatures to stack
    // because memory length can vary through time
    call_frame->memory_sign = call_frame->memory + call_frame->memory_length;
    memcpy(call_frame->memory_sign, icm_ram_memory_sign_tmp, sign_length(call_frame->memory_length));
    call_frame->top = call_frame->memory_sign + sign_length(call_frame->memory_length);
  }
  
  // create a new frame
  void *base = call_frame->top;
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
  memcpy(call_frame->value, value, sizeof(uint256_t));

  call_frame->code        = base;
  call_frame->code_sign   = call_frame->code        + page_length(code_length);
  call_frame->input       = call_frame->code_sign   + sign_length(code_length);
  call_frame->input_sign  = call_frame->input       + page_length(input_length);
  call_frame->stack       = call_frame->input_sign  + sign_length(input_length);
  call_frame->stack_sign  = call_frame->stack       + 32 * 1024;
  call_frame->memory      = call_frame->stack_sign  + 64;
  call_frame->memory_sign = icm_ram_memory_sign_tmp;

  call_frame->locally_deployed_contract_code = NULL;
  for (OCMDeployedCodeFrame *p = icm_config->deployed_codes + 1; p <= icm_config->deployed_codes_pointer; p++) {
    if (memcmp(p->address, icm_config->call_frame_pointer->address, 20) == 0) {
      // using deployed code
      call_frame->locally_deployed_contract_code = p;
      break;      
    }
  }

  for (uint32_t i = 0; i < sign_length(code_length); i += 64) {
    call_frame->code_sign[i + 63] = 0;
  }
  for (uint32_t i = 0; i < sign_length(input_length); i += 64) {
    call_frame->input_sign[i + 63] = 0;
  }

  if (!init) {
    // Set ENV
    memcpy_b(evm_env_code_size,         &(call_frame->code_length), 4);
    memcpy_b(evm_env_calldata_size,     &(call_frame->input_length), 4);
    memcpy_b(evm_env_msize,             &(call_frame->msize), 4);
    memcpy_b(evm_env_pc,                &(call_frame->pc), 4);
    memcpy_b(evm_env_gas,               &(call_frame->gas), 4);
    memcpy_b(evm_env_returndata_size,   &(call_frame->return_length), 4);
    memcpy_b(evm_env_value,               call_frame->value, 4);
    
    memcpy_b(evm_env_address, call_frame->address, sizeof(address_t));
    memcpy_b(evm_env_caller,  call_frame->caller_address, sizeof(address_t));
  }
}

void icm_stack_pop() {
  call_frame--;

  if (!icm_stack_is_empty()) {
    // Recover memory signatures from callstack
    memcpy(icm_ram_memory_sign_tmp, call_frame->memory_sign, call_frame->top - call_frame->memory_sign);

    // Recover ENV
    memcpy_b(evm_env_code_size,         &(call_frame->code_length), 4);
    memcpy_b(evm_env_calldata_size,     &(call_frame->input_length), 4);
    // memcpy_b(evm_env_stack_size,        &(call_frame->stack_size), 4);
    memcpy_b(evm_env_msize,             &(call_frame->msize), 4);
    memcpy_b(evm_env_pc,                &(call_frame->pc), 4);
    memcpy_b(evm_env_gas,               &(call_frame->gas), 4);
    memcpy_b(evm_env_returndata_size,   &(call_frame->return_length), 4);
    memcpy_b(evm_env_value,               call_frame->value, 4);
    
    memcpy_b(evm_env_address, call_frame->address, sizeof(address_t));
    memcpy_b(evm_env_caller,  call_frame->caller_address, sizeof(address_t));
  }
}

// CALL: stack_push, memcpy (last.mem -> this.input), run
// END:  memcpy (this.mem -> returndata_tmp) , stack_pop, memcpy (returndata_tmp -> this.mem), resume

///////////////////////////////////////////////////////////////////

uint32_t padded_size(uint32_t size, uint32_t block_size) {
  if (size == 0) return 0;
  uint32_t number_of_blocks = ((size - 1) / block_size + 1);
  return number_of_blocks * block_size;
}

void aes_decrypt(uint8_t *out, uint8_t *in, uint32_t size) {
  AES_ctx_set_iv(&(icm_config->aes_inst), iv);
  size = padded_size(size, 16);
  memcpy(out, in, size);
  AES_CBC_decrypt_buffer(&(icm_config->aes_inst), out, size);
}

void aes_decrypt_stack(uint8_t *out, uint8_t *in, uint32_t size) {
  AES_ctx_set_iv(&(icm_config->aes_inst), iv);
  memcpy(out, in, size);
  for (uint32_t i = size; i; i -= 32) {
    AES_CBC_decrypt_buffer(&(icm_config->aes_inst), out + i - 32, 32);
  }
}

uint32_t aes_encrypt(uint8_t *out, uint8_t *in, uint32_t size) {
  AES_ctx_set_iv(&(icm_config->aes_inst), iv);
  size = padded_size(size, 16);
  AES_CBC_encrypt_buffer(&(icm_config->aes_inst), in, size);
  memcpy(out, in, size);
  return size;
}

///////////////////////////////////////////////////////////////////

uint8_t *ecdsa_hash(uint8_t *data, uint32_t size) {
  /*
  sha3_context *c = &sha_inst;
  sha3_Init256(c);
  sha3_Update(c, data, size);
  return sha3_Finalize(c);
  */
  return NULL;
}

// void ecdsa_sign(uint8_t *out, uint8_t *data, uint32_t size) {
//   uint8_t *hash = ecdsa_hash(data, size);
//   uECC_sign(icm_config->hevm_priv, hash, 32, out, icm_config->curve);
// }

// int ecdsa_verify(uint8_t *in, uint8_t *data, uint32_t size, int is_user_key) {
//   uint8_t *hash = ecdsa_hash(data, size);
//   return uECC_verify(is_user_key ? icm_config->user_pub : icm_config->hevm_pub, hash, 32, in, icm_config->curve);
// }

///////////////////////////////////////////////////////////////////

void icm_init() {
  // ZERO
  memset(icm_config->zero, 0, 64);

  // AES
  AES_init_ctx_iv(&(icm_config->aes_inst), user_aes, iv);
  memset(zero_page, 0, sizeof(zero_page));
  aes_encrypt(zero_page, zero_page, PAGE_SIZE);

  // ECDSA
  //curve = uECC_secp224r1();
  //uECC_make_key(hevm_pub, hevm_priv, curve);

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

// void icm_get_address_for_create(void *address);

void icm_get_address_for_create2(void *address_output, void *code_hash_output, void *sender_address, void *salt) {
  // first hash the code
  // The code is the content of the returndata
  sha3_context* c = &(icm_config->c);
  sha3_Init256(&c);
  for (uint32_t i = 0; i < icm_config->immutable_page_length; i += PAGE_SIZE) {
    uint32_t len = i + PAGE_SIZE < icm_config->immutable_page_length ? PAGE_SIZE : icm_config->immutable_page_length - i;
    aes_decrypt(icm_raw_data_base, icm_ram_return_tmp, len);
    sha3_Update(&c, icm_raw_data_base, len);
  }
  void *code_hash = sha3_Finalize(&c);
  memcpy(code_hash_output, code_hash, 32);

  sha3_Init256(&c);
  uint8_t head = 0xff;
  sha3_Update(&c, &head, 1);
  sha3_Update(&c, sender_address, sizeof(address_t));
  sha3_Update(&c, salt, sizeof(uint256_t));
  sha3_Update(&c, code_hash_output, sizeof(uint256_t));
  void *address = sha3_Finalize(&c);
#ifdef ICM_DEBUG
  icm_debug("deployaddr", 10);
  icm_debug(address, sizeof(address_t));
#endif
  memcpy(address_output, address + 12, sizeof(address_t));
}

///////////////////////////////////////////////////////////////////

void icm_call(uint8_t func) {
  // CALL
  // get next level code size
  call_frame->call_end_func = func;
  uint8_t *evm_stack = call_frame->stack;
  cesm_state = CESM_WAIT_FOR_CODE_SIZE;

  if (func == OP_CREATE || func == OP_CREATE2) {
    // CREATE: code is local, calldata is none
    icm_config->cesm_ready = 1;
    icm_config->immutable_page_length = *(uint32_t*)(evm_stack + 64);  // size
#ifdef ICM_DEBUG
    icm_debug("page_length", 11);
    icm_debug(&(icm_config->immutable_page_length), sizeof(uint32_t));
#endif
  } else {
    // call target address, query from host
    // send ICM_SET_CONTRACT
    ECP *ecp = get_output_buffer();
    ecp->opcode = ICM;
    ecp->src = CONTROL;
    ecp->dest = HOST;
    ecp->func = ICM_SET_CONTRACT;
    ecp->src_offset = 0;
    ecp->dest_offset = 0;
    ecp->length = sizeof(address_t) * 2;
    memcpy(ecp->data, evm_stack + 32, sizeof(address_t));
    if (func == OP_CALLCODE || func == OP_DELEGATECALL) {
      // delegatecall use caller's storage
      memcpy(ecp->data + sizeof(address_t), call_frame->address, sizeof(address_t));
    } else {
      memcpy(ecp->data + sizeof(address_t), evm_stack + 32, sizeof(address_t));
    }
    build_outgoing_packet(sizeof(ECP) + ecp->length);

    icm_config->cesm_ready = 0;
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
  icm_config->immutable_page = icm_ram_return_tmp;
  icm_config->immutable_page_sign = icm_ram_return_sign_tmp;
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

#ifdef ICM_DEBUG
    icm_debug("return", 6);
    icm_debug("src", 3);
    icm_debug(&(ecp.src_offset), 4);
    icm_debug("length", 6);
    icm_debug(&(ecp.length), 4);
#endif

    evm_memory_copy(&ecp);
  } else {
    // no need for copy
    icm_config->cesm_ready = 1;
    icm_config->immutable_page_length = 0;
  }
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
    // wait until code size is received
    if (icm_config->cesm_ready == 0) {
      if (call_frame->call_end_func == OP_CREATE ||
          call_frame->call_end_func == OP_CREATE2)
      evm_memory_copy(NULL);
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
      callee_storage_address = (func == OP_CALLCODE ? call_frame->address : SELF_ADDRESS);
      callee_caller_address = call_frame->address;
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
      callee_storage_address = (func == OP_DELEGATECALL ? call_frame->address : SELF_ADDRESS);
      callee_caller_address = (func == OP_DELEGATECALL ? call_frame->caller_address : call_frame->address);
      value = (func == OP_DELEGATECALL ? call_frame->value : icm_config->zero);
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
      value = *(uint32_t*)(evm_stack);
      code_length = icm_config->immutable_page_length;
      input_length = 0;
      offset = *(uint32_t*)(evm_stack + 32);
      size = *(uint32_t*)(evm_stack + 32 * 2);
      call_frame->ret_offset = 0;
      call_frame->ret_size = 0;
    }

    // stack push
    icm_stack_push(callee_address, callee_storage_address, callee_caller_address, code_length, input_length, gas, value);
#ifdef ICM_DEBUG
    icm_debug("address:", 8);
    icm_debug(callee_address, 20);
    icm_debug(callee_storage_address, 20);
    icm_debug(callee_caller_address, 20);
    
    icm_debug("length:", 7);
    icm_debug(&code_length, 4);
    icm_debug(&input_length, 4);
#endif

    // copy memory as code (CREATE) or input (CALL)
    if (func == OP_CREATE || func == OP_CREATE2) {  
      icm_config->immutable_page = call_frame->code;
      icm_config->immutable_page_sign = call_frame->code_sign;
      icm_config->immutable_page_length = call_frame->code_length;
      for (uint32_t i = 0; i < page_number(call_frame->code_length); i++)
        call_frame->code_sign[i * 64 + 63] = 1;
    } else {
      icm_config->immutable_page = call_frame->input;
      icm_config->immutable_page_sign = call_frame->input_sign;  
      icm_config->immutable_page_length = call_frame->input_length;
    }
    ECP ecp;
    ecp.opcode = COPY;
    ecp.src = OCM_MEM;
    ecp.dest = OCM_IMMUTABLE_MEM;
    ecp.func = 0;
    ecp.src_offset = offset;
    ecp.dest_offset = 0;
    ecp.length = size;
    cesm_state = CESM_WAIT_FOR_INPUT_COPY;
    evm_memory_copy(&ecp);
  } else if (cesm_state == CESM_WAIT_FOR_INPUT_COPY) {
    // CALL
    // wait until copy finish
    if (icm_config->cesm_ready == 0) {
      evm_memory_copy(NULL);
      return;
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

    // start
    ECP ecp;
    ecp.opcode = CALL;
    ecp.src = HOST;
    ecp.dest = CONTROL;
    ecp.func = (call_frame - 1)->call_end_func;
    ecp.src_offset = 0;
    ecp.dest_offset = 0;
    ecp.length = 0;
    cesm_state = CESM_IDLE;
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

    uint8_t end_func = call_frame->call_end_func;
    icm_stack_pop();

    if (call_frame->call_end_func == OP_CREATE || call_frame->call_end_func == OP_CREATE2) {
#ifdef ICM_DEBUG
    icm_debug("deploy", 6);
#endif
      // The return value is the code to be deployed
      icm_config->deployed_codes_pointer++;
      void *salt = *(uint32_t*)(call_frame->stack + 32 * 3);
      void *sender_address = call_frame->address;
      icm_get_address_for_create2(icm_config->deployed_codes_pointer->address, icm_config->deployed_codes_pointer->code_hash, sender_address, salt);
      icm_config->deployed_codes_pointer->length    = icm_config->immutable_page_length;
      icm_config->deployed_codes_pointer->code      = (icm_config->deployed_codes_pointer - 1)->top;
      icm_config->deployed_codes_pointer->code_sign = icm_config->deployed_codes_pointer->code      + page_length(icm_config->deployed_codes_pointer->length);
      icm_config->deployed_codes_pointer->top       = icm_config->deployed_codes_pointer->code_sign + sign_length(icm_config->deployed_codes_pointer->length);
    
      for (uint32_t i = 0, t; (t = i * PAGE_SIZE) < icm_config->deployed_codes_pointer->length; i++) {
        memcpy(icm_config->deployed_codes_pointer->code + t, icm_ram_return_tmp, PAGE_SIZE);
        memcpy(icm_config->deployed_codes_pointer->code_sign + i * 64, icm_ram_return_sign_tmp, 64);
      }
    }

    if (icm_stack_is_empty()) {
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
      cesm_state = CESM_IDLE;

#ifdef ICM_DEBUG
    icm_debug("idle", 4);
#endif
    } else {
      // Resume
      cesm_state = CESM_WAIT_FOR_MEMORY_COPY;
      if (icm_config->immutable_page_length) {
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
        icm_config->cesm_ready = 0;
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
    uint32_t new_stack_size = call_frame->stack_size - call_frame->num_of_params + 1;
    *(uint32_t*)icm_raw_data_base = new_stack_size;
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
      ECP *ecp = get_output_buffer();
      ecp->opcode = ICM;
      ecp->src = CONTROL;
      ecp->dest = HOST;
      ecp->func = ICM_SET_CONTRACT;
      ecp->src_offset = 0;
      ecp->dest_offset = 0;
      ecp->length = sizeof(address_t) * 2;
      memcpy(ecp->data, call_frame->address, sizeof(address_t));
      memcpy(ecp->data + sizeof(address_t), call_frame->storage_address, sizeof(address_t));
      build_outgoing_packet(sizeof(ECP) + ecp->length);
    }

    // resume
    ECP ecp;
    ecp.opcode = CALL;
    ecp.src = HOST;
    ecp.dest = CONTROL;
    ecp.func = OP_RESUME;
    ecp.src_offset = 0;
    ecp.dest_offset = 0;
    ecp.length = 0;
    cesm_state = CESM_IDLE;
    handle_ecp(&ecp);
  }
}

uint8_t icm_decrypt() {
  ECP *req = get_input_buffer();
  
  if (req->opcode == ICM) {
    if (req->func == ICM_CLEAR_STORAGE) {
      icm_clear_storage();
    } else if (req->func == ICM_SET_USER_PUB) {
      // uECC_decompress(req->data, icm_config->user_pub, uECC_secp224r1());
    } else if (req->func == ICM_SET_CONTRACT) {
      icm_config->ext_code_size = req->length;
      icm_step();
    }
    return 0;
  } else if (req->opcode == DEBUG) {  // only for debug mode, does not encrypt
    // do nothing
    return 1;
  } else if (req->opcode == CALL) {
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
    memcpy_b(&code_length, evm_env_code_size, 4);
    memcpy_b(&input_length, evm_env_calldata_size, 4);
    memcpy_b(&gas, evm_env_code_size, 8);
    memcpy_b(value, evm_env_code_size, sizeof(uint256_t));

#ifdef ICM_DEBUG
    icm_debug(address, 20);
    icm_debug(&code_length, 4);
    icm_debug(&input_length, 4);
#endif

    icm_stack_push(address, SELF_ADDRESS, call_frame->address, code_length, input_length, gas, value);

    return 1;
  } else if (req->opcode == END) {
    // External force quit
    return 1;
  } else {
    if (req->src == STORAGE) { // this request is sent from host
      // dump storage from OCM to HOST
      ECP *res = get_output_buffer();
      memcpy(res, req, sizeof(ECP));

      uint64_t count = 0, content_length = 4;
      for (uint64_t i = 0; i < storage_prime; i++)
      if (icm_temp_storage->valid[i]) {
        memcpy(icm_raw_data_base + content_length, &(icm_temp_storage->record[i]), 84);
        count++; content_length += 84;
      }
      // finalize: send remaining records
      res->func = 1;
      res->length = content_length;
      *(uint32_t*)res->data = count;

      // encrypt storage elements
      uint32_t sign_offset = 4 + aes_encrypt(req->data + 4, icm_raw_data_base + 4, content_length - 4);
      content_length = sign_offset;

      build_outgoing_packet(sizeof(ECP) + content_length);
      return 0;
    } else if (req->dest == STORAGE) {
      // load storage from host to OCM

      // storage cache-miss swapping response: two phases
      // 0. check in OCM
      //    which is processed locally and will never go through this function
      // 1. if still not found, the host will check in plaintext global storage
      
      // responses of dummy requests should be discarded
      if (memcmp(req->data + 4, icm_config->sload_real_key, sizeof(uint256_t))) {
        return 0;
      }

      // [TODO] check merkle proof

      // plaintext need not decrypt
      memcpy(icm_raw_data_base, req->data, req->length);
      return 1;
    } else {  // memory like
      // the size of memory pages are always multiples of 16
      // so there is no need to pad content_length
      if (req->dest == ENV) {
        // plain text
        // [TODO] check integrity by merkle tree
        memcpy(icm_raw_data_base, req->data, req->length);

#ifdef ICM_DEBUG
    icm_debug("recv env", 8);
#endif
      } else if (req->dest == CODE) { // After internalize, this will be code only
        memcpy(call_frame->code + req->dest_offset, req->data, padded_size(req->length, 16));
        call_frame->code_sign[sign_offset(req->dest_offset) + 63] = 1;  // mark as valid
#ifdef ICM_DEBUG
    icm_debug("recv code", 9);
#endif

        aes_decrypt(icm_raw_data_base, req->data, req->length);
      } else if (req->dest == CALLDATA && call_frame == (icm_config->call_stack + 1)) { // After internalize, this will be code only
        memcpy(call_frame->input + req->dest_offset, req->data, padded_size(req->length, 16));
        call_frame->input_sign[sign_offset(req->dest_offset) + 63] = 1;  // mark as valid

        aes_decrypt(icm_raw_data_base, req->data, req->length);
      }
      /*
      memcpy(get_output_buffer(), "echo", 4);
      memcpy(get_output_buffer() + 4, icm_raw_data_base, req->length);
      build_outgoing_packet(4 + req->length);
      */
      
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
    if (req->func == 0x1f) {
      for (OCMDeployedCodeFrame *p = icm_config->deployed_codes + 1; p <= icm_config->deployed_codes_pointer; p++) {
        if (memcmp(p->address, icm_raw_data_base, 20) == 0) {
          memcpy(icm_raw_data_base, p->code_hash, 32);
          return 1;
        }
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
            // [TODO] OCM full swap
          }

          // OCM need not encryption
          icm_temp_storage->valid[id] = 1;
          memcpy(&(icm_temp_storage->record[id]), base + offset, 64);
          // also, copy the address of the current contract
          memcpy(&(icm_temp_storage->record[id].a), call_frame->storage_address, sizeof(address_t));
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
            // [TODO] OCM full swap
          }

          // OCM need no encryption
          icm_temp_storage->valid[id] = 1;
          memcpy(&(icm_temp_storage->record[id]), base, 64);
          // also, copy the address of the current contract
          memcpy(&(icm_temp_storage->record[id].a), call_frame->storage_address, sizeof(address_t));

          base += 64;
        }

        // storage cache-miss swapping query: two phases
        // 0. check in OCM

        uint32_t id = icm_find(base + 4);
        if (icm_temp_storage->valid[id]) {
          // found, do not send output request
          memcpy(icm_raw_data_base, base, 4 + 32);
          memcpy(icm_raw_data_base + 4 + 32, icm_temp_storage->record[id].v, 32);
          
          evm_load_storage();
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
        build_outgoing_packet(sizeof(ECP) + content_length);
        return 0;
      }
    }
    else {
      // memory-like
      if (req->src == STACK) {
        if (req->func == 1) {
          call_frame->num_of_params = call_frame->stack_size = *(uint32_t*)icm_raw_data_base;
          memcpy(call_frame->stack, icm_raw_data_base + 4, content_length - 4);
        } else {
          // [TODO] sign entire stack (except params)
          // encrypt stack elements
          aes_encrypt(call_frame->stack + call_frame->stack_size * 32, icm_raw_data_base + 4, content_length - 4);
          call_frame->stack_size += *(uint32_t*)icm_raw_data_base;
        }
        return 1;
      } else {
        uint8_t *target_page, *target_page_sign;
        uint32_t target_page_length;
        OCMStackFrame *target_frame;
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
        } else if (req->src == OCM_IMMUTABLE_MEM) {
          target_page = icm_config->immutable_page;
          target_page_sign = icm_config->immutable_page_sign;
          target_page_length = page_length(icm_config->immutable_page_length);
        } else if (req->src == CODE) {
          target_page = call_frame->code;
          target_page_sign = call_frame->code_sign;
          target_page_length = page_length(call_frame->code_length);
        } else if (req->src == CALLDATA) {
          target_page = call_frame->input;
          target_page_sign = call_frame->input_sign;
          target_page_length = page_length(call_frame->input_length);
        } else if (req->src == MEM) {
          target_page = call_frame->memory;
          target_page_sign = call_frame->memory_sign;
          target_page_length = call_frame->memory_length;
          target_frame = call_frame;
        }

        // copy to call_stack
        if (content_length) {
          if (req->src == MEM || req->src == OCM_MEM) {
            for (; target_frame->memory_length < req->src_offset; target_frame->memory_length += PAGE_SIZE) {
              memcpy(target_page + target_frame->memory_length, zero_page, PAGE_SIZE);
            }
            // and the copied out page
            target_page_length = target_frame->memory_length += PAGE_SIZE;
          }
          uint32_t cipher_length = aes_encrypt(target_page + req->src_offset, icm_raw_data_base, content_length);
          if (cesm_state == CESM_WAIT_FOR_RETURN_COPY && 
              req->src == OCM_IMMUTABLE_MEM &&
              icm_stack_is_root()
          ) {
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
            build_outgoing_packet(sizeof(ECP) + cipher_length);
            return 1;
          }
        }

        // copy back to HEVM
        if (req->opcode == SWAP) {
          if (req->src == CODE || (req->src == CALLDATA && icm_stack_is_root())) {
            // potential buffer overflow attack ?
            if (req->dest_offset >= target_page_length) {
              memset(icm_raw_data_base, 0, PAGE_SIZE);
            } else if (target_page_sign[sign_offset(req->dest_offset) + 63] != 0) { // valid
              aes_decrypt(icm_raw_data_base, target_page + req->dest_offset, PAGE_SIZE);
            } else if (req->src == CODE && icm_config->call_frame_pointer->locally_deployed_contract_code) {
              aes_decrypt(icm_raw_data_base, icm_config->call_frame_pointer->locally_deployed_contract_code->code + req->dest_offset, PAGE_SIZE);
            } else {
              // pass out
              build_outgoing_packet(sizeof(ECP));
              return 0;
            }
          } else {
            if (req->dest_offset >= target_page_length) {
              memset(icm_raw_data_base, 0, PAGE_SIZE);
            } else {
              aes_decrypt(icm_raw_data_base, target_page + req->dest_offset, PAGE_SIZE);
            }
          } 
        }
      }
      return 1;
    }
  }
}

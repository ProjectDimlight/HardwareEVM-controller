#include "udp_server.h"
#include "evm_controller.h"
#include "icm_keys.h"

#define NUMBER_OF_DUMMIES 127
#define PAGE_SIZE 1024
#define SIGNATURE_LENGTH 56

#define ENCRYPTION

// these address spaces are mapped to secure on chip memory
void *icm_raw_data_base         = (void*)0xFFFC0000ll;   // decrypted packet
void *icm_temp_storage_base     = (void*)0xFFFD0000ll;   // temporary storage
void *icm_config_base           = (void*)0xFFFE0000ll;   // system configuration and sensitive data
void *icm_rt_base               = (void*)0xFFFF0000ll;   // runtime, stack and heap

ICMTempStorage *icm_temp_storage= (ICMTempStorage*)0xFFFD0000ll;
ICMConfig      *icm_config      = (ICMConfig*)0xFFFE0000ll;

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
  uint32_t hash = icm_hash(icm_config->contract_address, key);
  uint32_t cnt = 0;
  for (;
      cnt < storage_prime &&
      icm_temp_storage->valid[hash] && (
      memcmp(icm_temp_storage->record[hash].a, icm_config->contract_address, sizeof(address_t)) != 0 ||
      memcmp(icm_temp_storage->record[hash].k, key, sizeof(uint256_t)) != 0);
    hash = (hash + 1) % storage_prime, cnt++);

  if (cnt == storage_prime) 
    return storage_prime;
  else 
    return hash;
}

///////////////////////////////////////////////////////////////////

void icm_init() {
  // AES
  AES_init_ctx_iv(&(icm_config->aes_inst), user_aes, iv);

  // ECDSA
  curve = uECC_secp224r1();
  uECC_make_key(hevm_pub, hevm_priv, curve);
}

uint32_t padded_size(uint32_t size, uint32_t block_size) {
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
  sha3_context *c = &sha_inst;
  sha3_Init256(c);
  sha3_Update(c, data, size);
  return sha3_Finalize(c);
}

void ecdsa_sign(uint8_t *out, uint8_t *data, uint32_t size) {
  uint8_t *hash = ecdsa_hash(data, size);
  uECC_sign(icm_config->hevm_priv, hash, 32, out, icm_config->curve);
}

int ecdsa_verify(uint8_t *in, uint8_t *data, uint32_t size, int is_user_key) {
  uint8_t *hash = ecdsa_hash(data, size);
  return uECC_verify(is_user_key ? icm_config->user_pub : icm_config->hevm_pub, hash, 32, in, icm_config->curve);
}

///////////////////////////////////////////////////////////////////

void icm_clear_storage() {
  memset(icm_temp_storage->valid, 0, sizeof(icm_temp_storage->valid));
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

uint8_t icm_decrypt() {
  ECP *req = get_input_buffer();
  
  if (req->opcode == ICM) {
    if (req->func == ICM_CLEAR_STORAGE) {
      icm_clear_storage();
    } else if (req->func == ICM_SET_USER_PUB) {
      uECC_decompress(req->data, icm_config->user_pub, uECC_secp224r1());
      // icm_init();
    }
    return 0;
  } else if (req->opcode == DEBUG) {  // only for debug mode, does not encrypt
    // do nothing
    return 1;
  } else if (req->opcode == CALL) {
    // memorize the contract address
    memcpy(icm_config->contract_address, req->data, sizeof(address_t));

    // check integrity, return 0 if failed, and the tx will not run

    // check stack hash
    if (req->func == 0) {
      // if start anew, the stack must be empty
      uint32_t* stackSize = (uint32_t*)(evm_env_addr + 0x1c0);
      if (*stackSize != 0) {
        return 0;
      }
    } else {
      if (!icm_config->stack_integrity_valid) {
        return 0;
      }
    }
    // clear
    icm_config->stack_integrity_valid = 0;

    // [TODO] check merkle proof of ENV values

    return 1;
  } else if (req->opcode == END) {
    return 1;
  } else {
    uint8_t *signature = req->data + req->length;
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
      // even if there are no more records, we still have to send out a request
      // with res->func set to 1, indicating the end
      res->func = 1;
      res->length = content_length;
      *(uint32_t*)res->data = count;
#ifdef ENCRYPTION 
      // encrypt storage elements
      uint32_t sign_offset = 4 + aes_encrypt(req->data + 4, icm_raw_data_base + 4, content_length - 4);
      // sign entire storage
      ecdsa_sign(req->data + sign_offset, icm_raw_data_base + 4, content_length - 4);
      content_length = sign_offset + 32;
#else
      memcpy(res->data + 4, icm_raw_data_base + 4, content_length - 4);
#endif
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
#ifdef ENCRYPTION
      // the size of memory pages and stack elements are always multiples of 16
      // so there is no need to pad content_length
      if (req->dest == STACK) {
        if (req->func == 0) {
          // plain text, do not decrypt
          memcpy(icm_raw_data_base, req->data, req->length);

          // [TODO] check integrity
          // if it is a reply for QUERY, check merkle proof
          // if it is the result of CREATE or CALL we can only trust it
        } else {
          // there is a 4-byte "num_of_items" field before stack elements

          *(uint32_t*)icm_raw_data_base = *(uint32_t*)req->data;
          aes_decrypt_stack(icm_raw_data_base + 4, req->data + 4, req->length - 4);
          if (!ecdsa_verify(req->data + req->length, icm_raw_data_base + 4, req->length - 4, 0)) {
            return 0;
          }
          icm_config->stack_integrity_valid = 1;
        }
      } else if (req->src == HOST && (req->dest == MEM || req->dest == OCM_MEM) && req->func == 0) {
        // a blank page
        memset(icm_raw_data_base, 0, 1024);
        req->length = 1024;
      } else if (req->dest == ENV) {
        // plain text
        // [TODO] check integrity by merkle tree
        memcpy(icm_raw_data_base, req->data, req->length);
      } else {
        // cipher text
        aes_decrypt(icm_raw_data_base, req->data, req->length);
        int is_user_key = req->dest == CODE || req->dest == CALLDATA;
        if (!ecdsa_verify(req->data + req->length, icm_raw_data_base + 4, req->length - 4, is_user_key)) {
          return 0;
        }
        icm_config->stack_integrity_valid = 1;
        
        /*
        memcpy(get_output_buffer(), "echo", 4);
        memcpy(get_output_buffer() + 4, icm_raw_data_base, req->length);
        build_outgoing_packet(4 + req->length);
        */
      }
#else
      memcpy(icm_raw_data_base, req->data, req->length);
#endif
      
      return 1;
    }
  }
}

void icm_encrypt(uint32_t length) {
  ECP *req = get_output_buffer();
  uint32_t content_length = length - sizeof(ECP);

  if (req->opcode == DEBUG) {  // only for debug mode, does not encrypt
    // do nothing
    build_outgoing_packet(length);
  } else if (req->opcode == QUERY || req->opcode == CALL || req->opcode == END) {
    // plaintext params
    memcpy(req->data, icm_raw_data_base, content_length);
    build_outgoing_packet(sizeof(ECP) + content_length);

    // [TODO] Store parameters in local stack to guarantee integrity
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
          memcpy(&(icm_temp_storage->record[id].a), icm_config->contract_address, sizeof(address_t));
        }

        // nothing to be sent out
        // and no need for integrity protection
        return;
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
          memcpy(&(icm_temp_storage->record[id].a), icm_config->contract_address, sizeof(address_t));

          base += 64;
        }

        // storage cache-miss swapping query: two phases
        // 0. check in OCM

        uint32_t id = icm_find(base + 4);
        if (icm_temp_storage->valid[id]) {
          // found, do not send output request
          ECP res;
          res.opcode = COPY;
          res.src = HOST;
          res.dest = STORAGE;

          memcpy(icm_raw_data_base, base, 4 + 32);
          memcpy(icm_raw_data_base + 4 + 32, icm_temp_storage->record[id].v, 32);
          
          ecp(&res);
          return;
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

#ifdef ENCRYPTION
        // [TODO] send dummy requests

        memcpy(req->data + 8, base + 4, 32);
        build_outgoing_packet(sizeof(ECP) + content_length);
#else
        memcpy(req->data + 8, base + 4, 32);
        build_outgoing_packet(sizeof(ECP) + content_length);
#endif
      }
    }
    else {
      // memory-like

#ifdef ENCRYPTION
      if (req->src == STACK) {
        if (req->func == 1) {
          // plaintext: params goes first, flipping on host side
          memcpy(req->data, icm_raw_data_base, content_length);
        } else {
          /*
          char t[16];
          memcpy(t, req, 16);
          
          memcpy(get_output_buffer(), "echo", 4);
          memcpy(get_output_buffer() + 4, icm_raw_data_base + 4, ((ECP*)t)->length - 4);
          build_outgoing_packet(((ECP*)t)->length);

          memcpy(req, t, 16);
          */

          *(uint32_t*)req->data = *(uint32_t*)icm_raw_data_base;
          // encrypt stack elements
          uint32_t sign_offset = 4 + aes_encrypt(req->data + 4, icm_raw_data_base + 4, content_length - 4);
          // sign entire stack (except params)
          ecdsa_sign(req->data + sign_offset, icm_raw_data_base + 4, content_length - 4);
          content_length = sign_offset + 32;
        }
      } else {
        uint32_t sign_offset = aes_encrypt(req->data, icm_raw_data_base, content_length);
        ecdsa_sign(req->data + sign_offset, icm_raw_data_base + 4, content_length - 4);
        content_length = sign_offset + 32;
      }
#else
      memcpy(req->data, icm_raw_data_base, content_length);
#endif
      build_outgoing_packet(sizeof(ECP) + content_length);
    }
  }
}

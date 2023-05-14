#include "udp_server.h"
#include "evm_controller.h"
#include "icm_keys.h"

#define NUMBER_OF_DUMMIES 127
#define PAGE_SIZE 1024

#define ENCRYPTION

// these address spaces are mapped to secure on chip memory
void *icm_raw_data_base         = (void*)0xFFFC0000ll;   // decrypted packet
void *icm_temp_storage_base     = (void*)0xFFFD0000ll;   // temporary storage
void *icm_storage_history_base  = (void*)0xFFFE0000ll;   // storage history window for dummy request generation
void *icm_config_base           = (void*)0xFFFF0000ll;   // system configuration

ICMTempStorage *icm_temp_storage= (ICMTempStorage*)0xFFFD0000ll;
ICMConfig      *icm_config      = (ICMConfig*)0xFFFF0000ll;

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

const uint8_t iv[16] = {0};

uint32_t padded_size(uint32_t size, uint32_t block_size) {
  uint32_t number_of_blocks = ((size - 1) / block_size + 1);
  return number_of_blocks * block_size;
}

void icm_set_keys(aes128_t user_aes, rsa2048_t user_pub, rsa2048_t user_mod, rsa2048_t hevm_priv, rsa2048_t hevm_pub, rsa2048_t hevm_mod) {
  AES_init_ctx_iv(&(icm_config->aes_inst), user_aes, iv);
}

void icm_init() {
  icm_set_keys(user_aes, user_pub, user_mod, hevm_priv, hevm_pub, hevm_mod);
}

void aes_decrypt(uint8_t *out, uint8_t *in, uint32_t size) {
  AES_ctx_set_iv(&(icm_config->aes_inst), iv);
  memcpy(out, in, size);
  size = padded_size(size, 16);
  AES_CBC_decrypt_buffer(&(icm_config->aes_inst), out, size);
}

uint32_t aes_encrypt(uint8_t *out, uint8_t *in, uint32_t size) {
  AES_ctx_set_iv(&(icm_config->aes_inst), iv);
  size = padded_size(size, 16);
  AES_CBC_encrypt_buffer(&(icm_config->aes_inst), in, size);
  memcpy(out, in, size);
  return size;
}

///////////////////////////////////////////////////////////////////

void icm_clear_storage() {
  memset(icm_temp_storage->valid, 0, sizeof(icm_temp_storage->valid));
}

// this function is used only when using address-separated storage strategy
// when using mixed strategy, there will be no swapping-out 
uint8_t icm_check_storage_signature(rsa2048_t sign_c) {
  rsa2048_t sign;
  uint256_t real;

  // decrypt by the public key to get the hash 
  // only the first 32 bytes are valid, remaining should be all 0
  // TODO

  // calculate hash
  // TODO

  // compare, return 1 if valid
  return memcmp(real, sign, sizeof(uint256_t)) == 0;
}

///////////////////////////////////////////////////////////////////

void icm_generate_dummy_requests() {
  
}

void icm_record_history() {
  
}

uint8_t icm_decrypt() {
  ECP *req = get_input_buffer();
  
  if (req->opcode == DEBUG) {  // only for debug mode, does not encrypt
    // do nothing
    return 1;
  } else if (req->opcode == CALL) {
    // memorize the contract address
    memcpy(icm_config->contract_address, req->data, sizeof(address_t));

    // TODO
    // check integrity, return 0 if failed, and the tx will not run

    // check stack hash
    // if res->func == 0 (start anew), the stack must be empty
    // if res->func == 1 (resume from call), the hash of the contents must match

    // check merkle proof of ENV values

    return 1;
  } else {
    uint8_t *signature = req->data + req->length;
    if (req->src == STORAGE) { // this request is sent from host
      ECP *res = get_output_buffer();
      memcpy(res, req, sizeof(ECP));

      // copy from OCM to HOST
      uint64_t count = 0, content_length = 4;
      for (uint64_t i = 0; i < storage_prime; i++)
      if (icm_temp_storage->valid[i]) {
        memcpy(icm_raw_data_base + content_length, &(icm_temp_storage->record[i]), 84);
        count++; content_length += 84;
      }
      // finalize: send remaining records
      // even if there are no more records, we still have to send out a request
      // with res->func set to 1, indicating the end
      // if (count != 0) {
      {
        res->func = 1;
        res->length = content_length;
        *(uint32_t*)res->data = count;
#ifdef ENCRYPTION 
        content_length = 4 + aes_encrypt(res->data + 4, icm_raw_data_base + 4, content_length - 4);
#else
        memcpy(res->data + 4, icm_raw_data_base + 4, content_length - 4);
#endif

        // TODO: Add Signature

        build_outgoing_packet(content_length + sizeof(ECP));
      }
      return 0;
    } else if (req->dest == STORAGE) {
      // storage cache-miss swapping response: two phases
      // 0. check in OCM
      //    which is processed locally and will never go through this function
      // 1. if still not found, the host will check in plaintext global storage
      
      // responses of dummy requests should be discarded
      if (memcmp(req->data + 4, icm_config->sload_real_key, sizeof(uint256_t))) {
        return 0;
      }

      // check merkle proof
      // TODO

      // plaintext need not decrypt
      memcpy(icm_raw_data_base, req->data, req->length);
      return 1;
    } else {  // memory like
#ifdef ENCRYPTION
      // the size of memory pages and stack elements are always multiples of 16
      // so there is no need to pad content_length
      if (req->dest == STACK) {
        // there is a 4-byte "num_of_items" field before stack elements
        aes_decrypt(icm_raw_data_base + 4, req->data + 4, req->length - 4);
        *(uint32_t*)icm_raw_data_base = *(uint32_t*)req->data;

        // do not check signature here
      } else if (req->dest == MEM && req->func == 1) {
        // a blank page
        memset(icm_raw_data_base, 0, 1024);
      } else {
        aes_decrypt(icm_raw_data_base, req->data, req->length);
      }
#else
      memcpy(icm_raw_data_base, req->data, req->length);
#endif

      memcpy(get_output_buffer(), "echo", 4);
      memcpy(get_output_buffer() + 4, icm_raw_data_base, req->length);
      build_outgoing_packet(4 + req->length);

      // check RSA signature
      /*
      if (req->dest != STACK) {
        
      }
      */
      
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
            // TODO: OCM full swap
          }

          // OCM need not encryption
          icm_temp_storage->valid[id] = 1;
          memcpy(&(icm_temp_storage->record[id]), base + offset, 64);
          // also, copy the address of the current contract
          memcpy(&(icm_temp_storage->record[id].a), icm_config->contract_address, sizeof(address_t));
        }
        // nothing to be sent out
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
            // TODO: OCM full swap
          }

          // OCM need not encryption
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
        // send dummy requests
        // TODO

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
          // plaintext
          memcpy(req->data, icm_raw_data_base, content_length);
        } else {
          content_length = 4 + aes_encrypt(req->data + 4, icm_raw_data_base + 4, content_length - 4);
          *(uint32_t*)req->data = *(uint32_t*)icm_raw_data_base;
        }
      } else {
        content_length = aes_encrypt(req->data, icm_raw_data_base, content_length);
      }
#else
      memcpy(req->data, icm_raw_data_base, content_length);
#endif
      
      // build RSA signature
      // TODO

      build_outgoing_packet(sizeof(ECP) + content_length);
    }
  }
}

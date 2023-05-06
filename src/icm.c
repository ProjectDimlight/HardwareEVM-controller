#include "udp_server.h"
#include "evm_controller.h"
#include "icm_keys.h"

#define NUMBER_OF_DUMMIES 127
#define PAGE_SIZE 1024

// #define ENCRYPTION

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
      memcmp(icm_temp_storage->record[hash].a, cm_config->contract_address, sizeof(address_t)) != 0 ||
      memcmp(icm_temp_storage->record[hash].k, key, sizeof(uint256_t)) != 0);
    hash = (hash + 1) % storage_prime, cnt++);

  if (cnt == storage_prime) 
    return storage_prime;
  else 
    return hash;
}

// decrypt = private key
// encrypt = public key

void icm_set_keys(aes128_t user_aes, rsa2048_t user_pub, rsa2048_t user_mod, rsa2048_t hevm_priv, rsa2048_t hevm_mod) {
  XCsuDma_Config *config = XCsuDma_LookupConfig(XSECURE_CSUDMA_DEVICEID);
  XCsuDma_CfgInitialize(&(icm_config->csu_dma_instance), config, config->BaseAddress);
  uint32_t iv[16] = {0};

  XSecure_AesInitialize(&(icm_config->user_aes_inst), &(icm_config->csu_dma_instance), XSECURE_CSU_AES_KEY_SRC_KUP, iv, (uint32_t*)user_aes);
  XSecure_RsaInitialize(&(icm_config->user_pub_inst), user_mod, NULL, user_pub);
  XSecure_RsaInitialize(&(icm_config->hevm_priv_inst), hevm_mod, NULL, hevm_priv);
}

void icm_init() {
  icm_set_keys(user_aes, user_pub, user_mod, hevm_priv, hevm_mod);
}

void icm_clear_storage() {
  icm_temp_storage->item_count = 0;
  memset(icm_temp_storage->valid, 0, sizeof(icm_temp_storage->valid));
}

// this function is used only when using address-separated storage strategy
// when using mixed strategy, there will be no swapping-out 
uint8_t icm_check_storage_signature(rsa2048_t sign_c) {
  rsa2048_t sign;
  uint256_t real;

  // decrypt to get the hash (only the first 32 bytes are valid, remaining should be all 0)
  XSecure_AesEncryptData(&(icm_config->hevm_priv_inst), sign_c, sizeof(rsa2048_t), sign);

  // calculate hash
  // TODO

  // compare, return 1 if valid
  return memcmp(real, sign, sizeof(uint256_t)) == 0;
}

uint8_t icm_decrypt() {
  ECP *req = get_input_buffer();
  
  if (req->opcode == DEBUG) {  // only for debug mode, does not encrypt
    // do nothing
    return 1;
  } else if (req->opcode == CALL) { // memorize the contract address
    memcpy(icm_config->contract_address, req->data, sizeof(address_t));
    return 1;
  } else {
    uint8_t *signature = req->data + req->length;
    if (req->src == STORAGE) { // this request is sent from host
      // copy from OCM to HOST
      uint64_t count = 0, content_length = 4;
      for (uint64_t i = 0; i < storage_prime; i++)
      if (icm_temp_storage->valid[i]) {
        memcpy(icm_raw_data_base + content_length, &(icm_temp_storage->record[i]), 84);
        count++; content_length += 84;
        
        if (count == 16) {
          req->length = content_length;
          *(uint32_t*)req->data = count;
#ifdef ENCRYPTION 
#else
          memcpy(req->data + 4, icm_raw_data_base + 4, content_length - 4);
#endif
          build_outgoing_packet(content_length + sizeof(ECP));
          count = 0, content_length = 4;
        }
      }
      // finalize: send remaining records
      if (count != 0) {
        req->length = content_length;
        *(uint32_t*)req->data = count;
#ifdef ENCRYPTION 
#else
          memcpy(req->data + 4, icm_raw_data_base + 4, content_length - 4);
#endif
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
    } else {
#ifdef ENCRYPTION
      XSecure_AesDecryptData(&(icm_config->user_aes_inst), icm_raw_data_base, req->data, req->length, NULL);
#else
      memcpy(icm_raw_data_base, req->data, req->length);
#endif
      /*
      memcpy(get_output_buffer(), "echo", 4);
      memcpy(get_output_buffer() + 4, req, sizeof(ECP) + req->length);
      build_outgoing_packet(4 + sizeof(ECP) + req->length);
      */

      // check RSA signature
      // TODO
      // XSecure_RsaPublicEncrypt(rsa_user_inst, sign_c, XSECURE_RSA_2048_KEY_SIZE, icm_temp_base);

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
        // copy from HEVM to OCM
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
        return 0;
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
          memcpy(&(icm_temp_storage->record[id]), base + offset, 64);
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
        req->length = 8 + 64;
#ifdef ENCRYPTION
        // send dummy requests 
#else
        memcpy(req->data + 4, base, 4 + 64);
#endif
        build_outgoing_packet(sizeof(ECP) + req->length);
      }
    }
    else {
      // memory-like

#ifdef ENCRYPTION
      XSecure_AesEncryptData(&(icm_config->user_aes_inst), req->data, icm_raw_data_base, length);
#else
      memcpy(req->data, icm_raw_data_base, content_length);
#endif
      
      // build RSA signature
      // TODO

      build_outgoing_packet(length);
    }
  }
}

void icm_generate_dummy_requests() {
  
}

void icm_record_history() {
  
}

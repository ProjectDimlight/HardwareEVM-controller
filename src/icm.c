#include "udp_server.h"
#include "evm_controller.h"
#include "icm.h"

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

uint32_t icm_hash(uint256_t key) {
  uint32_t hi = *(uint32_t*)(key + 28);
  uint32_t lo = *(uint32_t*)(key + 0);
  uint32_t hash = ((hi % 1009) * 17 + lo) % 1009;
  if (hash == 1008) hash = 0;
  return hash;
}

// returns the index
// if not found, return the first invalid (empty) element
// for insertion, use this as the new index
// for query, 
uint32_t icm_find(uint256_t key) {
  uint32_t hash = icm_hash(key);
  uint32_t cnt = 0;
  for (; cnt < 1008 && icm_temp_storage->valid[hash] && memcmp(icm_temp_storage->record[hash].k, key, sizeof(uint256_t)) != 0; hash = (hash + 1) % 1008, cnt++);

  if (cnt == 1008) 
    return 1008; 
  else 
    return hash;
}

// decrypt = private key
// encrypt = public key


void icm_clear_storage() {
  icm_temp_storage->item_count = 0;
  memset(icm_temp_storage->valid, 0, sizeof(icm_temp_storage->valid));
}

void icm_set_keys(aes128_t user_aes, rsa2048_t user_pub, rsa2048_t user_mod, rsa2048_t hevm_priv, rsa2048_t hevm_mod) {
  XCsuDma_Config *config = XCsuDma_LookupConfig(XSECURE_CSUDMA_DEVICEID);
  XCsuDma_CfgInitialize(&(icm_config->csu_dma_instance), config, config->BaseAddress);
  uint32_t iv[16] = {0};

  XSecure_AesInitialize(&(icm_config->user_aes_inst), &(icm_config->csu_dma_instance), XSECURE_CSU_AES_KEY_SRC_KUP, iv, (uint32_t*)user_aes);
  XSecure_RsaInitialize(&(icm_config->user_pub_inst), user_mod, NULL, user_pub);
  XSecure_RsaInitialize(&(icm_config->hevm_priv_inst), hevm_mod, NULL, hevm_priv);
}

void icm_init() {
  // icm_set_keys();
}

uint8_t icm_decrypt() {
  ECP *req = get_input_buffer();
  
  if (req->opcode == DEBUG) {  // only for debug mode, does not encrypt
    // do nothing
    return 1;
  }
  else {
    uint8_t *signature = req->data + req->length;
    if (req->dest == STORAGE) {
      // storage cache-miss swapping query: two phases
      // phase 0 is processed locally
      // 1. if still not found, the host will check in plaintext global storage
      // responses of dummy requests should be discarded

      if (memcmp(req->data + 4, icm_config->sload_real_key, sizeof(uint256_t))) {
        return 0;
      }

      // check merkle proof
      // TODO

      memcpy(icm_raw_data_base, req->data, req->length);
      return 1;
    }
    else {
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
  }
  else {
    if (req->src == STORAGE) {
      if (req->opcode == COPY) {
        // storage dump: just encrypt and send

        // TODO: encrypt
#ifdef ENCRYPTION
        
#else
        memcpy(req->data, icm_raw_data_base, content_length);
#endif
        build_outgoing_packet(length);

        // also, we should send out storage records in OCM
        uint64_t count = 0, content_length = 4;
        for (uint64_t i = 0; i < 1008; i++) if (icm_temp_storage->valid[i]) {
          memcpy(req->data + content_length, &(icm_temp_storage->record[i]), 64);
          count++; content_length += 64;
          
          if (count == 16) {
            req->length = content_length;
            *(uint32_t*)req->data = count;
            build_outgoing_packet(content_length + sizeof(ECP));

            count = 0; content_length = 4;
          }
        }
        if (count != 0) {
          req->length = content_length;
          *(uint32_t*)req->data = count;
          build_outgoing_packet(content_length + sizeof(ECP));
        }
      } else {
        void *base = icm_raw_data_base;

        // before anything else
        // write the swapped-out record into OCM
        uint32_t num_of_items = *(uint32_t*)base;
        if (num_of_items) {
          uint32_t id = icm_find(base + 4);
          // TODO: OCM full swap
          if (id != 1008) {
            icm_temp_storage->valid[id] = 1;
            memcpy(&(icm_temp_storage->record[id]), base + 4, 64);
          }
          base += 4 + 64;
        }
        else
          base += 4;

        // storage cache-miss swapping query: two phases
        // 0. check in encrypted buffer inside local storage
        // the swapped-out record should always been encrypted

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
        // send dummy
        // since the swapped-out record has been sent in phase 0
        // we are not sending it again, instead set output num_of_items to 0
        
        memcpy(icm_config->sload_real_key, base + 4, sizeof(uint256_t));

#ifdef ENCRYPTION
#else
        memcpy(req->data, icm_raw_data_base, content_length);
#endif
        build_outgoing_packet(length);
      }
    }
    else {
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

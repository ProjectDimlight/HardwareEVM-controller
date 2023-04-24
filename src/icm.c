#include "udp_server.h"
#include "evm_controller.h"
#include "icm.h"

#define NUMBER_OF_DUMMIES 127
#define PAGE_SIZE 1024
// #define ENCRYPTION

// these address spaces are mapped to secure on chip memory
void *icm_raw_data_base         = (void*)0xFFFC0000ll;   // decrypted packet
void *icm_temp_base             = (void*)0xFFFD0000ll;   // temporary variables
void *icm_storage_history_base  = (void*)0xFFFD0000ll;   // storage history window for dummy request generation
void *icm_config_base           = (void*)0xFFFF0000ll;   // system configuration

ICMSecureStorage *icm_config = (ICMSecureStorage *)0xFFFF0000ll;

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

uint8_t icm_decrypt() {
  ECP *ecp = get_input_buffer();
  
  if (ecp->opcode == DEBUG) {  // only for debug mode, does not encrypt
    // do nothing
    return 1;
  }
  else {
    uint8_t *signature = ecp->data + ecp->length;
    if (ecp->dest == STORAGE) {
      // storage cache-miss swapping query: two phases
      // phase 0 is processed locally
      // 1. if still not found, the host will check in plaintext global storage
      // responses of dummy requests should be discarded

      if (memcmp(ecp->data + 4, icm_config->sload_real_key, sizeof(uint256_t))) {
        return 0;
      }

      // check merkle proof
      // TODO

      memcpy(icm_raw_data_base, ecp->data, ecp->length);
      return 1;
    }
    else {
#ifdef ENCRYPTION
      XSecure_AesDecryptData(&(icm_config->user_aes_inst), icm_raw_data_base, ecp->data, ecp->length, NULL);
#else
      memcpy(icm_raw_data_base, ecp->data, ecp->length);
#endif
      /*
      memcpy(get_output_buffer(), "echo", 4);
      memcpy(get_output_buffer() + 4, ecp, sizeof(ECP) + ecp->length);
      build_outgoing_packet(4 + sizeof(ECP) + ecp->length);
      */

      // check RSA signature
      // TODO
      // XSecure_RsaPublicEncrypt(rsa_user_inst, sign_c, XSECURE_RSA_2048_KEY_SIZE, icm_temp_base);

      return 1;
    }
  }
}

void icm_encrypt(uint32_t length) {
  ECP *ecp = get_output_buffer();
  uint32_t content_length = length - sizeof(ECP);

  if (ecp->opcode == DEBUG) {  // only for debug mode, does not encrypt
    // do nothing
    build_outgoing_packet(length);
  }
  else {
    if (ecp->src == STORAGE) {
      if (ecp->opcode == COPY) {
        // storage dump: just encrypt and send

        // TODO: encrypt
#ifdef ENCRYPTION
        
#else
        memcpy(ecp->data, icm_raw_data_base, content_length);
#endif
        build_outgoing_packet(length);
      } else {
        // storage cache-miss swapping query: two phases
        // 0. check in encrypted buffer inside local storage
        // the swapped-out record should always been encrypted

        

        // 1. if still not found, generate plaintext dummy requests
        // send dummy
        // since the swapped-out record has been sent in phase 0
        // we are not sending it again, instead set output num_of_items to 0
        
        uint32_t num_of_items = *(uint32_t*)icm_raw_data_base;
        memcpy(icm_config->sload_real_key, icm_raw_data_base + 8 + num_of_items * 64, sizeof(uint256_t));

#ifdef ENCRYPTION
#else
        memcpy(ecp->data, icm_raw_data_base, content_length);
#endif
        build_outgoing_packet(length);
      }
    }
    else {
#ifdef ENCRYPTION
      XSecure_AesEncryptData(&(icm_config->user_aes_inst), ecp->data, icm_raw_data_base, length);
#else
      memcpy(ecp->data, icm_raw_data_base, content_length);
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

#include "udp_server.h"
#include "evm_controller.h"
#include "icm_keys.h"
#include "xtime_l.h"

#define PAGE_SIZE 1024
#define PAGE_ADDR_W 10
#define PAGE_SIGN_W 5
#define PAGES(x) (x ? (((x - 1) >> PAGE_ADDR_W) + 1) : 0)
#define SELF_ADDRESS ((call_frame + 1)->address)

#define call_frame (icm_config->call_frame_pointer)
#define cesm_state (icm_config->cesm_current_state)

#define ENCRYPTION
#define SIGNATURE
// #define LOCAL_PROTECTION
// #define DUMMY

XTime total_time, start_time, end_time;
uint8_t timing_mode;

void icm_timing_continue() {
  if (timing_mode == 0) {
    timing_mode = 1;
    XTime_GetTime(&start_time);
  }
}

void icm_timing_pause() {
  if (timing_mode == 1) {
    XTime_GetTime(&end_time);
    timing_mode = 0;
    total_time += end_time - start_time;
  }
}

void icm_timing_start() {
  timing_mode = 0;
  total_time = 0;
  icm_timing_continue();
}

///////////////////////////////////////////////////////////////////

// these address spaces are mapped to secure on chip memory
void * const icm_raw_data_base          = (void*)0xFFFC0000ll;   // decrypted packet
ICMTempStorage * const icm_temp_storage = (ICMTempStorage*)0xFFFC8000ll;
ICMConfig      * const icm_config       = (ICMConfig*)0xFFFD0000ll;

uint8_t icm_ram_stack[4096 * PAGE_SIZE];
uint8_t icm_ram_return_tmp[16 * PAGE_SIZE];
uint8_t icm_ram_deployed_code[1024 * PAGE_SIZE];
uint8_t zero_page[PAGE_SIZE];
ICMQueryHistoryCipher icm_query_history_cipher[QUERY_HISTORY_SLOTS];

///////////////////////////////////////////////////////////////////

void icm_debug(void *data, uint32_t length) {
  void *out = (void*)get_debug_buffer();
  memcpy(out, "dbug", 4);
  memcpy(out + 4, data, length);
  build_debug_packet(4 + length);
}

///////////////////////////////////////////////////////////////////

uint32_t icm_hash(address_t address, uint256_t key) {
  uint32_t ad = *(uint32_t*)(address + 0);
  uint32_t lo = *(uint32_t*)(key + 0);
  uint32_t hash = ad;
  hash = (hash << 4) + hash + lo;
  hash = hash & (storage_pow2);
  while (hash >= storage_prime) hash -= storage_prime;
  return hash;
}

// returns the index
// if not found, return the first invalid (empty) element
// for insertion, use this as the new index
// for query, 
uint32_t icm_find(uint256_t key) {
  if (icm_temp_storage->pool.item_count == storage_prime)
    icm_dump_storage();
  uint32_t hash = icm_hash(call_frame->storage_address, key);
  uint32_t cnt = 0;
  for (;
      cnt < storage_prime &&
      icm_temp_storage->valid[hash] && (
      memcmp(icm_temp_storage->record[hash].a, call_frame->storage_address, sizeof(address_t)) != 0 ||
      memcmp(icm_temp_storage->record[hash].k, key, sizeof(uint256_t)) != 0);
    hash = ((hash == (storage_prime - 1)) ? 0 : (hash + 1)), cnt++);

  if (cnt == storage_prime) {
    icm_dump_storage();
    return icm_find(key);
  }
  else
    return hash;
}

///////////////////////////////////////////////////////////////////

OCMBalance* getBalance(address_t addr) {
  for (OCMBalance* i = icm_config->local_balance; i < icm_config->local_balance_pointer; i++)
    if (memcmp(i->address, addr, sizeof(address_t)) == 0)
      return i;
  return NULL;
}

int balanceCanTransfer(uint256_t src, uint256_t val) {
  uint32_t *source = (uint32_t*)src;
  uint32_t *value = (uint32_t*)val;
  for (int i = sizeof(uint256_t) / sizeof(uint32_t) - 1; i >= 0; i--) {
    if (source[i] > value[i]) break;
    else if (source[i] < value[i]) return 0;
  }
  return 1;
}

void balanceSub(uint256_t x, uint256_t y) {
  uint32_t *X = (uint32_t*)x;
  uint32_t *Y = (uint32_t*)y;
  for (int i = sizeof(uint256_t) / sizeof(uint32_t) - 1; i >= 0; i--) {
    if (X[i] < Y[i])
      X[i + 1]--;
    X[i] = X[i] - Y[i];
  }
}

void balanceAdd(uint256_t x, uint256_t y) {
  uint32_t *X = (uint32_t*)x;
  uint32_t *Y = (uint32_t*)y;
  for (int i = 0; i < sizeof(uint256_t) / sizeof(uint32_t); i++) {
    uint32_t tmp = X[i] + Y[i];
    if (tmp < X[i]) X[i + 1]++;
    X[i] = tmp;
  }
}

void transferBalance(address_t src, address_t dst, uint256_t val) {
  OCMBalance *from = getBalance(src), *to = getBalance(dst);
  if (balanceCanTransfer(from->balance, val)) {
    balanceSub(from->balance, val), balanceAdd(to->balance, val);
  } else {
    icm_debug("balance underflow", 17);
  }
}

void fetchBalance(address_t address, uint256_t balance) {
  if (getBalance(address) == NULL) {
    memcpy(icm_config->local_balance_pointer->address, address, sizeof(address_t));
    memcpy(icm_config->local_balance_pointer->balance, balance, sizeof(uint256_t));
    icm_config->local_balance_pointer++;
    if ((uint64_t)icm_config->local_balance_pointer >= (uint64_t)&(icm_config->local_balance_pointer))
      icm_debug("balance ocm overflow", 20);
  }
}

void clearBalance() {
  icm_config->local_balance_pointer = icm_config->local_balance;
}

///////////////////////////////////////////////////////////////////

// Random

#define THE_PRIME 1000000007
#define ANOTHER_PRIME 19260817

void icm_init_random() {
  icm_config->last_random[0] = 114514;
  icm_config->last_random[1] = 0x114514;
  icm_config->last_random[2] = 1919810;
  icm_config->last_random[3] = 0x1919810;
}

int icm_random(int from, int to) {
  uint32_t range = to - from;
  uint32_t pow2 = 1;
  while (pow2 < range) pow2 <<= 1;
  pow2 -= 1;
  
  int origin = icm_config->last_random[2] * ANOTHER_PRIME - icm_config->last_random[1];
  int res = origin ^ (1u << (icm_config->last_random[3] & 31));

  while (res < 0) res += THE_PRIME;
  while (res >= THE_PRIME) res -= THE_PRIME;

  icm_config->last_random[3] = icm_config->last_random[2];
  icm_config->last_random[2] = icm_config->last_random[1];
  icm_config->last_random[1] = icm_config->last_random[0];
  icm_config->last_random[0] = res;

  res &= pow2;
  while (res >= range) {
    res -= range;
  }
  res += from;
  return res;
}

void icm_random_multiple_unique(int16_t output[], int count, int from, int to, int8_t valid[]) {
  for (int i = 0; i < count; i++) {
    int id, not_unique;
    while (1) {
      not_unique = 0;
      id = icm_random(from, to);
      if (valid[id] == 0) {
        continue;
      }

      for (int j = 0; j < i; j++) 
        if (output[j] == id) {
          not_unique = 1;
          break;
        }

      if (!not_unique) {
        output[i] = id;
        break;
      }
    }
  }
}

///////////////////////////////////////////////////////////////////

uint32_t padded_size(uint32_t size, uint32_t block_width) {
  if (size == 0) return 0;
  uint32_t number_of_blocks = (((size - 1) >> block_width) + 1);
  return number_of_blocks << block_width;
}

void aes_decrypt_ext(uint8_t *out, uint8_t *in, uint32_t size) {
#ifdef ENCRYPTION
  AES_ctx_set_iv(&(icm_config->aes_inst), iv);
  size = padded_size(size, 4);
  memcpy(out, in, size);
  AES_CBC_decrypt_buffer(&(icm_config->aes_inst), out, size);
#else
  memcpy(out, in, size);
#endif
}

void aes_decrypt(uint8_t *out, uint8_t *in, uint32_t size) {
#ifdef LOCAL_PROTECTION
  AES_ctx_set_iv(&(icm_config->aes_inst), iv);
  size = padded_size(size, 4);
  memcpy(out, in, size);
  AES_CBC_decrypt_buffer(&(icm_config->aes_inst), out, size);
#else
  memcpy(out, in, size);
#endif
}

void aes_decrypt_stack(uint8_t *out, uint8_t *in, uint32_t size) {
#ifdef LOCAL_PROTECTION
  AES_ctx_set_iv(&(icm_config->aes_inst), iv);
  memcpy(out, in, size);
  for (uint32_t i = size; i; i -= 32) {
    AES_CBC_decrypt_buffer(&(icm_config->aes_inst), out + i - 32, 32);
  }
#else
  memcpy(out, in, size);
#endif
}

uint32_t aes_encrypt_ext(uint8_t *out, uint8_t *in, uint32_t size) {
#ifdef ENCRYPTION
  AES_ctx_set_iv(&(icm_config->aes_inst), iv);
  size = padded_size(size, 4);
  AES_CBC_encrypt_buffer(&(icm_config->aes_inst), in, size);
  if (out != in)
    memcpy(out, in, size);
  return size;
#else
  memcpy(out, in, size);
  return size;
#endif
}

uint32_t aes_encrypt(uint8_t *out, uint8_t *in, uint32_t size) {
#ifdef LOCAL_PROTECTION
  AES_ctx_set_iv(&(icm_config->aes_inst), iv);
  size = padded_size(size, 4);
  AES_CBC_encrypt_buffer(&(icm_config->aes_inst), in, size);
  if (out != in)
    memcpy(out, in, size);
  return size;
#else
  memcpy(out, in, size);
  return size;
#endif
}

///////////////////////////////////////////////////////////////////

// Dummy

void icm_print_linked_list(int16_t seq) {
  uint8_t tmp[80];
  tmp[2] = tmp[3] = 0;

  for (int16_t p = icm_config->query_history_head[seq]; p != -1; p = icm_config->query_history_next[p]) {
    aes_decrypt_ext(tmp + 4, &icm_query_history_cipher[p], 64);
    *(int16_t*)tmp = p;

    icm_debug(tmp, 68);
  }
}

void icm_clear_query_history() {
  icm_init_random();

  // init history
  icm_config->count_query_history = 0;
  memset(icm_config->query_history_valid, 0, sizeof(icm_config->query_history_valid));

  // init recorder
  icm_config->query_history_deleted_sp = 0;
  icm_config->query_history_recorder_last_record_id = -1;
  icm_config->query_history_recorder_seq = -1;
  memset(icm_config->query_history_head, -1, sizeof(icm_config->query_history_head));
  icm_config->query_history_free_head = -1;

  for (int i = 0; i < QUERY_HISTORY_SLOTS; i++) {
    icm_config->query_history_next[i] = icm_config->query_history_free_head;
    icm_config->query_history_free_head = i;
  }
}

void icm_record_query(uint8_t type, uint8_t address[], uint8_t key[]) {
  if (icm_config->current_query_history_length >= 256) {
    return;
  }

  icm_config->current_query_history_length ++;

  // if there is insufficient history storage
  // remove a random record
  if (icm_config->query_history_free_head == -1) {
	  icm_debug("record full", 11);

    int16_t remove_id, i, j;
    icm_random_multiple_unique(&remove_id, 1, 0, icm_config->count_query_history, icm_config->query_history_valid);
    icm_config->query_history_valid[remove_id] = 0;
    for (j = -1, i = icm_config->query_history_head[remove_id]; i != -1; j = i, i = icm_config->query_history_next[i]);
    if (j != -1) {
      icm_config->query_history_next[j] = icm_config->query_history_free_head;
      icm_config->query_history_free_head = icm_config->query_history_head[remove_id];
      icm_config->query_history_head[remove_id] = -1;
    }

    icm_config->query_history_deleted[icm_config->query_history_deleted_sp ++] = remove_id;
  }

  // get a empty item from free link
  int16_t id = icm_config->query_history_free_head;
  icm_config->query_history_free_head = icm_config->query_history_next[icm_config->query_history_free_head];
  icm_config->query_history_next[id] = -1;

  // insert it to the tail
  if (icm_config->query_history_head[icm_config->query_history_recorder_seq] != -1) {
    icm_config->query_history_next[icm_config->query_history_recorder_last_record_id] = id;
  } else {
    icm_config->query_history_head[icm_config->query_history_recorder_seq] = id;
  }
  icm_config->query_history_recorder_last_record_id = id;

  // memorize the values
  uint8_t tmp[64];
  tmp[0] = type;
  tmp[1] = tmp[2] = tmp[3] = 0;
  memcpy(tmp + 4, address, 20);
  memcpy(tmp + 4 + 20, key, 32);

#ifdef ICM_DEBUG
  icm_debug("record", 6);
  icm_debug(&id, 2);
  icm_debug(tmp, 56);
#endif

  aes_encrypt_ext(&icm_query_history_cipher[id], tmp, 4 + 20 + 32);
}

void icm_init_dummy_generator() {
  // stop the recording of the last tx
  if (icm_config->query_history_recorder_last_record_id != -1) {
    icm_config->query_history_next[icm_config->query_history_recorder_last_record_id] = -1;
    icm_config->query_history_valid[icm_config->query_history_recorder_seq] = 1;
#ifdef DEBUG
    icm_print_linked_list(icm_config->query_history_recorder_seq);
#endif
  }

  // start new record
  if (icm_config->query_history_deleted_sp) {
    icm_config->query_history_recorder_seq = icm_config->query_history_deleted[--icm_config->query_history_deleted_sp];
  } else if (icm_config->count_query_history == QUERY_HISTORY_SIZE) {
	  icm_debug("seq full", 8);

    int16_t remove_id, i, j;
    icm_random_multiple_unique(&remove_id, 1, 0, icm_config->count_query_history, icm_config->query_history_valid);
    icm_config->query_history_valid[remove_id] = 0;
    for (j = -1, i = icm_config->query_history_head[remove_id]; i != -1; j = i, i = icm_config->query_history_next[i]);
    if (j != -1) {
      icm_config->query_history_next[j] = icm_config->query_history_free_head;
      icm_config->query_history_free_head = icm_config->query_history_head[remove_id];
      icm_config->query_history_head[remove_id] = -1;
    }

    icm_config->query_history_recorder_seq = remove_id;
  } else {
    icm_config->query_history_recorder_seq = icm_config->count_query_history++;
  }
  icm_config->current_query_history_length = 0;

  // select K dummy sequences
  icm_config->chosen_dummy_number = icm_config->count_query_history - 1 - icm_config->query_history_deleted_sp < NUMBER_OF_DUMMY_SEQS + 3 ? 0 : NUMBER_OF_DUMMY_SEQS;

#ifdef ICM_DEBUG
  icm_debug("recorder", 8);
  icm_debug(&icm_config->query_history_recorder_seq, 2);
  icm_debug("dummies", 7);
  icm_debug(&icm_config->chosen_dummy_number, 2);
#endif

  int16_t top = icm_config->count_query_history;
  top = (top == QUERY_HISTORY_SIZE || top == 0) ? top : top - 1;

  icm_random_multiple_unique(icm_config->chosen_dummy_seq, icm_config->chosen_dummy_number, 0, icm_config->count_query_history, icm_config->query_history_valid);


  for (int i = 0; i < icm_config->chosen_dummy_number; i++) {
    icm_config->chosen_dummy_ids[i] = icm_config->query_history_head[icm_config->chosen_dummy_seq[i]];
#ifdef ICM_DEBUG
    icm_debug(&icm_config->chosen_dummy_seq[i], 2);
#endif
  }
}

void icm_send_query(uint8_t type, int address[], int key[]) {
  if (type == 0) {  // STORAGE
    ECP *req = get_output_buffer();
    req->opcode = SWAP;
    req->src = STORAGE;
    req->dest = HOST;
    req->src_offset = 0;
    req->dest_offset = 0;
    req->length = 8 + 20 + 32;
    *(uint32_t*)req->data = 0;
    *(uint32_t*)(req->data + 4) = 1;

    memcpy(req->data + 8, address, 20);
    memcpy(req->data + 8 + 20, key, 32);
    build_outgoing_packet(sizeof(ECP) + 60);
  } else {
    ECP *req = get_output_buffer();
    req->opcode = QUERY;
    req->src = ENV;
    req->dest = HOST;
    req->func = type;
    req->src_offset = 0;
    req->dest_offset = 0;
    req->length = 20;
    memcpy(req->data, address, 20);
    build_outgoing_packet(sizeof(ECP) + 60);
  }
}

void icm_send_query_with_dummy(uint8_t type, int address[], int key[]) {
  int t = icm_random(0, icm_config->chosen_dummy_number + 1);  // the place for the real
  uint8_t tmp[64];

#ifdef ICM_DEBUG
  icm_debug("send", 4);
#endif

  for (int i = 0; i < t; i ++) {
    uint16_t id = icm_config->chosen_dummy_ids[i];
    if (id == -1) continue;

#ifdef ICM_DEBUG
    icm_debug("dummy", 5);
#endif
    aes_decrypt_ext(tmp, &icm_query_history_cipher[id], 64);
    icm_send_query(*(uint8_t*)tmp, tmp + 4, tmp + 4 + 20);
    icm_config->chosen_dummy_ids[i] = icm_config->query_history_next[id];
  }

#ifdef ICM_DEBUG
  icm_debug("real", 4);
#endif
  icm_send_query(type, address, key);

  for (int i = t; i < icm_config->chosen_dummy_number; i++) {
    int16_t id = icm_config->chosen_dummy_ids[i];
    if (id == -1) continue;

#ifdef ICM_DEBUG
    icm_debug("dummy", 5);
#endif
    aes_decrypt_ext(tmp, &icm_query_history_cipher[id], 64);
    icm_send_query(*(uint8_t*)tmp, tmp + 4, tmp + 4 + 20);
    icm_config->chosen_dummy_ids[i] = icm_config->query_history_next[id];
  }
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
    // read pc, msize, gas here
    dma_read_mem(evm_env_addr, icm_raw_data_base, 32 * 3);
    call_frame->pc = *(uint32_t*)icm_raw_data_base;
    call_frame->msize = *((uint32_t*)(icm_raw_data_base + 32));
    call_frame->gas = *((uint64_t*)(icm_raw_data_base + 64));
    call_frame->pc++;
#ifdef ICM_DEBUG
    icm_debug("env read", 8);
    icm_debug(&call_frame->pc, 4);
    icm_debug(&call_frame->msize, 4);
    icm_debug(&call_frame->gas, 8);
#endif

    // does not update stack size, because it has been cleared while dumping out stack elements
    
    // no longer need to copy memory sign
    call_frame->top = call_frame->memory + call_frame->memory_length;
    call_frame->sign_top = call_frame->memory_sign + sign_length(call_frame->memory_length);
    if (call_frame->sign_top >= icm_config->icm_ocm_return_sign_tmp)
      icm_debug("ocm_stack_hash overflow", 23);
  }

#ifdef ICM_DEBUG
  icm_debug("sign pointers", 13);
  icm_debug(&(call_frame->stack_sign), 4);
  icm_debug(&(call_frame->memory_sign), 4);
  icm_debug(&(call_frame->sign_top), 4);
  icm_debug("pc msize gas load", 17);
#endif
  
  // create a new frame
  if (call_frame == &icm_config->call_stack[63]) {
    icm_debug("frame overflow", 14);
  }

  void *base = call_frame->top;
  void *sign_base = call_frame->sign_top;

  call_frame++, icm_config->frame_depth++;
  if (call_frame == icm_config->call_stack + 32)
    icm_debug("frame overflow", 14);

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
  dma_memcpy(call_frame->value, value, sizeof(uint256_t));

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

  if (call_frame->memory_sign >= icm_config->icm_ocm_return_sign_tmp)
    icm_debug("sign overflow", 13);

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
    memset(icm_raw_data_base, 0, 10 * 32);
    *((uint32_t*)icm_raw_data_base) = call_frame->pc;
    *((uint32_t*)(icm_raw_data_base + 32)) = call_frame->msize;
    *((uint64_t*)(icm_raw_data_base + 32 * 2)) = call_frame->gas;
    memcpy(icm_raw_data_base + 32 * 3, call_frame->caller_address, sizeof(address_t));
    memcpy(icm_raw_data_base + 32 * 4, call_frame->storage_address, sizeof(address_t));
    *((uint32_t*)(icm_raw_data_base + 32 * 5)) = call_frame->code_length;
    *((uint32_t*)(icm_raw_data_base + 32 * 6)) = call_frame->input_length;
    memcpy(icm_raw_data_base + 32 * 7, call_frame->value, sizeof(uint256_t));
    *((uint32_t*)(icm_raw_data_base + 32 * 8)) = call_frame->return_length;
    if (balance != NULL)
      memcpy(icm_raw_data_base + 32 * 9, balance, sizeof(uint256_t));
    dma_write_mem(icm_raw_data_base, evm_env_addr, 10 * 32);
#ifdef ICM_DEBUG
    icm_debug("set env regs", 12);
#endif
  }
}

void icm_stack_pop() {
#ifdef ICM_DEBUG
  icm_debug("call stack pop", 14);
#endif

  call_frame--, icm_config->frame_depth--;

  if (!icm_stack_is_empty()) {
    // No longer need to copy memory sign

    // Recover ENV
    memset(icm_raw_data_base, 0, 10 * 32);
    *((uint32_t*)icm_raw_data_base) = call_frame->pc;
    *((uint32_t*)(icm_raw_data_base + 32)) = call_frame->msize;
    *((uint64_t*)(icm_raw_data_base + 32 * 2)) = call_frame->gas;
    memcpy(icm_raw_data_base + 32 * 3, call_frame->caller_address, sizeof(address_t));
    memcpy(icm_raw_data_base + 32 * 4, call_frame->storage_address, sizeof(address_t));
    *((uint32_t*)(icm_raw_data_base + 32 * 5)) = call_frame->code_length;
    *((uint32_t*)(icm_raw_data_base + 32 * 6)) = call_frame->input_length;
    memcpy(icm_raw_data_base + 32 * 7, call_frame->value, sizeof(uint256_t));
    *((uint32_t*)(icm_raw_data_base + 32 * 8)) = call_frame->return_length;
    memcpy(icm_raw_data_base + 32 * 9, getBalance(call_frame->storage_address)->balance, sizeof(uint256_t));
    dma_write_mem(icm_raw_data_base, evm_env_addr, 32 * 10);
  }

#ifdef ICM_DEBUG
  icm_debug("recover env regs", 16);
  icm_debug("sign pointers", 13);
  icm_debug(&(call_frame->stack_sign), 4);
  icm_debug(&(call_frame->memory_sign), 4);
  icm_debug(&(call_frame->sign_top), 4);
#endif
}

// CALL: stack_push, memcpy (last.mem -> this.input), run
// END:  memcpy (this.mem -> returndata_tmp) , stack_pop, memcpy (returndata_tmp -> this.mem), resume

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
#ifdef LOCAL_PROTECTION
  keccak_256_init();
  keccak_256_update(data, size);
  keccak_256_update(&type, 1);
  keccak_256_update(&nonce, 8);
  keccak_256_finalize(out);
#endif
}

int hash_verify(uint8_t *in, uint8_t *data, uint32_t size, uint8_t type, uint64_t nonce, uint8_t *pub_key) {
#ifdef LOCAL_PROTECTION
  uint8_t hash[32];
  keccak_256_init();
  keccak_256_update(data, size);
  keccak_256_update(&type, 1);
  keccak_256_update(&nonce, 8);
  keccak_256_finalize(hash);
  return memcmp(in, hash, 32) == 0;
#else
  return 1;
#endif
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
  return 1;
}

void ecdsa_sign(uint8_t *out, uint8_t *data, uint32_t size, uint8_t src, uint64_t nonce, uint8_t *priv_key) {
  uint8_t hash[32];
  keccak_256_init();
  keccak_256_update(data, size);
  keccak_256_update(&src, 1);
  keccak_256_update(&nonce, 8);
  keccak_256_finalize(hash);
  uint8_t res = uECC_sign(priv_key, hash, 32, out, icm_config->curve);
}

void ecdsa_sign_page(uint8_t *out, uint8_t *data, uint8_t src, uint32_t src_offset, uint64_t nonce, uint8_t *priv_key) {
  uint8_t hash[32];
  keccak_256_init();
  keccak_256_update(data, PAGE_SIZE);
  keccak_256_update(&src, 1);
  keccak_256_update(&src_offset, 4);
  keccak_256_update(&nonce, 8);
  keccak_256_finalize(hash);
  uint8_t res = uECC_sign(priv_key, hash, 32, out, icm_config->curve);
}

int ecdsa_verify_page(uint8_t *in, uint8_t *data, uint8_t src, uint32_t src_offset, uint64_t nonce, uint8_t *pub_key) {
  uint8_t hash[32];
  keccak_256_init();
  keccak_256_update(data, PAGE_SIZE);
  keccak_256_update(&src, 1);
  keccak_256_update(&src_offset, 4);
  keccak_256_update(&nonce, 8);
  keccak_256_finalize(hash);
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
  icm_config->frame_depth = 0;

  // Query history
#ifdef DUMMY
  icm_clear_query_history();
#endif
}

void icm_clear_storage() {
  memset(icm_temp_storage->valid, 0, sizeof(icm_temp_storage->valid));
  icm_pool_init(&(icm_temp_storage->pool));

  icm_config->deployed_codes_pointer = icm_config->deployed_codes;
  icm_config->deployed_codes->top = icm_ram_deployed_code;
  
  icm_config->local_balance_pointer = icm_config->local_balance;
  
  icm_config->integrity_valid = 1;
  icm_config->check_signature_of_immutable_mem = 1;
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

// ICM Storage Operation

void icm_pool_init(ICMStoragePool *p) {
  p->item_count = 0;
  memset(p->head, 0xff, sizeof(p->head));
  for (int i = 0; i < storage_record_count; i++)
    p->pos[i] = i;
}

void icm_add_storage_item(ICMStoragePool *p, uint32_t id, uint256_t v, uint256_t k, address_t a) {
  // update valid
  if (!icm_temp_storage->valid[id]) {
    icm_temp_storage->valid[id] = 1;
    memcpy(icm_temp_storage->record[id].k, k, sizeof(uint256_t));
    memcpy(icm_temp_storage->record[id].a, a, sizeof(address_t));
  }
  // check local depth item
  uint32_t pos = p->head[id];
  if (pos != (uint32_t)(-1) && p->pool[pos].depth == icm_config->frame_depth) {
    memcpy(p->pool[pos].v, v, sizeof(uint256_t));
    return;
  }
  // update ICMStorageItem
  pos = p->pos[p->item_count];
  p->pool[pos].depth = icm_config->frame_depth;
  memcpy(p->pool[pos].v, v, sizeof(uint256_t));
  // maintain bel info, update linked list
  p->bel[pos] = id;
  p->nxt[pos] = p->head[id];
  p->head[id] = pos;
  // update counter
  p->ordered_index[p->item_count++] = pos;
}

void icm_del_storage_item(ICMStoragePool *p, uint32_t id) {
  // update linked list
  if (p->nxt[id] == (uint32_t)(-1))
    icm_temp_storage->valid[p->bel[id]] = 0;
  p->head[p->bel[id]] = p->nxt[id];
  p->nxt[id] = (uint32_t)(-1);
}

// dump all items with depth = 0 (which is definitely modification)
void icm_dump_storage() {
  // dump storage from OCM to HOST
  ECP *res = get_output_buffer(), tmp;
  memcpy(&tmp, res, sizeof(ECP));
  res->opcode = COPY;
  res->src = STORAGE;
  res->dest = HOST;
  res->func = 1;
  res->src_offset = 0;
  res->dest_offset = 0;

  ICMStoragePool* p = &(icm_temp_storage->pool);
  uint32_t count = p->item_count, content_length = 4, i = 0;
  
  for (; i < p->item_count; i++) {
	uint32_t index = p->ordered_index[i];
    if (p->pool[index].depth) break;
    memcpy(icm_raw_data_base + content_length, &(icm_temp_storage->record[p->bel[index]]), sizeof(ICMStorageRecord)), content_length += sizeof(ICMStorageRecord);
    memcpy(icm_raw_data_base + content_length, &(p->pool[index].v), sizeof(uint256_t)), content_length += sizeof(uint256_t);
    icm_del_storage_item(p, index), p->pos[--count] = index;
  }
  for (uint32_t j = i; j < p->item_count; j++)
    p->ordered_index[j - i] = p->ordered_index[j];
  p->item_count = count;
#ifdef SIGNATURE
  if (!icm_config->integrity_valid)
    count += 10001;
#endif
  *(uint32_t*)icm_raw_data_base = i;
  res->length = content_length;

#ifdef ENCRYPTION
  uint32_t sign_offset = padded_size(content_length, 4);
#else
  uint32_t sign_offset = content_length;
#endif

#ifdef SIGNATURE
  // the signature is calculated over plaintext
  ecdsa_sign(res->data + sign_offset, icm_raw_data_base, content_length, STORAGE, 0, icm_config->hevm_priv);
#endif

  // encrypt storage elements
  aes_encrypt_ext(res->data, icm_raw_data_base, content_length);
  // memcpy(res->data, icm_raw_data_base, content_length);

#ifdef SIGNATURE
  content_length = sign_offset + 56;
#else
  content_length = sign_offset;
#endif

  build_outgoing_packet(sizeof(ECP) + content_length);

  // when storage pool is full with new modification, send all modification back to host
  if (i == 0 && p->item_count) {
    for (; i < p->item_count; i++) {
	    uint32_t index = p->ordered_index[i];
	    p->pool[index].depth = 0;
    }
    icm_dump_storage();
  }

  memcpy(res, &tmp, sizeof(ECP));
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
  icm_timing_pause();

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
  icm_config->icm_ocm_return_has_sign = 1;

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
      value = (uint8_t*)((uint64_t)evm_stack + 64);
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
        value = (uint8_t*)call_frame->value;
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
      dma_read_mem(evm_env_addr + 32 * 2, icm_raw_data_base, 32);
      gas = *(uint64_t*)icm_raw_data_base;
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
    }

#ifdef ICM_DEBUG
    icm_debug("call offset", 11);
    icm_debug(&offset, 4);
    icm_debug("call size", 9);
    icm_debug(&size, 4);
#endif

    if (icm_config->calling_precompiled) {
      // no need to transfer value (avoid ether burn)
      // no need to push stack
      // just copy params
      void *base = call_frame->top;

      icm_config->immutable_page_type = CALLDATA;
      icm_config->immutable_page = base;
      icm_config->immutable_page_sign = base + page_length(input_length);
      icm_config->immutable_page_length = input_length;

      dma_read_mem(evm_env_addr, icm_raw_data_base, 32);
      call_frame->pc = *(uint32_t*)icm_raw_data_base;
      call_frame->pc++;

      cesm_state = CESM_WAIT_FOR_PRECOMPILED_INPUT_COPY;
    } else {
      // stack push
      if (func != OP_DELEGATECALL && func != OP_STATICCALL)
        transferBalance(callee_caller_address, callee_address, value);
      icm_stack_push(callee_address, callee_storage_address, callee_caller_address, code_length, input_length, gas, value, getBalance(callee_address)->balance);
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

    icm_timing_pause();

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
    memset(icm_raw_data_base, 0, 32);
    *(uint32_t*)icm_raw_data_base = call_frame->return_length;
    dma_write_mem(icm_raw_data_base, evm_env_addr + 8 * 32, 32);

    // Resume
    cesm_state = CESM_WAIT_FOR_MEMORY_COPY;
    if (icm_config->immutable_page_length) {
      icm_config->cesm_ready = 0;
      
      icm_config->check_signature_of_immutable_mem = 0;
      icm_config->icm_ocm_return_has_sign = 0;

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
      memset(icm_raw_data_base, 0, 32);
      memcpy(icm_raw_data_base, call_frame->storage_address, sizeof(address_t));
      dma_write_mem(icm_raw_data_base, evm_env_addr + 4 * 32, 32);

      // transfer call value
      icm_switch_contract(
        call_frame->address,
        call_frame->address,
        caller_frame->stack
      );
      icm_timing_continue();
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
      if (icm_config->deployed_codes_pointer >= icm_config->local_balance)
        icm_debug("deployed code overflow", 22);
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

    ICMStoragePool* p = &(icm_temp_storage->pool);
    uint32_t frame_st = p->item_count, tmp = p->item_count;
    while(frame_st && p->pool[p->ordered_index[frame_st - 1]].depth == icm_config->frame_depth) frame_st--;
    // handle storage update, revert(delete) all the storage modification with this depth
    if (end_func == OP_REVERT || end_func == OP_STATICCALL || end_func == OP_INVALID) {
      for (; frame_st < tmp; frame_st++) {
        icm_del_storage_item(p, p->ordered_index[frame_st]);
        p->pos[--p->item_count] = p->ordered_index[frame_st];
      }
    }
    else {  // save this depth storage to next depth
      uint32_t st = frame_st;
      for (; frame_st < tmp; frame_st++) {
        uint32_t index = p->ordered_index[frame_st];
        if (p->nxt[index] != (uint32_t)(-1) && p->pool[p->nxt[index]].depth == icm_config->frame_depth - 1) {
          memcpy(p->pool[p->nxt[index]].v, p->pool[index].v, sizeof(uint256_t));
          icm_del_storage_item(p, index), p->pos[--p->item_count] = index;
        } else {
          p->pool[index].depth = icm_config->frame_depth - 1;
          p->ordered_index[st++] = index;
        }
      }
    }

    icm_stack_pop();

    if (icm_stack_is_empty()) {
      cesm_state = CESM_IDLE;

      icm_timing_pause();

      // Finish
      ECP *ecp = get_output_buffer();
      ecp->opcode = END;
      ecp->src = CONTROL;
      ecp->dest = HOST;
      ecp->func = end_func;
      ecp->src_offset = 0;
      ecp->dest_offset = 0;
      ecp->length = icm_config->immutable_page_length;
      ((uint64_t*)(ecp->data))[0] = total_time;
      ((uint64_t*)(ecp->data))[1] = COUNTS_PER_SECOND;
      build_outgoing_packet(sizeof(ECP) + 16);
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
    
    icm_config->check_signature_of_immutable_mem = 1;

    // Copy back EVM stack
    uint32_t new_stack_size = call_frame->stack_size - call_frame->num_of_params + 1;
    *(uint32_t*)icm_raw_data_base = new_stack_size;
    if (call_frame->call_end_func == OP_CREATE || call_frame->call_end_func == OP_CREATE2) {
      memset(icm_raw_data_base + 4 + 20, 0, 12);
      memcpy(icm_raw_data_base + 4, icm_config->deployed_codes_pointer->address, 20);
    } else {
      // set success
      memset(icm_raw_data_base + 4, 0, 32);
      *(uint8_t*)(icm_raw_data_base + 4) = ((call_frame + 1)->call_end_func != OP_REVERT && (call_frame + 1)->call_end_func != OP_INVALID);
    }
    aes_decrypt_stack(icm_raw_data_base + 4 + 32, call_frame->stack + 32 * call_frame->num_of_params, 32 * (new_stack_size - 1));
#ifdef ICM_DEBUG
    icm_debug("recover stack", 13);
    icm_debug(&call_frame->stack_size, 4);
    icm_debug(&new_stack_size, 4);
    icm_debug(icm_raw_data_base + 4, new_stack_size * 32);
#endif

#ifdef ICM_DEBUG
    {
      char tmp[100];
      int len = sprintf(tmp, "depth -- -> %d", call_frame - icm_config->call_stack);
      icm_debug(tmp, len);
    }
#endif

#ifdef SIGNATURE
    if (!hash_verify(call_frame->stack_sign, icm_raw_data_base + 4 + 32, 32 * (new_stack_size - 1), STACK, 0, icm_config->hevm_pub)) {
      icm_debug("stack signature verification failed!", 36);
      icm_config->integrity_valid = 0;
    }
#endif
    // Function evm_load_stack() will reorder stack data, since push should from bottom data. Here we need to verify
    //  stack data first, and then load them back to hardware.
    evm_load_stack(1);

    if (icm_config->calling_precompiled) {
      memset(icm_raw_data_base, 0, 32);
      *(uint32_t*)icm_raw_data_base = call_frame->pc;
      dma_write_mem(icm_raw_data_base, evm_env_addr, 32);
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
    dma_read_mem(evm_env_addr + 9 * 32, icm_raw_data_base, 32);
    memcpy(icm_raw_data_base, icm_config->contract_balance_after_transfer, 32);

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
#ifdef ICM_DEBUG
  icm_debug(req, 16);
#endif

  if (req->opcode == ICM) {
    if (req->func == ICM_CLEAR_STORAGE) {
      icm_clear_storage();
    } else if (req->func == ICM_SET_USER_PUB) {
      reset_udp();
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
      icm_timing_continue();
      if (icm_config->contract_address_waiting_for_size &&
        memcmp(req->data, icm_config->contract_address_waiting_for_size, 20) == 0) {
        fetchBalance(icm_config->contract_address_waiting_for_size, req->data + 20);
        icm_config->contract_address_waiting_for_size = NULL;
        if (icm_config->found_deployed_code == NULL)
          icm_config->ext_code_size = req->length;
        icm_step();
      }  
    } else if (req->func == ICM_FINISH) {
      icm_timing_continue();
#ifdef ICM_DEBUG
      icm_debug("received precompiled return value", 33);
      icm_debug(&(icm_config->immutable_page_length), 4);
#endif
      icm_step();
    } else if (req->func == ICM_CLEAR_BALANCE) {
      clearBalance();
    }
    return 0;
  } else if (req->opcode == DEBUG) {  // only for debug mode, does not encrypt
    // do nothing
    return 1;
  } else if (req->opcode == CALL) {
    // icm_tmp_test();
    // check integrity, return 0 if failed, and the tx will not run

    // check stack hash
    // starts anew, the stack must be empty
    evm_clear_stack();
#ifdef ICM_DEBUG
    icm_debug("call", 4);
#endif

#ifdef DUMMY
    icm_init_dummy_generator();
#endif

    // [TODO] check merkle proof of ENV values

    // check passed
    call_frame = icm_config->call_stack;
    dma_read_mem(evm_env_addr + 2 * 32, icm_raw_data_base, 32 * 8);
    memcpy(call_frame->address, icm_raw_data_base + 32, sizeof(address_t));
    
    call_frame->storage_address = call_frame->address;
    call_frame->caller_address = icm_config->zero;
    call_frame->call_end_func = req->func;

#ifdef ICM_DEBUG
    icm_debug("load", 4);
#endif

    address_t address;
    uint32_t code_length, input_length;
    uint64_t gas;
    uint256_t value, balance;

    memcpy(address, icm_raw_data_base + 32 * 2, sizeof(address_t));
    icm_config->found_deployed_code = icm_find_locally_deployed_contract_code(address);
    if (icm_config->found_deployed_code) {
      code_length = icm_config->found_deployed_code->length;
    } else {
      code_length = *((uint32_t*)(icm_raw_data_base + 32 * 3));
    }
    input_length = *((uint32_t*)(icm_raw_data_base + 32 * 4));
    gas = *((uint64_t*)(icm_raw_data_base));
    memcpy(value, icm_raw_data_base + 32 * 5, 32);
    memcpy(balance, icm_raw_data_base + 32 * 7, 32);
#ifdef ICM_DEBUG
    icm_debug(address, 20);
    icm_debug(&code_length, 4);
    icm_debug(&input_length, 4);
#endif
    icm_stack_push(address, SELF_ADDRESS, call_frame->address, code_length, input_length, gas, value, balance);
    fetchBalance(address, balance);
    return 1;
  } else if (req->opcode == END) {
    // External force quit
    icm_timing_start();
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
      
#ifdef DUMMY
      // responses of dummy requests should be discarded
      if (icm_config->query_real_type != 0 || 
          memcmp(req->data + 4, icm_config->query_real_address, sizeof(address_t)) ||
          memcmp(req->data + 4 + 20, icm_config->sload_real_key, sizeof(uint256_t))) {
#ifdef ICM_DEBUG
        icm_debug("dummy sload", 11);
#endif
        return 0;
      }
#endif

      icm_timing_continue();

#ifdef ICM_DEBUG
      icm_debug("real sload", 10);
#endif

      icm_config->query_real_type = 1;

      // plaintext need not decrypt
      memcpy(icm_raw_data_base, req->data, req->length);
#ifdef ICM_DEBUG
      icm_debug(icm_raw_data_base, req->length);
#endif

      void *base = icm_raw_data_base;
      uint32_t num_of_items = *(uint32_t*)base;
      uint32_t offset = 4 + 20;

      for (uint32_t i = 0; i < num_of_items; i++, offset += 64) {
        uint32_t id = icm_find(base + offset);
        // OCM need not encryption
        icm_add_storage_item(&(icm_temp_storage->pool), id, base + offset + 32, base + offset, call_frame->storage_address);

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
        // icm_timing_continue();

        // plain text
        // [TODO] check integrity <del> by merkle tree </del>
        // [TODO] check integrity by USER signature
        memcpy(icm_raw_data_base, req->data, req->length);

#ifdef ICM_DEBUG
    icm_debug("recv env", 8);
#endif
      } else if (req->dest == CODE) { // After internalize, this will be code only
        icm_timing_continue();
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
          aes_decrypt_ext(icm_raw_data_base, req->data, req->length);
          char sign[64];
          memcpy(sign, req->data + req->length, 56);

          if (req->length <= PAGE_SIZE) {
            memset(icm_raw_data_base + req->length, 0, PAGE_SIZE - req->length);
            memcpy(icm_config->buffer, icm_raw_data_base, PAGE_SIZE);
            aes_encrypt(call_frame->code + req->dest_offset, icm_config->buffer, PAGE_SIZE);
          }

#ifdef SIGNATURE
          // verify user hash
          if (!ecdsa_verify_page(sign, icm_raw_data_base, CODE, req->dest_offset, 0, icm_config->user_pub)) {
            icm_debug("user code page verification failed!", 35);
            icm_config->integrity_valid = 0;
          }
#endif
          
        } else {
          // icm_debug("plaintext code", 14);
          memcpy(icm_raw_data_base, req->data, req->length);
          memset(icm_raw_data_base + req->length, 0, PAGE_SIZE - req->length);
          memcpy(call_frame->code + req->dest_offset, icm_raw_data_base, PAGE_SIZE);

          // [TODO] prefetch
        }
        
        // icm_debug(icm_raw_data_base, PAGE_SIZE);
      } else if (req->dest == CALLDATA && call_frame == (icm_config->call_stack + 1)) { // After internalize, this will be code only
        icm_timing_continue();
        call_frame->input_mark[mark_offset(req->dest_offset)] = 1 | 2;  // mark as valid
#ifdef ICM_DEBUG
        icm_debug("recv input", 10);
        icm_debug(&req->dest_offset, 4);  
#endif
        aes_decrypt_ext(icm_raw_data_base, req->data, req->length);

        char sign[64];
        memcpy(sign, req->data + req->length, 56);
        if (req->length < PAGE_SIZE) {
          memset(icm_raw_data_base + req->length, 0, PAGE_SIZE - req->length);
          memcpy(icm_config->buffer, icm_raw_data_base, PAGE_SIZE);
          aes_encrypt(call_frame->input + req->dest_offset, icm_config->buffer, PAGE_SIZE);
        } else {
          memcpy(call_frame->input + req->dest_offset, icm_raw_data_base, PAGE_SIZE);
        }

#ifdef SIGNATURE
        // verify user hash
        if (!ecdsa_verify_page(sign, icm_raw_data_base, CALLDATA, req->dest_offset, 0, icm_config->user_pub)) {
          icm_debug("user calldata page verification failed!", 39);
          icm_config->integrity_valid = 0;
        }
#endif
      } else if (req->dest == STACK) {
#ifdef ICM_DEBUG
        icm_debug("recv stack", 10);
        icm_debug(req->data + 4, 32);
#endif

#ifdef DUMMY
        if (req->func != icm_config->query_real_type || memcmp(icm_config->query_real_address, req->data, 20)) {
#ifdef ICM_DEBUG
          icm_debug("dummy query", 11);
#endif
          return 0;
        }
#endif

      icm_timing_continue();

#ifdef ICM_DEBUG
        icm_debug("real query", 10);
#endif
        req->func = 0;
        icm_config->query_real_type = 1;

        // [TODO] Length has to be 0 or 1
        memcpy(icm_raw_data_base, req->data + 20, req->length - 20);
      } else if (req->dest == RETURNDATA && cesm_state == CESM_WAIT_FOR_PRECOMPILED_EXECUTION) {
#ifdef ICM_DEBUG
        icm_debug("recv precompiled results", 24);
#endif
        // This is NOT SIGNED
        if (req->length < PAGE_SIZE) {
          memset(req->data + req->length, 0, PAGE_SIZE - req->length);
        }
        aes_encrypt(icm_config->immutable_page + req->dest_offset, req->data, req->length);
        if (icm_config->immutable_page_length < req->dest_offset + req->length)
          icm_config->immutable_page_length = req->dest_offset + req->length;
        return 0;
      }
      
      icm_timing_continue();
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
    if (req->func == ExtCodeSize || req->func == ExtCodeHash) {
      OCMDeployedCodeFrame *p = icm_find_locally_deployed_contract_code(icm_raw_data_base);
      if (p) {
        if (req->func == ExtCodeSize) {    // ExtCodeSize
          memcpy(icm_raw_data_base, &(p->length), 4);
          memset(icm_raw_data_base + 4, 0, sizeof(uint256_t) - 4);
  #ifdef ICM_DEBUG
          icm_debug("found locally", 13);
          icm_debug(icm_raw_data_base, 32);
  #endif
          return 1;
        }
        else if (req->func == ExtCodeHash) { // ExtCodeHash
          memcpy(icm_raw_data_base, p->code_hash, 32);
  #ifdef ICM_DEBUG
          icm_debug("found locally", 13);
          icm_debug(icm_raw_data_base, 32);
  #endif
          return 1;
        }
      }
    } else if (req->func == Balance) {
      OCMBalance* b = getBalance(icm_raw_data_base);
      if (b) {
        memcpy(icm_raw_data_base, b->balance, sizeof(uint256_t));
        return 1;
      }
    }
    

    // plaintext params
    // memcpy(req->data, icm_raw_data_base, content_length);
    // build_outgoing_packet(sizeof(ECP) + content_length);

    icm_timing_pause();

#ifdef DUMMY
    icm_config->query_real_type = req->func;
    memcpy(icm_config->query_real_address, icm_raw_data_base, 20);

    icm_record_query(req->func, icm_raw_data_base, NULL);
    icm_send_query_with_dummy(req->func, icm_raw_data_base, NULL);
#else
    icm_send_query(req->func, icm_raw_data_base, NULL);
#endif

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
          icm_add_storage_item(&(icm_temp_storage->pool), id, base + offset + 32, base + offset, call_frame->storage_address);

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
#ifdef ICM_DEBUG
          {
            icm_debug("OCM store", 9);
            icm_debug(base, 64);
            icm_debug(call_frame->storage_address, 20);
          }
#endif

          // OCM need no encryption
          icm_add_storage_item(&(icm_temp_storage->pool), id, base + 32, base, call_frame->storage_address);
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
        uint32_t pool_id = icm_temp_storage->pool.head[id];
        if (icm_temp_storage->valid[id]) {
          ICMStorageItem* item = &(icm_temp_storage->pool.pool[pool_id]);
          // found, do not send output request
          memcpy(icm_raw_data_base, base, 4 + 32);
          memcpy(icm_raw_data_base + 4 + 32, item->v, 32);
          
          // evm_load_storage();
          return 1;
        }
        
        // 1. if still not found, generate plaintext dummy requests
        // record 
        icm_config->query_real_type = 0;
        memcpy(icm_config->query_real_address, call_frame->storage_address, sizeof(address_t));
        memcpy(icm_config->sload_real_key, base + 4, sizeof(uint256_t));
        
        icm_timing_pause();

        // since the swapped-out record has been saved in phase 0
        // we are not sending it again, instead set the output num_of_items to 0
#ifdef DUMMY
        icm_record_query(0, call_frame->storage_address, base + 4);
        icm_send_query_with_dummy(0, call_frame->storage_address, base + 4);
        // icm_send_query_with_dummy(base + 4);
#else
        icm_send_query(0, call_frame->storage_address, base + 4);
#endif
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
#ifdef SIGNATURE
          // sign entire stack (except params)
          hash_sign(call_frame->stack_sign, icm_raw_data_base + 4, content_length - 4, STACK, 0, icm_config->hevm_priv);
#endif

#ifdef DEBUG
          {
            char tmp[100];
            int len = sprintf(tmp, "depth %d -> ++", call_frame - icm_config->call_stack);
            icm_debug(tmp, len);
          }
#endif

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
#ifdef ENCRYPTION
              memcpy(target_page + target_frame->memory_length, zero_page, PAGE_SIZE);
#else
              memset(target_page + target_frame->memory_length, 0, PAGE_SIZE);
#endif
#ifdef SIGNATURE
              if (!init) {
                init = 1;
                memset(zero, 0, PAGE_SIZE);
              }
              hash_sign_page(target_page_sign + sign_offset(target_frame->memory_length), zero, target_page_type, target_frame->memory_length, 0, icm_config->hevm_priv);
#endif

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
#ifdef SIGNATURE
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
#endif

          if (end) {
            cipher_length = aes_encrypt_ext(target_page + req->src_offset, icm_raw_data_base, content_length);

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

#ifdef SIGNATURE
            cipher_length += 56;
#endif
            build_outgoing_packet(sizeof(ECP) + cipher_length);
            return 1;
          } else {
            cipher_length = aes_encrypt(target_page + req->src_offset, icm_raw_data_base, content_length);
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
              if (target_page_mark[mark_offset(req->dest_offset)] & 2) { // encrypted
                aes_decrypt(icm_raw_data_base, target_page + req->dest_offset, PAGE_SIZE);
              } else {
                // icm_debug("plaintext code", 14);
                memcpy(icm_raw_data_base, target_page + req->dest_offset, PAGE_SIZE);
              }
            } else if (req->src == CODE && icm_config->call_frame_pointer->locally_deployed_contract_code) {
              aes_decrypt(icm_raw_data_base, icm_config->call_frame_pointer->locally_deployed_contract_code->code + req->dest_offset, PAGE_SIZE);
            } else {
#ifdef ICM_DEBUG
              icm_debug("send out", 8);
#endif
              // pass out

              // set_retry_send();
              icm_timing_pause();
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

#ifdef SIGNATURE
              if (req->src == OCM_IMMUTABLE_MEM && !icm_config->check_signature_of_immutable_mem) {
                // do not check
              } else if (target_page_type == RETURNDATA && !icm_config->icm_ocm_return_has_sign) {
                // do not check
              } else if (!hash_verify_page(target_page_sign + sign_offset(req->dest_offset), icm_raw_data_base, target_page_type, req->dest_offset, 0, icm_config->hevm_pub)) {
                icm_debug("page signature verification failed!", 35);
                icm_debug(&target_page_type, 1);
                icm_debug(&(req->dest_offset), 4);
                icm_debug(&(target_frame->memory_length), 4);
                icm_config->integrity_valid = 0;
              }
#endif
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

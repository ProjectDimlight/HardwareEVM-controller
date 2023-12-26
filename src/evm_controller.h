#ifndef __EVM_CONTROLLER_H_
#define __EVM_CONTROLLER_H_

// #define SIMULATION
#include <stdint.h>

#define PAGE_SIZE 1024
#define NUMBER_OF_PAGES 4

extern volatile void* const evm_base_addr 		  ;
extern volatile void* const evm_cin_addr  		  ;
extern volatile void* const evm_cout_addr 		  ;
extern volatile void* const evm_code_addr     	;
extern volatile void* const evm_calldata_addr 	;
extern volatile void* const evm_mem_addr 		    ;
extern volatile void* const evm_storage_addr    ;
extern volatile void* const evm_env_addr 		    ;
extern volatile void* const evm_stack_addr      ;

extern volatile void* const evm_env_stack_size;
extern volatile void* const evm_env_pc;
extern volatile void* const evm_env_gas;
extern volatile void* const evm_env_msize;
extern volatile void* const evm_env_value;
extern volatile void* const evm_env_balance;
extern volatile void* const evm_env_code_size;
extern volatile void* const evm_env_calldata_size;
extern volatile void* const evm_env_returndata_size;
extern volatile void* const evm_env_address;
extern volatile void* const evm_env_caller;

extern const uint64_t pt_offset 		  ;
extern const uint64_t page_tag_mask	  ;
extern const uint64_t page_tagid_mask	;
extern const uint64_t page_id_mask	  ;
extern const uint64_t page_idof_mask  ;
extern const uint64_t page_of_mask	  ;
extern const uint64_t page_size 	    ;

enum EvmProtocolOperation {
  NONE,   // do nothing
  CALL,   // let the evm run from pc = 0 (code and call data are prepared)
  COPY,   // copy between memories
  SWAP,   // cache swap (mem and storage) req invoked by evm; host should reply with a "copy"
  END,    // contract execution over; evm send all storage change to host
  DEBUG,  // evm send {pc, gas, stackSize, all stack data} to host
  QUERY,  // require the host to send information to hevm
  LOG,    // log instruction
  ICM     // operations only for ICM
};

enum DebugFunc {
  DEBUG_TRACE_OFF,
  DEBUG_TRACE_ON,
  DEBUG_STEP_OFF,
  DEBUG_STEP_ON,
  DEBUG_TRACE_DATA
};

enum CallEndFunc {
  OP_STOP = 0x00,
  OP_RESUME = 0x01,
  OP_CREATE = 0x10,
  OP_CALL,
  OP_CALLCODE,
  OP_RETURN,
  OP_DELEGATECALL,
  OP_CREATE2,
  OP_STATICCALL = 0x1a,
  OP_REVERT = 0x1d,
  OP_SELFDESTRUCT = 0x1f
};

enum DataSource {
  CONTROL,
  CODE,
  CALLDATA,
  MEM,
  STORAGE,
  ENV,
  STACK,
  HOST,
  RETURNDATA,
  OCM_MEM,
  OCM_IMMUTABLE_MEM
};

typedef struct {
  uint8_t opcode;
  uint8_t src;
  uint8_t dest;
  uint8_t func;
  uint32_t src_offset;
  uint32_t dest_offset;
  uint32_t length;
  uint8_t data[0];
} __attribute__((packed)) ECP;  // EVM Control Protocol

#define ECP_OFFSET(p) ((ECP*)(p))

extern int evm_active;
extern uint32_t env_reg_buffer[8];

void evm_memory_copy(ECP *req);
void handle_ecp(ECP *buf);
void check_evm_output();
void check_debug_buffer();

void *memcpy_b(void *dst0, void *src0, uint32_t len0);
void *memset_b(void *dst0, uint8_t val, uint32_t len0);

void dma_read_env(void* env_addr);
void dma_write_env(void* env_addr);
void dma_memcpy(void* dst_addr, void* src_addr, uint32_t length);

#endif

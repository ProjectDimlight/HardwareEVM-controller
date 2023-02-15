#ifndef __EVM_CONTROLLER_H_
#define __EVM_CONTROLLER_H_

// #define SIMULATION

#define PAGE_SIZE 1024
#define NUMBER_OF_PAGES 4

enum EvmProtocolOperation {
  NONE,   // do nothing
  CALL,   // let the evm run from pc = 0 (code and call data are prepared)
  COPY,   // copy between memories
  SWAP,   // cache swap (mem and storage) req invoked by evm; host should reply with a "copy"
  END,    // contract execution over; evm send all storage change to host
  DEBUG,  // evm send {pc, gas, stackSize, all stack data} to host
  QUERY   // require the host to send information to hevm
};

enum DebugFunc {
  DEBUG_TRACE_OFF,
  DEBUG_TRACE_ON,
  DEBUG_STEP_OFF,
  DEBUG_STEP_ON,
  DEBUG_TRACE_DATA
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
  RETURNDATA
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

void ecp(uint8_t *buf);
void clear_storage();
void check_evm_output();

#endif

#include "udp_server.h"
#include "evm_controller.h"
#include "evm_test_program.h"

extern uint8_t buf_in [4096];
extern uint8_t buf_out[4096];

uint8_t *sim_ram = (uint8_t*)buf_in;
int step = 0;
int delay = 50;
int echo_length;

int require_sim_ram_reply = 0;

void initial() {
  ECP *req = (ECP*)sim_ram;
  void *addr_src = req->data;

  ///////////////////////////////////////////////

  req->opcode = COPY;
  req->src = HOST;
  req->dest = STACK;
  req->src_offset = 0;
  req->dest_offset = 0;
  req->length = 32 * 3 + 4;

  *(int*)addr_src = 3;
  uint8_t *data8 = addr_src + 4;

  for (int i = 0; i < 32 * 3; i++)
    data8[i] = 0;

  data8[0] = 1;
  data8[32] = 2;
  data8[64] = 3;

  ecp(sim_ram);

  echo_length = 16 + req->length;
  memcpy(buf_out, buf_in, echo_length);
  build_outgoing_packet(echo_length);

  ///////////////////////////////////////////////

  req->opcode = CALL;
  req->src = HOST;
  req->dest = CONTROL;
  req->src_offset = 0;
  req->dest_offset = 0;
  req->length = 0;

  ecp(sim_ram);

  echo_length = 16 + req->length;
  memcpy(buf_out, buf_in, echo_length);
  build_outgoing_packet(echo_length);
}

void init_code() {
  ECP *req = (ECP*)sim_ram;
  void *addr_src = req->data;

  req->opcode = COPY;
  req->src = HOST;
  req->dest = CODE;
  req->src_offset = 0;
  req->dest_offset = 0;
  req->length = sizeof(code);

  memcpy(addr_src, code, sizeof(code));

  ecp(sim_ram);

  echo_length = 16 + req->length;
  memcpy(buf_out, buf_in, echo_length);
  build_outgoing_packet(echo_length);
}

void init_mem() {
  ECP *req = (ECP*)sim_ram;
  void *addr_src = req->data;

  req->opcode = COPY;
  req->src = HOST;
  req->dest = MEM;
  req->src_offset = 0;
  req->dest_offset = 0;
  req->length = 1024;

  for (int i = 0; i < 1024; i++)
    ((uint8_t*)addr_src)[i] = 0;

  ecp(sim_ram);

  echo_length = 16 + req->length;
  memcpy(buf_out, buf_in, echo_length);
  build_outgoing_packet(echo_length);
}

void init_calldata() {
  ECP *req = (ECP*)sim_ram;
  void *addr_src = req->data;

  req->opcode = COPY;
  req->src = HOST;
  req->dest = CALLDATA;
  req->src_offset = 0;
  req->dest_offset = 0;
  req->length = 64;

  for (int i = 0; i < 64; i++)
    ((uint8_t*)addr_src)[i] = i;

  ecp(sim_ram);

  echo_length = 16 + req->length;
  memcpy(buf_out, buf_in, echo_length);
  build_outgoing_packet(echo_length);
}

/*
  req->opcode = COPY;
  req->src = HOST;
  req->dest = ENV;
  req->src_offset = 0;
  req->dest_offset = 32 * 15;
  req->length = 8;

  *(int*)addr_src = 0xe;
  *(int*)(addr_src + 4) = 0;

  ecp(sim_ram);

  // wait
  for (int i = 0; i < delay; i++);
*/

void calldata_copy_miss() {
  ECP *req = (ECP*)sim_ram;
  void *addr_src = req->data;

  req->opcode = COPY;
  req->src = HOST;
  req->dest = MEM;
  req->src_offset = 0;
  req->dest_offset = 0;
  req->length = 64;

  for (int i = 0; i < 64; i++)
    ((uint8_t*)addr_src)[i] = 0;

  echo_length = 16 + req->length;
  memcpy(buf_out, buf_in, echo_length);
  build_outgoing_packet(echo_length);
}

void long_jump_contract_miss() {
  ECP *req = (ECP*)sim_ram;
  void *addr_src = req->data;

  req->opcode = COPY;
  req->src = HOST;
  req->dest = CODE;
  req->src_offset = 0;
  req->dest_offset = 1024;
  req->length = 0x92 - 0x89 + 0x6;

  for (int i = 0; i < 0x6; i++)
    ((uint8_t*)addr_src)[i] = 0;
  memcpy(addr_src + 0x6, code + 0x89, 0x92 - 0x89);

  ecp(sim_ram);

  echo_length = 16 + req->length;
  memcpy(buf_out, buf_in, echo_length);
  build_outgoing_packet(echo_length);
}

void (*test[])() = {
  initial,
  init_code,
  //init_mem,
  init_calldata,
  calldata_copy_miss,
  long_jump_contract_miss
};

void check_simram() {
  if (require_sim_ram_reply) {
	memcpy(buf_out, "simram", 6);
	memcpy(buf_out + 6, &step, 4);
	build_outgoing_packet(10);

    test[step]();
    step++;
    require_sim_ram_reply = 0;
  }
}

#include "udp_server.h"
#include "evm_controller.h"
#include "sim_ram.h"

void wait(int time) {
	time *= 1000000;
	for (int i = 0; i < time; i++);
	return;
}

void *memcpy_b(void *dst0, void *src0, uint32_t len0)
{
  char *dst = dst0;
  char *src = src0;
  while (len0--)
    *dst++ = *src++;
  return dst0;
}

// EVM hardware addressing
// 0x10000000: control(input) "call"
// 0x10000004: control(input) "ready" (evm stop stalling)
// 0x10008000: control(output)
// 0x10010000: code
// 0x10020000: calldata
// 0x10030000: memory
// 0x10040000: storage
// 0x10050000: environment
// 0x10060000: stack

const void* evm_base_addr 		= (void*)0x410000000ll;
const void* evm_cin_addr  		= (void*)0x410000000ll;
const void* evm_cout_addr 		= (void*)0x410008000ll;
const void* evm_code_addr     	= (void*)0x410010000ll;
const void* evm_calldata_addr 	= (void*)0x410020000ll;
const void* evm_mem_addr 		= (void*)0x410030000ll;
const void* evm_storage_addr 	= (void*)0x410040000ll;
const void* evm_env_addr 		= (void*)0x410050000ll;
const void* evm_stack_addr 		= (void*)0x410060000ll;
const uint64_t pt_offset 		= 0x8000;
const uint64_t page_tag_mask	= ~0xfff;
const uint64_t page_tagid_mask	= ~0x3ff;
const uint64_t page_id_mask		= 0xc00;
const uint64_t page_idof_mask	= 0xfff;
const uint64_t page_of_mask		= 0x3ff;
const uint64_t page_size 		= 0x400;

void *data_source_to_address(uint8_t data_source, uint32_t offset) {
  return (void *) (evm_base_addr + (data_source << 16) + (offset & page_idof_mask));
}

uint32_t *data_source_to_pte(uint8_t data_source, uint32_t offset) {
  // page addr: 10bit, pte addr: 2bit
  return (uint32_t *) (evm_base_addr + (data_source << 16) + pt_offset + ((offset & page_id_mask) >> 8));
}

int evm_active = 0;

void clear_tag(uint8_t data_source, uint32_t offset) {
  (*data_source_to_pte(data_source, offset)) &= ~3;  // not valid
}

void sync_page_swap(uint8_t dirty, uint8_t src, uint32_t src_offset, uint32_t dest_offset) {
  ECP *buf = (ECP *)get_output_buffer();
  buf->opcode = SWAP;
  buf->src = src;
  buf->dest = HOST;
  buf->src_offset = src_offset;
  buf->dest_offset = dest_offset;
  buf->length = 1024;

  if (dirty) {
    buf->func = 1;
    memcpy_b(buf->data, data_source_to_address(src, src_offset), 1024);
    build_outgoing_packet(sizeof(ECP) + 1024);
  } else {
    buf->func = 0;
    build_outgoing_packet(sizeof(ECP) + 0);
  }

  ECP *p;
#ifdef SIMULATION
  require_sim_ram_reply = 1;
  check_simram();
  p = get_input_buffer();
#else
  while ((p = (ECP*)check_incoming_packet()) == 0);
#endif

  memcpy_b(data_source_to_address(src, dest_offset), p->data, p->length);
  *data_source_to_pte(src, dest_offset) = (dest_offset & page_tagid_mask) | 0x2;
}

void evm_memory_copy(ECP *req) {
  uint8_t src = req->src;
  uint8_t dest = req->dest;
  uint32_t src_offset = req->src_offset;
  uint32_t dest_offset = req->dest_offset;
  uint32_t length = req->length;

  void *addr_src, *addr_dest;
  uint32_t *pte_src, *pte_dest;

  while (length > 0) {
    // before page
    addr_src = data_source_to_address(src, src_offset);
    addr_dest = data_source_to_address(dest, dest_offset);

    pte_src = data_source_to_pte(src, src_offset);
    pte_dest = data_source_to_pte(dest, dest_offset);

    if (((*pte_src) & 2) == 0 || ((*pte_src) & page_tag_mask) != (src_offset & page_tag_mask)) {
      sync_page_swap(0, src, (*pte_src) & page_tagid_mask, src_offset & page_tagid_mask);
    }
    if (((*pte_dest) & 2) == 0 || ((*pte_dest) & page_tag_mask) != (dest_offset & page_tag_mask)) {
      sync_page_swap(((*pte_dest) & 3) == 3, dest, (*pte_dest) & page_tagid_mask, dest_offset & page_tagid_mask);
    }

    // get possible step length
    uint32_t step_length = length;
    if ((src_offset & page_of_mask) + step_length >= page_size)
      step_length = page_size - (src_offset & page_of_mask);
    if ((dest_offset & page_of_mask) + step_length >= page_size)
      step_length = page_size - (dest_offset & page_of_mask);

    // copy
    memcpy_b(addr_dest, addr_src, step_length);

#ifdef SIMULATION
    wait(5);
    memcpy_b(get_output_buffer(), addr_src, step_length);
    build_outgoing_packet(step_length);
    wait(5);
#endif

    // update
    src_offset += step_length;
    dest_offset += step_length;
    length -= step_length;
  }
}

uint16_t local_debug_counter = 0;
uint8_t local_debug_enable = 0;
uint8_t ecp_debug_template[16] = {0x05, 0x00, 0x07};

void check_debug_buffer() {
  if (!local_debug_enable) return;

  uint16_t *debug_counter = evm_cin_addr + 0xc;
  uint32_t *debug_buffer_base = 0xa0000000;
  uint32_t *data = get_output_buffer() + sizeof(ECP);

  for (uint16_t target = *debug_counter; local_debug_counter != target; local_debug_counter++) {
    // pc
	data[0] = debug_buffer_base[local_debug_counter * 4 + 0];

    // gas temporarily set to 0

    // stack size
    data[3] = debug_buffer_base[local_debug_counter * 4 + 3];

	memcpy_b(get_output_buffer(), ecp_debug_template, sizeof(ecp_debug_template));
	build_outgoing_packet(32);

	usleep(1000);
  }
}

void ecp(uint8_t *buf) {
  uint8_t tmp[16];
  memcpy(tmp, buf, 16);
  ECP *req = (ECP*)tmp;

  if (req->opcode == CALL && req->src == HOST) {
    // clear memory valid tag
    // code: clear except first page
    for (int i = 0; i < NUMBER_OF_PAGES; i++)
      clear_tag(CODE, i << 10);
    // calldata: clear except first page
    for (int i = 0; i < NUMBER_OF_PAGES; i++)
      clear_tag(CALLDATA, i << 10);
    // returndata: clear all
    for (int i = 0; i < NUMBER_OF_PAGES; i++)
      clear_tag(RETURNDATA, i << 10);
    // memory: clear all
    for (int i = 0; i < NUMBER_OF_PAGES; i++)
      clear_tag(MEM, i << 10);

    // record status
    evm_active = 1;

    // host tell evm to start
    *(uint8_t*)evm_cin_addr = 1;

    return;
  }
  else if (req->opcode == DEBUG && req->src == HOST) {
	local_debug_enable = req->func;
	*(uint8_t*)0x410000008ll = req->func;
    return;
  }

  void *addr_src, *addr_dest;
  uint32_t content_length = req->length;
  if (req->src == HOST)
    addr_src = get_input_buffer() + sizeof(ECP);
  else
    addr_src = data_source_to_address(req->src, req->src_offset);

  if (req->dest == HOST)
    addr_dest = get_output_buffer() + sizeof(ECP);
  else
    addr_dest = data_source_to_address(req->dest, req->dest_offset);

  if (req->opcode == DEBUG) {
    // fetch pc, gas, stackSize, all stack data
    uint32_t* data = (uint32_t*)addr_dest;

    // pc
    uint32_t *pc = (uint32_t*)(evm_env_addr + 0x1e0);
    data[0] = *pc;

    // gas temporarily set to 0

    // stack size
    uint32_t *stack_size = (uint32_t*)(evm_env_addr + 0x1c0);
    data[3] = *stack_size;

    /*
    // stack elements
    uint32_t *stack_data = (uint32_t*)(evm_stack_addr);
    memcpy_b(&data[4], stack_data, 32 * *stack_size);
	*/

    content_length = 16;
  }
  else if (req->opcode == COPY) {
    if (req->src == STORAGE) {
      // TODO
    }
    else if (req->dest == STORAGE) {
      // fetch all kv pairs and insert to local storage
      uint32_t* data = (uint32_t*)addr_src;
      uint32_t numItem = data[0], offset = 1;
      for (int i = 0; i < numItem; i++, offset += 16) {
        uint32_t index = data[offset] & 0x3f;
        uint32_t* slot = (uint32_t*)(evm_storage_addr + (index << 6));
        slot[0] = (data[offset] & 0xffffffc0) + 0x1;
        for (int j = 1; j < 16; j++)
          slot[j] = data[offset + j];
      }
    }
    else if (req->dest == STACK) {
      // COPY stack
      uint8_t* stackData = (uint8_t*)(evm_stack_addr + 0x8000);
      uint8_t* stackOp   = (uint8_t*)(evm_stack_addr + 0x8024);
      uint32_t* stackSize = (uint32_t*)(evm_env_addr + 0x1c0);

      for (int i = *stackSize; i; i--) {
        // pop
        *stackOp = 0;
      }

      // Then push
      uint32_t numItem = *(uint32_t*)addr_src;
      uint8_t* data = (uint8_t*)addr_src + 4 + 32 * numItem;

      for (int i = numItem; i; i--) {
        data -= 32;
        memcpy_b(stackData, data, 32);
        *stackOp = 1;
      }
    }
    else { // Memory
      if (req->src == HOST) {
        // update page table
        uint32_t *pte = data_source_to_pte(req->dest, req->dest_offset);
        *pte = ((uint32_t)req->dest_offset & page_tagid_mask) | 0x2;

        // only copy data
        // does not copy header
        memcpy_b(addr_dest, addr_src, req->length);
      } else if (req->dest == HOST) {
        // TODO
      } else {
        evm_memory_copy(req);
      }
    }
  }
  else if (req->opcode == SWAP) {
    /* swap from storage will cover 3 conditions:
        1. HEVM commit a dirty slot
        2. HEVM require a missing slot
        3. HEVM first commit a dirty slot, then require a missing slot
      req->length use least-significant 2 bits like that
      if in condition 3:
        first commit a dirty slot, then waiting for HEVM write new tag.
        send ecp package after recieve require tag
    */
    if (req->src == STORAGE) {
      uint32_t* slot = (uint32_t*)(evm_storage_addr + req->src_offset);
      uint32_t* data = (uint32_t*)addr_dest;
      // commit dirty item
      uint32_t offset = 1;
      data[0] = req->length & 0x1;		// dirty bit
      if (data[0]) {
        for (int i = 0; i < 16; i++)
          data[i + 1] = slot[i];
        uint32_t tmp = data[1] & 0xffffffc0;
        data[1] = tmp | (req->src_offset >> 6);
        slot[0] = slot[0] ^ 0x10;  		// clean dirty bit
        offset += 16;
      }
      if (data[0]) while(ECP_OFFSET(evm_cout_addr)->opcode == NONE);
      // require missing item
      data[offset] = (req->length & 0x02) >> 1;
      if (data[offset]) {
        offset++;
        for (int i = 0; i < 8; i++)
          data[i + offset] = slot[i];
        data[offset] = (data[offset] & 0xffffffc0) | (req->src_offset >> 6);
      }
      content_length = (offset + 8) * 4;
    }
    else { // swap memory
      if (req->func) { // has dirty page to send back
    	  memcpy_b(addr_dest, addr_src, req->length);
      } else {
        content_length = 0;
      }
    }

#ifdef SIMULATION
    require_sim_ram_reply = 1;
#endif
  }
  else if (req->opcode == END) {
    // Send a COPY before sending END
    uint32_t numItem = 0, offset = 1;
    uint32_t* data = (uint32_t*)addr_dest;
    uint32_t* slot = (uint32_t*)(evm_storage_addr);
    for (uint32_t index = 0; index < 64; index++, slot += 16)
      // valid and dirty: copy back
      if ((slot[0] & 0x3) == 0x3) {
        data[offset] = (slot[0] & 0xffffffc0) + index;
        for (int i = 1; i < 16; i++)
          data[offset + i] = slot[i];
        numItem++, offset += 16;
      }
    data[0] = numItem;

    ECP *buf = (ECP *)get_output_buffer();

    buf->opcode = COPY;
    buf->src = STORAGE;
    buf->dest = HOST;
    buf->src_offset = 0;
    buf->dest_offset = 0;
    buf->length = 64 * numItem + 4;
    build_outgoing_packet(sizeof(ECP) + buf->length);

    // then pack env variables to the END packet
    // pc, msize, gas
    uint8_t* data8 = (uint8_t*)addr_dest;
    uint8_t* env = (uint8_t*)(evm_env_addr);
    uint8_t* msize = env + 32 * 9;
    uint8_t* gas = env + 32 * 10;
    memcpy_b(data8 + 0,  msize, 8);
    memcpy_b(data8 + 8,  gas,   8);

    // copy return data from mem / call params from stack
    memcpy_b(addr_dest + 16, addr_src, req->length);

    content_length = req->length + 16;
    evm_active = 0;
  }
  else if (req->opcode == CALL) {
    // evm call to host
    // First send current environment to host
    ECP *buf = get_output_buffer();

    // COPY storage
    uint32_t numItem = 0, offset = 1;
    uint32_t* data = (uint32_t*)addr_dest;
    uint32_t* slot = (uint32_t*)(evm_storage_addr);
    for (uint32_t index = 0; index < 64; index++, slot += 16)
      // valid and dirty: copy back
      if ((slot[0] & 0x3) == 0x3) {
        data[offset] = (slot[0] & 0xffffffc0) + index;
        for (int i = 1; i < 16; i++)
          data[offset + i] = slot[i];
        numItem++, offset += 16;
      }
    data[0] = numItem;

    buf->opcode = COPY;
    buf->src = STORAGE;
    buf->dest = HOST;
    buf->src_offset = 0;
    buf->dest_offset = 0;
    buf->length = 64 * numItem + 4;
    build_outgoing_packet(sizeof(ECP) + buf->length);

    // COPY memory
    uint8_t* data8 = (uint8_t*)addr_dest;
    uint8_t *memory = (uint8_t*)(evm_mem_addr);

    uint8_t* env = (uint8_t*)(evm_env_addr);
    uint8_t* pc = env + 32 * 15;
    uint8_t* msize = env + 32 * 9;
    uint8_t* gas = env + 32 * 10;

    uint32_t i;
    memcpy_b(&i,  msize, 4);
    memcpy_b(data8, memory, i);

    buf->opcode = COPY;
    buf->src = MEM;
    buf->dest = HOST;
    buf->src_offset = 0;
    buf->dest_offset = 0;
    buf->length = i;
    build_outgoing_packet(sizeof(ECP) + buf->length);

    // COPY stack
    uint8_t* stackData = (uint8_t*)(evm_stack_addr + 0x8000);
    uint8_t* stackOp   = (uint8_t*)(evm_stack_addr + 0x8024);
    uint32_t* stackSize = (uint32_t*)(evm_env_addr + 0x1c0);
    data[0] = numItem = *stackSize;
    offset = 4;
    for (int i = numItem; i; i--, offset += 32) {
      // fetch the top of the stack
    	memcpy_b(data8 + offset, stackData, 32);
      // then pop
      *stackOp = 0;
    }

    buf->opcode = COPY;
    buf->src = STACK;
    buf->dest = HOST;
    buf->src_offset = 0;
    buf->dest_offset = 0;
    buf->length = 32 * numItem + 4;
    build_outgoing_packet(sizeof(ECP) + buf->length);

    // then pack env variables to the CALL packet and forward the request
    // pc, msize, gas
    memcpy_b(data8 + 0,  pc,    8);
    memcpy_b(data8 + 8,  msize, 8);
    memcpy_b(data8 + 16, gas,   8);

    content_length = 8 * 3;
    evm_active = 0;
  }
  else if (req->opcode == QUERY) {
    // queries need an address (or blockid) as param
    // which is always located at the top of the stack

    content_length = 32;
    memcpy_b(addr_dest, evm_stack_addr, content_length);
  }

  // construct header and send
  if (req->dest == HOST) {
	memcpy_b(get_output_buffer(), req, sizeof(ECP));
    build_outgoing_packet(sizeof(ECP) + content_length);
  }

  // clear local ECP
  if (buf == (uint8_t*)evm_cout_addr) {
	  ECP_OFFSET(buf)->opcode = 0;
  }

  // resume execution
  if (req->dest != HOST || req->opcode == DEBUG) {
#ifdef SIMULATION
      memcpy(get_output_buffer(), "activate", 8);
      build_outgoing_packet(8);
#endif
	 *(char*)(evm_cin_addr + 4) = evm_active;
  }
}

void check_evm_output() {
  uint8_t *p = (uint8_t*)evm_cout_addr;

  if (evm_active && (ECP_OFFSET(p)->opcode != NONE)) {
    // there is an operation
    // delegate to ecp
    ecp(p);
  }
}

void clear_storage() {
  // clear storage
  uint32_t* slot = (uint32_t*)evm_storage_addr;
  for (uint32_t index = 0; index < 64; index++, slot += 16)
    slot[0] = 0;
}

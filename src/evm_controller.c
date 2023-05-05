#include "udp_server.h"
#include "evm_controller.h"
#include "sim_ram.h"
#include "icm.h"

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

extern void *icm_raw_data_base;
void* const evm_base_addr 		  = (void*)0x410000000ll;
void* const evm_cin_addr  		  = (void*)0x410000000ll;
void* const evm_cout_addr 		  = (void*)0x410008000ll;
void* const evm_code_addr     	= (void*)0x410010000ll;
void* const evm_calldata_addr 	= (void*)0x410020000ll;
void* const evm_mem_addr 		    = (void*)0x410030000ll;
void* const evm_storage_addr 	  = (void*)0x410040000ll;
void* const evm_env_addr 		    = (void*)0x410050000ll;
void* const evm_stack_addr 		  = (void*)0x410060000ll;
const uint64_t pt_offset 		    = 0x8000;
const uint64_t page_tag_mask	  = ~0xfff;
const uint64_t page_tagid_mask	= ~0x3ff;
const uint64_t page_id_mask		  = 0xc00;
const uint64_t page_idof_mask	  = 0xfff;
const uint64_t page_of_mask		  = 0x3ff;
const uint64_t page_size 		    = 0x400;

int evm_active = 0;

typedef struct {
  // memcpy_progress
  ECP ecp;

  // page_swap
  uint32_t page_offset;
  uint8_t valid;
} Pending_EVM_Memory_Copy_Request;
Pending_EVM_Memory_Copy_Request pending_evm_memory_copy_request;

void *data_source_to_address(uint8_t data_source, uint32_t offset) {
  return (void *) (evm_base_addr + (data_source << 16) + (offset & page_idof_mask));
}

uint32_t *data_source_to_pte(uint8_t data_source, uint32_t offset) {
  // page addr: 10bit, pte addr: 2bit
  return (uint32_t *) (evm_base_addr + (data_source << 16) + pt_offset + ((offset & page_id_mask) >> 8));
}

void clear_tag(uint8_t data_source, uint32_t offset) {
  (*data_source_to_pte(data_source, offset)) &= ~3;  // not valid
}

// here we use a tricky solution
// this function only records the page that we requires, then exits immediately
// after the page is swapped, we will call evm_memory_copy again
void async_page_swap(uint8_t dirty, uint8_t src, uint32_t src_offset, uint32_t dest_offset) {
  pending_evm_memory_copy_request.page_offset = dest_offset;
  pending_evm_memory_copy_request.valid = 1;

  // send the output request
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
    icm_encrypt(sizeof(ECP) + 1024);
  } else {
    buf->func = 0;
    icm_encrypt(sizeof(ECP) + 0);
  }
}

void evm_memory_copy(ECP *req) {
  if (req)
    pending_evm_memory_copy_request.ecp = *req;
  req = &(pending_evm_memory_copy_request.ecp);
  pending_evm_memory_copy_request.valid = 0;

  void *addr_src, *addr_dest;
  uint32_t *pte_src, *pte_dest;

  while (req->length > 0) {
    // before page
    addr_src = data_source_to_address(req->src, req->src_offset);
    addr_dest = data_source_to_address(req->dest, req->dest_offset);

    pte_src = data_source_to_pte(req->src, req->src_offset);
    pte_dest = data_source_to_pte(req->dest, req->dest_offset);
    
    // get possible step length
    uint32_t step_length = req->length;
    if ((req->src_offset & page_of_mask) + step_length >= page_size)
      step_length = page_size - (req->src_offset & page_of_mask);
    if ((req->dest_offset & page_of_mask) + step_length >= page_size)
      step_length = page_size - (req->dest_offset & page_of_mask);


    if (((*pte_src) & 2) == 0 || ((*pte_src) & page_tag_mask) != (req->src_offset & page_tag_mask)) {
      async_page_swap(0, req->src, (*pte_src) & page_tagid_mask, req->src_offset & page_tagid_mask);
      return;
    }

    // if the source and dest maps to the same cache-page
    // we must use a temporary buffer to avoid data corruption
    // in fact, if they are actually the same page, we can use memcpy_b directly
    // but we are not implementing that now
    if (pte_src == pte_dest) {
      memcpy_b(icm_raw_data_base, addr_src, step_length);
    }

    if (((*pte_dest) & 2) == 0 || ((*pte_dest) & page_tag_mask) != (req->dest_offset & page_tag_mask)) {
      async_page_swap(((*pte_dest) & 3) == 3, req->dest, (*pte_dest) & page_tagid_mask, req->dest_offset & page_tagid_mask);
      return;
    }
    // copy
    
    if (pte_src == pte_dest) {
      memcpy_b(addr_dest, icm_raw_data_base, step_length);
    } else {
      memcpy_b(addr_dest, addr_src, step_length);
    }

#ifdef SIMULATION
    sleep(5);
    memcpy_b(get_output_buffer(), addr_src, step_length);
    build_outgoing_packet(step_length);
    sleep(5);
#endif

    // update
    req->src_offset += step_length;
    req->dest_offset += step_length;
    req->length -= step_length;
  }
}

uint16_t local_debug_counter = 0;
uint8_t local_debug_enable = 0;
uint8_t ecp_debug_template[16] = {0x05, 0x00, 0x07};

void check_debug_buffer() {
  if (!local_debug_enable) return;

  uint16_t *debug_counter = (uint16_t*)(evm_cin_addr + 0xc);
  uint32_t *debug_buffer_base = (uint32_t*)0xa0000000;
  uint32_t *data = get_output_buffer() + sizeof(ECP);
  uint16_t target = *debug_counter;

  for (; local_debug_counter != target; local_debug_counter++) {
    // gas8, pc4, stacksize4, gap16, res32
    for (int i = 0; i < 16; i++)
      data[i] = debug_buffer_base[(local_debug_counter & 127) * 16 + i];

    memcpy_b(get_output_buffer(), ecp_debug_template, sizeof(ecp_debug_template));
    icm_encrypt(sizeof(ECP) + 64);
  }
}

// TODO
// no longer copy the plaintext into the output buffer
// but to the ICM_RAW_DATA_BASE for encryption
void ecp(uint8_t *in) {
  ECP header;
  memcpy(&header, in, 16);
  ECP *req = &header;

  // clear local ECP
  ECP_OFFSET(in)->opcode = 0;

  if (req->src == HOST) {
    if (req->opcode == CALL) {
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

      //clear_storage();

      // record status
      evm_active = 1;

      // host tell evm to start
      *(uint8_t*)evm_cin_addr = 1;

      return;
    }
    else if (req->opcode == DEBUG) {
      if (req->func == 2)
        req->func = !local_debug_enable;
      local_debug_enable = req->func;
      *(uint8_t*)(evm_cin_addr + 8) = req->func;
      return;
    }
    else if (req->opcode == END){
      // this should not happen when hevm is correct
      // it is temporary added to restart hevm when it gets stuck

      // tell hevm to stop
      evm_active = 0;
      *(char*)(evm_cin_addr + 4) = 0;
      return;
    }
  }

  void *addr_src, *addr_dest;
  uint32_t content_length = req->length;

  // first the requests should be sent to encrypted OCM
  if (req->src == HOST)
    addr_src = icm_raw_data_base;
  else
    addr_src = data_source_to_address(req->src, req->src_offset);

  if (req->dest == HOST)
    addr_dest = icm_raw_data_base;
  else
    addr_dest = data_source_to_address(req->dest, req->dest_offset);

  if (req->opcode == COPY) {
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
      volatile uint8_t* stackOp   = (uint8_t*)(evm_stack_addr + 0x8024);
      uint32_t* stackSize = (uint32_t*)(evm_env_addr + 0x1c0);

      if (req->func == 1) {  // clear all current contents
        for (int i = *stackSize; i; i--) {
          // pop
          *stackOp = 0;
        }
      }

      // Then push
      uint32_t numItem = *(uint32_t*)addr_src;
      uint8_t* data = (uint8_t*)addr_src + 4;

      for (int i = 0; i < numItem; i++, data += 32) {
        memcpy_b(stackData, data, 32);
        *stackOp = 1;
      }
    }
    else { // Memory
      if (req->src == HOST) {
        // only copy data
        // does not copy header
        memcpy_b(addr_dest, addr_src, req->length);

        if (req->dest != ENV) {
          // update page table
          uint32_t *pte = data_source_to_pte(req->dest, req->dest_offset);
          *pte = ((uint32_t)req->dest_offset & page_tagid_mask) | 0x2;
        }
        
        // if there is a pending evm_memory_copy, resume 
        if (pending_evm_memory_copy_request.valid) {
          evm_memory_copy(NULL);
        }
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

      // require missing item
      data[offset] = (req->length & 0x2) >> 1;
      offset++;
      if (data[offset-1]) {
        slot = (uint32_t*)(evm_storage_addr + 0xff00);
        for (int i = 0; i < 8; i++)
          data[i + offset] = slot[i];
        data[offset] = (data[offset] & 0xffffffc0) | (req->src_offset >> 6);
        offset += 8;
      }
      content_length = offset * 4;
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
    // before actually ending the run
    // print all traces
    check_debug_buffer();

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
    icm_encrypt(sizeof(ECP) + buf->length);

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
    // before actually ending the run
    // print all traces
    check_debug_buffer();

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
    icm_encrypt(sizeof(ECP) + buf->length);

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
    icm_encrypt(sizeof(ECP) + buf->length);

    // COPY stack
    volatile uint8_t* stackOp = (uint8_t*)(evm_stack_addr + 0x8024);
    uint32_t* stackSize = (uint32_t*)(evm_env_addr + 0x1c0);
    numItem = *stackSize;
    offset = 4;
    for (int i = numItem, count = 0, flag = 1; i; i--, offset += 32) {
      // fetch the top of the stack
      // which is always mapped to offset 0
      memcpy_b(data8 + offset, evm_stack_addr, 32);
      // then pop
      *stackOp = 0;
      count ++;
      if (count == 32 || i == 1) {
        buf->opcode = COPY;
        buf->src = STACK;
        buf->dest = HOST;
        buf->func = flag;  // flag = 1 means start new transmission (clear current stack content), = 0 means continue
        buf->src_offset = 0;
        buf->dest_offset = 0;
        buf->length = 32 * count + 4;
        data[0] = count;
        icm_encrypt(sizeof(ECP) + buf->length);

        flag = 0;
        count = 0;
      }
    }

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
  else if (req->opcode == LOG) {
    // [TODO] send the stack contents to host
    volatile uint8_t* stackOp = (uint8_t*)(evm_stack_addr + 0x8024);
    for (int i = 0; i < req->func; i++)
      *stackOp = 0;
  }

  // construct header and send
  if (req->dest == HOST) {
    memcpy_b(get_output_buffer(), req, sizeof(ECP));
    icm_encrypt(sizeof(ECP) + content_length);
  }

  // resume execution                  | only when the evm_memory_copy is finished  
  if ((req->dest != HOST && !pending_evm_memory_copy_request.valid) || req->opcode == LOG) {
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

  icm_clear_storage();
}

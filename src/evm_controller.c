#include "udp_server.h"
#include "evm_controller.h"
#include "sim_ram.h"
#include "icm.h"
#include "xil_cache.h"

void *memcpy_b(void *dst0, void *src0, uint32_t len0)
{
  char *dst = dst0;
  char *src = src0;
  while (len0--)
    *dst++ = *src++;
  return dst0;
}

void *memset_b(void *dst0, uint8_t val, uint32_t len0)
{
  char *dst = dst0;
  while (len0--)
    *dst++ = val;
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

extern void * const icm_raw_data_base;
volatile void* const evm_base_addr 		  = (void*)0x410000000ll;
volatile void* const evm_cin_addr  		  = (void*)0x410000000ll;
volatile char* const evm_cin_core_state = (char*)0x410000004ll;
volatile void* const evm_cout_addr 		  = (void*)0x410008000ll;
volatile void* const evm_code_addr     	= (void*)0x410010000ll;
volatile void* const evm_calldata_addr 	= (void*)0x410020000ll;
volatile void* const evm_mem_addr 		    = (void*)0x410030000ll;
volatile void* const evm_storage_addr 	  = (void*)0x410040000ll;
volatile void* const evm_env_addr 		    = (void*)0x410050000ll;
volatile void* const evm_stack_addr 		  = (void*)0x410060000ll;

volatile void* const dma_config_addr     = (void*)0x410000010ll;
volatile void* const dma_srcAddr_addr    = (void*)0x410000014ll;
volatile void* const dma_destAddr_addr   = (void*)0x410000018ll;
volatile void* const dma_length_addr     = (void*)0x41000001Cll;

volatile void* const evm_storage_key     = (void*)0x410041000ll;
volatile void* const evm_storage_wbMap   = (void*)0x410042000ll;
volatile void* const evm_storage_reset   = (void*)0x410043000ll;

volatile void* const evm_stack_flush     = (void*)0x410068000ll;
volatile void* const evm_stack_counter   = (void*)0x410064000ll;

const uint64_t pt_offset 		    = 0x8000;
const uint64_t page_tag_mask	  = ~0xfff;
const uint64_t page_tagid_mask	= ~0x3ff;
const uint64_t page_id_mask		  = 0xc00;
const uint64_t page_idof_mask	  = 0xfff;
const uint64_t page_of_mask		  = 0x3ff;
const uint64_t page_size 		    = 0x400;

const uint32_t num_of_call_params[] = {3, 7, 7, 0, 6, 4, 0, 0, 0, 0, 6};
const uint32_t num_of_end_params[]  = {0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1};

int evm_active = 0;

typedef struct {
  // memcpy_progress
  ECP ecp;

  // page_swap
  uint8_t valid;
} Pending_EVM_Memory_Copy_Request;
Pending_EVM_Memory_Copy_Request pending_evm_memory_copy_request;

///////////////////////////////////////////////////////////////////

void dma_wait() {
  for(;;) {
	  if ((*(volatile uint32_t*)dma_config_addr & 0x1) == 1)
		  break;
  }
}

void dma_read_storage_slot(uint32_t index, void* dstAddr) {
  Xil_DCacheInvalidateRange(dstAddr, 1 << 6);
  *(uint32_t*)dma_srcAddr_addr = (uint32_t)evm_storage_addr + (index << 6);
  *(uint32_t*)dma_destAddr_addr = (uint32_t)dstAddr;
  *(uint32_t*)dma_length_addr = 1 << 6;
  *(uint32_t*)dma_config_addr = 0x0;
  dma_wait();
}

void dma_write_storage_slot(uint32_t index, void* srcAddr) {
  Xil_DCacheFlushRange(srcAddr, 1 << 6);
  *(uint32_t*)dma_srcAddr_addr = (uint32_t)srcAddr;
  *(uint32_t*)dma_destAddr_addr = (uint32_t)evm_storage_addr + (index << 6);
  *(uint32_t*)dma_length_addr = 1 << 6;
  *(uint32_t*)dma_config_addr = 0x2;
  dma_wait();
}

void dma_read_storage_key(void* dstAddr) {
  Xil_DCacheInvalidateRange(dstAddr, 1 << 5);
  *(uint32_t*)dma_srcAddr_addr = (uint32_t)evm_storage_key;
  *(uint32_t*)dma_destAddr_addr = (uint32_t)dstAddr;
  *(uint32_t*)dma_length_addr = 1 << 5;
  *(uint32_t*)dma_config_addr = 0x0;
  dma_wait();
}

void dma_read_stack(uint32_t itemNum, void* dstAddr) {
  if (itemNum == 0) return;
  Xil_DCacheInvalidateRange(dstAddr, itemNum << 5);
  *(uint32_t*)dma_srcAddr_addr = (uint32_t)evm_stack_addr;
  *(uint32_t*)dma_destAddr_addr = (uint32_t)dstAddr;
  *(uint32_t*)dma_length_addr = itemNum << 5;
  *(uint32_t*)dma_config_addr = 0x0;
  dma_wait();
}

void dma_write_stack(uint32_t itemNum, void* srcAddr) {
  if (itemNum == 0) return;
  Xil_DCacheFlushRange(srcAddr, itemNum << 5);
  *(uint32_t*)dma_srcAddr_addr = (uint32_t)srcAddr;
  *(uint32_t*)dma_destAddr_addr = (uint32_t)evm_stack_addr;
  *(uint32_t*)dma_length_addr = itemNum << 5;
  *(uint32_t*)dma_config_addr = 0x2;
  dma_wait();
}

void dma_read_mem(void* src_addr, void* dst_addr, uint32_t length) {
  if (length == 0) return;
  Xil_DCacheInvalidateRange(dst_addr, length);
  *(uint32_t*)dma_srcAddr_addr = (uint32_t)src_addr;
  *(uint32_t*)dma_destAddr_addr = (uint32_t)dst_addr;
  *(uint32_t*)dma_length_addr = length;
  *(uint32_t*)dma_config_addr = 0x0;
  dma_wait();
}

void dma_write_mem(void* src_addr, void* dst_addr, uint32_t length) {
  if (length == 0) return;
  Xil_DCacheFlushRange(src_addr, length);
  *(uint32_t*)dma_srcAddr_addr = (uint32_t)src_addr;
  *(uint32_t*)dma_destAddr_addr = (uint32_t)dst_addr;
  *(uint32_t*)dma_length_addr = length;
  *(uint32_t*)dma_config_addr = 0x2;
  dma_wait();
}

void dma_memcpy(void* dst_addr, void* src_addr, uint32_t length) {
  uint32_t dst = ((uint64_t)dst_addr >> 32), src = ((uint64_t)src_addr >> 32);
  if (dst && !src) {
    dma_write_mem(src_addr, dst_addr, length);
  } else if (!dst && src) {
    dma_read_mem(src_addr, dst_addr, length);
  } else if (!dst && !src) {
    memcpy(dst_addr, src_addr, length);
  } else {
    dma_read_mem(src_addr, icm_raw_data_base, length);
    dma_write_mem(icm_raw_data_base, dst_addr, length);
  }
}

///////////////////////////////////////////////////////////////////

void *data_source_to_address(uint8_t data_source, uint32_t offset) {
  if (data_source == OCM_IMMUTABLE_MEM)
    return icm_config->ocm_immutable_page + (offset & page_of_mask);
  else if (data_source == OCM_MEM)
    return icm_config->ocm_mem_page + (offset & page_of_mask);
  return (void *) (evm_base_addr + (data_source << 16) + (offset & page_idof_mask));
}

volatile uint32_t *data_source_to_pte(uint8_t data_source, uint32_t offset) {
  // page addr: 10bit, pte addr: 2bit
  if (data_source == OCM_IMMUTABLE_MEM)
    return &(icm_config->ocm_immutable_pte);
  else if (data_source == OCM_MEM)
    return &(icm_config->ocm_mem_pte);
  return (volatile uint32_t*) (evm_base_addr + (data_source << 16) + pt_offset + ((offset & page_id_mask) >> 8));
}

void clear_tag(uint8_t data_source, uint32_t offset) {
  (*data_source_to_pte(data_source, offset)) &= ~3;  // not valid
}

///////////////////////////////////////////////////////////////////

void evm_clear_stack() {
  *(volatile uint32_t*)evm_stack_flush = 1;
}

uint32_t evm_store_stack(uint32_t num_of_params) {
  uint32_t* data = (uint32_t*)icm_raw_data_base;
  uint32_t count = *(volatile uint32_t*)evm_stack_counter;
  if (num_of_params >= 0 && num_of_params <= count)
    count = num_of_params;
  *data = count, data = data + 1;
  uint32_t num = count;
  while(num) {
    uint32_t tmp = num > 0x20 ? 0x20 : num;
    dma_read_stack(tmp, data), num -= tmp, data += (tmp << 3);
  }
  return (count << 5) + 4;
}

void evm_load_stack(uint8_t func) {
  if (func == 1) {  // clear all current contents
    evm_clear_stack();
  }
  // Then push
  uint32_t* data = (uint32_t*)icm_raw_data_base;
  uint32_t numItem = data[0];
  for (uint32_t i = 1, j = (numItem << 3) - 7, tmp; i < j;) {
    for (uint32_t k = 0; k < 8; k++)
      tmp = data[i + k], data[i + k] = data[j + k], data[j + k] = tmp;
    i += 8, j -= 8;
  }
  data = data + 1;
  while (numItem) {
    uint32_t tmp = numItem > 0x20 ? 0x20 : numItem;
    dma_write_stack(tmp, data), numItem -= tmp, data += (tmp << 3);
  }
}

///////////////////////////////////////////////////////////////////

uint32_t evm_store_storage() {
  uint32_t numItem = 0, offset = 1;
  uint64_t wbMap = *(volatile uint64_t*)evm_storage_wbMap;
  uint32_t* data = (uint32_t*)icm_raw_data_base;
  for (int i = 0; i < 64; i++, wbMap >>= 1)
    if (wbMap & 1) {
      dma_read_storage_slot(i, data + offset);
      numItem++, offset += 16;
    }
  data[0] = numItem;
  return 64 * numItem + 4;
}

void evm_load_storage() {
  // fetch all kv pairs and insert to local storage
  uint32_t* data = (uint32_t*)icm_raw_data_base;
  uint32_t numItem = data[0], offset = 1;
  for (int i = 0; i < numItem; i++, offset += 16) {
    uint32_t index = data[offset] & 0x3f;
    dma_write_storage_slot(index, data + offset);
  }
}

uint32_t evm_swap_storage(uint32_t index) {
  uint32_t* data = (uint32_t*)icm_raw_data_base;
  uint64_t wbMap = *(uint64_t*)evm_storage_wbMap;
  // commit dirty item
  uint32_t offset = 1;
  // copy out if valid & dirty
  if (wbMap & (1ll << index)) {
    data[0] = 1;
    dma_read_storage_slot(index, data + offset);
    offset += 16;
  } else {
    data[0] = 0;
  }

  // require missing item
  data[offset++] = 1;
  dma_read_storage_key(data + offset);
  offset += 8;

  return offset * 4;
}

void evm_clear_storage() {
  *(uint32_t*)evm_storage_reset = 1;
}

///////////////////////////////////////////////////////////////////

void evm_dump_memory() {
  ECP *buf = get_output_buffer();
  uint8_t *memory = (uint8_t*)evm_mem_addr;
  for (int i = 0; i < NUMBER_OF_PAGES; i++) {
    volatile uint32_t pte = *data_source_to_pte(MEM, i << 10);
    if ((pte & 2) == 0)  // empty
      continue;
    memset(buf, 0, sizeof(ECP));
    buf->opcode = COPY;
    buf->src = MEM;
    buf->dest = HOST;
    buf->src_offset = pte & page_tagid_mask;
    buf->dest_offset = 0;
    buf->length = PAGE_SIZE;
    dma_read_mem(memory + (i << 10), icm_raw_data_base, PAGE_SIZE);
    icm_encrypt(sizeof(ECP) + buf->length);
    // clear mem cache
    *data_source_to_pte(MEM, i << 10) = 0;
  }
}

void evm_load_memlike(uint8_t dest, uint32_t dest_offset) {
  void *addr_dest = data_source_to_address(dest, dest_offset);
  dma_memcpy(addr_dest, icm_raw_data_base, PAGE_SIZE);
  if (dest != ENV) {
    // update page table
    volatile uint32_t *pte = data_source_to_pte(dest, dest_offset);
    *pte = (dest_offset & page_tagid_mask) | 0x2;
  }
}

///////////////////////////////////////////////////////////////////

// here we use a tricky solution
// this function only records the page that we requires, then exits immediately
// after the page is swapped, we will call evm_memory_copy again
uint8_t async_page_swap(uint8_t dirty, uint8_t src, uint32_t src_offset, uint32_t dest_offset) {
  pending_evm_memory_copy_request.valid = 1;

  // send the output request
  ECP *buf = (ECP *)get_output_buffer();
  buf->opcode = SWAP;
  buf->src = src;
  buf->dest = HOST;
  buf->src_offset = src_offset;
  buf->dest_offset = dest_offset;
  buf->length = PAGE_SIZE;

  uint8_t ready;
  if (dirty) {
    buf->func = 1;
    dma_memcpy(icm_raw_data_base, data_source_to_address(src, src_offset), PAGE_SIZE);
    ready = icm_encrypt(sizeof(ECP) + PAGE_SIZE);
  } else {
    buf->func = 0;
    ready = icm_encrypt(sizeof(ECP) + 0);
  }

  if (ready) {
    evm_load_memlike(src, dest_offset);
    pending_evm_memory_copy_request.valid = 0;
  }
  return ready;
}

void sync_page_dump(uint8_t dirty, uint8_t src, uint32_t src_offset) {
  if (!dirty) return;

  // send the output request
  ECP *buf = (ECP *)get_output_buffer();
  buf->opcode = COPY;
  buf->src = src;
  buf->dest = HOST;
  buf->src_offset = src_offset;
  buf->dest_offset = 0;
  buf->length = PAGE_SIZE;

  buf->func = 1;
  dma_memcpy(icm_raw_data_base, data_source_to_address(src, src_offset), PAGE_SIZE);
  icm_encrypt(sizeof(ECP) + 1024);
}

void evm_memory_copy(ECP *req) {
  if (req) {
    pending_evm_memory_copy_request.ecp = *req;
    if (req->src == RETURNDATA) {
      pending_evm_memory_copy_request.ecp.src = OCM_IMMUTABLE_MEM;
    }
    clear_tag(OCM_IMMUTABLE_MEM, 0);
    clear_tag(OCM_MEM, 0);
  }
  req = &(pending_evm_memory_copy_request.ecp);
  pending_evm_memory_copy_request.valid = 0;

  void *addr_src, *addr_dest;
  volatile uint32_t *pte_src, *pte_dest;

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

    trigger_input();
    if (((*pte_src) & 2) == 0 || ((*pte_src) & page_tagid_mask) != (req->src_offset & page_tagid_mask)) {
      // src of copy are always immutable (CALLDATA, RETURNDATA, etc) or MEMORY after execution and thus can never be dirty
      if (!async_page_swap(0, req->src, (*pte_src) & page_tagid_mask, req->src_offset & page_tagid_mask))
        return;
    }

    if (((*pte_dest) & 2) == 0 || ((*pte_dest) & page_tagid_mask) != (req->dest_offset & page_tagid_mask)) {
      if (req->dest != OCM_IMMUTABLE_MEM &&
          ((req->dest_offset & page_of_mask) != 0 || req->length < page_size)
      ) {
        // not a full page, require from host
        if (!async_page_swap(((*pte_dest) & 3) == 3, req->dest, (*pte_dest) & page_tagid_mask, req->dest_offset & page_tagid_mask))
          return;
      } else {
        sync_page_dump(((*pte_dest) & 3) == 3, req->dest, (*pte_dest) & page_tagid_mask);
        *pte_dest = req->dest_offset & page_tagid_mask;
      }
    }
    
    // copy
    dma_memcpy(addr_dest, addr_src, step_length);
    *pte_dest |= 0x3;

#ifdef ICM_DEBUG
    icm_debug("copied contents", 15);
    icm_debug(&step_length, 4);
#endif

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

  // finalize
  if (req->dest == OCM_MEM || req->dest == OCM_IMMUTABLE_MEM) {
    pte_dest = data_source_to_pte(req->dest, 0);
    sync_page_dump(((*pte_dest) & 3) == 3, req->dest, (*pte_dest) & page_tagid_mask);
    icm_step();
  }
}

// uint16_t local_debug_counter = 0;
// uint8_t local_debug_enable = 0;
// uint8_t ecp_debug_template[16] = {0x05, 0x00, 0x07};

// void check_debug_buffer() {
//   if (!local_debug_enable) return;

//   uint16_t *debug_counter = (uint16_t*)(evm_cin_addr + 0xc);
//   uint32_t *debug_buffer_base = (uint32_t*)0xa0000000;
//   uint32_t *data = get_output_buffer() + sizeof(ECP);
//   uint16_t target = *debug_counter;
//   uint32_t offset = 0;

//   for (; local_debug_counter != target; local_debug_counter++) {
//     // gas8, pc4, stacksize4, gap16, res32
//     for (int i = 0; i < 16; i++, offset++)
//       data[offset] = debug_buffer_base[((local_debug_counter & 127) << 4) + i];
//     if (offset >= 0x3000) {
//     	memcpy(get_output_buffer(), ecp_debug_template, sizeof(ecp_debug_template));
//     	((ECP*)get_output_buffer())->length = (offset << 2);
//     	icm_encrypt(sizeof(ECP) + (offset << 2));
//     	offset = 0;
//     }
//   }

//   if (offset == 0)
//     return;

//   // send multiple debug data at a time
//   memcpy(get_output_buffer(), ecp_debug_template, sizeof(ecp_debug_template));
//   ((ECP*)get_output_buffer())->length = (offset << 2);
//   icm_encrypt(sizeof(ECP) + (offset << 2));
// }
//
//void clear_debug_buffer() {
//  uint16_t *debug_counter = (uint16_t*)(evm_cin_addr + 0xc);
//  local_debug_counter = *debug_counter;
//}

uint8_t evm_has_output() {
  return evm_active && *(uint32_t*)evm_cout_addr != NONE;
}

uint8_t wait_for_query = 0;

void handle_ecp(ECP *in) {
  ECP header;
  dma_memcpy(&header, in, 16);
  ECP *req = &header;
  in->opcode = 0;

  uint8_t ready = 0;

//  check_debug_buffer();

#ifdef ICM_DEBUG
  icm_debug(req, 16);
#endif

  if (req->src == HOST) {
    if (req->opcode == CALL) {
#ifdef ICM_DEBUG
    icm_debug("clear buffer", 12);
#endif
      // clear memory valid tag
      // code: clear all
      for (int i = 0; i < NUMBER_OF_PAGES; i++)
        clear_tag(CODE, i << 10);
      // calldata: clear all
      for (int i = 0; i < NUMBER_OF_PAGES; i++)
        clear_tag(CALLDATA, i << 10);
      // returndata: clear all
      for (int i = 0; i < NUMBER_OF_PAGES; i++)
        clear_tag(RETURNDATA, i << 10);
      // memory: clear all
      // for (int i = 0; i < NUMBER_OF_PAGES; i++)
      //   clear_tag(MEM, i << 10);
      evm_clear_storage();

      // record status
      evm_active = 1;
      // host tell evm to start
      *(uint8_t*)evm_cin_addr = 1;

#ifdef ICM_DEBUG
    icm_debug("start exec", 10);
#endif
      return;
    }
//    else if (req->opcode == DEBUG) {
//      clear_debug_buffer();
//      if (req->func == 2)
//        req->func = !local_debug_enable;
//      local_debug_enable = req->func;
//      *(uint8_t*)(evm_cin_addr + 8) = req->func;
//      return;
//    }
    else if (req->opcode == END){
      // this should not happen when hevm is correct
      // it is temporary added to restart hevm when it gets stuck

      // tell hevm to stop
      evm_active = 0;
      *(char*)(evm_cin_addr + 4) = 0;
      pending_evm_memory_copy_request.valid = 0; // stop copying
      return;
    }
  }

  uint32_t content_length = req->length;

  if (req->opcode == COPY) {
    if (req->dest == STORAGE) {
      evm_load_storage();
    }
    else if (req->dest == STACK) {
      evm_load_stack(req->func);
      wait_for_query = 0;
    }
    else { // Memory
      if (req->src == HOST) {
        evm_load_memlike(req->dest, req->dest_offset);
        // if there is a pending evm_memory_copy, resume 
        if (pending_evm_memory_copy_request.valid) {
          evm_memory_copy(NULL);
        }
      } else if (req->dest != HOST) {
        // Interal memory copy
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
      content_length = evm_swap_storage(req->src_offset);
      memcpy_b(get_output_buffer(), req, sizeof(ECP));
      ready = icm_encrypt(sizeof(ECP) + content_length);
      if (ready) {
        evm_load_storage();
      }
    }
    else { // swap memory
#ifdef ICM_DEBUG
      icm_debug("swap page", 9);
#endif
      if (req->func) { // has dirty page to send back
        dma_memcpy(icm_raw_data_base, data_source_to_address(req->src, req->src_offset), req->length);
      } else {
        content_length = 0;
      }
      memcpy_b(get_output_buffer(), req, sizeof(ECP));
#ifdef ICM_DEBUG
      icm_debug("copied contents", 15);
      icm_debug(&content_length, 4);
#endif
      ready = icm_encrypt(sizeof(ECP) + content_length);
      if (ready) {
        // icm_debug("found locally, load to FPGA", 27);
        evm_load_memlike(req->src, req->dest_offset);
      }
    }

#ifdef SIMULATION
    require_sim_ram_reply = 1;
#endif
  }
  else if (req->opcode == END) {
    // before actually ending the run
    // print all traces
    evm_active = 0;

#ifdef ICM_DEBUG
    icm_debug("dump debug", 10);
#endif

    // Send a COPY before sending END
    ECP *buf = (ECP *)get_output_buffer();

    // COPY storage
    buf->opcode = COPY;
    buf->src = STORAGE;
    buf->dest = HOST;
    buf->src_offset = 0;
    buf->dest_offset = 0;
    buf->length = evm_store_storage();
    icm_encrypt(sizeof(ECP) + buf->length);

#ifdef ICM_DEBUG
    icm_debug("dump storage", 12);
#endif

    // COPY memory
    evm_dump_memory();
    
#ifdef ICM_DEBUG
    icm_debug("dump memory", 11);
#endif

    // COPY stack
    // the call params should remain as plaintext
    uint32_t num_of_params = num_of_end_params[req->func & 0xf]; 
    buf->opcode = COPY;
    buf->src = STACK;
    buf->dest = HOST;
    buf->func = 1;
    buf->src_offset = 0;
    buf->dest_offset = 0;
    buf->length = evm_store_stack(num_of_params);
    icm_encrypt(sizeof(ECP) + buf->length);
    // clear remaining elements
    evm_clear_stack();
    
#ifdef ICM_DEBUG
    icm_debug("dump stack", 10);
#endif

    // end
    content_length = 0;
    memcpy_b(get_output_buffer(), req, sizeof(ECP));
    icm_encrypt(sizeof(ECP));
  }
  else if (req->opcode == CALL) {
    // TODO: maybe check whether parameters enough or not ? (potential attack point)

    // before actually ending the run
    // print all traces
    evm_active = 0;

#ifdef ICM_DEBUG
    icm_debug("dump debug", 10);
#endif

    // evm call to host
    // First send current environment to host
    ECP *buf = get_output_buffer();

    // COPY storage
    buf->opcode = COPY;
    buf->src = STORAGE;
    buf->dest = HOST;
    buf->src_offset = 0;
    buf->dest_offset = 0;
    buf->length = evm_store_storage();
    icm_encrypt(sizeof(ECP) + buf->length);

#ifdef ICM_DEBUG
    icm_debug("dump storage", 12);
#endif

    // COPY memory
    evm_dump_memory();
#ifdef ICM_DEBUG
    icm_debug("dump memory", 11);
#endif

    // COPY stack
    // the call params should remain as plaintext
    uint32_t num_of_params = num_of_call_params[req->func & 0xf];
    buf->opcode = COPY;
    buf->src = STACK;
    buf->dest = HOST;
    buf->func = 1;
    buf->src_offset = 0;
    buf->dest_offset = 0;
    buf->length = evm_store_stack(num_of_params);
    icm_encrypt(sizeof(ECP) + buf->length);
    // then the remaining content as cipher
    buf->opcode = COPY;
    buf->src = STACK;
    buf->dest = HOST;
    buf->func = 0;
    buf->src_offset = 0;
    buf->dest_offset = 0;
    buf->length = evm_store_stack(-1);
    icm_encrypt(sizeof(ECP) + buf->length);

#ifdef ICM_DEBUG
    icm_debug("dump stack", 10);
#endif

    // call
    content_length = 0;
    memcpy_b(get_output_buffer(), req, sizeof(ECP));
    icm_encrypt(sizeof(ECP));
  }
  else if (req->opcode == QUERY) {
#ifdef ICM_DEBUG
    icm_debug("query", 5);
    uint32_t stackSize = (volatile uint32_t*)(evm_stack_counter);
    icm_debug(&stackSize, 4);
#endif
    // queries need an address (or blockid) as param
    // which is always located at the top of the stack
    content_length = 32;
    dma_read_stack(1, icm_raw_data_base);
    memcpy_b(get_output_buffer(), req, sizeof(ECP));
  
    if (req->func == ExtCodeCopy) { // ExtCodeCopy
      dma_read_stack(3, icm_raw_data_base + 32);
      evm_dump_memory();
    }

    if (icm_encrypt(sizeof(ECP) + content_length)) {
      // locally deployed 
      dma_write_stack(1, icm_raw_data_base);
      ready = 1; 
    } else {
      wait_for_query = 1;
    }
  }
  else if (req->opcode == LOG) {
    // [TODO] send the stack contents to host as log
    dma_read_stack(req->func, icm_raw_data_base);
    ready = 1;
  }
  else if (req->opcode == DEBUG) {
#ifdef ICM_DEBUG
    icm_debug("debug triggered", 15);
#endif
    ready = 1;
  }

  // resume execution                  | only when the evm_memory_copy is finished  
  if ((req->dest != HOST && !wait_for_query && !pending_evm_memory_copy_request.valid) || ready) {
    // does not continue if exception from evm not yet handled
    if (evm_has_output()) {
#ifdef ICM_DEBUG
      icm_debug("ecp pending", 11);
#endif
      return;
    }
    *evm_cin_core_state = evm_active;
#ifdef ICM_DEBUG
    icm_debug("cont", 4);
#endif
  }
}

void check_evm_output() {
  if (evm_has_output()) {
    // there is an operation
    // delegate to ecp
    handle_ecp(evm_cout_addr);
  }
}

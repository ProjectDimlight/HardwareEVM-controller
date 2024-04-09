#include "udp_server.h"
#include "evm_controller.h"
#include "sim_ram.h"
#include "icm.h"

extern ICMConfig* const icm_config;

extern uint32_t input_size;

/*
void test_malloc() {
  uint32_t *a = malloc(4096);

  for (int i = 0; i < 1024; i++)
    a[i] = i;

  memcpy(get_output_buffer(), "test", 4);
  memcpy(get_output_buffer() + 4, 0xFFFF0000, 4096);
  build_outgoing_packet(4100);
}
*/

int cnt = 0, led_on = 1, started = 0, fail = 0;
uint8_t *led_ptr = 0x480000000ll;

void led_and_heart_beat() {
  cnt ++;
  if (cnt == 1000000) {
    cnt = 0;
  }

  if (!started) {
    if (cnt == 0) {  
      led_on = led_on >= 8 ? 1 : (led_on << 1);
      *led_ptr = led_on;
    }
  } else {
    *led_ptr = (fail ? 0xa : (*evm_cin_core_state ? 0xf : 0x0));
#ifdef ICM_DEBUG
    // there are still heart beats after stuck
    // so it is a hardware issue
    if (cnt == 0) {
      //icm_debug("heart beat", 10);
    }
#endif
  }
}

int main(void)
{

  /* start the application*/
  start_application();
  
  icm_init();
  icm_clear_storage();

  // wait for a host
  // after receiving any packet, it will memorize the socket
  *led_ptr = led_on;

#ifdef SIMULATION
  require_sim_ram_reply = 1;
    check_simram();
#endif

  while (1) {
#ifdef SIMULATION
    check_simram();
#endif

    uint8_t *p = check_incoming_packet();
    if (p) {
      handle_ecp(p);
      /*
      if (!started) {
        test_malloc();
      }
      */
      started = 1;
    }

    check_evm_output();
    icm_call_end_state_machine();
//    check_debug_buffer();

    retry_timer();
    led_and_heart_beat();
  }

  return 0;
}

#include "udp_server.h"
#include "evm_controller.h"
#include "sim_ram.h"

extern uint32_t input_size;

int main(void)
{
	/* start the application*/
	start_application();

	clear_storage();

	// wait for a host
	// after receiving any packet, it will memorize the socket
	int cnt = 0, led_on = 1;
	uint8_t *led_ptr = 0x480000000ll;
	*led_ptr = led_on;

	while (1) {
		cnt ++;
		if (cnt == 1000000) {
			cnt = 0;
			led_on = led_on >= 8 ? 1 : (led_on << 1);
			*led_ptr = led_on;
		}

		uint8_t *p = check_incoming_packet();
		if (p) {
#ifdef SIMULATION
			memcpy(get_output_buffer(), p, input_size);
		    build_outgoing_packet(input_size);
#endif
			break;
		}
	}

#ifdef SIMULATION
    memcpy(get_output_buffer(), "check network", 13);
    build_outgoing_packet(13);

#endif

#ifdef SIMULATION
	require_sim_ram_reply = 1;
  	check_simram();
#endif

	while (1) {
#ifdef SIMULATION
		check_simram();
#endif

		uint8_t *p = check_incoming_packet();
	    if (p) ecp(p);

    	check_evm_output();
	}

	return 0;
}

/*
 * Copyright (C) 2017 - 2019 Xilinx, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 */

/** Connection handle for a UDP Server session */

#include "icm.h"
#include "udp_server.h"
#include "platform_config.h"
#include "netif/xadapter.h"

typedef struct {
	uint8_t enable_reliable;
	uint8_t reserved;
	uint16_t packet_id;
} ECPHeader;

extern struct netif server_netif;
static struct udp_pcb *pcb;

static struct udp_pcb *tpcb;
static ip_addr_t taddr;
static u16_t tport;

uint8_t buf_in[65536];
uint8_t buf_out[65536], buf_debug[65536];
uint32_t input_size;
uint8_t input_valid;

void *get_input_buffer() {
  return buf_in;
}

void *get_output_buffer() {
  return buf_out;
}

void *get_debug_buffer() {
  return buf_debug;
}

void trigger_input() {
	xemacif_input(&server_netif);
}

uint32_t retry_counter = 0;
uint16_t expected_reply_id = 0;
uint16_t request_id = 0;

struct pbuf *queue[64];

void reset_udp() {
	retry_counter = 0;

	for (uint32_t i = expected_reply_id; i != request_id; i++) {
		pbuf_free(queue[i & 0x3f]);
	}
	expected_reply_id = 0;
	request_id = 0;
#ifdef ICM_DEBUG
	icm_debug("reset udp", 9);
#endif
}

void retry_send() {
	if (expected_reply_id != request_id) {  // there exists packets to send
#ifdef ICM_DEBUG
	icm_debug("retry send", 10);
#endif
		struct pbuf *p = queue[expected_reply_id & 0x3f]; // 256
		queue[expected_reply_id & 0x3f] = pbuf_clone(PBUF_TRANSPORT, PBUF_POOL, p);
		udp_sendto(tpcb, p, &taddr, tport);
		pbuf_free(p);
	}
}

void retry_timer() {
	if (retry_counter == 0) {
		retry_send();
		retry_counter = 200000;
	} else {
		retry_counter--;
	}
}

uint8_t *check_incoming_packet() {
	xemacif_input(&server_netif);
	// now the packet is in the input buffer, but encrypted
	// decrypt the payloads to secure memory
	// and set input_valid only after the signature is checked

	if (input_valid) {
		input_valid = 0;

		ECPHeader *p = buf_in;
		if (p->enable_reliable == 1) {
			if (p->packet_id != expected_reply_id)
				return NULL;

			// ack
			pbuf_free(queue[expected_reply_id & 0x3f]);
			queue[expected_reply_id & 0x3f] = 0;
			expected_reply_id++;
			retry_counter = 0;
		}

		return icm_decrypt() ? buf_in + 4 : NULL;
	}
}

extern int fail;
extern uint8_t *led_ptr;

void build_outgoing_packet(uint32_t len) {
	// struct pbuf *obuf = pbuf_alloc_reference(buf_out, len, PBUF_REF);
	struct pbuf *obuf = NULL;
	obuf = pbuf_alloc(PBUF_TRANSPORT, 4 + len, PBUF_POOL);
	
	uint8_t enable_reliable = 1, zero = 0;

	ECP *p = buf_out;
	if (p->opcode == 100 || p->opcode == DEBUG)
		enable_reliable = 0;

	pbuf_take_at(obuf, &enable_reliable, 1, 0);
	pbuf_take_at(obuf, &zero, 1, 1);
	pbuf_take_at(obuf, &request_id, 2, 2);
	pbuf_take_at(obuf, buf_out, len, 4);

	if (enable_reliable) {
		queue[request_id & 0x3f] = pbuf_clone(PBUF_TRANSPORT, PBUF_POOL, obuf);
		if (request_id == expected_reply_id) { // empty queue
			udp_sendto(tpcb, obuf, &taddr, tport);
			pbuf_free(obuf);
		}
		request_id ++;
	} else {
		udp_sendto(tpcb, obuf, &taddr, tport);
		pbuf_free(obuf);
	}
}

void build_debug_packet(uint32_t len) {
	// struct pbuf *obuf = pbuf_alloc_reference(buf_out, len, PBUF_REF);
	struct pbuf *obuf = NULL;
	obuf = pbuf_alloc(PBUF_TRANSPORT, 4 + len, PBUF_POOL);
	
	uint32_t zero = 0;
	pbuf_take_at(obuf, &zero, 4, 0);
	pbuf_take_at(obuf, buf_debug, len, 4);

	udp_sendto(tpcb, obuf, &taddr, tport);
	pbuf_free(obuf);
}

static void build_incoming_packet(struct pbuf *p) {
	// received
	input_valid = 1;
	input_size = p->tot_len;
	pbuf_copy_partial(p, buf_in, input_size, 0);
}

/** Receive data on a udp session */
static void udp_recv_packet(void *arg, struct udp_pcb *rpcb,
		struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
	tpcb = rpcb;
	memcpy(&taddr, addr, sizeof(ip_addr_t));
	tport = port;

	build_incoming_packet(p);
	
	pbuf_free(p);
	return;
}

// ===================================================

extern volatile int TcpFastTmrFlag;
extern volatile int TcpSlowTmrFlag;
void network_timer_check() {
	if (TcpFastTmrFlag) {
		tcp_fasttmr();
		TcpFastTmrFlag = 0;
	}
	if (TcpSlowTmrFlag) {
		tcp_slowtmr();
		TcpSlowTmrFlag = 0;
	}

}

static void assign_default_ip(ip_addr_t *ip, ip_addr_t *mask, ip_addr_t *gw)
{
	int err;

	xil_printf("Configuring default IP %s \r\n", DEFAULT_IP_ADDRESS);

	err = inet_aton(DEFAULT_IP_ADDRESS, ip);
	if (!err)
		xil_printf("Invalid default IP address: %d\r\n", err);

	err = inet_aton(DEFAULT_IP_MASK, mask);
	if (!err)
		xil_printf("Invalid default IP MASK: %d\r\n", err);

	err = inet_aton(DEFAULT_GW_ADDRESS, gw);
	if (!err)
		xil_printf("Invalid default gateway address: %d\r\n", err);
}

struct netif server_netif;

void platform_enable_interrupts(void);
#if defined (__arm__) && !defined (ARMR5)
#if XPAR_GIGE_PCS_PMA_SGMII_CORE_PRESENT == 1 || \
		 XPAR_GIGE_PCS_PMA_1000BASEX_CORE_PRESENT == 1
int ProgramSi5324(void);
int ProgramSfpPhy(void);
#endif
#endif

#ifdef XPS_BOARD_ZCU102
#ifdef XPAR_XIICPS_0_DEVICE_ID
int IicPhyReset(void);
#endif
#endif

void start_application(void)
{
	struct netif *netif;
	netif = &server_netif;

	/* the mac address of the board. this should be unique per board */
	unsigned char mac_ethernet_address[] = {
		0x00, 0x0a, 0x35, 0x00, 0x01, 0x02 };

#if defined (__arm__) && !defined (ARMR5)
#if XPAR_GIGE_PCS_PMA_SGMII_CORE_PRESENT == 1 || \
		XPAR_GIGE_PCS_PMA_1000BASEX_CORE_PRESENT == 1
	ProgramSi5324();
	ProgramSfpPhy();
#endif
#endif

	/* Define this board specific macro in order perform PHY reset
	 * on ZCU102
	 */
#ifdef XPS_BOARD_ZCU102
	IicPhyReset();
#endif

	init_platform();

	/* initialize lwIP */
	lwip_init();

	/* Add network interface to the netif_list, and set it as default */
	if (!xemac_add(netif, NULL, NULL, NULL, mac_ethernet_address,
				PLATFORM_EMAC_BASEADDR)) {
		xil_printf("Error adding N/W interface\r\n");
		return;
	}
	netif_set_default(netif);

	/* now enable interrupts */
	platform_enable_interrupts();

	/* specify that the network if is up */
	netif_set_up(netif);

	assign_default_ip(&(netif->ip_addr), &(netif->netmask), &(netif->gw));

	err_t err;

	/* Create Server PCB */
	pcb = udp_new();
	if (!pcb) {
		xil_printf("UDP server: Error creating PCB. Out of Memory\r\n");
		return;
	}

	err = udp_bind(pcb, IP_ADDR_ANY, UDP_CONN_PORT);
	if (err != ERR_OK) {
		xil_printf("UDP server: Unable to bind to port");
		xil_printf(" %d: err = %d\r\n", UDP_CONN_PORT, err);
		udp_remove(pcb);
		return;
	}

	/* specify callback to use for incoming connections */
	udp_recv(pcb, udp_recv_packet, NULL);

	//tpcb = pcb;
	
	tpcb = pcb;
	taddr.addr = 0x0201a8c0;
	tport = 23333;

	return;
}

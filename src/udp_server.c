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

#include "udp_server.h"
#include "platform_config.h"
#include "netif/xadapter.h"

extern struct netif server_netif;
static struct udp_pcb *pcb;

static struct udp_pcb *tpcb;
static ip_addr_t taddr;
static u16_t tport;

uint8_t buf_in[4096];
uint8_t buf_out[4096];
uint32_t input_size;
uint8_t input_valid;

void *get_input_buffer() {
  return buf_in;
}

void *get_output_buffer() {
  return buf_out;
}

uint8_t *check_incoming_packet() {
	xemacif_input(&server_netif);
	return input_valid ? (input_valid = 0, buf_in) : (uint8_t*)0;
}

void build_outgoing_packet(uint32_t len) {
	struct pbuf *obuf = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
	pbuf_take(obuf, buf_out, len);

	udp_sendto(tpcb, obuf, &taddr, tport);
	pbuf_free(obuf);
}

static void build_incoming_packet(struct pbuf *p) {
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

	// udp_sendto(rpcb, p, addr, port);
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

	tpcb = pcb;
	taddr.addr = 0xc0a80102;
	tport = 5002;

	return;
}

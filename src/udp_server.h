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

#ifndef __UDP_PERF_SERVER_H_
#define __UDP_PERF_SERVER_H_

#include "lwipopts.h"
#include "lwip/ip_addr.h"
#include "lwip/err.h"
#include "lwip/udp.h"
#include "lwip/inet.h"
#include "xil_printf.h"
#include "platform.h"

#define DEFAULT_IP_ADDRESS	"192.168.1.1"
#define DEFAULT_IP_MASK		"255.255.255.0"
#define DEFAULT_GW_ADDRESS	"192.168.1.2"
#define UDP_CONN_PORT 5001

void *get_input_buffer();
void *get_output_buffer();

void trigger_input();
uint8_t *check_incoming_packet();
void build_outgoing_packet(uint32_t len);
void build_raw_packet(uint32_t len);

void network_timer_check();
void start_application(void);

// MAC
// 0 dest mac
// 6 src mac
// c len/type (0x0806 = ARP)
// e data
// 7f4 packet len
// 7f8 global interrupt enable
// 7fc control

typedef struct{
  uint8_t  dest_mac[6];
  uint8_t  src_mac[6];
  uint16_t len_type;
  uint8_t  data[0];
} __attribute__((packed)) MAC;

typedef struct{
  uint8_t  content[0x7f4];
  uint32_t packet_len;
  uint32_t global_interrupt_enable;
  uint32_t control;
} MACCtrl;

#define MAC_OFFSET(p) ((MAC*)(p))
#define MAC_CTRL_OFFSET(p) ((MACCtrl*)(p))

// IP + e
// 0 version
// 2 length
// 4 id
// 6 offset
// 8 ttl
// 9 upper level protocol (udp = 0x11)
// a checksum
// c src ip
// 10 dst ip
// 14 data

typedef struct {
  uint8_t  version;
  uint8_t  tos;
  uint16_t length;
  uint16_t id;
  uint16_t offset;
  uint8_t  ttl;
  uint8_t  upper_level_protocol;
  uint16_t checksum;
  uint32_t src_ip;
  uint32_t dest_ip;
  uint8_t  data[0];
} __attribute__((packed)) IP;

#define IP_OFFSET(p) ((IP*)(MAC_OFFSET(p)->data))

// UDP + e + 14
// 0 src port
// 2 dest port
// 4 length
// 6 checksum

typedef struct {
  uint16_t src_port;
  uint16_t dest_port;
  uint16_t length;
  uint16_t checksum;
  uint16_t padding;
  uint8_t  data[0];
} __attribute__((packed)) UDP;

#define UDP_OFFSET(p) ((UDP*)(IP_OFFSET(p)->data))

// Data + e + 14 + 8

// ARP + e
// 0 hardware type (0x0001 = ethernet)
// 2 protocol type (0x0800 = ip)
// 4 hardware size (0x06 = 6)
// 5 protocol size (0x04 = 4)
// 6 opcode (0x0001 = request, 0x0002 = response)
// 8 src mac
// e src ip
// 12 dest mac
// 18 dest ip
// 1c padding (length = 18)

typedef struct {
  uint16_t hardware_type;
  uint16_t protocol_type;
  uint8_t  hardware_size;
  uint8_t  protocol_size;
  uint16_t opcode;
  uint8_t  src_mac[6];
  uint32_t src_ip;
  uint8_t  dest_mac[6];
  uint32_t dest_ip;
  uint8_t  padding[18];
} __attribute__((packed)) ARP;

#define ARP_OFFSET(p) ((ARP*)(MAC_OFFSET(p)->data))

#endif /* __UDP_PERF_SERVER_H_ */

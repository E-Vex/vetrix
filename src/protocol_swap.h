#ifndef PROTOCOL_SWAP_H
#define PROTOCOL_SWAP_H

/* Standard library */
#include <stddef.h>
#include <stdio.h>

/* Project headers */
#include "endian.h"
#include "protocols.h"

void swap_global_header(pcap_global_header_t *global_header);
void swap_packet_header(pcap_packet_header_t *packet_header);

void swap_sll2_header(sll2_header_t *sll2_header);

void swap_ipv4_header(ipv4_header_t *ipv4_header);

void swap_tcp_header(tcp_header_t *tcp_header);
void swap_udp_header(udp_header_t *udp_header);

#endif
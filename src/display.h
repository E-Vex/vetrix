#ifndef DISPLAY_H
#define DISPLAY_H

/* Standard library */
#include <ctype.h>
#include <stdio.h>

/* Project headers */
#include "protocols.h"

void print_packet_header(pcap_packet_header_t *packet_header);
void print_ipv4_header(ipv4_header_t *ipv4_header);
void print_global_header(pcap_global_header_t *global_header);
void print_tcp_header(tcp_header_t *tcp_header);
void print_udp_header(udp_header_t *udp_header);
int print_payload(FILE *fp, size_t remaining_payload);
void print_packet_read_count(int *packet_counter);

#endif

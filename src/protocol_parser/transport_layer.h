#ifndef TRANSPORT_LAYER_H
#define TRANSPORT_LAYER_H

/* Standard library */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Project headers */
#include "endian.h"
#include "packet_context.h"
#include "protocols.h"

void parse_tcp_header(packet_context_t *ctx);
void parse_udp_header(packet_context_t *ctx);

#endif
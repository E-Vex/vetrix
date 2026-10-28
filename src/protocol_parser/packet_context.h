#ifndef PACKET_CONTEXT_H
#define PACKET_CONTEXT_H

/* Standard library */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct
{
    FILE *fp;
    size_t remaining_payload;
    int host_endianness;
    int pcap_endianness;

    uint32_t next_protocol;

} packet_context_t;

#endif
/* Standard library */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Project headers */
#include "endian.h"
#include "packet_context.h"
#include "protocols.h"
#include "../protocol_swap.h"

void parse_ipv4_header(packet_context_t *ctx)
{

    ipv4_header_t ipv4_header;

    fread(&ipv4_header, sizeof(ipv4_header_t), 1, ctx->fp);

    if (ctx->host_endianness == 1)
        swap_ipv4_header(&ipv4_header);

    int ipv4_header_len = 0;
    ipv4_header_len = (ipv4_header.version_ihl & 0x0F) * 4;
    if (ipv4_header_len > 20)
    {
        fseek(ctx->fp, (ipv4_header_len - 20), SEEK_CUR);
        ctx->remaining_payload -= ipv4_header_len;
    }
    else
    {
        ctx->remaining_payload -= 20;
    }

    ctx->next_protocol = ipv4_header.protocol;
}
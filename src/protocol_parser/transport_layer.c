/* Standard library */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Project headers */
#include "endian.h"
#include "packet_context.h"
#include "protocols.h"
#include "../protocol_swap.h"

void parse_tcp_header(packet_context_t *ctx)
{
    int tcp_header_len = 0;
    tcp_header_t tcp_header;

    fread(&tcp_header, sizeof(tcp_header_t), 1, ctx->fp);

    if (ctx->host_endianness == 1)
        swap_tcp_header(&tcp_header);

    tcp_header_len = ((tcp_header.offset_reserved >> 4) & 0x0F) * 4;
    if (tcp_header_len > 20)
    {
        fseek(ctx->fp, (tcp_header_len - 20), SEEK_CUR);
        ctx->remaining_payload -= tcp_header_len;
    }
    else
    {
        ctx->remaining_payload -= 20;
    }
}
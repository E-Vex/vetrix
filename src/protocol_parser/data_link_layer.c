/* Standard library */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Project headers */
#include "../display.h"
#include "endian.h"
#include "packet_context.h"
#include "protocols.h"
#include "protocol_swap.h"

void parse_sll2_header(packet_context_t *ctx)
{
    sll2_header_t sll2_header;
    if (fread(&sll2_header, sizeof(sll2_header_t), 1, ctx->fp) != 1)
        return;

    if (ctx->host_endianness == 1)
        swap_sll2_header(&sll2_header);

    ctx->next_protocol = sll2_header.protocol_type;
}

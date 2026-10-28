/* Standard library */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Project headers */
#include "display.h"
#include "endian.h"
#include "file_io.h"
#include "packet_context.h"
#include "protocols.h"
#include "protocol_swap.h"
#include "protocol_parser/protocol_parser.h"

#define LINKTYPE_ETHERNET 1
#define LINKTYPE_LINUX_SLL2 276
#define LINKTYPE_IEEE802_11 105
#define LINKTYPE_LINUX_SLL 113
#define LINKTYPE_NULL 0

void read_packets(FILE *fp, uint32_t data_link_type, uint32_t magic_number, file_info_t *file_info)
{
    pcap_packet_header_t packet_header;
    packet_context_t ctx;

    int packet_counter = 0;
    long limit = file_info->packets_to_read;

    /* Detect endianness once before the packet loop */
    uint8_t *bytes = magic_number_as_bytes(&magic_number);
    int pcap_endian = detect_pcap_endianness(bytes);
    int host_endian = detect_host_endianness();
    int need_swap = (pcap_endian != host_endian);

    ctx.host_endianness = host_endian;
    ctx.pcap_endianness = pcap_endian;

    while ((limit < 0 || packet_counter < limit) && fread(&packet_header, sizeof(pcap_packet_header_t), 1, fp) == 1)
    {
        ctx.remaining_payload = 0;
        ctx.fp = fp;
        packet_counter++;

        if (need_swap)
            swap_packet_header(&packet_header);

        ctx.remaining_payload += packet_header.incl_len;

        print_packet_header(&packet_header);

        switch (data_link_type)
        {
        case LINKTYPE_ETHERNET:
        {
            ethernet_header_t ethernet_header;
            (void)ethernet_header;
            fseek(fp, packet_header.incl_len, SEEK_CUR);
            break;
        }

        case LINKTYPE_LINUX_SLL:
        {
            sll_header_t sll_header;
            (void)sll_header;
            fseek(fp, packet_header.incl_len, SEEK_CUR);
            break;
        }

        case LINKTYPE_LINUX_SLL2:
        {
            parse_sll2_header(&ctx);
            ctx.remaining_payload -= sizeof(sll2_header_t);

            if (ctx.next_protocol == 0x800) // ipv4
            {
                parse_ipv4_header(&ctx);

                if (ctx.next_protocol == 6) // TCP
                {
                    parse_tcp_header(&ctx);
                }
                else if (ctx.remaining_payload > 0)
                {
                    fseek(fp, ctx.remaining_payload, SEEK_CUR);
                    ctx.remaining_payload = 0;
                }
            }
            else if (ctx.remaining_payload > 0)
            {
                fseek(fp, ctx.remaining_payload, SEEK_CUR);
                ctx.remaining_payload = 0;
            }

            if (ctx.remaining_payload > 0)
            {
                fseek(fp, ctx.remaining_payload, SEEK_CUR);
                ctx.remaining_payload = 0;
            }

            break;
        }

        default:
            printf("Unsupported Link Type!\n");
            fseek(fp, packet_header.incl_len, SEEK_CUR);
            break;
        }
        print_packet_read_count(&packet_counter);
    }
    printf("\n");
}

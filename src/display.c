/* Standard library */
#include <ctype.h>
#include <stdio.h>

/* Project headers */
#include "protocols.h"

void print_packet_header(pcap_packet_header_t *packet_header)
{
    printf("ts_sec : 0x%X\n", packet_header->ts_sec);
    printf("ts_usec : 0x%X\n", packet_header->ts_usec);
    printf("incl_len : %d\n", packet_header->incl_len);
    printf("orig_len : %d\n", packet_header->orig_len);
}
void print_ipv4_header(ipv4_header_t *ipv4_header)
{
    printf("version_ihl : %d\n", ipv4_header->version_ihl);
    printf("tos : %d\n", ipv4_header->tos);
    printf("total_length : %d\n", ipv4_header->total_length);
    printf("identification : %d\n", ipv4_header->identification);
    printf("flags_fo : %d\n", ipv4_header->flags_fo);
    printf("ttl : %d\n", ipv4_header->ttl);

    if (ipv4_header->protocol == 6)
    {
        printf("protocol : TCP\n");
    }
    else
    {
        printf("protocol : %d\n", ipv4_header->protocol);
    }

    printf("checksum : %d\n", ipv4_header->checksum);

    uint8_t *src = (uint8_t *)&ipv4_header->src_ip;
    printf("src_ip : %d.%d.%d.%d\n", src[0], src[1], src[2], src[3]);
    uint8_t *dst = (uint8_t *)&ipv4_header->dst_ip;
    printf("dst_ip : %d.%d.%d.%d\n", dst[0], dst[1], dst[2], dst[3]);
}
void print_global_header(pcap_global_header_t *global_header)
{
    printf("Magic Number : 0x%X\n", global_header->magic_number);
    printf("Major Version : %d\n", global_header->major_version);
    printf("Minor Version : %d\n", global_header->minor_version);
    printf("This Zone : %d\n", global_header->this_zone);
    printf("Sigfigs : %d\n", global_header->sigfigs);
    printf("Snaplen : %d\n", global_header->snaplen);
    printf("Network : 0x%X\n", global_header->network);
}
void print_tcp_header(tcp_header_t *tcp_header)
{
    printf("source_port : %u\n", tcp_header->source_port);
    printf("dst_port : %u\n", tcp_header->dst_port);
    printf("seq_num : %u\n", tcp_header->seq_num);
    printf("ack_num : %u\n", tcp_header->ack_num);

    printf("offset : 0x%X\n", (tcp_header->offset_reserved >> 4) & 0x0F);
    printf("reserved : 0x%X\n", ((tcp_header->offset_reserved)) & 0x0F);

    printf("TCP Flags: ");
    /*Bit Number :
     7    6    5    4    3    2    1    0
    +----+----+----+----+----+----+----+----+
    |CWR |ECE |URG |ACK |PSH |RST |SYN |FIN |
    +----+----+----+----+----+----+----+----+*/

    if (tcp_header->flags & 0x02)
        printf("SYN ");

    if (tcp_header->flags & 0x10)
        printf("ACK ");

    if (tcp_header->flags & 0x01)
        printf("FIN ");

    if (tcp_header->flags & 0x04)
        printf("RST ");

    printf("\n");

    printf("----------------\n");
    printf("window: %u\n", tcp_header->window);
    printf("checksum: %u\n", tcp_header->checksum);
    printf("urgent_ptr: %u\n", tcp_header->urgent_ptr);
}
void print_udp_header(udp_header_t *udp_header)
{
    printf("source_port : %u\n", udp_header->source_port);
    printf("dst_port : %u\n", udp_header->dst_port);
    printf("length : %u\n", udp_header->length);
    printf("checksum : %u\n", udp_header->checksum);

    printf("----------------\n");
}
int print_payload(FILE *fp, size_t remaining_payload)
{
    printf("\n--------------PAYLOAD--------------\n\n");

    if (remaining_payload == 0)
    {
        printf("There is no data to display\n");
        return 0;
    }

    if (remaining_payload < 0)
    {
        printf("Error! the file has been broken or it's corrupted\n");
        return 1;
    }

    uint8_t buf[16];
    size_t chk = 0;

    while (chk < remaining_payload)
    {
        size_t to_read = remaining_payload - chk;
        if (to_read > 16)
            to_read = 16;

        size_t nread = fread(buf, 1, to_read, fp);
        if (nread == 0)
        {
            printf("Error: unexpected end of file while reading payload\n");
            return 1;
        }
        chk += nread;

        for (size_t i = 0; i < nread; i++)
        {
            if (isprint(buf[i]))
                printf("%c", buf[i]);
            else
                printf(".");
        }

        printf("  |  ");

        for (size_t i = 0; i < nread; i++)
        {
            printf("%02X ", buf[i]);
        }

        /* Pad the rest of the 16-byte row */
        for (size_t i = nread; i < 16; i++)
        {
            printf("   ");
        }

        printf("\n");
    }

    return 0;
}
void print_packet_read_count(int *packet_counter)
{
    printf("\r\33[2Kpackets read: %d", *packet_counter);
    fflush(stdout);
}
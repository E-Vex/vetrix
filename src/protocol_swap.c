/* Standard library */
#include <stddef.h>
#include <stdio.h>

/* Project headers */
#include "endian.h"
#include "protocols.h"
void swap_global_header(pcap_global_header_t *global_header)
{

    static const field_descriptor_t fields[7] =
        {
            {offsetof(pcap_global_header_t, magic_number), sizeof(global_header->magic_number)},
            {offsetof(pcap_global_header_t, major_version), sizeof(global_header->major_version)},
            {offsetof(pcap_global_header_t, minor_version), sizeof(global_header->minor_version)},
            {offsetof(pcap_global_header_t, this_zone), sizeof(global_header->this_zone)},
            {offsetof(pcap_global_header_t, sigfigs), sizeof(global_header->sigfigs)},
            {offsetof(pcap_global_header_t, snaplen), sizeof(global_header->snaplen)},
            {offsetof(pcap_global_header_t, network), sizeof(global_header->network)}};

    swap_fields(global_header, fields, 7);
}
void swap_packet_header(pcap_packet_header_t *packet_header)
{
    static const field_descriptor_t fields[4] =
        {
            {offsetof(pcap_packet_header_t, ts_sec), sizeof(packet_header->ts_sec)},
            {offsetof(pcap_packet_header_t, ts_usec), sizeof(packet_header->ts_usec)},
            {offsetof(pcap_packet_header_t, incl_len), sizeof(packet_header->incl_len)},
            {offsetof(pcap_packet_header_t, orig_len), sizeof(packet_header->orig_len)}};

    swap_fields(packet_header, fields, 4);
}
void swap_sll2_header(sll2_header_t *sll2_header)
{
    static const field_descriptor_t fields[4] =
        {
            {offsetof(sll2_header_t, protocol_type), sizeof(sll2_header->protocol_type)},
            {offsetof(sll2_header_t, reserved), sizeof(sll2_header->reserved)},
            {offsetof(sll2_header_t, interface_index), sizeof(sll2_header->interface_index)},
            {offsetof(sll2_header_t, arphrd_type), sizeof(sll2_header->arphrd_type)}};

    swap_fields(sll2_header, fields, 4);
}
void swap_ipv4_header(ipv4_header_t *ipv4_header)
{
    // 1 byte no swap need

    static const field_descriptor_t fields[4] =
        {
            {offsetof(ipv4_header_t, total_length), sizeof(ipv4_header->total_length)},
            {offsetof(ipv4_header_t, identification), sizeof(ipv4_header->identification)},
            {offsetof(ipv4_header_t, flags_fo), sizeof(ipv4_header->flags_fo)},
            {offsetof(ipv4_header_t, checksum), sizeof(ipv4_header->checksum)}};

    swap_fields(ipv4_header, fields, 4);

    // no need to swap src and dst ip
}
void swap_tcp_header(tcp_header_t *tcp_header)
{
    static const field_descriptor_t fields[7] =
        {

            {offsetof(tcp_header_t, source_port), sizeof(tcp_header->source_port)},
            {offsetof(tcp_header_t, dst_port), sizeof(tcp_header->dst_port)},
            {offsetof(tcp_header_t, seq_num), sizeof(tcp_header->seq_num)},
            {offsetof(tcp_header_t, ack_num), sizeof(tcp_header->ack_num)},
            {offsetof(tcp_header_t, window), sizeof(tcp_header->window)},
            {offsetof(tcp_header_t, checksum), sizeof(tcp_header->checksum)},
            {offsetof(tcp_header_t, urgent_ptr), sizeof(tcp_header->urgent_ptr)}};

    swap_fields(tcp_header, fields, 7);

    /*-------------------check here why we dont swap offset_reserved and flags <IMPORTANT>-------------------------*/
    // swap_bytes(tcp_header->offset_reserved, sizeof(tcp_header->offset_reserved));
    // swap_bytes(tcp_header->flags, sizeof(tcp_header->flags));
}
void swap_udp_header(udp_header_t *udp_header)
{
    static const field_descriptor_t fields[4] =
        {
            {offsetof(udp_header_t, source_port), sizeof(udp_header->source_port)},
            {offsetof(udp_header_t, dst_port), sizeof(udp_header->dst_port)},
            {offsetof(udp_header_t, length), sizeof(udp_header->length)},
            {offsetof(udp_header_t, checksum), sizeof(udp_header->checksum)}};

    swap_fields(udp_header, fields, 4);
}
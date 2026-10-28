/* Standard library */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* System / POSIX */
#include <arpa/inet.h>

/* Project headers */
#include "cli/cli.h"
#include "display.h"
#include "file_info.h"
#include "file_io.h"
#include "packet_reader.h"
#include "protocols.h"

/*------------------------------------------------------------------*/

int main(int argc, char *argv[])
{
    pcap_global_header_t global_header;

    file_info_t file_info = {.path = NULL};

    /*---------------------------------------------------------------*/
    if (parse_cli(argc, argv, &file_info) != 1)
    {
        return 1;
    }

    pcap_file_info_t file_status = validate_pcap_file(&file_info);
    if (file_status.is_valid == false)
    {
        fprintf(stderr, "Error: Invalid or corrupted PCAP file header.\n");
        return -1;
    }

    FILE *filePointer = import_binary_file(file_info.path);
    check_file_pointer(filePointer);

    if (fread(&global_header, sizeof(pcap_global_header_t), 1, filePointer) != 1)
    {
        fprintf(stderr, "Error: failed to read global header\n");
        fclose(filePointer);
        return -1;
    }

    uint32_t magic_number = global_header.magic_number;

    uint32_t magic_local = global_header.magic_number;
    uint8_t *bytes = magic_number_as_bytes(&magic_local);
    int pcap_endian = detect_pcap_endianness(bytes);
    int host_endian = detect_host_endianness();

    if (pcap_endian != host_endian)
    {
        swap_global_header(&global_header);
    }

    print_global_header(&global_header);

    read_packets(filePointer, global_header.network, magic_number, &file_info);

    fclose(filePointer);
    return 0;
}

/* Standard library */
#include <stdio.h>
#include <stdlib.h>

/* Project headers */
#include "file_info.h"
#include "file_io.h"
#include "protocols.h"

FILE *import_binary_file(const char *filename)
{
    FILE *filePointer = fopen(filename, "rb");
    if (filePointer == NULL)
    {
        fprintf(stderr, "Error: failed to open file '%s'\n", filename);

        return NULL;
    }
    return filePointer;
}

char *get_file_path(file_info_t *file_info)
{
    return file_info->path;
}

void check_file_pointer(FILE *fp)
{
    if (fp == NULL)
    {
        fprintf(stderr, "Error: failed to open file\n");
        exit(1);
    }
}

pcap_file_info_t validate_pcap_file(FILE *fp, pcap_global_header_t *global_header)
{
    pcap_file_info_t pfi = {false};

    if (fread(global_header, sizeof(pcap_global_header_t), 1, fp) != 1)
    {
        return pfi;
    }

    if (global_header->magic_number != PCAP_MAGIC_MICRO && global_header->magic_number != PCAP_SWAPPED_MAGIC_MICRO)
    {
        return pfi;
    }

    if (global_header->snaplen == 0 || global_header->snaplen > 262144)
    {
        return pfi;
    }

    pfi.is_valid = true;
    return pfi;
}

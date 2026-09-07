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
        printf("Failed to open the file <NULL>\n");

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
        printf("Error: failed to open the file\n");
        exit(1);
    }
}

pcap_file_info_t validate_pcap_file(file_info_t *file_info)
{

    pcap_global_header_t global_header;
    pcap_file_info_t pfi = {false};

    FILE *t_filePointer = import_binary_file(file_info->path);
    check_file_pointer(t_filePointer);

    if (fread(&global_header, sizeof(pcap_global_header_t), 1, t_filePointer) != 1)
    {
        fclose(t_filePointer);
        return pfi;
    }

    if (global_header.magic_number != PCAP_MAGIC_MICRO && global_header.magic_number != PCAP_SWAPPED_MAGIC_MICRO)
    {
        fclose(t_filePointer);
        return pfi;
    }

    if (global_header.snaplen == 0 || global_header.snaplen > 262144)
    {
        fclose(t_filePointer);
        return pfi;
    }

    fclose(t_filePointer);
    pfi.is_valid = true;
    return pfi;
}

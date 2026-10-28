#ifndef FILE_H
#define FILE_H

/* Standard library */
#include <stdbool.h>
#include <stdio.h>

/* Project headers */
#include "file_info.h"
#include "protocols.h"

typedef struct
{
    bool is_valid;
} pcap_file_info_t;

FILE *import_binary_file(const char *filename);
char *get_file_path(file_info_t *file_info);
void check_file_pointer(FILE *fp);
pcap_file_info_t validate_pcap_file(FILE *fp, pcap_global_header_t *global_header);

#endif
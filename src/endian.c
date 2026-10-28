/* Standard library */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Project headers */
#include "endian.h"

void swap_bytes(void *data, size_t size)
{
    uint8_t *bytes = (uint8_t *)data;

    uint8_t tmp;

    for (size_t i = 0; i < size / 2; i++)
    {
        tmp = bytes[i];
        bytes[i] = bytes[size - 1 - i];
        bytes[size - 1 - i] = tmp;
    }
}
/*---------------------------------------------------------------*/

void swap_fields(void *base, const field_descriptor_t *fields, size_t count)
{
    for (size_t i = 0; i < count; i++)
    {
        swap_bytes((uint8_t *)base + fields[i].offset, fields[i].size);
    }
}

/*---------------------------------------------------------------*/

void magic_number_as_bytes(uint32_t magic_number, uint8_t out[4])
{
    memcpy(out, &magic_number, 4);
}

int detect_pcap_endianness(uint8_t *b)
{
    int endian_state = -1; /*LITTLE = 1 & BIG = 0, Default to -1 (Error / Unknown)*/

    if (b[0] == 0xa1 && b[1] == 0xb2 && b[2] == 0xc3 && b[3] == 0xd4)
    {
        endian_state = 0; /*BIG endian*/
    }
    else if (b[0] == 0xd4 && b[1] == 0xc3 && b[2] == 0xb2 && b[3] == 0xa1)
    {
        endian_state = 1; /*LITTLE endian*/
    }

    return endian_state;

    /*========================
    |-1 => (Error / Unknown) |
    | 1 => (LITTLE endian)   |
    | 0 => (BIG endian)      |
    ========================*/
}

int detect_host_endianness(void)
{
    uint32_t value = 0x01020304;
    unsigned char *ptr = (unsigned char *)&value;

    return (*ptr == 0x04);

    /*========================
    | 1 => (LITTLE endian)   |
    | 0 => (BIG endian)      |
    ========================*/
}
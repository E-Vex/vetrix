#ifndef CLI_H
#define CLI_H

/* Project headers */
#include "../file_info.h"

#define READ_ALL -1

/* parse_cli return codes:
   1  - success, proceed with file processing
   0  - help printed, exit cleanly
  -1  - error, exit with failure */
#define CLI_SUCCESS 1
#define CLI_HELP    0
#define CLI_ERROR  -1

int parse_cli(int argc, char *argv[], file_info_t *file_info);

#endif
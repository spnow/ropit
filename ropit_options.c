#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>

#include "ropit_options.h"

// input file
int ropit_option_file_input (int random) {
    fprintf(stderr, "error: Function not yet implemented\n");
    return -1;
}

// output file
int ropit_option_file_output (int random) {
    fprintf(stderr, "error: Function not yet implemented\n");
    return -1;
}

// file type
int ropit_option_file_type (int random) {
    fprintf(stderr, "error: Function not yet implemented\n");
    return -1;
}

// show how to use ROPit
void usage(char *program) {
    printf("ROPit 0.1 alpha 2 ( http://binholic.blogspot.com/ )\n");
    printf("Usage: %s [options]\n\n", program);
    printf("INPUT:\n");
    printf("    --file-in   :  Name of input file\n");
    printf("    --file-out  :  Name of output file\n");
    printf("    --file-type :  executable or raw, will check both by default\n");
    printf("OUTPUT:\n");
    printf("    --output-type : txt\n");
}

// parse options and trigger actions
void parse_options (int argc, char *argv[]) {
    int option_index = 0, option_id = 0;
    char flag[NUMBER_OF_OPTIONS] = {0};
    static struct option long_options[] = 
    {
        { "file-in", required_argument, NULL, ROPIT_OPTION_FILE_IN },
        { "file-out", no_argument, NULL, ROPIT_OPTION_FILE_OUT },
        { "file-type", required_argument, NULL, ROPIT_OPTION_FILE_TYPE },
        { "output-type", required_argument, NULL, ROPIT_OPTION_OUTPUT_TYPE },
        { "threads", required_argument, NULL, ROPIT_OPTION_THREADS },
        { "color", no_argument, NULL, ROPIT_OPTION_COLOR },
        { "verbose", no_argument, NULL, 'v' },
        { 0, 0, 0, 0 }
    };

    while (option_id >= 0) {
        option_id = getopt_long (argc, argv, "v", long_options, &option_index);

        switch (option_id) {
            case ROPIT_OPTION_FILE_IN:
                flag[ROPIT_OPTION_FILE_IN] = 1;
                break;
            case ROPIT_OPTION_FILE_OUT:
                flag[ROPIT_OPTION_FILE_OUT] = 1;
                break;
            case ROPIT_OPTION_FILE_TYPE:
                flag[ROPIT_OPTION_FILE_TYPE] = 1;
                break;
            case ROPIT_OPTION_OUTPUT_TYPE:
                flag[ROPIT_OPTION_OUTPUT_TYPE] = 1;
                break;
            case ROPIT_OPTION_COLOR:
                flag[ROPIT_OPTION_COLOR] = 1;
                break;
            case 'v':
                flag[ROPIT_OPTION_VERBOSE_LEVEL]++;
                break;
            default:
                break;
        }
    }

    if (flag[ROPIT_OPTION_FILE_IN] != 1) {
        fprintf(stderr, "file-in not defined\n");
        exit(-1);
    }

    if (flag[ROPIT_OPTION_FILE_OUT] != 1) {
    }
    else {
    }

    if (flag[ROPIT_OPTION_FILE_TYPE] != 1) {
    }
    else {
    }
}


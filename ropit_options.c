#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>

#include "ropit_options.h"

// input file
int ropit_option_file_input (int random) {
}

// show how to use ROPit
void usage(char *program) {
    printf("Usage: %s file\n\n", program);
    printf("--file-in   :  Name of input file\n");
    printf("--file-out  :  Name of output file\n");
    printf("--file-type :  executable or raw, will check both by default\n");
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
        { 0, 0, 0, 0 }
    };

    while (1) {
        option_id = getopt_long (argc, argv, NULL, long_options, &option_index);
        if (option_id == -1)
            break;

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
        }
    }
}

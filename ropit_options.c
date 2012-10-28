#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>

#include "arch/arch.h"
#include "ropit_options.h"

struct ropit_options_t config;

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
    printf("==========================================\n");
    printf("==      ROPit v0.1 alpha 2 by m_101     ==\n");
    printf("==  site: http://binholic.blogspot.com/ ==\n");
    printf("==========================================\n");
    printf("Usage: %s [options]\n\n", program);
    printf("INPUT:\n");
    printf("    --in [filename]      : Name of input file\n");
    printf("    --filetype [type]    : executable or raw, will check both by default\n");
    printf("    --payload [name]     : Choose a payload\n");
    printf("    --color              : Enable coloring\n");
    printf("    --verbose            : Enable verbosity (up to 3)\n");
    printf("OUTPUT:\n");
    printf("    --oX [basename] : output in XML\n");
    printf("    --oT [basename] : output in TXT\n");
    printf("    --oA [basename] : output in XML and TXT\n");
}

struct ropit_options_t *config_default (struct ropit_options_t *config)
{
    if (!config)
        return NULL;
    
    // config default
    config->filename_input = NULL;
    config->filename_output = "output_default.txt";
    config->filetype = 0;
    config->verbose_level = 0;
    config->color = 1;
    config->n_threads = 1;
    config->arch = ARCH_X86_32;

    return config;
}

// parse options and trigger actions
void parse_options (int argc, char *argv[]) {
    int option_index = 0, option_id = 0;
    int flag[NUMBER_OF_OPTIONS];
    static struct option long_options[] = 
    {
        { "in", required_argument, NULL, 'i' },
        { "out", optional_argument, NULL, 'o' },
        { "filetype", required_argument, NULL, 't' },
        { "format", required_argument, NULL, 'f' },
        { "threads", required_argument, NULL, 'n' },
        { "color", no_argument, NULL, 'c' },
        { "verbose", no_argument, NULL, 'v' },
        { 0, 0, 0, 0 }
    };

    while (option_id >= 0) {
        option_id = getopt_long (argc, argv, "i::o:t::f::n::cv", long_options, &option_index);

        switch (option_id) {
            case 'i':
                if (flag[ROPIT_OPTION_FILE_IN] == 0 && optarg) {
                    config.filename_input = optarg;
                    flag[ROPIT_OPTION_FILE_IN] = 1;
                }
                break;
            case 'o':
                if (flag[ROPIT_OPTION_FILE_OUT] == 0 && optarg) {
                        config.filename_output = optarg;
                    flag[ROPIT_OPTION_FILE_OUT] = 1;
                }
                break;
            case 't':
                if (flag[ROPIT_OPTION_FILE_TYPE] == 0 && optarg) {
                    flag[ROPIT_OPTION_FILE_TYPE] = 1;
                }
                break;
            case 'f':
                flag[ROPIT_OPTION_OUTPUT_TYPE] = 1;
                break;
            case 'c':
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


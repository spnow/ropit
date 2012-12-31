#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include <getopt.h>

#include "arch/arch.h"
#include "gadgets_cache.h"
#include "ropit_options.h"

struct ropit_options_t config;

// input file
int ropit_option_file_input (int random) {
    debug_printf (MESSAGE_ERROR, stderr, "error: Function not yet implemented\n");
    return -1;
}

// output file
int ropit_option_file_output (int random) {
    debug_printf (MESSAGE_ERROR, stderr, "error: Function not yet implemented\n");
    return -1;
}

// file type
int ropit_option_file_type (int random) {
    debug_printf (MESSAGE_ERROR, stderr, "error: Function not yet implemented\n");
    return -1;
}

void banner ()
{
    printf("==========================================\n");
    printf("==      ROPit v0.1 alpha 3 by m_101     ==\n");
    printf("==  site: http://binholic.blogspot.com/ ==\n");
    printf("==========================================\n");
}

// show how to use ROPit
void usage(char *program)
{
    printf("Usage: %s [options]\n\n", program);
    printf("GENERAL:\n");
    printf("    --help , -h           : help\n");
    printf("INPUT:\n");
    printf("    --in [filename] , -i   : Name of input file\n");
    /*
    printf("    --filetype [type] , -t   : executable or raw, will check both by default\n");
    printf("    --payload [name]  , -p   : Choose a payload\n");
    //*/
    printf("    --color , -c             : Enable coloring\n");
    printf("    --verbose , -v           : Enable verbosity (up to 3)\n");
    printf("OUTPUT:\n");
    printf("    --out [filename] , o [filename]  : output to [basename]\n");
    /*
    printf("    -tX [basename] : output in XML\n");
    printf("    -tT [basename] : output in TXT\n");
    printf("    -tA [basename] : output in XML and TXT\n");
    //*/
    printf("FORMAT:\n");
    printf("    --format , -f [format]     : stack or line (default)\n");
}

struct ropit_options_t *config_default (struct ropit_options_t *config)
{
    if (!config)
        return NULL;
    
    // config default
    config->filename_input = NULL;
    config->filename_output = NULL;
    config->format = GADGET_CACHE_LINE;
    config->filetype = 0;
    config->verbose_level = 0;
    config->color = 0;
    config->n_threads = 1;
    config->arch = ARCH_X86_32;

    return config;
}

// parse options and trigger actions
void parse_options (int argc, char *argv[]) {
    int option_index = 0, option_id = 0;
    static struct option long_options[] = 
    {
        { "in", required_argument, NULL, 'i' },
        { "out", required_argument, NULL, 'o' },
        { "filetype", required_argument, NULL, 't' },
        { "format", required_argument, NULL, 'f' },
        { "threads", required_argument, NULL, 'n' },
        { "color", no_argument, NULL, 'c' },
        { "verbose", no_argument, NULL, 'v' },
        { "help", no_argument, NULL, 'h' },
        { 0, 0, 0, 0 }
    };

    if (argc <= 0 || !argv) {
        debug_printf (MESSAGE_ERROR, stderr, "fatal: No parameters\n");
        exit (1);
    }

    config_default (&config);

    while (option_id >= 0) {
        option_id = getopt_long (argc, argv, "i:o:t:f:n:cvh", long_options, &option_index);

        switch (option_id) {
            case 'i':
                config.filename_input = optarg;
                break;
            case 'o':
                config.filename_output = optarg;
                break;
            case 't':
                config.filetype = 1;
                break;
            case 'f':
                if (optarg == NULL)
                    config.format = GADGET_CACHE_LINE;
                else if (strcmp (optarg, "line") == 0)
                    config.format = GADGET_CACHE_LINE;
                else if (strcmp (optarg, "stack") == 0)
                    config.format = GADGET_CACHE_STACK;
                break;
            case 'n':
                config.n_threads = strtol (optarg, NULL, 10);
                if (config.n_threads == LONG_MIN
                        || config.n_threads == LONG_MAX
                        || config.n_threads <= 0
                        || config.n_threads > 8) {
                    debug_printf (MESSAGE_ERROR, stderr, "fatal: n_threads should be between 0-8\n");
                    exit (1);
                }
                break;
            case 'c':
                config.color = GADGET_CACHE_COLOR;
                break;
            case 'v':
                if (config.verbose_level < 3)
                    config.verbose_level++;
                break;
            case 'h':
                usage(argv[0]);
                exit(1);
                break;
            default:
                break;
        }
    }

    if (config.filename_input == NULL) {
        debug_printf (MESSAGE_ERROR, stderr, "error: --input not defined\n");
        exit(-1);
    }

    if (config.format == 0) {
        debug_printf (MESSAGE_ERROR, stderr, "fatal: format should be either 'stack' or 'line'\n");
        exit (1);
    }

    if (config.verbose_level > 0)
        debug_set_verbose_level (config.verbose_level);
}


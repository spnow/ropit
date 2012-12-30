#ifndef _ROPIT_OPTIONS_H_
#define _ROPIT_OPTIONS_H_

void banner ();
// show how to use ROPit
void usage(char *program);
// parse options and trigger actions
void parse_options (int argc, char *argv[]);

struct ropit_options_t {
    char *filename_input;
    char *filename_output;
    int format;
    int filetype;
    int verbose_level;
    int color;
    int n_threads;
    int arch;
};

extern struct ropit_options_t config;

#define ROPIT_OPTION_FILE_IN        0
#define ROPIT_OPTION_FILE_OUT       1
#define ROPIT_OPTION_FILE_TYPE      2
#define ROPIT_OPTION_OUTPUT_TYPE    3
#define ROPIT_OPTION_VERBOSE_LEVEL  4
#define ROPIT_OPTION_COLOR          5
#define ROPIT_OPTION_THREADS        6

#define NUMBER_OF_OPTIONS           7

#endif /* _ROPIT_OPTIONS_H_ */

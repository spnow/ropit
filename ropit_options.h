#ifndef _ROPIT_OPTIONS_H_
#define _ROPIT_OPTIONS_H_

// show how to use ROPit
void usage(char *program);
// parse options and trigger actions
void parse_options (int argc, char *argv[]);

#define ROPIT_OPTION_FILE_IN        0
#define ROPIT_OPTION_FILE_OUT       1
#define ROPIT_OPTION_FILE_TYPE      2

#define NUMBER_OF_OPTIONS           4

#endif /* _ROPIT_OPTIONS_H_ */

#ifndef _GADGETS_X86_H_
#define _GADGETS_X86_H_

#include <stdint.h>

//
#include "offsets.h"

// search rets
struct ropit_offsets_t* ropit_opcodes_find_ret(uint8_t *bytes, int len);
// check if inst is good
int ropit_instructions_check (char *inst, int len);

// disasm functions
char* ropit_listing_disasm (uint8_t *bytes, int len);
char* ropit_instructions_show (uint8_t *bytes, int len);

#endif /* _GADGETS_X86_H_ */

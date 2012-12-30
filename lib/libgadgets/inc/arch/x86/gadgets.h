#ifndef _GADGETS_X86_H_
#define _GADGETS_X86_H_

#include <stdint.h>

//
#include "offsets.h"

extern struct gadget_plugin_t x86_gadget_plugin;

// init x86 gadget plugin
struct gadget_plugin_t *gadgets_x86_init (void);
// search rets
struct offsets_t* ropit_opcodes_find_ret(uint8_t *bytes, int len);
// check if inst is good
int ropit_instructions_check (char *inst, int len);

// disasm functions
char* ropit_listing_disasm (uint8_t *bytes, int len);
// disasm 1 instruction
char *ropit_x86_disasm (uint8_t *bytes, int len, int *sz_dis);
char* ropit_instructions_show (uint8_t *bytes, int len);

#endif /* _GADGETS_X86_H_ */

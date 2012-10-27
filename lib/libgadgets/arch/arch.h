#ifndef _GADGET_ARCH_H_
#define _GADGET_ARCH_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define ARCH_X86_16     1
#define ARCH_X86_32     2
#define ARCH_X86_64     4

// search some opcodes
struct offsets_t* ropit_opcodes_find(uint8_t *bytes, int szBytes,
        uint8_t *opcodes, int szOps, int szOpcode);
// find valid instructions offsets before ret
struct offsets_t* ropit_instructions_find(uint8_t *bytes, int len);

struct gadget_plugin_t {
	char *name;
	char *arch;
	char *desc;
	int (*init)(void *user);
	int (*fini)(void *user);
    char (*find_gadgets) (uint8_t *buf, int len);
    char (*find_rets) (uint8_t *buf, int len);
    char (*find_branches) (uint8_t *buf, int len);
};

#include "x86/gadgets.h"

#endif /* _GADGET_ARCH_H_ */

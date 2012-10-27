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

extern struct gadget_plugin_t *current_gadget_plugin;

struct gadget_plugin_t {
    // attributes
	char *name;
	char *arch;
	char *desc;
    //
    char *rets;
    int n_rets;

    // methods
	int (*init)(void);
	int (*fini)(void);
    int (*find_gadgets) (uint8_t *buf, int len);
    struct offsets_t *(*find_rets) (uint8_t *buf, int len);
    struct offsets_t *(*find_branches) (uint8_t *buf, int len);
};

struct gadget_plugin_t *gadget_plugin_new_copy (struct gadget_plugin_t *plugin);
int gadget_plugin_destroy (struct gadget_plugin_t **plugin);

#include "x86/gadgets.h"

#endif /* _GADGET_ARCH_H_ */

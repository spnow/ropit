#ifndef _GADGET_ARCH_H_
#define _GADGET_ARCH_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// search some opcodes
struct ropit_offsets_t* ropit_opcodes_find(uint8_t *bytes, int szBytes,
        uint8_t *opcodes, int szOps, int szOpcode);
// find valid instructions offsets before ret
struct ropit_offsets_t* ropit_instructions_find(uint8_t *bytes, int len);

#include "x86/gadgets_x86.h"

#endif /* _GADGET_ARCH_H_ */

/*
    ROPit - Gadget generator tool
    Copyright (C) 2011  m_101

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _GADGETS_INTERNAL_H_
#define _GADGETS_INTERNAL_H

#define DISASSEMBLED_SIZE_MAX   256
#define GADGET_SIZE_MAX         2048

#include <stdlib.h>

#include "gadgets_data.h"

int compare_ints (const void * a, const void * b);
// search some opcodes
struct ropit_offsets_t* ropit_opcodes_find(unsigned char *bytes, size_t n,
        unsigned char *opcodes, size_t m, size_t szOpcode);
// search rets
struct ropit_offsets_t* ropit_opcodes_find_ret(unsigned char *bytes, size_t len);

// filter by regexp
struct ropit_offsets_t* ropit_filter_regexp(unsigned char *bytes, size_t len, char *expr);
// filter pop/pop/ret
struct ropit_offsets_t* ropit_filter_ppr(unsigned char *bytes, size_t len);

// find valid instructions offsets before ret
struct ropit_offsets_t* ropit_instructions_find(unsigned char *bytes, size_t len);

// find gadgets offsets
// construct gadgets from instructions finder
struct ropit_gadget_t* ropit_gadgets_find(unsigned char *bytes, size_t len, uint64_t base);

char* ropit_listing_disasm (unsigned char *bytes, size_t len);
char* ropit_instructions_show (unsigned char *bytes, size_t len);

#endif

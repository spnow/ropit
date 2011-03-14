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

#ifndef _GADGETS_H_
#define _GADGETS_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct ropit_offsets_t {
    int *offsets;
    size_t capacity;
    size_t used;
};

struct ropit_offsets_t* ropit_offsets_new(size_t size);
struct ropit_offsets_t* ropit_offsets_realloc(struct ropit_offsets_t *ropmatch, size_t size);
void ropit_offsets_destroy(struct ropit_offsets_t **match);
size_t ropit_offsets_exist(struct ropit_offsets_t *array, int offset);
int compare_ints (const void * a, const void * b);
// search some opcodes
struct ropit_offsets_t* ropit_opcodes_find(unsigned char *bytes, size_t n,
        unsigned char *opcodes, size_t m, size_t szOpcode);
// search rets
struct ropit_offsets_t* ropit_opcodes_find_ret(unsigned char *bytes, size_t len);
//
struct ropit_offsets_t* ropit_filter_regexp(unsigned char *bytes, size_t len, char *expr);
struct ropit_offsets_t* ropit_filter_ppr(unsigned char *bytes, size_t len);
// find valid instructions offsets before ret
struct ropit_offsets_t* ropit_instructions_find(unsigned char *bytes, size_t len);

struct string_t {
    char *str;
    size_t len;
    // boolean for malloc() to avoid error while freeing
    int malloced;
};

struct ropit_gadget_t {
    // gadgets
    struct ropit_offsets_t *gadgets;
    // instructions
    size_t nInstructions;
};

struct ropit_gadget_t* ropit_gadget_new(size_t n);
struct ropit_gadget_t* ropit_gadget_realloc(struct ropit_gadget_t *gadget, size_t n);
void ropit_gadget_destroy(struct ropit_gadget_t **gadget);
struct ropit_gadget_t* ropit_gadget_append (struct ropit_gadget_t *gadgets_list, struct ropit_gadget_t *gadgets);
// find gadgets offsets
// construct gadgets from instructions finder
struct ropit_gadget_t* ropit_gadgets_find(unsigned char *bytes, size_t len, uint64_t base);
// find gadgets in executable file
struct ropit_gadget_t* ropit_gadgets_find_in_executable(char *filename);
// find gadgets in file
struct ropit_gadget_t* ropit_gadgets_find_in_file(char *filename);
char* ropit_listing_disasm (unsigned char *bytes, size_t len);
char* ropit_instructions_show (unsigned char *bytes, size_t len);

#endif /* _GADGETS_H_ */

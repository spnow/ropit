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

#define GADGET_FILE_CACHE   "tmp/gadget_cache"
#define GADGET_FILE_RESUME  "tmp/gadget_resume"

/* colors */
#define COLOR_PURPLE    "\033[95m"
#define COLOR_BLUE      "\033[94m"
#define COLOR_GREEN     "\033[92m"
#define COLOR_YELLOW    "\033[93m"
#define COLOR_RED       "\033[91m"
#define COLOR_WHITE     "\033[0m"

// one gadget
struct gadget_t {
    uint64_t address;
    int32_t type;
    // ret
    uint64_t ret_addr;
    uint8_t *ret_bytes;
    // binary repr
    int16_t len_bytes;
    int16_t sz_bytes;
    uint8_t *bytes;
    // disassembled repr
    int16_t len_repr;
    int16_t sz_repr;
    uint8_t *repr;
};

// free gadget
void gadget_free (struct gadget_t *gadget);
// init gadget
struct gadget_t *gadget_init (struct gadget_t *gadget, int sz);
// allocate new gadget
struct gadget_t* gadget_new(void);
// allocate new gadget and copy old
struct gadget_t* gadget_new_copy(struct gadget_t *gadget);
// destroy gadget
void gadget_destroy(struct gadget_t **gadget);
// copy a gadget to another one
struct gadget_t* gadget_copy(struct gadget_t *dest, struct gadget_t *src);
// get address of gadget
uint64_t gadget_get_address(struct gadget_t *gadget);

// show gadget
void gadget_show (struct gadget_t *gadget);

#endif /* _GADGETS_H_ */

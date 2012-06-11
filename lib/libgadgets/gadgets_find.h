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

#ifndef _GADGETS_FIND_H_
#define _GADGETS_FIND_H_

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// generic callback
struct gadget_callbacks_t {
    // find branching instructions
    struct offset_t* (*find_branches)(uint8_t *bytes, int nBytes);
    // find gadgets
    struct offset_t* (*find_gadgets)(uint8_t *bytes, int nBytes);
};

// find gadgets in ELF file
struct gadget_t* gadgets_find_in_elf(char *filename);
// find gadgets in PE file
struct gadget_t* gadgets_find_in_pe(char *filename);
// find gadgets in executable file
struct gadget_t* gadgets_find_in_executable(char *filename);
// find gadgets in file
struct gadget_t* gadgets_find_in_file(char *filename);

#endif /* _GADGETS_H_ */

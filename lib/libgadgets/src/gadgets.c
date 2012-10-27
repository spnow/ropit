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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <string.h>
#include <ctype.h>
#include <elf.h>

#define BUF_SIZE    1024
#define LINE_SIZE   1024

#include "gadgets.h"

// allocate new gadget
struct gadget_t* gadget_new(void) {
    struct gadget_t *gadget;

    gadget = calloc(sizeof(*gadget), 1);
    
    return gadget;
}

// allocate new gadget and copy old
struct gadget_t* gadget_new_copy(struct gadget_t *gadget) {
    struct gadget_t *copy;

    //
    if (!gadget) {
        fprintf(stderr, "error: gadget_new_copy(): gadget was null\n");
        return NULL;
    }

    // allocs
    copy = gadget_new();
    if (!copy) {
        fprintf(stderr, "error: gadget_new_copy(): copy was not allocated\n");
        return NULL;
    }
    copy->repr = calloc(gadget->sz_repr, sizeof(*copy->repr));
    copy->bytes = calloc(gadget->sz_bytes, sizeof(*copy->bytes));

    // if one of the alloc failed
    // then copied object failed
    if (copy->repr == NULL || copy->bytes == NULL) {
        fprintf(stderr, "error: gadget_new_copy(): failed bytes or repr allocation\n");
        free(copy->repr);
        free(copy->bytes);

        return NULL;
    }

    // if copy failed
    // then bye
    if (gadget_copy(copy, gadget) == NULL) {
        fprintf(stderr, "error: gadget_new_copy(): failed copy\n");
        gadget_destroy(&copy);
        return NULL;
    }

    return copy;
}

// destroy gadget
void gadget_destroy(struct gadget_t **gadget) {
    if (!gadget || !(*gadget))
        return;

    free((*gadget)->repr);
    free((*gadget)->bytes);
    *gadget = NULL;
}

// copy a gadget to another one
struct gadget_t* gadget_copy(struct gadget_t *dest, struct gadget_t *src) {
    // check parameters
    if ((!dest || !src) && src == dest) {
        fprintf(stderr, "error: gadget_copy(): dest or src are non existent\n");
        return NULL;
    }

    // check src
    if (!src->bytes || !src->repr) {
        fprintf(stderr, "error: gadget_copy(): src has no elements\n");
        return NULL;
    }

    // 
    if (dest->sz_bytes != src->sz_bytes) {
        fprintf(stderr, "warning: gadget_copy(): realloc of dest->bytes\n");
        dest->bytes = realloc(dest->bytes, src->sz_bytes * sizeof(*dest->bytes));
    }
    // 
    if (dest->sz_repr != src->sz_repr) {
        fprintf(stderr, "warning: gadget_copy(): realloc of dest->repr\n");
        dest->repr = realloc(dest->repr, src->sz_repr * sizeof(*dest->repr));
    }

    // check
    if (dest->bytes == NULL || dest->repr == NULL) {
        fprintf(stderr, "error: gadget_copy(): dest->bytes = %p or dest->repr = %p\n", dest->bytes, dest->repr);
        return NULL;
    }

    dest->address = src->address;
    dest->len_bytes = src->len_bytes;
    dest->sz_bytes = src->sz_bytes;
    dest->len_repr = src->len_repr;
    dest->sz_repr = src->sz_repr;

    // copy repr and bytes
    memcpy(dest->bytes, src->bytes, src->len_bytes);
    memcpy(dest->repr, src->repr, src->len_repr);

    return dest;
}


#include <stdio.h>
#include <stdlib.h>

#include <stdint.h>

#include <fall4c/fall4c.h>

#include "offsets.h"

struct offsets_t* offsets_new(int nElt) {
    struct offsets_t *match = calloc(1, sizeof(*match));

    if (!match)
        return NULL;
    if (!nElt)
        nElt = 1;
    match->offsets = calloc(nElt, sizeof(*(match->offsets)));
    if (!match->offsets)
        return NULL;
    match->capacity = nElt;
    match->used = 0;

    return match;
}

struct offsets_t* offsets_realloc(struct offsets_t *offsets, int nElt) {
    if (!offsets || nElt <= 0)
        return NULL;

    offsets->offsets = realloc(offsets->offsets, nElt * sizeof(*(offsets->offsets)));
    offsets->capacity = nElt;
    //
    if (offsets->used > nElt)
        offsets->used = nElt;

    return offsets;
}

void offsets_destroy(struct offsets_t **match) {
    if (!match)
        return;
    if (!*match)
        return;

    free((*match)->offsets);
    free(*match);
    *match = NULL;
}

int offsets_exist(struct offsets_t *array, int offset) {
    int idx;

    if (!array)
        return 0;

    for (idx = 0; idx < array->used; idx++) {
        if (array->offsets[idx] == offset) {
            return idx + 1;
        }
    }

    return -1;
}

// append 2 offsets_t* struct
struct offsets_t* offsets_append(struct offsets_t *dest, struct offsets_t *src) {
    int idxOff, nElt;

    // check parameters
    if (!dest || !src) {
        debug_printf (MESSAGE_ERROR, stderr, "error: offsets_append(): dest or src not set\n");
        return NULL;
    }

    // destination
    debug_printf (MESSAGE_INFO, stdout, "info : before: dest->capacity: %d , dest->used: %d\n", dest->capacity, dest->used);
    dest = offsets_realloc(dest, dest->used + src->used);
    if (!dest) {
        debug_printf (MESSAGE_ERROR, stderr, "error: offsets_append(): failed allocating enough memory for dest\n");
        return NULL;
    }
    debug_printf (MESSAGE_INFO, stdout, "info : after: dest->capacity: %d , dest->used: %d\n", dest->capacity, dest->used);
    debug_printf (MESSAGE_INFO, stdout, "info : offsets_append(): src->used=%d dest->used=%d\n", src->used, dest->used);

    //
    for (idxOff = dest->used; idxOff < dest->used + src->used; idxOff++)
        dest->offsets[idxOff] = src->offsets[idxOff - dest->used];
    dest->used = dest->used + src->used;

    return dest;
}

// append an array to an offsets_t* struct
struct offsets_t* offsets_append_array(struct offsets_t *dest, uint64_t *src, int n) {
    int idxOff, nElt;

    if (!dest || !src || n <= 0) {
        debug_printf (MESSAGE_ERROR, stderr, "error: offsets_append_array(): dest or src not set\n");
        return NULL;
    }

    dest = offsets_realloc(dest, dest->used + n);
    if (!dest) {
        debug_printf (MESSAGE_ERROR, stderr, "error: offsets_append_array(): failed allocating enough memory for dest\n");
        return NULL;
    }

    for (idxOff = dest->used; idxOff < dest->used + n; idxOff++)
        dest->offsets[idxOff] = src[idxOff - dest->used];
    dest->used = dest->used + n;

    return dest;
}


#include <stdio.h>
#include <stdlib.h>

#include "offsets.h"

struct offsets_t* offsets_new(int nElt) {
    struct offsets_t *match = calloc(1, sizeof(*match));

    if (!match)
        return NULL;
    match->offsets = calloc(nElt, sizeof(*(match->offsets)));
    if (!match->offsets)
        return NULL;
    match->capacity = nElt;
    match->used = 0;

    return match;
}

struct offsets_t* offsets_realloc(struct offsets_t *ropmatch, int nElt) {
    if (!ropmatch || nElt <= 0)
        return NULL;

    ropmatch->offsets = realloc(ropmatch->offsets, nElt * sizeof(*(ropmatch->offsets)));
    ropmatch->capacity = nElt;
    //
    if (ropmatch->used > nElt)
        ropmatch->used = nElt;

    return ropmatch;
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
        fprintf(stderr, "error: offsets_append(): dest or src not set\n");
        return NULL;
    }

    // destination
    fprintf(stdout, "info: before: dest->capacity: %d , dest->used: %d\n", dest->capacity, dest->used);
    dest = offsets_realloc(dest, dest->used + src->used);
    if (!dest) {
        fprintf(stderr, "error: offsets_append(): failed allocating enough memory for dest\n");
        return NULL;
    }
    fprintf(stdout, "info: after: dest->capacity: %d , dest->used: %d\n", dest->capacity, dest->used);
    fprintf(stdout, "info: offsets_append(): src->used=%d dest->used=%d\n", src->used, dest->used);

    //
    for (idxOff = dest->used; idxOff < dest->used + src->used; idxOff++)
        dest->offsets[idxOff] = src->offsets[idxOff - dest->used];
    dest->used = dest->used + src->used;

    return dest;
}

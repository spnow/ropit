#include <stdio.h>
#include <stdlib.h>

#include "offsets.h"

struct ropit_offsets_t* ropit_offsets_new(int nElt) {
    struct ropit_offsets_t *match = calloc(1, sizeof(*match));

    if (!match)
        return NULL;
    match->offsets = calloc(nElt, sizeof(*(match->offsets)));
    if (!match->offsets)
        return NULL;
    match->capacity = nElt;
    match->used = 0;

    return match;
}

struct ropit_offsets_t* ropit_offsets_realloc(struct ropit_offsets_t *ropmatch, int nElt) {
    if (!ropmatch || nElt <= 0)
        return NULL;

    ropmatch->offsets = realloc(ropmatch->offsets, nElt * sizeof(*(ropmatch->offsets)));
    ropmatch->capacity = nElt;
    //
    if (ropmatch->used > nElt)
        ropmatch->used = nElt;

    return ropmatch;
}

void ropit_offsets_destroy(struct ropit_offsets_t **match) {
    if (!match)
        return;
    if (!*match)
        return;

    free((*match)->offsets);
    free(*match);
    *match = NULL;
}

int ropit_offsets_exist(struct ropit_offsets_t *array, int offset) {
    int idx;

    if (!array)
        return 0;

    for (idx = 0; idx < array->used; idx++) {
        if (array->offsets[idx] == offset) {
            return idx + 1;
        }
    }

    return 0;
}

// append 2 offsets_t* struct
struct ropit_offsets_t* offsets_append(struct ropit_offsets_t *dest, struct ropit_offsets_t *src) {
    int idxOff, nElt;

    // check parameters
    if (!dest || !src) {
        fprintf(stderr, "error: offsets_append(): dest or src not set\n");
        return NULL;
    }

    // destination
    fprintf(stdout, "info: before: dest->capacity: %d , dest->used: %d\n", dest->capacity, dest->used);
    dest = ropit_offsets_realloc(dest, dest->used + src->used);
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

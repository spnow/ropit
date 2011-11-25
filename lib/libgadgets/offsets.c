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
    if (!ropmatch)
        return NULL;

    ropmatch->offsets = realloc(ropmatch->offsets, nElt * sizeof(*(ropmatch->offsets)));
    ropmatch->capacity = nElt;

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

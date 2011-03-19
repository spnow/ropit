#include <stdio.h>
#include <stdlib.h>

#include "gadgets_data.h"

struct ropit_offsets_t* ropit_offsets_new(size_t nElt) {
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

struct ropit_offsets_t* ropit_offsets_realloc(struct ropit_offsets_t *ropmatch, size_t nElt) {
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

size_t ropit_offsets_exist(struct ropit_offsets_t *array, int offset) {
    size_t idx;

    if (!array)
        return 0;

    for (idx = 0; idx < array->used; idx++) {
        if (array->offsets[idx] == offset) {
            return idx + 1;
        }
    }

    return 0;
}




struct ropit_gadget_t* ropit_gadget_new(size_t n) {
    struct ropit_gadget_t *gadget;

    gadget = calloc(1, sizeof(*gadget));
    if (!gadget)
        return NULL;

    gadget->gadgets = ropit_offsets_new(n);

    return gadget;
}

struct ropit_gadget_t* ropit_gadget_realloc(struct ropit_gadget_t *gadget, size_t n) {
    if (!gadget)
        return NULL;

    gadget->gadgets = ropit_offsets_realloc(gadget->gadgets, n);

    return gadget;
}

void ropit_gadget_destroy(struct ropit_gadget_t **gadget) {
    if (!gadget)
        return;
    if (!*gadget)
        return;

    ropit_offsets_destroy(&((*gadget)->gadgets));
    free(*gadget);
    *gadget = NULL;
}

struct ropit_gadget_t* ropit_gadget_append (struct ropit_gadget_t *gadgets_list, struct ropit_gadget_t *gadgets) {
    struct ropit_gadget_t *wip;

    //
    if (!gadgets_list || !gadgets)
        return NULL;

    gadgets_list = ropit_gadget_realloc(gadgets_list, gadgets_list->gadgets->used + gadgets->gadgets->used);
    if (!gadgets_list)
        return NULL;

    return gadgets_list;
}



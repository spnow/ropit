#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include "offsets.h"
#include "gadgets_data.h"

struct ropit_gadget_t* ropit_gadget_new(int n) {
    struct ropit_gadget_t *gadget;

    gadget = calloc(1, sizeof(*gadget));
    if (!gadget)
        return NULL;

    gadget->offsets = ropit_offsets_new(n);

    return gadget;
}

struct ropit_gadget_t* ropit_gadget_realloc(struct ropit_gadget_t *gadget, int n) {
    if (!gadget)
        return NULL;

    gadget->offsets = ropit_offsets_realloc(gadget->offsets, n);

    return gadget;
}

void ropit_gadget_destroy(struct ropit_gadget_t **gadget) {
    if (!gadget)
        return;
    if (!*gadget)
        return;

    ropit_offsets_destroy(&((*gadget)->offsets));
    free(*gadget);
    *gadget = NULL;
}

struct ropit_gadget_t* ropit_gadget_append (struct ropit_gadget_t *gadgets_list, struct ropit_gadget_t *gadgets) {
    struct ropit_gadget_t *wip;

    //
    if (!gadgets_list || !gadgets)
        return NULL;

    gadgets_list = ropit_gadget_realloc(gadgets_list, gadgets_list->offsets->used + gadgets->offsets->used);
    if (!gadgets_list)
        return NULL;
    memcpy(gadgets_list->offsets + gadgets_list->offsets->used * sizeof(*(gadgets_list->offsets)),
            gadgets->offsets, gadgets->offsets->used * sizeof(*(gadgets->offsets)));

    return gadgets_list;
}



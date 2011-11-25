#ifndef _GADGETS_DATA_H_
#define _GADGETS_DATA_H_

#include <stdlib.h>

struct ropit_gadget_t {
    // gadgets
    struct ropit_offsets_t *offsets;
    // instructions
    int nInstructions;
};

struct ropit_gadget_t* ropit_gadget_new(int n);
struct ropit_gadget_t* ropit_gadget_realloc(struct ropit_gadget_t *gadget, int n);
void ropit_gadget_destroy(struct ropit_gadget_t **gadget);
struct ropit_gadget_t* ropit_gadget_append (struct ropit_gadget_t *gadgets_list, struct ropit_gadget_t *gadgets);


#endif /* _GADGETS_DATA_H_ */

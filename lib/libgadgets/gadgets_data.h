#ifndef _GADGETS_DATA_H_
#define _GADGETS_DATA_H_

struct ropit_offsets_t {
    int *offsets;
    size_t capacity;
    size_t used;
};

struct ropit_offsets_t* ropit_offsets_new(size_t size);
struct ropit_offsets_t* ropit_offsets_realloc(struct ropit_offsets_t *ropmatch, size_t size);
void ropit_offsets_destroy(struct ropit_offsets_t **match);
size_t ropit_offsets_exist(struct ropit_offsets_t *array, int offset);



struct ropit_gadget_t {
    // gadgets
    struct ropit_offsets_t *gadgets;
    // instructions
    size_t nInstructions;
};

struct ropit_gadget_t* ropit_gadget_new(size_t n);
struct ropit_gadget_t* ropit_gadget_realloc(struct ropit_gadget_t *gadget, size_t n);
void ropit_gadget_destroy(struct ropit_gadget_t **gadget);
struct ropit_gadget_t* ropit_gadget_append (struct ropit_gadget_t *gadgets_list, struct ropit_gadget_t *gadgets);


#endif /* _GADGETS_DATA_H_ */

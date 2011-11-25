#ifndef _OFFSETS_H_
#define _OFFSETS_H_

struct ropit_offsets_t {
    int *offsets;
    int capacity;
    int used;
};

struct ropit_offsets_t* ropit_offsets_new(int size);
struct ropit_offsets_t* ropit_offsets_realloc(struct ropit_offsets_t *ropmatch, int size);
void ropit_offsets_destroy(struct ropit_offsets_t **match);
int ropit_offsets_exist(struct ropit_offsets_t *array, int offset);
int ropit_offsets_remove_dupe(struct ropit_offsets_t *array);

#endif /* _OFFSETS_H_ */

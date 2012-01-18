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
// append 2 offsets_t* struct
struct ropit_offsets_t* offsets_append(struct ropit_offsets_t *dest, struct ropit_offsets_t *src);

#endif /* _OFFSETS_H_ */

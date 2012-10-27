#ifndef _OFFSETS_H_
#define _OFFSETS_H_

#include <stdint.h>

struct offsets_t {
    int64_t *offsets;
    int capacity;
    int used;
};

struct offsets_t* offsets_new(int size);
struct offsets_t* offsets_realloc(struct offsets_t *ropmatch, int size);
void offsets_destroy(struct offsets_t **match);
int offsets_exist(struct offsets_t *array, int offset);
int offsets_remove_dupe(struct offsets_t *array);
// append 2 offsets_t* struct
struct offsets_t* offsets_append(struct offsets_t *dest, struct offsets_t *src);
// append an array to an offsets_t* struct
struct offsets_t* offsets_append_array(struct offsets_t *dest, uint64_t *src, int n);

#endif /* _OFFSETS_H_ */

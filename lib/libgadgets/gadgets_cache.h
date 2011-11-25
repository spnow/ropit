#ifndef _ROPIT_GADGETS_CACHE_H_
#define _ROPIT_GADGETS_CACHE_H_

#include "gadgets.h"

// generic
#define GADGET_CACHE_OK                 0

// about the cache structure
#define ERR_GADGET_CACHE_UNDEFINED      -1
#define ERR_GADGET_CACHE_FULL           -2

// about the cache file
#define ERR_GADGET_CACHE_FILE_UNDEFINED -1
#define ERR_GADGET_CACHE_FILE_INVALID   -2

struct gadget_cache_t {
    // number of gadgets in cache
    int used;
    // cache size
    int capacity;
    //
    struct gadget_t **gadgets;
};

/* cache structure */
// allocate cache
struct gadget_cache_t* gadget_cache_new(int nGadget);
// destroy cache
void gadget_cache_destroy(struct gadget_cache_t **cache);
// add gadget to cache
int gadget_cache_add_gadget(struct gadget_cache_t *cache, struct gadget_t *gadget);
// get element at index
struct gadget_t* gadget_cache_get(struct gadget_cache_t *cache, int index);
// purge cache: just "free" by resetting the used counter
int gadget_cache_reset(struct gadget_cache_t *cache);
// purge cache: "free" and re-init the cache
int gadget_cache_purge(struct gadget_cache_t *cache);
// get number of elements in cache
int gadget_cache_get_size(struct gadget_cache_t *cache);
// get max elements that can be stored in cache
int gadget_cache_get_capacity(struct gadget_cache_t *cache);


/* cache file */
// check cache file validity
int gadget_cache_fcheck(FILE *fp);
// save cache to file
// return number of gadgets written
int gadget_cache_fwrite(FILE *fp, struct gadget_cache_t *cache);
// load file to cache
// return number of gadgets readed
int gadget_cache_fread(FILE *fp, struct gadget_cache_t **cache, int nRead);
// show cache file (it has to respect the file format ... no verification is made so possible crash)
// return number of gadgets showed
int gadget_cache_fshow(FILE *fp);

#endif /* _ROPIT_GADGETS_CACHE_H_ */

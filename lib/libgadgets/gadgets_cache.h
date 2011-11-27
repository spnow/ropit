#ifndef _ROPIT_GADGETS_CACHE_H_
#define _ROPIT_GADGETS_CACHE_H_

#include <pthread.h>
#include <semaphore.h>

#include "gadgets.h"

// generic
#define GADGET_CACHE_OK                 0

// about the cache structure
#define ERR_GADGET_CACHE_UNDEFINED      -1
#define ERR_GADGET_CACHE_FULL           -2

// about the cache file
#define ERR_GADGET_CACHE_FILE_UNDEFINED -1
#define ERR_GADGET_CACHE_FILE_INVALID   -2

// state
#define GADGET_CACHE_STATE_END          1
#define GADGET_CACHE_STATE_FREAD        2
#define GADGET_CACHE_STATE_FWRITE       3

struct gadget_cache_thread_data_t {
};

struct gadget_cache_data_t {
};

struct gadget_cache_t {
    // number of gadgets in cache
    int used;
    // cache size
    int capacity;
    // stored gadgets in cache
    struct gadget_t **gadgets;

    // thread data
    int countGadgets;
    pthread_mutex_t countGadgets_mutex;
    // state: END, FREAD, FWRITE    
    int state;
    // file
    FILE *fp;
    pthread_t fwrite_thread;
    // mutex for file access and thread_cache access (which can be this)
    pthread_mutex_t fwrite_mutex;
    sem_t fwrite_sem;
    struct gadget_cache_t *thread_cache;
};

/* cache structure */
// allocate cache
struct gadget_cache_t* gadget_cache_new(int nGadget);
// allocate gadget cache by copy
struct gadget_cache_t* gadget_cache_new_copy(struct gadget_cache_t *cache);
// destroy cache
void gadget_cache_destroy(struct gadget_cache_t **cache);
// gadget cache copy (both cache must have the same size)
struct gadget_cache_t* gadget_cache_copy(struct gadget_cache_t *dest, struct gadget_cache_t *src);
// add gadget to cache
int gadget_cache_add_gadget(struct gadget_cache_t *cache, struct gadget_t *gadget);
// get element at index
struct gadget_t* gadget_cache_get(struct gadget_cache_t *cache, int index);
// set element at index
struct gadget_t* gadget_cache_set(struct gadget_cache_t *cache, int index, struct gadget_t *gadget);
// zero entirely the cache
int gadget_cache_zero(struct gadget_cache_t *cache);
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
// thread fwrite to augment data througput on multi-core systems
int gadget_cache_fwrite_threaded(FILE *fp, struct gadget_cache_t *cache);
// load file to cache
// return number of gadgets readed
int gadget_cache_fread(FILE *fp, struct gadget_cache_t **cache, int nRead);
// show cache file (it has to respect the file format ... no verification is made so possible crash)
// return number of gadgets showed
int gadget_cache_fshow(FILE *fp);

#endif /* _ROPIT_GADGETS_CACHE_H_ */

#ifndef _ROPIT_GADGETS_CACHE_H_
#define _ROPIT_GADGETS_CACHE_H_

#include <pthread.h>
#include <semaphore.h>

#include <fall4c/fall4c.h>
#include "arch/arch.h"
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

// flags
#define GADGET_CACHE_COLOR              1
#define GADGET_CACHE_STACK              2
#define GADGET_CACHE_LINE               4
#define GADGET_CACHE_BASE               8

struct gadget_cache_t {
    uint64_t base;
    struct cache_t *cache;
};

struct gadget_cache_queue_t {
    struct queue_t *caches;

    // fwrite
    FILE *file;

    // mutex for read and write
    pthread_mutex_t queue_mutex;
    sem_t queue_sem;
};

/* cache queue */
struct gadget_cache_queue_t *gadget_cache_queue_init (struct gadget_cache_queue_t **queue);
struct gadget_cache_queue_t *gadget_cache_queue_add (struct gadget_cache_queue_t *queue, struct cache_t *cache);
int gadget_cache_queue_fwrite_worker (struct gadget_cache_queue_t *queue);
int gadget_cache_queue_set_file (struct gadget_cache_queue_t *queue, void *file);
struct gadget_cache_queue_t *gadget_cache_queue_destroy (struct gadget_cache_queue_t **queue);

/* cache file */
// check cache file validity
int gadget_cache_fcheck(FILE *fp);
// save cache to file
// return number of gadgets written
int gadget_cache_fwrite (FILE *fp, struct cache_t *cache, struct gadget_plugin_t *plugin);
// load file to cache
// return number of gadgets readed
int gadget_cache_fread(FILE *fp, struct cache_t **cache, int nRead);
// show cache file (it has to respect the file format ... no verification is made so possible crash)
// return number of gadgets showed
int gadget_cache_fshow (FILE *fp_in, FILE *fp_out, int flags);

#endif /* _ROPIT_GADGETS_CACHE_H_ */

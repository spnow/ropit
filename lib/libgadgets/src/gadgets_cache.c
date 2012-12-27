#include <stdlib.h>
#include <stdio.h>

// threading
#include <pthread.h>
#include <semaphore.h>
#include <fall4c/fall4c.h>

#include "byte-order.h"
#include "gadgets.h"
#include "gadgets_cache.h"

/* cache file */

// check cache file validity
int gadget_cache_fcheck (FILE *fp)
{
    // boolean for file validity
    int check;
    // base address of file
    uint64_t base;
    // diverse values
    int fsize; // file size in bytes
    // cache
    struct gadget_t host = {0}, file = {0};

    // check parameters
    if (!fp)
        return ERR_GADGET_CACHE_FILE_UNDEFINED;

    // get file size
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    if (fsize <= 0)
        return 0;
    // rewind
    fseek(fp, 0, SEEK_SET);

    // assume file as valid (until it fail one of the following tests)
    check = GADGET_CACHE_OK;

    // get base address
    fread(&base, sizeof(base), 1, fp);
    base = file_to_host_order_by_size(base, sizeof(base));
    // check for fp error or end-of-file
    if (ferror(fp) || feof(fp))
        check = ERR_GADGET_CACHE_FILE_INVALID;

    while (!feof(fp) && !ferror(fp) && check == GADGET_CACHE_OK) {
        // address
        fread(&(file.address), sizeof(file.address), 1, fp);
        host.address = file_to_host_order_by_size(file.address, sizeof(file.address));
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;

        // bytes
        fread(&(file.len_bytes), sizeof(file.len_bytes), 1, fp);
        host.len_bytes = file_to_host_order_by_size(file.len_bytes, sizeof(file.len_bytes));
        if (host.len_bytes >= fsize) {
            check = ERR_GADGET_CACHE_FILE_INVALID;
            break;
        }
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;
        // ignore bytes
        fseek(fp, host.len_bytes, SEEK_CUR);

        // repr
        fread(&(file.len_repr), sizeof(file.len_repr), 1, fp);
        host.len_repr = file_to_host_order_by_size(file.len_repr, sizeof(file.len_repr));
        if (host.len_repr >= fsize) {
            check = ERR_GADGET_CACHE_FILE_INVALID;
            break;
        }
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;
        fseek(fp, host.len_repr, SEEK_CUR);

        if (host.len_bytes == 0 && host.len_repr == 0)
            break;
    }

    return check != ERR_GADGET_CACHE_FILE_INVALID ? 1 : 0;
}

// save cache to file
// return number of gadgets written
int gadget_cache_fwrite (FILE *fp, struct cache_t *cache)
{
    int idx_cache, countGadgets;
    struct gadget_t *cached, file;
    int16_t sz_buf;

    //
    if (!fp || !cache)
        return ERR_GADGET_CACHE_UNDEFINED;

    // go through the cache
#ifdef _DEBUG
    printf("write cache file\n");
#endif
    for (idx_cache = countGadgets = 0; idx_cache < cache_get_size(cache); idx_cache++) {
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;
        // get a cached element
        cached = cache_get(cache, idx_cache);
        if (!cached)
            continue;
        countGadgets++;
        // write to cache file in big endian (so it is portable accross platform :))
        // write address
        file.address = host_to_file_order_by_size(cached->address, sizeof(cached->address));
        fwrite(&file.address, sizeof(cached->address), 1, fp);
        // write bytes
        sz_buf = cached->len_bytes;
        if (cached->bytes == NULL || sz_buf < 0)
            sz_buf = 0;
        if (sz_buf > 0)
            sz_buf += 1;
        file.len_bytes = host_to_file_order_by_size(sz_buf, sizeof(file.len_bytes));
        fwrite(&(file.len_bytes), sizeof(file.len_bytes), 1, fp);
        if (sz_buf > 0)
            fwrite(cached->bytes, sizeof(*cached->bytes), sz_buf, fp);
#ifdef _DEBUG
        printf("len_bytes: %d - %x\n", cached->len_bytes, cached->len_bytes);
#endif
        // write repr
        sz_buf = cached->len_repr;
        if (cached->repr == NULL || sz_buf < 0)
            sz_buf = 0;
        if (sz_buf > 0)
            sz_buf += 1;
        file.len_repr = host_to_file_order_by_size(sz_buf, sizeof(file.len_repr));
        fwrite(&file.len_repr, sizeof(file.len_repr), 1, fp);
        if (sz_buf > 0)
            fwrite(cached->repr, sizeof(*cached->repr), sz_buf, fp);
#ifdef _DEBUG
        printf("len_repr: %d - %x\n\n", cached->len_repr, cached->len_repr);
#endif
    }

    return countGadgets;
}

// load file to cache
// return number of gadgets readed
int gadget_cache_fread (FILE *fp, struct cache_t **cache, int n_read)
{
    int idx_cache, countGadgets, bRead;
    struct gadget_t *cached, *gadget;

    if (!fp || !cache || n_read <= 0)
        return ERR_GADGET_CACHE_UNDEFINED;

    // cache
    if (!*cache) {
        *cache = cache_new(n_read);
        if (!*cache) {
            return 0;
        }

        // allocate gadget array
        for (idx_cache = 0; idx_cache < cache_get_capacity(*cache); idx_cache++) {
            gadget = gadget_new();
            if (cache_add(*cache, gadget) != GADGET_CACHE_OK)
                gadget_destroy(&gadget);
        }
    }

    // go through the cache
#ifdef _DEBUG
    printf("read cache file\n");
#endif
    for (idx_cache = countGadgets = 0; idx_cache < cache_get_size(*cache); idx_cache++) {
        // check for fp error or end-of-file
        if (feof(fp) || ferror(fp))
            break;
        // get a cached element
        cached = cache_get(*cache, idx_cache);
        if (!cached)
            continue;
        countGadgets++;
        // read from cache file       These  functions should not fail and do not set the external variable errno.  (However, in case fileno() detects that its argument
        // read address
#ifdef _DEBUG
        printf("sizeof(address): %lu\n", sizeof(cached->address));
#endif
        bRead = fread(&(cached->address), sizeof(cached->address), 1, fp);
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;
        cached->address = file_to_host_order_by_size(cached->address, sizeof(cached->address));
#ifdef _DEBUG
        printf("address: %p - bRead: %d\n", cached->address, bRead);
        printf("ftell(fp): %d\n", ftell(fp));
        printf("---------\n");
        // read bytes
        printf("sizeof(len_bytes): %lu\n", sizeof(cached->len_bytes));
#endif
        bRead = fread(&(cached->len_bytes), sizeof(cached->len_bytes), 1, fp);
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;
        cached->len_bytes = file_to_host_order_by_size((uint16_t)cached->len_bytes, sizeof(cached->len_bytes));
#ifdef _DEBUG
        printf("len_bytes: %d - %x\n", cached->len_bytes, cached->len_bytes);
        printf("bRead: %d\n", bRead);
        printf("---------\n");
        bRead = 0;
#endif
        if (cached->len_bytes) {
            cached->bytes = realloc(cached->bytes, cached->len_bytes * sizeof(*cached->bytes));
            bRead = fread(cached->bytes, sizeof(*cached->bytes), cached->len_bytes, fp);
            // check for fp error or end-of-file
            if (ferror(fp) || feof(fp))
                break;
        }
#ifdef _DEBUG
        printf("bRead: %d\n", bRead);
        printf("ftell(fp): %d\n", ftell(fp));
        printf("---------\n");
        // read repr
        printf("sizeof(len_repr): %lu\n", sizeof(cached->len_repr));
#endif
        bRead = fread(&(cached->len_repr), sizeof(cached->len_repr), 1, fp);
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;
        cached->len_repr = file_to_host_order_by_size((uint16_t)cached->len_repr, sizeof(cached->len_repr));
#ifdef _DEBUG
        printf("len_repr: %d - %x\n", cached->len_repr, cached->len_repr);
        printf("bRead: %d\n", bRead);
        printf("---------\n");
        bRead = 0;
#endif
        if (cached->len_repr) {
            cached->repr = realloc(cached->repr, cached->len_repr * sizeof(*cached->repr));
            bRead = fread(cached->repr, sizeof(*cached->repr), cached->len_repr, fp);
            // check for fp error or end-of-file
            if (ferror(fp) || feof(fp))
                break;
        }
#ifdef _DEBUG
        printf("bRead: %d\n", bRead);
        printf("ftell(fp): %d\n\n", ftell(fp));
#endif
    }

    return countGadgets;
}

// show cache file
// return number of gadgets showed
int gadget_cache_fshow (FILE *fp)
{
    int idx_cache, countGadgets;
    struct cache_t *cache = NULL;
    struct gadget_t *cached;
    // base address
    uint64_t base;

    if (!fp) {
        fprintf(stderr, "gadget_cache_file_fshow(): Cache file was undefined\n");
        return ERR_GADGET_CACHE_FILE_UNDEFINED;
    }

    // if file is not valid
    // then do not do anything else
    if (gadget_cache_fcheck(fp) == 0) {
        fprintf(stderr, "gadget_cache_file_fshow(): Cache file is invalid\n");
        return ERR_GADGET_CACHE_FILE_INVALID;
    }

    // rewind
    fseek(fp, 0, SEEK_SET);

    // get base address
    fread(&base, sizeof(base), 1, fp);
    base = file_to_host_order_by_size(base, sizeof(base));
    printf("base address: 0x%08llx\n", base);

    countGadgets = 0;
    while (gadget_cache_fread(fp, &cache, 1024) != 0) {
        for (idx_cache = 0; idx_cache < cache_get_size(cache); idx_cache++) {
            cached = cache_get(cache, idx_cache);
            if (!cached || cached->repr == NULL)
                continue;
            printf("0x%08llx : %s\n", base + cached->address, cached->repr);

            countGadgets++;
        }
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;
    }

    // cache_destroy(&cache);

    return countGadgets;
}

struct gadget_cache_queue_t *gadget_cache_queue_init (struct gadget_cache_queue_t **queue)
{
    int retcode;

    if (!queue) {
        fprintf (stderr, "gadget_cache_queue_init (): Bad parameter\n");
        return NULL;
    }

    // init semaphore
    retcode = sem_init(&(*queue)->queue_sem, 0, 0);
    if (retcode != 0) {
        fprintf (stderr, "error: gadget_cache_queue_init(): queue semaphore init failed\n");
        return NULL;
    }

    // init mutexes
    retcode = pthread_mutex_init(&(*queue)->queue_mutex, NULL);
    if (retcode != 0) {
        fprintf (stderr, "error: gadget_cache_queue_init(): queue mutex init failed\n");
        return NULL;
    }

    // init queue caches
    (*queue)->caches = NULL;

    return (*queue);
}

struct gadget_cache_queue_t *gadget_cache_queue_add (struct gadget_cache_queue_t *queue, struct cache_t *cache)
{
    int retcode;

    retcode = queue_push (&queue->caches, cache);
    if (retcode)
        return NULL;
    
    // there is data to be consumed!
    sem_post (&queue->queue_sem);

    return queue;
}

// thread function
int gadget_cache_queue_fwrite_worker (struct gadget_cache_queue_t *queue)
{
    struct cache_t *cache;

    if (!queue) {
        return NULL;
    }

    if (!queue->file) {
        return NULL;
    }

    // there is data to be consumed!
    sem_wait (&queue->queue_sem);

    cache = queue_pop (&queue->caches);
    if (!cache)
        return -1;

    gadget_cache_fwrite (queue->file, cache);

    return 0;
}

int gadget_cache_queue_set_file (struct gadget_cache_queue_t *queue, void *file)
{
    if (!queue || !file)
        return -1;
    
    queue->file = file;

    return 0;
}

struct gadget_cache_queue_t *gadget_cache_queue_destroy (struct gadget_cache_queue_t **queue)
{
    // destroy mutex
    pthread_mutex_destroy (&(*queue)->queue_mutex);
    // destroy semaphore
    sem_destroy (&(*queue)->queue_sem);
    free (*queue);
    *queue = NULL;
}


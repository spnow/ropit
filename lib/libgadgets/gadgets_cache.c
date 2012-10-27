#include <stdlib.h>
#include <stdio.h>

// threading
#include <pthread.h>
#include <semaphore.h>

#include "byte-order.h"
#include "gadgets.h"
#include "gadgets_cache.h"

/* thread cache */
// allocate gadget cache thread local storage
struct gadget_cache_t* _gadget_cache_new_thread_data(struct gadget_cache_t *cache);
// destroy gadget cache thread local storage
void _gadget_cache_destroy_thread_data(struct gadget_cache_t *cache);
struct gadget_cache_t* _gadget_cache_new(int n_gadget);

// fwrite thread callback
void *gadget_cache_fwrite_thread(void *data);

/* thread cache */
// allocate gadget cache thread local storage
struct gadget_cache_t* _gadget_cache_new_thread_data(struct gadget_cache_t *cache) {
    int retcode;
    struct gadget_cache_t *thread_lcache;

    // check parameter
    if (!cache) {
        fprintf(stderr, "_gadget_cache_new_thread_data(): error: cache does not exist\n");
        return NULL;
    }

    // alloc copy
    fprintf(stderr, "Copying cache\n");
    thread_lcache = gadget_cache_new_copy(cache);
    if (!thread_lcache) {
        fprintf(stderr, "_gadget_cache_new_thread_data(): error: local cache failed allocation\n");
        return NULL;
    }
    // thread lcache data
    thread_lcache->fp = cache->fp;
    thread_lcache->thread_cache = thread_lcache;    // point to itself
    // set cache
    cache->thread_cache = thread_lcache;

    // init mutexes
    retcode = pthread_mutex_init(&thread_lcache->fwrite_mutex, NULL);
    if (retcode != 0) {
        fprintf(stderr, "_gadget_cache_new_thread_data(): error: fwrite_mutex init failed\n");
        return NULL;
    }

    // init mutexes
    retcode = pthread_mutex_init(&thread_lcache->countGadgets_mutex, NULL);
    if (retcode != 0) {
        fprintf(stderr, "_gadget_cache_new_thread_data(): error: countGadgets mutex init failed\n");
        return NULL;
    }

    // init semaphore
    retcode = sem_init(&thread_lcache->fwrite_sem, 0, 0);
    if (retcode != 0) {
        fprintf(stderr, "_gadget_cache_new_thread_data(): error: fwrite semaphore init failed\n");
        return NULL;
    }

    // create thead
    fprintf(stderr, "Creating thread\n");
    retcode = pthread_create(&thread_lcache->fwrite_thread, NULL, gadget_cache_fwrite_thread, (void *)thread_lcache);
    if (retcode != 0) {
        fprintf(stderr, "_gadget_cache_new_thread_data(): error: fwrite thread creation failed\n");
        return NULL;
    }
    fprintf(stderr, "Thread created\n");

    return cache;
}

// destroy gadget cache thread local storage
void _gadget_cache_destroy_thread_data(struct gadget_cache_t *gcache) {
    struct gadget_cache_t *thread_lcache;
    // check parameters
    if (!gcache) {
        fprintf(stderr, "_gadget_cache_destroy_thread_data(): error: gcache does not exist\n");
        return;
    }
    thread_lcache = gcache->thread_cache;
    if (!thread_lcache) {
        fprintf(stderr, "_gadget_cache_destroy_thread_data(): error : No thread local cache\n");
        return;
    }

    // ensure we are not writing to file
    pthread_mutex_lock(&thread_lcache->fwrite_mutex);
    fprintf(stderr, "_gadget_cache_destroy_thread_data(): warning: Destroying thread local cache\n");

    // trigger thread exit
    //thread_lcache->state = GADGET_CACHE_STATE_END;
    sem_post(&thread_lcache->fwrite_sem);

    // unlock it (avoid deadlock)
    pthread_mutex_unlock(&thread_lcache->fwrite_mutex);

    // wait for thread completion
    pthread_join(thread_lcache->fwrite_thread, NULL);

    // destroy mutex
    pthread_mutex_destroy(&thread_lcache->fwrite_mutex);
    // destroy semaphore
    sem_destroy(&thread_lcache->fwrite_sem);

    // destroy cache
    _gadget_cache_destroy(&gcache->thread_cache);
}

/* cache structure */

// allocate cache
struct gadget_cache_t* gadget_cache_new(int n_gadget) {
    struct gadget_cache_t *cache;

    if (n_gadget <= 0)
        return NULL;

    cache = _gadget_cache_new(n_gadget);
    if (!cache)
        return NULL;

    // create local thread storage
    cache->thread_cache = _gadget_cache_new_thread_data(cache);
    if (!cache->thread_cache) {
        fprintf(stderr, "error: gadget_cache_new(): cache copy failed\n");
        return ERR_GADGET_CACHE_UNDEFINED;
    }

    return cache;
}

struct gadget_cache_t* _gadget_cache_new(int n_gadget) {
    struct gadget_cache_t *cache;

    if (n_gadget <= 0)
        return NULL;

    cache = calloc(sizeof(*cache), 1);
    if (!cache)
        return NULL;

    cache->gadgets = calloc(sizeof(*cache->gadgets), n_gadget);
    if (!cache->gadgets) {
        free(cache);
        return NULL;
    }

    cache->capacity = n_gadget;

    return cache;
}

// allocate gadget cache by copy
struct gadget_cache_t* gadget_cache_new_copy(struct gadget_cache_t *cache) {
    struct gadget_cache_t *copy, *res;

    // allocate copy
    copy = _gadget_cache_new(gadget_cache_get_capacity(cache));
    // make copy
    res = gadget_cache_copy(copy, cache);
    if (res == NULL)
        gadget_cache_destroy(&copy);

    return copy;
}

// destroy cache
void _gadget_cache_destroy(struct gadget_cache_t **cache) {
    // check parameters
    if (!cache || !*cache)
        return;

    // destroy gadget cache
    gadget_cache_purge(*cache);
    free((*cache)->gadgets);
    free(*cache);
    *cache = NULL;
}

// destroy cache
void gadget_cache_destroy(struct gadget_cache_t **cache) {
    // check parameters
    if (!cache || !*cache)
        return;

    // destroy thread local cache
    _gadget_cache_destroy_thread_data(cache);

    // destroy cache
    _gadget_cache_destroy(cache);
}

// gadget cache copy (both cache must have the same size)
struct gadget_cache_t* gadget_cache_copy(struct gadget_cache_t *dest, struct gadget_cache_t *src) {
    int idx_cache;
    int capDest, capSrc;
    struct gadget_t *copied, *cached;

    // check parameters
    if ((!dest || !src) && src == dest) {
        fprintf(stderr, "error: gadget_cache_copy(): Bad parameters\n");
        return NULL;
    }

    // cache must be of same sizes
    capDest = gadget_cache_get_capacity(dest);
    capSrc = gadget_cache_get_capacity(src);
    if (capDest != capSrc) {
        fprintf(stderr, "error: gadget_cache_copy(): dest and src are not of the same size\n");
        return NULL;
    }

    // copy cache
    dest->used = src->used;
    for (idx_cache = 0; idx_cache < gadget_cache_get_size(src); idx_cache++) {
        // get elements
        cached = gadget_cache_get(src, idx_cache);
        copied = gadget_cache_get(dest, idx_cache);

        //
        if (copied == NULL && cached != NULL)
            copied = gadget_new_copy(cached);
        else if (copied && cached)
            gadget_copy(copied, cached);

        // copying
        gadget_cache_set(dest, idx_cache, copied);
    }

    return dest;
}

//

// add gadget to cache
int gadget_cache_add_gadget(struct gadget_cache_t *cache, struct gadget_t *gadget) {
    // check parameters
    if (!cache || !gadget) {
        printf("gadget_cache_add_gadget(): cache does not exist\n");
        return ERR_GADGET_CACHE_UNDEFINED;
    }

    // re-adjust used if inferior of equal to 0
    cache->used = (cache->used <= 0) ? 0 : cache->used;

    // if cache full
    if (cache->used >= cache->capacity) {
        // re-adjust used so it never goes above capacity
        cache->used = (cache->used > cache->capacity) ? cache->capacity : cache->used;
        return ERR_GADGET_CACHE_FULL;
    }

    // add to cache
    if (gadget_cache_set(cache, cache->used, gadget) != NULL)
        cache->used++;

    return GADGET_CACHE_OK;
}

// get element at index
struct gadget_t* gadget_cache_get(struct gadget_cache_t *cache, int index) {
    if (!cache)
        return NULL;

    if (index < 0 || index >= cache->used || index >= cache->capacity)
        return NULL;

    return cache->gadgets[index];
}

// set element at index
struct gadget_t* gadget_cache_set(struct gadget_cache_t *cache, int index, struct gadget_t *gadget) {
    if (!cache)
        return NULL;

    if (index < 0 || index >= cache->capacity)
        return NULL;

    cache->gadgets[index] = gadget;

    return gadget;
}

// zero entirely the cache
int gadget_cache_zero(struct gadget_cache_t *cache) {
    int idx_gadget;

    // check parameters
    if (!cache)
        return ERR_GADGET_CACHE_UNDEFINED;

    // reset cache (heavy one)
    for (idx_gadget = 0; idx_gadget < gadget_cache_get_capacity(cache); idx_gadget++)
        gadget_cache_set(cache, idx_gadget, NULL);

    // reset used counter
    cache->used = 0;

    return GADGET_CACHE_OK;
}

// purge cache: just "free" by resetting the used counter
int gadget_cache_reset(struct gadget_cache_t *cache) {
    int idx_gadget;

    // check parameters
    if (!cache)
        return ERR_GADGET_CACHE_UNDEFINED;

    // just reset the used counter :) (we overwrite over it)
    cache->used = 0;

    return GADGET_CACHE_OK;
}

// purge cache: "free" and re-init the cache
int gadget_cache_purge(struct gadget_cache_t *cache) {
    int idx_gadget;

    // check parameters
    if (!cache)
        return ERR_GADGET_CACHE_UNDEFINED;

    // reinit whole cache
    for (idx_gadget = 0; idx_gadget < gadget_cache_get_capacity(cache); idx_gadget++) {
        gadget_destroy(&(cache->gadgets[idx_gadget]));
        gadget_cache_set(cache, idx_gadget, NULL);
    }

    // reset the used counter
    cache->used = 0;

    return GADGET_CACHE_OK;
}

// get number of elements in cache
int gadget_cache_get_size(struct gadget_cache_t *cache) {
    // bye
    if (!cache) {
        fprintf(stderr, "gadget_cache_get_size(): cache is NULL\n");
        return ERR_GADGET_CACHE_UNDEFINED;
    }

    if (cache->used < 0)
        cache->used = 0;
    if (cache->used > cache->capacity)
        return cache->capacity;

    return cache->used;
}

// get max elements that can be stored in cache
int gadget_cache_get_capacity(struct gadget_cache_t *cache) {
    // bye
    if (!cache) {
        fprintf(stderr, "gadget_cache_get_capacity(): cache is NULL\n");
        return ERR_GADGET_CACHE_UNDEFINED;
    }

    return cache->capacity;
}


/* cache file */

// check cache file validity
int gadget_cache_fcheck(FILE *fp) {
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
int gadget_cache_fwrite(FILE *fp, struct gadget_cache_t *cache) {
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
    for (idx_cache = countGadgets = 0; idx_cache < gadget_cache_get_size(cache); idx_cache++) {
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;
        // get a cached element
        cached = gadget_cache_get(cache, idx_cache);
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

// fwrite thread
void *gadget_cache_fwrite_thread(void *data) {
    struct gadget_cache_t *cache = data;
    struct gadget_cache_t *thread_lcache;

    // if no data
    if (!cache)
        return NULL;
    thread_lcache = cache->thread_cache;

    while (thread_lcache && thread_lcache->state != GADGET_CACHE_STATE_END) {
        // waiting for available data
        sem_wait(&thread_lcache->fwrite_sem);

        // write to file
        fprintf(stderr, "gadget_cache_fwrite_thread(): Trying to get lock\n");
        pthread_mutex_lock(&thread_lcache->fwrite_mutex);

        // check for state
        fprintf(stderr, "gadget_cache_fwrite_thread(): Checking for state\n");
        if (thread_lcache->state == GADGET_CACHE_STATE_END
                && gadget_cache_get_size(thread_lcache) == 0) {
            fprintf(stderr, "gadget_cache_fwrite_thread(): no local storage or thread ended\n");
            pthread_mutex_unlock(&thread_lcache->fwrite_mutex);
            break;
        }

        // write to file
        fprintf(stderr, "gadget_cache_fwrite_thread(): Local cache size: %d\n", gadget_cache_get_size(thread_lcache));
        thread_lcache->countGadgets += gadget_cache_fwrite(thread_lcache->fp, thread_lcache);
        gadget_cache_reset(thread_lcache);
        // finished writing to file
        pthread_mutex_unlock(&thread_lcache->fwrite_mutex);
    }
    pthread_exit(NULL);

    return NULL;
}

// thread fwrite to augment data througput on multi-core systems
int gadget_cache_fwrite_threaded(FILE *fp, struct gadget_cache_t *cache) {
    int retcode;
    // 
    struct gadget_cache_t *local_cache;

    // check parameters
    if (!fp || !cache) {
        fprintf(stderr, "error: gadget_cache_fwrite_threaded(): invalid parameters\n");
        return ERR_GADGET_CACHE_UNDEFINED;
    }

    // get local thread cache
    local_cache = cache->thread_cache;
    if (!local_cache) {
        fprintf(stderr, "error: gadget_cache_fwrite_threaded(): local_cache does not exist\n");
        return ERR_GADGET_CACHE_UNDEFINED;
    }

    // ensure we are not writing to file yet
    pthread_mutex_lock(&local_cache->fwrite_mutex);

    // file pointer
    local_cache->fp = fp;

    // make copy of cache
    if (gadget_cache_copy(local_cache, cache) == NULL) {
        fprintf(stderr, "Failed copying to thread local cache\n");
        gadget_cache_reset(local_cache);
    }
    else {
        sem_post(&local_cache->fwrite_sem);
        fprintf(stderr, "warning: gadget_cache_fwrite_threaded(): Emptying cache\n");
        fprintf(stderr, "warning: gadget_cache_fwrite_threaded(): Cache size: %d\n", gadget_cache_get_size(cache));
        fprintf(stderr, "warning: gadget_cache_fwrite_threaded(): Local cache size: %d\n", gadget_cache_get_size(local_cache));
    }

    // finished copying data
    pthread_mutex_unlock(&local_cache->fwrite_mutex);

    return local_cache->countGadgets;
}

// load file to cache
// return number of gadgets readed
int gadget_cache_fread(FILE *fp, struct gadget_cache_t **cache, int n_read) {
    int idx_cache, countGadgets, bRead;
    struct gadget_t *cached, *gadget;

    if (!fp || !cache || n_read <= 0)
        return ERR_GADGET_CACHE_UNDEFINED;

    // cache
    if (!*cache) {
        *cache = gadget_cache_new(n_read);
        if (!*cache) {
            return 0;
        }

        // allocate gadget array
        for (idx_cache = 0; idx_cache < gadget_cache_get_capacity(*cache); idx_cache++) {
            gadget = gadget_new();
            if (gadget_cache_add_gadget(*cache, gadget) != GADGET_CACHE_OK)
                gadget_destroy(&gadget);
        }
    }

    // go through the cache
#ifdef _DEBUG
    printf("read cache file\n");
#endif
    for (idx_cache = countGadgets = 0; idx_cache < gadget_cache_get_size(*cache); idx_cache++) {
        // check for fp error or end-of-file
        if (feof(fp) || ferror(fp))
            break;
        // get a cached element
        cached = gadget_cache_get(*cache, idx_cache);
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
int gadget_cache_fshow(FILE *fp) {
    int idx_cache, countGadgets;
    struct gadget_cache_t *cache = NULL;
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
        for (idx_cache = 0; idx_cache < gadget_cache_get_size(cache); idx_cache++) {
            cached = gadget_cache_get(cache, idx_cache);
            if (!cached || cached->repr == NULL)
                continue;
            printf("0x%08llx : %s\n", base + cached->address, cached->repr);

            countGadgets++;
        }
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;
    }

    // gadget_cache_destroy(&cache);

    return countGadgets;
}


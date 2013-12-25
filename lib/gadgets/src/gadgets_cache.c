#include <stdlib.h>
#include <stdio.h>

// threading
#include <pthread.h>
#include <semaphore.h>
#include <fall4c/fall4c.h>

#include "arch/arch.h"
#include "arch/x86/gadget_output.h"
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
    //
    int chr;
    int sz_read;

    // check parameters
    if (!fp)
        return ERR_GADGET_CACHE_FILE_UNDEFINED;

    // get file size
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    if (fsize <= 0) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fcheck(): fsize is NULL\n");
        return 0;
    }
    // rewind
    fseek(fp, 0, SEEK_SET);

    // assume file as valid (until it fail one of the following tests)
    check = GADGET_CACHE_OK;

    // get base address
    fread(&base, sizeof(base), 1, fp);
    base = file_to_host_order_by_size(base, sizeof(base));
    // check for fp error or end-of-file
    if (ferror(fp) || feof(fp)) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fcheck(): Failed reading base address\n");
        check = ERR_GADGET_CACHE_FILE_INVALID;
    }

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
            debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fcheck(): len_bytes > fsize\n");
            check = ERR_GADGET_CACHE_FILE_INVALID;
            break;
        }
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;
        // ignore bytes
        fseek(fp, host.len_bytes, SEEK_CUR);

        // repr
        /*
        fread(&(file.len_repr), sizeof(file.len_repr), 1, fp);
        host.len_repr = file_to_host_order_by_size(file.len_repr, sizeof(file.len_repr));
        if (host.len_repr >= fsize) {
            debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fcheck(): len_repr > fsize\n");
            check = ERR_GADGET_CACHE_FILE_INVALID;
            break;
        }
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;

        // check for repr length
        sz_read = 0;
        while (fread(&chr, 1, 1, fp)) {
            ++sz_read;
            if (isprint(chr & 0xff) == 0)
                break;
        }
        if (host.len_repr != sz_read) {
            debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fcheck(): Failed at offset %d, strlen(repr) != len_repr, %d != %d\n", ftell(fp), sz_read, host.len_repr);
            check = ERR_GADGET_CACHE_FILE_INVALID;
            break;
        }
        //*/
    }

    return check != ERR_GADGET_CACHE_FILE_INVALID ? 1 : 0;
}

// save cache to file
// return number of gadgets written
int gadget_cache_fwrite (FILE *fp, struct cache_t *cache, struct gadget_plugin_t *plugin)
{
    int idx_cache, count_gadgets;
    struct gadget_t *cached, file;
    uint64_t base;
    int16_t sz_buf;
    static int base_written = 0;

    //
    if (!plugin || !fp || !cache) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fwrite(): Bad parameter(s)\n");
        return ERR_GADGET_CACHE_UNDEFINED;
    }

    // write base address
    if (base_written == 0) {
        base = plugin->base_addr;
        base = file_to_host_order_by_size(base, sizeof(base));
        fwrite(&base, sizeof(base), 1, fp);
        base_written = 1;
    }

    // go through the cache
#ifdef _DEBUG
    printf("write cache file\n");
#endif
    for (idx_cache = count_gadgets = 0; idx_cache < cache_get_size(cache); idx_cache++) {
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp)) {
            debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fwrite(): fp error\n");
            break;
        }
        // get a cached element
        cached = cache_get(cache, idx_cache);
        if (!cached) {
            debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fwrite(): cache is NULL\n");
            continue;
        }
        count_gadgets++;

        // write to cache file in big endian (so it is portable accross platform :))
        // write address
        file.address = host_to_file_order_by_size(cached->address, sizeof(cached->address));
        fwrite(&file.address, sizeof(file.address), 1, fp);

        // write bytes
        sz_buf = cached->len_bytes;
        if (cached->bytes == NULL || sz_buf < 0)
            sz_buf = 0;
        file.len_bytes = host_to_file_order_by_size(sz_buf, sizeof(file.len_bytes));
        fwrite(&(file.len_bytes), sizeof(file.len_bytes), 1, fp);
        if (sz_buf > 0)
            fwrite(cached->bytes, sizeof(*cached->bytes), sz_buf, fp);
#ifdef _DEBUG
        printf("len_bytes: %d - %x\n", cached->len_bytes, cached->len_bytes);
#endif
        // write repr
        /*
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
        //*/
    }

    return count_gadgets;
}

// load file to cache
// return number of gadgets readed
int gadget_cache_fread (FILE *fp, struct cache_t **cache, int n_read)
{
    int idx_cache, count_gadgets, bRead;
    struct gadget_t *cached, *gadget;

    if (!fp || !cache || n_read <= 0) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fread(): Cache is undefined\n");
        return ERR_GADGET_CACHE_UNDEFINED;
    }

    // cache
    if (!*cache) {
        *cache = cache_new(n_read);
        if (!*cache) {
            debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fread(): Cache failed alloc\n");
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
    for (idx_cache = count_gadgets = 0; idx_cache < cache_get_size(*cache); idx_cache++) {
        // check for fp error or end-of-file
        if (feof(fp) || ferror(fp)) {
            debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fread(): EOL\n");
            break;
        }
        // get a cached element
        cached = cache_get(*cache, idx_cache);
        if (!cached) {
            debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fread(): Failed getting cached gadget\n");
            continue;
        }
        count_gadgets++;
        // read from cache file       These  functions should not fail and do not set the external variable errno.  (However, in case fileno() detects that its argument
        // read address
#ifdef _DEBUG
        printf("sizeof(address): %lu\n", sizeof(cached->address));
#endif
        bRead = fread(&(cached->address), sizeof(cached->address), 1, fp);
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp)) {
            debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fread(): Failed reading address\n");
            break;
        }
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
        if (ferror(fp) || feof(fp)) {
            debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fread(): Failed reading len_bytes\n");
            break;
        }
        cached->len_bytes = file_to_host_order_by_size((uint16_t)cached->len_bytes, sizeof(cached->len_bytes));
#ifdef _DEBUG
        printf("len_bytes: %d - %x\n", cached->len_bytes, cached->len_bytes);
        printf("bRead: %d\n", bRead);
        printf("---------\n");
        bRead = 0;
#endif
        if (cached->len_bytes > 0) {
            cached->bytes = realloc(cached->bytes, cached->len_bytes * sizeof(*cached->bytes));
            bRead = fread(cached->bytes, sizeof(*cached->bytes), cached->len_bytes, fp);
            // check for fp error or end-of-file
            if (ferror(fp) || feof(fp)) {
                debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fread(): Failed reading bytes\n");
                break;
            }
        }
#ifdef _DEBUG
        printf("bRead: %d\n", bRead);
        printf("ftell(fp): %d\n", ftell(fp));
        printf("---------\n");

        // read repr
        printf("sizeof(len_repr): %lu\n", sizeof(cached->len_repr));
#endif
        /*
        bRead = fread(&(cached->len_repr), sizeof(cached->len_repr), 1, fp);
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp)) {
            debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fread(): Failed reading len repr\n");
            break;
        }
        cached->len_repr = file_to_host_order_by_size((uint16_t)cached->len_repr, sizeof(cached->len_repr));
#ifdef _DEBUG
        printf("len_repr: %d - %x\n", cached->len_repr, cached->len_repr);
        printf("bRead: %d\n", bRead);
        printf("---------\n");
        bRead = 0;
#endif
        if (cached->len_repr > 0) {
            cached->repr = realloc(cached->repr, cached->len_repr * sizeof(*cached->repr));
            bRead = fread(cached->repr, sizeof(*cached->repr), cached->len_repr, fp);
            // check for fp error or end-of-file
            if (ferror(fp) || feof(fp)) {
                debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fread(): Failed reading repr\n");
                gadget_show(cached);
                break;
            }
        }
#ifdef _DEBUG
        printf("bRead: %d\n", bRead);
        printf("ftell(fp): %d\n\n", ftell(fp));
#endif
        //*/
    }

    return count_gadgets;
}

// show cache file
// return number of gadgets showed
int gadget_cache_fshow (FILE *fp_in, FILE *fp_out, int flags)
{
    int idx_cache, count_gadgets;
    struct cache_t *cache;
    struct gadget_t *cached;
    // base address
    uint64_t base;
    int retcode;

    if (!fp_in || !fp_out) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_file_fshow(): Bad parameter(s)\n");
        return ERR_GADGET_CACHE_FILE_UNDEFINED;
    }

    // if file is not valid
    // then do not do anything else
    if (gadget_cache_fcheck(fp_in) == 0) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_file_fshow(): Cache file is invalid\n");
        return ERR_GADGET_CACHE_FILE_INVALID;
    }

    if ((flags & GADGET_CACHE_STACK) == 0)
        flags |= GADGET_CACHE_LINE;

    // rewind
    fseek(fp_in, 0, SEEK_SET);

    // get base address
    fread(&base, sizeof(base), 1, fp_in);
    base = file_to_host_order_by_size(base, sizeof(base));
    printf("base address: 0x%08llx\n", base);

    count_gadgets = 0;
    cache = NULL;
    while (gadget_cache_fread(fp_in, &cache, 1024) != 0) {
        for (idx_cache = 0; idx_cache < cache_get_size(cache); idx_cache++) {
            cached = cache_get(cache, idx_cache);
            if (!cached)
                continue;

            if (flags & GADGET_CACHE_BASE)
                cached->address += base;

            retcode = 0;
            if (flags & GADGET_CACHE_LINE)
                retcode = gadget_output_format_line (fp_out, cached, flags & GADGET_CACHE_COLOR);
            else if (flags & GADGET_CACHE_STACK)
                retcode = gadget_output_format_stack (fp_out, cached, flags & GADGET_CACHE_COLOR);
            if (retcode > 0)
                count_gadgets += 1;
        }
        // check for fp error or end-of-file
        if (ferror(fp_in) || feof(fp_in)) {
            debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_fshow(): EOL\n");
            break;
        }
    }

    cache_destroy(&cache, gadget_destroy);

    return count_gadgets;
}

struct gadget_cache_queue_t *gadget_cache_queue_init (struct gadget_cache_queue_t **queue)
{
    int retcode;

    if (!queue) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_queue_init (): Bad parameter\n");
        return NULL;
    }

    if (!*queue) {
        *queue = calloc(sizeof(**queue), 1);
        if (!*queue) {
            debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_queue_init (): Gadget queue allocation failed\n");
            return NULL;
        }
    }

    // init queue caches
    (*queue)->caches = NULL;

    // init semaphore
    retcode = sem_init(&(*queue)->queue_sem, 0, 0);
    if (retcode != 0) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_queue_init(): queue semaphore init failed\n");
        return NULL;
    }

    // init mutexes
    retcode = pthread_mutex_init(&(*queue)->queue_mutex, NULL);
    if (retcode != 0) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_queue_init(): queue mutex init failed\n");
        return NULL;
    }

    return (*queue);
}

struct gadget_cache_queue_t *gadget_cache_queue_add (struct gadget_cache_queue_t *queue, struct cache_t *cache)
{
    int retcode;

    retcode = queue_push (&queue->caches, cache);
    if (!retcode) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_queue_add(): queue push failed\n");
        return NULL;
    }

    // there is data to be consumed!
    sem_post (&queue->queue_sem);

    return queue;
}

// thread function
int gadget_cache_queue_fwrite_worker (struct gadget_cache_queue_t *queue)
{
    int count_gadgets;
    struct cache_t *cache;
    struct gadget_plugin_t *plugin;

    if (!queue) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_queue_fwrite_worker(): Bad parameter\n");
        return NULL;
    }

    if (!queue->file) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_queue_fwrite_worker(): File is NULL\n");
        return NULL;
    }

    // there is data to be consumed!
    sem_wait (&queue->queue_sem);

    cache = queue_pop (&queue->caches);
    if (!cache) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadget_cache_queue_fwrite_worker(): queue_pop() failed\n");
        return -1;
    }

    plugin = gadget_plugin_dispatch(0);
    count_gadgets = gadget_cache_fwrite (queue->file, cache, plugin);

    return count_gadgets;
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
    queue_destroy (&(*queue)->caches, NULL);
    free (*queue);
    *queue = NULL;
}


#include <stdlib.h>
#include <stdio.h>

#include "byte-order.h"
#include "gadgets_cache.h"

/* cache structure */

// allocate cache
struct gadget_cache_t* gadget_cache_new(int nGadget) {
    struct gadget_cache_t *cache;

    if (nGadget <= 0)
        return NULL;

    cache = calloc(sizeof(*cache), 1);
    if (!cache)
        return NULL;

    cache->gadgets = calloc(sizeof(*cache->gadgets), nGadget);
    if (!cache->gadgets) {
        free(cache);
        return NULL;
    }

    cache->capacity = nGadget;

    return cache;
}

// destroy cache
void gadget_cache_destroy(struct gadget_cache_t **cache) {
    if (!cache || !*cache)
        return;

    gadget_cache_purge(*cache);
    free((*cache)->gadgets);
    free(*cache);
    *cache = NULL;
}

// add gadget to cache
int gadget_cache_add_gadget(struct gadget_cache_t *cache, struct gadget_t *gadget) {
    // check parameters
    if (!cache || !gadget) {
        printf("gadget_cache_add_gadget(): cache does not exist\n");
        return ERR_GADGET_CACHE_UNDEFINED;
    }

    // re-adjust used if inferior of equal to 0
    cache->used =  (cache->used <= 0) ? 0 : cache->used;

    // if cache full
    if (cache->used >= cache->capacity)
        return ERR_GADGET_CACHE_FULL;

    cache->gadgets[cache->used] = gadget;
    cache->used++;

    return GADGET_CACHE_OK;
}

// get element at index
struct gadget_t* gadget_cache_get(struct gadget_cache_t *cache, int index) {
    if (!cache)
        return NULL;

    if (index < 0 || index > cache->used || index == cache->capacity)
        return NULL;

    return cache->gadgets[index];
}

// purge cache: just "free" by resetting the used counter
int gadget_cache_reset(struct gadget_cache_t *cache) {
    int idxGadget;

    // check parameters
    if (!cache)
        return ERR_GADGET_CACHE_UNDEFINED;

    // reset cache
    for (idxGadget = 0; idxGadget < gadget_cache_get_size(cache); idxGadget++)
        cache->gadgets[idxGadget] = NULL;

    // just reset the used counter :) (we overwrite over it)
    cache->used = 0;

    return GADGET_CACHE_OK;
}

// purge cache: "free" and re-init the cache
int gadget_cache_purge(struct gadget_cache_t *cache) {
    int idxGadget;

    // check parameters
    if (!cache)
        return ERR_GADGET_CACHE_UNDEFINED;

    // reinit whole cache
    for (idxGadget = 0; idxGadget < gadget_cache_get_size(cache); idxGadget++) {
        free(cache->gadgets[idxGadget]);
        cache->gadgets[idxGadget] = NULL;
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
        fread(&(file.lenBytes), sizeof(file.lenBytes), 1, fp);
        host.lenBytes = file_to_host_order_by_size(file.lenBytes, sizeof(file.lenBytes));
        if (host.lenBytes >= fsize) {
            check = ERR_GADGET_CACHE_FILE_INVALID;
            break;
        }
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;
        // ignore bytes
        fseek(fp, host.lenBytes, SEEK_CUR);

        // repr
        fread(&(file.lenRepr), sizeof(file.lenRepr), 1, fp);
        host.lenRepr = file_to_host_order_by_size(file.lenRepr, sizeof(file.lenRepr));
        if (host.lenRepr >= fsize) {
            check = ERR_GADGET_CACHE_FILE_INVALID;
            break;
        }
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;
        fseek(fp, host.lenRepr, SEEK_CUR);

        if (host.lenBytes == 0 && host.lenRepr == 0)
            break;
    }

    return check != ERR_GADGET_CACHE_FILE_INVALID ? 1 : 0;
}

// save cache to file
// return number of gadgets written
int gadget_cache_fwrite(FILE *fp, struct gadget_cache_t *cache) {
    int idxCache, countGadgets;
    struct gadget_t *cached, file;
    uint16_t szBuf;

    //
    if (!fp || !cache)
        return ERR_GADGET_CACHE_UNDEFINED;

    // go through the cache
#ifdef _DEBUG
    printf("write cache file\n");
#endif
    for (idxCache = countGadgets = 0; idxCache < gadget_cache_get_size(cache); idxCache++) {
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;
        // get a cached element
        cached = gadget_cache_get(cache, idxCache);
        if (!cached)
            continue;
        countGadgets++;
        // write to cache file in big endian (so it is portable accross platform :))
        // write address
        file.address = host_to_file_order_by_size(cached->address, sizeof(cached->address));
        fwrite(&file.address, sizeof(cached->address), 1, fp);
        // write bytes
        szBuf = cached->lenBytes;
        if (cached->bytes == NULL || szBuf < 0)
            szBuf = 0;
        if (szBuf > 0)
            szBuf += 1;
        file.lenBytes = host_to_file_order_by_size(szBuf, sizeof(file.lenBytes));
        fwrite(&(file.lenBytes), sizeof(file.lenBytes), 1, fp);
        if (szBuf > 0)
            fwrite(cached->bytes, sizeof(*cached->bytes), szBuf, fp);
#ifdef _DEBUG
        printf("lenBytes: %d - %x\n", cached->lenBytes, cached->lenBytes);
#endif
        // write repr
        szBuf = cached->lenRepr;
        if (cached->repr == NULL || szBuf < 0)
            szBuf = 0;
        if (szBuf > 0)
            szBuf += 1;
        file.lenRepr = host_to_file_order_by_size(szBuf, sizeof(file.lenRepr));
        fwrite(&file.lenRepr, sizeof(file.lenRepr), 1, fp);
        if (szBuf > 0)
            fwrite(cached->repr, sizeof(*cached->repr), szBuf, fp);
#ifdef _DEBUG
        printf("lenRepr: %d - %x\n\n", cached->lenRepr, cached->lenRepr);
#endif
    }

    return countGadgets;
}

// load file to cache
// return number of gadgets readed
int gadget_cache_fread(FILE *fp, struct gadget_cache_t **cache, int nRead) {
    int idxCache, countGadgets, bRead;
    struct gadget_t *cached;
    int loop_protection;

    if (!fp || !cache || nRead <= 0)
        return ERR_GADGET_CACHE_UNDEFINED;

    // cache
    if (!*cache) {
        *cache = gadget_cache_new(nRead);
        if (!*cache) {
            return 0;
        }

        // allocate gadget array
        for (idxCache = 0; idxCache < gadget_cache_get_capacity(*cache); idxCache++) {
            gadget_cache_add_gadget((*cache), gadget_new());
        }
    }

    // go through the cache
#ifdef _DEBUG
    printf("read cache file\n");
#endif
    for (idxCache = countGadgets = 0; idxCache < gadget_cache_get_size(*cache); idxCache++) {
        // check for fp error or end-of-file
        if (feof(fp) || ferror(fp))
            break;
        // get a cached element
        cached = gadget_cache_get(*cache, idxCache);
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
        printf("sizeof(lenBytes): %lu\n", sizeof(cached->lenBytes));
#endif
        bRead = fread(&(cached->lenBytes), sizeof(cached->lenBytes), 1, fp);
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;
        cached->lenBytes = file_to_host_order_by_size((uint16_t)cached->lenBytes, sizeof(cached->lenBytes));
#ifdef _DEBUG
        printf("lenBytes: %d - %x\n", cached->lenBytes, cached->lenBytes);
        printf("bRead: %d\n", bRead);
        printf("---------\n");
        bRead = 0;
#endif
        if (cached->lenBytes) {
            cached->bytes = calloc(cached->lenBytes, sizeof(*cached->bytes));
            bRead = fread(cached->bytes, sizeof(*cached->bytes), cached->lenBytes, fp);
            // check for fp error or end-of-file
            if (ferror(fp) || feof(fp))
                break;
        }
#ifdef _DEBUG
        printf("bRead: %d\n", bRead);
        printf("ftell(fp): %d\n", ftell(fp));
        printf("---------\n");
        // read repr
        printf("sizeof(lenRepr): %lu\n", sizeof(cached->lenRepr));
#endif
        bRead = fread(&(cached->lenRepr), sizeof(cached->lenRepr), 1, fp);
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;
        cached->lenRepr = file_to_host_order_by_size((uint16_t)cached->lenRepr, sizeof(cached->lenRepr));
#ifdef _DEBUG
        printf("lenRepr: %d - %x\n", cached->lenRepr, cached->lenRepr);
        printf("bRead: %d\n", bRead);
        printf("---------\n");
        bRead = 0;
#endif
        if (cached->lenRepr) {
            cached->repr = calloc(cached->lenRepr, sizeof(*cached->repr));
            bRead = fread(cached->repr, sizeof(*cached->repr), cached->lenRepr, fp);
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

// show cache file (it has to respect the file format ... no verification is made so possible crash)
// return number of gadgets showed
int gadget_cache_fshow(FILE *fp) {
    int idxCache, countGadgets;
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
        for (idxCache = 0; idxCache < gadget_cache_get_size(cache); idxCache++) {
            cached = gadget_cache_get(cache, idxCache);
            if (!cached || cached->repr == NULL)
                continue;
            printf("0x%08llx : %s\n", base + cached->address, cached->repr);
            if (cached->repr) {
                free(cached->repr);
                cached->repr = NULL;
            }
            if (cached->bytes) {
                free(cached->bytes);
                cached->bytes = NULL;
            }
            countGadgets++;
        }
        // check for fp error or end-of-file
        if (ferror(fp) || feof(fp))
            break;
    }

    gadget_cache_destroy(&cache);

    return countGadgets;
}


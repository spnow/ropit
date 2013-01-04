#include <stdlib.h>
#include <stdio.h>

// for offsetof
#include <stddef.h>
#include <stdint.h>

#include "byte-order.h"
#include "file-ropit-metadata.h"

// fix metadata byte order
struct ropit_file_metadata_t* ropit_file_metadata_fix_endianness(struct ropit_file_metadata_t *metadata);

int ropit_file_metadata_check (struct ropit_file_metadata_t *metadata)
{
    uint8_t magic[16];

    //
    if (!metadata)
        return -1;

    memset (magic, 0, 16);
    memcpy (magic, "ROPIT_GADGETS", 13);
    if (memcmp(metadata->magic, magic, sizeof(metadata->magic)))
        return 0;

    // if you're here
    // then you passed all the check successfully :)
    return 1;
}

struct ropit_file_metadata_t* ropit_file_metadata_read (FILE *fp)
{
    struct ropit_file_metadata_t *metadata;
    int soffset;
    int sz_hash;
    //
    int idx_section;
    // number of readed bytes
    int n_read;

    // if not opened
    if (!fp)
        return NULL;

    // allocate memory for metadata
    metadata = calloc(sizeof(*metadata), 1);
    if (!metadata)
        return NULL;

    // rewind (metadata is at the beginning of file
    fseek(fp, 0, SEEK_SET);

    //
    soffset = offsetof(struct ropit_file_metadata_t, hash);
    n_read = fread(metadata, sizeof(uint8_t), soffset, fp);
    // fix endianness
    metadata = ropit_file_metadata_fix_endianness(metadata);

    // get size of hash (in bytes) depending on hash type
    if (metadata->hashtype == ROPIT_FILE_METADATA_HASHTYPE_MD5)
        sz_hash = 32;
    else if (metadata->hashtype == ROPIT_FILE_METADATA_HASHTYPE_SHA1)
        sz_hash = 40;
    else
        goto _error;

    // room for hash
    metadata->hash = calloc(sizeof(uint8_t), sz_hash);
    if (!metadata->hash)
        goto _error;
    // get hash
    n_read = fread(metadata->hash, sizeof(uint8_t), sz_hash, fp);

    // get filename size
    n_read = fread(&(metadata->sz_filename), sizeof(uint16_t), 1, fp);
    metadata->sz_filename = file_to_host_order(metadata->sz_filename);

    // get filename
    metadata->filename = calloc(sizeof(uint8_t), metadata->sz_filename);
    if (!metadata->filename)
        goto _error;
    n_read = fread(metadata->filename, sizeof(uint8_t), metadata->sz_filename, fp);

    // get number of sections
    n_read = fread(&(metadata->n_sections), sizeof(uint16_t), 1, fp);
    metadata->n_sections = file_to_host_order(metadata->n_sections);

    // get section headers table
    metadata->sheaders = calloc(sizeof(*(metadata->sheaders)), metadata->n_sections);
    if (!metadata->sheaders)
        goto _error;
    n_read = fread(metadata->sheaders, sizeof(uint8_t), metadata->n_sections, fp);

    // fix endianness
    for (idx_section = 0; idx_section < metadata->n_sections; idx_section++) {
        metadata->sheaders[idx_section].type = file_to_host_order(metadata->sheaders[idx_section].type);
        metadata->sheaders[idx_section].n_elt = file_to_host_order(metadata->sheaders[idx_section].n_elt);
    }

    // check metadata
    if (ropit_file_metadata_check(metadata) != 1)
        goto _error;

    return metadata;

_error:
    // free memory
    free(metadata->hash);
    free(metadata->filename);
    free(metadata->sheaders);
    free(metadata);

    return NULL;
}

void ropit_file_metadata_destroy(struct ropit_file_metadata_t **metadata) {
    // check parameters
    if (!metadata || !(*metadata))
        goto _error;

    free((*metadata)->hash);
    free((*metadata)->filename);
    free((*metadata)->sheaders);
    free(*metadata);
    *metadata = NULL;

_error:
    return;
}

// fix metadata byte order
struct ropit_file_metadata_t* ropit_file_metadata_fix_endianness (struct ropit_file_metadata_t *metadata)
{
    if (!metadata)
        return NULL;

    // version
    metadata->version_minor = host_to_file_order(metadata->version_minor);
    metadata->version_major = host_to_file_order(metadata->version_major);
    metadata->version_patch = host_to_file_order(metadata->version_patch);
    //
    metadata->arch = host_to_file_order(metadata->arch);
    metadata->arch_flavor = host_to_file_order(metadata->arch_flavor);
    //
    metadata->target = host_to_file_order(metadata->target);
    //
    metadata->hashtype = host_to_file_order(metadata->hashtype);

    return metadata;
}

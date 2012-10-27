#include <stdlib.h>
#include <stdio.h>

// for offsetof
#include <stddef.h>
#include <stdint.h>

#include "byte-order.h"
#include "file-ropit-metadata.h"

// fix metadata byte order
struct ropit_file_metadata_t* ropit_file_metadata_fix_endianness(struct ropit_file_metadata_t *metadata);

int ropit_file_metadata_check(struct ropit_file_metadata_t *metadata) {
    //
    if (!metadata)
        return -1;

    if (memcmp(metadata->magic, "ROPIT_GADGETS", 13))
        return 0;

    // if you're here
    // then you passed all the check successfully :)
    return 1;
}

struct ropit_file_metadata_t* ropit_file_metadata_read(FILE *fp) {
    struct ropit_file_metadata_t *metadata;
    int soffset;
    int szHash;
    //
    int idxSection;
    // number of readed bytes
    int nRead;

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
    nRead = fread(metadata, sizeof(uint8_t), soffset, fp);
    // fix endianness
    metadata = ropit_file_metadata_fix_endianness(metadata);

    // get size of hash (in bytes) depending on hash type
    if (metadata->hashtype == ROPIT_FILE_METADATA_HASHTYPE_MD5)
        szHash = 32;
    else if (metadata->hashtype == ROPIT_FILE_METADATA_HASHTYPE_SHA1)
        szHash = 40;
    else
        goto _error;

    // room for hash
    metadata->hash = calloc(sizeof(uint8_t), szHash);
    if (!metadata->hash)
        goto _error;
    // get hash
    nRead = fread(metadata->hash, sizeof(uint8_t), szHash, fp);

    // get filename size
    nRead = fread(&(metadata->szFilename), sizeof(uint16_t), 1, fp);
    metadata->szFilename = file_to_host_order(metadata->szFilename);

    // get filename
    metadata->filename = calloc(sizeof(uint8_t), metadata->szFilename);
    if (!metadata->filename)
        goto _error;
    nRead = fread(metadata->filename, sizeof(uint8_t), metadata->szFilename, fp);

    // get number of sections
    nRead = fread(&(metadata->n_sections), sizeof(uint16_t), 1, fp);
    metadata->n_sections = file_to_host_order(metadata->n_sections);

    // get section headers table
    metadata->sheaders = calloc(sizeof(*(metadata->sheaders)), metadata->n_sections);
    if (!metadata->sheaders)
        goto _error;
    nRead = fread(metadata->sheaders, sizeof(uint8_t), metadata->n_sections, fp);

    // fix endianness
    for (idxSection = 0; idxSection < metadata->n_sections; idxSection++) {
        metadata->sheaders[idxSection].type = file_to_host_order(metadata->sheaders[idxSection].type);
        metadata->sheaders[idxSection].nElt = file_to_host_order(metadata->sheaders[idxSection].nElt);
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
struct ropit_file_metadata_t* ropit_file_metadata_fix_endianness(struct ropit_file_metadata_t *metadata) {
    if (!metadata)
        return NULL;

    // version
    metadata->versionMinor = host_to_file_order(metadata->versionMinor);
    metadata->versionMajor = host_to_file_order(metadata->versionMajor);
    metadata->versionPatch = host_to_file_order(metadata->versionPatch);
    //
    metadata->arch = host_to_file_order(metadata->arch);
    metadata->arch_flavor = host_to_file_order(metadata->arch_flavor);
    //
    metadata->target = host_to_file_order(metadata->target);
    //
    metadata->hashtype = host_to_file_order(metadata->hashtype);

    return metadata;
}

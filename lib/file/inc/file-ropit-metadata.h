#ifndef _ROPIT_FILE_METADATA_H_
#define _ROPIT_FILE_METADATA_H_

#include "file-ropit-section.h"

#define ROPIT_FILE_METADATA_HASHTYPE_UNDEFINED  0
#define ROPIT_FILE_METADATA_HASHTYPE_MD5        1
#define ROPIT_FILE_METADATA_HASHTYPE_SHA1       2

// metadata
struct ropit_file_metadata_t {
    // file identification
    uint8_t magic[16];
    // version
    uint16_t version_minor;
    uint16_t version_major;
    uint16_t version_patch;
    //
    uint16_t arch;
    uint16_t arch_flavor;
    //
    uint16_t target;
    //
    uint16_t hashtype;
    uint8_t *hash;
    // filename
    uint16_t sz_filename;
    uint8_t *filename;
    // number of sections
    uint16_t n_sections;
    struct ropit_file_section_header_t *sheaders;
};

// metadata
struct ropit_file_metadata_t* ropit_file_metadata_read(FILE *fp);
void ropit_file_metadata_destroy(struct ropit_file_metadata_t **metadata);

#endif /* _ROPIT_FILE_METADATA_H_ */

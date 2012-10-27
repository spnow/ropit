#include <stdio.h>
#include <stdint.h>

#include "file-ropit.h"

int ropit_file_gadget_update(FILE *fp, uint8_t *bytes, int nBytes) {
    struct ropit_file_metadata_t *metadata;
    struct ropit_file_section_header_t *sheaders;
    struct ropit_file_section_header_t *section;
    int idxSHeader;

    if (!fp || !bytes || nBytes <= 0)
        return -1;

    // get metadata
    metadata = ropit_file_metadata_read(fp);
    if (!metadata)
        return -1;
    sheaders = metadata->sheaders;
    section = NULL;

    // get gadget section header
    for (idxSHeader = 0; idxSHeader < metadata->n_sections; idxSHeader++) {
        if (sheaders[idxSHeader].type = ROPIT_FILE_SECTION_TYPE_GADGET)
            section = &(sheaders[idxSHeader]);
    }

    // ignore image base
    fseek(fp, sizeof(uint64_t), ftell(fp));

    //
    ropit_file_metadata_destroy(&metadata);

    // no gadget section
    if (section == NULL)
        return -1;
}


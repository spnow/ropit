#ifndef _ROPIT_FILE_H_
#define _ROPIT_FILE_H_

#include <stdint.h>

#include "file-ropit-metadata.h"
#include "file-ropit-section.h"

#define ROPIT_ACTION_BEGIN          0
#define ROPIT_ACTION_FIND_RETS      1
#define ROPIT_ACTION_FIND_GADGETS   2
#define ROPIT_ACTION_END            3

// file format for resume file
struct ropit_file_resume_t {
    //
    struct ropit_file_metadata_t metadata;
    // state: searching for rets or gadgets; begin, end
    uint32_t state;
    // number of threads used for gadget search
    uint8_t nThreads;

    // when searching for rets or gadgets
    // current offset: not used when multi-threaded
    uint32_t currOffset;

    // when searching for rets
    struct {
        uint32_t idx;
        uint32_t n;
        uint32_t *array;
    } rets;
};

// ropit file
struct ropit_file_t {
    struct ropit_file_metadata_t metadata;
    int offFile;
    int offResume;
    struct ropit_file_gadget_t *file;
    struct ropit_file_resume_t *resume;
};

struct ropit_file_index_t {
    uint32_t nFiles;
    struct ropit_file_t *files;
    char **filenames;
    char *szFilename;
};

#endif /* _ROPIT_FILE_H_ */

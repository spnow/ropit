#ifndef _ROPIT_FILE_SECTION_H_
#define _ROPIT_FILE_SECTION_H_

#define ROPIT_FILE_SECTION_TYPE_GADGET   0

struct ropit_file_section_header_t {
    uint16_t type;
    uint32_t size;
};

#endif /* _ROPIT_FILE_SECTION_H_ */

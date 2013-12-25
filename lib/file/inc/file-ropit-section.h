#ifndef _ROPIT_FILE_SECTION_H_
#define _ROPIT_FILE_SECTION_H_

#define ROPIT_FILE_SECTION_TYPE_GADGET   0

struct ropit_file_section_header_t {
    uint32_t name;          /* Section name (string tbl index) */
    uint32_t type;          /* Section type */
    uint32_t flags;         /* Section flags */
    uint64_t addr;          /* Section virtual base addr */
    uint64_t offset;        /* Section file offset */
    uint32_t size;          /* Section size in bytes */
    uint32_t align;         /* Section alignment */
    uint32_t reserved[7];
    uint16_t n_elt;
};

int rop_section_fwrite (struct ropit_file_section_header_t *sheader, FILE *fp);
int rop_section_fread (struct ropit_file_section_header_t *sheader, FILE *fp);

#endif /* _ROPIT_FILE_SECTION_H_ */

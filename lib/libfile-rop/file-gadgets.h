#ifndef _ROPIT_FILE_GADGET_H_
#define _ROPIT_FILE_GADGET_H_

// file format for saving all the gadgets
struct ropit_file_gadget_t {
    //
    struct ropit_file_metadata_t metadata;
    // baseaddress of executable file
    uint64_t imageBase;
    // sections
    void **sections;
};

#endif /* _ROPIT_FILE_GADGET_H_ */

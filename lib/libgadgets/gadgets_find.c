#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// threading
#include <pthread.h>

#include <libdis.h>
#include <pcre.h>

#include "arch/arch.h"
#include "filemap.h"
#include "file_pe.h"
#include "file_elf.h"
#include "offsets.h"

// internal functions
// find valid instructions offsets before ret
struct offsets_t *_gadgets_find_stub(uint8_t *bytes, int len, int64_t *rets, int n_rets);

int compare_ints (const void * a, const void * b) {
    return ( *(int*)a - *(int*)b );
}

// search some opcodes
struct offsets_t *ropit_opcodes_find(uint8_t *bytes, int sz_bytes,
        uint8_t *opcodes, int sz_ops, int sz_opcode) {
    //
    int idx_bytes, n_ops;
    //
    int idx_op;
    struct offsets_t *ops = NULL;

    if (!bytes || sz_bytes <= 0
            || !opcodes || sz_ops <= 0
            || sz_opcode <= 0)
        return NULL;

    // alloc
    ops = offsets_new(sz_bytes);
    if (!ops)
        return NULL;

    // find offsets
    for (idx_bytes = 0, n_ops = 0; idx_bytes < sz_bytes; idx_bytes++) {
        for (idx_op = 0; idx_op < sz_ops; idx_op++) {
            if (bytes[idx_bytes] == opcodes[idx_op]) {
                ops->offsets[n_ops] = idx_bytes;
                n_ops++;
            }
        }
    }

    qsort (ops->offsets, n_ops, sizeof(int), compare_ints);

    ops->used = n_ops;

    return ops;
}

//
struct offsets_t *ropit_filter_regexp(uint8_t *bytes, int len, char *expr) {
    pcre *pattern = NULL;
    const char *errptr = NULL;
    int erroffset = 0;
    int rc;
    struct offsets_t *matches = NULL;
    int wspace[64] = {0}, wcount = 20;
    //
    int start, mcount, idx;

    matches = offsets_new(1200);
    if (!matches)
        return NULL;

    // pattern = pcre_compile("(pop\\s+\\w{3}\\s+){2}ret", PCRE_CASELESS, &errptr, &erroffset, NULL);
    pattern = pcre_compile(expr, PCRE_CASELESS, &errptr, &erroffset, NULL);
    if (errptr) {
        fprintf(stderr, "%s\n", errptr);
        return NULL;
    }

    // find ALL possibilities and have backtracking capabilities
    for (start = 0, mcount = 0, idx = 0; start < len; idx++) {
        rc = pcre_exec(pattern, NULL, (char *)bytes, len, start, 0, wspace, wcount);
        if (rc <= 0) {
            //fprintf(stderr, "Error: pcre_exec() failed\n");
            start++;
        }
        else {
            start = wspace[1];
            matches->offsets[mcount] = wspace[0];
            matches->offsets[mcount+1] = wspace[1];
            mcount++;
        }
        memset(wspace, 0, 64);
    }

    pcre_free(pattern);

    //matches->used = rc - 1;
    matches->used = mcount;

    return matches;
}

struct _gadget_find_thread_data {
    uint8_t *bytes;
    int len;
    uint64_t *rets;
    int sz_rets;
};

void* gadgets_find_thread_n(void *data) {
    struct _gadget_find_thread_data *tdata = data;
    struct offsets_t *rets;
    struct offsets_t *gadgets;

    if (!data)
        return NULL;

    rets = tdata->rets;
    if (!rets)
        return NULL;
    gadgets = _gadgets_find_stub(tdata->bytes, tdata->len, rets->offsets, rets->used);
    if (!gadgets)
        return NULL;

    pthread_exit(gadgets);
}

struct bytes_t {
    uint8_t *bytes;
    int used;
    int capacity;
    struct offsets_t *rets;
};

// thread for finding instructions before ret
void* gadgets_find_thread(void *data) {
    struct bytes_t *bytes = data;
    struct offsets_t *offsets, *rets;

    // check parameter
    if (!bytes)
        return NULL;

    fprintf(stdout, "info: gadgets_find_thread(): bytes->bytes=%p\n", bytes->bytes);
    fprintf(stdout, "info: gadgets_find_thread(): bytes->used=%d\n", bytes->used);

    // get rets
    rets = bytes->rets;

    // find valid instructions
    offsets = _gadgets_find_stub(bytes->bytes, bytes->used, rets->offsets, rets->used);
    if (!offsets) {
        fprintf(stdout, "info: gadgets_find_thread(): no offsets\n");
        pthread_exit(offsets);
    }

    fprintf(stdout, "info: gadgets_find_thread(): rets->capacity=%d\n", rets->capacity);
    fprintf(stdout, "info: gadgets_find_thread(): rets->used=%d\n", rets->used);
    fprintf(stdout, "info: gadgets_find_thread(): offsets->capacity=%d\n", offsets->capacity);
    fprintf(stdout, "info: gadgets_find_thread(): offsets->used=%d\n", offsets->used);
    // offsets = gadgets_find(bytes->bytes, bytes->used);

    // exit
    pthread_exit(offsets);
}

// find valid instructions offsets before ret in a threaded way
struct offsets_t *gadgets_find_threaded_n(uint8_t *bytes, int len) {
    // code return from calls
    int retcode;
    // threads
    int n_threads = 4;
    int idx_thread;
    pthread_t *threads;
    struct _gadget_find_thread_data *tdata;
    struct offsets_t **tresult;
    int rest, rlen, tlen;
    // gadgets finding
    struct offsets_t *gadgets;

    // check params
    if (!bytes || len <= 0) {
        fprintf(stderr, "error: _gadgets_find_threaded_n(): Bytes null or len <= 0\n");
        return NULL;
    }

    tdata = calloc(n_threads, sizeof(*tdata));
    if (!tdata) {
        fprintf(stderr, "error: _gadgets_find_threaded_n(): Couldn't alloc tdata\n");
        return NULL;
    }

    tresult = calloc(n_threads, sizeof(*tresult));
    if (!tresult) {
        fprintf(stderr, "error: _gadgets_find_threaded_n(): Couldn't alloc tresult\n");
        return NULL;
    }
    
    // allocate threads
    threads = calloc(n_threads, sizeof(*threads));
    if (!threads) {
        fprintf(stderr, "error: _gadgets_find_threaded_n(): Could alloc threads\n");
        return NULL;
    }

    rest = len % n_threads;
    rlen = len - rest;
    tlen = len / n_threads;

    for (idx_thread = 0; idx_thread < n_threads; idx_thread++) {
        tdata[idx_thread].bytes = bytes;
        tdata[idx_thread].len = len;
        if (idx_thread != (n_threads - 1))
            tdata[idx_thread].rets = ropit_opcodes_find_ret(bytes + tlen * idx_thread, tlen);
        else
            tdata[idx_thread].rets = ropit_opcodes_find_ret(bytes + tlen * idx_thread, tlen + rest);

        // create thead
        retcode = pthread_create(&threads[idx_thread], NULL, gadgets_find_thread_n, (void *)&(tdata[idx_thread]));
        if (retcode != 0)
            fprintf(stderr, "error: _gadgets_find_threaded(): thread %d creation failed\n", idx_thread);
    }
    fprintf(stdout, "Threads created\n");

    // wait for threads completion
    fprintf(stdout, "Threads joining\n");
    for (idx_thread = 0; idx_thread < n_threads; idx_thread++) {
        retcode = pthread_join(threads[idx_thread], &(tresult[idx_thread]));
        printf("info: _gadgets_find_threaded(): offsets = %p\n", tresult[idx_thread]);
        if (retcode != 0)
            fprintf(stderr, "error: _gadgets_find_threaded(): thread %d did not join\n", idx_thread);
    }
    fprintf(stdout, "Threads joined\n");

    // agregate gadgets offsets
    gadgets = offsets_new(0);
    for (idx_thread = 0; idx_thread < n_threads; idx_thread++)
        offsets_append(gadgets, tresult[idx_thread]);

    // show and free offsets
    for (idx_thread = 0; idx_thread < n_threads; idx_thread++) {
        printf("Local pointers of thread %d: %p\n", idx_thread, tresult[idx_thread]);
        // free instructions
        offsets_destroy(&tresult[idx_thread]);
        offsets_destroy(&(tdata[idx_thread].rets));
    }
    // cleanup
    free(tdata);
    free(tresult);
    free(threads);

    return NULL;
}

// find valid instructions offsets before ret in a threaded way
struct offsets_t *gadgets_find_threaded(uint8_t *bytes, int len) {
    // code return from calls
    int retcode;
    // threads
    int n_threads = 4;
    int idx_thread;
    pthread_t *threads;
    // rest and split length
    int rlen, slen;
    // offsets
    struct offsets_t **local_pointers, **rets, *local_inst;
    struct bytes_t *tdata;

    // check params
    if (!bytes || len <= 0) {
        fprintf(stderr, "error: _gadgets_find_threaded(): Bytes null or len <= 0\n");
        return NULL;
    }

    // if buffer is not big enough
    // then no need for threading
    if (len < n_threads) {
        fprintf(stdout, "info: _gadgets_find_threaded(): Buffer has len than %d bytes so no need for threading\n", n_threads);
        return _gadgets_find_stub(bytes, len, (*rets)->offsets, (*rets)->used);
    }

    // allocate threads
    threads = calloc(n_threads, sizeof(*threads));
    if (!threads)
        return NULL;

    // allocate local offsets
    local_inst = offsets_new(1024);
    if (!local_inst)
        return NULL;

    // allocate local offsets
    local_pointers = calloc(n_threads, sizeof(*local_pointers));
    if (!local_pointers)
        return NULL;

    // allocate local offsets
    tdata = calloc(n_threads, sizeof(*tdata));
    if (!tdata)
        return NULL;

    // search rets
    rets = calloc(n_threads, sizeof(*rets));
    if (!rets) {
        return NULL;
    }

    // arithmetic to get buffer split length between threads
    rlen = len % n_threads;
    slen = (len - rlen) / n_threads;

    // gets rets
    for (idx_thread = 0; idx_thread < n_threads - 1; idx_thread++) {
        rets[idx_thread] = ropit_opcodes_find_ret(bytes + slen * idx_thread, slen);
    }
    rets[idx_thread] = ropit_opcodes_find_ret(bytes + slen * idx_thread, slen + rlen);

    // create threads
    fprintf(stdout, "Creating threads\n");
    for (idx_thread = 0; idx_thread < n_threads; idx_thread++) {
        tdata[idx_thread].rets = rets[idx_thread];
        tdata[idx_thread].bytes = bytes;
        tdata[idx_thread].capacity = len;
        tdata[idx_thread].used = len;

        // create thead
        retcode = pthread_create(&threads[idx_thread], NULL, gadgets_find_thread, (void *)&(tdata[idx_thread]));
        if (retcode != 0)
            fprintf(stderr, "error: _gadgets_find_threaded(): thread %d creation failed\n", idx_thread);
    }
    fprintf(stdout, "Threads created\n");

    // wait for threads completion
    fprintf(stdout, "Threads joining\n");
    for (idx_thread = 0; idx_thread < n_threads; idx_thread++) {
        retcode = pthread_join(threads[idx_thread], &(local_pointers[idx_thread]));
        printf("info: _gadgets_find_threaded(): offsets = %p\n", local_pointers[idx_thread]);
        if (retcode != 0)
            fprintf(stderr, "error: _gadgets_find_threaded(): thread %d did not join\n", idx_thread);
    }
    fprintf(stdout, "Threads joined\n");

    // aggregate offsets
    for (idx_thread = 0; idx_thread < n_threads; idx_thread++) {
        if (offsets_append(local_inst, local_pointers[idx_thread]) == NULL) {
            fprintf(stderr, "error: _gadgets_find_threaded(): Failed appending offsets\n");
        }
    }

    // show and free offsets
    for (idx_thread = 0; idx_thread < n_threads; idx_thread++) {
        printf("Local pointers of thread %d: %p\n", idx_thread, local_pointers[idx_thread]);
        // free instructions
        offsets_destroy(&local_pointers[idx_thread]);
    }

    // clean up
    free(local_pointers);
    free(threads);
    free(tdata);
    for (idx_thread = 0; idx_thread < n_threads; idx_thread++)
        offsets_destroy(&rets[idx_thread]);

    return local_inst;
}

// find valid instructions offsets before ret
struct offsets_t *_gadgets_find_stub(uint8_t *bytes, int len, int64_t *rets, int n_rets) {
    int sz_ret;
    int sz_inst;                /* size of instruction */
    x86_insn_t insn;         /* instruction */
    int idx_ret, idx_valid;
    int validGadget;
    // dupe variables
    int idx_dupe, dupe;
    // back track instruction count
    int n_backtrackInst, n_backtrackBytes;
    // gadgets offsets
    struct offsets_t *valid;
    // start for rop search
    uint8_t *start, *gadget_start;

    // check params
    if (!bytes || len <= 0) {
        fprintf(stderr, "error: _gadgets_find_stub(): Bytes null or len <= 0\n");
        return NULL;
    }

    // search rets
    if (!rets || n_rets <= 0) {
        fprintf(stderr, "error: _gadgets_find_stub(): No rets\n");
        return NULL;
    }

    // allocate
    valid = offsets_new(len / 8);
    if (!valid) {
        fprintf(stderr, "error: gadgets_find(): failed alloc\n");
        return NULL;
    }

    // init disasm
    x86_init(opt_none, NULL, NULL);

    for (idx_ret = 0, idx_valid = 0; idx_ret < n_rets; idx_ret++) {
        start = bytes + rets[idx_ret];
        n_backtrackInst = 0;
        n_backtrackBytes = 0;
        while ( bytes <= start && start <= bytes + len ) {
            /* disassemble address */
            sz_inst = x86_disasm(start, start - bytes, 0, 0, &insn);
            if (!sz_inst) {
                printf("not found inst\n");
                n_backtrackBytes++;
                // x86_oplist_free(&insn);
            }
            else {
                // printf("found inst\n");
                sz_ret = 0;
                n_backtrackBytes = 0;
                n_backtrackInst++;
                // x86_oplist_free(&insn);

                gadget_start = --start;
                validGadget = 0;
                while ( bytes <= gadget_start && gadget_start <= bytes + rets[idx_ret] ) {
                    /* disassemble address */
                    sz_inst = x86_disasm(gadget_start, gadget_start - bytes, 0, 0, &insn);
                    if (sz_inst)
                        gadget_start += sz_inst;
                    else {
                        validGadget = 0;
                        break;
                    }
                    x86_oplist_free(&insn);

                    if (gadget_start == bytes + rets[idx_ret]) {
                        validGadget = 1;
                        break;
                    }
                }

                sz_ret = x86_disasm(bytes + rets[idx_ret], len - rets[idx_ret], 0, 0, &insn);
#define DISASSEMBLED_SIZE_MAX 1024
                int disasLength;
                char disassembled[DISASSEMBLED_SIZE_MAX] = {0};
                disasLength = x86_format_insn(&insn, disassembled, DISASSEMBLED_SIZE_MAX, intel_syntax);
                printf("ret 0x%08x: %s\n", rets[idx_ret], disassembled);
                x86_oplist_free(&insn);
                /*
                   printf("gadget_start: 0x%p\n", gadget_start);
                   printf("bytes + rets[idx_ret]: 0x%p\n\n", bytes + rets[idx_ret]);
                //*/

                if (validGadget == 1) {
                    // printf("got a good gadget\n");
                    gadget_start = start;
                    while ( start <= gadget_start && gadget_start < bytes + rets[idx_ret] + sz_ret ) {
                        /* disassemble address */
                        sz_inst = x86_disasm(gadget_start, gadget_start - bytes, 0, 0, &insn);
                        if (sz_inst) {
#define DISASSEMBLED_SIZE_MAX 1024
                            int disasLength;
                            char disassembled[DISASSEMBLED_SIZE_MAX] = {0};
                            disasLength = x86_format_insn(&insn, disassembled, DISASSEMBLED_SIZE_MAX, intel_syntax);
                            printf("0x%08x: %s\n", gadget_start - bytes, disassembled);

                            gadget_start += sz_inst;
                        }
                        else {
                        }
                        x86_oplist_free(&insn);
                    }
                    putchar('\n');
                }
            }
            start--;

            // maximum intel instruction size is 15
            if (n_backtrackBytes >= 15 || n_backtrackInst == 32)
                break;
        }
    }
    x86_cleanup();

    return valid;
}

// find valid instructions offsets before ret
struct offsets_t *gadgets_find(uint8_t *bytes, int len, uint64_t base) {
    struct offsets_t *rets, *instructions;

    // search rets
    rets = ropit_opcodes_find_ret(bytes, len);
    if (!rets) {
        fprintf(stderr, "error: gadgets_find(): No rets\n");
        return NULL;
    }
    instructions = _gadgets_find_stub(bytes, len, rets->offsets, rets->used);
    offsets_destroy(&rets);

    return instructions;
}

int ropit_pointers_check_charset(uint64_t pointer,
        char *charset, int sz_charset) {
    int idx_charset, idx_ptr;
    uint8_t p[8] = {0};
    int isGood = 0;

    p[0] = pointer & 0xff;
    p[1] = (pointer >> 8) & 0xff;
    p[2] = (pointer >> 16) & 0xff;
    p[3] = (pointer >> 24) & 0xff;
    p[4] = (pointer >> 32) & 0xff;
    p[5] = (pointer >> 40) & 0xff;
    p[6] = (pointer >> 48) & 0xff;
    p[7] = (pointer >> 56) & 0xff;

    // checking that each byte is in the charset
    // if it is
    // then it is good
    for (idx_ptr = 0; idx_ptr < 8; idx_ptr++) {
        for (idx_charset = 0; idx_charset < sz_charset; idx_charset++) {
            // badchar
            if (p[idx_ptr] != charset[idx_charset])
                isGood = 0;
            // goodchar
            else {
                isGood = 1;
                break;
            }
        }
    }

    return isGood;
}

int ropit_pointers_check_pointer_characteristics() {
    return 0;
}

// find gadgets in ELF file
struct gadget_t *gadgets_find_in_elf(char *filename) {
    ELF_FILE *elffile;
    Elf32_Ehdr *elfHeader = NULL;
    Elf32_Phdr *programHeadersTable;
    int idx_programSegment;

    elffile = ElfLoad(filename);
    if (!elffile) {
        fprintf(stderr, "error: gadgets_find_in_elf(): Failed loading ELF\n");
        return NULL;
    }

    if (ElfCheckArchitecture (elffile) == 0) {
        fprintf(stderr, "error: gadgets_find_in_elf(): Architecture not supported\n");
        ElfUnload(&elffile);
        return NULL;
    }

    elfHeader = ElfGetHeader(elffile);
    if (!elfHeader) {
        fprintf(stderr, "error: gadgets_find_in_elf(): Failed getting elfHeaders\n");
        return NULL;
    }

    // program segments parsing (sections are part of program segments)
    programHeadersTable = ElfGetProgramHeadersTable (elffile);
    if (!programHeadersTable) {
        fprintf(stderr, "error: gadgets_find_in_elf(): Failed getting Program Headers Table\n");
    }
    else {
        for (idx_programSegment = 0; idx_programSegment < elfHeader->e_phnum; idx_programSegment++) {
            if (programHeadersTable[idx_programSegment].p_flags & PF_X) {
                gadgets_find(elffile->fmap->map + programHeadersTable[idx_programSegment].p_offset,
                        programHeadersTable[idx_programSegment].p_filesz,
                        programHeadersTable[idx_programSegment].p_paddr);
            }
        }
    }

    ElfUnload(&elffile);

    return NULL;
}

// find gadgets in PE file
struct gadget_t *gadgets_find_in_pe(char *filename) {
    PE_FILE *pefile;
    IMAGE_SECTION_HEADER *section_headersTable;
    IMAGE_NT_HEADERS *nt_header = NULL;
    int idx_section;

    pefile = PeLoad(filename);
    if (!pefile) {
        fprintf(stderr, "error: gadgets_find_in_pe(): Failed loading PE\n");
        return NULL;
    }

    if (PeCheckArchitecture (pefile) == 0) {
        fprintf(stderr, "error: gadgets_find_in_pe(): Architecture not supported\n");
        PeUnload(&pefile);
        return NULL;
    }

    nt_header = PeGetNtHeader(pefile);
    if (!nt_header) {
        fprintf(stderr, "error: gadgets_find_in_pe(): Failed getting NtHeaders\n");
        return NULL;
    }
    section_headersTable = PeGetSection_headerTable(pefile);
    if (!section_headersTable) {
        fprintf(stderr, "error: gadgets_find_in_pe(): Failed getting Section Headers Table\n");
        return NULL;
    }

    for (idx_section = 0; idx_section < nt_header->FileHeader.NumberOfSections; idx_section++) {
        if (section_headersTable[idx_section].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            gadgets_find(pefile->fmap->map + section_headersTable[idx_section].PointerToRawData,
                    section_headersTable[idx_section].SizeOfRawData,
                    nt_header->OptionalHeader.ImageBase + section_headersTable[idx_section].VirtualAddress);
        }
    }

    PeUnload(&pefile);

    return NULL;
}

// find gadgets in executable file
struct gadget_t *gadgets_find_in_executable(char *filename) {
    FILE *fp;

    fp = fopen(filename, "r");
    if (!fp)
        return NULL;

    if (ElfCheck(fp))
        gadgets_find_in_elf(filename);
    else if (PeCheck(fp))
        gadgets_find_in_pe(filename);
    else
        fprintf(stderr, "error: %s is not an executable file\n");

    fclose(fp);

    return NULL;
}

// find gadgets in file
struct gadget_t *gadgets_find_in_file(char *filename) {
    FILE *fp = NULL;
    struct filemap_t *fmap = NULL;

    if (!filename)
        return NULL;

    fp = fopen(filename, "r");
    if (!fp)
        goto gadgets_find_in_file_cleanup;

    fmap = filemap_create(fp);
    if (!fmap)
        goto gadgets_find_in_file_cleanup;

    gadgets_find(fmap->map, fmap->sz_map, 0);

    return NULL;

gadgets_find_in_file_cleanup:
    fclose(fp);
    filemap_destroy(&fmap);

    return NULL;
}


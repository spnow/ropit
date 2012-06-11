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
struct offsets_t* _gadgets_find_stub(uint8_t *bytes, int len, int *rets, int nRets);

int compare_ints (const void * a, const void * b) {
    return ( *(int*)a - *(int*)b );
}

// search some opcodes
struct offsets_t* ropit_opcodes_find(uint8_t *bytes, int szBytes,
        uint8_t *opcodes, int szOps, int szOpcode) {
    //
    int idxBytes, nOps;
    //
    int idxOp;
    struct offsets_t *ops = NULL;

    if (!bytes || szBytes <= 0
            || !opcodes || szOps <= 0
            || szOpcode <= 0)
        return NULL;

    // alloc
    ops = offsets_new(szBytes);
    if (!ops)
        return NULL;

    // find offsets
    for (idxBytes = 0, nOps = 0; idxBytes < szBytes; idxBytes++) {
        for (idxOp = 0; idxOp < szOps; idxOp++) {
            if (bytes[idxBytes] == opcodes[idxOp]) {
                ops->offsets[nOps] = idxBytes;
                nOps++;
            }
        }
    }

    qsort (ops->offsets, nOps, sizeof(int), compare_ints);

    ops->used = nOps;

    return ops;
}

//
struct offsets_t* ropit_filter_regexp(uint8_t *bytes, int len, char *expr) {
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
struct offsets_t* gadgets_find_threaded(uint8_t *bytes, int len) {
    // code return from calls
    int retcode;
    // threads
    int nThreads = 4;
    int idxThread;
    pthread_t *threads;
    // rest and split length
    int rlen, slen;
    // offsets
    struct offsets_t **local_pointers, **rets, *local_inst;
    struct bytes_t *tdata;

    // check params
    if (!bytes || len <= 0) {
        fprintf(stderr, "error: _gadgets_find_stub(): Bytes null or len <= 0\n");
        return NULL;
    }

    // if buffer is not big enough
    // then no need for threading
    if (len < nThreads) {
        fprintf(stdout, "info: _gadgets_find_stub(): Buffer has len than %d bytes so no need for threading\n", nThreads);
        return _gadgets_find_stub(bytes, len, (*rets)->offsets, (*rets)->used);
    }

    // allocate threads
    threads = calloc(nThreads, sizeof(*threads));
    if (!threads)
        return NULL;

    // allocate local offsets
    local_inst = offsets_new(1024);
    if (!local_inst)
        return NULL;

    // allocate local offsets
    local_pointers = calloc(nThreads, sizeof(*local_pointers));
    if (!local_pointers)
        return NULL;

    // allocate local offsets
    tdata = calloc(nThreads, sizeof(*tdata));
    if (!tdata)
        return NULL;

    // search rets
    rets = calloc(nThreads, sizeof(*rets));
    if (!rets) {
        return NULL;
    }

    // arithmetic to get buffer split length between threads
    rlen = len % nThreads;
    slen = (len - rlen) / nThreads;

    // gets rets
    for (idxThread = 0; idxThread < nThreads - 1; idxThread++) {
        rets[idxThread] = ropit_opcodes_find_ret(bytes + slen * idxThread, slen);
    }
    rets[idxThread] = ropit_opcodes_find_ret(bytes + slen * idxThread, slen + rlen);

    // create threads
    fprintf(stdout, "Creating threads\n");
    for (idxThread = 0; idxThread < nThreads; idxThread++) {
        tdata[idxThread].rets = rets[idxThread];
        tdata[idxThread].bytes = bytes;
        tdata[idxThread].capacity = len;
        tdata[idxThread].used = len;

        // create thead
        retcode = pthread_create(&threads[idxThread], NULL, gadgets_find_thread, (void *)&(tdata[idxThread]));
        if (retcode != 0)
            fprintf(stderr, "error: _gadgets_find_threaded(): thread %d creation failed\n", idxThread);
    }
    fprintf(stdout, "Threads created\n");

    // wait for threads completion
    fprintf(stdout, "Threads joining\n");
    for (idxThread = 0; idxThread < nThreads; idxThread++) {
        retcode = pthread_join(threads[idxThread], &(local_pointers[idxThread]));
        printf("info: _gadgets_find_threaded(): offsets = %p\n", local_pointers[idxThread]);
        if (retcode != 0)
            fprintf(stderr, "error: _gadgets_find_threaded(): thread %d did not join\n", idxThread);
    }
    fprintf(stdout, "Threads joined\n");

    // aggregate offsets
    for (idxThread = 0; idxThread < nThreads; idxThread++) {
        if (offsets_append(local_inst, local_pointers[idxThread]) == NULL) {
            fprintf(stderr, "error: _gadgets_find_threaded(): Failed appending offsets\n");
        }
    }

    // show and free offsets
    for (idxThread = 0; idxThread < nThreads; idxThread++) {
        printf("Local pointers of thread %d: %p\n", idxThread, local_pointers[idxThread]);
        // free instructions
        offsets_destroy(&local_pointers[idxThread]);
    }

    // clean up
    free(local_pointers);
    free(threads);
    free(tdata);
    for (idxThread = 0; idxThread < nThreads; idxThread++)
        offsets_destroy(&rets[idxThread]);

    return local_inst;
}

// find valid instructions offsets before ret
struct offsets_t* _gadgets_find_stub(uint8_t *bytes, int len, int *rets, int nRets) {
    int szRet;
    int szInst;                /* size of instruction */
    x86_insn_t insn;         /* instruction */
    int idxRet, idxValid;
    int validGadget;
    // dupe variables
    int idxDupe, dupe;
    // back track instruction count
    int nBacktrackInst, nBacktrackBytes;
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
    if (!rets || nRets <= 0) {
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

    for (idxRet = 0, idxValid = 0; idxRet < nRets; idxRet++) {
        start = bytes + rets[idxRet];
        nBacktrackInst = 0;
        nBacktrackBytes = 0;
        while ( bytes <= start && start <= bytes + len ) {
            /* disassemble address */
            szInst = x86_disasm(start, start - bytes, 0, 0, &insn);
            if (!szInst) {
                // printf("not found inst\n");
                nBacktrackBytes++;
                x86_oplist_free(&insn);
            }
            else {
                // printf("found inst\n");
                szRet = 0;
                nBacktrackBytes = 0;
                nBacktrackInst++;
                x86_oplist_free(&insn);

                gadget_start = --start;
                validGadget = 0;
                while ( bytes <= gadget_start && gadget_start <= bytes + rets[idxRet] ) {
                    /* disassemble address */
                    szInst = x86_disasm(gadget_start, gadget_start - bytes, 0, 0, &insn);
                    if (szInst)
                        gadget_start += szInst;
                    else {
                        validGadget = 0;
                        break;
                    }
                    x86_oplist_free(&insn);

                    if (gadget_start == bytes + rets[idxRet]) {
                        validGadget = 1;
                        break;
                    }
                }
                
                szRet = x86_disasm(bytes + rets[idxRet], len - rets[idxRet], 0, 0, &insn);
#define DISASSEMBLED_SIZE_MAX 1024
                int disasLength;
                char disassembled[DISASSEMBLED_SIZE_MAX] = {0};
                disasLength = x86_format_insn(&insn, disassembled, DISASSEMBLED_SIZE_MAX, intel_syntax);
                printf("ret 0x%08x: %s\n", rets[idxRet], disassembled);
                x86_oplist_free(&insn);
                /*
                   printf("gadget_start: 0x%p\n", gadget_start);
                   printf("bytes + rets[idxRet]: 0x%p\n\n", bytes + rets[idxRet]);
                //*/

                if (validGadget == 1) {
                    // printf("got a good gadget\n");
                    gadget_start = start;
                    while ( start <= gadget_start && gadget_start < bytes + rets[idxRet] + szRet ) {
                        /* disassemble address */
                        szInst = x86_disasm(gadget_start, gadget_start - bytes, 0, 0, &insn);
                        if (szInst) {
#define DISASSEMBLED_SIZE_MAX 1024
                            int disasLength;
                            char disassembled[DISASSEMBLED_SIZE_MAX] = {0};
                            disasLength = x86_format_insn(&insn, disassembled, DISASSEMBLED_SIZE_MAX, intel_syntax);
                            printf("0x%08x: %s\n", gadget_start - bytes, disassembled);

                            gadget_start += szInst;
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
            if (nBacktrackBytes >= 15 || nBacktrackInst == 32)
                break;
        }
    }
    x86_cleanup();

    return valid;
}

// find valid instructions offsets before ret
struct offsets_t* gadgets_find(uint8_t *bytes, int len, uint64_t base) {
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
        char *charset, int szCharset) {
    int idxCharset, idxPtr;
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
    for (idxPtr = 0; idxPtr < 8; idxPtr++) {
        for (idxCharset = 0; idxCharset < szCharset; idxCharset++) {
            // badchar
            if (p[idxPtr] != charset[idxCharset])
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
struct gadget_t* gadgets_find_in_elf(char *filename) {
    ELF_FILE *elffile;
    Elf32_Ehdr *elfHeader = NULL;
    Elf32_Phdr *programHeadersTable;
    int idxProgramSegment;

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
        for (idxProgramSegment = 0; idxProgramSegment < elfHeader->e_phnum; idxProgramSegment++) {
            if (programHeadersTable[idxProgramSegment].p_flags & PF_X) {
                gadgets_find(elffile->fmap->map + programHeadersTable[idxProgramSegment].p_offset,
                        programHeadersTable[idxProgramSegment].p_filesz,
                        programHeadersTable[idxProgramSegment].p_paddr);
            }
        }
    }

    ElfUnload(&elffile);

    return NULL;
}

// find gadgets in PE file
struct gadget_t* gadgets_find_in_pe(char *filename) {
    PE_FILE *pefile;
    IMAGE_SECTION_HEADER *sectionHeadersTable;
    IMAGE_NT_HEADERS *ntHeader = NULL;
    int idxSection;

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

    ntHeader = PeGetNtHeader(pefile);
    if (!ntHeader) {
        fprintf(stderr, "error: gadgets_find_in_pe(): Failed getting NtHeaders\n");
        return NULL;
    }
    sectionHeadersTable = PeGetSectionHeaderTable(pefile);
    if (!sectionHeadersTable) {
        fprintf(stderr, "error: gadgets_find_in_pe(): Failed getting Section Headers Table\n");
        return NULL;
    }

    for (idxSection = 0; idxSection < ntHeader->FileHeader.NumberOfSections; idxSection++) {
        if (sectionHeadersTable[idxSection].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            gadgets_find(pefile->fmap->map + sectionHeadersTable[idxSection].PointerToRawData,
                    sectionHeadersTable[idxSection].SizeOfRawData,
                    ntHeader->OptionalHeader.ImageBase + sectionHeadersTable[idxSection].VirtualAddress);
        }
    }

    PeUnload(&pefile);

    return NULL;
}

// find gadgets in executable file
struct gadget_t* gadgets_find_in_executable(char *filename) {
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
struct gadget_t* gadgets_find_in_file(char *filename) {
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

    gadgets_find(fmap->map, fmap->szMap, 0);

    return NULL;

gadgets_find_in_file_cleanup:
    fclose(fp);
    filemap_destroy(&fmap);

    return NULL;
}


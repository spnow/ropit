/*
    ROPit - Gadget generator tool
    Copyright (C) 2011  m_101

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <string.h>
#include <ctype.h>
#include <elf.h>

#include <libdis.h>
#include <pcre.h>

#include "arch/arch.h"
#include "byte-order.h"
#include "file_elf.h"
#include "file_pe.h"
#include "string_extended.h"

#define BUF_SIZE    1024
#define LINE_SIZE   1024

#include "gadgets.h"
#include "gadgets_cache.h"
#include "gadgets_internal.h"
#include "offsets.h"

// internal functions
// find valid instructions offsets before ret
struct ropit_offsets_t* _ropit_instructions_find_stub(uint8_t *bytes, int len, struct ropit_offsets_t *rets);
// allocate gadget cache thread local storage
struct gadget_cache_t* _gadget_cache_new_thread_data(struct gadget_cache_t *cache);
// destroy gadget cache thread local storage
void _gadget_cache_destroy_thread_data(struct gadget_cache_t *gcache);

// allocate new gadget
struct gadget_t* gadget_new(void) {
    struct gadget_t *gadget;

    gadget = calloc(sizeof(*gadget), 1);
    
    return gadget;
}

// allocate new gadget and copy old
struct gadget_t* gadget_new_copy(struct gadget_t *gadget) {
    struct gadget_t *copy;

    //
    if (!gadget) {
        // fprintf(stderr, "error: gadget_new_copy(): gadget was null\n");
        return NULL;
    }

    // allocs
    copy = gadget_new();
    if (!copy) {
        // fprintf(stderr, "error: gadget_new_copy(): copy was not allocated\n");
        return NULL;
    }
    copy->repr = calloc(gadget->szRepr, sizeof(*copy->repr));
    copy->bytes = calloc(gadget->szBytes, sizeof(*copy->bytes));

    // if one of the alloc failed
    // then copied object failed
    if (copy->repr == NULL || copy->bytes == NULL) {
        fprintf(stderr, "error: gadget_new_copy(): failed bytes and repr allocation\n");
        free(copy->repr);
        free(copy->bytes);

        return NULL;
    }

    // if copy failed
    // then bye
    if (gadget_copy(copy, gadget) == NULL) {
        fprintf(stderr, "error: gadget_new_copy(): failed copy\n");
        gadget_destroy(&copy);
        return NULL;
    }

    return copy;
}

// destroy gadget
void gadget_destroy(struct gadget_t **gadget) {
    if (!gadget || !(*gadget))
        return;

    free((*gadget)->repr);
    free((*gadget)->bytes);
    *gadget = NULL;
}

// copy a gadget to another one
struct gadget_t* gadget_copy(struct gadget_t *dest, struct gadget_t *src) {
    // check parameters
    if (!dest || !src) {
        fprintf(stderr, "error: gadget_copy(): dest or src are non existent\n");
        return NULL;
    }

    // check src
    if (!src->bytes || !src->repr) {
        fprintf(stderr, "error: gadget_copy(): src has no elements\n");
        return NULL;
    }

    // 
    if (dest->szBytes != src->szBytes) {
        fprintf(stderr, "warning: gadget_copy(): realloc of dest->bytes\n");
        dest->bytes = realloc(dest->bytes, src->szBytes * sizeof(*dest->bytes));
    }
    // 
    if (dest->szRepr != src->szRepr) {
        fprintf(stderr, "warning: gadget_copy(): realloc of dest->repr\n");
        dest->repr = realloc(dest->repr, src->szRepr * sizeof(*dest->repr));
    }

    // check
    if (dest->bytes == NULL || dest->repr == NULL) {
        fprintf(stderr, "error: gadget_copy(): dest->bytes = %p or dest->repr = %p\n", dest->bytes, dest->repr);
        return NULL;
    }

    dest->address = src->address;
    dest->lenBytes = src->lenBytes;
    dest->szBytes = src->szBytes;
    dest->lenRepr = src->lenRepr;
    dest->szRepr = src->szRepr;

    // copy repr and bytes
    memcpy(dest->bytes, src->bytes, src->szBytes);
    memcpy(dest->repr, src->repr, src->szRepr);

    return dest;
}

int compare_ints (const void * a, const void * b) {
    return ( *(int*)a - *(int*)b );
}

// search some opcodes
struct ropit_offsets_t* ropit_opcodes_find(uint8_t *bytes, int szBytes,
        uint8_t *opcodes, int szOps, int szOpcode) {
    //
    int idxBytes, nOps;
    //
    int idxOp;
    struct ropit_offsets_t *ops = NULL;

    if (!bytes || szBytes <= 0
            || !opcodes || szOps <= 0
            || szOpcode <= 0)
        return NULL;

    // alloc
    ops = ropit_offsets_new(szBytes);
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
struct ropit_offsets_t* ropit_filter_regexp(uint8_t *bytes, int len, char *expr) {
    pcre *pattern = NULL;
    const char *errptr = NULL;
    int erroffset = 0;
    int rc;
    struct ropit_offsets_t *matches = NULL;
    int wspace[64] = {0}, wcount = 20;
    //
    int start, mcount, idx;

    matches = ropit_offsets_new(1200);
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
    struct ropit_offsets_t *rets;
};

// thread for finding instructions before ret
void* ropit_instructions_find_thread(void *data) {
    struct bytes_t *bytes = data;
    struct ropit_offsets_t *offsets, *rets;

    // check parameter
    if (!bytes)
        return NULL;

    fprintf(stdout, "info: ropit_instructions_find_thread(): bytes->bytes=%p\n", bytes->bytes);
    fprintf(stdout, "info: ropit_instructions_find_thread(): bytes->used=%d\n", bytes->used);

    // get rets
    rets = bytes->rets;

    // find valid instructions
    offsets = _ropit_instructions_find_stub(bytes->bytes, bytes->used, rets);
    if (!offsets) {
        fprintf(stdout, "info: ropit_instructions_find_thread(): no offsets\n");
        pthread_exit(offsets);
    }

    fprintf(stdout, "info: ropit_instructions_find_thread(): rets->capacity=%d\n", rets->capacity);
    fprintf(stdout, "info: ropit_instructions_find_thread(): rets->used=%d\n", rets->used);
    fprintf(stdout, "info: ropit_instructions_find_thread(): offsets->capacity=%d\n", offsets->capacity);
    fprintf(stdout, "info: ropit_instructions_find_thread(): offsets->used=%d\n", offsets->used);
    // offsets = ropit_instructions_find(bytes->bytes, bytes->used);

    // exit
    pthread_exit(offsets);
}

// find valid instructions offsets before ret in a threaded way
struct ropit_offsets_t* ropit_instructions_find_threaded(uint8_t *bytes, int len) {
    // code return from calls
    int retcode;
    // threads
    int nThreads = 4;
    int idxThread;
    pthread_t *threads;
    // rest and split length
    int rlen, slen;
    // offsets
    struct ropit_offsets_t **local_pointers, **rets, *local_inst;
    struct bytes_t *tdata;

    // check params
    if (!bytes || len <= 0) {
        fprintf(stderr, "error: _ropit_instructions_find_stub(): Bytes null or len <= 0\n");
        return NULL;
    }

    // if buffer is not big enough
    // then no need for threading
    if (len < nThreads) {
        fprintf(stdout, "info: _ropit_instructions_find_stub(): Buffer has len than %d bytes so no need for threading\n", nThreads);
        return _ropit_instructions_find_stub(bytes, len, rets);
    }

    // allocate threads
    threads = calloc(nThreads, sizeof(*threads));
    if (!threads)
        return NULL;

    // allocate local offsets
    local_inst = ropit_offsets_new(1024);
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
        retcode = pthread_create(&threads[idxThread], NULL, ropit_instructions_find_thread, (void *)&(tdata[idxThread]));
        if (retcode != 0)
            fprintf(stderr, "error: _ropit_instructions_find_threaded(): thread %d creation failed\n", idxThread);
    }
    fprintf(stdout, "Threads created\n");

    // wait for threads completion
    fprintf(stdout, "Threads joining\n");
    for (idxThread = 0; idxThread < nThreads; idxThread++) {
        retcode = pthread_join(threads[idxThread], &(local_pointers[idxThread]));
        printf("info: _ropit_instructions_find_threaded(): offsets = %p\n", local_pointers[idxThread]);
        if (retcode != 0)
            fprintf(stderr, "error: _ropit_instructions_find_threaded(): thread %d did not join\n", idxThread);
    }
    fprintf(stdout, "Threads joined\n");

    // aggregate offsets
    for (idxThread = 0; idxThread < nThreads; idxThread++) {
        if (offsets_append(local_inst, local_pointers[idxThread]) == NULL) {
            fprintf(stderr, "error: _ropit_instructions_find_threaded(): Failed appending offsets\n");
        }
    }

    // show and free offsets
    for (idxThread = 0; idxThread < nThreads; idxThread++) {
        printf("Local pointers of thread %d: %p\n", idxThread, local_pointers[idxThread]);
        // free instructions
        ropit_offsets_destroy(&local_pointers[idxThread]);
    }

    // clean up
    free(local_pointers);
    free(threads);
    free(tdata);
    for (idxThread = 0; idxThread < nThreads; idxThread++)
        ropit_offsets_destroy(&rets[idxThread]);

    return local_inst;
}

// find valid instructions offsets before ret
struct ropit_offsets_t* _ropit_instructions_find_stub(uint8_t *bytes, int len, struct ropit_offsets_t *rets) {
    int size;                /* size of instruction */
    x86_insn_t insn;         /* instruction */
    int idxRet, idxValid;
    // dupe variables
    int idxDupe, dupe;
    // back track instruction count
    int nBacktrackInst, nBacktrackBytes;
    // back offsets
    int prevOffset;
    int currOffset;

    struct ropit_offsets_t *valid;

    // start for rop search
    uint8_t *start;
    // offsets

    // check params
    if (!bytes || len <= 0) {
        fprintf(stderr, "error: _ropit_instructions_find_stub(): Bytes null or len <= 0\n");
        return NULL;
    }

    // search rets
    if (!rets) {
        fprintf(stderr, "error: _ropit_instructions_find_stub(): No rets\n");
        return NULL;
    }

    // allocate
    valid = ropit_offsets_new(len / 8);
    if (!valid) {
        fprintf(stderr, "error: ropit_instructions_find(): failed alloc\n");
        return NULL;
    }

    // init disasm
    x86_init(opt_none, NULL, NULL);

    for (idxRet = 0, idxValid = 0; idxRet < rets->used; idxRet++) {
        currOffset = rets->offsets[idxRet];
        start = bytes + currOffset;
        nBacktrackInst = 0;
        nBacktrackBytes = 1;
        while ( bytes <= start && start <= bytes + len ) {
            /* disassemble address */
            size = x86_disasm(start, start - bytes, 0, 0, &insn);
            if (size) {
                // check presence of value, if there it's not added
                for (idxDupe = 0, dupe = 0; idxDupe < idxValid; idxDupe++) {
                    if (valid->offsets[idxDupe] == start - bytes) {
                        dupe = 1;
                        break;
                    }
                }

                // doesn't register offset if already there
                if (!dupe) {
                    if (idxValid >= valid->capacity)
                        valid = ropit_offsets_realloc(valid, valid->capacity * 2);
                    if (!valid || !(valid->offsets)) {
                        x86_cleanup();
                        ropit_offsets_destroy(&rets);
                        return NULL;
                    }
                    valid->offsets[idxValid] = start - bytes;
                    idxValid++;
                }
                start--;
                nBacktrackBytes = 1;
                nBacktrackInst++;
            }
            else {
                start--;
                nBacktrackBytes++;
            }
            x86_oplist_free(&insn);
            // maximum intel instruction size is 15
            if (nBacktrackBytes >= 15 || nBacktrackInst == 32)
                break;
        }
    }
    x86_cleanup();

    valid->used = idxValid;

    // we remove out rets in instructions list
    for (idxValid = 0; idxValid < valid->used; idxValid++) {
        if (ropit_offsets_exist(rets, valid->offsets[idxValid])) {
            valid->offsets[idxValid] = -1;
            valid->used--;
        }
    }

    qsort (valid->offsets, idxValid, sizeof(int), compare_ints);
    valid = ropit_offsets_realloc(valid, valid->used);

    return valid;
}

// find valid instructions offsets before ret
struct ropit_offsets_t* ropit_instructions_find(uint8_t *bytes, int len) {
    struct ropit_offsets_t *rets, *instructions;

    // search rets
    rets = ropit_opcodes_find_ret(bytes, len);
    if (!rets) {
        fprintf(stderr, "error: ropit_instructions_find(): No rets\n");
        return NULL;
    }
    instructions = _ropit_instructions_find_stub(bytes, len, rets);
    ropit_offsets_destroy(&rets);

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

// find gadgets offsets
// construct gadgets from instructions finder
struct ropit_gadget_t* ropit_gadgets_find(uint8_t *bytes, int len, uint64_t base) {
    // disasm
    struct ropit_offsets_t *instructions = NULL;
    int idxInstruction;
    int pos = 0;            /* current position in buffer */
    int startpos = 0;       // starting position in buffer
    int size;               /* size of instruction */
    int nInstructions;      // number of instructions in gadget
    x86_insn_t insn;        /* instruction */
    uint64_t base_addr_be;  // base address in big endian
    // instruction str buffer
    char disassembled[DISASSEMBLED_SIZE_MAX] = {0};
    int disasLength;
    char *addrRet;
    char gadgetline[GADGET_SIZE_MAX] =  {0};
    int lenGadgetLine;
    // gadget cache: once the cache is full we write it to file
    struct gadget_cache_t *gcache, *gcache_thread;
    struct gadget_t *gadget, *cached;
    int idxCache;
    // gadgets
    struct gadget_t *gadgets;
    int idxGadget, nGadgets, countGadgets;
    // retcode
    int retcode;
    // gadget cache, resume file
    FILE *fp_cache, *fp_resume;

    // resume file in case of interruption
    fp_resume = fopen("tmp/gadget_resume", "wb");
    if (!fp_resume)
        return NULL;

    // 
    fp_cache = fopen("tmp/gadget_cache", "wb");
    if (!fp_cache)
        return NULL;

    // get instructions
    instructions = ropit_instructions_find_threaded(bytes, len);
    if (!instructions)
        return NULL;

    // gadget cache
    gcache = gadget_cache_new(1024);
    if (!gcache)
        return NULL;
    gcache->fp = fp_cache;

    // create local thread storage
    gcache_thread = _gadget_cache_new_thread_data(gcache);
    if (!gcache_thread) {
        fprintf(stderr, "error: ropit_gadgets_find(): cache copy failed\n");
        return ERR_GADGET_CACHE_UNDEFINED;
    }

    // gadgets
    nGadgets = gadget_cache_get_capacity(gcache);
    gadgets = calloc(sizeof(*gadgets), nGadgets);
    if (!gadgets)
        return NULL;
    for (idxGadget = 0; idxGadget < nGadgets; idxGadget++) {
        gadgets[idxGadget].szBytes = GADGET_SIZE_MAX;
        gadgets[idxGadget].bytes = calloc(gadgets[idxGadget].szBytes, sizeof(uint8_t));
        gadgets[idxGadget].szRepr = GADGET_SIZE_MAX;
        gadgets[idxGadget].repr = calloc(gadgets[idxGadget].szRepr, sizeof(uint8_t));
    }

    // init disasm
    x86_init(opt_none, NULL, NULL);

    // put base address in cache
    base_addr_be = host_to_file_order_by_size(base, sizeof(base));
    fwrite(&base_addr_be, sizeof(base_addr_be), 1, fp_cache);

    // we search for gadgets
    idxInstruction = countGadgets = 0;
    while (idxInstruction < instructions->used) {
        // gadget start position
        pos = instructions->offsets[idxInstruction];
        startpos = pos;
        nInstructions = 0;
        // gadget index
        idxGadget = gadget_cache_get_size(gcache) > 0 ? gadget_cache_get_size(gcache) - 1 : 0;
        // get gadgets
        addrRet = NULL;
        do {
            /* disassemble address */
            size = x86_disasm(bytes, len, 0, pos, &insn);
            if (size) {
                disasLength = x86_format_insn(&insn, disassembled, DISASSEMBLED_SIZE_MAX, intel_syntax);
                x86_oplist_free(&insn);

                // filter out bad instructions
                if (ropit_instructions_check(disassembled, DISASSEMBLED_SIZE_MAX) == 0)
                    break;
                if (nInstructions >= 8)
                    break;

                // construct gadget
#ifdef PRINT_IN_COLOR
                strncat(gadgetline, COLOR_RED, GADGET_SIZE_MAX - strlen(gadgetline));
                strncat(gadgetline, disassembled, GADGET_SIZE_MAX - strlen(gadgetline));
                strncat(gadgetline, COLOR_PURPLE, GADGET_SIZE_MAX - strlen(gadgetline));
                strncat(gadgetline, " # ", GADGET_SIZE_MAX - strlen(gadgetline));
                gadgetline[GADGET_SIZE_MAX-1] = '\0';
#else
                strncat(gadgetline, disassembled, GADGET_SIZE_MAX - strlen(gadgetline));
                strncat(gadgetline, " # ", GADGET_SIZE_MAX - strlen(gadgetline));
                gadgetline[GADGET_SIZE_MAX-1] = '\0';
#endif

                addrRet = strstr(disassembled, "ret");
                if (addrRet)
                    break;
                // go forward
                pos += size;
                nInstructions++;
            }
        } while (size);

        if (addrRet == NULL)
            memset(gadgetline, 0, GADGET_SIZE_MAX);

        // if gadget found
        lenGadgetLine = strlen(gadgetline);
        if (lenGadgetLine && nInstructions) {
            // replace tabulations by spaces
            str_tabs2spaces(gadgetline, GADGET_SIZE_MAX);

            // set gadget
            gadgets[idxGadget].address = startpos;
            strncpy(gadgets[idxGadget].repr, gadgetline, gadgets[idxGadget].szRepr-1);
            gadgets[idxGadget].lenBytes = 0;
            gadgets[idxGadget].lenRepr = lenGadgetLine;

            // reset gadgetline
            memset(gadgetline, 0, GADGET_SIZE_MAX);

            // save gadget offset in cache
            retcode = gadget_cache_add_gadget(gcache, &(gadgets[idxGadget]));

            // writing cache to file
            if (retcode == ERR_GADGET_CACHE_FULL) {
                countGadgets += gadget_cache_fwrite_threaded(fp_cache, gcache);

                // reset cache
                gadget_cache_reset(gcache);

                // add non added gadget
                retcode = gadget_cache_add_gadget(gcache, &(gadgets[idxGadget]));
            }
        }

        idxInstruction++;
    }
    x86_cleanup();

    // free cache
    countGadgets += gadget_cache_fwrite_threaded(fp_cache, gcache);
    // destroy thread local cache
    _gadget_cache_destroy_thread_data(gcache);
    // zero out our cache to avoid segfault
    // (since we are not referencing heap alloced buffers)
    gadget_cache_zero(gcache);
    //
    gadget_cache_destroy(&gcache);

    // clean up
    // free gadgets
    for (idxGadget = 0; idxGadget < nGadgets; idxGadget++) {
        free(gadgets[idxGadget].bytes);
        free(gadgets[idxGadget].repr);
    }
    free(gadgets);

    // free instructions
    ropit_offsets_destroy(&instructions);

    // close files
    fclose(fp_cache);
    fclose(fp_resume);

    return gadget;
}

// find gadgets in ELF file
struct ropit_gadget_t* ropit_gadgets_find_in_elf(char *filename) {
    ELF_FILE *elffile;
    Elf32_Ehdr *elfHeader = NULL;
    Elf32_Phdr *programHeadersTable;
    int idxProgramSegment;

    elffile = ElfLoad(filename);
    if (!elffile) {
        fprintf(stderr, "error: ropit_gadgets_find_in_elf(): Failed loading ELF\n");
        return NULL;
    }

    if (ElfCheckArchitecture (elffile) == 0) {
        fprintf(stderr, "error: ropit_gadgets_find_in_elf(): Architecture not supported\n");
        ElfUnload(&elffile);
        return NULL;
    }

    elfHeader = ElfGetHeader(elffile);
    if (!elfHeader) {
        fprintf(stderr, "error: ropit_gadgets_find_in_elf(): Failed getting elfHeaders\n");
        return NULL;
    }

    // program segments parsing (sections are part of program segments)
    programHeadersTable = ElfGetProgramHeadersTable (elffile);
    if (!programHeadersTable) {
        fprintf(stderr, "error: ropit_gadgets_find_in_elf(): Failed getting Program Headers Table\n");
    }
    else {
        for (idxProgramSegment = 0; idxProgramSegment < elfHeader->e_phnum; idxProgramSegment++) {
            if (programHeadersTable[idxProgramSegment].p_flags & PF_X) {
                ropit_gadgets_find(elffile->fmap->map + programHeadersTable[idxProgramSegment].p_offset,
                        programHeadersTable[idxProgramSegment].p_filesz,
                        programHeadersTable[idxProgramSegment].p_paddr);
            }
        }
    }

    ElfUnload(&elffile);

    return NULL;
}

// find gadgets in PE file
struct ropit_gadget_t* ropit_gadgets_find_in_pe(char *filename) {
    PE_FILE *pefile;
    IMAGE_SECTION_HEADER *sectionHeadersTable;
    IMAGE_NT_HEADERS *ntHeader = NULL;
    int idxSection;

    pefile = PeLoad(filename);
    if (!pefile) {
        fprintf(stderr, "error: ropit_gadgets_find_in_pe(): Failed loading PE\n");
        return NULL;
    }

    if (PeCheckArchitecture (pefile) == 0) {
        fprintf(stderr, "error: ropit_gadgets_find_in_pe(): Architecture not supported\n");
        PeUnload(&pefile);
        return NULL;
    }

    ntHeader = PeGetNtHeader(pefile);
    if (!ntHeader) {
        fprintf(stderr, "error: ropit_gadgets_find_in_pe(): Failed getting NtHeaders\n");
        return NULL;
    }
    sectionHeadersTable = PeGetSectionHeaderTable(pefile);
    if (!sectionHeadersTable) {
        fprintf(stderr, "error: ropit_gadgets_find_in_pe(): Failed getting Section Headers Table\n");
        return NULL;
    }

    for (idxSection = 0; idxSection < ntHeader->FileHeader.NumberOfSections; idxSection++) {
        if (sectionHeadersTable[idxSection].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            ropit_gadgets_find(pefile->fmap->map + sectionHeadersTable[idxSection].PointerToRawData,
                    sectionHeadersTable[idxSection].SizeOfRawData,
                    ntHeader->OptionalHeader.ImageBase + sectionHeadersTable[idxSection].VirtualAddress);
        }
    }

    PeUnload(&pefile);

    return NULL;
}

// find gadgets in executable file
struct ropit_gadget_t* ropit_gadgets_find_in_executable(char *filename) {
    FILE *fp;

    fp = fopen(filename, "r");
    if (!fp)
        return NULL;

    if (ElfCheck(fp))
        ropit_gadgets_find_in_elf(filename);
    else if (PeCheck(fp))
        ropit_gadgets_find_in_pe(filename);

    fclose(fp);

    return NULL;
}

// find gadgets in file
struct ropit_gadget_t* ropit_gadgets_find_in_file(char *filename) {
    FILE *fp = NULL;
    struct filemap_t *fmap = NULL;

    if (!filename)
        return NULL;

    fp = fopen(filename, "r");
    if (!fp)
        goto ropit_gadgets_find_in_file_cleanup;

    fmap = filemap_create(fp);
    if (!fmap)
        goto ropit_gadgets_find_in_file_cleanup;

    ropit_gadgets_find(fmap->map, fmap->szMap, 0);

    return NULL;

ropit_gadgets_find_in_file_cleanup:
    fclose(fp);
    filemap_destroy(&fmap);

    return NULL;
}


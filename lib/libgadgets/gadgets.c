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

#include "file_elf.h"
#include "file_pe.h"
#include "string_extended.h"

#define BUF_SIZE    1024
#define LINE_SIZE   1024

#include "gadgets.h"
#include "gadgets_data.h"
#include "gadgets_internal.h"

int compare_ints (const void * a, const void * b) {
    return ( *(int*)a - *(int*)b );
}

// search some opcodes
struct ropit_offsets_t* ropit_opcodes_find(unsigned char *bytes, size_t n,
        unsigned char *opcodes, size_t m, size_t szOpcode) {
    //
    size_t idx, k;
    //
    size_t idxOp;
    struct ropit_offsets_t *ops = NULL;

    if (!bytes || !n
            || !opcodes || !m || !szOpcode)
        return NULL;

    ops = ropit_offsets_new(n);
    if (!ops)
        return NULL;

    // find offsets
    for (idx = 0, k = 0; idx < n; idx++) {
        for (idxOp = 0; idxOp < m; idxOp++) {
            if (bytes[idx] == opcodes[idxOp]) {
                ops->offsets[k] = idx;
                k++;
            }
        }
    }

    qsort (ops->offsets, k, sizeof(int), compare_ints);

    ops->used = k;

    return ops;
}

// search rets
struct ropit_offsets_t* ropit_opcodes_find_ret(unsigned char *bytes, size_t len) {
    unsigned char opcodes[] = "\xc3\xc2\xca\xcb\xcf";
    struct ropit_offsets_t *rets = ropit_opcodes_find(bytes, len, opcodes, strlen((char*)opcodes), 1);

    return rets;
}

//
struct ropit_offsets_t* ropit_filter_regexp(unsigned char *bytes, size_t len, char *expr) {
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

struct ropit_offsets_t* ropit_filter_ppr(unsigned char *bytes, size_t len) {
    return ropit_filter_regexp(bytes, len, "(pop\\s+\\w{3}\\s+){2}\\s*ret");
}

// find valid instructions offsets before ret
struct ropit_offsets_t* ropit_instructions_find(unsigned char *bytes, size_t len) {
    int size;                /* size of instruction */
    x86_insn_t insn;         /* instruction */
    long idx, idxValid;
    // dupe variables
    long idxDupe, dupe;
    // back track instruction count
    long nBacktrackInst, nBacktrackBytes;

    struct ropit_offsets_t *valid;

    // start for rop search
    unsigned char *start;
    // offsets

    // search rets
    struct ropit_offsets_t *rets = ropit_opcodes_find_ret(bytes, len);
    if (!rets) {
        fprintf(stderr, "Error: No rets\n");
        return NULL;
    }

    // allocate
    valid = ropit_offsets_new(len / 8);
    if (!valid) {
        fprintf(stderr, "ropit_instructions_find(): failed alloc\n");
        return NULL;
    }

    // init disasm
    x86_init(opt_none, NULL, NULL);

    for (idx = 0, idxValid = 0; idx < rets->used; idx++) {
        start = bytes + rets->offsets[idx];
        nBacktrackInst = 0;
        nBacktrackBytes = 1;
        while ( bytes <= start ) {
            /* disassemble address */
            size = x86_disasm(start, start - bytes, 0, 0, &insn);
            if (size) {
                // check presence of value, if there it's not added
                for (idxDupe = 0, dupe = 0; idxDupe < idxValid; idxDupe++) {
                    if (valid->offsets[idxDupe] == start - bytes)
                        dupe = 1;
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

    ropit_offsets_destroy(&rets);

    return valid;
}

int ropit_pointers_check_charset(uint64_t pointer,
                                 char *charset, size_t szCharset) {
    size_t idxCharset;
    unsigned char p[8] = {0};

    p[0] = pointer & 0xff;
    p[1] = (pointer >> 8) & 0xff;
    p[2] = (pointer >> 16) & 0xff;
    p[3] = (pointer >> 24) & 0xff;
    p[4] = (pointer >> 32) & 0xff;
    p[5] = (pointer >> 40) & 0xff;
    p[6] = (pointer >> 48) & 0xff;
    p[7] = (pointer >> 56) & 0xff;
    
    for (idxCharset = 0; idxCharset < szCharset; idxCharset++) {
    }

    return 0;
}

int ropit_pointers_check_pointer_characteristics() {
}

// check if inst is good
int ropit_instructions_check (char *inst, size_t len) {
    char *good[] = {
        // stack
        "pop", "push",
        "leave", "ret",
        "call",
        // arithmetic
        "adc", "add", "sbb", "sub", "imul", "mul", "idiv", "div",
        // shifts
        "rcl", "rcr", "rol", "ror", "sal", "sar", "shl", "shr",
        // memvalue
        "lea",
        "xadd", "xchg", "mov",
        // eflags
        "lahf", "sahf", "pushf", "popf",
        // converts
        "cbw", "cdq", "cwde", "cwd",
        // 
        "inc", "dec", 
        // logic
        "or", "and", "not", "neg", "xor",
        // jmp
        // "jmp", "jnz", "jne", "je", "jz",
        "bswap",
        "nop",
        "set", "sto",
        NULL
    };
    size_t idxGood;

    if (!inst)
        return 0;

    idxGood = 0;
    while (good[idxGood] != NULL) {
        if (strstr(inst, good[idxGood]))
            return 1;
        idxGood++;
    }

    return 0;
}

// find gadgets offsets
// construct gadgets from instructions finder
struct ropit_gadget_t* ropit_gadgets_find(unsigned char *bytes, size_t len, uint64_t base) {
    struct ropit_offsets_t *instructions = NULL;
    struct ropit_gadget_t *gadget = NULL;
    size_t idxGadget, idxInstruction;
    int pos = 0;             /* current position in buffer */
    int size;                /* size of instruction */
    int nInstructions;
    x86_insn_t insn;         /* instruction */
    // instruction str buffer
    char disassembled[DISASSEMBLED_SIZE_MAX] = {0};
    int disasLength;
    char gadgetline[GADGET_SIZE_MAX] =  {0};

    instructions = ropit_instructions_find(bytes, len);
    if (!instructions)
        return NULL;

    gadget = ropit_gadget_new(1024);
    if (!gadget)
        return NULL;

    // init disasm
    x86_init(opt_none, NULL, NULL);

    // we search for gadgets
    idxInstruction = 0;
    idxGadget = 0;
    while (idxInstruction < instructions->used) {
        if (idxGadget >= gadget->gadgets->capacity)
            gadget = ropit_gadget_realloc(gadget, gadget->gadgets->capacity * 2);
        // gadget start position
        pos = instructions->offsets[idxInstruction];
        gadget->gadgets->offsets[idxGadget] = pos;
        nInstructions = 0;
        // get gadgets
        do {
            /* disassemble address */
            size = x86_disasm(bytes, len, 0, pos, &insn);
            if (size) {
                disasLength = x86_format_insn(&insn, disassembled, DISASSEMBLED_SIZE_MAX, intel_syntax);
                x86_oplist_free(&insn);

                // filter out bad instructions
                if (ropit_instructions_check(disassembled, DISASSEMBLED_SIZE_MAX) == 0)
                    break;
                if (strstr(gadgetline, "ret"))
                    break;
                if (nInstructions >= 8)
                    break;

                // construct gadget
                strncat(gadgetline, COLOR_RED, GADGET_SIZE_MAX - strlen(gadgetline));
                strncat(gadgetline, disassembled, GADGET_SIZE_MAX - strlen(gadgetline));
                strncat(gadgetline, COLOR_PURPLE, GADGET_SIZE_MAX - strlen(gadgetline));
                strncat(gadgetline, " # ", GADGET_SIZE_MAX - strlen(gadgetline));
                gadgetline[GADGET_SIZE_MAX-1] = '\0';

                // go forward
                pos += size;
                nInstructions++;
            }
        } while (size);

        if (!strstr(gadgetline, "ret"))
            memset(gadgetline, 0, GADGET_SIZE_MAX);

        // if gadget found
        if (strlen(gadgetline) && nInstructions) {
            str_tabs2spaces(gadgetline, GADGET_SIZE_MAX);
            printf("%s%p: %s\n", COLOR_GREEN, (void *)(base + gadget->gadgets->offsets[idxGadget]), gadgetline);
            // for strncat() upper
            *gadgetline = '\0';
            gadget->gadgets->used++;
            idxGadget++;
        }

        idxInstruction++;
    }
    x86_cleanup();
    printf("%s\n", COLOR_WHITE);

    gadget->nInstructions = instructions->used;
    ropit_offsets_destroy(&instructions);

    return gadget;
}

// find gadgets in ELF file
struct ropit_gadget_t* ropit_gadgets_find_in_elf(char *filename) {
    ELF_FILE *elffile;
    struct ropit_gadget_t *gadgets;
    Elf32_Ehdr *elfHeader = NULL;
    Elf32_Phdr *programHeadersTable;
    size_t idxProgramSegment;
    //
    size_t nGadgets, nInstructions;

    elffile = ElfLoad(filename);
    if (!elffile) {
        fprintf(stderr, "ropit_gadgets_find_in_elf(): Failed loading ELF\n");
        return NULL;
    }

    if (ElfCheckArchitecture (elffile) == 0) {
        fprintf(stderr, "ropit_gadgets_find_in_elf(): Architecture not supported\n");
        ElfUnload(&elffile);
        return NULL;
    }

    elfHeader = ElfGetHeader(elffile);
    if (!elfHeader) {
        fprintf(stderr, "ropit_gadgets_find_in_elf(): Failed getting elfHeaders\n");
        return NULL;
    }

    // program segments parsing (sections are part of program segments)
    programHeadersTable = ElfGetProgramHeadersTable (elffile);
    if (!programHeadersTable) {
        fprintf(stderr, "ropit_gadgets_find_in_elf(): Failed getting Program Headers Table\n");
    }
    else {
        for (idxProgramSegment = 0, nGadgets = 0, nInstructions = 0; idxProgramSegment < elfHeader->e_phnum; idxProgramSegment++) {
            if (programHeadersTable[idxProgramSegment].p_flags & PF_X) {
                gadgets = ropit_gadgets_find(elffile->fmap->map + programHeadersTable[idxProgramSegment].p_offset,
                        programHeadersTable[idxProgramSegment].p_filesz,
                        programHeadersTable[idxProgramSegment].p_paddr);
                if (!gadgets)
                    continue;

                nGadgets += gadgets->gadgets->used;
                nInstructions += gadgets->nInstructions;

                ropit_gadget_destroy(&gadgets);
            }
        }
    }

    printf("\n== SUMMARY ==\n");
    printf("nInstructions: %s%lu\n", COLOR_YELLOW, nInstructions);
    printf("nGadgets: %s%lu\n", COLOR_YELLOW, nGadgets);
    printf("%s\n", COLOR_WHITE);

    ElfUnload(&elffile);

    return NULL;
}

// find gadgets in PE file
struct ropit_gadget_t* ropit_gadgets_find_in_pe(char *filename) {
    PE_FILE *pefile;
    struct ropit_gadget_t *gadgets;
    IMAGE_SECTION_HEADER *sectionHeadersTable;
    IMAGE_NT_HEADERS *ntHeader = NULL;
    size_t idxSection;
    //
    size_t nGadgets, nInstructions;

    pefile = PeLoad(filename);
    if (!pefile) {
        fprintf(stderr, "ropit_gadgets_find_in_pe(): Failed loading PE\n");
        return NULL;
    }

    if (PeCheckArchitecture (pefile) == 0) {
        fprintf(stderr, "ropit_gadgets_find_in_pe(): Architecture not supported\n");
        PeUnload(&pefile);
        return NULL;
    }

    ntHeader = PeGetNtHeader(pefile);
    if (!ntHeader) {
        fprintf(stderr, "ropit_gadgets_find_in_pe(): Failed getting NtHeaders\n");
        return NULL;
    }
    sectionHeadersTable = PeGetSectionHeaderTable(pefile);
    if (!sectionHeadersTable) {
        fprintf(stderr, "ropit_gadgets_find_in_pe(): Failed getting Section Headers Table\n");
        return NULL;
    }

    for (idxSection = 0, nGadgets = 0, nInstructions = 0; idxSection < ntHeader->FileHeader.NumberOfSections; idxSection++) {
        if (sectionHeadersTable[idxSection].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            gadgets = ropit_gadgets_find(pefile->fmap->map + sectionHeadersTable[idxSection].PointerToRawData,
                    sectionHeadersTable[idxSection].SizeOfRawData,
                    ntHeader->OptionalHeader.ImageBase + sectionHeadersTable[idxSection].VirtualAddress);
            if (!gadgets)
                continue;

            nGadgets += gadgets->gadgets->used;
            nInstructions += gadgets->nInstructions;

            ropit_gadget_destroy(&gadgets);
        }
    }

    printf("\n== SUMMARY ==\n");
    printf("nInstructions: %lu\n", nInstructions);
    printf("nGadgets: %lu\n", nGadgets);

    PeUnload(&pefile);

    return NULL;
}

// find gadgets in executable file
struct ropit_gadget_t* ropit_gadgets_find_in_executable(char *filename) {
    FILE *fp;
    struct ropit_gadget_t *gadgets;

    fp = fopen(filename, "r");
    if (!fp)
        return NULL;

    if (ElfCheck(fp))
        gadgets = ropit_gadgets_find_in_elf(filename);
    else if (PeCheck(fp))
        gadgets = ropit_gadgets_find_in_pe(filename);

    fclose(fp);

    return NULL;
}

// find gadgets in file
struct ropit_gadget_t* ropit_gadgets_find_in_file(char *filename) {
    FILE *fp = NULL;
    struct ropit_gadget_t *gadgets = NULL;
    struct filemap_t *fmap = NULL;

    if (!filename)
        return NULL;

    fp = fopen(filename, "r");
    if (!fp)
        goto ropit_gadgets_find_in_file_cleanup;

    fmap = filemap_create(fp);
    if (!fmap)
        goto ropit_gadgets_find_in_file_cleanup;

    gadgets = ropit_gadgets_find(fmap->map, fmap->szMap, 0);
    if (!gadgets)
        goto ropit_gadgets_find_in_file_cleanup;

    return gadgets;

ropit_gadgets_find_in_file_cleanup:
    fclose(fp);
    filemap_destroy(&fmap);
    ropit_gadget_destroy(&gadgets);

    return NULL;
}

char* ropit_listing_disasm (unsigned char *bytes, size_t len) {
    int pos = 0;             /* current position in buffer */
    int size;                /* size of instruction */
    x86_insn_t insn;         /* instruction */
    char line[4096] = {0};
    int linelen = 4096;
    char *listing = NULL;

    listing = calloc(2048, sizeof(*listing));

    x86_init(opt_none, NULL, NULL);
    while ( pos < len ) {
        /* disassemble address */
        size = x86_disasm(bytes, len, 0, pos, &insn);
        if ( size ) {
            /* print instruction */
            x86_format_insn(&insn, line, linelen, intel_syntax);
            // printf("%s\n", line);
            strcat(listing, line);
            strcat(listing, "\n");
            pos += size;
        }
        else {
            pos++;
        }
        x86_oplist_free(&insn);
    }
    x86_cleanup();

    return listing;
}

char* ropit_instructions_show (unsigned char *bytes, size_t len) {
    int size;                /* size of instruction */
    x86_insn_t insn;         /* instruction */
    char line[4096] = {0};
    int linelen = 4096;
    int idx;
    struct ropit_offsets_t *instructions;

    instructions = ropit_instructions_find(bytes, len);
    if (!instructions)
        return NULL;

    x86_init(opt_none, NULL, NULL);
    printf("used: %lu\n", instructions->used);
    for (idx = 0; idx < instructions->used; idx++) {
        size = x86_disasm(bytes, len, 0, instructions->offsets[idx], &insn);
        if ( size ) {
            x86_format_insn(&insn, line, linelen, intel_syntax);
            printf("instruction[%d] at offset %d with size %d: %s\n", idx, instructions->offsets[idx], size, line);
        }
        else {
            printf("this isn't an instruction\n");
        }
        x86_oplist_free(&insn);
    }
    x86_cleanup();

    ropit_offsets_destroy(&instructions);

    return NULL;
}


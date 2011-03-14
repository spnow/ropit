/*
    ROPit - Gadget generator tool
    Copyright (C) 2010  m_101

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

#include <string.h>
#include <ctype.h>

#include <libdis.h>
#include <pcre.h>

#include <file_pe.h>

#define BUF_SIZE    1024
#define LINE_SIZE   1024

#include "gadgets.h"

struct ropit_offsets_t* ropit_offsets_new(size_t nElt) {
    struct ropit_offsets_t *match = calloc(1, sizeof(*match));

    if (!match)
        return NULL;
    match->offsets = calloc(nElt, sizeof(*(match->offsets)));
    match->capacity = nElt;
    match->used = 0;

    return match;
}

struct ropit_offsets_t* ropit_offsets_realloc(struct ropit_offsets_t *ropmatch, size_t nElt) {
    if (!ropmatch)
        return NULL;

    ropmatch->offsets = realloc(ropmatch->offsets, nElt * sizeof(*(ropmatch->offsets)));
    ropmatch->capacity = nElt;

    return ropmatch;
}

void ropit_offsets_destroy(struct ropit_offsets_t **match) {
    if (!match)
        return;
    if (!*match)
        return;

    free((*match)->offsets);
    free(*match);
    *match = NULL;
}

size_t ropit_offsets_exist(struct ropit_offsets_t *array, int offset) {
    size_t idx;

    if (!array)
        return 0;

    for (idx = 0; idx < array->used; idx++) {
        if (array->offsets[idx] == offset) {
            return idx + 1;
        }
    }

    return 0;
}

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

// search jumps
// check address
int check_pointer(void *address) {
    return 0;
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
    valid = ropit_offsets_new(len * 1024);
    if (!valid)
        return NULL;

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

    ropit_offsets_destroy(&rets);

    qsort (valid->offsets, idxValid, sizeof(int), compare_ints);

    valid->used = idxValid;

    return valid;
}

struct ropit_gadget_t* ropit_gadget_new(size_t n) {
    struct ropit_gadget_t *gadget;

    gadget = calloc(1, sizeof(*gadget));
    if (!gadget)
        return NULL;

    gadget->repr = calloc(n, sizeof(*(gadget->repr)));
    gadget->nrepr = n;
    gadget->offsets = calloc(n, sizeof(*(gadget->offsets)));

    return gadget;
}

    struct ropit_gadget_t* ropit_gadget_realloc(struct ropit_gadget_t *gadget, size_t n) {
        if (!gadget)
            return NULL;

        printf("n: %lu\n", n);

        gadget->repr = realloc(gadget->repr, n * sizeof(*(gadget->repr)));
        gadget->nrepr = n;
        gadget->offsets = realloc(gadget->offsets, n * sizeof(*(gadget->offsets)));

        return gadget;
    }

void ropit_gadget_destroy(struct ropit_gadget_t **gadget) {
    size_t idxRepr;

    if (!gadget)
        return;
    if (!*gadget)
        return;
    if ((*gadget)->repr) {
        for (idxRepr = 0; idxRepr < (*gadget)->nrepr; idxRepr++) {
            if ((*gadget)->repr[idxRepr].malloced) {
                free((*gadget)->repr[idxRepr].str);
                (*gadget)->repr[idxRepr].str = NULL;
            }
        }
    }

    free((*gadget)->repr);
    free((*gadget)->offsets);
    ropit_offsets_destroy(&((*gadget)->instructions));
    free(*gadget);
    *gadget = NULL;
}

struct ropit_gadget_t* ropit_gadget_append (struct ropit_gadget_t *gadgets_list, struct ropit_gadget_t *gadgets) {
    struct ropit_gadget_t *wip;

    printf("sizeof(string_t): %lu\n", sizeof(*(gadgets->repr)));
    //
    if (!gadgets_list || !gadgets)
        return NULL;

    gadgets_list = ropit_gadget_realloc(gadgets_list, gadgets_list->nrepr + gadgets->nrepr);
    if (!gadgets_list)
        return NULL;
    memcpy(gadgets_list->offsets + gadgets_list->nrepr * sizeof(*(gadgets_list->offsets)),
            gadgets->offsets,
            gadgets->nrepr * sizeof(*(gadgets->offsets)));
    memcpy(gadgets_list->repr + gadgets_list->nrepr * sizeof(*(gadgets_list->repr)),
            gadgets->repr,
            gadgets->nrepr * sizeof(*(gadgets->repr)));

    gadgets_list->instructions = realloc(gadgets_list->instructions, (gadgets_list->instructions->used
                + gadgets->instructions->used)
            * sizeof(*(gadgets_list->instructions)));
    if (!gadgets_list->instructions) {
        ropit_gadget_destroy(&gadgets_list);
        return NULL;
    }

    memcpy(gadgets_list->instructions + gadgets_list->instructions->used * sizeof(*(gadgets_list->instructions)),
            gadgets->instructions,
            gadgets->instructions->used * sizeof(*(gadgets->instructions)));
    gadgets_list->instructions->used = gadgets_list->instructions->used + gadgets->instructions->used;

    return gadgets_list;
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
        if (strcasestr(inst, good[idxGood]))
            return 1;
        idxGood++;
    }

    return 0;
}

// find gadgets offsets
// construct gadgets from instructions finder
struct ropit_gadget_t* ropit_gadgets_find(unsigned char *bytes, size_t len, uint64_t base) {
    struct ropit_offsets_t *instructions = NULL, *rets = NULL;
    struct ropit_gadget_t *gadget = NULL;
    size_t idxGadget, idxInstruction, idxRet, idxOptim;
    int pos = 0;             /* current position in buffer */
    int size;                /* size of instruction */
    int nInstructions;
    x86_insn_t insn;         /* instruction */
    // store pointer to previous gadget
    char *previousGadget = NULL;
    // pointer to search gadget
    char *searchGadget = NULL;

    instructions = ropit_instructions_find(bytes, len);
    if (!instructions)
        return NULL;

    rets = ropit_opcodes_find_ret(bytes, len);
    if (!rets)
        return NULL;

    gadget = ropit_gadget_new(1024);
    if (!gadget)
        return NULL;

    // init disasm
    x86_init(opt_none, NULL, NULL);
    // we remove out rets in gadget start list
    for (idxInstruction = 0; idxInstruction < instructions->used; idxInstruction++) {
        if (ropit_offsets_exist(rets, instructions->offsets[idxInstruction])) {
            instructions->offsets[idxInstruction] = -1;
            instructions->used--;
        }
    }
    qsort (instructions->offsets, instructions->used, sizeof(int), compare_ints);

    // we search for gadgets
    idxInstruction = 0;
    for (idxRet = 0, idxGadget = 0; idxRet < rets->used; idxRet++) {
        while (idxInstruction < instructions->used) {
            if (idxGadget >= gadget->nrepr) {
                gadget = ropit_gadget_realloc(gadget, gadget->nrepr * 2);
            }
            // gadget start position
            pos = instructions->offsets[idxInstruction];
            gadget->offsets[idxGadget] = pos;
            char gadgetline[4096] = {0};
            nInstructions = 0;
            // get gadgets
            do {
                char line[4096] = {0};
                int linelen = 4096;
                /* disassemble address */
                size = x86_disasm(bytes, len, 0, pos, &insn);
                if (size) {
                    x86_format_insn(&insn, line, linelen, intel_syntax);
                    x86_oplist_free(&insn);

                    // filter out bad instructions
                    if (ropit_instructions_check(line, linelen) == 0) {
                        memset(line, 0, 4096);
                        break;
                    }
#ifdef DEBUG
                    snprintf(gadgetline, 4096, "%s #%u %s", gadgetline, pos, line);
#else
                    strncat(gadgetline, line, 4096 - strlen(gadgetline));
                    strncat(gadgetline, " # ", 4096 - strlen(gadgetline));
                    gadgetline[4095] = '\0';
#endif
                    pos += size;
                    nInstructions++;
                }
                if (strcasestr(gadgetline, "ret"))
                    break;
                if (nInstructions >= 8)
                    break;
            } while (size);

            if (!strcasestr(gadgetline, "ret"))
                memset(gadgetline, 0, 4096);

            // if gadget found
            if (strlen(gadgetline) && nInstructions) {
                /*
                for (idxOptim = 0; idxOptim < idxGadget; idxOptim++) {
                    // memory optimization
                    searchGadget = strcasestr(gadget->repr[idxOptim].str, gadgetline);
                    if (searchGadget)
                        break;
                }
                // memory optimization
                if (searchGadget) {
                    gadget->repr[idxGadget].str = searchGadget;
                    gadget->repr[idxGadget].malloced = 0;
                    }
                    else {
                    gadget->repr[idxGadget].str = strdup(gadgetline);
                    gadget->repr[idxGadget].malloced = 1;
                    }
                //*/

                printf("%p: %s\n", base + gadget->offsets[idxGadget], gadgetline);

                // gadget->repr[idxGadget].len = strlen(gadgetline);
                gadget->repr[idxGadget].malloced = 0;
                // previousGadget = gadget->repr[idxGadget].str;
                idxGadget++;
            }

            idxInstruction++;
        }
    }
    x86_cleanup();

    ropit_offsets_destroy(&rets);
    qsort (instructions->offsets, idxGadget, sizeof(int), compare_ints);

    gadget->instructions = instructions;
    gadget->nrepr = idxGadget;

    return gadget;
}

// find gadgets in executable file
struct ropit_gadget_t* ropit_gadgets_find_in_executable(char *filename) {
    PE_FILE *pefile;
    struct ropit_gadget_t *gadgets, *gadget_list;
    IMAGE_SECTION_HEADER *sectionHeadersTable;
    IMAGE_NT_HEADERS *ntHeader = NULL;
    size_t idxSection, idxGadget;
    //
    size_t nGadgets, nInstructions;

    pefile = PeLoad(filename);
    if (!pefile) {
        fprintf(stderr, "ropit_gadgets_find_in_executable(): Failed loading PE\n");
        return NULL;
    }

    ntHeader = PeGetNtHeader(pefile);
    if (!ntHeader) {
        fprintf(stderr, "ropit_gadgets_find_in_executable(): Failed getting NtHeaders\n");
        return NULL;
    }
    sectionHeadersTable = PeGetSectionHeaderTable(pefile);
    if (!sectionHeadersTable) {
        fprintf(stderr, "ropit_gadgets_find_in_executable(): Failed getting Section Headers Table\n");
        return NULL;
    }

    gadget_list = ropit_gadget_new(1024);

    for (idxSection = 0, nGadgets = 0; idxSection < ntHeader->FileHeader.NumberOfSections; idxSection++) {
        if (sectionHeadersTable[idxSection].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            gadgets = ropit_gadgets_find(pefile->fmap->map + sectionHeadersTable[idxSection].PointerToRawData,
                    sectionHeadersTable[idxSection].SizeOfRawData,
                    ntHeader->OptionalHeader.ImageBase + sectionHeadersTable[idxSection].VirtualAddress);
            if (!gadgets)
                continue;

            nGadgets += gadgets->nrepr;
            nInstructions += gadgets->instructions->used;

            // gadget_list = ropit_gadget_append(gadget_list, gadgets);
            /*
               for (idxGadget = 0; idxGadget < gadgets->nrepr; idxGadget++) {
               printf("%p: %s\n", ntHeader->OptionalHeader.ImageBase
               + sectionHeadersTable[idxSection].VirtualAddress
               + gadgets->offsets[idxGadget],
               gadgets->repr[idxGadget].str);
               }
            //*/
            ropit_gadget_destroy(&gadgets);
        }
    }

    printf("\n== SUMMARY ==\n");
    printf("nInstructions: %lu\n", nInstructions);
    printf("nGadgets: %lu\n", nGadgets);

    PeUnload(&pefile);
    ropit_gadget_destroy(&gadget_list);

    return NULL;
}

// find gadgets in file
struct ropit_gadget_t* ropit_gadgets_find_in_file(char *filename) {
    FILE *fp = NULL;
    struct ropit_gadget_t *gadgets = NULL;
    size_t idxGadget;
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


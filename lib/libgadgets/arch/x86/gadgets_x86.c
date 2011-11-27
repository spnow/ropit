#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libdis.h>

#include "offsets.h"
#include "gadgets_x86.h"
#include "../arch.h"

static const char * jcc_insns[] = {
        "ja", "jae", "jb", "jbe", "jc", "jcxz", "jecxz", 
        "jrcxz", "je", "jg", "jge", "jl", "jle", "jna", "jnae", "jnb", "jnbe",
        "jnc", "jne", "jng", "jnge", "jnl", "jnle", "jno", "jnp", "jns", "jnz",
        "jo", "jp", "jpe", "js", "jz"
};

static const char * call_insns[] = { "lcall", "call", "callq" };

static const char * jmp_insns[] = { "jmp", "ljmp", "jmpq" };

static const char * ret_insns[] = {
        "ret", "lret", "retq", "retf", "iret", "iretd", "iretq"
};

int gadgets_x86_init (void) {
}

// search rets
struct ropit_offsets_t* ropit_opcodes_find_ret(uint8_t *bytes, int len) {
    uint8_t opcodes[] = "\xc3\xc2\xca\xcb\xcf";
    struct ropit_offsets_t *rets = ropit_opcodes_find(bytes, len, opcodes, strlen((char*)opcodes), 1);

    return rets;
}

struct ropit_offsets_t* ropit_filter_ppr(uint8_t *bytes, int len) {
    return ropit_filter_regexp(bytes, len, "(pop\\s+\\w{3}\\s+){2}\\s*ret");
}

// check if inst is good
int ropit_instructions_check (char *inst, int len) {
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
        "jmp", "jnz", "jne", "je", "jz",
        "bswap",
        "nop",
        "set", "sto",
        NULL
    };
    int idxGood;

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

char* ropit_listing_disasm (uint8_t *bytes, int len) {
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

char* ropit_instructions_show (uint8_t *bytes, int len) {
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
    printf("used: %d\n", instructions->used);
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


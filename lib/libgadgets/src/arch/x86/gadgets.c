#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libdis.h>

#include "arch/arch.h"
#include "offsets.h"
#include "gadgets.h"

struct offsets_t* ropit_x86_find_rets(uint8_t *bytes, int len);
struct offsets_t* ropit_x86_find_gadgets(uint8_t *bytes, int len);

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
    struct gadget_plugin_t *plugin = gadget_plugin_new ();

    if (!plugin)
        return -1;

    // arguments
	plugin->name = strdup ("Intel x86");
	plugin->arch = strdup ("x86");
	plugin->desc = strdup ("Intel x86 Architecture");

    // methods
    plugin->find_gadgets = ropit_x86_find_gadgets;
    plugin->find_rets = ropit_x86_find_rets;
}

int compare_uint64 (const void * a, const void * b) {
    return ( *(uint64_t*)a - *(uint64_t*)b );
}

// search rets
struct offsets_t *ropit_x86_find_rets (uint8_t *bytes, int len) {
    int idx_byte, idx_op, idx_ret;
    uint8_t opcodes[] = "\xc3\xc2\xca\xcb";
    struct offsets_t *rets;

    if (!bytes || len <= 0) {
        return NULL;
    }

    rets = offsets_new(len);
    if (!rets) 
        return NULL;

    // search for rets in bytes
    printf("total bytes: %d\n", len);
    printf("sizeof(opcodes): %d\n", sizeof(opcodes));
    idx_ret = 0;
    for (idx_byte = 0; idx_byte < len; idx_byte++) {
        for (idx_op = 0; idx_op < (sizeof(opcodes) - 1); idx_op++) {
            if (bytes[idx_byte] == opcodes[idx_op]) {
                rets->offsets[idx_ret] = idx_byte;
                idx_ret++;
                break;
            }
        }
    }
    
    printf ("there are %d bytes\n", idx_byte);
    printf ("there are %d rets\n", idx_ret);

    qsort (rets->offsets, idx_ret, sizeof(*rets->offsets), compare_uint64);
    rets->used = idx_ret;

    printf ("sizeof(*rets->offsets) : %d\n", sizeof(*rets->offsets));
    printf ("sizeof(*(rets->offsets)) : %d\n", sizeof(*(rets->offsets)));
    printf ("sizeof(int) : %d\n", sizeof(int));

    return rets;
}

struct offsets_t* ropit_filter_ppr(uint8_t *bytes, int len) {
    return ropit_filter_regexp(bytes, len, "(pop\\s+\\w{3}\\s+){2}\\s*ret");
}

// check if inst is good
int ropit_x86_check_inst (char *inst, int len) {
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
    int idx_good;

    if (!inst)
        return 0;

    idx_good = 0;
    while (good[idx_good] != NULL) {
        if (strstr(inst, good[idx_good]))
            return 1;
        idx_good++;
    }

    return 0;
}

char *ropit_x86_list_disasm (uint8_t *bytes, int len) {
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

//char *ropit_instructions_show (uint8_t *bytes, int len) {
//    int size;                /* size of instruction */
//    x86_insn_t insn;         /* instruction */
/*
   char line[4096] = {0};
   int linelen = 4096;
   int idx;
   struct offsets_t *instructions;

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

   offsets_destroy(&instructions);

   return NULL;
   }
   */

#define DISASSEMBLED_SIZE_MAX 1024
// find valid instructions offsets before ret
struct offsets_t *_ropit_x86_find_gadgets (uint8_t *bytes, int len, int64_t *rets, int n_rets) {
    int sz_ret;
    int sz_inst;                /* size of instruction */
    x86_insn_t insn;         /* instruction */
    int idx_ret;
    int valid_gadget;
    // dupe variables
    int idx_dupe, dupe;
    // back track instruction count
    int n_backtrackInst, n_backtrackBytes;
    // start for rop search
    uint8_t *start, *gadget_start;
    // disassemble
    int disasLength;
    char disassembled[DISASSEMBLED_SIZE_MAX] = {0};

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

    // init disasm
    x86_init(opt_none, NULL, NULL);

    for (idx_ret = 0; idx_ret < n_rets; idx_ret++) {
        start = bytes + rets[idx_ret];

        n_backtrackInst = 0;
        n_backtrackBytes = 0;
        while ( bytes <= start && start <= bytes + len ) {
            /* disassemble address */
            sz_inst = x86_disasm(start, len - (start - bytes), 0, 0, &insn);
            x86_oplist_free(&insn);

            if (!sz_inst) {
                // printf("not found inst\n");
                n_backtrackBytes++;
            }
            else {
                // printf("found inst\n");
                sz_ret = 0;
                n_backtrackBytes = 0;
                n_backtrackInst++;

                // check gadget validity
                gadget_start = --start;
                valid_gadget = 0;
                while ( bytes <= gadget_start && gadget_start <= bytes + rets[idx_ret] ) {
                    /* disassemble address */
                    sz_inst = x86_disasm(gadget_start, gadget_start - bytes, 0, 0, &insn);
                    x86_oplist_free(&insn);
                    if (sz_inst)
                        gadget_start += sz_inst;
                    else
                        break;

                    if (gadget_start == bytes + rets[idx_ret]) {
                        valid_gadget = 1;
                        break;
                    }
                }

                /*
                   printf("gadget_start: 0x%p\n", gadget_start);
                   printf("bytes + rets[idx_ret]: 0x%p\n\n", bytes + rets[idx_ret]);
                //*/

                if (valid_gadget == 1) {
                    // show ret
                    //*
                    sz_ret = x86_disasm (bytes + rets[idx_ret], len - rets[idx_ret], 0, 0, &insn);
                    disasLength = x86_format_insn(&insn, disassembled, DISASSEMBLED_SIZE_MAX, intel_syntax);
                    printf("ret 0x%08x: %s\n", rets[idx_ret], disassembled);
                    x86_oplist_free(&insn);
                    //*/

                    // printf("got a good gadget\n");
                    gadget_start = start;
                    while ( start <= gadget_start && gadget_start < bytes + rets[idx_ret] + sz_ret ) {
                        /* disassemble address */
                        sz_inst = x86_disasm(gadget_start, gadget_start - bytes, 0, 0, &insn);
                        if (sz_inst) {
                            disasLength = x86_format_insn(&insn, disassembled, DISASSEMBLED_SIZE_MAX, intel_syntax);
                            printf("0x%08x: %s\n", gadget_start - bytes, disassembled);

                            gadget_start += sz_inst;
                        }
                        x86_oplist_free(&insn);
                    }
                    putchar('\n');
                }
            }
            --start;

            // maximum intel instruction size is 15
            if (n_backtrackBytes >= 15 || n_backtrackInst == 8)
                break;
        }
    }
    x86_cleanup();

    return 0;
}

// find valid instructions offsets before ret
struct offsets_t *ropit_x86_find_gadgets (uint8_t *bytes, int len)
{
    struct offsets_t *rets, *instructions;

    // search rets
    rets = ropit_x86_find_rets(bytes, len);
    if (!rets) {
        fprintf(stderr, "error: gadgets_find(): No rets\n");
        return NULL;
    }
    instructions = _ropit_x86_find_gadgets (bytes, len, rets->offsets, rets->used);

    offsets_destroy(&rets);
    offsets_destroy(&instructions);

    return 0;
}


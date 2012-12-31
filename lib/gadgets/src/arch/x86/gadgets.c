#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <libdis.h>

#include <fall4c/fall4c.h>
#include "arch/arch.h"
#include "offsets.h"
#include "gadgets.h"
#include "gadgets_cache.h"

struct offsets_t* ropit_x86_find_rets(uint8_t *bytes, int len);
struct offsets_t* ropit_x86_find_gadgets(uint8_t *bytes, int len);

struct gadget_plugin_t x86_gadget_plugin = {
	.name = "Intel x86",
	.arch = "x86",
	.desc = "Intel x86 Architecture",

    // methods
    .init = plugin_no_init,
    .fini = plugin_no_fini,
    .find_gadgets = ropit_x86_find_gadgets,
    .find_rets = ropit_x86_find_rets,
    .find_branches = plugin_no_find_branches
};

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

// init x86 gadget plugin
struct gadget_plugin_t *gadgets_x86_init (void)
{
    struct gadget_plugin_t *plugin;

    plugin = gadget_plugin_new ();
    if (!plugin)
        return -1;

    // arguments
	plugin->name = strdup ("Intel x86");
	plugin->arch = strdup ("x86");
	plugin->desc = strdup ("Intel x86 Architecture");

    // methods
    plugin->find_gadgets = ropit_x86_find_gadgets;
    plugin->find_rets = ropit_x86_find_rets;

    return plugin;
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
    debug_printf (MESSAGE_INFO, stdout, "info : ropit_x86_find_rets(): total bytes: %d\n", len);
    debug_printf (MESSAGE_INFO, stdout, "info : ropit_x86_find_rets(): sizeof(opcodes): %d\n", sizeof(opcodes));
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
    
    debug_printf (MESSAGE_INFO, stdout, "info : ropit_x86_find_rets(): there are %d bytes\n", idx_byte);
    debug_printf (MESSAGE_INFO, stdout, "info : ropit_x86_find_rets(): there are %d rets\n", idx_ret);

    qsort (rets->offsets, idx_ret, sizeof(*rets->offsets), compare_uint64);
    rets->used = idx_ret;

    debug_printf (MESSAGE_INFO, stdout, "info : ropit_x86_find_rets(): sizeof(*rets->offsets) : %d\n", sizeof(*rets->offsets));
    debug_printf (MESSAGE_INFO, stdout, "info : ropit_x86_find_rets(): sizeof(*(rets->offsets)) : %d\n", sizeof(*(rets->offsets)));
    debug_printf (MESSAGE_INFO, stdout, "info : ropit_x86_find_rets(): sizeof(int) : %d\n", sizeof(int));

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
    int pos = 0;             // current position in buffer
    int size;                // size of instruction
    x86_insn_t insn;         // instruction
    char line[4096] = {0};
    int linelen = 4096;
    char *listing = NULL;

    listing = calloc(2048, sizeof(*listing));

    x86_init(opt_none, NULL, NULL);
    while ( pos < len ) {
        // disassemble address
        size = x86_disasm(bytes, len, 0, pos, &insn);
        if ( size ) {
            // print instruction
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

// disasm 1 instruction
char *ropit_x86_disasm (uint8_t *bytes, int len, int *sz_dis)
{
    int sz_inst, len_disasm;             /* sz_inst of instruction */
    x86_insn_t insn;         /* instruction */
    char line[1024];
    int sz_line = 1024;
    char *disasm;

    if (!bytes || len <= 0 || !sz_dis) {
        debug_printf (MESSAGE_ERROR, stderr, "error: ropit_x86_disasm(): Bad parameter(s)\n");
        return NULL;
    }

    len_disasm = 0;

    x86_init(opt_none, NULL, NULL);
    sz_inst = x86_disasm (bytes, len, 0, 0, &insn);
    if (sz_inst > 0) {
        len_disasm = x86_format_insn (&insn, line, sz_line, intel_syntax);
        *sz_dis = sz_inst;
    }
    x86_oplist_free (&insn);
    x86_cleanup();

    if (len_disasm == 0)
        return NULL;

    disasm = calloc (len_disasm, sizeof(*disasm));
    if (!disasm) {
        debug_printf (MESSAGE_ERROR, stderr, "error: ropit_x86_disasm(): Failed disasm alloc\n");
        return NULL;
    }

    memcpy (disasm, line, len_disasm);

    return disasm;
}

#define DISASSEMBLED_SIZE_MAX 1024
// find valid instructions offsets before ret
struct offsets_t *_ropit_x86_find_gadgets (uint8_t *bytes, int len, int64_t *rets, int n_rets) {
    int sz_inst;                /* size of instruction */
    x86_insn_t insn;         /* instruction */
    int idx_ret, sz_ret;
    int valid_gadget;
    // back track instruction count
    int n_backtrack_inst, n_backtrack_bytes;
    // start for rop search
    uint8_t *start, *gadget_start;
    // disassemble
    int len_disasm;
    int sz_dst;
    char disassembled[DISASSEMBLED_SIZE_MAX] = {0};
    // cache
    FILE *fp_cache;
    struct cache_t *caches;
    int idx_caches, n_caches;
    struct gadget_t *gadgets;
    int idx_gadgets, n_gadgets;
    // cache queue
    struct gadget_cache_queue_t *cache_queue;

    // check params
    if (!bytes || len <= 0) {
        debug_printf (MESSAGE_ERROR, stderr, "error: _ropit_x86_find_gadgets(): Bytes null or len <= 0\n");
        return NULL;
    }

    // search rets
    if (!rets || n_rets <= 0) {
        debug_printf (MESSAGE_ERROR, stderr, "error: _ropit_x86_find_gadgets(): No rets\n");
        return NULL;
    }

    // init gadget_cache
    fp_cache = fopen("tmp/gadget_cache", "w");
    if (!fp_cache) {
        debug_printf (MESSAGE_ERROR, stderr, "error: _ropit_x86_find_gadgets(): Failed open (w)\n");
        return NULL;
    }

    // init cache_queue
    cache_queue = NULL;
    if (!gadget_cache_queue_init(&cache_queue)) {
        debug_printf (MESSAGE_ERROR, stderr, "error: _ropit_x86_find_gadgets(): Cache queue allocation failed\n");
        return NULL;
    }
    gadget_cache_queue_set_file (cache_queue, fp_cache);

    // init gadgets
    n_gadgets = 1024;
    gadgets = calloc(sizeof(struct gadget_t), n_gadgets);
    if (!gadgets) {
        debug_printf (MESSAGE_ERROR, stderr, "error: _ropit_x86_find_gadgets(): Failed allocating caches\n");
        return NULL;
    }

    for (idx_gadgets = 0; idx_gadgets < n_gadgets; idx_gadgets++)
        gadget_init(&(gadgets[idx_gadgets]), DISASSEMBLED_SIZE_MAX);

    // init caches
    n_caches = 1;
    caches = calloc(sizeof(struct cache_t), n_caches);
    if (!caches) {
        debug_printf (MESSAGE_ERROR, stderr, "error: _ropit_x86_find_gadgets(): Failed allocating caches\n");
        return NULL;
    }

    for (idx_caches = 0; idx_caches < n_caches; idx_caches++) {
        cache_init(&(caches[idx_caches]), 1024);
    }

    gadget_cache_queue_set_file(&cache_queue, fp_cache);

    // init disasm
    x86_init(opt_none, NULL, NULL);

    idx_caches = 0;
    idx_gadgets = 0;
    for (idx_ret = 0; idx_ret < n_rets; idx_ret++) {
        start = bytes + rets[idx_ret];

        n_backtrack_inst = 0;
        n_backtrack_bytes = 0;
        while ( bytes <= start && start <= bytes + len ) {
            /* disassemble address */
            sz_inst = x86_disasm(start, len - (start - bytes), 0, 0, &insn);
            x86_oplist_free(&insn);

            if (!sz_inst) {
                // printf("not found inst\n");
                n_backtrack_bytes++;
            }
            else {
                // printf("found inst\n");
                n_backtrack_bytes = 0;
                n_backtrack_inst++;

                // check gadget validity
                gadget_start = --start;
                valid_gadget = 0;
                while ( bytes <= gadget_start && gadget_start <= bytes + rets[idx_ret] ) {
                    /* disassemble address */
                    sz_inst = x86_disasm(gadget_start, gadget_start - bytes, 0, 0, &insn);
                    x86_oplist_free(&insn);
                    if (sz_inst > 0)
                        gadget_start += sz_inst;
                    else
                        break;

                    if (gadget_start == bytes + rets[idx_ret]) {
                        valid_gadget = 1;
                        break;
                    }
                }

                if (valid_gadget == 1) {
                    // get ret size
                    sz_ret = x86_disasm(gadget_start, bytes + rets[idx_ret], 0, 0, &insn);
                    x86_oplist_free(&insn);

                    // fill gadget structure
                    gadgets[idx_gadgets].ret_addr = rets[idx_ret];
                    gadgets[idx_gadgets].ret_bytes = rets[idx_ret] + bytes;
                    gadgets[idx_gadgets].address = start - bytes;
                    gadgets[idx_gadgets].len_bytes = (rets[idx_ret] - (start - bytes)) + sz_ret;
                    if (gadgets[idx_gadgets].sz_bytes < gadgets[idx_gadgets].len_bytes) {
                        gadgets[idx_gadgets].bytes = realloc (gadgets[idx_gadgets].bytes, gadgets[idx_gadgets].len_bytes);
                        gadgets[idx_gadgets].sz_bytes = gadgets[idx_gadgets].len_bytes;
                    }
                    memcpy(gadgets[idx_gadgets].bytes, start, gadgets[idx_gadgets].len_bytes);

                    /*
                    // construct repr
                    gadget_start = start;
                    gadgets[idx_gadgets].len_repr = 0;
                    sz_dst = gadgets[idx_gadgets].sz_repr;
                    gadgets[idx_gadgets].repr[0] = '\0';
                    while ( start <= gadget_start && gadget_start <= bytes + rets[idx_ret] ) {
                        /  disassemble address
                        sz_inst = x86_disasm(gadget_start, gadget_start - bytes, 0, 0, &insn);
                        gadget_start += sz_inst;
                        if (sz_inst <= 0) {
                            x86_oplist_free(&insn);
                            break;
                        }
                        else {
                            len_disasm = x86_format_insn(&insn, disassembled, DISASSEMBLED_SIZE_MAX, intel_syntax);
                            x86_oplist_free(&insn);
                            str_replace_chr(disassembled, len_disasm, '\t', ' ');

                            if (sz_dst <= 0)
                                continue;

                            // copy disassembly
                            strncat (gadgets[idx_gadgets].repr + gadgets[idx_gadgets].len_repr, disassembled, sz_dst);
                            gadgets[idx_gadgets].len_repr += len_disasm;
                            sz_dst -= len_disasm;

                            // copy separation
                            strncat (gadgets[idx_gadgets].repr + gadgets[idx_gadgets].len_repr, " # ", sz_dst);
                            gadgets[idx_gadgets].len_repr += 3;
                            sz_dst -= 3;
                        }
                    }
                    //*/

                    if (cache_add (&(caches[idx_caches]), &(gadgets[idx_gadgets])) == -ERR_CACHE_FULL) {
                        gadget_cache_queue_add (cache_queue, &(caches[idx_caches]));
                        gadget_cache_queue_fwrite_worker (cache_queue);
                        cache_reset (&(caches[idx_caches]));
                    }

                    idx_gadgets = (idx_gadgets + 1) % n_gadgets;
                }
            }
            --start;

            // maximum intel instruction size is 15
            if (n_backtrack_bytes >= 15 || n_backtrack_inst == 8)
                break;
        }
    }
    x86_cleanup();

    // write remaining gadgets
    gadget_cache_queue_add (cache_queue, &(caches[idx_caches]));
    gadget_cache_queue_fwrite_worker (cache_queue);
    cache_reset (&(caches[idx_caches]));

    // clean up
    for (idx_caches = 0; idx_caches < n_caches; idx_caches++)
        free(caches[idx_caches].objects);
    free(caches);

    //*
    for (idx_gadgets = 0; idx_gadgets < n_gadgets; idx_gadgets++) {
        // gadget_free(&(gadgets[idx_gadgets]));
        // free (gadgets[idx_gadgets].repr);
        free (gadgets[idx_gadgets].bytes);
    }
    //*/
    free(gadgets);

    gadget_cache_queue_destroy (&cache_queue);

    fclose (fp_cache);

    return 0;
}

// find valid instructions offsets before ret
struct offsets_t *ropit_x86_find_gadgets (uint8_t *bytes, int len)
{
    struct offsets_t *rets, *instructions;

    if (!bytes || len <= 0) {
        return NULL;
    }

    // search rets
    rets = ropit_x86_find_rets(bytes, len);
    if (!rets) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadgets_find(): No rets\n");
    }
    instructions = _ropit_x86_find_gadgets (bytes, len, rets->offsets, rets->used);

    offsets_destroy(&rets);
    offsets_destroy(&instructions);

    return 0;
}


#include <stdio.h>
#include <stdlib.h>

#include <libdis.h>

#include "gadgets.h"
#include "gadgets_cache.h"
#include "arch/x86/gadget_output.h"

/* formatting gadget as stack:
addr  : inst 1
addr+x: inst 2
...
*/
int gadget_output_format_stack (FILE *fp_out, struct gadget_t *gadget, int color)
{
    //
    int sz_inst;
    //
    char line[1024];
    int len_line = 1024, len_disasm;
    //
    char *bytes;
    int len;
    uint64_t addr;
    x86_insn_t insn;         /* instruction */
    //
    int n_disasm;

    if (!fp_out || !gadget) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadget_output_format_stack(): Bad parameter(s)\n");
        return -1;
    }

    bytes = gadget->bytes;
    len = gadget->len_bytes;
    addr = gadget->address;

    x86_init (opt_none, NULL, NULL);
    while (bytes < (gadget->bytes + gadget->len_bytes)) {
        sz_inst = x86_disasm (bytes, len, 0, 0, &insn);
        if (sz_inst > 0) {
            len_disasm = x86_format_insn(&insn, line, len_line, intel_syntax);
            n_disasm++;
        }
        else
            sz_inst = 0;
        x86_oplist_free(&insn);

        str_replace_chr(line, len_disasm, '\t', ' ');
        if (!color)
            fprintf (fp_out, "%p: %s\n", addr, line);
        else {
            fprintf (fp_out, COLOR_RED "%p: " COLOR_GREEN "%s\n", addr, line);
            fprintf (fp_out, "%s", COLOR_WHITE);
        }

        addr += sz_inst;
        bytes += sz_inst;
        len -= sz_inst;
    }
    x86_cleanup();

    if (gadget->len_bytes)
        fprintf (fp_out, "\n");

    return n_disasm;
}

/* formatting gadget as line:
addr  : inst 1 # inst 2
...
*/
int gadget_output_format_line (FILE *fp_out, struct gadget_t *gadget, int color)
{
    //
    int sz_inst;
    //
    char line[1024];
    int len_line = 1024, len_disasm;
    //
    char *bytes;
    int len;
    uint64_t addr;
    x86_insn_t insn;         /* instruction */
    //
    int n_disasm;

    if (!fp_out || !gadget) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadget_output_format_stack(): Bad parameter(s)\n");
        return -1;
    }

    bytes = gadget->bytes;
    len = gadget->len_bytes;
    addr = gadget->address;

    n_disasm = 0;
    x86_init (opt_none, NULL, NULL);
    while (bytes < (gadget->bytes + gadget->len_bytes)) {
        sz_inst = x86_disasm (bytes, len, 0, 0, &insn);
        if (sz_inst > 0) {
            len_disasm = x86_format_insn(&insn, line, len_line, intel_syntax);
            n_disasm++;
        }
        else
            sz_inst = 0;
        x86_oplist_free(&insn);

        str_replace_chr(line, len_disasm, '\t', ' ');
        if (!color) {
            if (bytes == gadget->bytes)
                fprintf (fp_out, "%p: %s # ", addr, line);
            else
                fprintf (fp_out, "%s # ", line);
        }
        else {
            if (bytes == gadget->bytes)
                fprintf (fp_out, COLOR_RED "%p: " COLOR_GREEN "%s" COLOR_PURPLE " # ", addr, line);
            else
                fprintf (fp_out, COLOR_GREEN "%s" COLOR_PURPLE " # ", line);
            fprintf (fp_out, "%s", COLOR_WHITE);
        }

        addr += sz_inst;
        bytes += sz_inst;
        len -= sz_inst;
    }
    x86_cleanup();

    if (gadget->len_bytes)
        fprintf (fp_out, "\n");

    return n_disasm;
}


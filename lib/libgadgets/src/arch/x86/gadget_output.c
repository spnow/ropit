#include <stdio.h>
#include <stdlib.h>

#include <libdis.h>

#include "gadgets.h"
#include "arch/x86/gadget_output.h"

/* formatting gadget as stack:
addr  : inst 1
addr+x: inst 2
...
*/
int gadget_output_format_stack (struct gadget_t *gadget, int color)
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

    if (!gadget) {
        fprintf (stderr, "error: gadget_output_format_stack(): Bad parameter(s)\n");
        return -1;
    }

    bytes = gadget->bytes;
    len = gadget->len_bytes;
    addr = gadget->address;

    x86_init (opt_none, NULL, NULL);
    while (bytes < (gadget->bytes + gadget->len_bytes)) {
        sz_inst = x86_disasm (bytes, len, 0, 0, &insn);
        if (sz_inst > 0)
            len_disasm = x86_format_insn(&insn, line, len_line, intel_syntax);
        else
            sz_inst = 0;
        x86_oplist_free(&insn);

        str_replace_chr(line, len_disasm, '\t', ' ');
        if (!color)
            printf ("%p: %s\n", addr, line);
        else {
            printf (COLOR_RED "%p: " COLOR_GREEN "%s\n", addr, line);
            printf ("%s", COLOR_WHITE);
        }

        addr += sz_inst;
        bytes += sz_inst;
        len -= sz_inst;
    }
    x86_cleanup();

    putchar ('\n');

    return 0;
}

/* formatting gadget as line:
addr  : inst 1 # inst 2
...
*/
int gadget_output_format_line (struct gadget_t *gadget, int color)
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

    if (!gadget) {
        fprintf (stderr, "error: gadget_output_format_stack(): Bad parameter(s)\n");
        return -1;
    }

    bytes = gadget->bytes;
    len = gadget->len_bytes;
    addr = gadget->address;

    x86_init (opt_none, NULL, NULL);
    while (bytes < (gadget->bytes + gadget->len_bytes)) {
        sz_inst = x86_disasm (bytes, len, 0, 0, &insn);
        if (sz_inst > 0)
            len_disasm = x86_format_insn(&insn, line, len_line, intel_syntax);
        else
            sz_inst = 0;
        x86_oplist_free(&insn);

        str_replace_chr(line, len_disasm, '\t', ' ');
        if (!color) {
            if (bytes == gadget->bytes)
                printf ("%p: %s # ", addr, line);
            else
                printf ("%s # ", line);
        }
        else {
            if (bytes == gadget->bytes)
                printf (COLOR_RED "%p: " COLOR_GREEN "%s" COLOR_PURPLE " # ", addr, line);
            else
                printf (COLOR_GREEN "%s" COLOR_PURPLE " # ", line);
            printf ("%s", COLOR_WHITE);
        }

        addr += sz_inst;
        bytes += sz_inst;
        len -= sz_inst;
    }
    x86_cleanup();

    putchar ('\n');

    return 0;
}


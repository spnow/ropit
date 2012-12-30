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

#include "arch/arch.h"
#include "arch/x86/gadgets.h"
#include "gadgets_cache.h"
#include "gadgets_find.h"
#include "file_pe.h"
#include "file_elf.h"
#include "ropit_options.h"

int main (int argc, char *argv[]) {
    FILE *fp_file;
    FILE *fp_cache;
    FILE *fp_out;
    int countGadgets;
    struct gadget_plugin_t *plugin;

    if (argc < 2) {
        banner();
        usage(argv[0]);
        return -1;
    }
    banner();

    parse_options (argc, argv);

    plugin = gadgets_x86_init();
    if (!plugin) {
        fprintf(stderr, "error: main(): Failed init x86 gadget plugin\n");
        return -1;
    }

    fp_file = fopen(config.filename_input, "r");
    if (!fp_file) {
        fprintf(stderr, "error: main(): Failed opening file '%s' (r)\n", config.filename_input);
        return -2;
    }

    if (ElfCheck(fp_file) || PeCheck(fp_file))
        gadgets_find_in_executable(config.filename_input);
    else
        gadgets_find_in_file (plugin, config.filename_input);
    fclose(fp_file);
    gadget_plugin_destroy (&plugin);

    fp_cache = fopen("tmp/gadget_cache", "rb");
    if (!fp_cache)
        return -1;
    printf("showing gadgets in cache\n");

    if (config.filename_output == NULL)
        fp_out = stdout;
    else
        fp_out = fopen(config.filename_output, "w");

    countGadgets = gadget_cache_fshow(fp_cache, fp_out, config.format | config.color);

    printf ("\n== SUMMARY ==\n");
    printf ("Found %d gadgets\n", countGadgets);

    fclose(fp_cache);
    fclose(fp_out);

    return 0;
}


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
#include "gadgets_find.h"
#include "file_pe.h"
#include "file_elf.h"
#include "ropit_options.h"

int main (int argc, char *argv[]) {
    FILE *fp_file;
    FILE *fp_cache;
    int countGadgets;
    struct gadget_plugin_t *plugin;

    printf("=================================\n");
    printf("== ROPit v0.1 alpha 2 by m_101 ==\n");
    printf("=================================\n");
    if (argc < 2) {
        // usage(argv[0]);
        printf("Usage: %s filename\n", argv[0]);
        return -1;
    }
    printf("\n");

    plugin = gadgets_x86_init();
    if (!plugin) {
        fprintf(stderr, "Failed init x86 gadget plugin\n");
        return -1;
    }

    fp_file = fopen(argv[1], "r");
    if (!fp_file) {
        fprintf(stderr, "Failed opening file '%s' (r)\n", argv[1]);
        return -2;
    }

    if (ElfCheck(fp_file) || PeCheck(fp_file))
        gadgets_find_in_executable(argv[1]);
    else
        gadgets_find_in_file (plugin, argv[1]);
    fclose(fp_file);
    gadget_plugin_destroy (&plugin);

    fp_cache = fopen("tmp/gadget_cache", "rb");
    if (!fp_cache)
        return -1;
    printf("showing gadgets in cache\n");
    countGadgets = gadget_cache_fshow(fp_cache);
#ifdef PRINT_IN_COLOR
    printf("\n== SUMMARY ==\n");
    // printf("nInstructions: %s%lu\n", COLOR_YELLOW, nInstructions);
    // printf("nGadgets: %s%lu\n", COLOR_YELLOW, nGadgets);
    printf("%s\n", COLOR_WHITE);
#else
    printf("\n== SUMMARY ==\n");
    // printf("nInstructions: %lu\n", nInstructions);
    // printf("nGadgets: %lu\n", nGadgets);
#endif
    printf("Found %d gadgets\n", countGadgets);

    fclose(fp_cache);

    return 0;
}


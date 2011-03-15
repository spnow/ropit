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

#include "gadgets.h"
#include "file_pe.h"
#include "file_elf.h"

int main (int argc, char *argv[]) {
    size_t idxGadget;
    FILE *fp;
    struct ropit_gadget_t *gadgets;

    printf("=================================\n");
    printf("== ROPit v0.1 alpha 2 by m_101 ==\n");
    printf("=================================\n");
    if (argc < 2) {
        printf("Usage: %s file\n\n", argv[0]);
        return -1;
    }
    printf("\n");

    fp = fopen(argv[1], "r");
    if (!fp)
        return -2;

    if (ElfCheck(fp) || PeCheck(fp))
        gadgets = ropit_gadgets_find_in_executable(argv[1]);
    else
        gadgets = ropit_gadgets_find_in_file(argv[1]);

    // clean up
ropit_cleanup:
    fclose(fp);
    ropit_gadget_destroy(&gadgets);

    return 0;
}

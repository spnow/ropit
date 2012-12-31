/*
   libbparse - Binary file parser library
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

#include <stdlib.h>
#include <stdio.h>

int main (int argc, char *argv[]) {
    unsigned char *bytes;
    size_t offset, szFile, szData;
    char *endptr;
    FILE *fin, *fout;

    if (argc < 5) {
        debug_printf (MESSAGE_ERROR, stderr, "Usage: %s file output offset size\n", argv[0]);
        exit(1);
    }

    // input file
    fin = fopen(argv[1], "r");
    if (!fin) {
        debug_printf (MESSAGE_ERROR, stderr, "Failed opening file\n");
        exit(1);
    }

    // get file size
    fseek(fin, 0, SEEK_END);
    szFile = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    // get file offset
    offset = strtol(argv[3], &endptr, 10);
    if (!offset)
        offset = strtol(argv[3], &endptr, 16);
    if (!offset)
        exit(1);

    // check
    if (offset > szFile) {
        debug_printf (MESSAGE_ERROR, stderr, "Offset above file size\n");
        exit(1);
    }

    // get dump size
    szData = strtol(argv[4], &endptr, 10);
    if (!szData)
        offset = strtol(argv[4], &endptr, 16);
    if (!szData) {
        debug_printf (MESSAGE_ERROR, stderr, "Could not get size to dump\n");
        exit(1);
    }

    // fix szData
    if (offset + szData > szFile) {
        printf("Fixed size from: %lu to %lu\n", szData, szFile - offset);
        szData = szFile - offset;
    }

    // file output
    fout = fopen(argv[2], "w");
    if (!fout) {
        debug_printf (MESSAGE_ERROR, stderr, "Failed creating file\n");
        exit(1);
    }

    // write data out
    bytes = calloc(szData, sizeof(*bytes));
    if (!bytes) {
        debug_printf (MESSAGE_ERROR, stderr, "Failed allocating buffer\n");
        exit(1);
    }
    fseek(fin, offset, SEEK_SET);
    fread(bytes, sizeof(*bytes), szData, fin);
    fwrite(bytes, sizeof(*bytes), szData, fout);

    // clean up
    free(bytes);
    fclose(fin);
    fclose(fout);

    return 0;
}

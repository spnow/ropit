/*
    libbparse - Binary file parser library
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
#include <stdint.h>
#include <limits.h>

#include <string.h>
#include <elf.h>

#include "file_elf.h"
#include <fall4c/fall4c.h>

//
ELF_FILE* ElfLoad (char *filename) {
    FILE *fp;
    ELF_FILE *elf;

    fp = fopen(filename, "r");
    if (!fp)
        return NULL;
    elf = calloc(1, sizeof(*elf));
    if (!elf) {
        fclose(fp);
        return NULL;
    }
    elf->filename = strdup(filename);
    elf->fp = fp;
    elf->fmap = filemap_create(filename);

    return elf;
}

//
void ElfUnload (ELF_FILE **elf) {
    if (!elf)
        return;
    if (!*elf)
        return;
    free((*elf)->filename);
    filemap_destroy(&((*elf)->fmap));
    fclose((*elf)->fp);
    free(*elf);
    *elf = NULL;
}

// check file type
int ElfCheck (FILE *fp) {
	unsigned int magic = 0;

	// check file pointer
	if (!fp)
		return 0;

	fseek(fp, 0, SEEK_SET);
	fread(&magic, 4, 1, fp);

	if (magic == ELF_MAGIC)
		return 1;
	else
		return 0;
}

// check if architecture is supported
int ElfCheckArchitecture (ELF_FILE *elffile) {
	Elf32_Ehdr* elfHeader;

    if (!elffile)
        return -1;

	// get elf header
	elfHeader = ElfGetHeader (elffile);
	if (!elfHeader)
		return -1;

	if (elfHeader->e_machine == EM_386)
		return 1;
	else
		return 0;	
}

// get elf header
Elf32_Ehdr* ElfGetHeader (ELF_FILE *elffile) {
	struct filemap_t *fmap;

    if (!elffile)
        return NULL;
    if (!elffile->fp)
        return NULL;

	// create filemap
	fmap = filemap_create (elffile->filename);
	if (!fmap)
		return NULL;

	return fmap->map;
}

// get program headers table
Elf32_Phdr* ElfGetProgramHeadersTable (ELF_FILE *elffile) {
	struct filemap_t *fmap;	
	Elf32_Ehdr *elfHeader;
	Elf32_Phdr *programHeadersTable;

    if (!elffile) {
        debug_printf (MESSAGE_ERROR, stderr, "ElfGetProgramHeadersTable(): Given ELF_FILE pointer is bad\n");
        return NULL;
    }
    if (!elffile->fp) {
        debug_printf (MESSAGE_ERROR, stderr, "ElfGetProgramHeadersTable(): File pointer is bad\n");
        return NULL;
    }

	// create filemap
	fmap = filemap_create (elffile->filename);
	if (!fmap) {
        debug_printf (MESSAGE_ERROR, stderr, "ElfGetProgramHeadersTable(): Failed file mapping\n");
		return NULL;
    }

	// get elf header
	elfHeader = ElfGetHeader(elffile);
	if (!elfHeader) {
        debug_printf (MESSAGE_ERROR, stderr, "ElfGetProgramHeadersTable(): Failed getting ELF header\n");
		return NULL;
    }

	// if no program headers table
	if (elfHeader->e_phnum == 0 || elfHeader->e_phoff == 0) {
        debug_printf (MESSAGE_ERROR, stderr, "ElfGetProgramHeadersTable(): No program segments\n");
		return NULL;
    }
    if (elfHeader->e_phoff >= fmap->sz_map)
        return NULL;
	// else we have one
	programHeadersTable = fmap->map + elfHeader->e_phoff;

	return programHeadersTable;
}

// get sections table
Elf32_Shdr* ElfGetSectionHeadersTable (ELF_FILE *elffile) {
	struct filemap_t *fmap;
	Elf32_Ehdr *elfHeader;
	Elf32_Shdr *sectionsTable;

    if (!elffile) {
        debug_printf (MESSAGE_ERROR, stderr, "ElfGetSectionHeadersTable(): Given ELF_FILE pointer is bad\n");
        return NULL;
    }
    if (!elffile->fp) {
        debug_printf (MESSAGE_ERROR, stderr, "ElfGetSectionHeadersTable(): File pointer is bad\n");
        return NULL;
    }

	// create filemap
	fmap = filemap_create (elffile->filename);
	if (!fmap) {
        debug_printf (MESSAGE_ERROR, stderr, "ElfGetSectionHeadersTable(): Failed file mapping\n");
		return NULL;
    }
	
	// get elf header
	elfHeader = ElfGetHeader(elffile);
	if (!elfHeader) {
        debug_printf (MESSAGE_ERROR, stderr, "ElfGetSectionHeadersTable(): Failed getting ELF header\n");
		return NULL;
    }
	
	// if no section headers table
	if (elfHeader->e_shnum == 0 || elfHeader->e_shoff == 0) {
        debug_printf (MESSAGE_ERROR, stderr, "ElfGetSectionHeadersTable(): No sections\n");
		return NULL;
    }
    if (elfHeader->e_shoff >= fmap->sz_map)
        return NULL;
	// else we have one
	sectionsTable = fmap->map + elfHeader->e_shoff;

	return sectionsTable;
}

// get section table with all names
char* ElfGetSectionNamesTable (ELF_FILE *elffile) {
	struct filemap_t *fmap;
	Elf32_Ehdr *elfHeader;
	Elf32_Shdr *sectionNamesTableHeader;
	char *sectionNamesTable;

    if (!elffile)
        return NULL;
    if (!elffile->fp)
        return NULL;

	// create filemap
	fmap = filemap_create (elffile->filename);
	if (!fmap)
		return NULL;
	
	// get elf header
	elfHeader = ElfGetHeader(elffile);
	if (!elfHeader)
		return NULL;

	// if no section names table
	if (elfHeader->e_shstrndx == SHN_UNDEF)
		return NULL;
	// else we have one
	sectionNamesTableHeader = &(ElfGetSectionHeadersTable(elffile)[elfHeader->e_shstrndx]);	

    sectionNamesTable = fmap->map + sectionNamesTableHeader->sh_offset;

	return sectionNamesTable;
}

// get base address of elf
uint64_t ElfGetBaseAddr (ELF_FILE *elf_file)
{
    //
    int idx_phdr;
    uint64_t base_addr, p_vaddr;
    //
	Elf32_Ehdr *elf_hdr;
	Elf32_Phdr *pheaders_table;

    // get elf header
    elf_hdr = ElfGetHeader (elf_file);
    if (!elf_hdr) {
        return NULL;
    }

    // get program headers table
    pheaders_table = ElfGetProgramHeadersTable (elf_file);
    if (!pheaders_table) {
        return NULL;
    }

    // search for lowest LOAD section
    base_addr = ULLONG_MAX;
    for (idx_phdr = 0; idx_phdr < elf_hdr->e_phnum; idx_phdr++) {
        if (pheaders_table[idx_phdr].p_type & PT_LOAD) {
            p_vaddr = pheaders_table[idx_phdr].p_vaddr;
            if (p_vaddr < base_addr && p_vaddr != 0)
                base_addr = pheaders_table[idx_phdr].p_vaddr;
        }
    }

    return base_addr;
}

void elf_header_get_imports (char *binaryName) {
}

void elf_header_get_symbols (char *binaryName) {
}

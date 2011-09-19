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
#include <stdint.h>
#include <string.h>

#include <elf.h>

#include "filemap.h"

struct data_t {
    unsigned char *data;
    uint64_t szData;
};

// check ELF header validity using some heuristics
int ElfHeaderCheckValidity(Elf32_Ehdr *elfHeader) {
    Elf64_Ehdr *elfHeader64 = elfHeader;

    if (!elfHeader)
        return -1;

    // checking version
    if (elfHeader->e_version != EV_NONE && elfHeader64->e_version != EV_CURRENT)
        return 0;
    if (elfHeader->e_version != elfHeader->e_ident[EI_VERSION] && elfHeader64->e_version != elfHeader->e_ident[EI_VERSION])
        return 0;

    // checking ELF header size
    if (elfHeader->e_ehsize != sizeof(Elf32_Ehdr) && elfHeader64->e_ehsize != sizeof(Elf64_Ehdr))
        return 0;

    // check ELF Program Header size
    if (elfHeader->e_phentsize != sizeof(Elf32_Phdr) && elfHeader64->e_phentsize != sizeof(Elf64_Phdr))
        return 0;

    // check ELF Section Header size
    if (elfHeader->e_shentsize != sizeof(Elf32_Shdr) && elfHeader64->e_shentsize != sizeof(Elf64_Shdr))
        return 0;

    return 1;
}

Elf32_Ehdr* ElfGetHeaderFromFileRaw(char *filename) {
    size_t offsetFile, szFile, found;
    FILE *fp;
    Elf32_Ehdr *elfHeader;
    struct filemap_t *fmap;

    if (!filename)
        return NULL;

    // open file
    fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "ElfGetHeaderFromFileRaw(): File doesn't exist\n");
        return NULL;
    }
    
    // get file size
    fseek(fp, 0, SEEK_END);
    szFile = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // create filemap
    fmap = filemap_create(fp);
    if (!fmap) {
        fclose(fp);
        return NULL;
    }

    // search ELF header
    for (offsetFile = 0, found = 0; offsetFile < szFile; offsetFile++) {
        if (memcmp(fmap->map + offsetFile, "\x7f\x45\x4c\x46", 4) == 0) {
            found = 1;
            break;
        }
    }

    // we found elf header
    if (!found)
        elfHeader = NULL;
    else {
        elfHeader = malloc(((Elf32_Ehdr *)(fmap->map + offsetFile))->e_ehsize);
        if (elfHeader) {
            memcpy(elfHeader, fmap->map + offsetFile, ((Elf32_Ehdr *)(fmap->map + offsetFile))->e_ehsize);
            // fix offsets
            elfHeader->e_phoff += offsetFile;
            elfHeader->e_shoff += offsetFile;
        }
    }

    // clean up
    fclose(fp);
    filemap_destroy(&fmap);

    if (ElfHeaderCheckValidity(elfHeader) > 0)
        return elfHeader;
    else {
        fprintf(stderr, "ElfGetHeaderFromFileRaw(): Invalid ELF header\n");
        free(elfHeader);
        return NULL;
    }
}

Elf32_Phdr* ElfGetProgramHeadersUsingElfHeader(struct filemap_t *fmap, Elf32_Ehdr *elfHeader) {
    Elf32_Phdr *programHeadersTable;

    if (!elfHeader || !fmap)
        return NULL;

	programHeadersTable = fmap->map + elfHeader->e_phoff;

    return programHeadersTable;
}

struct data_t* ElfDumpProgramSegments(struct filemap_t *fmap, Elf32_Ehdr *elfHeader) {
    struct data_t *segments;
    size_t idxSegment, offsetSegment;
    Elf32_Phdr *segmentHeaders;

    if (!fmap || !elfHeader)
        return NULL;

    //
    segmentHeaders = ElfGetProgramHeadersUsingElfHeader(fmap, elfHeader);
    if (!segmentHeaders)
        return NULL;

    // allocate memory for segments
    segments = calloc(1, sizeof(*segments));
    if (!segments)
        return NULL;

    // get total size
    for (idxSegment = 0, segments->szData = 0; idxSegment < elfHeader->e_phnum; idxSegment++) {
        segments->szData += segmentHeaders[idxSegment].p_filesz;
    }

    printf("segments total size: %lu\n", segments->szData);

    if (fmap->map + segments->szData >= fmap->map + fmap->szMap) {
        fprintf(stderr, "ElfDumpProgramSegments: Offset farther than actual file size\n");
        return NULL;
    }

    // allocate memory for segments
    segments->data = calloc(segments->szData, sizeof(*(segments->data)));
    if (!segments->data)
        return NULL;

    // get total size
    for (idxSegment = 0, offsetSegment = 0; idxSegment < elfHeader->e_phnum; idxSegment++) {
        memcpy(segments->data + offsetSegment, fmap->map + segmentHeaders[idxSegment].p_offset, segmentHeaders[idxSegment].p_filesz);
        offsetSegment += segmentHeaders[idxSegment].p_filesz;
    }

    return segments;
}

Elf32_Shdr* ElfGetSectionHeadersUsingElfHeader(struct filemap_t *fmap, Elf32_Ehdr *elfHeader) {
    Elf32_Shdr *sectionHeadersTable;

    if (!elfHeader || !fmap)
        return NULL;

    sectionHeadersTable = fmap->map + elfHeader->e_shoff;

    return sectionHeadersTable;
}

int compare_ulongs (void *a, void *b) {
    return *((unsigned long *)a) - *((unsigned long *)b);
}

int compare_elf_sections_by_name_idx (void *a, void *b) {
    Elf32_Shdr *section1 = a, *section2 = b;

    return section1->sh_name - section2->sh_name;
}

// use program headers table to carve out section headers table
Elf32_Shdr* ElfSectionHeaderCarveUsingEHeaderAndPHeaders (struct filemap_t *fmap, Elf32_Ehdr *elf32, Elf32_Phdr *programHeaders) {
    size_t *potentials, idxPHeader, countMatch = 0, offsetFile;
    size_t *offPNames, *offNames;
    long offsetNamesTable;
    int c;
    Elf32_Shdr *section, **sectionHeaders;

    // check pointers
    if (!fmap || !elf32 || !programHeaders)
        return NULL;

    // potentials section headers table start
    potentials = calloc(elf32->e_phnum, sizeof(*potentials));
    if (!potentials)
        return NULL;

    // offPNames names
    offPNames = calloc(elf32->e_phnum, sizeof(*offPNames));
    if (!offPNames)
        return NULL;
    
    // offNames names
    offNames = calloc(elf32->e_shnum, sizeof(*offNames));
    if (!offNames)
        return NULL;

    // section headers
    sectionHeaders = calloc(elf32->e_phnum, sizeof(*sectionHeaders));
    if (!sectionHeaders)
        return NULL;

    // get potential section header start
    for (idxPHeader = 0; idxPHeader < elf32->e_phnum; idxPHeader++) {
        for (offsetFile = 0; offsetFile < fmap->szMap - sizeof(*section); offsetFile++) {
            section = fmap->map + offsetFile;

            // found a matching program segment and section
            if (section->sh_addralign == programHeaders[idxPHeader].p_align
                    && section->sh_addr == programHeaders[idxPHeader].p_vaddr
                    && section->sh_offset == programHeaders[idxPHeader].p_offset) {
                potentials[idxPHeader] = offsetFile;
                offPNames[idxPHeader] = section->sh_name;
                sectionHeaders[idxPHeader] = section;
                break;
            }
        }
    }

    // ascending sort
    qsort(sectionHeaders, elf32->e_phnum, sizeof(*sectionHeaders), compare_elf_sections_by_name_idx);

    // find start of names table
    for (offsetNamesTable = offPNames[0]; offsetNamesTable > 0; offsetNamesTable--) {
        c = *((char *)fmap->map + offsetNamesTable);
        if (!isprint(c) && c != '\0')
            break;

    }

    // now backtracking to find the real beginning to the file
    for (offsetFile = 0; offsetFile < fmap->szMap; offsetFile++) {
    }
}

struct data_t* ElfDumpSections(struct filemap_t *fmap, Elf32_Ehdr *elfHeader) {
    struct data_t *sections;
    size_t idxSection, offsetSection;
    Elf32_Shdr *sectionHeaders;

    if (!fmap || !elfHeader)
        return NULL;

    //
    sectionHeaders = ElfGetSectionHeadersUsingElfHeader(fmap, elfHeader);
    if (!sectionHeaders)
        return NULL;

    // allocate memory for sections
    sections = calloc(1, sizeof(*sections));
    if (!sections)
        return NULL;

    // get total size
    for (idxSection = 0, sections->szData = 0; idxSection < elfHeader->e_phnum; idxSection++) {
        sections->szData += sectionHeaders[idxSection].sh_size;
    }

    printf("sections total size: %lu\n", sections->szData);

    if (fmap->map + sections->szData >= fmap->map + fmap->szMap) {
        fprintf(stderr, "ElfDumpSections(): Offset farther than actual file size\n");
        return NULL;
    }

    // allocate memory for sections
    sections->data = calloc(sections->szData, sizeof(*(sections->data)));
    if (!sections->data)
        return NULL;

    // get total size
    for (idxSection = 0, offsetSection = 0; idxSection < elfHeader->e_shnum; idxSection++) {
        memcpy(sections->data + offsetSection, fmap->map + sectionHeaders[idxSection].sh_offset, sectionHeaders[idxSection].sh_size);
        offsetSection += sectionHeaders[idxSection].sh_size;
    }

    return sections;
}

char* ElfHeaderIdentDecode (Elf32_Ehdr *elfHeader) {
    char *ident = NULL;

    if (!elfHeader)
        return NULL;

    ident = calloc(1024, sizeof(*ident));
    if (!ident)
        return NULL;

    if (elfHeader->e_ident[EI_CLASS] == ELFCLASS32)
        strncat(ident, "32 bits | ", 1024 - strlen(ident));
    else if (elfHeader->e_ident[EI_CLASS] == ELFCLASS32)
        strncat(ident, "64 bits | ", 1024 - strlen(ident));
    else
        strncat(ident, "Invalid Class | ", 1024 - strlen(ident));

    if (elfHeader->e_ident[EI_DATA] == ELFDATA2LSB)
        strncat(ident, "Little-Endian | ", 1024 - strlen(ident));
    else if (elfHeader->e_ident[EI_DATA] == ELFDATA2MSB)
        strncat(ident, "Big-Endian | ", 1024 - strlen(ident));
    else
        strncat(ident, "Invalid Encoding | ", 1024 - strlen(ident));


    if (elfHeader->e_ident[EI_OSABI] == ELFOSABI_SYSV)
        strncat(ident, "SYSV ABI | ", 1024 - strlen(ident));
    else if (elfHeader->e_ident[EI_OSABI] == ELFOSABI_HPUX)
        strncat(ident, "HPUX ABI | ", 1024 - strlen(ident));
    else if (elfHeader->e_ident[EI_OSABI] == ELFOSABI_STANDALONE)
        strncat(ident, "Standalone ABI | ", 1024 - strlen(ident));

    return ident;
}

char* ElfHeaderTypeDecode (Elf32_Ehdr *elfHeader) {
    char *type = NULL;

    if (!elfHeader)
        return NULL;

    if (elfHeader->e_type == ET_NONE)
        type = "No file type";
    else if (elfHeader->e_type == ET_REL)
        type = "Relocatable";
    else if (elfHeader->e_type == ET_EXEC)
        type = "Executable file";
    else if (elfHeader->e_type == ET_DYN)
        type = "Shared Object";
    else if (elfHeader->e_type == ET_CORE)
        type = "Core file";
    else if (elfHeader->e_type == ET_LOPROC)
        type = "ET_LOPROC";
    else if (elfHeader->e_type == ET_HIPROC)
        type = "ET_HIPROC";

    return type;
}

char* ElfMachineTypeDecode (Elf32_Ehdr *elfHeader) {
    char *machine = NULL;

    if (!elfHeader)
        return NULL;

    if (elfHeader->e_machine == EM_NONE)
        machine = "No machine";
    else if (elfHeader->e_machine == EM_M32)
        machine = "AT&T WE 32100";
    else if (elfHeader->e_machine == EM_SPARC)
        machine = "SPARC";
    else if (elfHeader->e_machine == EM_386)
        machine = "x86";
    else if (elfHeader->e_machine == EM_68K)
        machine = "Motorola 68000";
    else if (elfHeader->e_machine == EM_88K)
        machine = "Motorola 88000";
    else if (elfHeader->e_machine == EM_860)
        machine = "Intel 80860";
    else if (elfHeader->e_machine == EM_MIPS)
        machine = "MIPS RS3000";
    else
        machine = "Unknown machine";

    return machine;
}

void ElfShowElfHeader (Elf32_Ehdr *elfHeader) {
    char *type, *ident;

    if (!elfHeader)
        return;

    type = ElfHeaderTypeDecode(elfHeader);
    ident = ElfHeaderIdentDecode(elfHeader);
    printf("== ELF HEADER\n");
    printf("Elf machine type        : %s\n", ElfMachineTypeDecode(elfHeader));
    printf("Elf machine type        : %s\n", ident);
    printf("Elf file type           : %s\n", type);
    printf("Elf file format version : %x\n", elfHeader->e_version);
    printf("Entry point             : %p\n", elfHeader->e_entry);
    printf("Elf Header Size         : %lu\n", elfHeader->e_ehsize);
    printf("* Segments:\n");
    printf("    -> Program headers offset: %lu\n", elfHeader->e_phoff);
    printf("    -> Number Of Segments    : %lu\n", elfHeader->e_phnum);
    printf("    -> Size Of program Header: %lu\n", elfHeader->e_phentsize);
    printf("* Sections:\n");
    printf("    -> Section headers offset: %lu\n", elfHeader->e_shoff);
    printf("    -> Number Of Sections    : %lu\n", elfHeader->e_shnum);
    printf("    -> Size Of Section Header: %lu\n\n", elfHeader->e_shentsize);
}

char* ElfDecodeSegmentType (Elf32_Phdr *programHeader) {
    char *type = NULL;

    if (!programHeader)
        return NULL;

    if (programHeader->p_type == PT_NULL)
        type = "NULL";
    else if (programHeader->p_type == PT_LOAD)
        type = "LOAD";
    else if (programHeader->p_type == PT_DYNAMIC)
        type = "DYNAMIC";
    else if (programHeader->p_type == PT_INTERP)
        type = "INTERP";
    else if (programHeader->p_type == PT_NOTE)
        type = "NOTE";
    else if (programHeader->p_type == PT_SHLIB)
        type = "SHLIB";
    else if (programHeader->p_type == PT_PHDR)
        type = "PHDR";
    else if (programHeader->p_type == PT_LOPROC)
        type = "LOPROC";
    else if (programHeader->p_type == PT_HIPROC)
        type = "HIPROC";

    return type;
}


char* ElfDecodeSegmentFlags (Elf32_Phdr *programHeader) {
    char *flag[3] = { NULL };
    char *buffer = NULL;
    size_t idxFlag;

    if (!programHeader)
        return NULL;

    buffer = calloc(1024, sizeof(*buffer));
    if (!buffer)
        return NULL;

    if (programHeader->p_flags & PF_R)
        flag[0] = "r";
    if (programHeader->p_flags & PF_W)
        flag[1] = "w";
    if (programHeader->p_flags & PF_X)
        flag[2] = "x";

    for (idxFlag = 0; idxFlag < 3; idxFlag++) {
        if (flag[idxFlag])
            strncat(buffer, flag[idxFlag], 1024 - strlen(buffer));
        else
            strncat(buffer, "-", 1024 - strlen(buffer));
    }

    return buffer;
}

void ElfShowProgramHeaders (Elf32_Phdr *programHeaders, size_t nHeaders) {
    size_t idxHeader;
    char *type = NULL, *flags = NULL;

    if (!programHeaders || !nHeaders)
        return;

    printf("== Program Headers\n");
    printf("==========================================================================================\n");
    printf("|  Type   |  offset  |    vaddr   |   paddr    |  filesz  |   memsz  | flags |   align   |\n");
    printf("|----------------------------------------------------------------------------------------|\n");
    for (idxHeader = 0; idxHeader < nHeaders; idxHeader++) {
        //printf("|----------------------------------------------------------------------------------------|\n");
        type = ElfDecodeSegmentType(&(programHeaders[idxHeader]));
        flags = ElfDecodeSegmentFlags(&(programHeaders[idxHeader]));
        printf("| %7s | %8u | %10p | %10p | %8u | %8u |  %3s  | %8u  |\n", type, programHeaders[idxHeader].p_offset, programHeaders[idxHeader].p_vaddr, programHeaders[idxHeader].p_paddr, programHeaders[idxHeader].p_filesz, programHeaders[idxHeader].p_memsz, flags, programHeaders[idxHeader].p_align);
        /*
        printf("Type             : %s\n", type);
        printf("File offset      : %u\n", programHeaders[idxHeader].p_offset);
        printf("Virtual Address  : %p\n", programHeaders[idxHeader].p_vaddr);
        printf("Physical Address : %p\n", programHeaders[idxHeader].p_paddr);
        printf("File size        : %u\n", programHeaders[idxHeader].p_filesz);
        printf("Memory size      : %u\n", programHeaders[idxHeader].p_memsz);
        printf("Flags            : %s\n", flags);
        printf("Alignment        : %u\n", programHeaders[idxHeader].p_align);
        printf("----------------\n");
        //*/
        free(flags);
    }
    printf("==========================================================================================\n");
    printf("\n");

}

char* ElfDecodeSectionType (Elf32_Phdr *programHeader) {
    char *type = NULL;

    if (!programHeader)
        return NULL;

    if (programHeader->p_type == PT_NULL)
        type = "NULL";
    else if (programHeader->p_type == PT_LOAD)
        type = "LOAD";
    else if (programHeader->p_type == PT_DYNAMIC)
        type = "DYNAMIC";
    else if (programHeader->p_type == PT_INTERP)
        type = "INTERP";
    else if (programHeader->p_type == PT_NOTE)
        type = "NOTE";
    else if (programHeader->p_type == PT_SHLIB)
        type = "SHLIB";
    else if (programHeader->p_type == PT_PHDR)
        type = "PHDR";
    else if (programHeader->p_type == PT_LOPROC)
        type = "LOPROC";
    else if (programHeader->p_type == PT_HIPROC)
        type = "HIPROC";
    else
        type = "Unknown Type";

    return type;
}


char* ElfDecodeSectionFlags (Elf32_Phdr *programHeader) {
    char *flag[3] = { NULL };
    char *buffer = NULL;
    size_t idxFlag;

    if (!programHeader)
        return NULL;

    buffer = calloc(1024, sizeof(*buffer));
    if (!buffer)
        return NULL;

    if (programHeader->p_flags & PF_R)
        flag[0] = "r";
    if (programHeader->p_flags & PF_W)
        flag[1] = "w";
    if (programHeader->p_flags & PF_X)
        flag[2] = "x";

    for (idxFlag = 0; idxFlag < 3; idxFlag++) {
        if (flag[idxFlag])
            strncat(buffer, flag[idxFlag], 1024 - strlen(buffer));
        else
            strncat(buffer, "-", 1024 - strlen(buffer));
    }

    return buffer;
}

void ElfShowSectionHeaders (Elf32_Shdr *sectionHeaders, size_t nHeaders) {
    size_t idxHeader;
    char *type = NULL, *flags = NULL;

    if (!sectionHeaders || !nHeaders)
        return;

    printf("== Section Headers\n");
    printf("======================================================================================================\n");
    printf("|  Name   |  Type   |  offset  |    addr    |   size   | flags |   align   |    Info    |    Link    |\n");
    printf("|----------------------------------------------------------------------------------------------------|\n");
    for (idxHeader = 0; idxHeader < nHeaders; idxHeader++) {
        type = ElfDecodeSectionType(&(sectionHeaders[idxHeader]));
        flags = ElfDecodeSectionFlags(&(sectionHeaders[idxHeader]));
        printf("| %7u | %7s | %8u | %10p | %8u |  %3s  | %8u  |  %8u  |  %8u  |\n", sectionHeaders[idxHeader].sh_name, type, sectionHeaders[idxHeader].sh_offset, sectionHeaders[idxHeader].sh_addr, sectionHeaders[idxHeader].sh_size, flags, sectionHeaders[idxHeader].sh_addralign, sectionHeaders[idxHeader].sh_info, sectionHeaders[idxHeader].sh_link);
        /*
        printf("Name             : %u\n", sectionHeaders[idxHeader].sh_name);
        printf("Type             : %s\n", type);
        printf("Flags            : %s\n", flags);
        printf("Address          : %p\n", sectionHeaders[idxHeader].sh_addr);
        printf("File offset      : %u\n", sectionHeaders[idxHeader].sh_offset);
        printf("Size             : %u\n", sectionHeaders[idxHeader].sh_size);
        printf("Link             : %u\n", sectionHeaders[idxHeader].sh_link);
        printf("Info             : %u\n", sectionHeaders[idxHeader].sh_info);
        printf("Alignment        : %u\n", sectionHeaders[idxHeader].sh_addralign);
        printf("Entry Size       : %u\n", sectionHeaders[idxHeader].sh_entsize);
        printf("----------------\n");
        //*/
        free(flags);
    }
    printf("======================================================================================================\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    FILE *fp;
    struct filemap_t *fmap;
    Elf32_Ehdr *elfHeader;
    Elf32_Phdr *programHeaders;
    Elf32_Shdr *sectionHeaders;
    struct data_t *segments, *sections;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s file output\n", argv[0]);
        exit(1);
    }

    // open file
    fp = fopen(argv[1], "r");
    if (!fp) {
        fprintf(stderr, "File does not exist\n");
        exit(1);
    }

    // carve ELF file header
    elfHeader = ElfGetHeaderFromFileRaw(argv[1]);
    if (!elfHeader) {
        fprintf(stderr, "Couldn't find an ELF file to carve\n");
        exit(1);
    }

    //*
    if (elfHeader->e_machine != EM_386) {
        fprintf(stderr, "Only x86 architecture supported\n");
        exit(1);
    }
    //*/

    // printf ELF section infos
    ElfShowElfHeader(elfHeader);

    // create filemap
    fmap = filemap_create(fp);
    if (!fmap)
        exit(1);

    programHeaders = ElfGetProgramHeadersUsingElfHeader(fmap, elfHeader);
    if (!programHeaders) {
        fprintf(stderr, "No program headers\n");
    }
    ElfShowProgramHeaders(programHeaders, elfHeader->e_phnum);

    sectionHeaders = ElfGetSectionHeadersUsingElfHeader(fmap, elfHeader);
    if (!sectionHeaders) {
        fprintf(stderr, "No section headers\n");
    }
    ElfShowSectionHeaders (sectionHeaders, elfHeader->e_shnum);

    segments = ElfDumpProgramSegments(fmap, elfHeader);
    if (!segments) {
        fprintf(stderr, "No program segments\n");
    }
    sections = ElfDumpSections(fmap, elfHeader);
    if (!sections) {
        fprintf(stderr, "No sections\n");
    }

    // create fixed file

    fclose(fp);
    filemap_destroy(&fmap);

    return 0;
}

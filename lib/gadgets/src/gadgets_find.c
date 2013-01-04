#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// threading
#include <pthread.h>

#include <libdis.h>
#include <pcre.h>

#include "arch/arch.h"
#include <fall4c/filemap.h>
#include "file_pe.h"
#include "file_elf.h"
#include "offsets.h"

//
struct offsets_t *ropit_filter_regexp(uint8_t *bytes, int len, char *expr) {
    pcre *pattern = NULL;
    const char *errptr = NULL;
    int erroffset = 0;
    int rc;
    struct offsets_t *matches = NULL;
    int wspace[64] = {0}, wcount = 20;
    //
    int start, mcount, idx;

    matches = offsets_new(1200);
    if (!matches)
        return NULL;

    // pattern = pcre_compile("(pop\\s+\\w{3}\\s+){2}ret", PCRE_CASELESS, &errptr, &erroffset, NULL);
    pattern = pcre_compile(expr, PCRE_CASELESS, &errptr, &erroffset, NULL);
    if (errptr) {
        debug_printf (MESSAGE_ERROR, stderr, "%s\n", errptr);
        return NULL;
    }

    // find ALL possibilities and have backtracking capabilities
    for (start = 0, mcount = 0, idx = 0; start < len; idx++) {
        rc = pcre_exec(pattern, NULL, (char *)bytes, len, start, 0, wspace, wcount);
        if (rc <= 0) {
            //debug_printf (MESSAGE_ERROR, stderr, "Error: pcre_exec() failed\n");
            start++;
        }
        else {
            start = wspace[1];
            matches->offsets[mcount] = wspace[0];
            matches->offsets[mcount+1] = wspace[1];
            mcount++;
        }
        memset(wspace, 0, 64);
    }

    pcre_free(pattern);

    //matches->used = rc - 1;
    matches->used = mcount;

    return matches;
}

struct _gadget_find_thread_data {
    struct gadget_plugin_t *plugin;
    uint8_t *bytes;
    int n_bytes;
};

void *_gadgets_find_thread (void *data) {
    struct _gadget_find_thread_data *tdata = data;
    int ret;

    if (!tdata)
        return NULL;
    if (!tdata->plugin)
        return NULL;
    ret = tdata->plugin->find_gadgets (tdata->bytes, tdata->n_bytes);

    pthread_exit(ret);
}

// find valid instructions offsets before ret in a threaded way
int gadgets_find_threaded (struct gadget_plugin_t *plugin, uint8_t *bytes, int len)
{
    // code return from calls
    int retcode;
    // threads
    int n_threads = 4;
    int idx_thread;
    pthread_t *threads;
    struct _gadget_find_thread_data *tdata;
    int *tresult;
    struct offsets_t *rets;
    // gadgets finding
    struct gadget_plugin_t **plugins;
    //
    int n_rets, n_bytes;

    // check params
    if (!plugin || !bytes || len <= 0) {
        debug_printf (MESSAGE_ERROR, stderr, "error: _gadgets_find_threaded_n(): Bytes null or len <= 0\n");
        return NULL;
    }

    tdata = calloc(n_threads, sizeof(*tdata));
    if (!tdata) {
        debug_printf (MESSAGE_ERROR, stderr, "error: _gadgets_find_threaded_n(): Couldn't alloc tdata\n");
        return NULL;
    }

    tresult = calloc(n_threads, sizeof(*tresult));
    if (!tresult) {
        debug_printf (MESSAGE_ERROR, stderr, "error: _gadgets_find_threaded_n(): Couldn't alloc tresult\n");
        return NULL;
    }
    
    plugins = calloc(n_threads, sizeof(*plugins));
    if (!plugins) {
        debug_printf (MESSAGE_ERROR, stderr, "error: _gadgets_find_threaded_n(): Couldn't alloc plugins\n");
        return NULL;
    }

    // allocate threads
    threads = calloc(n_threads, sizeof(*threads));
    if (!threads) {
        debug_printf (MESSAGE_ERROR, stderr, "error: _gadgets_find_threaded_n(): Could alloc threads\n");
        return NULL;
    }

    rets = plugin->find_rets (bytes, len);
    if (!rets) {
        debug_printf (MESSAGE_ERROR, stderr, "error: _gadgets_find_threaded_n(): Could find rets\n");
        return NULL;
    }

    for (idx_thread = 0; idx_thread < n_threads; idx_thread++) {
        // allocate and populate data for each thread
        plugins[idx_thread] = gadget_plugin_new_copy (plugin);
        tdata[idx_thread].plugin = plugins[idx_thread];
        tdata[idx_thread].plugin->rets = rets->offsets + n_rets * idx_thread;
        tdata[idx_thread].plugin->n_rets = n_rets;
        tdata[idx_thread].bytes = bytes + *(rets->offsets + n_rets * idx_thread);
        tdata[idx_thread].n_bytes = len - *(rets->offsets + n_rets * idx_thread);

        // create thead
        retcode = pthread_create(&threads[idx_thread], NULL, _gadgets_find_thread, (void *)&(tdata[idx_thread]));
        if (retcode != 0)
            debug_printf (MESSAGE_ERROR, stderr, "error: _gadgets_find_threaded(): thread %d creation failed\n", idx_thread);
    }
    fprintf(stdout, "Threads created\n");

    // wait for threads completion
    fprintf(stdout, "Threads joining\n");
    for (idx_thread = 0; idx_thread < n_threads; idx_thread++) {
        retcode = pthread_join(threads[idx_thread], &(tresult[idx_thread]));
        debug_printf (MESSAGE_INFO, stdout, "info : _gadgets_find_threaded(): offsets = %p\n", tresult[idx_thread]);
        if (retcode != 0)
            debug_printf (MESSAGE_ERROR, stderr, "error: _gadgets_find_threaded(): thread %d did not join\n", idx_thread);
    }
    fprintf(stdout, "Threads joined\n");

    for (idx_thread = 0; idx_thread < n_threads; idx_thread++)
        gadget_plugin_destroy(&plugins[idx_thread]);

    // cleanup
    free(tdata);
    free(tresult);
    free(plugins);
    free(threads);

    return NULL;
}

// find valid instructions offsets before ret
struct offsets_t *gadgets_find (struct gadget_plugin_t *plugin, uint8_t *bytes, int len) {
    return plugin->find_gadgets (bytes, len);
}

int ropit_pointers_check_charset(uint64_t pointer,
        char *charset, int sz_charset) {
    int idx_charset, idx_ptr;
    uint8_t p[8] = {0};
    int isGood = 0;

    p[0] = pointer & 0xff;
    p[1] = (pointer >> 8) & 0xff;
    p[2] = (pointer >> 16) & 0xff;
    p[3] = (pointer >> 24) & 0xff;
    p[4] = (pointer >> 32) & 0xff;
    p[5] = (pointer >> 40) & 0xff;
    p[6] = (pointer >> 48) & 0xff;
    p[7] = (pointer >> 56) & 0xff;

    // checking that each byte is in the charset
    // if it is
    // then it is good
    for (idx_ptr = 0; idx_ptr < 8; idx_ptr++) {
        for (idx_charset = 0; idx_charset < sz_charset; idx_charset++) {
            // badchar
            if (p[idx_ptr] != charset[idx_charset])
                isGood = 0;
            // goodchar
            else {
                isGood = 1;
                break;
            }
        }
    }

    return isGood;
}

int ropit_pointers_check_pointer_characteristics() {
    return 0;
}

// find gadgets in ELF file
int gadgets_find_in_elf (char *filename) {
    ELF_FILE *elf_file;
    Elf32_Ehdr *elf_header = NULL;
    Elf32_Phdr *program_headers_table;
    int idx_program_segment;
    struct gadget_plugin_t *plugin;
    int n_gadgets;
    int retcode;

    elf_file = ElfLoad(filename);
    if (!elf_file) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadgets_find_in_elf(): Failed loading ELF\n");
        return -1;
    }

    if (ElfCheckArchitecture (elf_file) == 0) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadgets_find_in_elf(): Architecture not supported\n");
        goto out_error;
    }

    elf_header = ElfGetHeader(elf_file);
    if (!elf_header) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadgets_find_in_elf(): Failed getting elf_headers\n");
        goto out_error;
    }

    // get appropriate plugin
    plugin = gadget_plugin_dispatch (0);
    if (!plugin) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadgets_find_in_elf(): Failed init gadget plugin\n");
        goto out_error;
    }

    // program segments parsing (sections are part of program segments)
    program_headers_table = ElfGetProgramHeadersTable (elf_file);
    if (!program_headers_table) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadgets_find_in_elf(): Failed getting Program Headers Table\n");
        goto out_error;
    }

    for (idx_program_segment = 0; idx_program_segment < elf_header->e_phnum; idx_program_segment++) {
        if (program_headers_table[idx_program_segment].p_flags & PF_X) {
            gadgets_find (plugin, elf_file->fmap->map + program_headers_table[idx_program_segment].p_offset,
                    program_headers_table[idx_program_segment].p_filesz);
            // base address = program_headers_table[idx_program_segment].p_paddr
        }
    }

    ElfUnload(&elf_file);

    return n_gadgets;

out_error:
    ElfUnload(&elf_file);

    return -1;
}

// find gadgets in PE file
int gadgets_find_in_pe (char *filename) {
    PE_FILE *pefile;
    IMAGE_SECTION_HEADER *section_headers_table;
    IMAGE_NT_HEADERS *nt_header = NULL;
    int idx_section;
    struct gadget_plugin_t *plugin;
    int n_gadgets;
    int retcode;

    pefile = PeLoad(filename);
    if (!pefile) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadgets_find_in_pe(): Failed loading PE\n");
        return -1;
    }

    if (PeCheckArchitecture (pefile) == 0) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadgets_find_in_pe(): Architecture not supported\n");
        goto out_error;
    }

    nt_header = PeGetNtHeader(pefile);
    if (!nt_header) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadgets_find_in_pe(): Failed getting NtHeaders\n");
        goto out_error;
    }

    section_headers_table = PeGetSectionHeaderTable(pefile);
    if (!section_headers_table) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadgets_find_in_pe(): Failed getting Section Headers Table\n");
        goto out_error;
    }

    // get appropriate plugin
    plugin = gadget_plugin_dispatch (0);
    if (!plugin) {
        debug_printf (MESSAGE_ERROR, stderr, "error: gadgets_find_in_pe(): Failed init gadget plugin\n");
        goto out_error;
    }

    n_gadgets = 0;
    for (idx_section = 0; idx_section < nt_header->FileHeader.NumberOfSections; idx_section++) {
        if (section_headers_table[idx_section].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            retcode = gadgets_find(plugin, pefile->fmap->map + section_headers_table[idx_section].PointerToRawData,
                    section_headers_table[idx_section].SizeOfRawData);
            if (retcode > 0)
                n_gadgets += retcode;
            // base address = nt_header->OptionalHeader.ImageBase + section_headers_table[idx_section].VirtualAddress
        }
    }


    // gadget_plugin_destroy (&plugin);
    PeUnload(&pefile);

    return n_gadgets;

out_error:
    PeUnload(&pefile);

    return -1;
}

// find gadgets in executable file
int gadgets_find_in_executable (char *filename)
{
    FILE *fp;
    int n_gadgets;

    fp = fopen(filename, "r");
    if (!fp)
        return -1;

    if (ElfCheck(fp))
        n_gadgets = gadgets_find_in_elf(filename);
    else if (PeCheck(fp))
        n_gadgets = gadgets_find_in_pe(filename);
    else {
        debug_printf (MESSAGE_ERROR, stderr, "error: %s is not an executable file\n");
        n_gadgets = -1;
    }

    fclose(fp);

    return n_gadgets;
}

// find gadgets in file
int gadgets_find_in_file (struct gadget_plugin_t *plugin, char *filename)
{
    FILE *fp;
    struct filemap_t *fmap;
    int n_gadgets;

    if (!plugin || !filename)
        return -1;

    fp = fopen(filename, "r");
    if (!fp)
        goto gadgets_find_in_file_cleanup;

    fmap = filemap_create(filename);
    if (!fmap)
        goto gadgets_find_in_file_cleanup;

    n_gadgets = plugin->find_gadgets (fmap->map, fmap->sz_map);

    return n_gadgets;

gadgets_find_in_file_cleanup:
    fclose(fp);
    filemap_destroy(&fmap);

    return -1;
}


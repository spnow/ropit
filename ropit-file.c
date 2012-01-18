#include <stdio.h>
#include <stdlib.h>

#include <glib.h>

gint g_compare_uint64(gpointer a, gpointer b) {
    return (guint64)a - (guint64)b;
}

// read file
gpointer read_file (char *filename) {
    FILE *fp;
    GHashTable *htable;
    gpointer skey, key, value;
    // base address
    guint64 qword, offset;
    // length
    guint16 hword;
    //
    char *str;
    //
    GSList *addrList;
    
    // check param
    if (!filename)
        return NULL;
    
    // create hash table of gadgets
    htable = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
    if (!htable)
        return NULL;

    // open gadget cache file
    fp = fopen(filename, "r");
    if (!fp)
        return NULL;

    fread(&qword, sizeof(qword), 1, fp);
    qword = GUINT64_FROM_BE(qword);

    printf("base address: 0x%08lx\n", qword);

    // read file
    while (!feof(fp) && !ferror(fp)) {
        // read address
        fread(&offset, sizeof(offset), 1, fp);
        offset = GUINT64_FROM_BE(offset);

        // read bytes
        fread(&hword, sizeof(hword), 1, fp);
        hword = GUINT16_FROM_BE(hword);
        // ignore bytes
        fseek(fp, hword, SEEK_CUR);

        // read repr
        fread(&hword, sizeof(hword), 1, fp);
        hword = GUINT16_FROM_BE(hword);
        str = calloc(hword, sizeof(*str));
        if (!str)
            continue;
        fread(str, sizeof(*str), hword, fp);

        // get our linked list
        if (g_hash_table_lookup_extended(htable, str, &key, &value) == TRUE)
            addrList = value;
        else
            addrList = g_slist_alloc();
        // add address to list
        addrList = g_slist_append(addrList, offset);

        // insert
        g_hash_table_insert(htable, str, addrList);
    }

    fclose(fp);

    return htable;
}

void gadget_iterator(gpointer key, gpointer value, gpointer user_data) {
    char *str = key;
    GSList *addrList = value, *node;
    guint64 offset;

    // sort
    g_slist_sort(addrList, g_compare_uint64);

    printf("%s : [ ", key);
    for (node = addrList; node != NULL; node = g_slist_next(node))
        printf("%08lx, ", node->data);
    printf("]\n");
}

void gadget_iterator_remove(gpointer key, gpointer value, gpointer user_data) {
    free(key);
    g_slist_free(value);
    return TRUE;
}

// show file
void show_file (char *filename) {
    // hashtable
    GHashTable *htable;
    GSList *addrList;
    char *str;
    guint64 offset;
    //
    int idx;

    //
    htable = read_file(filename);
    if (!htable)
        return;

    g_hash_table_foreach(htable, gadget_iterator, NULL);
    g_hash_table_foreach_remove(htable, gadget_iterator_remove, NULL);

    g_hash_table_destroy(htable);
}

int main (int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s filename\n", argv[0]);
        return -1;
    }

    show_file(argv[1]);

    return 0;
}


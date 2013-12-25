#include <stdio.h>
#include <stdlib.h>

#include <fall4c/fall4c.h>
#include "byte-order.h"
#include "file-ropit-section.h"

int rop_section_fwrite (struct ropit_file_section_header_t *sheader, FILE *fp)
{
    uint32_t val32;
    uint64_t val64;
    int nb_written;

    if (!sheader || !fp) {
        debug_message (MESSAGE_ERROR, "rop_fwrite(): Bad parameter(s)\n");
        return -1;
    }

    nb_written = 0;

    val32 = host_to_file_order_by_size (sheader->name, sizeof(sheader->name));
    nb_written += fwrite (&val32, 1, sizeof(val32), fp);
    val32 = host_to_file_order_by_size (sheader->type, sizeof(sheader->type));
    nb_written += fwrite (&val32, 1, sizeof(val32), fp);
    val32 = host_to_file_order_by_size (sheader->flags, sizeof(sheader->flags));
    nb_written += fwrite (&val32, 1, sizeof(val32), fp);
    val64 = host_to_file_order_by_size (sheader->addr, sizeof(sheader->addr));
    nb_written += fwrite (&val64, 1, sizeof(val64), fp);
    val64 = host_to_file_order_by_size (sheader->offset, sizeof(sheader->offset));
    nb_written += fwrite (&val64, 1, sizeof(val64), fp);
    val32 = host_to_file_order_by_size (sheader->size, sizeof(sheader->size));
    nb_written += fwrite (&val32, 1, sizeof(val32), fp);
    val32 = host_to_file_order_by_size (sheader->align, sizeof(sheader->align));
    nb_written += fwrite (&val32, 1, sizeof(val32), fp);

    return nb_written;
}

int rop_section_fread (struct ropit_file_section_header_t *sheader, FILE *fp)
{
    uint32_t val32;
    uint64_t val64;
    int nb_read;

    if (!sheader || !fp) {
        debug_message (MESSAGE_ERROR, "rop_fwrite(): Bad parameter(s)\n");
        return -1;
    }

    nb_read = 0;

    nb_read += fread (&val32, 1, sizeof(val32), fp);
    sheader->name = file_to_host_order_by_size (val32, sizeof(sheader->name));
    nb_read += fread (&val32, 1, sizeof(val32), fp);
    sheader->type = file_to_host_order_by_size (val32, sizeof(sheader->type));
    nb_read += fread (&val32, 1, sizeof(val32), fp);
    sheader->flags = file_to_host_order_by_size (val32, sizeof(sheader->flags));
    nb_read += fread (&val64, 1, sizeof(val64), fp);
    sheader->addr = file_to_host_order_by_size (val64, sizeof(sheader->addr));
    nb_read += fread (&val64, 1, sizeof(val64), fp);
    sheader->offset = file_to_host_order_by_size (val64, sizeof(sheader->offset));
    nb_read += fread (&val32, 1, sizeof(val32), fp);
    sheader->size = file_to_host_order_by_size (val32, sizeof(sheader->size));
    nb_read += fread (&val32, 1, sizeof(val32), fp);
    sheader->align = file_to_host_order_by_size (val32, sizeof(sheader->align));

    return nb_read;
}


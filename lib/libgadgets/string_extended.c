#include <stdlib.h>
#include <string.h>

#include "string_extended.h"

int str_tabs2spaces(char *str, size_t len) {
    char *wip = str;

    if (!str || !len)
        return -1;

    while (wip < str + len && *wip != '\0') {
        if (*wip == '\t')
            *wip = ' ';
        wip++;
    }

    return 0;
}

#include <stdio.h>
#include <stdlib.h>

int main (int argc, char *argv[]) {
    if (arch_is_big_endian())
        printf("big endian architecture\n");
    else
        printf("little endian architecture\n");
}


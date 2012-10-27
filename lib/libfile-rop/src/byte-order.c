#include <stdint.h>

#include "byte-order.h"

// return true if big endian
int arch_is_big_endian() {
    long one = 1;
    return !(*((char *)(&one)));
}

uint16_t endian_swap_16(uint16_t x) {
    uint16_t swapped = x;

    swapped = (swapped>>8) | (swapped<<8);

    return swapped;
}

uint32_t endian_swap_32(uint32_t x) {
    uint32_t swapped = x;

    swapped = (swapped>>24) | 
        ((swapped<<8) & 0x00FF0000) |
        ((swapped>>8) & 0x0000FF00) |
        (swapped<<24);

    return swapped;
}

uint64_t endian_swap_64(uint64_t x) {
    uint64_t swapped = x;

    swapped = (swapped>>56) | 
        ((swapped<<40) & 0x00FF000000000000) |
        ((swapped<<24) & 0x0000FF0000000000) |
        ((swapped<<8)  & 0x000000FF00000000) |
        ((swapped>>8)  & 0x00000000FF000000) |
        ((swapped>>24) & 0x0000000000FF0000) |
        ((swapped>>40) & 0x000000000000FF00) |
        (swapped<<56);

    return swapped;
}

uint64_t endian_swap_by_size (uint64_t x, int sz) {
    uint64_t swapped = x;

    if (sz == 2)
        swapped = endian_swap_16((uint16_t)x);
    else if (sz == 4)
        swapped = endian_swap_32((uint32_t)x);
    else if (sz == 8)
        swapped = endian_swap_64((uint64_t)x);
     return swapped;
}


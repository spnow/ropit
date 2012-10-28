#include <stdint.h>

#include "arch/arch.h"
#include "arch/x86/inst.h"
#include "offsets.h"

static struct opcode branches[] = {
    // rets
    {
        .arch = ARCH_X86_32 | ARCH_X86_64,
        .type = INST_TYPE_RET,
        .sz_bytes = 1,
        .bytes = "\xc2",
        .sz_repr = 3,
        .repr = "ret" 
    },
    {
        .arch = ARCH_X86_32 | ARCH_X86_64,
        .type = INST_TYPE_RET,
        .sz_bytes = 1,
        .bytes = "\xc3",
        .sz_repr = 3,
        .repr = "ret" 
    },
    {
        .arch = ARCH_X86_32 | ARCH_X86_64,
        .type = INST_TYPE_RET,
        .sz_bytes = 3,
        .bytes = "\xca??",
        .sz_repr = 3,
        .repr = "ret"
    },
    {
        .arch = ARCH_X86_32 | ARCH_X86_64,
        .type = INST_TYPE_RET,
        .sz_bytes = 3,
        .bytes = "\xcb??",
        .sz_repr = 3,
        .repr = "ret"
    },
    {
        .arch = ARCH_X86_32 | ARCH_X86_64,
        .type = INST_TYPE_RET,
        .sz_bytes = 1,
        .bytes = "\xcf",
        .sz_repr = 3,
        .repr = "ret"
    },

    // call
    {
        .arch = ARCH_X86_16,
        .type = INST_TYPE_CALL,
        .sz_bytes = 3,
        .bytes = "\xe8??",
        .sz_repr = 5,
        .repr = "call "
    },
    {
        .arch = ARCH_X86_32 | ARCH_X86_64,
        .type = INST_TYPE_CALL,
        .sz_bytes = 5,
        .bytes = "\xe8????",
        .sz_repr = 5,
        .repr = "call "
    },
    {
        .arch = ARCH_X86_16,
        .type = INST_TYPE_CALL,
        .sz_bytes = 5,
        .bytes = "\x9a????",
        .sz_repr = 5,
        .repr = "call "
    },
    {
        .arch = ARCH_X86_32 | ARCH_X86_64,
        .type = INST_TYPE_CALL,
        .sz_bytes = 7,
        .bytes = "\x9a??????",
        .sz_repr = 5,
        .repr = "call "
    },
    {
        .arch = ARCH_X86_16 | ARCH_X86_32 | ARCH_X86_64,
        .type = INST_TYPE_CALL,
        .sz_bytes = 2,
        .bytes = "\xff\xd0",
        .sz_repr = 5,
        .repr = "call "
    },


    // jmp
    {
        .arch = ARCH_X86_16,
        .type = INST_TYPE_JMP,
        .sz_bytes = 3,
        .bytes = "\xe9??",
        .sz_repr = 5,
        .repr = "jmp"
    },
    {
        .arch = ARCH_X86_32 | ARCH_X86_64,
        .type = INST_TYPE_JMP,
        .sz_bytes = 5,
        .bytes = "\xe9????",
        .sz_repr = 5,
        .repr = "jmp"
    },
    {
        .arch = ARCH_X86_16,
        .type = INST_TYPE_JMP,
        .sz_bytes = 5,
        .bytes = "\xea????",
        .sz_repr = 5,
        .repr = "jmp"
    },
    {
        .arch = ARCH_X86_32 | ARCH_X86_64,
        .type = INST_TYPE_JMP,
        .sz_bytes = 7,
        .bytes = "\xea??????",
        .sz_repr = 5,
        .repr = "jmp"
    },
    {
        .arch = ARCH_X86_16 | ARCH_X86_32 | ARCH_X86_64,
        .type = INST_TYPE_JMP,
        .sz_bytes = 2,
        .bytes = "\xeb?",
        .sz_repr = 5,
        .repr = "jmp short"
    },

    // jcc
    // end
    { 0 }
};

int bytes_cmp_mask (uint8_t *bytes, int blen, uint8_t *mask, int mlen)
{
    int idx_byte;

    if (blen < mlen)
        return blen - mlen;

    for (idx_byte = 0; idx_byte < mlen; idx_byte++) {
        if (mask[idx_byte] == '?' || mask[idx_byte] == '*')
            continue;
        if (bytes[idx_byte] != mask[idx_byte])
            return *bytes - *mask;
    }

    return 0;
}

uint8_t *bytes_search (uint8_t *haystack, int hlen, uint8_t *needle, int nlen)
{
    int idx_byte;

    for (idx_byte = 0; idx_byte < hlen; idx_byte++) {
        if (byte_cmp_mask(haystack + idx_byte, hlen - idx_byte, needle, nlen) == 0)
            return haystack + idx_byte;
    }

    return NULL;
}

struct offsets_t *x86_find_opcodes (uint8_t *bytes, int len, struct opcode *opcodes)
{
    int idx_opcode;
    struct opcode opcode;

    for (idx_opcode = 0; ; idx_opcode++) {

    }

    return NULL;
}

struct offsets_t *x86_find_branches (uint8_t *bytes, int len)
{
}

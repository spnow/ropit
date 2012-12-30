#ifndef _INST_X86_H_
#define _INST_X86_H_

enum INST_TYPE {
    INST_TYPE_RET, INST_TYPE_JMP, INST_TYPE_CALL
};

struct opcode {
    int arch;
    int type;
    int sz_bytes;
    char *bytes;
    int sz_repr;
    char *repr;
};

#endif /* _INST_X86_H_ */


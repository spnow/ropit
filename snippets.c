// find valid instructions offsets before ret
struct ropit_offsets_t* ropit_gadgets_find_new(unsigned char *bytes, size_t len) {
    int size;                /* size of instruction */
    x86_insn_t insn;         /* instruction */
    long idx, idxValid;
    // dupe variables
    long idxDupe, dupe;
    // back track instruction count
    long nBacktrackInst, nBacktrackBytes;

    struct ropit_offsets_t *valid;

    // start for rop search
    unsigned char *start;
    // offsets

    // search rets
    struct ropit_offsets_t *rets = ropit_opcodes_find_ret(bytes, len);
    if (!rets) {
        fprintf(stderr, "Error: No rets\n");
        return NULL;
    }

    // allocate
    valid = ropit_offsets_new(len / 8);
    if (!valid) {
        fprintf(stderr, "ropit_instructions_find(): failed alloc\n");
        return NULL;
    }

    // init disasm
    x86_init(opt_none, NULL, NULL);

    for (idx = 0, idxValid = 0; idx < rets->used; idx++) {
        start = bytes + rets->offsets[idx];
        nBacktrackInst = 0;
        nBacktrackBytes = 1;
        while ( bytes <= start ) {
            /* disassemble address */
            size = x86_disasm(start, start - bytes, 0, 0, &insn);
            if (size) {
                // check presence of value, if there it's not added
                for (idxDupe = 0, dupe = 0; idxDupe < idxValid; idxDupe++) {
                    if (valid->offsets[idxDupe] == start - bytes)
                        dupe = 1;
                }

                // doesn't register offset if already there
                if (!dupe) {
                    if (idxValid >= valid->capacity)
                        valid = ropit_offsets_realloc(valid, valid->capacity * 2);
                    if (!valid || !(valid->offsets)) {
                        x86_cleanup();
                        ropit_offsets_destroy(&rets);
                        return NULL;
                    }
                    valid->offsets[idxValid] = start - bytes;
                    idxValid++;
                }
                start--;
                nBacktrackBytes = 1;
                nBacktrackInst++;
            }
            else {
                start--;
                nBacktrackBytes++;
            }
            x86_oplist_free(&insn);
            // maximum intel instruction size is 15
            if (nBacktrackBytes >= 15 || nBacktrackInst == 32)
                break;
        }
    }
    x86_cleanup();

    valid->used = idxValid;

    // we remove out rets in instructions list
    for (idxValid = 0; idxValid < valid->used; idxValid++) {
        if (ropit_offsets_exist(rets, valid->offsets[idxValid])) {
            valid->offsets[idxValid] = -1;
            valid->used--;
        }
    }

    qsort (valid->offsets, idxValid, sizeof(int), compare_ints);
    valid = ropit_offsets_realloc(valid, valid->used);

    ropit_offsets_destroy(&rets);

    return valid;
}

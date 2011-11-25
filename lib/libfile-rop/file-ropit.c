#include <stdlib.h>
#include <stdio.h>

// for O_WRONLY
#include <fcntl.h>
#include <string.h>

// for offsetof() macro
#include <stddef.h>

// tar library
#include <libtar.h>
// bzip2 library
#include <bzlib.h>

#include "file-ropit.h"
#include "byte-order.h"

static char tmpDir[L_tmpnam];

int ropit_file_load (char *filename) {
    // local labels
    __label__ _cleanup;
    //
    FILE *fp;
    int szFilename;
    // bzip2
    BZFILE *bzfile;
    int bzerror;
    char bzdata[1024];
    // tarfile
    TAR *tarfile;
    FILE *tarfp;

    // file names
    char *fnameResume, *fnameGadget;

    // check file
    if (!filename)
        return -1;

    // open file
    fp = fopen(filename, "r");
    if (!fp)
        return -1;
    
    // open bz2 file
    bzfile = BZ2_bzReadOpen(&bzerror, fp, 0, 0, NULL, 0);
    if (!bzfile || bzerror != BZ_OK)
        goto _cleanup;

    // create temporary tar 
    do {
        tarfp = tmpfile();
    } while (tarfp == NULL);

    // decompress tar file
    do {
        BZ2_bzRead(&bzerror, bzfile, bzdata, 1024);
        fwrite(bzdata, sizeof(*bzdata), 1024, tarfp);
    } while (bzerror == BZ_OK && bzerror != BZ_STREAM_END);

    //
    tar_fdopen(&tarfile, fileno(tarfp), "", NULL, O_WRONLY, 0, TAR_GNU);

    // temporary dir name
    tar_extract_all(tarfile, tmpnam(tmpDir));

    // close tar file
    tar_close(tarfile);
    // delete tar file
    fclose(tarfp);

    // close bz2 file
    BZ2_bzReadClose(&bzerror, bzfile);

    // close archive file
    fclose(fp);


    szFilename = strlen(filename);

    // load resume file
    // get resume filename
    fnameResume = calloc(sizeof(*fnameResume), szFilename + 8);
    strcpy(fnameResume, filename);
    strcat(fnameResume, "-resume");
    // now we load extracted files
    fp = fopen(fnameResume, "r");
    if (!fp)
        goto _end;
    fclose(fp);

    // load gadget file
    // get gadget filename
    fnameGadget = calloc(sizeof(*fnameGadget), szFilename + 8);
    strcpy(fnameGadget, filename);
    strcat(fnameGadget, "-gadget");
    // now we load extracted files
    fp = fopen(fnameGadget, "r");
    if (fp)
        goto _end;

_cleanup:
    fclose(fp);
_end:
    return 0;
}

int ropit_file_check_size(FILE *fp) {
}

int ropit_file_resume_check(FILE *fp) {
}

int ropit_file_gadget_check(FILE *fp) {
}

// check validity of ropit file
int ropit_file_check(FILE *fp) {
}

struct ropit_file_resume* ropit_file_resume_load(char *filename) {
}

int ropit_file_resume_update(FILE *fp, struct ropit_file_resume *file) {
}

struct ropit_file_resume* ropit_file_gadget_load(char *filename) {
}


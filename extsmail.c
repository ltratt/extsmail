// Copyright (C)2008 Laurence Tratt http://tratt.net/laurie/
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.


#include "Config.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#include "conf.h"
#include "common.h"




extern char* __progname;




int main(int argc, char** argv)
{
    Conf *conf = read_conf();

    // Check that everything to do with the spool dir is OK.

    if (!check_spool_dir(conf))
        exit(1);
    
    // Create the spool file.
    
    char *sp; // spool path
    if (asprintf(&sp, "%s%s%s%sXXXXXXXXXX", conf->spool_dir, DIR_SEP, MSGS_DIR,
      DIR_SEP) == -1) {
        errx(1, "Unable to allocate memory");
    }
    
    int sfd;
    if ((sfd = mkstemp(sp)) == -1) {
        err(1, "When creating spool file %s", sp);
    }
    
    // We immediately try to gain an exclusive lock on the newly created spool
    // file. If, in between the spool file being created, and us gaining the
    // lock extsmaild gains a lock it will notice that the file is currently
    // 0 bytes long, and that therefore the file is incomplete. extsmaild will
    // then relinquish its lock, allowing us to gain it and write the file in
    // full.
    
    if (flock(sfd, LOCK_EX) == -1) {
        err(1, "When locking spool file %s", sp);
    }

    // Open the spool file for writing. The format of the spool file is:
    //
    //   1) The file format version number (of the format "v1" etc.)
    //   2) Newline
    //   3) The number of command line arguments
    //   4) Newline
    //   5) Each command line argument, with the format "<len(arg)>\n<arg>\n".
    //   6) The mail contents as read from stdin
    
    FILE *sf;
    if ((sf = fdopen(sfd, "w")) == NULL) {
        err(1, NULL);
    }

#   define SPOOL_WRITE(fmt, args...) if (fprintf(sf, fmt, ##args) == -1) \
        err(1, "%s: When writing to spool file", sp)

    // Write out the file format version number

    SPOOL_WRITE("%s\n", VERSION1_ID);

    // Write out all the command-line args

    SPOOL_WRITE("%d\n", argc - 1);
    
    for (int i = 1; i < argc; i += 1) {
        SPOOL_WRITE("%zd\n%s\n", strlen(argv[i]), argv[i]);
    }

#   define BUF_SIZE 1024

    char buf[BUF_SIZE];
    while (1) {
        size_t nbr; // Number of bytes read
        if ((nbr = fread(buf, 1, BUF_SIZE, stdin)) < BUF_SIZE) {
            if (ferror(stdin)) {
                fprintf(stderr, "%s: Error when reading stdin.", __progname);
                exit(1);
            }
        }

        if (fwrite(buf, 1, nbr, sf) < nbr) {
            fprintf(stderr, "%s: Error when writing to spool file.", __progname);
            exit(1);
        }
        
        if (feof(stdin) != 0)
            break;
    }
    
    fflush(sf);
    fclose(sf);
    flock(sfd, LOCK_UN);
    close(sfd);
    
    return 0;
}

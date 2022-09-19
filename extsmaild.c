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

#include <assert.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <regex.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifdef HAVE_KQUEUE
#   include <sys/event.h>
#elif HAVE_INOTIFY
#   include <sys/inotify.h>
#   include <sys/select.h>
#endif
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifndef HAVE_STRTONUM
#include "compat/strtonum.h"
#endif

#ifdef HAVE_BSD_STDLIB_H
#include <bsd/stdlib.h>
#endif

#include "conf.h"
#include "common.h"
#include "externals.h"

// #define DBG_LEAKS 1

static const char *EXTERNALS_PATHS[] = {"~/.extsmail/externals",
  "/etc/extsmail/externals", NULL};
#define LOCKFILE "extsmaild.lock"

// Size of the initial header buffer (and also the size that it will be
// incremented by if it's not big enough).
#define HEADER_BUF 2048
// Size of the initial stderr buffer (and also the size that it will be
// incremented by if it's not big enough).
#define STDERR_BUF_ALLOC 1024
// Size of the initial buffer copying data from a message to the child
// process.
#define PTOC_BUFLEN 4096
// Initial poll wait in seconds - on each failure, this value is doubled. The
// value is capped at MAX_POLL_WAIT seconds.
#define INITIAL_POLL_WAIT 5
// The maximum number of seconds to wait between polls.
#define MAX_POLL_WAIT 60
// The maximum number of seconds to wait when no data has been sent or received
// from the sendmail process.
#define MAX_POLL_NO_SEND 60

#ifdef HAVE_INOTIFY
// Size in bytes of the inotify buffer.
#   define INOTIFY_BUFLEN ((sizeof(struct inotify_event)+FILENAME_MAX)*1024)
#endif


typedef struct _pid_llist {
    pid_t pid;
    int cstdin_fd;
    struct _pid_llist *next;
} PID_LList;

typedef struct {
    bool any_failure;     // Set to true if any message in the spool dir was not
                          // sent. Reset on each cycle
    time_t last_success;  // The time of the last successful send of all
                          // messages.
    time_t last_notify_failure; // The time of the last notification of failure.
                          // Note this always >= last_success.

    // A linked list of processes which have been timed out and for which we're
    // waiting for a SIGKILL to take effect. Normally SIGKILL has immediate
    // effect, unless the process is an uninterruptable sleep (e.g. it's waiting
    // on a read from a disk with a bad sector) at which point the kernel may
    // keep the process alive but not send signals to it. We have to keep seeing
    // if such processes have come alive and died
    PID_LList *pid_llist;
} Status;


extern char* __progname;

static void read_externals(char *);
char *find_externals_path();
static void free_groups();
static int try_externals_path(const char *);
static int cycle(Conf *, Group *, Status *);
static bool try_groups(Conf *, Status *, const char *, int);
static void push_killed_pid(Status *, pid_t, int);
static void cycle_killed_pids(Status *);
static void do_notify_failure_cmd(Conf *, Status *);
static void do_notify_success_cmd(Conf *, int);
static bool set_nonblock(int);




////////////////////////////////////////////////////////////////////////////////
// Lock file
//

static char *lock_path;
static int lock_fd;

static void lock_exit();
static void sigterm_trap(int);
static void sighup_trap(int);
static volatile sig_atomic_t reload_config = 0;


static void obtain_lock(Conf *conf)
{
    if (asprintf(&lock_path, "%s%s%s", conf->spool_dir, DIR_SEP, LOCKFILE)
      == -1) {
        errx(1, "obtain_lock: asprintf: unable to allocate memory");
    }

    // Try and obtain the lock file. We do this by trying to create a lock file
    // and then gaining a lock on it. If the lock file exists but there isn't
    // a lock on it then we assume the lock file is stale and that there's no
    // running extsmaild.

    if (((lock_fd = open(lock_path, O_CREAT | O_RDWR, 0600)) == -1)
     && errno != EEXIST) {
        err(1, "Unable to obtain lockfile '%s'", lock_path);
    }

    if (flock(lock_fd, LOCK_EX | LOCK_NB) == -1) {
        err(1, "Unable to obtain lockfile '%s'", lock_path);
    }

    // Install an exit handler and signal trap so that, barring something going
    // catastrophically wrong, the lockfile is removed on exit.

    atexit(lock_exit);
    signal(SIGINT, sigterm_trap);
    signal(SIGTERM, sigterm_trap);
    signal(SIGHUP, sighup_trap);
}



////////////////////////////////////////////////////////////////////////////////
// Configuration file related
//

Group *groups = NULL;
extern int yyeparse(void);
extern FILE *yyein;



//
// Exit handler for atexit.
//
// This should be kept as simple as possible.
//

static void lock_exit()
{
    unlink(lock_path);
    free(lock_path);
    flock(lock_fd, LOCK_UN);
    close(lock_fd);
}



//
// Function when SIGINT/SIGTERM is received. Basically it's only intended
// (indirectly) to call lock_exit. Note that at the moment we kill ourselves
// immediately rather than waiting for a poll loop - at the very worse this
// means a message might get sent twice. A message will never not get sent
// because we bomb out at an arbitrary point.
//

static void sigterm_trap(__attribute__ ((unused)) int sigraised)
{
    exit(1);
}



//
// Function when SIGHUP is received. This reloads the externals configuration.
// Check the configuration file by running "extsmaild -t"
//

static void sighup_trap(__attribute__ ((unused)) int sigraised)
{
    reload_config = 1;
}



//
// Read the externals file in.
//
// This function does not return if there is a problem.
//

static void read_externals(char *path)
{
    if (path != NULL) {
        int rtn = try_externals_path(path);
        if (rtn != 0)
            err(1, "Couldn't read externals file at '%s'", path);
    }

    for (int i = 0; EXTERNALS_PATHS[i] != NULL; i += 1) {
        char *cnd_path = expand_path(path);
        if (cnd_path == NULL) {
            free(cnd_path);
            return;
        }

        int rtn = try_externals_path(cnd_path);
        free(cnd_path);
        if (rtn == 0)
            return;
        else if (rtn == -1)
            exit(1);
    }

    err(1, "Can't find a valid externals file");
}


//
// Search for an externals file, returning a malloc'd block containing a path
// if successful.
//
// This function does not return if it does not find an externals file.
//

char *find_externals_path() {
    for (int i = 0; EXTERNALS_PATHS[i] != NULL; i += 1) {
        char *cnd_path = expand_path(EXTERNALS_PATHS[i]);

        if (access(cnd_path, F_OK) == 0)
            return cnd_path;

        free(cnd_path);
    }

    err(1, "Can't find a valid externals file");
}


//
// Free groups/matches/externals
//

static void free_matches(Match *match) {
    if (NULL == match)
        return;

    Match *next = match->next;

#if DBG_LEAKS
    fprintf(stderr, "MAT free_matches(%p)\n", (void *)match);
    fprintf(stderr, "    regex: %s\n", match->regex);
    fprintf(stderr, "    preg= %p\n", (void *)&match->preg);
    fprintf(stderr, "MAT free_matches next= %p\n", (void *)next);
#endif

    free(match->regex);
    regfree(&match->preg);
    free(match);

    free_matches(next);
}


static void free_externals(External *external)
{
    if (NULL == external)
        return;

    External *next = external->next;

#if DBG_LEAKS
    fprintf(stderr, "EXT free_externals(%p)\n", (void *)external);
    fprintf(stderr, "    name: %s\n", external->name);
    fprintf(stderr, "    sendmail: %s\n", external->sendmail);
    fprintf(stderr, "    sendmail_argv: %s\n", *external->sendmail_argv);
    fprintf(stderr, "    sendmail_nargv: %d\n", external->sendmail_nargv);
    fprintf(stderr, "EXT free_externals next= %p\n", (void *)next);
#endif

    free(external->name);
    free(external->sendmail);
    for (int i = 0; i < external->sendmail_nargv; i++)
        free(external->sendmail_argv[i]);
    free(external->sendmail_argv);
    free(external);

    free_externals(next);
}


static void free_groups()
{
    if (groups == NULL)
        return;

    Group *cur = groups;
    while (cur != NULL) {
        free_matches(cur->matches);
        free_externals(cur->externals);
        Group *old = cur;
        cur = old->next;
        free(old);
    }
}

#if HAVE_YYLEX_DESTROY
extern void yyelex_destroy(void);
#endif

//
// Attempts to read a configuration file at 'path'; returns 0 on success, 1 if a
// file is not found and -1 if an error occurred.
//

static int try_externals_path(const char *path)
{
    yyein = fopen(path, "rt");
    if (yyein == NULL) {
        if (errno == ENOENT)
            return 1;
        return -1;
    }

    // See whether the externals exists at 'path'.
    struct stat externals_st;
    if (fstat(fileno(yyein), &externals_st) == -1) {
        return 1;
    }

    // Check that the user and group of the externals file match the
    // executing process.
    if (externals_st.st_uid != geteuid() || externals_st.st_gid != getegid()) {
        warnx("The user and / or group permissions of '%s' do not match the "
          "executing user", path);
        return -1;
    }

    if (yyeparse() != 0) {
        fclose(yyein);
        return -1;
    }
    assert(groups != NULL);

    fclose(yyein);
#if HAVE_YYLEX_DESTROY
    yyelex_destroy();
#endif

    return 0;
}



////////////////////////////////////////////////////////////////////////////////
// The main message sending cycle
//

//
// Try sending any messages in the spool dir. Returns the number of messages
// successfully sent.
//

static int cycle(Conf *conf, Group *groups, Status *status)
{
    char *msgs_path; // msgs dir (within spool dir)
    if (asprintf(&msgs_path, "%s%s%s", conf->spool_dir, DIR_SEP, MSGS_DIR)
      == -1) {
        syslog(LOG_CRIT, "cycle: asprintf: unable to allocate memory");
        exit(1);
    }

    DIR *dirp = opendir(msgs_path);
    if (dirp == NULL) {
        syslog(LOG_ERR, "When opening spool dir: %s", strerror (errno));
        free(msgs_path);
        return false;
    }

    if (conf->mode == DAEMON_MODE) {
        if (status->any_failure) {
            // In daemon mode, we try to make sure we don't get "stuck" on the
            // same message. For example, if a message is too big to be sent by
            // the remote sendmail, it can stop us sending other messages. If
            // in the last cycle we encountered a failure, we randomly skip
            // some entries in the queue directory on the basis that it might
            // allow some other messages to be sent.
            uint32_t num_entries = 0;
            while (readdir(dirp) != NULL) {
                num_entries += 1;
            }
            rewinddir(dirp);
            uint32_t skip = arc4random_uniform(num_entries);
            for (uint32_t i = 0; i < skip; i += 1) {
                readdir(dirp);
            }
        }
    }

    // Reset all the externals "working" status so that we'll try all of them
    // again.

    Group *cur_group = groups;
    while (cur_group != NULL) {
        External *cur_ext = cur_group->externals;
        while (cur_ext != NULL) {
            cur_ext->working = true;
            cur_ext = cur_ext->next;
        }
        cur_group = cur_group->next;
    }

    bool all_sent = true;
    bool reached_end = false; // Have we iterated through the directory at least once?
    int num_successes = 0;   // How many messages have been successfully sent.
    while (1) {
        char *msg_path = NULL;

        errno = 0;
        struct dirent *dp = readdir(dirp);
        if (dp == NULL) {
            if (errno == 0) {
                // We've got to the end of the directory.
                if (conf->mode == DAEMON_MODE) {
                    if (reached_end
                      || (!reached_end && !status->any_failure && num_successes == 0)) {
                        break;
                    }
                    reached_end = true;
                    rewinddir(dirp);
                    continue;
                }
                else
                    break;
            }
            else {
                all_sent = false;
                break;
            }
        }

        // The entries "." and ".." are, fairly obviously, not messages.
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0) {
            continue;
        }

        if (asprintf(&msg_path, "%s%s%s%s%s", conf->spool_dir, DIR_SEP,
          MSGS_DIR, DIR_SEP, dp->d_name) == -1) {
            syslog(LOG_CRIT, "cycle: asprintf: unable to allocate memory");
            exit(1);
        }

        int fd = open(msg_path, O_RDONLY);
        if (fd == -1) {
            // If we couldn't so much as open the file then something odd
            // has happened.
            free(msg_path);
            all_sent = false;
            continue;
        }

        if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
            if (errno != EWOULDBLOCK)
                syslog(LOG_ERR, "Error when flocking'ing '%s'", msg_path);

            free(msg_path);
            close(fd);
            all_sent = false;
            continue;
        }

        // We've now got an exclusive lock on the file.
        struct stat msg_st;
        if (fstat(fd, &msg_st) == -1) {
            syslog(LOG_ERR, "Error when fstat'ing '%s'", msg_path);
            free(msg_path);
            close(fd);
            all_sent = false;
            continue;
        }

       if (msg_st.st_size == 0) {
            // If the file is zero size it either means that we managed to
            // interrupt extsmail before it had managed to obtain an exclusive
            // lock and write any data to the file or the user accidentally
            // created a 0 length file in the spool dir (which is easy to do by
            // calling "extsmail" instead of "extsmaild"). Because the latter
            // is a semi-permanent condition, we don't count this as
            // unsuccessful.
            free(msg_path);
            close(fd);
            continue;
        }

        if (try_groups(conf, status, msg_path, fd)) {
            num_successes += 1;
        } else {
            all_sent = false;
            close(fd);
        }
        free(msg_path);
    }

    closedir(dirp);
    free(msgs_path);

    if (conf->mode == DAEMON_MODE) {
        if (all_sent) {
            status->any_failure = false;
            status->last_success = status->last_notify_failure = time(NULL);
            if (num_successes == 0) {
                // Since we haven't sent anything, we don't really know if our
                // externals are alive or not. We therefore assume they are
                // all live or have come back to life. Update the last_success
                // accordingly to force them to be used the next time there are
                // messages to send.
                Group *cur_group = groups;
                while (cur_group != NULL) {
                    External *cur_ext = cur_group->externals;
                    while (cur_ext != NULL) {
                        cur_ext->last_success = time(NULL);
                        cur_ext = cur_ext->next;
                    }
                    cur_group = cur_group->next;
                }
            }
        }
        else
            status->any_failure = true;
    }

    if (num_successes > 0)
        do_notify_success_cmd(conf, num_successes);

    return num_successes;
}



//
// Read in the arguments passed to a message file.
//
// Returns true on success, false on failure. If successful, 'rargv' points to an
// array of argument strings of length 'rnargv'.
//

static bool read_argv(const char *msg_path, int fd, char ***rargv, int *rnargv)
{
    // Check that the version string is one we can handle.

    char *vs = fdrdline(fd); // Version string
    if (vs == NULL || strcmp(vs, VERSION1_ID) != 0) {
        if (vs != NULL)
            free(vs);
        syslog(LOG_ERR, "Unknown version specifier in '%s'", msg_path);
        return false;
    }
    free(vs);

    // Process all the arguments given to extsmail.

    char *nas = fdrdline(fd); // Number of arguments
    if (nas == NULL) {
        syslog(LOG_ERR, "Corrupted message '%s'", msg_path);
        return false;
    }
    const char *errstr = NULL;
    int nargv = (int) strtonum(nas, 0, INT_MAX - 1, &errstr);
    free(nas);
    if (errstr != NULL) {
        syslog(LOG_ERR, "Invalid number of arguments in '%s'", msg_path);
        return false;
    }
    char **argv = malloc((nargv + 1) * sizeof(char *));
    for (int i = 0; i < nargv; i++) {
        char *as = fdrdline(fd); // Size of argument
        if (as == NULL) {
            for (int j = 0; j < i; j += 1)
                free(argv[j]);
            free(argv);
            syslog(LOG_ERR, "Corrupted message '%s'", msg_path);
            return false;
        }
        assert(errstr == NULL);
        int sa = (int) strtonum(as, 0, INT_MAX - 1, &errstr);
        free(as);
        if (errstr != NULL) {
            for (int j = 0; j < i; j += 1)
                free(argv[j]);
            free(argv);
            syslog(LOG_ERR, "Invalid argument size in '%s'", msg_path);
            return false;
        };

        char *arg = malloc(sa + 1);
        if (arg == NULL) {
            syslog(LOG_CRIT, "try_groups: malloc: %s", strerror (errno));
            exit(1);
        }

        ssize_t nr = read(fd, arg, sa + 1);
        if (nr < sa + 1 // Note this also captures nr == 0 and nr == -1
          || arg[sa] != '\n') {
            for (int j = 0; j < i; j += 1)
                free(argv[j]);
            free(argv);
            free(arg);
            syslog(LOG_ERR, "Corrupted message '%s'", msg_path);
            return false;
        }
        arg[sa] = '\0';

        argv[i] = arg;
    }
    argv[nargv] = NULL;

    *rargv = argv;
    *rnargv = nargv;

    return true;
}



//
// Try and find a matching group for 'fd'.
//
// Returns a group if successsful, or NULL on failure.
//
// NOTE: This function can arbitrarily move the current seek position of fd.
//

static Group *find_group(const char *msg_path, int fd)
{
    // Read in the messages header, doctoring it along the way to make it
    // suitable for being searched with regular expressions. The doctoring is
    // very simple. Individual headers are often split over multiple lines: we
    // merge such lines together.

    ssize_t dhb_buf_alloc = HEADER_BUF;
    char *dhd_buf = malloc(dhb_buf_alloc); // Doctored header buffer
    int dhd_buf_len = 0;
    while (true) {
        char *line = fdrdline(fd);
        if (line == NULL) {
            syslog(LOG_ERR, "Corrupted message '%s'", msg_path);
            goto err;
        }
        ssize_t line_len = strlen(line);

        // If we've hit an empty line then we've reached the end of the headers.

        if (line_len == 0) {
            free(line);
            break;
        }

        while (dhd_buf_len + line_len + 1 > dhb_buf_alloc) {
            dhb_buf_alloc += HEADER_BUF;
            dhd_buf = realloc(dhd_buf, dhb_buf_alloc);
            if (dhd_buf == NULL) {
                syslog(LOG_CRIT, "try_groups: realloc: %s", strerror (errno));
                exit(1);
            }
        }

        if (dhd_buf_len > 0 && (line[0] == ' ' || line[0] == '\t')) {
            // This line began with space / tab chars, which means it's a
            // continuation of the header in the previous line.

            dhd_buf_len -= 1;
        }
        memcpy(dhd_buf + dhd_buf_len, line, line_len);
        dhd_buf[dhd_buf_len + line_len] = '\n';
        dhd_buf_len += line_len + 1;
        free(line);
    }
    dhd_buf[dhd_buf_len - 1] = 0; // Convert the last newline into a NUL

    // Try and find a matching group and then send the message.

    Group *group = groups;
    while (group != NULL) {
        if (group->matches == NULL) {
            // As soon as we hit a group with no match / reject clauses, we've
            // found a matching group.
            break;
        }

        Match *match = group->matches;
        while (match != NULL) {
            // XXX at the moment we try and preserve compatibility by
            // NUL-terminating dhd_buf - this means that if NUL-chars appear in
            // the header, unpredictable behaviour might result. Is this a
            // problem?

            int rtn = regexec(&match->preg, dhd_buf, 0, NULL, 0);
            if (!(rtn == 0 || rtn == REG_NOMATCH)) {
                size_t buf_size = regerror(rtn, &match->preg, NULL, 0);
                char *buf = malloc(buf_size);
                if (buf == NULL) {
                    syslog(LOG_CRIT, "try_groups: malloc: %s", strerror (errno));
                    exit(1);
                }
                regerror(rtn, &match->preg, buf, buf_size);
                warnx("Error when matching regular expression '%s': %s",
                  match->regex, buf);
                free(buf);
                goto err;
            }

            if (match->type == MATCH && rtn != 0)
                goto next_group;
            else if (match->type == REJECT && rtn == 0)
                goto next_group;

            match = match->next;
        }

        // At this point we know that all the matches in this group have been
        // successful - we've found our group!

        break;

next_group:
        group = group->next;
    }

    free(dhd_buf);
    return group;

err:
    free(dhd_buf);
    return NULL;
}



//
// Send the message to the child sendmail process, by copying the contents of
// 'fd' from the current seek position to the pipe 'cstdin_fd'.
//
// Returns true on success, false on failure. 'errmsgbuf' will point to a
// malloc'd area of memory which will contain 'errmsgbuf_used' bytes of error
// output. This block is allocated whether true or false is returned.
// `cstdin_fd` will be set -1 if the caller of the child process's stdin is
// not yet closed (i.e. if the caller to the function must close the file
// descriptor itself).
//

bool write_to_child(int fd, int cstderr_fd, int *cstdin_fd,
                    char **errmsgbuf, ssize_t *errmsgbuf_used)
{
    // The temporary buffer we use for reading from fd.
    ssize_t fdbuf_alloc = PTOC_BUFLEN;
    char *fdbuf = malloc(fdbuf_alloc);
    ssize_t fdbuf_used = 0, fdbuf_off = 0;

    // The stderr buffer.
    ssize_t stderrbuf_alloc = STDERR_BUF_ALLOC;
    *errmsgbuf = malloc(stderrbuf_alloc);
    *errmsgbuf_used = 0;

    if (fdbuf == NULL || *errmsgbuf == NULL) {
        syslog(LOG_CRIT, "write_to_child: malloc: %s", strerror (errno));
        exit(1);
    }

    // The 3 defines below must match the order of entries in the `statuses`
    // array and that the descriptors are passed to `poll`.
#   define POLL_FD 0
#   define POLL_CSTDIN 1
#   define POLL_CSTDERR 2

    // Has this file reached EOF and thus been closed?
#   define STATUS_EOF 1
    // Has this file hit an error and thus been closed? Note that EOF and ERR
    // are mutually exclusive.
#   define STATUS_ERR 2
    uint8_t statuses[3] = {0, 0, 0};

    // Set all the files to be non-blocking.
    if (!set_nonblock(fd) || !set_nonblock(cstderr_fd)
      || !set_nonblock(*cstdin_fd)) {
        *errmsgbuf_used = strlcpy(*errmsgbuf, "Can't set file descriptor flags", stderrbuf_alloc);
        goto err;
    }

    time_t last_io_time = time(NULL);
    int rtn;
    while (true) {
        // Are all files successfully closed?
        if ( (statuses[POLL_FD] & STATUS_EOF)
          && (statuses[POLL_CSTDIN] & STATUS_EOF)
          && (statuses[POLL_CSTDERR] & STATUS_EOF)) {
            // If there's still stuff in the buffer to write out, we've failed.
            if (fdbuf_used > 0)
                goto err;
            rtn = true;
            goto cleanup;
        }

        // Is at least one file in an error state and the other files are
        // closed?
        if ( (statuses[POLL_FD] & (STATUS_EOF|STATUS_ERR))
          && (statuses[POLL_CSTDIN] & (STATUS_EOF|STATUS_ERR))
          && (statuses[POLL_CSTDERR] & (STATUS_EOF|STATUS_ERR))) {
            goto err;
        }

        // Do we want to write to the child but it has closed its STDIN and
        // STDERR? Note that we need to wait until we have fully read its
        // stderr output.
        if (  fdbuf_used > 0
          && (statuses[POLL_CSTDIN] & (STATUS_EOF|STATUS_ERR))
          && (statuses[POLL_CSTDERR] & (STATUS_EOF|STATUS_ERR))) {
            if (!(statuses[POLL_FD] & (STATUS_EOF|STATUS_ERR))) {
                statuses[POLL_FD] = STATUS_EOF;
                close(fd);
            }
            goto err;
        }

        if (fdbuf_used == 0 && (statuses[POLL_FD] & STATUS_EOF)) {
            // We've fully written out fd. If the child's stdin hasn't been
            // closed, we can now close it. If we don't do this explicitly,
            // some child processes will hang, waiting for more input to be
            // received.
            if (!(statuses[POLL_CSTDIN] & (STATUS_EOF|STATUS_ERR))) {
                close(*cstdin_fd);
                *cstdin_fd = -1;
                statuses[POLL_CSTDIN] = STATUS_EOF;
            }
        }

        struct pollfd fds[] = {
          {fd, POLLIN, 0},
          {*cstdin_fd, POLLOUT, 0},
          {cstderr_fd, POLLIN, 0}};

        assert(!(statuses[POLL_FD] & STATUS_ERR));
        if (statuses[POLL_FD] & STATUS_EOF) {
            // If fd can't produce further input there's no point polling it.
            fds[POLL_FD].fd = -1;
        } else if (fdbuf_used > 0) {
            // We've still got stuff to write out from fdbuf, but we'd still
            // like to check whether it has closed or has suffered an error.
            fds[POLL_FD].events = 0;
        }

        if (statuses[POLL_CSTDIN] & (STATUS_EOF|STATUS_ERR)) {
            // If the child process won't accept further input, there's no
            // point polling it.
            fds[POLL_CSTDIN].fd = -1;
        } else if (fdbuf_used == 0) {
            // There's nothing to write to the child's stdin, but we'd still
            // like to check whether it is closed or has suffered an error.
            fds[POLL_CSTDIN].events = 0;
        }

        if (statuses[POLL_CSTDERR] & (STATUS_EOF | STATUS_ERR)) {
            // If the child's stderr cannot produce further output, there's no
            // point polling it.
            fds[POLL_CSTDERR].fd = -1;
        }

        time_t tout = (MAX_POLL_NO_SEND - (time(NULL) - last_io_time)) * 1000;
        if (tout <= 0) {
            *errmsgbuf_used = strlcpy(*errmsgbuf, "Timeout", stderrbuf_alloc);
            goto err;
        }

        if (poll(fds, 3, tout) == -1) {
            if (errno == EINTR)
                continue;
            goto err;
        }

        // First, try reading from POLL_FD. If any branch fails, `fds[POLL_FD]`
        // will be set to `STATUS_ERR`.
        if (fds[POLL_FD].revents & (POLLERR|POLLNVAL)) {
            statuses[POLL_FD] = STATUS_ERR;
        } else if (fds[POLL_FD].revents & POLLIN) {
            assert(fdbuf_used == 0);
            ssize_t nr = read(fd, fdbuf, fdbuf_alloc);
            if ((nr == -1) && !(errno == EAGAIN || errno == EINTR)) {
                // Something unrecoverable has happened to `fd`.
                statuses[POLL_FD] = STATUS_ERR;
            } else {
                last_io_time = time(NULL);
                if (nr == 0) {
                    close(fd);
                    statuses[POLL_FD] = STATUS_EOF;
                } else {
                    fdbuf_off = 0;
                    fdbuf_used = nr;
                }
            }
        } else if (fds[POLL_FD].revents & POLLHUP) {
            // It's unlikely that fd can be disconnected without POLLIN being
            // true and read() returning zero, but there's nothing to say this
            // can't happen. Note that POLLIN and POLLHUP are not mutually
            // exclusive, so we deliberately only check POLLHUP if POLLIN is
            // not set.
            close(fd);
            statuses[POLL_FD] = STATUS_EOF;
        }

        if (statuses[POLL_FD] & STATUS_ERR) {
            // If we've got an error reading from fd then we need to kill() the
            // child without closing its stdin, so that it doesn't think it's
            // successfully read all its input. Since this error is (highly
            // unlikely) to be the child's fault, there's no point carrying on
            // and trying to read the child's stderr.
            *errmsgbuf_used = strlcpy(*errmsgbuf,
              "Error reading message file", stderrbuf_alloc);
            goto err;
        }

        // Write data to the child process (if appropriate).
        if (fds[POLL_CSTDIN].revents & (POLLERR|POLLNVAL)) {
            statuses[POLL_CSTDIN] = STATUS_ERR;
        } else {
            if (fds[POLL_CSTDIN].revents & POLLOUT) {
                while (fdbuf_off < fdbuf_used) {
                    ssize_t tnw = write(*cstdin_fd, fdbuf + fdbuf_off, fdbuf_used - fdbuf_off);
                    if (tnw == -1) {
                        if (!(errno == EAGAIN || errno == EINTR)) {
                            statuses[POLL_CSTDIN] = STATUS_ERR;
                        }
                        break;
                    } else {
                        last_io_time = time(NULL);
                        fdbuf_off += tnw;
                        assert(fdbuf_off <= fdbuf_used);
                        if (fdbuf_off == fdbuf_used) {
                            fdbuf_off = fdbuf_used = 0;
                        }
                    }
                }
            } else if (fds[POLL_CSTDIN].revents & POLLHUP) {
                // POSiX specifies that POLLOUT and POLLHUP are mutually exclusive
                // so the `else if` is correct.
                close(*cstdin_fd);
                *cstdin_fd = -1;
                statuses[POLL_CSTDIN] = STATUS_EOF;
            }
        }

        // Read the child's stderr (if appropriate).
        if (fds[POLL_CSTDERR].revents & (POLLERR|POLLNVAL)) {
            close(cstderr_fd);
            statuses[POLL_CSTDERR] = STATUS_ERR;
        } else {
            if (fds[POLL_CSTDERR].revents & POLLIN) {
                ssize_t nr = read(cstderr_fd, *errmsgbuf + *errmsgbuf_used,
                  stderrbuf_alloc - *errmsgbuf_used);
                if (nr == -1) {
                    if (!(errno == EAGAIN || errno == EINTR)) {
                        close(cstderr_fd);
                        statuses[POLL_CSTDERR] = STATUS_ERR;
                    }
                } else {
                    last_io_time = time(NULL);
                    if (nr == 0) {
                        close(cstderr_fd);
                        statuses[POLL_CSTDERR] = STATUS_EOF;
                    } else if (nr == stderrbuf_alloc - *errmsgbuf_used) {
                        stderrbuf_alloc += STDERR_BUF_ALLOC;
                        *errmsgbuf = realloc(*errmsgbuf, stderrbuf_alloc);
                        if (*errmsgbuf == NULL) {
                            syslog(LOG_CRIT, "write_to_child: realloc: %s", strerror (errno));
                            exit(1);
                        }
                    }
                    *errmsgbuf_used += nr;
                }
            }
            if (fds[POLL_CSTDERR].revents & POLLHUP) {
                // Note that POLLIN and POLLHUP are not mutually exclusive so the
                // `if` is correct.
                close(cstderr_fd);
                statuses[POLL_CSTDERR] = STATUS_EOF;
            }
        }
    }

err:
    // stderr messages sometimes have random newline chars at the end of line - this loop
    // chomps them off.
    while (*errmsgbuf_used > 0
      && ((*errmsgbuf)[*errmsgbuf_used - 1] == '\n'
      || (*errmsgbuf)[*errmsgbuf_used - 1] == '\r'))
        *errmsgbuf_used -= 1;

    rtn = false;
    goto cleanup;

cleanup:
    free(fdbuf);
    if (!(statuses[POLL_FD] & (STATUS_EOF|STATUS_ERR)))
        close(fd);
    if (!(statuses[POLL_CSTDERR] & (STATUS_EOF|STATUS_ERR)))
        close(cstderr_fd);

    return rtn;
}



//
// Try sending an individual message. Returns true if successful, false
// otherwise.
//

static bool try_groups(Conf *conf, Status *status, const char *msg_path, int fd)
{
    char **argv;
    int nargv;
    if (!read_argv(msg_path, fd, &argv, &nargv))
        return false;

    // We need to record where the actual message starts before calling
    // find_group.

    off_t mf_body_off = lseek(fd, 0, SEEK_CUR);
    if (mf_body_off == -1) {
        syslog(LOG_ERR, "Error when lseek'ing from '%s'", msg_path);
        goto fail;
    }
    Group *group = find_group(msg_path, fd);
    if (group == NULL) {
        syslog(LOG_ERR, "No matching group found for '%s'", msg_path);
        goto fail;
    }
    if (lseek(fd, mf_body_off, SEEK_SET) == -1) {
        syslog(LOG_ERR, "Error when lseek'ing from '%s': %s", msg_path, strerror (errno));
        goto fail;
    }

    // At this point we've found a matching group for the message. We now go
    // through each external in the group and try to use it to send the message.

    External *cur_ext = group->externals;
    while (cur_ext != NULL) {
        // If we're in daemon mode, and we have an external which has a timeout
        // but which hasn't previously been tried, then we set its 'last_success'
        // value to the current time so that timeouts are measured from the first
        // time it is used.
        if (conf->mode == DAEMON_MODE
          && cur_ext->timeout != 0
          && cur_ext->last_success == 0) {
            assert(cur_ext->working);
            cur_ext->last_success = time(NULL);
        }

        if (!cur_ext->working) {
            // This particular external has previously been found to not be
            // working in this cycle.

            if (conf->mode == DAEMON_MODE) {
                // Check the external's timeout (if it has one). If the timeout
                // hasn't been exceeded, then we have to give up on trying to
                // send this messages via this, or other, externals - we need
                // to wait for the timeout to be exceeded.
                if (cur_ext->timeout != 0 &&
                  cur_ext->last_success + cur_ext->timeout > time(NULL)) {
                    goto fail;
                }
            }

            // Don't bother trying to use this external. This is an important
            // optimisation if using ssh for example: if a host is down, it can
            // take quite a while for network connections to time out, so we
            // don't want to continually retry something that already hasn't
            // worked. On the next cycle, the "working" flag will be reset.

            cur_ext = cur_ext->next;
            continue;
        }

        // OK, we're now ready to invoke the sendmail command for this
        // external. In order to do this, we first fork, with the child process
        // executing the sendmail command. We then pipe the message into the
        // sendmail process, and pipe stderr out from the child (so that we can
        // report errors to the user).

        int pipeto[2], pipefrom[2];
        if (pipe(pipeto) == -1) {
            syslog(LOG_ERR, "try_groups: pipe: %s", strerror (errno));
            goto fail;
        }
        if (pipe(pipefrom) == -1) {
            close(pipeto[0]);
            close(pipeto[1]);
            syslog(LOG_ERR, "try_groups: pipe: %s", strerror (errno));
            goto fail;
        }

        pid_t pid = fork();
        if (pid == -1) {
            close(pipeto[0]);
            close(pipeto[1]);
            close(pipefrom[0]);
            close(pipefrom[1]);
            syslog(LOG_ERR, "try_groups: fork: %s", strerror (errno));
            goto fail;
        }
        else if (pid == 0) {
            // Child / sendmail process. Any errors in this branch should cause
            // the child process to exit rather than try to continue executing
            // as if it was the parent process.

            close(STDOUT_FILENO);
            if (dup2(pipeto[0], STDIN_FILENO) == -1 || dup2(pipefrom[1],
              STDERR_FILENO) == -1) {
                close(pipeto[0]);
                close(pipeto[1]);
                close(pipefrom[0]);
                close(pipefrom[1]);
                syslog(LOG_CRIT, "try_groups: dup2: %s", strerror (errno));
                exit(1);
            }
            close(pipeto[0]);
            close(pipeto[1]);
            close(pipefrom[0]);
            close(pipefrom[1]);

            char **sub_argv = malloc((nargv + cur_ext->sendmail_nargv + 1) *
              sizeof(char *));
            if (sub_argv == NULL) {
                syslog(LOG_CRIT, "try_groups: malloc: %s", strerror (errno));
                exit(1);
            }

            memcpy(sub_argv, cur_ext->sendmail_argv,
              cur_ext->sendmail_nargv * sizeof(char *));
            memcpy(sub_argv + cur_ext->sendmail_nargv, argv,
              nargv * sizeof(char *));
            sub_argv[nargv + cur_ext->sendmail_nargv] = NULL;

            execvp(cur_ext->sendmail_argv[0], (char **const) sub_argv);
            free(sub_argv);
            syslog(LOG_CRIT, "try_groups: execvp: %s", strerror (errno));
            exit(1);
        }
        else {
            // Parent process.

            close(pipeto[0]);
            close(pipefrom[1]);

            char *errmsgbuf;
            ssize_t errmsgbuf_used;
            if (!write_to_child(fd, pipefrom[0], &pipeto[1], &errmsgbuf, &errmsgbuf_used)) {
                if (errmsgbuf_used == 0) {
                    syslog(LOG_ERR, "%s: Unable to read/write successfully when executing '%s' on '%s'",
                      cur_ext->name, cur_ext->sendmail, msg_path);
                } else {
                    syslog(LOG_ERR, "%s: Unable to read/write successfully when executing '%s' on '%s': %.*s",
                      cur_ext->name, cur_ext->sendmail, msg_path, (int) errmsgbuf_used, errmsgbuf);
                }
                goto next_with_kill;
            }
            assert(pipeto[1] == -1);

            // Now we need to wait for confirmation that the child process
            // executed correctly. We are conservative here: if in doubt, we
            // assume it didn't execute correctly and that we'll need to
            // retry the message send later.

            int rtn_status;
            time_t timeout = time(NULL) + MAX_POLL_NO_SEND;
            while (true) {
                int rtn = waitpid(pid, &rtn_status, WNOHANG);
                if (rtn > 0) {
                    if (WIFEXITED(rtn_status)) {
                        int child_rtn = WEXITSTATUS(rtn_status);
                        if (child_rtn == 0)
                            break;
                        else {
                            if (errmsgbuf_used == 0) {
                                syslog(LOG_ERR, "%s: Received error %d when executing "
                                  "'%s' on '%s'", cur_ext->name, child_rtn,
                                  cur_ext->sendmail, msg_path);
                            } else {
                                syslog(LOG_ERR, "%s: Received error %d when executing "
                                  "'%s' on '%s': %.*s", cur_ext->name, child_rtn,
                                  cur_ext->sendmail, msg_path, (int) errmsgbuf_used, errmsgbuf);
                            }
                            goto next;
                        }
                    } else if (WIFSIGNALED(rtn_status)) {
                        if (errmsgbuf_used == 0) {
                            syslog(LOG_ERR, "%s: Received signal %d when executing "
                              "'%s' on '%s'", cur_ext->name, WTERMSIG(rtn_status),
                              cur_ext->sendmail, msg_path);
                        } else {
                            syslog(LOG_ERR, "%s: Received signal %d when executing "
                              "'%s' on '%s': %.*s", cur_ext->name, WTERMSIG(rtn_status),
                              cur_ext->sendmail, msg_path, (int) errmsgbuf_used, errmsgbuf);
                        }
                        goto next;
                    }
                } else if (rtn == -1) {
                    syslog(LOG_ERR, "%s: waitpid failed when executing "
                      "'%s' on '%s'", cur_ext->name, cur_ext->sendmail, msg_path);
                    goto next;
                }
                if (time(NULL) > timeout) {
                    if (errmsgbuf_used == 0) {
                        syslog(LOG_ERR, "%s: Timeout when executing "
                          "'%s' on '%s'", cur_ext->name,
                          cur_ext->sendmail, msg_path);
                    } else {
                        syslog(LOG_ERR, "%s: Timeout when executing "
                          "'%s' on '%s': %.*s", cur_ext->name,
                          cur_ext->sendmail, msg_path, (int) errmsgbuf_used, errmsgbuf);
                    }
                    goto next_with_kill;
                }
                sleep(1);
            }

            // At this point, we know everything has worked, so we just need
            // to cleanup.

            for (int j = 0; j < nargv; j += 1)
                free(argv[j]);
            free(argv);
            free(errmsgbuf);
            unlink(msg_path);

            cur_ext->last_success = time(NULL);
            syslog(LOG_INFO, "%s: Message '%s' sent", cur_ext->name, msg_path);

            return true;

next_with_kill:
            // We want to go to the next message, but something has gone wrong,
            // so the sendmail process either hasn't succeeded or (at best)
            // hasn't been 'wait'ed upon. We send the process a SIGKILL (since
            // something has obviously gone wrong), then add it to the list
            // of processes we're waiting to die. This avoids processes
            // turning into zombies.

            kill(pid, SIGKILL);
            push_killed_pid(status, pid, pipeto[1]);

next:
            free(errmsgbuf);

            cur_ext->working = false;
            if (conf->mode == DAEMON_MODE) {
                // Check the external's timeout (if it has one). If the timeout
                // hasn't been exceeded, then we have to give up on trying to
                // send this messages via this, or other, externals - we need
                // to wait for the timeout to be exceeded.
                if (cur_ext->timeout != 0
                  && cur_ext->last_success + cur_ext->timeout > time(NULL)) {
                    goto fail;
                }
            }

            cur_ext = cur_ext->next;
        }
    }

fail:
    for (int j = 0; j < nargv; j += 1)
        free(argv[j]);
    free(argv);

    return false;
}



//
// Push the pid 'pid' onto the stack of processes which has been SIGKILLed. If
// `cstdin_fd` is != -1, it will be closed after the process has been waited
// on.
//

static void push_killed_pid(Status *status, pid_t pid, int cstdin_fd)
{
    // Before we malloc more memory, see if any previous killed PIDs have died.
    // If so, it'll free up some memory.
    cycle_killed_pids(status);

    PID_LList *pll = malloc(sizeof(PID_LList));
    if (pll == NULL)
        errx(1, "push_killed_pid: unable to allocate memory");
    pll->pid = pid;
    pll->cstdin_fd = cstdin_fd;
    pll->next = status->pid_llist;
    status->pid_llist = pll;
}



//
// Go through the list of processes which have been SIGKILLed and see if any
// of them have actually exited.
//

static void cycle_killed_pids(Status *status)
{
    PID_LList *pll = status->pid_llist;
    PID_LList *last_pll = NULL;
    while (pll != NULL) {
        if (waitpid(pll->pid, NULL, WNOHANG) == pll->pid) {
            // The process has exited, so remove it from the linked list.
            if (pll->cstdin_fd != -1)
                close(pll->cstdin_fd);
            PID_LList *dead_pll = pll;
            pll = pll->next;
            free(dead_pll);
            if (last_pll == NULL)
                status->pid_llist = pll;
            else
                last_pll->next = pll;
        }
        else {
            last_pll = pll;
            pll = pll->next;
        }
    }
}



static void do_notify_failure_cmd(Conf *conf, Status *status)
{
    if (conf->notify_failure_cmd == NULL)
        return;

    char *time_fmted;
    uintmax_t diff = time(NULL) - status->last_success;
    int r;
    if (diff < 60)
        r = asprintf(&time_fmted, "%ju seconds", diff);
    else if (diff < 60 * 60)
        r = asprintf(&time_fmted, "%ju minutes", diff / 60);
    else if (diff < 60 * 60 * 24)
        r = asprintf(&time_fmted, "%ju hours %ju minutes", diff / (60 * 60), (diff / 60) % 60);
    else
        r = asprintf(&time_fmted, "%ju days %ju hours", diff / (60 * 60 * 24), (diff / (60 * 60)) % 24);

    if (r == -1) {
        // The asprintf call (whichever one it was) failed.
        return;
    }

    char *cmd = str_replace(conf->notify_failure_cmd, "${TIME}", time_fmted);
    if (system(cmd) != 0)
        syslog(LOG_ERR, "When running cmd: %s", cmd);

    free(cmd);
    free(time_fmted);
}



static void do_notify_success_cmd(Conf *conf, int num_successes)
{
    if (conf->notify_success_cmd == NULL)
        return;

    char *successes_str;
    if (asprintf(&successes_str, "%d", num_successes) == -1)
        return;

    char *cmd = str_replace(conf->notify_success_cmd, "${SUCCESSES}", successes_str);
    if (system(cmd) != 0)
        syslog(LOG_ERR, "When running cmd: %s", cmd);

    free(successes_str);
    free(cmd);
}



//
// Set 'fd' to be non-blocking, returning true on success or false on failure
//

static bool set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return false;
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        return false;
    return true;
}



//
// Display configuration.
//

static void display_matches(const Match *match)
{
    if (NULL == match)
        return;

    Match *next = match->next;

    if (match->type == MATCH) {
        printf("\tmatch  ");
    } else if (match->type == REJECT) {
        printf("\treject ");
    }

    if (match->location == HEADER) {
        printf("header");
    }

    printf(" \"%s\"\n", match->regex);

    display_matches(next);
}


static void display_externals(const External *external)
{
    if (NULL == external)
        return;

    External *next = external->next;

    printf("\texternal %s:\n", external->name);
    printf("\t\tsendmail = \"%s\"\n", external->sendmail);

    printf("\t\ttimeout = ");
    if (external->timeout) {
        printf("%ld seconds\n", external->timeout);
    } else {
        printf("infinite\n");
    }

    display_externals(next);
}


static void display_groups(const Group *group, const int no)
{
    if (NULL == group)
        return;

    Group *next = group->next;
    printf("Group %d:\n", no);

    display_matches(group->matches);
    if (NULL != group->matches)
        printf("\n");

    display_externals(group->externals);
    if (NULL != next)
        printf("\n");

    display_groups(next, no+1);
}



//
// Check if the externals file can be loaded.
//

static void check_externals(const char *file)
{
    int rtn = try_externals_path(file);

    if (rtn == 0) {
        printf("%s: OK\n", file);
        display_groups(groups, 1);
        free_groups();
    } else {
        fprintf(stderr, "%s: Syntax error, wrong permissions or file not found\n", file);
    }
}



////////////////////////////////////////////////////////////////////////////////
// main
//

static void usage(int rtn_code)
{
    fprintf(stderr, "Usage: %s [-c <config-file>] [-e <externals-file>] [-hv] [-m <batch|daemon>] [-t]\n", __progname);
    exit(rtn_code);
}


static void version()
{
  puts(PACKAGE_NAME " " PACKAGE_VERSION);
}


int main(int argc, char** argv)
{
#ifdef HAVE_PLEDGE
    if (pledge("stdio rpath wpath cpath flock getpw proc exec", NULL) == -1)
        err(EXIT_FAILURE, "pledge");
#endif

    Mode mode = BATCH_MODE;
    int ch;
    char *conf_path = NULL;
    char *externals_path = NULL;
    while ((ch = getopt(argc, argv, "c:e:hm:t:v")) != -1) {
        switch (ch) {
            case 'c':
                if (conf_path)
                    usage(1);
                conf_path = malloc(strlen(optarg) + 1);
                if (conf_path == NULL)
                    errx(1, "main: unable to allocate memory");
                strcpy(conf_path, optarg);
                break;
            case 'e':
                if (externals_path)
                    usage(1);
                externals_path = malloc(strlen(optarg + 1));
                if (externals_path == NULL)
                    errx(1, "main: unable to allocate memory");
                strcpy(externals_path, optarg);
                break;
            case 'm':
                if (strcmp(optarg, "batch") == 0)
                    mode = BATCH_MODE;
                else if (strcmp(optarg, "daemon") == 0)
                    mode = DAEMON_MODE;
                else
                    usage(1);
                break;
            case 'h':
                usage(0);
                break;
            case 't':
                check_externals(optarg);
                exit(0);
                break;
            case 'v':
                version();
                exit(0);
                break;
            default:
                usage(1);
        }
    }

    Conf *conf = read_conf(conf_path);

    if (externals_path == NULL)
        externals_path = find_externals_path();
    read_externals(externals_path);

    obtain_lock(conf);

    // In our context, SIGPIPE would occur when a write to a pipe fails, causing
    // us to terminate. Therefore we ignore SIGPIPE's, which means that calls to
    // write will return -1 if EPIPE occurs. Why this isn't the default behaviour
    // is anyone's guess.

    signal(SIGPIPE, SIG_IGN);

    // Check that everything to do with the spool dir is OK.

    if (!check_spool_dir(conf))
        exit(1);

    Status status;
    status.any_failure = false;
    status.last_success = status.last_notify_failure = time(NULL);
    status.pid_llist = NULL;

    if (mode == DAEMON_MODE) {
        if (daemon(1, 0) == -1) {
            syslog(LOG_CRIT, "failed to become daemon");
            exit(1);
        }

        conf->mode = DAEMON_MODE;

        char *msgs_path; // msgs dir (within spool dir)
        if (asprintf(&msgs_path, "%s%s%s", conf->spool_dir, DIR_SEP, MSGS_DIR)
          == -1) {
            syslog(LOG_CRIT, "main: asprintf: unable to allocate memory");
            exit(1);
        }

        // On platforms that support an appropriate mechanism (such as kqueue
        // or inotify), we try and monitor spool_dir/msgs so that if we're a
        // daemon then, as soon as someone starts fiddling with it (i.e. extsmail
        // putting a new message in there) we try to send all messages. This
        // gives the nice illusion that message sending with extsmail is pretty
        // much instant.

#ifdef HAVE_KQUEUE
        int kq = kqueue();
        if (kq == -1) {
            syslog(LOG_CRIT, "main: kqueue: %s", strerror (errno));
            exit(1);
        }

        int smf = open(msgs_path, O_RDONLY);
        if (smf == -1) {
            syslog(LOG_CRIT, "When opening '%s': %s", msgs_path, strerror (errno));
            exit(1);
        }

        struct kevent changes;
        struct kevent events;
        EV_SET(&changes, smf, EVFILT_VNODE,
          EV_ADD | EV_ENABLE | EV_ONESHOT,
          NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_ATTRIB
          | NOTE_LINK | NOTE_RENAME | NOTE_REVOKE,
          0, 0);
#elif HAVE_INOTIFY
        int fd = inotify_init();
        if (fd < 0) {
            syslog(LOG_CRIT, "main: inotify_init: %s", strerror (errno));
            exit(1);
        }

        if (inotify_add_watch(fd, msgs_path, IN_CLOSE_WRITE) < 0) {
            syslog(LOG_CRIT, "main: inotify_add_watch: %s", strerror (errno));
            exit(1);
        }
#endif

        openlog(__progname, LOG_CONS, LOG_MAIL);

        int unsuccessful_wait = INITIAL_POLL_WAIT;
        while (1) {
            // Reload the externals file if asked to
            if (reload_config)  {
                free_groups();
                read_externals(externals_path);
                syslog(LOG_INFO, "Reloaded externals");
                reload_config = 0;
            }

            // The main message sending cycle

            int num_successes = cycle(conf, groups, &status);

            if (status.any_failure && conf->notify_failure_interval > 0
              && time(NULL) >
              status.last_notify_failure + conf->notify_failure_interval) {
                do_notify_failure_cmd(conf, &status);
                status.last_notify_failure = time(NULL);
            }

            cycle_killed_pids(&status);

            // If all messages have been sent successfully (or if there were no
            // messages to send), we don't want to wait INITIAL_POLL_WAIT
            // seconds - it's far too wasteful. We might as well wait a full
            // MAX_POLL_WAIT. If anything hasn't been sent, we wait
            // unsuccesful_wait seconds (a gradually increasing int from
            // INITIAL_POLL_WAIT to MAX_POLL_WAIT).

            int poll_wait;
            if (status.any_failure) {
                if (num_successes > 0) {
                    // Some messages were sent, so it's better not to wait too
                    // long before trying to send more.
                    unsuccessful_wait = INITIAL_POLL_WAIT;
                }
                poll_wait = unsuccessful_wait;
            }
            else
                poll_wait = MAX_POLL_WAIT;

            // On platforms that support an appropriate mechanism (such as kqueue
            // or inotify), we try and send messages as soon as we notice changes
            // to spool_dir/msgs. We also wake-up every 'poll_wait' seconds to
            // check the queue and send messages. This is in case the network
            // goes up and down - we can't just wait until the user tries sending
            // messages.
            //
            // Note that if kqueue / inotify return errors, they are deliberately
            // ignored: while support for these mechanisms is very nice, it's
            // still possible for extsmaild to operate without them.

#ifdef HAVE_KQUEUE
            struct timespec timeout = {poll_wait, 0};
            kevent(kq, &changes, 1, &events, 1, &timeout);
#elif HAVE_INOTIFY
            fd_set descriptors;
            FD_ZERO(&descriptors);
            FD_SET(fd, &descriptors);
            struct timespec timeout = {poll_wait, 0};
            int rtn = pselect(fd + 1, &descriptors, NULL, NULL, &timeout, NULL);
            if (rtn == 1) {
                // Even though we don't care what the result of the inotify read
                // is, we still need to read from it so that the buffer doesn't
                // fill up.
                char buf[INOTIFY_BUFLEN];
                int res = read(fd, buf, INOTIFY_BUFLEN);
                if (res == -1)
                    syslog(LOG_ERR, "Error when reading from inotify buffer");
            } else if (rtn == -1) {
                syslog(LOG_ERR, "main: pselect: %s", strerror(errno));
            }
#else
            // If no other support is available, we fall back on polling alone.
            sleep(poll_wait);
#endif

            if (!status.any_failure)
                unsuccessful_wait = INITIAL_POLL_WAIT;
            else {
                unsuccessful_wait *= 2;
                if (unsuccessful_wait > MAX_POLL_WAIT)
                    unsuccessful_wait = MAX_POLL_WAIT;
            }
        }
    }
    else {
        conf->mode = BATCH_MODE;
        free(externals_path);

        openlog(__progname, LOG_PERROR, LOG_MAIL);
        setlogmask(LOG_UPTO(LOG_NOTICE));

        if (!cycle(conf, groups, &status)) {
            do_notify_failure_cmd(conf, &status);
            closelog();
            return 1;
        }

        closelog();

        free_conf(conf);
        free_groups();

        return 0;
    }
}

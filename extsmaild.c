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

#include "conf.h"
#include "common.h"
#include "externals.h"

// #define DBG_LEAKS 1

const char *EXTERNALS_PATHS[] = {"~/.extsmail/externals",
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
    struct _pid_llist *next;
} PID_LList;

typedef struct {
    long spool_loc;       // The next entry number in the spool dir to try.
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

static void read_externals(void);
static void free_groups(Group *);
int try_externals_path(const char *);
bool cycle(Conf *, Group *, Status *);
bool try_groups(Conf *, Group *, Status *, const char *, int);
void push_killed_pid(Status *, pid_t);
void cycle_killed_pids(Status *);
void do_notify_failure_cmd(Conf *, Status *);
void do_notify_success_cmd(Conf *, Status *, int);
bool set_nonblock(int);




////////////////////////////////////////////////////////////////////////////////
// Lock file
//

char *lock_path;
int lock_fd;

void lock_exit();
void sigterm_trap(int);
void sighup_trap(int);

void obtain_lock(Conf *conf)
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

Group *groups;
extern int yyeparse(void);
FILE *yyein;



//
// Exit handler for atexit.
//
// This should be kept as simple as possible.
//

void lock_exit()
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

void sigterm_trap(int sigraised)
{
    exit(1);
}



//
// Function when SIGHUP is received. This reloads the externals configuration.
// Check the configuration file by running "extsmaild -t"
//

void sighup_trap(int sigraised)
{
    free_groups(groups);
    read_externals();
    syslog(LOG_INFO, "Reloaded configuration");
}



//
// Read the externals file in.
//
// This function does not return if there is a problem.
//

static void read_externals(void)
{
    for (int i = 0; EXTERNALS_PATHS[i] != NULL; i += 1) {
        int rtn = try_externals_path(EXTERNALS_PATHS[i]);
        if (rtn == 0)
            return;
        else if (rtn == -1)
            exit(1);
    }

    err(1, "Can't find a valid externals file");
}


//
// Free groups/matches/externals
//

static void free_matches(Match *match)
{
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


static void free_groups(Group *group)
{
    if (NULL == group)
	return;

    Group *next = group->next;

#if DBG_LEAKS
    fprintf(stderr, "GRO free_groups(%p)\n", (void *)group);
    fprintf(stderr, "GRO free_groups group->next= %p\n", (void *)group->next);
#endif

    free_matches(group->matches);
    free_externals(group->externals);
    free(group);

    free_groups(next);
}

#if HAVE_YYLEX_DESTROY
extern void yyelex_destroy(void);
#endif

//
// Attempts to read a configuration file at 'path'; returns 0 on success, 1 if a
// file is not found and -1 if an error occurred.
//

int try_externals_path(const char *path)
{
    char *cnd_path = expand_path(path);
    if (cnd_path == NULL) {
        free(cnd_path);
        return -1;
    }

    yyein = fopen(cnd_path, "rt");
    if (yyein == NULL) {
        free(cnd_path);
        if (errno == ENOENT)
            return 1;
        return -1;
    }
    
    // See whether the externals exists at 'path'.
    struct stat externals_st;
    if (fstat(fileno(yyein), &externals_st) == -1) {
        free(cnd_path);
        return 1;
    }
    
    // Check that the user and group of the externals file match the
    // executing process.
    if (externals_st.st_uid != geteuid() || externals_st.st_gid != getegid()) {
        warnx("The user and / or group permissions of '%s' do not match the "
          "executing user", path);
        free(cnd_path);
        return -1;
    }
    free(cnd_path);

    if (yyeparse() != 0) {
        fclose(yyein);
        return -1;
    }

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
// Try sending any messages in the spool dir. Returns true if all messages were
// sent successfully (or if there were no messages to send), or false if at least
// one message failed to be succesfully sent.
//

bool cycle(Conf *conf, Group *groups, Status *status)
{
    char *msgs_path; // msgs dir (within spool dir)
    if (asprintf(&msgs_path, "%s%s%s", conf->spool_dir, DIR_SEP, MSGS_DIR)
      == -1) {
        syslog(LOG_CRIT, "cycle: asprintf: unable to allocate memory");
        exit(1);
    }

    DIR *dirp = opendir(msgs_path);
    if (dirp == NULL) {
        syslog(LOG_ERR, "When opening spool dir: %m");
        free(msgs_path);
        return false;
    }
    
    if (conf->mode == DAEMON_MODE) {
        // In daemon mode, we try to make sure we don't get "stuck" on the same
        // message. For example, if a message is too big to be sent by the
        // remote sendmail, it could stop us trying to send other messages which
        // might be successful. So, on each cycle, we try starting one entry
        // further into the spool dir. In other words if we have entries:
        //   a, b, c
        // in the spool dir then we will try sending them in this order upon
        // each cycle (until some are actually sent):
        //   1: a, b, c
        //   2: b, c, a
        //   3: c, a, b

        // Skip the entries we tried on the last iteration.
        for (int i = 0; i < status->spool_loc; i += 1) {
            errno = 0;
            if (readdir(dirp) == NULL) {
                // We've hit the end of the directory; it probably means that we
                // managed to send some messages on the last iteration.
                status->spool_loc = 0;
                if (errno == 0) {
                    rewinddir(dirp);
                    break;
                }
                else {
                    // Something odd happened, and it's not obvious what we could
                    // do to recover. We're best off starting afresh in the next
                    // cycle.
                    closedir(dirp);
                    free(msgs_path);
                    return false;
                }
            }
        }
    }
    long start_spool_loc, spool_loc;
    start_spool_loc = spool_loc = status->spool_loc;
    
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
    bool tried_once = false; // Make sure we read every entry at least once.
    int num_successes = 0;   // How many messages have been successfully sent.
    while (1) {
        char *msg_path = NULL;

        errno = 0;
        struct dirent *dp = readdir(dirp);
        if (dp == NULL) {
            if (errno == 0) {
                // We've got to the end of the directory.
                if (conf->mode == DAEMON_MODE) {                    
                    if (tried_once && start_spool_loc == 0) {
                        // We started this cycle from the start of the directory,
                        // so we can now be sure that we've read everything.
                        break;
                    }
                    else if (!tried_once) {
                        // We haven't read any entries, but we've already read
                        // past the end of the directory. We reset the directory
                        // read to the start and carry on as if we'd always
                        // intended to start from the beginning of the
                        // directory.
                        start_spool_loc = status->spool_loc = 0;
                    }
                    else if (start_spool_loc > spool_loc) {
                        // Entries have been removed from the directory during
                        // the cycle (probably because we've sent messages
                        // successfully, but maybe because of user interaction).
                        // We reset the directory read to the start, in case
                        // files were present earlier in the readdir that we
                        // never tried, or new files have been added in the
                        // interim.
                        start_spool_loc = status->spool_loc = 0;
                        tried_once = false;
                    }
                        
                    // There could be entries between seekdir(0) and
                    // seekdir(status->spool_loc) that we haven't yet tried to
                    // send, so rewind to make sure we have a chance of trying
                    // then.
                    rewinddir(dirp);
                    spool_loc = 0;
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

        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
            goto next_msg;

        if (asprintf(&msg_path, "%s%s%s%s%s", conf->spool_dir, DIR_SEP,
          MSGS_DIR, DIR_SEP, dp->d_name) == -1) {
            syslog(LOG_CRIT, "cycle: asprintf: unable to allocate memory");
            exit(1);
        }
        
        int tries = 3; // Max number of times we'll try to operate on this file.
        while (1) {
            int fd = open(msg_path, O_RDONLY);
            if (fd == -1) {
                // If we couldn't so much as open the file then something odd
                // has happened.
                goto next_try;
            }

            if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
                if (errno != EWOULDBLOCK)
                    syslog(LOG_ERR, "Error when flocking'ing '%s'", msg_path);

                close(fd);
                goto next_try;
            }

            // We've now got an exclusive lock on the file.
            struct stat msg_st;
            if (fstat(fd, &msg_st) == -1) {
                syslog(LOG_ERR, "Error when fstat'ing '%s'", msg_path);
                close(fd);
                goto next_try;
            }

            // If the file is zero size it probably means that we managed to
            // interrupt extsmail before it had managed to obtain an
            // exclusive lock and write any data to the file. In such a case
            // we don't try and do anything; instead (below) we sleep a
            // second and then try again. This is because in general we
            // assume that extsmail will have finished with a file in at
            // most a couple of seconds (and probably much less).

            if (msg_st.st_size == 0) {
                close(fd);
                goto next_try;
            }

            if (try_groups(conf, groups, status, msg_path, fd)) {
                num_successes += 1;
                break;
            }

            // The send failed for whatever reason. Give up for the time being.
            all_sent = false;
            close(fd);
            break;

next_try:
            // At this point, either we've released the exclusive lock we'd
            // previously gained (because we'd gained it before any data had
            // been written to the spool file) or we weren't able to gain the
            // lock at all. Assuming we haven't tried this too many times, we now
            // try sleeping for a second and then having another go.
            
            tries -= 1;
            if (tries < 0) {
                all_sent = false;
                break;
            }
            sleep(1);
        }

        if (conf->mode == DAEMON_MODE && !all_sent) {
            status->spool_loc = spool_loc + 1;
            free(msg_path);
            break;
        }

next_msg:
        if (msg_path)
            free(msg_path);

        if (conf->mode == DAEMON_MODE) {
            if (tried_once && spool_loc == start_spool_loc) {
                // We've read all the directory entries at least once.
                break;
            }
            spool_loc += 1;
            tried_once = true;
        }
    }

    closedir(dirp);
    free(msgs_path);
    
    if (conf->mode == DAEMON_MODE) {
        if (all_sent) {
            status->spool_loc = 0;
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
        do_notify_success_cmd(conf, status, num_successes);

    return all_sent;
}



//
// Read in the arguments passed to a message file.
//
// Returns true on success, false on failure. If successful, 'rargv' points to an
// array of argument strings of length 'rnargv'.
//

bool read_argv(Conf *conf, const char *msg_path, int fd, char ***rargv,
               int *rnargv)
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
            syslog(LOG_CRIT, "try_groups: malloc: %m");
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

Group *find_group(Conf *conf, const char *msg_path, int fd)
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
                syslog(LOG_CRIT, "try_groups: realloc: %m");
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
                    syslog(LOG_CRIT, "try_groups: malloc: %m");
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
// Returns true on success, false on failure. 'rstderrbuf' will point to a
// malloc'd area of memory which, if the function is successful, will contain
// 'rstderrbuf_used' bytes read from the child process's stderr (if unsuccessful,
// its contents are undefined, as are those of 'rstderrbuf_used').
//

bool write_to_child(External *cur_ext, const char *msg_path, int fd, int cstderr_fd, int cstdin_fd,
                    char **rstderrbuf, ssize_t *rstderrbuf_used)
{
    // In the following while loop we feed the message into the child sendmail
    // process, and read its stderr output. This reading and writing can be
    // interleaved.

    // The temporary buffer we use for reading from fd.
    ssize_t fdbuf_alloc = PTOC_BUFLEN;
    char *fdbuf = malloc(fdbuf_alloc);
    ssize_t fdbuf_used = 0, fdbuf_off = 0;

    // The stderr buffer.
    ssize_t stderrbuf_alloc = STDERR_BUF_ALLOC;
    char *stderrbuf = malloc(stderrbuf_alloc);
    ssize_t stderrbuf_used = 0;

    bool eof_fd = false, eof_cstderr = false;

    if (fdbuf == NULL || stderrbuf == NULL) {
        syslog(LOG_CRIT, "write_to_child: malloc: %m");
        exit(1);
    }
    
    // Set all the files to be non-blocking.
    if (!set_nonblock(fd) || !set_nonblock(cstderr_fd)
      || !set_nonblock(cstdin_fd)) {
        syslog(LOG_ERR, "%s: Can't set file descriptor flags",
          cur_ext->name);
        goto err;
    }

    time_t last_io_time = time(NULL);
    while (!eof_fd || !eof_cstderr) {
        // The 3 defines below must match the order that the descriptors
        // are passed to poll.
#       define POLL_FD 0
#       define POLL_CSTDIN 1
#       define POLL_CSTDERR 2
        struct pollfd fds[] = {
          {fd, POLLIN, 0},
          {cstdin_fd, POLLOUT, 0},
          {cstderr_fd, POLLIN, 0}};

        if (eof_fd || fdbuf_used > 0) {
            // If fd is closed, or there's still stuff in the buffer
            // that hasn't been written, don't poll it.
            fds[POLL_FD].fd = -1;
        }
        if (fdbuf_used == 0) {
            // If there's nothing to write, there's no point polling
            // the child's stdin process.
            fds[POLL_CSTDIN].fd = -1;
        }
        if (eof_cstderr)
            fds[POLL_CSTDERR].fd = -1;

        time_t tout = (MAX_POLL_NO_SEND - (time(NULL) - last_io_time)) * 1000;
        if (tout <= 0) {
            syslog(LOG_ERR, "%s: Timeout when sending '%s'",
              cur_ext->name, msg_path);
            goto err;
        }

        if (poll(fds, 3, tout) == -1) {
            if (errno == EINTR)
                continue;
            goto err;
        }

        // Check if any of the files we're reading/writing from have got
        // irrecoverable problems. Note that POLL_FD can't suffer from POLLHUP
        // (since it's write only) and that we catch POLLHUP on POLL_CSTDERR
        // later.

        assert(!(fds[POLL_FD].revents & POLLHUP));
        if (fds[POLL_FD].revents & (POLLERR|POLLNVAL))
            goto fd_err;
        if (fds[POLL_CSTDIN].revents & (POLLERR|POLLHUP|POLLNVAL))
            goto cstdin_err;
        if (fds[POLL_CSTDERR].revents & (POLLERR|POLLNVAL))
            goto cstderr_err;

        // Read in data from fd (if appropriate)

        if (!eof_fd && fdbuf_used == 0 && fds[POLL_FD].revents & POLLIN) {
            ssize_t nr = read(fd, fdbuf, fdbuf_alloc);
            if (nr == -1) {
                if (errno == EAGAIN || errno == EINTR)
                    continue;
                goto fd_err;
            }
            assert(nr >= 0);
            last_io_time = time(NULL);
            if (nr == 0) {
                // It might look like we'd like to close(fd) now, but
                // it's still possible for things to go wrong, with fd
                // needing to be tried again.
                eof_fd = true;
                close(cstdin_fd);
            }
            else {
                fdbuf_off = 0;
                fdbuf_used = nr;
            }
        }

        // Write data to the child process (if appropriate).

        if (fdbuf_used > 0 && fds[POLL_CSTDIN].revents & POLLOUT) {
            while (fdbuf_off < fdbuf_used) {
                ssize_t tnw = write(cstdin_fd, fdbuf + fdbuf_off, fdbuf_used - fdbuf_off);
                if (tnw == -1) {
                    if (errno == EAGAIN || errno == EINTR)
                        break;
                    goto cstdin_err;
                }
                assert(tnw >= 0);
                if (tnw == 0) {
                    // The write pipe has been closed, but we still have
                    // data to write out.
                    goto cstdin_err;
                }
                fdbuf_off += tnw;
                assert(fdbuf_off <= fdbuf_used);
                if (fdbuf_off == fdbuf_used) {
                    fdbuf_off = fdbuf_used = 0;
                }
                last_io_time = time(NULL);
            }
        }

        // Check if the child's stderr was closed
        if (fds[POLL_CSTDERR].revents & POLLHUP)
            eof_cstderr = true;

        // Read the child's stderr (if appropriate).

        if (!eof_cstderr && fds[POLL_CSTDERR].revents & POLLIN) {
            ssize_t nr = read(cstderr_fd, stderrbuf + stderrbuf_used,
              stderrbuf_alloc - stderrbuf_used);
            if (nr == -1) {
                if (errno == EAGAIN || errno == EINTR)
                    continue;
                goto cstderr_err;
            }
            assert(nr >= 0);
            last_io_time = time(NULL);
            if (nr == 0) {
                close(cstderr_fd);
                eof_cstderr = true;
            }
            else if (nr == stderrbuf_alloc - stderrbuf_used) {
                stderrbuf_alloc += STDERR_BUF_ALLOC;
                stderrbuf = realloc(stderrbuf, stderrbuf_alloc);
                if (stderrbuf == NULL) {
                    syslog(LOG_CRIT, "try_groups: realloc: %m");
                    exit(1);
                }
            }
            stderrbuf_used += nr;
        }
    }

    // For reasons that I don't pretend to understand, stderr messages
    // sometimes have random newline chars at the end of line - this loop
    // chomps them off.

    while (stderrbuf_used > 0
      && (stderrbuf[stderrbuf_used - 1] == '\n'
      || stderrbuf[stderrbuf_used - 1] == '\r'))
        stderrbuf_used -= 1;

    bool rtn = true;
    goto cleanup;

fd_err:
    syslog(LOG_ERR, "%s: Error when reading from '%s'",
      cur_ext->name, msg_path);
    goto err;

cstdin_err:
    syslog(LOG_ERR, "%s: Error when writing to '%s' process",
      cur_ext->name, cur_ext->sendmail);
    goto err;

cstderr_err:
    syslog(LOG_ERR, "%s: When reading stderr from '%s': %m",
      cur_ext->name, cur_ext->sendmail);
    goto err;

err:
    rtn = false;
    goto cleanup;

cleanup:
    free(fdbuf);
    if (!eof_fd)
        close(cstdin_fd);
    if (!eof_cstderr)
        close(cstderr_fd);

    *rstderrbuf = stderrbuf;
    *rstderrbuf_used = stderrbuf_used;

    return rtn;
}



//
// Try sending an individual message. Returns true if successful, false
// otherwise.
//

bool try_groups(Conf *conf, Group *groups, Status *status,
                const char *msg_path, int fd)
{
    char **argv;
    int nargv;
    if (!read_argv(conf, msg_path, fd, &argv, &nargv))
        return false;

    // We need to record where the actual message starts before calling
    // find_group.
    
    off_t mf_body_off = lseek(fd, 0, SEEK_CUR);
    if (mf_body_off == -1) {
        syslog(LOG_ERR, "Error when lseek'ing from '%s'", msg_path);
        goto fail;
    }
    Group *group = find_group(conf, msg_path, fd);
    if (group == NULL) {
        syslog(LOG_ERR, "No matching group found for '%s'", msg_path);
        goto fail;
    }
    if (lseek(fd, mf_body_off, SEEK_SET) == -1) {
        syslog(LOG_ERR, "Error when lseek'ing from '%s': %m", msg_path);
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
        if (pipe(pipeto) == -1 || pipe(pipefrom) == -1) {
            syslog(LOG_ERR, "try_groups: pipe: %m");
            goto fail;
        }

        pid_t pid = fork();
        if (pid == -1) {
            syslog(LOG_ERR, "try_groups: fork: %m");
            goto fail;
        }
        else if (pid == 0) {
            // Child / sendmail process.

            close(STDOUT_FILENO);
            if (dup2(pipeto[0], STDIN_FILENO) == -1 || dup2(pipefrom[1],
              STDERR_FILENO) == -1) {
                syslog(LOG_CRIT, "try_groups: dup2: %m");
                goto fail;
            }
            close(pipeto[0]);
            close(pipeto[1]);
            close(pipefrom[0]);
            close(pipefrom[1]);

            char **sub_argv = malloc((nargv + cur_ext->sendmail_nargv + 1) *
              sizeof(char *));
            if (sub_argv == NULL) {
                syslog(LOG_CRIT, "try_groups: malloc: %m");
                exit(1);
            }

            memcpy(sub_argv, cur_ext->sendmail_argv,
              cur_ext->sendmail_nargv * sizeof(char *));
            memcpy(sub_argv + cur_ext->sendmail_nargv, argv,
              nargv * sizeof(char *));
            sub_argv[nargv + cur_ext->sendmail_nargv] = NULL;

            execvp(cur_ext->sendmail_argv[0], (char **const) sub_argv);
            free(sub_argv);
            syslog(LOG_CRIT, "try_groups: execvp: %m");
            goto fail;
        }
        else {
            // Parent process.

            close(pipeto[0]);
            close(pipefrom[1]);

            char *stderrbuf;
            ssize_t stderrbuf_used;
            if (!write_to_child(cur_ext, msg_path, fd, pipefrom[0], pipeto[1], &stderrbuf,
              &stderrbuf_used))
                goto next_with_kill;

            // Now we need to wait for confirmation that the child process
            // executed correctly. We are conservative here: if in doubt, we
            // assume it didn't execute correctly and that we'll need to
            // retry the message send later.

            int rtn_status;
            if (waitpid(pid, &rtn_status, 0) || WIFEXITED(rtn_status)) {
                int child_rtn = WEXITSTATUS(rtn_status);
                if (child_rtn != 0) {
                    syslog(LOG_ERR, "%s: Received error %d when executing "
                      "'%s' on '%s': %.*s", cur_ext->name, child_rtn,
                      cur_ext->sendmail, msg_path, (int) stderrbuf_used, stderrbuf);
                    goto next;
                }
            }
            else {
                goto next;
            }

            // At this point, we know everything has worked, so we just need
            // to cleanup.

            close(fd);
            for (int j = 0; j < nargv; j += 1)
                free(argv[j]);
            free(argv);
            free(stderrbuf);
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
            push_killed_pid(status, pid);

next:
            free(stderrbuf);
            if (lseek(fd, mf_body_off, SEEK_SET) == -1) {
                syslog(LOG_ERR, "%s: Error when lseek'ing from '%s': %m",
                  cur_ext->name, msg_path);
                goto fail;
            }

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
// Push the pid 'pid' onto the stack of processes which has been SIGKILLed.
//

void push_killed_pid(Status *status, pid_t pid)
{
    // Before we malloc more memory, see if any previous killed PIDs have died.
    // If so, it'll free up some memory.
    cycle_killed_pids(status);

    PID_LList *pll = malloc(sizeof(PID_LList));
    if (pll == NULL)
        errx(1, "push_killed_pid: unable to allocate memory");
    pll->pid = pid;
    pll->next = status->pid_llist;
    status->pid_llist = pll;
}



//
// Go through the list of processes which have been SIGKILLed and see if any
// of them have actually exited.
//

void cycle_killed_pids(Status *status)
{
    PID_LList *pll = status->pid_llist;
    PID_LList *last_pll = NULL;
    while (pll != NULL) {
        if (waitpid(pll->pid, NULL, WNOHANG) == pll->pid) {
            // The process has exited, so remove it from the linked list.
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



void do_notify_failure_cmd(Conf *conf, Status *status)
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



void do_notify_success_cmd(Conf *conf, Status *status, int num_successes)
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

bool set_nonblock(int fd)
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
	printf("%d seconds\n", external->timeout);
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
	free_groups(groups);
    } else {
	fprintf(stderr, "%s: Syntax error, wrong permissions or file not found\n", file);
    }
}



////////////////////////////////////////////////////////////////////////////////
// main
//

void usage(int rtn_code)
{
    fprintf(stderr, "Usage: %s [-m <batch|daemon>] [-t <conf>]\n", __progname);
    exit(rtn_code);
}


int main(int argc, char** argv)
{
    Mode mode = BATCH_MODE;
    int ch;
    while ((ch = getopt(argc, argv, "hm:t:")) != -1) {
        switch (ch) {
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
	    case 't':
                check_externals(optarg);
                exit(0);
		break;
            default:
                usage(1);
        }
    }

    Conf *conf = read_conf();

    read_externals();
    
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
    status.spool_loc = 0;
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
            syslog(LOG_CRIT, "main: kqueue: %m");
            exit(1);
        }

        int smf = open(msgs_path, O_RDONLY);
        if (smf == -1) {
            syslog(LOG_CRIT, "When opening '%s': %m", msgs_path);
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
            syslog(LOG_CRIT, "main: inotify_init: %m");
            exit(1);
        }

        if (inotify_add_watch(fd, msgs_path, IN_CLOSE_WRITE) < 0) {
            syslog(LOG_CRIT, "main: inotify_add_watch: %m");
            exit(1);
        }
#endif

        openlog(__progname, LOG_CONS, LOG_MAIL);

        int unsuccessful_wait = INITIAL_POLL_WAIT;
        while (1) {
            bool all_sent = cycle(conf, groups, &status);

            if (!all_sent && conf->notify_failure_interval > 0
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
            if (all_sent)
                poll_wait = MAX_POLL_WAIT;
            else
                poll_wait = unsuccessful_wait;

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
            if (pselect(fd + 1, &descriptors, NULL, NULL, &timeout, NULL) != -1)
            {
                // Even though we don't care what the result of the inotify read
                // is, we still need to read from it so that the buffer doesn't
                // fill up.
                char buf[INOTIFY_BUFLEN];
                int res = read(fd, buf, INOTIFY_BUFLEN);
                if (res == -1)
                    syslog(LOG_ERR, "Error when reading from inotify buffer");
            }
#else
            // If no other support is available, we fall back on polling alone.
            sleep(poll_wait);
#endif

            if (all_sent)
                unsuccessful_wait = INITIAL_POLL_WAIT;
            else {
                unsuccessful_wait *= 2;
                if (unsuccessful_wait > MAX_POLL_WAIT)
                    unsuccessful_wait = MAX_POLL_WAIT;
            }
        }

	// not reached
        free_conf(conf); // XXX should be done in the exit handler
        free_groups(groups); // XXX should be done in the exit handler
    }
    else {
        conf->mode = BATCH_MODE;

        openlog(__progname, LOG_PERROR, LOG_MAIL);
        setlogmask(LOG_UPTO(LOG_NOTICE));

        if (!cycle(conf, groups, &status)) {
            do_notify_failure_cmd(conf, &status);
            closelog();
            return 1;
        }

        closelog();

        free_conf(conf);
        free_groups(groups);

        return 0;
    }
}

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
#include <poll.h>
#include <regex.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
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

#include "conf.h"
#include "common.h"
#include "externals.h"



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
// How many seconds to wait between checking spool_dir/msgs.
#define POLL_WAIT 60

#ifdef HAVE_INOTIFY
// Size in bytes of the inotify buffer.
#   define INOTIFY_BUFLEN ((sizeof(struct inotify_event)+FILENAME_MAX)*1024)
#endif

extern char* __progname;

Group *read_externals(void);
int try_externals_path(const char *);
bool cycle(Conf *conf, Group *groups);
bool try_groups(Conf *, Group *, const char *, int);




////////////////////////////////////////////////////////////////////////////////
// Lock file
//

char *lock_path;
int lock_fd;

void lock_exit();
void sigterm_trap(int);

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

    if ((lock_fd = open(lock_path, O_CREAT | O_RDWR)) == -1) {
        if (errno != EEXIST)
            err(1, "Unable to obtain lockfile '%s'", lock_path);
    }

    if (flock(lock_fd, LOCK_EX | LOCK_NB) == -1) {
        err(1, "Unable to obtain lockfile '%s'", lock_path);
    }

    fchmod(lock_fd, S_IRUSR | S_IWUSR | S_IXUSR);
    
    // Install an exit handler and signal trap so that, barring something going
    // catastrophically wrong, the lockfile is removed on exit.
    
    atexit(lock_exit);
    signal(SIGINT, sigterm_trap);
    signal(SIGTERM, sigterm_trap);
}



//
// Exit handler for atexit.
//
// This should be kept as simple as possible.
//

void lock_exit()
{
    unlink(lock_path);
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



////////////////////////////////////////////////////////////////////////////////
// Configuration file related
//

Group *groups;
extern int yyeparse(void);
FILE *yyein;

//
// Read the externals file in.
//
// This function does not return if there is a problem.
//

Group *read_externals(void)
{
    for (int i = 0; EXTERNALS_PATHS[i] != NULL; i += 1) {
        int rtn = try_externals_path(EXTERNALS_PATHS[i]);
        if (rtn == 0)
            return groups;
        else if (rtn == -1)
            exit(1);
    }

    err(1, "Can't find a valid externals file");
}



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

    // See whether the externals exists at 'path'.
    struct stat externals_st;
    if (stat(cnd_path, &externals_st) == -1) {
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

    yyein = fopen(cnd_path, "rt");
    if (yyein == NULL) {
        free(cnd_path);
        return -1;
    }
    free(cnd_path);
    
    if (yyeparse() != 0) {
        return -1;
    }
    
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

bool cycle(Conf *conf, Group *groups)
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
        return false;
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
    
    int all_sent = true;
    while (1) {
        errno = 0;
        struct dirent *dp = readdir(dirp);
        if (dp == NULL) {
            if (errno == 0) {
                // We've read all the directory entries.
                break;
            }
            else
                syslog(LOG_ERR, "When scanning spool dir: %m");
        }

        // The entries "." and ".." are, fairly obviously, not messages.

        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
            continue;

        char *msg_path;
        if (asprintf(&msg_path, "%s%s%s%s%s", conf->spool_dir, DIR_SEP,
          MSGS_DIR, DIR_SEP, dp->d_name) == -1) {
            syslog(LOG_CRIT, "cycle: asprintf: unable to allocate memory");
            exit(1);
        }
        
        int tries = 3; // Max number of times we'll try to operate on this file.
        while (1) {
            int fd = open(msg_path, O_RDONLY);
            if (fd == -1) {
                // If we couldn't so much as open the file, something odd has
                // happened.
                all_sent = false;
                break;
            }

            if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
                if (errno != EWOULDBLOCK)
                    syslog(LOG_ERR, "Error when flocking'ing '%s'", msg_path);

                goto next;
            }

            // We've now got an exclusive lock on the file.
            struct stat msg_st;
            if (fstat(fd, &msg_st) == -1) {
                // If stat failed then something odd has happened and it's
                // best to bail out for the time being.

                syslog(LOG_ERR, "Error when fstat'ing '%s'", msg_path);
                close(fd);
                all_sent = false;
                break;
            }

            // If the file is zero size it probably means that we managed to
            // interrupt extsmail before it had managed to obtain an
            // exclusive lock and write any data to the file. In such a case
            // we don't try and do anything; instead (below) we sleep a
            // second and then try again. This is because in general we
            // assume that extsmail will have finished with a file in at
            // most a couple of seconds (and probably much less).

            if (msg_st.st_size > 0) {
                if (try_groups(conf, groups, msg_path, fd)) {
                    close(fd);
                    break;
                }
                else {
                    all_sent = false;
                    close(fd);
                    break;
                }
            }

next:
            close(fd);

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
        
        free(msg_path);
    }

    closedir(dirp);
    free(msgs_path);

    return all_sent;
}



//
// Try sending an individual message. Returns true if successful, false
// otherwise.
//

bool try_groups(Conf *conf, Group *groups, const char *msg_path, int fd)
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
    int nargv = atoi(nas);
    free(nas);
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
        int sa = atoi(as);
        free(as);
        
        char *arg = malloc(sa + 1);
        if (arg == NULL) {
            syslog(LOG_CRIT, "try_groups: malloc: %m");
            exit(1);
        }

        ssize_t nr = read(fd, arg, sa + 1);
        if (nr < sa + 1) { // Note this also captures nr == 0 and nr == -1
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

    // Setup a buffer into which we will read stderr from any child processes.
    
    size_t stderr_buf_alloc = STDERR_BUF_ALLOC;
    char *stderr_buf = malloc(stderr_buf_alloc);
    if (stderr_buf == NULL) {
        syslog(LOG_CRIT, "try_groups: malloc: %m");
        exit(1);
    }

    // We now need to record where the actual message starts.
    
    off_t mf_body_off = lseek(fd, 0, SEEK_CUR);
    if (mf_body_off == -1) {
        syslog(LOG_ERR, "Error when ftell'ing from '%s'", msg_path);
        goto preheaderfail;
    }

    // Read in the messages header, doctoring it along the way to make it
    // suitable for being searched with regular expressions. The doctoring is
    // very simple. Individual headers are often split over multiple lines: we
    // merge such lines together.

    size_t dhb_buf_alloc = HEADER_BUF;
    char *dhd_buf = malloc(dhb_buf_alloc); // Doctored header buffer
    int dhd_buf_len = 0;
    while (1) {
        char *line = fdrdline(fd);
        if (line == NULL) {
            syslog(LOG_ERR, "Corrupted message '%s'", msg_path);
            goto fail;
        }
        size_t line_len = strlen(line);

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

        int start;
        if (dhd_buf_len > 0 && (line[0] == ' ' || line[0] == '\t')) {
            // This line began with space / tab chars, which means it's a
            // continuation of the header in the previous line.

            start = 0;
            while (line[start] == ' ' || line[start] == '\t')
                start += 1;
            
            memcpy(dhd_buf + dhd_buf_len - 1, line + start, line_len - start);
            dhd_buf[dhd_buf_len + line_len] = '\n';
            dhd_buf_len += line_len + 1;
        }
        else {
            memcpy(dhd_buf + dhd_buf_len, line, line_len);
            dhd_buf[dhd_buf_len + line_len] = '\n';
            dhd_buf_len += line_len + 1;
        }
        free(line);
    }
    dhd_buf[dhd_buf_len - 1] = 0; // Convert the last newline into a NUL
    
    if (lseek(fd, mf_body_off, SEEK_SET) == -1) {
        syslog(LOG_ERR, "Error when lseek'ing from '%s': %m", msg_path);
        goto fail;
    }
    
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
                goto fail;
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
    
    if (group == NULL) {
        syslog(LOG_ERR, "No matching group found for '%s'", msg_path);
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
        if (conf->mode == DAEMON_MODE && cur_ext->timeout != 0 &&
          cur_ext->last_success == 0) {
            assert(cur_ext->working);
            cur_ext->last_success = time(NULL);
        }

        if (!cur_ext->working) {
            // This particular external has previously been found to not be
            // working in this cycle.

            if (conf->mode == DAEMON_MODE) {
                // If we're in daemon mode then, if this external has been found
                // not to be working, check the timeout (if it exists). If the
                // timeout hasn't been exceeded, then we have to give up on
                // trying to send this messages via this, or other, externals -
                // we need to wait for the timeout to be exceeded.       
                if (cur_ext->timeout != 0 &&
                  cur_ext->last_success + cur_ext->timeout > time(NULL)) {
                    goto fail;
                }
            }

            // Don't bother trying to use this external. This is an important
            // optimisation if using ssh for exmaple: if a host is down, it can
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
                exit(1);
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
            syslog(LOG_CRIT, "try_groups: execvp: %m");
            exit(1);
        }
        else {
            // Parent process.

            close(pipeto[0]);
            close(pipefrom[1]);

            // In the following while loop we feed the message into the child
            // sendmail process, and read its stderr output. This reading and
            // writing can be interleaved.

            char *buf = malloc(PTOC_BUFLEN);
            int stderr_buf_len = 0;
            bool eof_fd = false, eof_stderr = false;
            while (!eof_fd || !eof_stderr) {
#               define POLL_FD 0
#               define POLL_PIPEFROM 1
                struct pollfd fds[] = {{fd, POLLIN, 0}, {pipefrom[0], POLLIN, 0}};
                
                if (poll(fds, 2, 0) == -1) {
                    if (errno == EINTR)
                        continue;
                    goto next;
                }
            
                if (fds[POLL_FD].revents & POLLIN) {
                    ssize_t nr = read(fd, buf, PTOC_BUFLEN);
                    if (nr == 0) {
                        // It might look like we'd like to close(fd) now, but
                        // it's still possible for things to go wrong, with fd
                        // needing to be tried again.
                        eof_fd = true;
                        close(pipeto[1]);
                    }
                    else if (nr == -1) {
                        syslog(LOG_ERR, "%s: Error when reading from '%s'",
                          cur_ext->name, msg_path);
                        goto next;
                    }
                    else {
                        ssize_t nw = 0; // Number of bytes written
                        while (nw < nr) {
                            ssize_t tnw = write(pipeto[1], buf + nw, nr - nw);
                            if (tnw == -1) {
                                syslog(LOG_ERR, "%s: Error when writing to '%s'"
                                  " process", cur_ext->name, cur_ext->sendmail);
                                goto next;
                            }
                            nw += tnw;
                        }
                    }

                }

                if (fds[POLL_PIPEFROM].revents & POLLIN || eof_fd) {
                    ssize_t nr = read(pipefrom[0], stderr_buf + stderr_buf_len, 
                      stderr_buf_alloc - stderr_buf_len);
                    if (nr == -1) {
                        syslog(LOG_ERR, "%s: When reading stderr from '%s': %m",
                          cur_ext->name, cur_ext->sendmail);
                        goto next;
                    }
                    else if (nr == 0) {
                        close(pipefrom[0]);
                        eof_stderr = true;
                    }
                    else if ((size_t) nr == stderr_buf_alloc - stderr_buf_len) {
                        stderr_buf_alloc += STDERR_BUF_ALLOC;
                        stderr_buf = realloc(stderr_buf, stderr_buf_alloc);
                        if (stderr_buf == NULL) {
                            syslog(LOG_CRIT, "try_groups: realloc: %m");
                            exit(1);
                        }
                    }
                    stderr_buf_len += nr;
                }
            }

            // For reasons that I don't pretend to understand, stderr messages
            // sometimes have random newline chars at the end of line - this loop
            // chomps them off.

            while (stderr_buf_len > 0 && (stderr_buf[stderr_buf_len - 1] == '\n'
              || stderr_buf[stderr_buf_len - 1] == '\r'))
                stderr_buf_len -= 1;

            // Now we need to wait for confirmation that the child process
            // executed correctly. We are conservative here: if in doubt, we
            // assume it didn't execute correctly and that we'll need to
            // retry the message send later.

            int status;
            if (waitpid(pid, &status, 0) || WIFEXITED(status)) {
                int child_rtn = WEXITSTATUS(status);
                if (child_rtn != 0) {
                    syslog(LOG_ERR, "%s: Received error %d when executing "
                      "'%s' on '%s': %.*s", cur_ext->name, child_rtn,
                      cur_ext->sendmail, msg_path, stderr_buf_len, stderr_buf);
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
            free(stderr_buf);
            free(dhd_buf);
            free(buf);
            unlink(msg_path);

            cur_ext->last_success = time(NULL);
            syslog(LOG_INFO, "%s: Message '%s' sent", cur_ext->name, msg_path);

            return true;

next:
            free(buf);
            if (!eof_fd)
                close(pipeto[1]);
            if (!eof_stderr)
                close(pipefrom[0]);
            if (lseek(fd, mf_body_off, SEEK_SET) == -1) {
                syslog(LOG_ERR, "%s: Error when lseek'ing from '%s': %m",
                  cur_ext->name, msg_path);
                goto fail;
            }

            cur_ext->working = false;
            if (conf->mode == DAEMON_MODE) {
                // If we're in daemon mode then, if this external has been found
                // not to be working, check the timeout (if it exists). If the
                // timeout hasn't been exceeded, then we have to give up on
                // trying to send this messages via this, or other, externals -
                // we need to wait for the timeout to be exceeded.       
                if (cur_ext->timeout != 0 &&
                  cur_ext->last_success + cur_ext->timeout > time(NULL)) {
                    goto fail;
                }
            }

            cur_ext = cur_ext->next;
        }
    }

fail:
    free(dhd_buf);
preheaderfail:
    for (int j = 0; j < nargv; j += 1)
        free(argv[j]);
    free(argv);
    free(stderr_buf);

    return false;
}



////////////////////////////////////////////////////////////////////////////////
// main
//

void usage(int rtn_code)
{
    fprintf(stderr, "Usage: %s [-m <batch|daemon>]\n", __progname);
    exit(rtn_code);
}



int main(int argc, char** argv)
{
    Mode mode = BATCH_MODE;
    int ch;
    while ((ch = getopt(argc, argv, "hm:")) != -1) {
        switch (ch) {
            case 'm':
                if (strcmp(optarg, "batch") == 0)
                    mode = BATCH_MODE;
                else if (strcmp(optarg, "daemon") == 0)
                    mode = DAEMON_MODE;
                else
                    usage(0);
                break;
            case 'h':
                usage(0);
            default:
                usage(1);
        }

    }

    Conf *conf = read_conf();

    Group *groups = read_externals();
    
    obtain_lock(conf);

    // In our context, SIGPIPE would occur when a write to a pipe fails, causing
    // us to terminate. Therefore we ignore SIGPIPE's, which means that calls to
    // write will return -1 if EPIPE occurs. Why this isn't the default behaviour
    // is anyone's guess.
    
    signal(SIGPIPE, SIG_IGN);

    // Check that everything to do with the spool dir is OK.

    if (!check_spool_dir(conf))
        exit(1);

    if (mode == DAEMON_MODE) {
        daemon(1, 0);
        
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
          NOTE_DELETE | NOTE_WRITE | NOTE_EXTEND | NOTE_TRUNCATE | NOTE_ATTRIB
          | NOTE_LINK | NOTE_RENAME | NOTE_REVOKE,
          0, 0);
#elif HAVE_INOTIFY
        int fd = inotify_init();
        if (fd < 0) {
            syslog(LOG_CRIT, "main: inotify_init: %m");
            exit(1);
        }
   
        if (inotify_add_watch(fd, msgs_path,
          IN_ACCESS | IN_DELETE | IN_ATTRIB | IN_CLOSE_WRITE) < 0) {
            syslog(LOG_CRIT, "main: inotify_add_watch: %m");
            exit(1);
        }
#endif

        openlog(__progname, LOG_CONS, LOG_MAIL);

        while (1) {
            cycle(conf, groups);

            // On platforms that support an appropriate mechanism (such as kqueue
            // or inotify), we try and send messages as soon as we notice changes
            // to spool_dir/msgs. We also wake-up every POLL_WAIT seconds to
            // check the queue and send messages. This is in case the network
            // goes up and down - we can't just wait until the user tries sending
            // messages.
            //
            // Note that if kqueue / inotify return errors, they are deliberately
            // ignored: while support for these mechanisms is very nice, it's
            // still possible for extsmaild to operate without them.
            
#ifdef HAVE_KQUEUE
            struct timespec timeout = {POLL_WAIT, 0};
            kevent(kq, &changes, 1, &events, 1, &timeout);
#elif HAVE_INOTIFY
            fd_set descriptors;
            FD_ZERO(&descriptors);
            FD_SET(fd, &descriptors);
            struct timespec timeout = {POLL_WAIT, 0};
            if (pselect(fd + 1, &descriptors, NULL, NULL, &timeout, NULL) != -1)
            {
                // Even though we don't care what the result of the inotify read
                // is, we still need to read from it so that the buffer doesn't
                // fill up.
                char buf[INOTIFY_BUFLEN];
                read(fd, buf, INOTIFY_BUFLEN);
            }
#else
            // If no other support is available, we fall back on polling alone.
            sleep(POLL_WAIT);
#endif
        }
    }
    else {
        conf->mode = BATCH_MODE;

        openlog(__progname, LOG_PERROR, LOG_MAIL);

        if (!cycle(conf, groups)) {
            closelog();
            return 1;
        }

        closelog();

        return 0;
    }
}

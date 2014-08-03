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
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "conf.h"
#include "common.h"
#include "conf_parser.tab.h"


const char *CONF_PATHS[] = {"~/.extsmail/conf", "/etc/extsmail/conf", NULL};
#define HOME_PFX "~/"

static int try_conf_path(const char *);
static bool check_dir(const char *);





////////////////////////////////////////////////////////////////////////////////
// Configuration related
//

extern int yycparse(void);
#if HAVE_YYLEX_DESTROY
extern void yyclex_destroy(void);
#endif
FILE *yycin;
Conf *conf; // Global variable needed for Yacc. Sigh.

//
// Read the configuration file.
//

Conf *read_conf()
{
    conf = malloc(sizeof(Conf));
    if (conf == NULL)
        errx(1, "read_conf: unable to allocate memory");
    conf->spool_dir = NULL;
    conf->notify_failure_interval = 0;
    conf->notify_failure_cmd = NULL;
    conf->notify_success_cmd = NULL;

    int i;
    for (i = 0; CONF_PATHS[i] != NULL; i += 1) {
        int rtn = try_conf_path(CONF_PATHS[i]);
        if (rtn == 0)
            break;
        else if (rtn == -1)
            exit(1);
    }
    
    if (CONF_PATHS[i] == NULL)
        err(1, "Can't find a valid configuration file");
    
    return conf;
}


//
// Free configuration
//

void free_conf(Conf *conf)
{
    free(conf->spool_dir);
    free(conf);
}


//
// Attempts to read a configuration file at 'path'; returns 0 on success, 1 if a
// file is not found and -1 if an error occurred.
//

static int try_conf_path(const char *path)
{
    char *cnd_path = expand_path(path);
    if (cnd_path == NULL) {
        return -1;
    }

    yycin = fopen(cnd_path, "rt");
    free(cnd_path);
    if (yycin == NULL) {
        if (errno == ENOENT)
            return 1;
        return -1;
    }
    
    if (yycparse() != 0) {
        fclose(yycin);
        return -1;
    }

    fclose(yycin);
#if HAVE_YYLEX_DESTROY
    yyclex_destroy();
#endif

    return 0;
}



//
// Check that the spool dir is correctly setup, returning true if so and false
// if problems are found.
//

bool check_spool_dir(Conf *conf)
{
    if (conf->spool_dir == NULL) {
        warnx("spool_dir not defined");
        return false;
    }

    if (!check_dir(conf->spool_dir))
        return false;

    char *mdp; // spool path
    if (asprintf(&mdp, "%s%s%s", conf->spool_dir, DIR_SEP, MSGS_DIR) == -1)
        errx(1, "check_spool_dir: asprintf: unable to allocate memory");
    
    if (!check_dir(mdp)) {
        free(mdp);
        return false;
    }
        
    free(mdp);

    return true;
} 
   


static bool check_dir(const char *path)
{
    struct stat sd_st;
    if (stat(path, &sd_st) == -1) {
        if (errno == ENOENT) {
            // If the directory does not exist, we try and create it.
            if (mkdir(path, S_IRUSR | S_IWUSR | S_IXUSR) != 0) {
                warn("%s", path);
                return false;
            }
            
            // There's no need to go through the rest of the checks; since
            // mk_dir was successful, spool_dir now exists as a directory with
            // the correct permissions.
            return true;
        }
        else {
            warn("%s", path);
            return false;
        }
    }

    // 'path' must be a directory.

    if (!S_ISDIR(sd_st.st_mode)) {
        warnx("%s: Exists and is not a directory", path);
        return false;
    }

    // 'path' must have owner only having rwx access.
    
    if ((sd_st.st_mode & (S_IRWXU | S_IRWXG | S_IRWXG))
      != (S_IRUSR | S_IWUSR | S_IXUSR)) {
        warnx("%s: Incorrect permissions (should be %.o)", path,
          S_IRUSR | S_IWUSR | S_IXUSR);
        return false;
    }

    return true;
}



////////////////////////////////////////////////////////////////////////////////
// Misc
//

//
// Reads a malloc'd NULL-terminated line from 'fd', stripping any newlines
// from the end.
//
// Upon error NULL is returned.
//

char *fdrdline(int fd)
{
#   define TMPBUFLEN 128

    char tmpbuf[TMPBUFLEN];
    
    char *line = NULL;
    size_t line_len = 0;
    size_t line_alloc = 0;
    while (1) {
        ssize_t nr = read(fd, &tmpbuf, TMPBUFLEN);
        if (nr == 0)
            break;
        else if (nr == -1) {
            if (line != NULL) {
                free(line);
                return NULL;
            }
        }

        off_t i;
        for (i = 0; i < nr; i++) {
            if (tmpbuf[i] == '\n' || tmpbuf[i] == '\r')
                break;
        }
        
        if (line == NULL) {
            line_alloc = i + 1;
            line = malloc(line_alloc);
            if (line == NULL)
                errx(1, "fdrdline: malloc");
        }
        else if (line_alloc < line_len + i + 1) {
            line = realloc(line, line_len + i + 1);
            if (line == NULL)
                errx(1, "fdrdline: realloc");
        }
        
        memcpy(line + line_len, tmpbuf, i);
        line_len += i;
        
        if (i < nr) {
            if (lseek(fd, 1 -(nr - i), SEEK_CUR) == -1) {
                free(line);
                return NULL;
            }
            break;
        }
    }
    
    // If we didn't read in any data, then we hit EOF. The user is expected to
    // have detected that condition, so we return NULL.
    if (line == NULL)
        return NULL;
    
    line[line_len] = 0;

    return line;
}


//
// Performs tilde expansion on 'path'. This returns a malloc'd object with the
// new path in (regardless of whether expansion occurred or not) unless an error
// occurred in which case NULL is returned.
//

char *expand_path(const char *path)
{
    char *exp_path;
    // If path begins with "~/", we expand that to the users home directory.
    if (strncmp(path, HOME_PFX, strlen(HOME_PFX)) == 0) {
        struct passwd *pw_ent = getpwuid(geteuid());
        if (pw_ent == NULL)
            return NULL;

        if (asprintf(&exp_path, "%s%s%s", pw_ent->pw_dir, DIR_SEP, path + strlen(HOME_PFX)) == -1)
            errx(1, "expand_path: asprintf: unable to allocate memory");
    }
    else if (asprintf(&exp_path, "%s", path) == -1)
        errx(1, "expand_path: asprintf: unable to allocate memory");
    
    return exp_path;
}



char *mk_str(char *str)
{
    char *buf = malloc(strlen(str) + 1);
    if (buf == NULL)
        errx(1, "mk_str: malloc");

    memmove(buf, str, strlen(str) + 1);
    
    return buf;
}



char *str_replace(const char *str, const char *old, const char *new)
{
    size_t new_size = 0, i = 0;
    while (i < strlen(str)) {
        if (i < strlen(str) - strlen(old)
          && memcmp(str + i, old, strlen(old)) == 0) {
            i += strlen(old);
            new_size += strlen(new);
        }
        else {
            new_size += 1;
            i += 1;
        }
    }
    
    char *new_str = malloc(new_size + 1);
    if (new_str == NULL)
        errx(1, "str_replace: malloc");
    i = 0;
    size_t j = 0;
    while (i < strlen(str)) {
        if (i < strlen(str) - strlen(old)
          && memcmp(str + i, old, strlen(old)) == 0) {
            memmove(new_str + j, new, strlen(new));
            i += strlen(old);
            j += strlen(new);
        }
        else
            new_str[j++] = str[i++];
    }
    new_str[new_size] = 0;
    
    return new_str;
}

%{
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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "conf.h"


extern int yyclex(void);
void yycerror(const char *);

extern Conf *conf;
char *expand_path(const char *);

bool set_entry(const char *, const char *);


%}


%union {
    const char *str;
    time_t time;
}

%token TASSIGN
%token TID
%token TSTRING
%token TTIME


%%


start : defns
    ;

defns : defn defns
    | defn
    ;
    
defn  : TID TASSIGN TSTRING
        {
            if (strcmp($<str>1, "spool_dir") == 0) {
                conf->spool_dir = expand_path($<str>3);
                if (conf->spool_dir == NULL) {
                    warnx("Unable to expand path '%s'", $<str>3);
                    YYABORT;
                }
                free((void *) $<str>3);
            }
            else if (strcmp($<str>1, "notify_cmd") == 0) {
                conf->notify_cmd = $<str>3;
            }
            else {
                warn_var($<str>1);
            free((void *) $<str>3);
                YYABORT;
            }

            free((void *) $<str>1);
        }
    | TID TASSIGN TTIME
        {
            if (strcmp($<str>1, "notify_interval") == 0) {
                conf->notify_interval = $<time>3;
            }
            else {
                warn_var($<str>1);
                YYABORT;
            }

            free((void *) $<str>1);
        }
    ;



%%

void yycerror(const char *s)
{
    warnx("%s", s);
}



int yycwrap()
{
    return 1;
}



void warn_var(const char *id)
{
    if (strcmp(id, "spool_dir") == 0
      || strcmp(id, "notify_interval") == 0
      ||  strcmp(id, "notify_cmd") == 0) {
        warnx("Value of incorrect type for '%s'", id);
    }
    else
        warnx("Unknown conf var '%s'", id);
}
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


#include <err.h>
#include <stdbool.h>
#include <stdio.h>

#include "conf.h"


extern int yyclex(void);
void yycerror(const char *);

extern Conf *conf;
char *expand_path(const char *);

bool set_entry(const char *, const char *);


%}


%union {
    const char *str;
}

%token TASSIGN
%token TID
%token TSTRING



%%

%start start

start : defns
      ;

defns : defns defn
      | defn
      ;
    
defn  : TID TASSIGN TSTRING
            {
                if (!set_entry($1.str, $3.str))
                    YYABORT;
                
                free((void *) $<str>1);
                free((void *) $<str>3);
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



bool set_entry(const char *id, const char *val)
{
    if (strcmp(id, "spool_dir") == 0) {
        if (conf->spool_dir != NULL) {
            warnx("Multiple definitions of '%s'", id);
            return false;
        }
        
        conf->spool_dir = expand_path(val);
        if (conf->spool_dir == NULL)
            return false;
    }
    else {
        warnx("Unknown conf var '%s'", id);
        return false;
    }
    
    return true;
}

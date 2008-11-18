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
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>

#include "conf.h"
#include "externals.h"


extern int yyelex(void);
void yyeerror(const char *);

extern Group *groups;
char *expand_path(const char *);

External *_wk_external;

Match *add_match(Match_Type, const char *);
%}



%union {
    const char *str;
    Match *match;
    External *external;
    Group *group;
}

%token TGROUP
%token TEXTERNAL
%token TASSIGN
%token TLCB
%token TRCB
%token TMATCH
%token TREJECT
%token THEADER
%token TID
%token TSTRING



%%



start : groups
        {
            groups = $<group>1;
        }
    ;

groups : groups group
        {
            $<group>1->next = $<group>2;

            $<group>$ = $<group>1;
        }
    | group
    ;

group : TGROUP TLCB matches externals TRCB
        {
            Group *group = malloc(sizeof(Group));
            group->matches = $<match>3;
            group->externals = $<external>4;
            group->next = NULL;
            
            $<group>$ = group;
        }
    | TGROUP TLCB externals TRCB
        {
            Group *group = malloc(sizeof(Group));
            group->matches = NULL;
            group->externals = $<external>3;
            group->next = NULL;
            
            $<group>$ = group;
        }
    ;

matches : matches mr
        {
            $<match>1->next = $<match>2;

            $<match>$ = $<match>1;
        }
    | mr
    ;

mr : match
    | reject
    ;

match : TMATCH THEADER TSTRING
        {
            Match *m = add_match(MATCH, $<str>3);
            if (m == NULL)
                YYABORT;
            $<match>$ = m;
        }
    ;

reject : TREJECT THEADER TSTRING
        {
            Match *m = add_match(REJECT, $<str>3);
            if (m == NULL)
                YYABORT;
            $<match>$ = m;
        }
    ;

externals : externals external
        {
            External *lhs = $<external>1;
            External *rhs = $<external>2;

            lhs->next = rhs;

            $<external>$ = lhs;
        }
    | external
    ;
    
external : TEXTERNAL TID
        {
            _wk_external = malloc(sizeof(External));
            _wk_external->name = $<str>2;
            _wk_external->sendmail = NULL;
        }
    TLCB defns TRCB
        {    
            _wk_external->next = NULL;
        
            $<external>$ = _wk_external;
        }
    ;

defns : defns defn
    | defn
    ;

defn  : TID TASSIGN TSTRING
        {
            if (strcmp($<str>1, "sendmail") == 0) {
                if (_wk_external->sendmail != NULL) {
                    warnx("Multiple definitions of 'sendmail' in '%s'",
                      _wk_external->name);
                    YYABORT;
                }

#            define IS_WHITESPACE(x) ($<str>3[i] == ' ' || $<str>3[i] == '\t' \
                || $<str>3[i] == '\n')

                int nargv = 0; // Number of arguments
                int nargv_alloced = 16;
                char **argv = malloc(sizeof(char *) * nargv_alloced);
                if (argv == NULL)
                    errx(1, "Unable to allocate memory");
                
                int len = strlen($<str>3);
                for (int i = 0; i < len; i++) {
                    // Skip whitespace at beginning of arg
                    while (i < len && IS_WHITESPACE(i))
                        i += 1;
                    
                    if (i == len)
                        break;
                    
                    // Identify an argument. This is nominally a string of non
                    // whitespace characters - unless it's within quotes, when
                    // it can contain whitespace.

                    int start, end;
                    if ($<str>3[i] == '\'') {
                        start = i + 1;
                        i += 1;
                        while (i < len) {
                            if ($<str>3[i] == '\\')
                                i += 2;
                            else if ($<str>3[i] == '\'')
                                break;
                            else
                                i += 1;
                        }
                        
                        if (i == len)
                            end = i;
                        else
                            end = i - 1;
                    }
                    else if ($<str>3[i] == '"') {
                        start = i + 1;
                        i += 1;
                        while (i < len) {
                            if ($<str>3[i] == '\\')
                                i += 2;
                            else if ($<str>3[i] == '"')
                                break;
                            else
                                i += 1;
                        }
                        
                        if (i == len)
                            end = i;
                        else
                            end = i - 1;
                    }
                    else {
                        start = i;
                        while (i < len && ! IS_WHITESPACE(i))
                            i += 1;
                        end = i;
                    }
                    char *arg = malloc(i - start + 1);
                    memcpy(arg, $<str>3 + start, i - start);
                    arg[i - start] = 0;
                    
                    if (nargv == nargv_alloced) {
                        nargv_alloced *= 2;
                        argv = malloc(sizeof(char *) * nargv_alloced);
                        if (argv == NULL)
                            errx(1, "Unable to allocate memory");
                    }
                    argv[nargv++] = arg;
                }
                _wk_external->sendmail = $<str>3;
                _wk_external->sendmail_argv = (const char**) argv;
                _wk_external->sendmail_nargv = nargv;
            }
            else {
                warnx("Unknown externals var '%s'", $<str>1);
                YYABORT;
            }
            
            free((void *) $<str>1);
        }
    ;


%%


Match *add_match(Match_Type type, const char *ptn)
{
    Match *m = malloc(sizeof(Match));
    m->regex = ptn;
    m->type = type;
    int rtn = regcomp(&m->preg, ptn,
      REG_EXTENDED | REG_ICASE | REG_NOSUB | REG_NEWLINE);
    if (rtn != 0) {
        size_t buf_size = regerror(rtn, &m->preg, NULL, 0);
        char *buf = malloc(buf_size);
        if (buf == NULL)
            errx(1, "Out of memory");
        regerror(rtn, &m->preg, buf, buf_size);
        warnx("Error when compiling regular expression '%s': %s", ptn, buf);
        free(buf);
        return NULL;
    }
    
    m->next = NULL;
    
    return m;
}



void yyeerror(const char *s)
{
    warn("%s", s);
}



int yyewrap()
{
    return 1;
}
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
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#include "conf.h"
#include "common.h"
#include "externals_parser.tab.h"

char *mk_str(char *);
%}


%option nounput


%%


#.*$ { }

[ \t\n]+ { }

"=" { return TASSIGN; }
"{" { return TLCB; }
"}" { return TRCB; }
"group" { return TGROUP; }
"external" { return TEXTERNAL; }
"match" { return TMATCH; }
"reject" { return TREJECT; }
"header" { return THEADER; }

[_a-zA-Z][_a-zA-Z0-9]* {
        yyelval.str = mk_str(yytext);
        return TID;
    }

\"    {
        size_t len = 128;
        size_t i = 0;
        char *buf = malloc(len);
        int c;
        while ((c = input()) != 0) {
            if (c == '"') {
                break;
            }

            // Note we always ensure there's 1 spare byte so that we can null
            // terminate the string later.

            if (i + 1 == len) {
                len *= 2;
                buf = realloc(buf, len);
                if (buf == NULL)
                    errx(1, "Out of memory");
            }

            if (c == '\\') {
                int c2 = input();
                switch (c2) {
                    case 'n':
                        buf[i++] = '\n';
                        break;
                    case 'r':
                        buf[i++] = '\r';
                        break;
                    case 't':
                        buf[i++] = '\t';
                        break;
                    default:
                        buf[i++] = c2;
                        break;
                }
            }
            else
                buf[i++] = c;
        }

        buf = realloc(buf, i + 1); // We probably over allocated earlier.
        if (buf == NULL)
            errx(1, "Fatal error");
        buf[i] = 0;

        yyelval.str = buf;
        return TSTRING;
    }

[0-9]+[dhms] {
        char *ep;
        errno = 0;
        time_t num = strtol(yytext, &ep, 10);
        if (ep != yytext + strlen(yytext) - 1)
            errx(1, "Invalid number '%.*s'\n", (int) strlen(yytext) - 1, yytext);
        if (num <= 0 || num >= 365 * 24 * 60 * 60) {
            errx(1, "Time value '%s' out of range", yytext);
        }

        switch (yytext[strlen(yytext) - 1]) {
            case 'd':
                yyelval.time = num * 24 * 60 * 60;
                break;
            case 'h':
                yyelval.time = num * 60 * 60;
                break;
            case 'm':
                yyelval.time = num * 60;
                break;
            case 's':
                yyelval.time = num;
                break;
        }

        return TTIME;
    }

.   {
        errx(1, "Illegal char '%s'\n", yytext );
    }

%%

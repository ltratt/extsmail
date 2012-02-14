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
#include <string.h>
#include <stdio.h>

#include "conf.h"
#include "conf_parser.tab.h"
#include "common.h"

char *mk_str(char *);
%}



%%


#.* { }

[ \t\n]+ { }

"=" { return TASSIGN; }

[_a-zA-Z][_a-zA-Z0-9]* {
        yyclval.str = mk_str(yyctext);
        return TID;
    }

\"    {
        size_t len = 128;
        int i = 0;
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
        
        yyclval.str = buf;
        return TSTRING;
    }

.    {
        errx(1, "Illegal char '%s'\n", yyctext );
    }



%%

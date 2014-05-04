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


typedef enum {MATCH, REJECT} Match_Type;
typedef enum {HEADER} Match_Location;

typedef struct _mat {
    Match_Type type;
    Match_Location location;
    const char *regex;          // Human friendly.
    regex_t preg;
    
    struct _mat *next;
} Match;

typedef struct _ext {
    const char *name;           // Human friendly name - can be anything.
    const char *sendmail;       // sendmail command as a string.
    const char **sendmail_argv; // sendmail command broken up into argv for exec.
    int sendmail_nargv;         // Number of entries in sendmail_argv.
    
    bool working;               // On each cycle, reset to 'true'.
    time_t last_success;        // The time of the last successful execution of
                                // this external. If set to 0, this external has
                                // not previously been tried.
    time_t timeout;             // How many seconds before assuming this external
                                // is dead. If set to 0, means there is no
                                // timeout for this external.

    struct _ext *next;
} External;

typedef struct _grp {
    Match *matches;
    External *externals;

    struct _grp *next;
} Group;

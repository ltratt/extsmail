#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// This test is fragile, because some syslog implementations truncate messages
// at 1KiB.

// This value must be bigger than STDERR_BUF_ALLOC in extsmaild.c.
#define WRITE_SIZE 4096

int main() {
    char *buf = malloc(WRITE_SIZE);
    for (size_t i = 0; i < WRITE_SIZE; i++)
	buf[i] = 'a';
    write(STDERR_FILENO, buf, WRITE_SIZE);
    return 1;
}

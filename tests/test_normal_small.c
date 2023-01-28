#include <assert.h>
#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    char buf[4096];
    size_t read_sz = 0;
    while (true) {
	int rtn = read(STDIN_FILENO, buf, 4096);
	if (rtn == 0)
	    break;
	else if (rtn == -1)
	    err(1, "Failed to read");
	else
	    read_sz += rtn;
    }
    assert(read_sz == 268);
    return 0;
}

#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    char buf[4096];
    while (true) {
	int rtn = read(STDIN_FILENO, buf, 4096);
	if (rtn == 0)
	    break;
	else if (rtn == -1)
	    err(1, "Failed to read");
    }
    return 1;
}

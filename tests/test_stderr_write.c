#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    sleep(1);
    dprintf(STDERR_FILENO, "test");
    return 1;
}

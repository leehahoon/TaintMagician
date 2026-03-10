#include "example.h"
#include <unistd.h>
#include <string.h>

int source(int *buf) {
    // Read an int value from stdin into buf (tainted input).
    int tmp = 0;
    ssize_t n = read(0, &tmp, sizeof(tmp));
    if (n <= 0) {
        tmp = 0;
    }
    *buf = tmp;
    return tmp;
}

void sink(int x) {
    int y = x + 1;
    // Temporary sink: do nothing (no I/O) to keep tests simple.
    (void)y;
}

int sanitizer(int x) {
    // Temporary sanitizer: identity function.
    return x;
}


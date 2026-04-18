#include <string.h>
#include <stdio.h>

// Intentional stack buffer overflow — used by oracle tests only
int main(void) {
    char buf[8];
    char line[256];
    if (fgets(line, sizeof(line), stdin)) {
        strcpy(buf, line);  // deliberate overflow
    }
    printf("%s\n", buf);
    return 0;
}

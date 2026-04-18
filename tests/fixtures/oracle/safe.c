#include <stdio.h>
#include <string.h>

int main(void) {
    char buf[256];
    if (fgets(buf, sizeof(buf), stdin)) {
        buf[strcspn(buf, "\n")] = '\0';
        printf("hello, %s\n", buf);
    }
    return 0;
}

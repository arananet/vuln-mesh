#include <stdio.h>
#include "utils.h"

int main(int argc, char *argv[]) {
    char buf[64];
    gets(buf);
    printf("got: %s\n", buf);
    return 0;
}

#include <stdio.h>
#include <unistd.h>
#include <sys/file.h>

int main() {
    FILE *o;
    o = fopen("build.lst", "a+");
    flock(*o, LOCK_EX);

    fprintf(o, "123\n");
    sleep(3);

    fclose(o);
    return 0;
}

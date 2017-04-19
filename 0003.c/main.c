#include <stdio.h>
#include <stdlib.h>

int main() {
	printf("main/BEG\n");

    FILE *f;
    f = fopen("5640-1.9p", "rb");
    if (!f) {
        printf("main/ERR\n");
        return 1;
    }

    char *tail;
    char ssize[4];
    long size;
    fread(&ssize, 4, 1, f);
    size = strtol(ssize, &tail, 10);
    printf("%s=%d|%s\n", ssize, size, tail);

    fclose(f);

	printf("main/END\n");
    return 0;
}

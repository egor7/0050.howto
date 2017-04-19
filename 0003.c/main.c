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
    unsigned char ssize[4];
    long size;
    fread(ssize, 4, 1, f);
    size = ssize[0] | (ssize[1]<<8) | (ssize[2]<<16) | (ssize[3]<<24);
    printf("%d\n", size);

    fclose(f);

	printf("main/END\n");
    return 0;
}

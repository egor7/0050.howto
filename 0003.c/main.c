#include <stdio.h>
#include <stdlib.h>
#include "c9.h"

int main() {
    printf("main/BEG\n");

    FILE *f;
    f = fopen("5640-1.9p", "rb");
    if (!f) {
        printf("main/ERR\n");
        return 1;
    }

    long sum = 0;
    unsigned char ssize[4];
    while (fread(ssize, 4, 1, f) > 0) {
        long size;
        size = ssize[0] | (ssize[1]<<8) | (ssize[2]<<16) | (ssize[3]<<24);
        printf("%d\n", size);
        sum += size;

        size -= 4;
        unsigned char *sbody = malloc(sizeof(unsigned char)*size);
        fread(sbody, size, 1, f);

        -- prepare internal C9t/C9r
        c/s9proc()
            C9ctx.read(size)
            C9ctx.read(body)
          C9t.t()/C9r.r() -- вешаем callback работать с приходящими сообщениями

        c/s9_type_()
            R/T()
                C9ctx.begin()
            C9ctx.end


	free(sbody);
    }

    fclose(f);

    printf("main/sum = %d\n", sum);
    printf("main/END\n");
    return 0;
}

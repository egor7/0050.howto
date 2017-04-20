#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "c9.h"

void o(const char* fmt, ...)
{
    FILE *o;
    o = fopen("build.lst", "a+");

    va_list args;
    va_start(args, fmt);
    vfprintf(o, fmt, args);
    va_end(args);

    fclose(o);
}

int main() {
    o("main/BEG\n");

    FILE *f;
    f = fopen("5640-1.9p", "rb");
    if (!f) {
        o("main/ERR\n");
        return 1;
    }

    long sum = 0;
    unsigned char ssize[4];
    while (fread(ssize, 4, 1, f) > 0) {
        long size;
        size = ssize[0] | (ssize[1]<<8) | (ssize[2]<<16) | (ssize[3]<<24);
        o("%d\n", size);
        sum += size;

        size -= 4;
        unsigned char *sbody = malloc(sizeof(unsigned char)*size);
        fread(sbody, size, 1, f);

        // -- client Receive
        // c9proc()
        //     C9ctx.read(size)
        //     C9ctx.read(body)
        //   C9r.r() -- вешаем callback работать с подготовленным сообщением
        // 
        // -- client Transmit
        // c9_type_(_custom__fields_)
        //     T() -- common part
        //         C9ctx.begin() -- create b(TAG) buffer
        //     C9ctx.end() -- apply b buffer

	free(sbody);
    }

    fclose(f);

    o("main/sum = %d\n", sum);
    o("main/END\n");
    return 0;
}

/*
    C ECHO client example using sockets
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdarg.h>

#include <pthread.h>

#include "c9.h"
#include "aux.h"
#include "trace.h"

int tlvl = 0;
void tlog(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    FILE *o;
    o = fopen("clt.lst", "a+");
    fprintf(o, "c:");
    for (int i = 0; i < tlvl; i++) {
        fprintf(o, "    ");
    }
    vfprintf(o, fmt, args);
    fprintf(o, "\n");
    fclose(o);

    va_end(args);
}
void tbeg(const char* str) {
    tlog("%s/BEG", str);
    tlvl++;
}
void tend(const char* str) {
    tlvl--;
    tlog("%s/END", str);
}
int terr(const char* str) {
    tlvl--;
    tlog("%s/ERR", str);
    return 1;
}

uint8_t *readbuf(C9ctx *ctx, uint32_t size, int *err)
{
    tbeg("readbuf");
    C9aux *a = ((C9aux*)ctx->aux);

    if (a->msize > 0) {
        tlog("free: %d bytes", a->msize);
        free(a->message);
        a->msize = 0;
    }
    a->message = (uint8_t *)malloc(size*sizeof(uint8_t));
    memset(a->message, 0, size*sizeof(uint8_t));
    a->msize = size;
    tlog("alloc: %d bytes", a->msize);

    int msize = recv(a->sock, a->message, size, 0);

    int i,j;
    uint8_t s[8192] = "", buf[10];
    for (i = 0, j = 0; i < msize; i++)
    {
        if (i > 0) strcat(s, ":");
        sprintf(buf, "%02x", a->message[i]);
        strcat(s, buf);
    }
    tlog(s);

    tend("readbuf");
    return a->message;
}

void r_(C9ctx *ctx, C9r *r9)
{
    tbeg("r_");
    C9aux *a = ((C9aux*)ctx->aux);

    if (a->msize > 0) {
        tlog("free: %d bytes", a->msize);
        free(a->message);
        a->msize = 0;
    }

    switch (r9->type){
        case Rversion:
            tlog("Rversion");
            break;
    }

    tend("r_");
}

uint8_t *makebuf(C9ctx *ctx, uint32_t size)
{
    tbeg("makebuf");
    C9aux *a = ((C9aux*)ctx->aux);

    if (a->msize > 0) {
        tlog("free: %d bytes", a->msize);
        free(a->message);
        a->msize = 0;
    }
    a->message = (uint8_t *)malloc(size*sizeof(uint8_t));
    a->msize = size;
    tlog("alloc: %d bytes", a->msize);

    tend("makebuf");
    return a->message;
}

int sendbuf(C9ctx *ctx)
{
    tbeg("sendbuf");
    C9aux *a = ((C9aux*)ctx->aux);

    if(send(a->sock, a->message, a->msize, 0) < 0)
        return terr("send failed");

    tlog("free: %d bytes", a->msize);
    free(a->message);
    a->msize = 0;

    tend("sendbuf");
    return 0;
}

void *threadf(void *arg)
{
    tbeg("threadf");
    char *str;
    int i = 0;

    str=(char*)arg;

    while(i < 10 )
    {
        usleep(1);
        tlog("threadFunc says: %s\n", str);
        ++i;
    }

    tend("threadf");
    return NULL;
}

int main(int argc , char *argv[])
{
    tbeg("main");
    int sock, read_size;
    struct sockaddr_in server;
    uint8_t message[] = "123";

    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
        return terr("could not create socket");
        tlog("socket created");

    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons( 8888 );

    if (connect(sock , (struct sockaddr*)&server , sizeof(server)) < 0)
        return terr("connect failed");
        tlog("connected");


    C9tag tag;

    C9aux aux;
    aux.message = NULL;
    aux.msize = 0;
    aux.sock = sock;

    C9ctx ctx;
    ctx.aux = &aux;
    ctx.error = &tlog;
    ctx.msize = 8192;
    ctx.svflags = 0;
    // receive
    ctx.read = &readbuf;
    ctx.r = &r_;
    // send
    ctx.begin = &makebuf;
    ctx.end = &sendbuf;

    // pthread_t pth;
    // pthread_create(&pth, NULL, threadf, "processing...");
    // pthread_join(pth, NULL);


    c9version(&ctx, &tag, 8192);
    c9proc(&ctx);

    close(sock);

    tend("main");
    return 0;
}

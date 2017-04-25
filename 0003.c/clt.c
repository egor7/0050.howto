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
    int i;
    for (i = 0; i < tlvl; i++) {
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

int t2lvl = 0;
void t2log(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    FILE *o;
    o = fopen("clt2.lst", "a+");
    fprintf(o, "c2:");
    int i;
    for (i = 0; i < t2lvl; i++) {
        fprintf(o, "    ");
    }
    vfprintf(o, fmt, args);
    fprintf(o, "\n");
    fclose(o);

    va_end(args);
}
void t2beg(const char* str) {
    t2log("%s/BEG", str);
    t2lvl++;
}
void t2end(const char* str) {
    t2lvl--;
    t2log("%s/END", str);
}
int t2err(const char* str) {
    t2lvl--;
    t2log("%s/ERR", str);
    return 1;
}

uint8_t *readbuf(C9ctx *ctx, uint32_t size, int *err)
{
    t2beg("readbuf");
    C9aux *a = ((C9aux*)ctx->aux);

    if (a->nrecv > 0) {
        t2log("free (recv): %d bytes", a->nrecv);
        free(a->recv);
        a->nrecv = 0;
    }
    a->recv = (uint8_t *)malloc(size*sizeof(uint8_t));
    memset(a->recv, 0, size*sizeof(uint8_t));
    a->nrecv = size;
    t2log("alloc (recv): %d bytes", a->nrecv);

    int nrecv = recv(a->sock, a->recv, size, 0);

    int i,j;
    uint8_t s[8192] = "", buf[10];
    for (i = 0, j = 0; i < nrecv; i++)
    {
        if (i > 0) strcat(s, ":");
        sprintf(buf, "%02x", a->recv[i]);
        strcat(s, buf);
    }
    t2log(s);

    t2end("readbuf");
    return a->recv;
}

void r_(C9ctx *ctx, C9r *r9)
{
    t2beg("r_");
    C9aux *a = ((C9aux*)ctx->aux);

    if (a->nrecv > 0) {
        t2log("free (recv): %d bytes", a->nrecv);
        free(a->recv);
        a->nrecv = 0;
    }

    switch (r9->type){
        case Rversion:
            t2log("Rversion");
            // how to get full message unpacked info?
            break;
    }

    t2end("r_");
}

uint8_t *makebuf(C9ctx *ctx, uint32_t size)
{
    tbeg("makebuf");
    C9aux *a = ((C9aux*)ctx->aux);

    if (a->nsend > 0) {
        tlog("free (send): %d bytes", a->nsend);
        free(a->send);
        a->nsend = 0;
    }
    a->send = (uint8_t *)malloc(size*sizeof(uint8_t));
    a->nsend = size;
    tlog("alloc (send): %d bytes", a->nsend);

    tend("makebuf");
    return a->send;
}

int sendbuf(C9ctx *ctx)
{
    tbeg("sendbuf");
    C9aux *a = ((C9aux*)ctx->aux);

    if(send(a->sock, a->send, a->nsend, 0) < 0)
        return terr("send failed");

    tlog("free (send): %d bytes", a->nsend);
    free(a->send);
    a->nsend = 0;

    tend("sendbuf");
    return 0;
}

void *threadf(void *arg)
{
    C9ctx *ctx = ((C9ctx*)arg);
    int i = 0;
    while(i++ < 4) c9proc(ctx);
    pthread_exit(NULL);
}

int main(int argc , char *argv[])
{
    tbeg("main");
    int sock, read_size;
    struct sockaddr_in server;

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
    aux.send = NULL;
    aux.recv = NULL;
    aux.nsend = 0;
    aux.nrecv = 0;
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

    pthread_t pth;
    pthread_create(&pth, NULL, threadf, &ctx);

    c9version(&ctx, &tag, 8192 + 2);
    c9version(&ctx, &tag, 8192);
    c9version(&ctx, &tag, 8192 + 1);
    C9fid afid = 7;
    c9auth(&ctx, &tag, afid, "user/password", "instance");


    // sleep(1);
    pthread_join(pth, NULL);
    close(sock);

    tend("main");
    return 0;
}

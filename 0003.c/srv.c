/*
    C socket server example

    http://www.binarytides.com/server-client-example-c-sockets-linux
    http://stackoverflow.com/questions/28027937/cross-platform-sockets
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdarg.h>

#include "c9.h"
#include "aux.h"
#include "trace.h"

int tlvl = 0;
void tlog(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    FILE *o;
    o = fopen("srv.lst", "a+");
    fprintf(o, "s:");
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

void t_(C9ctx *ctx, C9t *t9)
{
    tbeg("t_");
    C9aux *a = ((C9aux*)ctx->aux);

    if (a->msize > 0) {
        tlog("free: %d bytes", a->msize);
        free(a->message);
        a->msize = 0;
    }

    tlog("client send:%d", (int)t9->type);
    switch (t9->type){
        case Tversion:
            s9version(ctx);
            break;
    }

    tend("t_");
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

int main(int argc, char *argv[])
{
    tbeg("main");

    int socket_desc, client_sock, c, msize;
    struct sockaddr_in server, client;
    uint8_t client_message[8192];
    uint8_t server_message[] = "321";

    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1)
        return terr("could not create socket");
        tlog("socket created");

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 8888 );

    if(bind(socket_desc, (struct sockaddr*)&server, sizeof(server)) < 0)
        return terr("bind failed");
        tlog("bind done");

    listen(socket_desc, 3);
    c = sizeof(struct sockaddr_in);
    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
    if (client_sock < 0)
        return terr("accept failed");
        tlog("connection accepted");

    C9aux aux;
    aux.message = NULL;
    aux.msize = 0;
    aux.sock = client_sock;

    C9ctx ctx;
    ctx.aux = &aux;
    ctx.error = &tlog;
    ctx.msize = 8192;
    ctx.svflags = 0;
    // receive
    ctx.read = &readbuf;
    ctx.t = &t_;
    // send
    ctx.begin = &makebuf;
    ctx.end = &sendbuf;


    while(!s9proc(&ctx));

    tlog("client disconnected");

    if (aux.msize > 0) {
        tlog("free: %d bytes", aux.msize);
        free(aux.message);
        aux.msize = 0;
    }

    // custom
    // close(client_sock);

    tend("main");
    return 0;
}

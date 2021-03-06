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

#include <pthread.h>

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
    o = fopen("srv2.lst", "a+");
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
    tbeg("readbuf");
    tlog("size = %d", size);
    C9aux *a = ((C9aux*)ctx->aux);

    if (a->nrecv > 0) {
        tlog("free (recv): %d bytes", a->nrecv);
        free(a->recv);
        a->nrecv = 0;
    }
    a->recv = (uint8_t *)malloc(size*sizeof(uint8_t));
    memset(a->recv, 0, size*sizeof(uint8_t));
    a->nrecv = size;
    tlog("alloc (recv): %d bytes", a->nrecv);

    int n = recv(a->sock, a->recv, size, 0);

    int i,j;
    uint8_t s[8192] = "", buf[10];
    for (i = 0, j = 0; i < n; i++)
    {
        if (i > 0) strcat(s, ":");
        sprintf(buf, "%02x", a->recv[i]);
        strcat(s, buf);
    }
    tlog(s);

    tend("readbuf");
    return a->recv;
}

// void *threadf(void *arg)
// {
//     tbeg("threadf");
//     C9ctx *ctx = ((C9ctx*)arg);
//     C9aux *a = ((C9aux*)ctx->aux);
//     C9t *t9 = a->t9;
// 
//     switch (t9->type){
//         case Tauth:
//             tlog("Tauth: [%d] (%d) %s %s", t9->tag, t9->auth.afid, t9->auth.uname, t9->auth.aname);
//             C9qid q;
//             q.path = 0;
//             q.version = 0;
//             q.type = C9qtfile;
//             s9auth(ctx, t9->tag, &q);
//             break;
// 
//         default:
//             tlog("%d", (int)t9->type);
//     }
// 
//     tend("threadf");
//     // pthread_exit(NULL);
// }

void t_(C9ctx *ctx, C9t *t9)
{
    tbeg("t_");

    switch (t9->type){
        case Tversion:
            tlog("Tversion: [%d]", t9->tag);
            s9version(ctx);
            break;

        case Tauth:
            tlog("Tauth: [%d] (%d) %s %s", t9->tag, t9->auth.afid, t9->auth.uname, t9->auth.aname);
            C9qid q;
            q.path = 0;
            q.version = 0;
            q.type = C9qtfile;
            s9auth(ctx, t9->tag, &q);
            break;

        default:
            tlog("%d", (int)t9->type);

        // default:
        //     //pthread_t pth;
        //     //pthread_create(&pth, NULL, threadf, ctx);
        //     threadf(ctx);
    }

    tend("t_");
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

int main(int argc, char *argv[])
{
    tbeg("main");

    int sock, client_sock, c;
    struct sockaddr_in server, client;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1)
        return terr("could not create socket");
        tlog("socket created");

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 8888 );

    if(bind(sock, (struct sockaddr*)&server, sizeof(server)) < 0)
        return terr("bind failed");
        tlog("bind done");

    listen(sock, 3);
    c = sizeof(struct sockaddr_in);
    client_sock = accept(sock, (struct sockaddr *)&client, (socklen_t*)&c);
    if (client_sock < 0)
        return terr("accept failed");
        tlog("connection accepted");

    C9aux aux;
    aux.send = NULL;
    aux.recv = NULL;
    aux.nsend = 0;
    aux.nrecv = 0;
    aux.sock = client_sock;

    C9ctx ctx;
    ctx.aux = &aux;
    ctx.error = &tlog;
    ctx.msize = 8192 + 1;
    ctx.svflags = 0;
    // receive
    ctx.read = &readbuf;
    ctx.t = &t_;
    // send
    ctx.begin = &makebuf;
    ctx.end = &sendbuf;


    while(!s9proc(&ctx));

    tlog("client disconnected");

    if (aux.nrecv > 0) {
        tlog("free (recv): %d bytes", aux.nrecv);
        free(aux.recv);
        aux.nrecv = 0;
    }

    close(client_sock);
    close(sock);

    tend("main");

    fclose(stdin);
    fclose(stdout);
    fclose(stderr);

    return 0;
}

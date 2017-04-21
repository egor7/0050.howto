/*
    C ECHO client example using sockets
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "c9.h"
#include "aux.h"

void ok(const char* str) {FILE *o; o = fopen("clt.lst", "a+"); fprintf(o, "c:%s\n", str); fclose(o);}
int err(const char* str) {FILE *o; o = fopen("clt.lst", "a+"); fprintf(o, "c:%s\n", str); fclose(o); return 1;}

uint8_t *begin_(C9ctx *ctx, uint32_t size)
{
    C9aux *a = ((C9aux*)ctx->aux);
    a->message = (uint8_t *)malloc(size*sizeof(uint8_t));
    a->msize = size;
    return a->message;
}

int end_(C9ctx *ctx)
{
    C9aux *a = ((C9aux*)ctx->aux);

    if(send(a->sock, a->message, a->msize, 0) < 0)
        return err("send failed");

    free(a->message);
    a->msize = 0;
    return 0;
}

void error_(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    //vprintf(fmt, args);
    FILE *o;
    o = fopen("clt.lst", "a+");
    vfprintf(o, fmt, args);
    fclose(o);

    va_end(args);
}

int main(int argc , char *argv[])
{
    int sock, read_size;
    struct sockaddr_in server;
    uint8_t message[] = "123", server_reply[2000];

    sock = socket(AF_INET , SOCK_STREAM , 0);
    if (sock == -1)
        return err("could not create socket");
        ok("socket created");

    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons( 8888 );

    if (connect(sock , (struct sockaddr*)&server , sizeof(server)) < 0)
        return err("connect failed");
        ok("connected");


    C9tag tag;

    C9aux aux;
    aux.message = NULL;
    aux.msize = 0;
    aux.sock = sock;

    C9ctx ctx;
    ctx.error = &error_;
    ctx.begin = &begin_;
    ctx.end = &end_;
    ctx.aux = &aux;

    c9version(&ctx, &tag, 8192);

    // if((read_size = recv(sock, server_reply, 2000, 0)) < 0)
    //     return err("recv failed");
    // server_reply[read_size] = '\0';
    //     ok("server reply:");
    //     ok(server_reply);

    close(sock);
    return 0;
}

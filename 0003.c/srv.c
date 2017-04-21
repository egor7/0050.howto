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

//void ok(const char* str) {FILE *o; o = fopen("srv.lst", "a+"); fprintf(o, "s: %s\n", str); fclose(o);}
int err(const char* str) {FILE *o; o = fopen("srv.lst", "a+"); fprintf(o, "s:%s\n", str); fclose(o); return 1;}

// -- client Receive
// s9proc()
//     C9ctx.read(size)
//     C9ctx.read(body)
//   C9ctx.t(C9t) -- вешаем callback работать с подготовленным сообщением

void ok(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    FILE *o;
    o = fopen("srv.lst", "a+");
    fprintf(o, "s:");
    vfprintf(o, fmt, args);
    fprintf(o, "\n");
    fclose(o);

    va_end(args);
}

uint8_t *read_(C9ctx *ctx, uint32_t size, int *err)
{
    ok("read_/BEG");
    C9aux *a = ((C9aux*)ctx->aux);

    // todo free
    if (a->msize > 0) {
        free(a->message);
        a->msize = 0;
    }
    a->message = (uint8_t *)malloc(size*sizeof(uint8_t));
    memset(a->message, 0, size*sizeof(uint8_t));
    a->msize = size;
    int msize = recv(a->sock, a->message, size, 0);

    int i,j;
    uint8_t s[8192] = "", buf[10];
    for (i = 0, j = 0; i < msize; i++)
    {
        //if (i > 0) sprintf(s, "%s:", s);
        //sprintf(s, "%s%02x", s, a->message[i]);
        if (i > 0) strcat(s, ":");
        sprintf(buf, "%02x", a->message[i]);
        strcat(s, buf);
    }
    ok(s);

    ok("read_/END");
    return a->message;
}

void t_(C9ctx *ctx, C9t *t)
{
    ok("t_/BEG");
    C9aux *a = ((C9aux*)ctx->aux);

    a->t = *t;

    ok("t_/END");
}


int main(int argc, char *argv[])
{
    int socket_desc, client_sock, c, msize;
    struct sockaddr_in server, client;
    uint8_t client_message[8192];
    uint8_t server_message[] = "321";

    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1)
        return err("could not create socket");
        ok("socket created");

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 8888 );

    if(bind(socket_desc, (struct sockaddr*)&server, sizeof(server)) < 0)
        return err("bind failed");
        ok("bind done");

    listen(socket_desc, 3);
    c = sizeof(struct sockaddr_in);
    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
    if (client_sock < 0)
        return err("accept failed");
        ok("connection accepted");

    C9aux aux;
    aux.message = NULL;
    aux.msize = 0;
    aux.sock = client_sock;

    C9ctx ctx;
    ctx.error = &ok;
    ctx.read = &read_;
    ctx.aux = &aux;
    ctx.t = &t_;
    ctx.msize = 8192;
    ctx.svflags = 0;

    C9error err;
    while((err = s9proc(&ctx)) == 0)
    {
        ok("client send:%d", (int)aux.t.type);
        //write(client_sock, server_message, strlen(server_message));
    }
    ok("client disconnected");

    if (aux.msize > 0) {
        free(aux.message);
        aux.msize = 0;
    }

    // custom
    // close(client_sock);

    return 0;
}

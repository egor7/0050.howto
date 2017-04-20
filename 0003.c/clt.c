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

void ok(const char* str) {FILE *o; o = fopen("clt.lst", "a+"); fprintf(o, "c: %s\n", str); fclose(o);}
int err(const char* str) {FILE *o; o = fopen("clt.lst", "a+"); fprintf(o, "c: %s\n", str); fclose(o); return 1;}

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

typedef struct aux aux;
struct aux {
    uint8_t *message;
    int msize;
};

uint8_t *begin(C9ctx *ctx, uint32_t size)
{
    aux *a = ((aux*)ctx->aux);
    a->message = (uint8_t *)malloc(size*sizeof(uint8_t));
    a->msize = size;
    return a->message;
}

int end(C9ctx *ctx)
{
    aux *a = ((aux*)ctx->aux);
    char s[200] = "";
    int i;
    for (i = 0; i < a->msize; i++)
    {
        if (i > 0) sprintf(s, "%s:", s);
        sprintf(s, "%s%02X", s, a->message[i]);
    }
    ok(s);

    free(a->message);
    a->msize = 0;
    return 0;
}

int main(int argc , char *argv[])
{
    int sock, read_size;
    struct sockaddr_in server;
    char message[] = "123", server_reply[2000];

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
    C9ctx c;
    aux a;
    a.message = NULL;
    a.msize = 0;

    c.begin = &begin;
    c.end = &end;
    c.aux = &a;
    c9version(&c, &tag, 8192);


    // loop while(1)
    if( send(sock, message, strlen(message), 0) < 0)
        return err("send failed");

    if((read_size = recv(sock, server_reply, 2000, 0)) < 0)
        return err("recv failed");
    server_reply[read_size] = '\0';
        ok("server reply:");
        ok(server_reply);

    close(sock);
    return 0;
}

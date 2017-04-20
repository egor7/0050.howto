/*
    C socket server example

    http://www.binarytides.com/server-client-example-c-sockets-linux
    http://stackoverflow.com/questions/28027937/cross-platform-sockets
*/

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

void ok(const char* str) {FILE *o; o = fopen("srv.lst", "a+"); fprintf(o, "s: %s\n", str); fclose(o);}
int err(const char* str) {FILE *o; o = fopen("srv.lst", "a+"); fprintf(o, "s: %s\n", str); fclose(o); return 1;}

int main(int argc , char *argv[])
{
    int socket_desc, client_sock, c, msize;
    struct sockaddr_in server , client;
    uint8_t client_message[8192];
    char message[] = "321";

    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
        return err("could not create socket");
        ok("socket created");

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 8888 );

    if(bind(socket_desc, (struct sockaddr*)&server, sizeof(server)) < 0)
        return err("bind failed");
        ok("bind done");

    listen(socket_desc , 3);
    c = sizeof(struct sockaddr_in);
    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
    if (client_sock < 0)
        return err("accept failed");
        ok("connection accepted");

    while((msize = recv(client_sock , client_message , 2000 , 0)) > 0)
    {
        ok("client send:");

        int i;
        char s[8192] = "";
        for (i = 0; i < msize; i++)
        {
            if (i > 0) sprintf(s, "%s:", s);
            sprintf(s, "%s%02x", s, client_message[i]);
        }
        ok(s);

        write(client_sock, message, strlen(message));
    }
    if(msize == 0)
    {
        ok("client disconnected");
        fflush(stdout);
    }
    else if(msize == -1)
        return err("recv failed");

    return 0;
}

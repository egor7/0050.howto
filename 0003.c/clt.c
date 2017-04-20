/*
    C ECHO client example using sockets
*/
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

void ok(char* str) {printf("c: %s\n", str);}
int err(char* str) {printf("c: %s\n", str); return 1;}

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

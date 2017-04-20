/*
    C socket server example

    1. Create socket
    2. Bind to address and port
    3. Put in listening mode
    4. Accept connections and process there after.

    http://www.binarytides.com/server-client-example-c-sockets-linux
    http://stackoverflow.com/questions/28027937/cross-platform-sockets
*/

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

void ok(char* str)
{
    printf("s: %s\n", str);
}

int err(char* str)
{
    printf("s: %s\n", str);
    return 1;
}

int main(int argc , char *argv[])
{
    int socket_desc, client_sock, c, read_size;
    struct sockaddr_in server , client;
    char client_message[2000];
    char message[] = "321";

    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
        return err("could not create socket");
    ok("socket created");

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( 8888 );

    if( bind(socket_desc, (struct sockaddr*)&server, sizeof(server)) < 0)
        return err("bind failed");
    ok("bind done");

    listen(socket_desc , 3);
    ok("waiting for incoming connections...");
    c = sizeof(struct sockaddr_in);

    client_sock = accept(socket_desc, (struct sockaddr *)&client, (socklen_t*)&c);
    if (client_sock < 0)
        return err("accept failed");
    ok("connection accepted");

    while((read_size = recv(client_sock , client_message , 2000 , 0)) > 0)
    {
        client_message[read_size] = '\0';
        ok(client_message);
        write(client_sock, message, strlen(message));
    }

    if(read_size == 0)
    {
        ok("client disconnected");
        fflush(stdout);
    }
    else if(read_size == -1)
        return err("recv failed");

    return 0;
}
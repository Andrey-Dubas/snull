#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <error.h>
#include <errno.h>
#include <string.h>

#include <unistd.h>
#include <iostream>

int main()
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        std::cout << "socket creation failed" << std::endl;
    }

    sockaddr_in sockaddr;
    sockaddr.sin_addr.s_addr = inet_addr("192.168.10.1");
    //sockaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    sockaddr.sin_port = htons(11111);
    sockaddr.sin_family = AF_INET;

    int r = bind(s, (struct sockaddr*) &sockaddr, sizeof(sockaddr));
    if (r < 0)
    {
        std::cout << "binding failed: " << strerror(errno) << std::endl;
    }

    if (listen(s, 3) < 0)
    {
        std::cout << "listening error" << std::endl;
    }

    sockaddr_in remoteAddr;
    socklen_t remoteAddrLen;

    int workerSocket = accept(s, (struct sockaddr*) &remoteAddr, &remoteAddrLen);
    if (workerSocket < 0)
    {
        std::cout << "No worker socket created" << std::endl;
    }

    char str[255];
    int len = recv(workerSocket, &str, 255, 0);
    if (len > 0)
    {
        std::cout << "received a string: " << str << std::endl;
    }
    recv(workerSocket, &str, 1, 0);
    close(workerSocket);
    close(s);
}

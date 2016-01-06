#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <unistd.h>
#include <iostream>

int main()
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == 0)
    {
        std::cout << "socker creation failed" << std::endl;
    }

    /*
    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, "vd1", 3) < 0)
    {
        std::cout << "can't set the device" << std::endl;
    }
    */

    sockaddr_in sockaddr;
    sockaddr.sin_addr.s_addr = inet_addr("192.168.10.1");
    sockaddr.sin_port = htons(11111);
    sockaddr.sin_family = AF_INET;
    
    int r = connect(s, (struct sockaddr*) &sockaddr, sizeof(sockaddr));
    if (r < 0)
    {
        std::cout << "can't connect" << std::endl;
    }

    char message[] = "hi!";

    send(s, message, sizeof(message), MSG_NOSIGNAL);

    close(s);
}

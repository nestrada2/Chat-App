#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include  <sys/ioctl.h>

#define BUF_SIZE 500
#define FD_SIZE 64
#define LAB_NETWORK "10.10.13.255" // Address UDP Broadcast
#define PRESENCE_PORT 8221      // Differs between Devices
#define ASSIGNED_PORT 8328      // Differs between Devices

void pollLoop(struct pollfd fds[], char buffer[], int udpSocket, int tcpSocket);

// A user struct which stores the information of all the users on the network.
struct user
{
    char status[BUF_SIZE];
    char name[BUF_SIZE];
    char port[BUF_SIZE];
    char host[NI_MAXHOST];
} users[64];

// We send an online/offline message over UDP.
void presence(int sfd, char status[])
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, LAB_NETWORK, &addr.sin_addr);
    addr.sin_port = htons(PRESENCE_PORT);

    char buf[BUF_SIZE];
    strncpy(buf, status, BUF_SIZE);
    strncat(buf, " nestrada2 ", BUF_SIZE);
    strncat(buf, "8328", BUF_SIZE);

    int len = strlen(buf) + 1; // + 1 to include the Null Terminator

    if (sendto(sfd, buf, len, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_in)) != len)
    {
        perror("sendto");
    }
}

int createUDPSocket()
{
    // Set up UDP socket
    struct addrinfo hints;
    struct addrinfo* result, * rp;
    int s, sfd;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    ssize_t nread;
    char buf[BUF_SIZE];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;      // Allow IPv$ or IPv6
    hints.ai_socktype = SOCK_DGRAM; // Datagram Socket
    hints.ai_flags = AI_PASSIVE;    // Any IP Address (DHCP)
    hints.ai_protocol = 0;          // Any Protocol
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    // Get a LinkedList
    s = getaddrinfo(NULL, "8221", &hints, &result);

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        // creating a socket returns an int, and that int is known as a file descriptor
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        int enable_broadcast = 1;
        setsockopt(sfd, SOL_SOCKET, SO_BROADCAST, &enable_broadcast, sizeof(int));

        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
        {
            printf("Successful bind!\n");
            return sfd;
        }
        else
        {
            printf("Not Successful bind!\n");
        }
        close(sfd);
    }
    return -1;
}

int createTCPReceiverSocket() 
{
    struct addrinfo hints;
    struct addrinfo* result, * rp;
    int s, sfd;
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    ssize_t nread;
    char buf[BUF_SIZE];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; // Allow IPv$ or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;    // Any IP Address (DHCP)
    hints.ai_protocol = IPPROTO_TCP;          // Any Protocol
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    // Get a LinkedList
    s = getaddrinfo(NULL, "8328", &hints, &result);
    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        int enable_broadcast = 1;
        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &enable_broadcast, sizeof(int));

        // making your port 8328 available for other people to send messages to
        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
        {
            int enable = 1;
            ioctl(sfd, FIONBIO, (char*)enable);
            int l = listen(sfd, 64);
            if (l == -1) 
            {
                printf("Unable to listen to TCP socket");
                return -1;
            }
            return sfd;
        }
        else
        {
            printf("Not Successful TCP bind!\n");
        }
        close(sfd);
    }
    return -1;
}

// Main Function: Entry Point of a C Program
int main(int argc, char* argv[])
{
    // Set up UDP socket and broadcast presence.
    int udpSocket = createUDPSocket();
    // sending out a message to everyone (no one in particular) 
    // that we are online
    presence(udpSocket, "online");

    // Set up TCP listener
    int tcpSocket = createTCPReceiverSocket();

    // Array of pollfds: 3 sockets
    struct pollfd fds[FD_SIZE];
    // Standard input file listener
    fds[0].fd = STDIN_FILENO;
    fds[0].events = POLL_IN;

    // UDP socket
    fds[1].fd = udpSocket;
    fds[1].events = POLL_IN;

    // TCP socket
    fds[2].fd = tcpSocket;
    fds[2].events = POLL_IN;

    static char buffer[1024]; // Static lifetime but local name scope

    // start poll loop 
    pollLoop(fds, buffer, udpSocket, tcpSocket);

    return 0;
}

void pollLoop(struct pollfd fds[], char buffer[], int udpSocket, int tcpSocket)
{
    int next_fd_entry = 3;
    int counter = 0;

    int num_users = 0;
    while (1)
    {
        // Poll - Which of these Sockets is Ready to Read
        int num_ready = poll(fds, FD_SIZE, 500);

        if (num_ready == 0)
        {
            counter += 1;
            // Periodically send presence
            if (counter == 100)
            {
                presence(udpSocket, "online");
                counter = 0;
            }
        }

        if (num_ready > 0)
        {
            // Loop Over All 64 FDS
            for (int i = 0; i < FD_SIZE; i += 1)
            {
                if (fds[i].revents & POLL_IN) // POLL_IN See what is Readable fds through the Array
                {
                    // printf("Data ready on: FD(%d) idx(%d)\n", fds[i].fd, i);
                    // Handle user-input
                    if (fds[i].fd == STDIN_FILENO) // STDIN_FILENO is a well known fd that is always open
                    {
                        char c; // reads 1 character from stdin, poll timeout is running
                        while (c != '\n')
                        {
                            // Quit and shut down cleanly
                            if (c == 'q' || c == -1)
                            {
                                presence(udpSocket, "offline");
                                for (int i = 0; i < FD_SIZE; i += 1)
                                {
                                    close(fds[i].fd);
                                }
                                exit(0);
                            }
                            c = getchar();
                            strcat(buffer, &c);
                        }

                        // Extract username and message from the user input.

                        // error handling if its not correctly formatted.
                        char* username;
                        username = strtok(buffer, ": ");
                        username++;

                        char* msg;
                        msg = strtok(NULL, ": ");

                        int userFound = 0;
                        struct user tempUser;
                        for (int i = 0; i < num_users; i++) {
                            if (strcmp(username, users[i].name)) {
                                userFound = 1;
                                tempUser = users[i];
                                break;
                            }
                        }

                        if (!userFound) {
                            continue;
                        }

                        // Sending our chat message to the receiver via TCP
                        struct addrinfo hints;
                        memset(&hints, 0, sizeof(hints));
                        hints.ai_family = AF_INET;
                        hints.ai_socktype = SOCK_STREAM;
                        struct addrinfo* res;
                        int rc = getaddrinfo(tempUser.host, tempUser.port, &hints, &res);
                        if (rc != 0)
                            printf("%s\n", gai_strerror(rc));
                        int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

                        if (connect(fd, res->ai_addr, res->ai_addrlen) != 0)
                            perror("connect");

                        int len = strlen(msg) + 1;
                        if (send(fd, msg, len, 0) == -1)
                            perror("send");

                        if (close(fd) == -1)
                            perror("close");

                        c = '\0';
                        memset(buffer, 0, 1024);
                    }

                    if (fds[i].fd == tcpSocket) 
                    {
                        // Receiving a chat message
                        int s;
                        struct sockaddr clientaddress;
                        int address_len;
                        int newFd = accept(tcpSocket, &clientaddress, &address_len);

                        fds[next_fd_entry].fd = newFd;
                        fds[next_fd_entry].events = POLL_IN;
                        next_fd_entry += 1;
                    }

                    // Handle an incoming UDP message
                    if (fds[i].fd == udpSocket)
                    {
                        int s;
                        struct sockaddr_storage peer_addr;
                        socklen_t peer_addr_len;
                        ssize_t nread;
                        char buf[BUF_SIZE];
                        char host[NI_MAXHOST], service[NI_MAXSERV];

                        peer_addr_len = sizeof(peer_addr);
                        nread = recvfrom(udpSocket, buf, BUF_SIZE, 0,
                            (struct sockaddr*)&peer_addr, &peer_addr_len);

                        s = getnameinfo((struct sockaddr*)&peer_addr,
                            peer_addr_len, host, NI_MAXHOST,
                            service, NI_MAXSERV, NI_NUMERICSERV);

                        if (nread == -1)
                        {
                            continue; // Ignore failed request
                        }

                        // parse status, name, port from buf
                        char status[BUF_SIZE];
                        char name[BUF_SIZE];
                        char port[BUF_SIZE];
                        sscanf(buf, "%s %s %s", status, name, port);

                        if (strcmp(status, "online"))
                        {
                            strcpy(users[num_users].status, status);
                            strcpy(users[num_users].name, name);
                            strcpy(users[num_users].port, port);
                            strcpy(users[num_users].host, host);
                            num_users += 1;
                        }
                        else
                        {
                            for (int i = 0; i < num_users; i++)
                            {
                                if (users[i].name == name)
                                {
                                    strcpy(users[i].status, status);
                                }
                            }
                        }

                        printf("received status(%s) name(%s) port(%s) from host(%s)\n", status, name, port, host);
                    }

                    // loop through all of the chat file descriptors that we received.
                    if (i > 2) 
                    {
                        char recvbuf[128];
                        int res = recv(fds[i].fd, recvbuf, sizeof(recvbuf), 0);
                        if (res == 0) 
                        {
                            // Connection closed
                            fds[i].fd = -1;
                        }
                        else 
                        {
                            printf("%s\n", recvbuf);
                        }
                    }
                }
            }
        }
    }
}

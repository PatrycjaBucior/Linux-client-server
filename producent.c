#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <sys/timerfd.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include <netdb.h>


#define BLOCK_SIZE 640
#define BUF_SIZE 13312
#define POLL_SIZE 800
#define PORTION_SIZE 1024

struct Client {
    int fd;    //deskryptor
    int sent;  //ilosc wysłanych bajtow
    unsigned short port;
    char ip[16];
};

unsigned short port;
char* addr;

struct pollfd poll_set[POLL_SIZE];
struct Client client[POLL_SIZE];
char buf[BUF_SIZE];

int readArgs(int argc, char* argv[]);
void setAddrPort(char* argv);
char* productionBlock(char* block, struct timespec work_time);
void warehouseManagement(struct timespec work_time);
struct timespec diff(struct timespec start, struct timespec end);
void sleepTime(long time);
void distribution(int fd);
void registration(int sockfd, char * host);
int connection(int sockfd, int nfds);
void production(int fd, struct timespec work_time);
short createSocket();
struct timespec convertTime(float speed);
void setNonblockAndReuseable(int serv_sock_fd);
void setPassiveMode(int serv_sock_fd);
int checkBytesOrder();
char* getHost();
int initTimer();
struct timespec getTime(struct timespec time, int clock);
void printTime();
void readTimer(int timer_fd);
void printRegularReport(int num_of_clients, int fillness, float proc, int flow);
void initPoll(int serv_sock_fd, int timer_fd);
void printDisconnectReport(int wasted, int k);
int countWastedBytes(int pipe_fd, int k);
void serveClient(int pipe_fd, int k);
int moveClients(int nfds);
void zeroClient(int k);
void mainLoop(int reserved_bytes, int nfds, int available_bytes, int connected_clients, int serv_sock_fd, int old, int timer_fd, int new_socket, int fd);


int main(int argc, char* argv[])
{
    int speed = readArgs(argc, argv);
    struct timespec work_time = convertTime(speed);
    warehouseManagement(work_time);
    return 0;
}


int readArgs(int argc, char* argv[])
{
    int option;
    float speed = 1;
    while ((option = getopt (argc, argv, "p:")) != -1)
    {
        switch (option)
        {
            case 'p':
            {
                speed = strtof(optarg, NULL);
                speed *= 2662;
                printf("-production speed: %f\n", speed);
                break;
            }
            case '?':
            {
                if(optopt == 'p')
                    printf ("Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    printf ("Unknown option `-%c'.\n", optopt);
                else
                    printf ("Unknown option character `\\x%x'.\n", optopt);
                exit(1);
            }
            default:
                abort ();
        }
    }

    if(argv[optind] == NULL)
    {
        printf("missing parameter: [<addr>:]port\n");
        exit(5);
    }

    if(speed==0)
    {
        printf("production speed cannot be zero\n");
        exit(8);
    }

    setAddrPort(argv[optind]);
    return speed;
}


struct timespec convertTime(float speed)
{
    struct timespec time;
    double work_time = (BLOCK_SIZE/speed);
    time.tv_sec = work_time;
    time.tv_nsec = (work_time-time.tv_sec)*1000000000;
    return time;
}


void setAddrPort(char* argv)
{
    if(argv[0] > '0' && argv[0] <= '9')
    {
        port = (unsigned short)strtoul( argv, NULL, 10 );
        addr = (char*)malloc(sizeof(char)*9);
        addr = "localhost";
    }
    else
    {
        int count;
        for(count=0; count< strlen(argv); ++count)
        {
            if(argv[count] == ':') break;
        }
        addr = (char*)malloc(sizeof(char)*count);
        strncpy(addr, argv, count);
        char * pEnd = argv + count+1;
        port = (unsigned short)strtoul( pEnd, NULL, 10 );
    }
}


int checkBytesOrder()
{
    int tmp = 0x12345678;
    unsigned char *c = (unsigned char*)(&tmp);
    if (*c == 0x78)
        return 1; // little-endian

    return 0; // big-endian
}


char* getHost()
{
    struct hostent *h = gethostbyname(addr);
    if (h == NULL)
    {
        printf("gethostbyname() failed\n");
        exit(-5);
    }
    else {
        return inet_ntoa( *( struct in_addr*)( h -> h_addr_list[0]));
    }
}


char* productionBlock(char* block, struct timespec work_time)
{
    struct timespec time1, time2;
    time1 = getTime(time1, CLOCK_REALTIME);

    static int letter = 0;
    char letters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    memset(block, letters[letter], BLOCK_SIZE);
    if(letter < 51)
        ++letter;
    else
        letter = 0;

    time2 = getTime(time2, CLOCK_REALTIME);
    struct timespec elapsed_time = diff(time1,time2);
    if( work_time.tv_sec > elapsed_time.tv_sec || work_time.tv_nsec > elapsed_time.tv_nsec )
    {
        work_time.tv_sec = work_time.tv_sec - elapsed_time.tv_sec;
        work_time.tv_nsec = work_time.tv_nsec - elapsed_time.tv_nsec;
        nanosleep(&work_time,NULL);
    }
    return block;
}


void warehouseManagement(struct timespec work_time)
{
    int fd[2];
    if (pipe(fd) == -1)
    {
        printf("Create pipe error");
        exit(-1);
    }
    pid_t pid = fork();
    if(pid>0) {
        close(fd[0]);
        production(fd[1], work_time);
    }
    if(pid==0)
    {
        close(fd[1]);
        distribution(fd[0]);
    }
    else if(pid==-1)
    {
        printf( "fork error\n" );
        exit(-1);
    }
}


struct timespec diff(struct timespec start, struct timespec end)
{
    struct timespec temp;
    if ((end.tv_nsec-start.tv_nsec)<0)
    {
        temp.tv_sec = end.tv_sec-start.tv_sec-1;
        temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
    }
    else
    {
        temp.tv_sec = end.tv_sec-start.tv_sec;
        temp.tv_nsec = end.tv_nsec-start.tv_nsec;
    }
    return temp;
}


void initPoll(int serv_sock_fd, int timer_fd)
{
    memset(poll_set, 0 , sizeof(poll_set));
    memset(client, 0 , sizeof(client));
    poll_set[0].fd = serv_sock_fd;
    poll_set[0].events = POLLIN;
    poll_set[1].fd = timer_fd;
    poll_set[1].events = POLLIN;
}


void distribution(int fd)
{
    int reserved_bytes = 0;
    int nfds = 2;
    int available_bytes = 0;
    int connected_clients = 0;
    int serv_sock_fd = createSocket();
    int old;
    ioctl(fd, FIONREAD, &old);
    int timer_fd = initTimer();
    setNonblockAndReuseable(serv_sock_fd);
    registration(serv_sock_fd,getHost());
    setPassiveMode(serv_sock_fd);
    initPoll(serv_sock_fd, timer_fd);
    int new_socket = 0;
    mainLoop(reserved_bytes, nfds, available_bytes, connected_clients, serv_sock_fd, old, timer_fd, new_socket, fd);
}


void mainLoop(int reserved_bytes, int nfds, int available_bytes, int connected_clients, int serv_sock_fd, int old, int timer_fd, int new_socket, int fd)
{
    int last_client_fd = 0;
    while (1)
    {
        int nbytes;
        ioctl(fd, FIONREAD, &nbytes);
        available_bytes = nbytes - reserved_bytes;
        if (available_bytes >= BUF_SIZE)
        {
            char tmp[16];
            poll(poll_set, nfds, 100);
            int current_size = nfds;
            for (int i = 0; i < current_size; i++)
            {
                if(poll_set[i].revents == 0)
                    continue;

                if (poll_set[i].fd == timer_fd && poll_set[i].revents == POLLIN)
                {
                    readTimer(timer_fd);
                    int fillness;
                    ioctl(fd, FIONREAD, &fillness);
                    int capacity = fcntl(fd, F_GETPIPE_SZ);
                    float proc = ((float)fillness/capacity)*100;
                    int flow = fillness - old;
                    old = fillness;
                    printRegularReport(connected_clients, fillness, proc, flow);
                }

                else if (poll_set[i].fd == serv_sock_fd && poll_set[i].revents == POLLIN && nfds<POLL_SIZE)
                {
                    do{
                        new_socket = connection(serv_sock_fd, nfds);
                        //printf("  New incoming connection - %d\n", new_socket);
                        if(new_socket != -1)
                        {
                            poll_set[nfds].fd = new_socket;
                            poll_set[nfds].events = POLLOUT;
                            client[nfds-2].fd = new_socket;
                            nfds++;
                            reserved_bytes +=13;
                            connected_clients++;
                            //printf("connected clients: %d\n", connected_clients);
                        }
                    }while (new_socket != -1);
                }

                else if(poll_set[i].revents == POLLOUT && poll_set[i].fd != serv_sock_fd && client[i-2].fd != 0)
                {
                    if(client[i-2].sent < BUF_SIZE )
                    {
                        if(connected_clients > 1)
                        {
                            if(last_client_fd != client[i-2].fd)
                                serveClient(fd, i);
                        }
                        else
                            serveClient(fd, i);

                        last_client_fd = client[i-2].fd;
                    }
                }
                if(recv(poll_set[i].fd, tmp, 16*sizeof(char), MSG_PEEK | MSG_DONTWAIT) == 0 )
                {
                    connected_clients--;
                    int wasted = countWastedBytes(fd, i-2);
                    printDisconnectReport(wasted, i-2);
                    zeroClient(i);
                    nfds = moveClients(nfds);
                    reserved_bytes -= 13;
                    //printf("connected clients: %d\n", connected_clients);
                }
            }
        }
    }
}


void zeroClient(int k)
{
    close(poll_set[k].fd);
    poll_set[k].fd = -1;
    poll_set[k].revents = 0;
    client[k-2].fd = 0;
    client[k-2].sent = 0;
    client[k-2].port = 0;
    memset(client[k-2].ip, '\0' , 16*sizeof(char));
}


int moveClients(int nfds)
{
    for (int i = 0; i < nfds; i++)
    {
        if (poll_set[i].fd == -1)
        {
            for(int j = i; j < nfds; j++)
            {
                poll_set[j].fd = poll_set[j+1].fd;
                client[j-2].fd = client[j-1].fd;
                client[j-2].sent = client[j-1].sent;
                client[j-2].port = client[j-1].port;
                sscanf(client[j-1].ip, "%s", client[j-2].ip);
            }
            i--;
            nfds--;
        }
    }
    return nfds;
}


void serveClient(int pipe_fd, int k)
{
    poll_set[k].revents = 0;
    if (read(pipe_fd, buf, PORTION_SIZE) == -1)
    {
        printf("read from pipe error");
        exit(1);
    }

    client[k-2].sent += PORTION_SIZE;
    //printf("klient %d (%d) dostal juz %d bajtow \n", client[k-2].fd, poll_set[k].fd, client[k-2].sent);
    if (write(poll_set[k].fd, buf, PORTION_SIZE) < 0)
    {
        printf("write to socket error");
        exit(2);
    }
}


int countWastedBytes(int pipe_fd, int k)
{
    int wasted = 0;
    if(client[k].sent != 0)
    {
        wasted = BUF_SIZE - client[k].sent;
        if (read(pipe_fd, buf, wasted) == -1)
        {
            printf("Read from pipe error");
            exit(1);
        }
    }
    return wasted;
}


void printRegularReport(int num_of_clients, int fillness, float proc, int flow)
{
    printTime();
    fprintf(stderr, "number of connected clients: %d\n", num_of_clients);
    fprintf(stderr, "filling warehouse space: %dB -> %.2f%%\n", fillness, proc);
    fprintf(stderr, "material flow: %d\n\n", flow);
}


void printDisconnectReport(int wasted, int k)
{
    printTime();
    fprintf(stderr,"disconnection with the client %s (port %d)\n", client[k].ip, client[k].port);
    fprintf(stderr, "number of wasted bytes: %d\n\n", wasted);
}


void setPassiveMode(int serv_sock_fd)
{
    if( listen(serv_sock_fd,POLL_SIZE) == -1 )
    {
        printf("listen error");
        close(serv_sock_fd);
        exit(1);
    }
}


void setNonblockAndReuseable(int serv_sock_fd)
{
    int on = 1;
    if (setsockopt(serv_sock_fd, SOL_SOCKET,  SO_REUSEADDR, (char *)&on, sizeof(on)) < 0)
    {
        printf("setsockopt() failed");
        close(serv_sock_fd);
        exit(-1);
    }

    if (ioctl(serv_sock_fd, FIONBIO, (char *)&on) < 0)
    {
        printf("ioctl() failed");
        close(serv_sock_fd);
        exit(-1);
    }
}


short createSocket()
{
    short sockfd = socket(AF_INET,SOCK_STREAM,0);
    if( sockfd == -1 )
    {
        printf("create socket error");
        exit(1);
    }
    return sockfd;
}


void registration( int sockfd, char * host)
{
    struct sockaddr_in A;
    A.sin_family = AF_INET;
    if(checkBytesOrder())
        A.sin_port = htons(port);
    else
        A.sin_port = port;

    int res = inet_aton(host,&A.sin_addr);
    if( !res )
    {
        printf("invalid address: %s\n", host);
        exit(1);
    }

    if( bind(sockfd,(struct sockaddr *)&A,sizeof(A)) )
    {
        printf("registration error");
        exit(1);
    }
}


int connection(int sockfd, int nfds)
{
    struct sockaddr_in peer;
    socklen_t addr_len = sizeof(peer);

    int new_socket = accept(sockfd,(struct sockaddr *)&peer,&addr_len);
    if( new_socket == -1 )
    {
        if (errno != EWOULDBLOCK)
        {
            printf("accept failed");
            exit(1);
        }
    }
    else{

        sscanf(inet_ntoa(peer.sin_addr), "%s", client[nfds-2].ip);
        client[nfds-2].port = ntohs(peer.sin_port);
    }
    return new_socket;
}


void production(int fd, struct timespec work_time)
{
    char* block = (char*)malloc(sizeof(char)*BLOCK_SIZE);
    while (1)
    {
        int max_buf = fcntl(fd, F_GETPIPE_SZ);
        int nbytes;
        ioctl(fd, FIONREAD, &nbytes);
        if(max_buf-nbytes >= BLOCK_SIZE)
        {
            block = productionBlock(block, work_time);
            if (write(fd, block, BLOCK_SIZE) == -1)
            {
                printf("Write to pipe error");
                exit(1);
            }
        }
    }
}


int initTimer()
{
    int timer_fd = timerfd_create( CLOCK_MONOTONIC, TFD_NONBLOCK);
    if( timer_fd == -1 )
    {
        printf("create timer error");
        exit(6);
    }

    struct itimerspec time;
    time.it_interval.tv_sec = 5;
    time.it_interval.tv_nsec = 0;
    time.it_value.tv_sec = 5;
    time.it_value.tv_nsec = 0;

    if(timerfd_settime( timer_fd, 0, &time, NULL) == -1)
    {
        printf("set timer error");
        exit(7);
    }
    return timer_fd;
}


struct timespec getTime(struct timespec time, int clock)
{
    if(clock_gettime(clock, &time) == -1)
    {
        printf( "clock gettime error" );
        exit( EXIT_FAILURE );
    }
    return time;
}


void printTime()
{
    struct timespec time;
    time = getTime(time, CLOCK_REALTIME);
    struct tm now_time;
    localtime_r(&time.tv_sec, &now_time);
    fprintf(stderr, "%04d.%02d.%02d. %02d:%02d:%02d\n", now_time.tm_year + 1900, now_time.tm_mon, now_time.tm_mday, now_time.tm_hour, now_time.tm_min, now_time.tm_sec);
}


void readTimer(int timer_fd)
{
    uint64_t exp;
    if (read(timer_fd, &exp, sizeof(uint64_t)) == -1)
    {
        printf("Read from timer error");
        exit(1);
    }
}

// programy powinny działać poprawnie np. dla:
// ./producent -p 1 localhost:8000
// ./konsument -c 1 -p 1 -d 0.1 localhost:8000

// server serving many clients algorithm base on:
// https://www.ibm.com/support/knowledgecenter/ssw_ibm_i_71/rzab6/poll.htm
// https://cboard.cprogramming.com/c-programming/158125-sockets-using-poll.html

// checkBytesOrder:
// https://stackoverflow.com/questions/1024951/does-my-amd-based-machine-use-little-endian-or-big-endian?fbclid=IwAR04-kUKy51rhdBQU7LTU0SRVrJmuIPgc0FytDt36HiGdieHPObYgOq3ivE

// getHost:
// https://paulschreiber.com/blog/2005/10/28/simple-gethostbyname-example/
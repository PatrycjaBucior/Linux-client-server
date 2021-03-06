#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/timerfd.h>

#define BUF_SIZE 13312
#define TIMER_SIG SIGRTMAX
#define PORTION_SIZE 1024

unsigned short port;
char* addr;

int fillness = 0;
int connected = 0;
int reserved_bytes;
int r_counter = 0;

struct Report {
    struct timespec open_conn_time;
    struct timespec close_conn_time;
    struct timespec first_portion_time;
    unsigned short my_port;
    char my_ip[16];
};

struct Report** report;

void setAddrPort(char* argv);
int createSocket();
struct sockaddr_in registration();
void connection(int sockfd, struct sockaddr_in A);
void receiveData(struct timespec work_time, float degradation_speed, int capacity);
void processData(int timer_fd, int socket_fd, struct timespec work_time, float degradation_speed, int capacity);
struct timespec diff(struct timespec start, struct timespec end);
void sleepTime(long time);
struct timespec convertTime(float speed, int k);
int checkBytesOrder(); // zwraca 1, jezeli należy dokonac konwersji
char* getHost();
void printReport();
void printTime();
void setMyAddrPort(int sockfd);
struct timespec getTime(struct timespec time, int clock);
int initTimer();
void readTimer(int timer_fd);
void validateArgs(char* argv, float consumption_speed, int capacity);


int main(int argc, char* argv[])
{
    int option;
    float consumption_speed = 0;
    float degradation_speed = 0;
    int capacity = 0;
    while ((option = getopt (argc, argv, "c:p:d:")) != -1)
    {
        switch (option)
        {
            case 'c':
            {
                capacity = strtol(optarg, NULL, 10);
                capacity *= 30 *1024;
                printf("-warehouse capacity: %d\n", capacity);
                break;
            }
            case 'p':
            {
                consumption_speed = strtof(optarg, NULL);
                consumption_speed *= 4435;
                printf("-consumption speed: %f\n", consumption_speed);
                break;
            }
            case 'd':
            {
                degradation_speed = strtof(optarg, NULL);
                degradation_speed *= 819;
                printf("-degradation speed: %f\n\n", degradation_speed);
                break;
            }
            case '?':
            {
                if(optopt == 'c' || optopt == 'p' || optopt == 'd')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                return 1;
            }
            default:
                abort ();
        }
    }

    validateArgs(argv[optind], consumption_speed, capacity);
    setAddrPort(argv[optind]);

    report = (struct Report**)malloc(sizeof(struct Report*)*1);
    *report = (struct Report*)malloc(sizeof(struct Report)*1);

    struct timespec work_time = convertTime(consumption_speed, PORTION_SIZE);
    receiveData(work_time, degradation_speed, capacity);
    return 0;
}


void validateArgs(char* argv, float consumption_speed, int capacity)
{
    if(argv == NULL)
    {
        printf("missing parameter: [<addr>:]port\n");
        exit(5);
    }

    if(consumption_speed==0)
    {
        printf("consumption speed cannot be zero\n");
        exit(8);
    }

    if(capacity==0)
    {
        printTime();
        printf("warehouse equal 0 -> no point to connect with server\n");
        exit(0);
    }
}


struct timespec convertTime(float speed, int k)
{
    struct timespec time;
    double work_time = (k/speed);
    time.tv_sec = work_time;
    time.tv_nsec = (work_time-time.tv_sec)*1000000000;
    return time;
}


void setAddrPort(char* argv)
{
    if(argv[0] > '0' && argv[0] < '9')
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

    return inet_ntoa( *( struct in_addr*)( h -> h_addr_list[0]));
}


int createSocket()
{
    int sockfd = socket(AF_INET,SOCK_STREAM,0);
    if( sockfd == -1 )
    {
        printf("create socket error");
        exit(1);
    }
    return sockfd;
}


struct sockaddr_in registration()
{
    struct sockaddr_in A;
    A.sin_family = AF_INET;
    if(checkBytesOrder())
        A.sin_port = htons(port);
    else
        A.sin_port = port;

    const char * Host = getHost();//"127.0.0.1";
    int res = inet_aton(Host,&A.sin_addr);
    if( !res )
    {
        printf("invalid address: %s\n",Host);
        exit(1);
    }
    return A;
}


void connection(int sockfd, struct sockaddr_in A)
{
    int attempt = 11;
    while( --attempt )
    {
        if( connect(sockfd,(struct sockaddr *)&A,sizeof(A)) != -1 )
            break;
    }
    if( ! attempt )
    {
        printf("accept connection failed\n");
        exit(2);
    }
    printf("connection to server %s (port %d) established\n", inet_ntoa(A.sin_addr),ntohs(A.sin_port));
    connected = 1;
    report[0][r_counter].open_conn_time = getTime(report[0][r_counter].open_conn_time, CLOCK_MONOTONIC);
    *report = (struct Report*)realloc(*report, (((r_counter+1)+2)*sizeof(struct Report)));

    if(reserved_bytes<=0)
        reserved_bytes = BUF_SIZE;
}


void receiveData(struct timespec work_time, float degradation_speed, int capacity)
{
    int socket_fd = 0;
    atexit(printReport);
    int timer_fd = initTimer();

    while(1)
    {
        if(!connected)
        {
            socket_fd = createSocket();
            //printf("file descriptor: %d\n", socket_fd);
            struct sockaddr_in A = registration();
            connection(socket_fd, A);
            setMyAddrPort(socket_fd);
        }
        processData(timer_fd, socket_fd, work_time, degradation_speed, capacity);
    }
}


void processData(int timer_fd, int socket_fd, struct timespec work_time, float degradation_speed, int capacity)
{
    static int counter = 0;
    struct timespec time1, time2;
    int nfds = 2;
    struct pollfd poll_set[2];
    poll_set[0].fd = socket_fd;
    poll_set[0].events = POLLIN;
    poll_set[0].revents = 0;
    poll_set[1].fd = timer_fd;
    poll_set[1].events = POLLIN;
    poll_set[1].revents = 0;

    char buf[BUF_SIZE];
    while(1) {
        poll(poll_set, nfds, -1);
        if(poll_set[1].revents == POLLIN)
        {
            readTimer(timer_fd);
            if(fillness-degradation_speed>0)
                fillness -= degradation_speed;
            //printf("timer -> fillness: %d, degradation speed: %f\n", fillness, degradation_speed);
        }
        if(poll_set[0].revents == POLLIN)
        {
            time1 = getTime(time1, CLOCK_REALTIME);
            if (read(socket_fd, buf, PORTION_SIZE) > 0)
            {
                reserved_bytes -= strlen(buf);
                fillness += strlen(buf);
                printf("filing warehouse space: %d bytes\n", fillness);
                if(counter==0)
                {
                    report[0][r_counter].first_portion_time = getTime(report[0][r_counter].first_portion_time, CLOCK_MONOTONIC);
                }
                time2 = getTime(time2, CLOCK_REALTIME);
                struct timespec elapsed_time = diff(time1,time2);
                if( work_time.tv_sec > elapsed_time.tv_sec || work_time.tv_nsec > elapsed_time.tv_nsec )
                {
                    work_time.tv_sec = work_time.tv_sec - elapsed_time.tv_sec;
                    work_time.tv_nsec = work_time.tv_nsec - elapsed_time.tv_nsec;
                    nanosleep(&work_time,NULL);
                }
                counter++;

                if(counter >= 13)
                {
                    if (shutdown(socket_fd, SHUT_RDWR)) {
                        perror("shutdown");
                        exit(2);
                    }
                    close(socket_fd);
                    connected = 0;
                    counter = 0;
                    report[0][r_counter].close_conn_time = getTime(report[0][r_counter].close_conn_time, CLOCK_MONOTONIC);
                    r_counter++;
                    printf("whole block received -> connection closure\n");
                    //printf("obecnie bajtow w magazynie: %d, pojemnosc: %d, roznica %d\n", fillness, capacity, capacity-fillness);
                    if (capacity - fillness < BUF_SIZE)
                    {
                        //printReport();
                        exit(0);
                    }
                }
                break;
            }
        }
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


struct timespec getTime(struct timespec time, int clock)
{
    if(clock_gettime(clock, &time) == -1)
    {
        printf( "clock gettime error" );
        exit( EXIT_FAILURE );
    }
    return time;
}


void printReport()
{
    printTime();
    for(int i=0; i<r_counter; i++)
    {
        fprintf(stderr, "PID: %d, ", getpid());
        fprintf(stderr, "IP address: %s, port: %d\n", report[0][i].my_ip, report[0][i].my_port);
        struct timespec conn_delay = diff(report[0][i].open_conn_time, report[0][i].first_portion_time);
        fprintf(stderr, "connection to first portion delay: %lds %ldns\n", conn_delay.tv_sec, conn_delay.tv_nsec);
        struct timespec disconn_delay = diff(report[0][i].first_portion_time, report[0][i].close_conn_time);
        fprintf(stderr, "first portion to closing connection delay: %lds %ldns\n", disconn_delay.tv_sec, disconn_delay.tv_nsec);
    }
}

void printTime()
{
    struct timespec time;
    time = getTime(time, CLOCK_REALTIME);
    struct tm now_time;
    localtime_r(&time.tv_sec, &now_time);
    fprintf(stderr, "\n=========================================================================");
    fprintf(stderr, "\n%04d.%02d.%02d. %02d:%02d:%02d\n", now_time.tm_year + 1900, now_time.tm_mon, now_time.tm_mday, now_time.tm_hour, now_time.tm_min, now_time.tm_sec);
}


void setMyAddrPort(int sockfd)
{
    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    unsigned int len = sizeof(my_addr);
    getsockname(sockfd, (struct sockaddr *) &my_addr, &len);
    inet_ntop(AF_INET, &my_addr.sin_addr, report[0][r_counter].my_ip, 16*sizeof(char));
    report[0][r_counter].my_port = ntohs(my_addr.sin_port);
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
    time.it_interval.tv_sec = 1;
    time.it_interval.tv_nsec = 0;
    time.it_value.tv_sec = 1;
    time.it_value.tv_nsec = 0;

    if(timerfd_settime( timer_fd, 0, &time, NULL) == -1)
    {
        printf("set timer error");
        exit(7);
    }
    return timer_fd;
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


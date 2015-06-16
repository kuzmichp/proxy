/* header.h */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <stdbool.h>

#define ERR(source) (perror(source),\
		     fprintf(stderr,"%s:%d\n",__FILE__,__LINE__),\
		     exit(EXIT_FAILURE))

#define HERR(source) (fprintf(stderr,"%s(%d) at %s:%d\n",source,h_errno,__FILE__,__LINE__),\
		     exit(EXIT_FAILURE))

#define BACKLOG 3
#define MAX_IN_DATA_LENGTH 65535
#define MAX_LOGIN_LENGTH 64
#define MAX_SERV_NAME_LENGTH 64
#define MAX_INT_DIGITS_NUM 32
#define DELIMITERS_NUM 4

#define MAX_LOG_REC_LENGTH 64
#define MAX_IN_DATA_LENGTH 65535

#define MAX_RESP_SIZE 128

typedef struct 
{
    char name[64];
    char host[64];
    int port;
} service;

typedef struct
{
    char login[64];
    int active;
    char tariff_plan[64];
    double bandwidth;
    double amount;
} client;

typedef struct
{
    int opt;
    char service[64];
    char host[64];
    int port;
} cs_request;

typedef struct
{
    service **services;
    client **clients;
    int *services_num;
    int *clients_num;
    int *sock;
    pthread_mutex_t *serv_mutex;
    pthread_mutex_t *cl_mutex;
    char *msg;
    ssize_t msg_size;
} thread_arg;

typedef struct
{
    char type;
    char data_size[32];
    char login[64];
    char serv_name[64];
    char data[65535];
} cl_msg;

typedef struct 
{
    char login[MAX_LOGIN_LENGTH];
    char service[MAX_SERV_NAME_LENGTH];
} conn_data;

ssize_t bulk_write(int fd, char *buf, size_t count)
{
    int c;
    size_t len = 0;

    do
    {
        c = TEMP_FAILURE_RETRY(write(fd, buf, count));
        if(c < 0)
            return c;
        buf += c;
        len += c;
        count -= c;
    }
    while (count > 0);

    return len;
}

ssize_t bulk_read(int fd, char *buf, size_t count)
{
	int c;
	size_t len = 0;

	do
	{
		c = TEMP_FAILURE_RETRY(read(fd, buf, count));
		if (c < 0)
			return c;
		if (c == 0)
			return len;
		buf += c;
		len += c;
		count -= c;
	}
	while (count > 0);

	return len;
}

int make_socket(void)
{
    int sock;

    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) { ERR("socket"); }

    return sock;
}

struct sockaddr_in make_address(char *address, uint16_t port)
{
    struct sockaddr_in addr;
    struct hostent *hostinfo;

    addr.sin_family = AF_INET;
    addr.sin_port = htons (port);

    hostinfo = gethostbyname(address);
    if (hostinfo == NULL) { ERR("gethostbyname"); }
    addr.sin_addr = *(struct in_addr*) hostinfo->h_addr;

    return addr;
}

int add_new_client(int sfd)
{
	int nfd;
	if ((nfd = TEMP_FAILURE_RETRY(accept(sfd, NULL, NULL))) < 0)
	{
		if (EAGAIN == errno || EWOULDBLOCK == errno)
			return -1;
		ERR("accept");
	}

	return nfd;
}

int connect_socket(char *name, uint16_t port)
{
    struct sockaddr_in addr;
    int socketfd;
    socketfd = make_socket();
    addr = make_address(name,port);
    if(connect(socketfd,(struct sockaddr*) &addr,sizeof(struct sockaddr_in)) < 0){
        if(errno!=EINTR) ERR("connect");
        else {
            fd_set wfds ;
            int status;
            socklen_t size = sizeof(int);
            FD_ZERO(&wfds);
            FD_SET(socketfd, &wfds);
            if(TEMP_FAILURE_RETRY(select(socketfd+1,NULL,&wfds,NULL,NULL))<0) ERR("select");
            if(getsockopt(socketfd,SOL_SOCKET,SO_ERROR,&status,&size)<0) ERR("getsockopt");
            if(0!=status) ERR("connect");
        }
    }
    return socketfd;
}

int bind_tcp_socket(uint16_t port)
{
	struct sockaddr_in addr;
	int socketfd, t=1;

	socketfd = make_socket();
	memset(&addr, 0x00, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(t)))
		ERR("setsockopt");
	if (bind(socketfd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		ERR("bind");
	if (listen(socketfd, BACKLOG) < 0)
		ERR("listen");

	return socketfd;
}

int sethandler(void (*f)(int), int sigNo)
{
    struct sigaction act;
    memset(&act, 0x00, sizeof(struct sigaction));
    act.sa_handler = f;

    if (-1 == sigaction(sigNo, &act, NULL)) { ERR("sigaction"); }

    return 0;
}

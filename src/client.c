/* client.c */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <signal.h>
#include <netdb.h>
#include <time.h>
#include <arpa/inet.h>

#define ERR(source) (perror(source),\
		     fprintf(stderr,"%s:%d\n",__FILE__,__LINE__),\
		     exit(EXIT_FAILURE))

#define MAX_MSG_SIZE 64
#define BACKLOG 3
#define MAX_IN_DATA_LENGTH 1500

volatile sig_atomic_t do_work = 1;

struct sockaddr_in make_address(char *name, uint16_t port);

int sethandler(void (*f)(int), int sigNo);

int connect_socket(char *name, uint16_t port);

int make_socket(void);

int bind_tcp_socket(uint16_t port);

int add_new_client(int sfd);

ssize_t bulk_read(int fd, char *buf, size_t count);

ssize_t bulk_write(int fd, char *buf, size_t count);

void sigint_handler(int sig)
{
    do_work = 0;
}

void usage(char *name)
{
    fprintf(stderr, "USAGE: %s login domain port service port\n",name);
    exit(EXIT_FAILURE);
}

void get_in_data(int in_sock, int out_sock, char *in_data, int *in_size)
{

    int i;

    int app_sock;

    fd_set base_rfds, rfds;
    sigset_t mask, old_mask;

    FD_ZERO(&base_rfds);
    FD_SET(in_sock, &base_rfds);

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigprocmask(SIG_BLOCK, &mask, &old_mask);

    while (do_work)
    {
        rfds = base_rfds;
		app_sock = -1;

        if (pselect(in_sock + 1, &rfds, NULL, NULL, NULL, &old_mask) > 0)
        {
			if (FD_ISSET(in_sock, &rfds))
			{
				app_sock = add_new_client(in_sock);
     	    	if (app_sock >= 0)
                {
                    /*
                     * Getting data from application
                     */
                    if ((*in_size = TEMP_FAILURE_RETRY(recv(app_sock, in_data, MAX_IN_DATA_LENGTH, 0))) == -1) { ERR("read"); }
                	//if ((*in_size = bulk_read(app_sock, in_data, MAX_IN_DATA_LENGTH)) < 0) { ERR("read"); }

                    /*
                     * Sending data to proxy server
                     * Broken PIPE is treated as critical error here
                     */
                    if (bulk_write(out_sock, in_data, *in_size) < 0) { ERR("write"); }

					if (TEMP_FAILURE_RETRY(close(app_sock))<0) { ERR("close"); }
				}
            }
        }
        else
        {
            if (EINTR == errno)
                continue;
            ERR("pselect");
        }
    }

    sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

int main(int argc, char *argv[])
{
    /* app -> client <-> server proxy <-> service */

    /*
     * in_sock will be bind to localhost and listen to incoming connections from application
     * out_sock will be used to establish connection between client and proxy server
     */
    int in_sock, out_sock;
    int flags;

    /*
     * Packet content will be kept in in_data
     */
    char *in_data;
    int in_size;



    //int i;

    char *msg = (char *) malloc(MAX_MSG_SIZE * sizeof(char));
    if (msg == NULL) { ERR("malloc"); }

    /*
     * 0. program name
     * 1. login
     * 2. proxy server address
     * 3. proxy server port
     * 4. service name
     * 5. port
     */
    if (argc != 6) { usage(argv[0]); }

    /*
     * Setting sig handlers
     */
    if (sethandler(SIG_IGN, SIGPIPE)) { ERR("Setting SIGPIPE:"); }
	if (sethandler(sigint_handler, SIGINT)) { ERR("Setting SIGINT"); }

    /*
    * Establish connection with proxy server
    */
    out_sock = connect_socket(argv[2], atoi(argv[3]));

    /*
     * Listening to incoming connection (from application)
     */
    in_sock = bind_tcp_socket(atoi(argv[5]));
    flags = fcntl(in_sock, F_GETFL) | O_NONBLOCK;
    if (fcntl(in_sock, F_SETFL, flags) == -1) { ERR("fcntl:"); }

    /*
     * Main client function
     */
    in_data = (char *) calloc(MAX_IN_DATA_LENGTH, sizeof(char));
    get_in_data(in_sock, out_sock, in_data, &in_size);
    if (TEMP_FAILURE_RETRY(close(in_sock)) < 0) { ERR("close:"); }








    if (sprintf(msg, "0 GET / HTTP/1.1\r\n\r\n") < 0) { ERR("sprintf"); }

    if (bulk_write(out_sock, msg, MAX_MSG_SIZE) < 0) { ERR("write"); }

    free(msg);
    /* Broken PIPE is treated as critical error here */

    if (TEMP_FAILURE_RETRY(close(out_sock)) < 0) { ERR("close:"); }

    return EXIT_SUCCESS;
}

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
		fprintf(stderr, "%d", c);
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

int connect_socket(char *name, uint16_t port){
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

int make_socket(void)
{
    int sock;
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        ERR("socket");

    return sock;
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

int sethandler(void (*f)(int), int sigNo) {
    struct sigaction act;
    memset(&act, 0x00, sizeof(struct sigaction));
    act.sa_handler = f;

    if (-1 == sigaction(sigNo, &act, NULL))
        ERR("sigaction");

    return 0;
}

struct sockaddr_in make_address(char *address, uint16_t port){
    struct sockaddr_in addr;
    struct hostent *hostinfo;
    addr.sin_family = AF_INET;
    addr.sin_port = htons (port);
    //addr.sin_port = htons (80);
    hostinfo = gethostbyname(address);

    //hostinfo = gethostbyname("google.com");

    if(hostinfo == NULL)ERR("gethostbyname");
    addr.sin_addr = *(struct in_addr*) hostinfo->h_addr;
    return addr;
}


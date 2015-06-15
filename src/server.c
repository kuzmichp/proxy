/* server.c */

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
#include <pthread.h>
#include <stdbool.h>

#define ERR(source) (perror(source),\
		     fprintf(stderr,"%s:%d\n",__FILE__,__LINE__),\
		     exit(EXIT_FAILURE))

#define BACKLOG 3

#define SERVICES_NUM 2
#define CLIENTS_NUM 2

#define NAME_MAX_LENGTH 10
#define HOST_MAX_LENGTH 16

#define LOGIN_MAX_LENGTH 15
#define TPLAN_MAX_LENGTH 10

#define RES_LENGTH 2
#define IN_DATA_LENGTH 1024
#define IN_DATA_LENGTH 1024

#define MAX_LOG_REC_LENGTH 64
#define MAX_MSG_SIZE 64

#define MAX_IN_DATA_LENGTH 65535

typedef struct {
    char name[32];
    char host[32];
    int port;
} service;

typedef struct {
    char login[32];
    int active;
    char tariff_plan[32];
    double bandwidth;
    double amount;
} client;

/* Change services array request */
typedef struct {
    int opt;
    char service[32];
    char host[32];
    int port;

} cs_request;

typedef struct {
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

volatile sig_atomic_t do_work = 1;

int sethandler(void (*f)(int), int sigNo);

int bind_tcp_socket(uint16_t port);

int make_socket(void);

void manage_connections(service **services, client **clients, int *services_num, int *clients_num, int in_socket, int log_fd, pthread_mutex_t *serv_mutex, pthread_mutex_t *cl_mutex);

void usage(char *name);

void siginthandler(int sig);

int add_new_client(int socket);

void communicate(service **services, client **clients, int *services_num, int *clients_num, int client_sock, pthread_mutex_t *serv_mutex);

ssize_t bulk_read(int fd, char *buf, size_t count);

void manage_client_connection(char *msg, ssize_t size, service **services, client **clients, int *services_num,
                              int *clients_num, pthread_mutex_t *serv_mutex, pthread_mutex_t *cl_mutex);

void *client_thread_func(void *arg);

struct sockaddr_in make_address(char *address, uint16_t port)
{
    struct sockaddr_in addr;
    struct hostent *hostinfo;

    addr.sin_family = AF_INET;
    addr.sin_port = htons (port);

    hostinfo = gethostbyname(address);
    if(hostinfo == NULL) { ERR("gethostbyname"); }
    addr.sin_addr = *(struct in_addr*) hostinfo->h_addr;

    return addr;
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

int main(int argc, char *argv[])
{
    /*
     * in_sock will be used to communicate with clients
     * out_sock will be used to communicate with services
     */
    int in_sock;
    //int out_sock;
    int flags;

    /*
     * Log file descriptor
     */
    int log_fd;

    /*
     * Collections for storing informations about services and clients
     */
    service *services;
    client *clients;

    int services_num = 0, clients_num = 0;

    /*
     * Mutexes prove synchronization during operations on services and clients collections
     */
    pthread_mutex_t services_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

    /*
     * 0. ./server
     * 1. port
     */
    if (argc != 2) { usage(argv[0]); }

    /*
     * Creating a log file
     */
    if ((log_fd = TEMP_FAILURE_RETRY(open("./log.txt", O_CREAT | O_RDWR | O_APPEND, S_IRWXU | S_IRWXG | S_IRWXO))) == -1) { ERR("open"); }

    /*
     * Allocate memory for services and clients collections
     */
    services = (service *) malloc(services_num * sizeof(service));
    if (services == NULL) { ERR("malloc"); }

    clients = (client *) malloc(clients_num * sizeof(client));
    if (clients == NULL) { ERR("malloc"); }

    /*
     * Setting sig handlers
     */
    sethandler(SIG_IGN, SIGPIPE);
    sethandler(siginthandler, SIGINT);

    /*
     * Bind socket and start listening to incoming connection (from client)
     */
    in_sock = bind_tcp_socket(atoi(argv[1]));
    flags = fcntl(in_sock, F_GETFL) | O_NONBLOCK;
    if (fcntl(in_sock, F_SETFL, flags) == -1) { ERR("fcntl"); }

    manage_connections(&services, &clients, &services_num, &clients_num, in_sock, log_fd, &services_mutex, &clients_mutex);

    if (TEMP_FAILURE_RETRY(close(log_fd)) < 0) { ERR("close"); }
    if (TEMP_FAILURE_RETRY(close(in_sock)) < 0) { ERR("close"); }

    free(services);
    free(clients);

    //TODO: Destroy mutexes

    return EXIT_SUCCESS;
}

void communicate(service **services, client **clients, int *services_num, int *clients_num, int client_sock, pthread_mutex_t *serv_mutex) {

    int i;
    int g_sock;
    struct sockaddr_in addr;
    char resp[1536];
    ssize_t resp_size;


    struct hostent *hostinfo;

    int pos;
    char *msg = (char *) malloc(MAX_IN_DATA_LENGTH);
    ssize_t size;


    //char serv_req[64];
    //int opt;

    /* Read message */
    fprintf(stderr, "Before reading data\n");
    if ((size = bulk_read(client_sock, msg, MAX_IN_DATA_LENGTH)) < 0) { ERR("read"); }

    fprintf(stderr, "Data was read!\n");

    if ((msg = realloc(msg, size)) == NULL) { ERR("realloc"); }

	fprintf(stderr, "Packet size: %li\n", size);
	
	fprintf(stderr, "Packet content:\n");

	for (i = 0; i < size; ++i)
	{
		fprintf(stderr, "%c", msg[i]);
	} 

    fprintf(stderr, "\n");

    /* Parse message */
    cs_request *request = (cs_request *) malloc(sizeof(cs_request));
    if (request == NULL) { ERR("malloc"); }

    /* Manage messages */
    switch (atoi(&msg[0]))
    {
        case 1:
            fprintf(stderr, "\nAdd service request\n");
            if (sscanf(msg, "%d %s %s %d", &(request->opt), request->service, request->host, &(request->port)) < 0) { ERR("fscanf"); }

            /* Add new service */
	    pthread_mutex_lock(serv_mutex);
            (*services_num)++;


            fprintf(stderr, "Services number: %d\n", *services_num);

            pos = *services_num;
            if ((*services = realloc(*services, (*services_num) * sizeof(service))) == NULL) { ERR("realloc"); }

	    service serv;

            if (memcpy(&(serv.name), request->service, sizeof(request->service)) == NULL) { ERR("memcpy"); }
            if (memcpy(&(serv.host), request->host, sizeof(request->host)) == NULL) { ERR("memcpy"); }
            serv.port = request->port;

            (*services)[pos - 1] = serv;
	    pthread_mutex_unlock(serv_mutex);

            //if (memcpy((*services)[pos - 1]->name, request->service, sizeof(request->service)) == NULL) { ERR("memcpy"); }
            //if (memcpy((*services)[pos - 1]->host, request->host, sizeof(request->host)) == NULL) { ERR("memcpy"); }
            //(*services)[pos - 1]->port = request->port;

            /*for (i = 0; i < *services_num; ++i) {
                fprintf(stderr, "SERVICE NAME: %s - HOST: %s - PORT: %d\n", services[i]->name, services[i]->host, services[i]->port);
            }*/



            free(msg);
            //fprintf(stderr, "Request: %d %s %s %d", request->opt, request->service, request->host, request->port);

            break;
        case 0:
            fprintf(stderr, "\nClient request\n");

            /* Connect to google.com */
            if ((g_sock = socket(PF_INET, SOCK_STREAM, 0)) == -1) { ERR("socket"); }

            addr.sin_family = AF_INET;
            addr.sin_port = htons(80);
            hostinfo = gethostbyname("google.com");
            if(hostinfo == NULL)ERR("gethostbyname");
            addr.sin_addr = *(struct in_addr*) hostinfo->h_addr;

            if (connect(g_sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {ERR("connect"); }

            if (send(g_sock, "GET / HTTP/1.1\r\n\r\n", MAX_MSG_SIZE, 0) < 0) { ERR("send"); }
            if ((resp_size = recv(g_sock, resp, 1536, 0)) < 0) { ERR("recv"); }

            fprintf(stderr, "Google resp: %s\n", resp);
            fprintf(stderr, "Resp size: %li\n", resp_size);

            //TODO: Perform operations on the client account

            break;
    }

    free(request);

    if(TEMP_FAILURE_RETRY(close(client_sock))<0)ERR("close");
}

ssize_t bulk_read(int fd, char *buf, size_t count) {
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

void *client_thread_func(void *arg)
{
    int fd, j;

    thread_arg *targ = (thread_arg *) arg;

    char login[32];
    char *serv;
    char *data_size;
    char data[65535];
    char msg_type;

    int i;
    int del_num = 0;
    int del_pos[4];
    
    int serv_name_length;

    char resp[65535];
    ssize_t resp_size;
    
    char host[64];
    char port[64];

    int sock;

    int serv_ex = 1;
	
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL) != 0) { ERR("pthread_mask"); }

    for (i = 0; i < targ->msg_size; ++i)
    {
        if (targ->msg[i] == ' ' && del_num < 4)
        {
            del_pos[del_num++] = i;
        }
    }

    data_size = (char *) calloc(del_pos[1] - del_pos[0] - 1, sizeof(char));

	if ((serv = (char *) malloc(32 * sizeof(char))) == NULL) { ERR("malloc"); }

	serv_name_length = del_pos[3] - del_pos[2] - 1;


    memcpy(&msg_type, targ->msg, sizeof(char));
    memcpy(data_size, targ->msg + del_pos[0] + 1, (del_pos[1] - del_pos[0] - 1) * sizeof(char));
    memcpy(login, targ->msg + del_pos[1] + 1, (del_pos[2] - del_pos[1] - 1) * sizeof(char));
    memcpy(serv, targ->msg + del_pos[2] + 1, (del_pos[3] - del_pos[2] - 1) * sizeof(char));
    memcpy(data, targ->msg + del_pos[3] + 1, atoi(data_size));
    
    if ((serv = realloc(serv, serv_name_length * sizeof(char))) == NULL) { ERR("realloc"); }
    
    for	(i = 0; i < *(targ->services_num); i++)
    {
    	if (strncmp((*(targ->services)[i]).name, serv, serv_name_length) == 0) { serv_ex = 0; }
    }
   
	sock = *(targ->sock);
    
    if (serv_ex == 1)
	{
		if (bulk_write(sock, "Service doesn't exist", strlen("Service doesn't exist")) < 0) { ERR("write"); }
		if (pthread_sigmask(SIG_UNBLOCK, &mask, NULL) != 0) { ERR("pthread_sigmask"); }

		free(targ);
		return NULL;
	}
	
    /*if (atoi(&msg[0]) == 0)
{
    manage_client_connection(msg, size, services, clients, services_num, clients_num, serv_mutex, cl_mutex);
}
else
{
    //manage_admin_connection(msg, size, services, clients, services_num, clients_num, serv_mutex, cl_mutex);
}*/

    
    fprintf(stderr, "(int) Data: \n");
    
    for	(i = 0; i < atoi(data_size); i++)
    {
    	fprintf(stderr, "%d", (int) data[i]);
    }
    
    fprintf(stderr, "\nData: %s\n", data);

    fd = connect_socket("google.com", 80);

    fprintf(stderr, "\nConnected to service\n");

    //char d[200] = "GET http://google.com/ HTTP/1.1\r\n\r\n";

    if (bulk_write(fd, data, atoi(data_size)) < 0) { ERR("write"); }
    if ((resp_size = TEMP_FAILURE_RETRY(recv(fd, resp, 65535 * sizeof(char), 0))) == -1) { ERR("recv"); }

    //if (bulk_write(fd, data, atoi(data_size)) < 0) { ERR("send"); }
    //if ((resp_size = TEMP_FAILURE_RETRY(recv(fd, resp, 65535 * sizeof(char), 0))) == -1) { ERR("recv"); }

    //if (TEMP_FAILURE_RETRY(send(fd, d, strlen(d), 0)) == -1) { ERR("send"); }
    //if ((resp_size = TEMP_FAILURE_RETRY(recv(fd, resp, 65535 * sizeof(char), 0))) == -1) { ERR("recv"); }

    //fprintf(stderr, "\nGoogle response size: %li\n", resp_size);

    //for (j = 0; j < resp_size; ++j) {
    //    fprintf(stderr, "%c", resp[j]);
    //}



    /*for (int k = 0; k < strlen(d); ++k) {
        fprintf(stderr, "%c", d[k]);
    }*/

    if (bulk_write(sock, resp, resp_size) < 0) { ERR("write"); }

    if (TEMP_FAILURE_RETRY(close(sock)) == -1) { ERR("close"); }

    fprintf(stderr, "\nSent data\n");

    //if (TEMP_FAILURE_RETRY(send(sock, data, atoi(data_size), 0)) == -1) { ERR("send"); }
    //if (bulk_write(targ->sock, data, atoi(data_size)) < 0) { ERR("write"); }

    if (pthread_sigmask(SIG_UNBLOCK, &mask, NULL) != 0) { ERR("pthread_sigmask"); }

    free(targ);
    return NULL;
}

void manage_connections(service **services, client **clients, int *services_num, int *clients_num, int in_socket, int log_fd, pthread_mutex_t *serv_mutex, pthread_mutex_t *cl_mutex)
{
    int i;

    int client_sock;

    fd_set base_rfds, rfds;
    sigset_t mask, old_mask;


    time_t curr_time;
    int log_rec_size;

    char *msg = (char *) malloc(MAX_IN_DATA_LENGTH);
    ssize_t size;

    FD_ZERO(&base_rfds);
    FD_SET(in_socket, &base_rfds);

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigprocmask(SIG_BLOCK, &mask, &old_mask);

    pthread_t thread;
    thread_arg *targ;
    
    /*
     * Zmienne używane do pobrania aktualnego czasu i dodania wpisu do logfile'a 
     */
    time_t rawtime;
    struct tm *info;
    char log_rec[MAX_LOG_REC_LENGTH];
    
    /*
     * Zmienna używana jest to przechowywania informacji o tym, kto się połączył do serwera proxy 
     */
    bool cl = false;   

    while (do_work)
    {
        rfds = base_rfds;

        if (pselect(in_socket + 1, &rfds, NULL, NULL, NULL, &old_mask) > 0)
        {
            client_sock = add_new_client(in_socket);

            if (client_sock >= 0)
            {
                /*
                 * Odbieranie wiadomości od aplikacji klienckiej 
                 */
                if ((size = TEMP_FAILURE_RETRY(recv(client_sock, msg, MAX_IN_DATA_LENGTH, 0))) == -1) { ERR("read"); }
                if ((msg = realloc(msg, size)) == NULL) { ERR("realloc"); }

				/*
				 * Sprawdzanie typu wiadomości 
				 */
				if (atoi(&msg[0]) == 0) { cl = true; }

				/*
				 * Pobieranie aktualnego czasu 
				 */
				if (time(&rawtime) == (time_t)-1) { ERR("time"); }
				if ((info = localtime(&rawtime)) == NULL) { ERR("localtime"); }
				if (asctime(info) == NULL) { ERR("asctime"); }
				
				/*
				 * Dodawanie wpisu do logfile'a
				 */
				if ((log_rec_size = snprintf(log_rec, MAX_LOG_REC_LENGTH, "%s%s has been connected\n", asctime(info), cl == true ? "client" : "admin")) < 0) { ERR("snprintf"); }
				if (TEMP_FAILURE_RETRY(write(log_fd, log_rec, log_rec_size)) == -1) { ERR("write"); }


                if ((targ = (thread_arg *) calloc(1, sizeof(thread_arg))) == NULL) { ERR("calloc"); }

                /*
                 * Prepare thread_arg structure
                 */
                targ->services = services;
                targ->clients = clients;
                targ->services_num = services_num;
                targ->clients_num = clients_num;
                targ->serv_mutex = serv_mutex;
                targ->cl_mutex = cl_mutex;
                targ->sock = &client_sock;
                targ->msg = msg;
                targ->msg_size = size;

                //fprintf(stderr, "Client sock_fd: %d\n", client_sock);

                /*
                 * Run thread executing
                 */
                if (pthread_create(&thread, NULL, client_thread_func, (void *) targ) != 0) { ERR("pthread_create"); }
                if (pthread_detach(thread) != 0) { ERR("pthread_detach"); }

                //if (TEMP_FAILURE_RETRY(close(client_sock)) == -1) { ERR("close"); }

                /*switch (atoi(&msg[0]))
                {
                    case 0:
                        fprintf(stderr, "\nClient\n");
                        //Manage client connection
                        break;
                    case 1:
                        //Manage admin connection (add new service)
                        break;
                    case 2:
                        //Manage admin connection (remove service)
                        break;
                    case 3:
                        //Manage admin connection (add new client)
                        break;
                    case 4:
                        //Manage admin connection (remove client)
                        break;
                    case 5:
                        //Manage admin connection (get counters for all clients)
                        break;
                    case 6:
                        break;
                    case 7:
                        break;
                    case 8:
                        //Manage admin connection (block user)
                        break;
                    case 9:
                        //Manage admin connection (unblock user)
                        break;
                }*/
                //if ((size = bulk_read(client_sock, msg, MAX_IN_DATA_LENGTH)) < 0) { ERR("read"); }

                //communicate(services, clients, services_num, clients_num, client_sock, serv_mutex);
            }
        }
        else
        {
            if (EINTR == errno) continue;
            ERR("pselect");
        }
    }

    sigprocmask(SIG_UNBLOCK, &mask, NULL);
}

void manage_client_connection(char *msg, ssize_t size, service **services, client **clients, int *services_num,
                              int *clients_num, pthread_mutex_t *serv_mutex, pthread_mutex_t *cl_mutex)
{


}

int add_new_client(int socket) {
    int nfd;
    if ((nfd = TEMP_FAILURE_RETRY(accept(socket, NULL, NULL))) < 0)
    {
        if (EAGAIN == errno || EWOULDBLOCK == errno)
            return -1;
        ERR("accept");
    }
    fprintf(stderr, "Client %d accepted\n", socket);

    return nfd;
}

int bind_tcp_socket(uint16_t port) {
    struct sockaddr_in addr;
    int socketfd, t = 1;

    socketfd = make_socket();
    memset(&addr, 0x00, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(t))) { ERR("setsockopt"); }
    if (bind(socketfd, (struct sockaddr *) &addr, sizeof(addr)) < 0) { ERR("bind"); }
    if (listen(socketfd, BACKLOG) < 0) { ERR("listen"); }

    return socketfd;
}

int make_socket(void) {
    int sock;
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        ERR("socket");

    return sock;
}

int sethandler(void (*f)(int), int sigNo) {
    struct sigaction act;
    memset(&act, 0x00, sizeof(struct sigaction));
    act.sa_handler = f;

    if (-1 == sigaction(sigNo, &act, NULL))
        ERR("sigaction");

    return 0;
}

void siginthandler(int sig) {
    do_work = 0;
}

void usage(char *name) {
    fprintf(stderr, "USAGE: %s port\n", name);
	exit(EXIT_FAILURE);
}

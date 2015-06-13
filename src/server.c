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

#define MAX_IN_DATA_LENGTH 1500

typedef struct {
    char name[32];
    char host[32];
    int port;
} service;

typedef struct {
    char *login;
    int active;
    char *tariff_plan;
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

volatile sig_atomic_t do_work = 1;

pthread_mutex_t services_mutex;

int sethandler(void (*f)(int), int sigNo);

int bind_tcp_socket(uint16_t port);

int make_socket(void);

void manage_connections(service **services, client **clients, int *services_num, int *clients_num, int socket, int log_fd, pthread_mutex_t *serv_mutex);

void usage(char *name);

void siginthandler(int sig);

int add_new_client(int socket);

void communicate(service **services, client **clients, int *services_num, int *clients_num, int client_sock, pthread_mutex_t *serv_mutex);

ssize_t bulk_read(int fd, char *buf, size_t count);

int main(int argc, char *argv[]) {
    int j;
    int log_fd;
    int socket, new_flags;
    int services_num = 0, clients_num = 0;
    pthread_mutex_t serv_mutex = PTHREAD_MUTEX_INITIALIZER;
    //pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER;

    if (argc != 2) {
        usage(argv[0]);
    }

    if ((log_fd = TEMP_FAILURE_RETRY(open("./.log", O_CREAT | O_WRONLY | O_APPEND))) == -1) { ERR("open"); }

    /* Allocate memory for services and clients */
    service *services = (service *) malloc(services_num * sizeof(service));
    if (services == NULL) { ERR("malloc"); }

    client *clients = (client *) malloc(clients_num * sizeof(client));
    if (clients == NULL) { ERR("malloc"); }

    /*for (i = 0; i < SERVICES_NUM; ++i)
    {
        services[i].name = (char *) calloc(NAME_MAX_LENGTH, sizeof(char));
        if (services[i].name == NULL) { ERR("calloc"); }
        services[i].host = (char *) calloc(HOST_MAX_LENGTH, sizeof(char));
        if (services[i].host == NULL) { ERR("calloc"); }
    }*/

    /* Initialize services */
    /*for (i = 0; i < SERVICES_NUM; ++i)
    {
        int size = sprintf(services[i].name, "%s%d", "service", i);
        if (size < 0) { ERR("sprintf"); }
        services[i].port = i;
    }*/

    /* Initialize clients */
    /*for (i = 0; i < CLIENTS_NUM; ++i)
    {
        clients[i].login = (char *) calloc(LOGIN_MAX_LENGTH, sizeof(char));
        if (clients[i].login == NULL) { ERR("calloc"); }
        clients[i].tariff_plan = (char *) calloc(TPLAN_MAX_LENGTH, sizeof(char));
        if (clients[i].tariff_plan == NULL) { ERR("calloc"); }
    }*/

    /*for (i = 0; i < CLIENTS_NUM; ++i)
    {
        int size = sprintf(clients[i].login, "%s%d", "client", i);
        if (size < 0) { ERR("sprintf"); }
        size = sprintf(clients[i].tariff_plan, "%s", i%2 == 0 ? "abonament" : "prepaid");
        if (size < 0) { ERR("sprintf"); }
        clients[i].active = 0;
    }*/

    /*for (i = 0; i < SERVICES_NUM; ++i)
    {
        fprintf(stderr, "%s - %d\n", services[i].name, services[i].port);
    }

    for (i = 0; i < CLIENTS_NUM; ++i)
    {
        fprintf(stderr, "%s - %d - %s\n", clients[i].login, clients[i].active, clients[i].tariff_plan);
    }*/

    /* Signals handlers */
    sethandler(SIG_IGN, SIGPIPE);
    sethandler(siginthandler, SIGINT);

    /* Create socket */
    socket = bind_tcp_socket(atoi(argv[1]));
    new_flags = fcntl(socket, F_GETFL) | O_NONBLOCK;
    if (fcntl(socket, F_SETFL, new_flags) == -1) { ERR("fcntl"); }

    manage_connections(&services, &clients, &services_num, &clients_num, socket, log_fd, &serv_mutex);

    if (TEMP_FAILURE_RETRY(close(log_fd)) < 0) { ERR("close"); }
    if (TEMP_FAILURE_RETRY(close(socket)) < 0) { ERR("close"); }

    fprintf(stderr, "\nSERVICES:\n");

    for (j = 0; j < services_num; ++j) {
        fprintf(stderr, "NAME: %s - HOST: %s - PORT: %d\n", services[j].name, services[j].host, services[j].port);
    }

    fprintf(stderr, "Server terminated\n");

    //free(services);
    //free(clients);

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

void manage_connections(service **services, client **clients, int *services_num, int *clients_num, int socket, int log_fd, pthread_mutex_t *serv_mutex) {
    int client_sock;
    fd_set base_rfds, rfds;
    sigset_t mask, oldmask;
    char log_rec[MAX_LOG_REC_LENGTH];
    time_t curr_time;
    int log_rec_size;

    char *msg = (char *) malloc(MAX_IN_DATA_LENGTH);
    ssize_t size;
    int i;

    FD_ZERO(&base_rfds);
    FD_SET(socket, &base_rfds);
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigprocmask(SIG_BLOCK, &mask, &oldmask);

    while (do_work) {
        rfds = base_rfds;
        if (pselect(socket + 1, &rfds, NULL, NULL, NULL, &oldmask) > 0) {
            client_sock = add_new_client(socket);
            if (client_sock >= 0) {
                if ((curr_time = time(NULL)) == (time_t)(1)) { ERR("time"); }
                if ((log_rec_size = snprintf(log_rec, MAX_LOG_REC_LENGTH, "[%ld] - Client %d was accepted\n", curr_time, client_sock)) < 0) { ERR("fprintf"); }
                //TODO: Add information about new accepted connection to log file
                if (TEMP_FAILURE_RETRY(write(log_fd, log_rec, log_rec_size)) == -1) { ERR("write"); }

                //TODO: Create new pthread for managing connection
                fprintf(stderr, "Before reading data\n");
                if ((size = TEMP_FAILURE_RETRY(recv(client_sock, msg, MAX_IN_DATA_LENGTH, 0))) == -1) { ERR("read"); }
                //if ((size = bulk_read(client_sock, msg, MAX_IN_DATA_LENGTH)) < 0) { ERR("read"); }

                fprintf(stderr, "Data was read!\n");
                fprintf(stderr, "Packet size: %li\n", size);
                if ((msg = realloc(msg, size)) == NULL) { ERR("realloc"); }
                fprintf(stderr, "Packet content:\n");

                for (i = 0; i < size; ++i)
                {
                    fprintf(stderr, "%c", msg[i]);
                }

                fprintf(stderr, "\n");
                fprintf(stderr, "Before communicate func invoking\n");
                //communicate(services, clients, services_num, clients_num, client_sock, serv_mutex);
            }
        } else {
            if (EINTR == errno) continue;
            ERR("pselect");
        }
    }

    sigprocmask(SIG_UNBLOCK, &mask, NULL);
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

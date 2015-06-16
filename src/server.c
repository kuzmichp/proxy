/* server.c */

#include "header.h"

volatile sig_atomic_t do_work = 1;

void siginthandler(int sig)
{
    do_work = 0;
}

void usage(char *name)
{
    fprintf(stderr, "USAGE: %s port\n", name);
    exit(EXIT_FAILURE);
}

void *client_thread_func(void *arg)
{
    fprintf(stderr, "Cos przyszlo od klienta\n");

    int fd;

    thread_arg *targ = (thread_arg *) arg;

    int i;
    int del_num = 0;
    int del_pos[4];

    char resp[65535];
    ssize_t resp_size;

    int sock;

    //int serv_ex = 1;

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL) != 0) { ERR("pthread_mask"); }

    /*
     * Parsowanie wiadomosci od klienta
     */
    cl_msg client_msg;

    if (sscanf(targ->msg, "%c %s %s %s %s", &client_msg.type, client_msg.data_size, client_msg.login, client_msg.serv_name, client_msg.data) != 5) { ERR("sscanf"); }

    /*
     * Sprawdzanie pozycji separatorow
     */
    for (i = 0; i < targ->msg_size; ++i)
    {
        if (targ->msg[i] == ' ' && del_num < 4)
        {
            del_pos[del_num++] = i;
        }
    }

    memset(client_msg.data, 0, strlen(client_msg.data));
    memcpy(client_msg.data, targ->msg + del_pos[3] + 1, atoi(client_msg.data_size));

    /*for	(i = 0; i < *(targ->services_num); i++)
    {
        if (strncmp((*(targ->services)[i]).name, client_msg.serv_name, strlen(client_msg.serv_name)) == 0) { serv_ex = 0; }
    }*/

    sock = *(targ->sock);

    /*if (serv_ex == false)
	{
		if (bulk_write(sock, "Service doesn't exist", strlen("Service doesn't exist")) < 0) { ERR("write"); }
		if (pthread_sigmask(SIG_UNBLOCK, &mask, NULL) != 0) { ERR("pthread_sigmask"); }

		free(targ);
		return NULL;
	}*/

    fd = connect_socket("stackoverflow.com", 80);

    if (bulk_write(fd, client_msg.data, atoi(client_msg.data_size)) < 0) { ERR("write"); }
    if ((resp_size = TEMP_FAILURE_RETRY(recv(fd, resp, 65535 * sizeof(char), 0))) == -1) { ERR("recv"); }

    if (bulk_write(sock, resp, resp_size) < 0) { ERR("write"); }

    if (pthread_sigmask(SIG_UNBLOCK, &mask, NULL) != 0) { ERR("pthread_sigmask"); }

    if (TEMP_FAILURE_RETRY(close(fd)) == -1) { ERR("close"); }
    if (TEMP_FAILURE_RETRY(close(sock)) == -1) { ERR("close"); }

    free(targ);
    return NULL;
}

void *admin_thread_func(void *arg)
{
    thread_arg *targ = (thread_arg *) arg;

    service **services = targ->services;
    //client **clients = targ->clients;

    int *serv_num = targ->services_num;
    //int *cl_num = targ->clients_num;

    pthread_mutex_t *s_mutex = targ->serv_mutex;
    //pthread_mutex_t *cl_mutex = targ->cl_mutex;

    char *msg = targ->msg;

    char msg_type = (targ->msg)[0];

    /*
     * Zmienne do parsowania wiadomosci
     */
    service serv;
    char name[64];
    char host[64];
    int port;
    //client cl;

    /* Dodawanie nowego serwisu */
    if (msg_type == '1')
    {
        //if (sscanf(msg, "%s %s %s %d", &msg_type, serv.name, serv.host, &(serv.port)) != 4) { ERR("sscanf"); }
        if (sscanf(msg, "%s %s %s %d", &msg_type, name, host, &port) != 4) { ERR("sscanf"); }

        pthread_mutex_lock(s_mutex);

        (*serv_num) += 1;
        if ((*services = realloc(*services, (*serv_num) * sizeof(service))) == NULL) { ERR("realloc"); }

        memcpy(&(serv.name), name, strlen(name));
        memcpy(&(serv.host), host, strlen(host));
        serv.port = port;

        (*services)[(*serv_num) - 1] = serv;

        pthread_mutex_unlock(s_mutex);

        fprintf(stderr, "Dodano nowy serwis: %s %s %d\n", serv.name, serv.host, serv.port);
    }
    /* Usuwanie serwisu */
    else if (msg_type == '2')
    {

    }
    /* Dodawanie klienta */
    else if (msg_type == '3')
    {

    }
    /* Usuwanie klienta */
    else if (msg_type == '4')
    {

    }
    /* Pobieranie wartosci licznikow */
    else if (msg_type == '5')
    {

    }
    /* Blokowanie uzytkownika */
    else if (msg_type == '6')
    {

    }
    /* Odblokowanie uzytkownika */
    else if (msg_type == '7')
    {

    }
    else {}

    free(targ);
    return NULL;
}

void manage_connections(service **services, client **clients, int *services_num, int *clients_num, int in_socket, int log_fd, pthread_mutex_t *serv_mutex, pthread_mutex_t *cl_mutex)
{
    int client_sock;

    fd_set base_rfds, rfds;
    sigset_t mask, old_mask;

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

    /*
     * Informacja o nawiazanym polaczeniu jest przechowywana w tablicy log_rec
     */
    char log_rec[MAX_LOG_REC_LENGTH];
    int log_rec_size;

    /*
     * Zmienna używana jest to przechowywania informacji o tym, kto się połączył do serwera proxy
     */
    int cl = 1;

    while (do_work)
    {
        rfds = base_rfds;

        if (pselect(in_socket + 1, &rfds, NULL, NULL, NULL, &old_mask) > 0)
        {
            if (FD_ISSET(in_socket, &rfds))
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
                    if (atoi(&msg[0]) == 0) { cl = 0; }

                    /*
                     * Pobieranie aktualnego czasu
                     */
                    if (time(&rawtime) == (time_t)-1) { ERR("time"); }
                    if ((info = localtime(&rawtime)) == NULL) { ERR("localtime"); }
                    if (asctime(info) == NULL) { ERR("asctime"); }

                    /*
                     * Dodawanie wpisu do logfile'a
                     */
                    if ((log_rec_size = snprintf(log_rec, MAX_LOG_REC_LENGTH, "%s%s has been connected\n", asctime(info), cl == 0 ? "client" : "admin")) < 0) { ERR("snprintf"); }
                    if (TEMP_FAILURE_RETRY(write(log_fd, log_rec, log_rec_size)) == -1) { ERR("write"); }

                    if ((targ = (thread_arg *) calloc(1, sizeof(thread_arg))) == NULL) { ERR("calloc"); }

                    /*
                     * Przygotowanie structury thread_arg
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

                    /*
                     * Uruchomienie watku
                     */
                    if (cl == 0)
                    {
                        if (pthread_create(&thread, NULL, client_thread_func, (void *) targ) != 0) { ERR("pthread_create"); }
                    }
                    else
                    {
                        if (pthread_create(&thread, NULL, admin_thread_func, (void *) targ) != 0) { ERR("pthread_create"); }
                    }

                    if (pthread_detach(thread) != 0) { ERR("pthread_detach"); }
                }
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

int main(int argc, char *argv[])
{
    int i;

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

    for (i = 0; i < strlen(services[0].name) + 1; ++i) {
        fprintf(stderr, "%d", (int) (services[0].name)[i]);
    }

    fprintf(stderr, "\nSerwisy:\n");
    for (i = 0; i < services_num; ++i)
    {
        fprintf(stderr, "%s %s %d", services[i].name, services[i].host, services[i].port);
        fprintf(stderr, "\n");
    }

    //TODO: Destroy mutexes

    return EXIT_SUCCESS;
}
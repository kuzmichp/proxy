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

/*
 * Funkcja do sprawdzania, czy istnieje serwis o wskazanej nazwie
 */
int check_service(char name[], service **services, int *serv_num, char **addr, int *port)
{
    int i;

    for (i = 0; i < *serv_num; ++i)
    {
        if (strncmp((*services)[i].name, name, strlen(name)) == 0)
        {
            if ((*addr = realloc(*addr, sizeof(char) * strlen((*services)[i].host))) == NULL) { ERR("realloc"); }
            memcpy(*addr, (*services)[i].host, strlen((*services)[i].host));

            *port = (*services[i]).port;

            return 0;
        }
    }

    return 1;
}

/*
 * Funkcja sluzy do zmiany liczby przeslanych bytow przez klienta
 */
/*void change_sent_data_size(client **clients, int *cl_num, char login[], int transfer)
{
    int i;

    for (i = 0; i < *cl_num; ++i)
    {
        if (strncmp((*clients)[i].login, login, strlen(login)) == 0)
        {
            (*clients)[i].bytes_num = 0;
            (*clients)[i].bytes_num += transfer;
        }
    }
}*/

void *client_thread_func(void *arg)
{
    int fd;

    thread_arg *targ = (thread_arg *) arg;

    int i;
    int del_num = 0;
    int del_pos[4];

    char resp[MAX_IN_DATA_LENGTH];
    ssize_t resp_size;

    char *addr;
    int port;

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL) != 0) { ERR("pthread_mask"); }

    /*
     * Parsowanie wiadomosci od klienta
     */
    cl_msg client_msg;

    /*
     * Istnienie uslugi
     */
    int res;

    /*
     * Transfer
     */
    //int transfer = 0;

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

    /*
     * Sprawdzanie, czy rzadany serwis istnieje
     */
    if ((addr = (char *) malloc(sizeof(char))) == NULL) { ERR("malloc"); }
    pthread_mutex_lock(targ->serv_mutex);
    res = check_service(client_msg.serv_name, targ->services, targ->services_num, &addr, &port);
    pthread_mutex_unlock(targ->serv_mutex);

    if (res == 1)
    {
        if (bulk_write(*(targ->sock), "Serwis o wskazanej nazwie nie istnieje", strlen("Serwis o wskazanej nazwie nie istnieje")) < 0) { ERR("write"); }
        if (pthread_sigmask(SIG_UNBLOCK, &mask, NULL) != 0) { ERR("pthread_sigmask"); }

        if (TEMP_FAILURE_RETRY(close(*(targ->sock))) == -1) { ERR("close"); }

        free(addr);
        free(targ);
        return NULL;
    }

    if (bulk_write(*(targ->sock), "Znaleziono serwis o wskazanej nazwie", strlen("Znaleziono serwis o wskazanej nazwie")) < 0) { ERR("write"); }

    fd = connect_socket(addr, port);

    if (bulk_write(fd, client_msg.data, atoi(client_msg.data_size)) < 0) { ERR("write"); }
    //transfer = atoi(client_msg.data_size);

    if ((resp_size = TEMP_FAILURE_RETRY(recv(fd, resp, MAX_IN_DATA_LENGTH * sizeof(char), 0))) == -1) { ERR("recv"); }
    //transfer += resp_size;

    //pthread_mutex_lock(targ->cl_mutex);
    //change_sent_data_size(targ->clients, targ->clients_num, client_msg.login, transfer);
    //pthread_mutex_unlock(targ->cl_mutex);

    if (bulk_write(*(targ->sock), resp, resp_size) < 0) { ERR("write"); }

    if (pthread_sigmask(SIG_UNBLOCK, &mask, NULL) != 0) { ERR("pthread_sigmask"); }

    if (TEMP_FAILURE_RETRY(close(fd)) == -1) { ERR("close"); }
    if (TEMP_FAILURE_RETRY(close(*(targ->sock))) == -1) { ERR("close"); }

    free(targ);
    free(addr);
    return NULL;
}

void *admin_thread_func(void *arg)
{
    //int i;

    thread_arg *targ = (thread_arg *) arg;

    service **services = targ->services;
    client **clients = targ->clients;

    int *serv_num = targ->services_num;
    int *cl_num = targ->clients_num;

    pthread_mutex_t *s_mutex = targ->serv_mutex;
    pthread_mutex_t *cl_mutex = targ->cl_mutex;

    char *msg = targ->msg;

    char msg_type = (targ->msg)[0];

    /*
     * Zmienne do parsowania wiadomosci
     */
    service serv;
    client cl;

    char s_name[MAX_SERV_NAME_LENGTH];
    char s_host[MAX_HOST_LENGTH];
    char s_port[MAX_PORT_SIZE];

    char cl_login[MAX_LOGIN_LENGTH];
    char plan[MAX_TARIFF_PLAN_LENGTH];

    /*
     * Odpowiedz do admina
     */
    char *resp;
    int resp_size;

    /*
     * Dodawanie nowego serwisu
     */
    if (msg_type == '1')
    {
        if (sscanf(msg, "%c %s %s %s", &msg_type, s_name, s_host, s_port) != 4) { ERR("sscanf"); }

        pthread_mutex_lock(s_mutex);

        (*serv_num) += 1;
        if ((*services = realloc(*services, (*serv_num) * sizeof(service))) == NULL) { ERR("realloc"); }

        memcpy(&(serv.name), s_name, strlen(s_name) + 1);
        (serv.name)[strlen(s_name)] = '\0';
        memcpy(&(serv.host), s_host, strlen(s_host) + 1);
        (serv.host)[strlen(s_host)] = '\0';
        serv.port = atoi(s_port);

        (*services)[(*serv_num) - 1] = serv;

        pthread_mutex_unlock(s_mutex);

        if ((resp = (char *) malloc(MAX_RESP_SIZE * sizeof(char))) == NULL) { ERR("malloc"); }
        if ((resp_size = sprintf(resp, "Dodano nowa usluge: %s %s", serv.name, serv.host)) < 0) { ERR("sprintf"); };
        fprintf(stderr, "Dodano nowa usluge: %s\n", serv.name);

        if (bulk_write(*(targ->sock), resp, resp_size) < 0) { ERR("write"); }
    }
    /* Usuwanie serwisu */
    else if (msg_type == '2')
    {

    }
    /* Dodawanie klienta */
    else if (msg_type == '3')
    {
        if (sscanf(msg, "%c %s %d %s %lf %lf", &msg_type, cl_login, &(cl.active), plan, &(cl.bandwidth), &(cl.amount)) != 6) { ERR("sscanf"); }

        pthread_mutex_lock(cl_mutex);

        (*cl_num) += 1;

        if ((*clients = realloc(*clients, (*cl_num) * sizeof(client))) == NULL) { ERR("realloc"); }

        memcpy(&(cl.login), cl_login, strlen(cl_login) + 1);
        (cl.login)[strlen(cl_login)] = '\0';
        memcpy(&(cl.tariff_plan), plan, strlen(plan) + 1);
        (cl.tariff_plan)[strlen(plan)] = '\0';

        (*clients)[(*cl_num) - 1] = cl;

        pthread_mutex_unlock(cl_mutex);

        if ((resp = (char *) malloc(MAX_RESP_SIZE * sizeof(char))) == NULL) { ERR("malloc"); }
        if ((resp_size = sprintf(resp, "Dodano nowego klienta: %s %d %s %f %f", cl.login, cl.active, cl.tariff_plan, cl.bandwidth, cl.amount)) < 0) { ERR("sprintf"); };
        fprintf(stderr, "Dodano nowego klienta: %s\n", cl.login);

        if (bulk_write(*(targ->sock), resp, resp_size) < 0) { ERR("write"); }
    }
    /* Usuwanie klienta */
    else if (msg_type == '4')
    {

    }
    /* Pobieranie wartosci licznikow */
    else if (msg_type == '5')
    {
        /*for (i = 0; i < *(targ->clients_num); ++i)
        {
            fprintf(stderr, "Licznik: %d\n", (*clients)[i].bytes_num);

            if ((resp = (char *) malloc(MAX_RESP_SIZE * sizeof(char))) == NULL) { ERR("malloc"); }
            if ((resp_size = sprintf(resp, "%s - %d", (*clients)[i].login, (*clients)[i].bytes_num)) < 0) { ERR("sprintf"); };

            if (bulk_write(*(targ->sock), resp, resp_size) < 0) { ERR("write"); }
        }*/
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

    if (TEMP_FAILURE_RETRY(close(*(targ->sock))) == -1) { ERR("close"); }

    free(targ);
    return NULL;
}

void manage_connections(service **services, client **clients, int *services_num, int *clients_num, int in_socket, int log_fd, pthread_mutex_t *serv_mutex, pthread_mutex_t *cl_mutex)
{
    int client_sock;

    fd_set base_rfds, rfds;
    sigset_t mask, old_mask;

    char *msg;
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
    int cl;

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
                     * Informacja o tym, kto nawiazuje polaczenie
                     */
                    cl = 1;

                    /*
                     * Odbieranie wiadomości od aplikacji klienckiej
                     */
                    if ((msg = (char *) malloc(MAX_IN_DATA_LENGTH)) == NULL) { ERR("malloc"); }
                    if ((size = TEMP_FAILURE_RETRY(recv(client_sock, msg, MAX_IN_DATA_LENGTH, 0))) == -1) { ERR("read"); }

                    if ((msg = realloc(msg, size)) == NULL) { ERR("realloc"); }

                    /*
                     * Sprawdzanie typu wiadomości
                     */
                    if (atoi(&msg[0]) == 0) { cl = 0; }

                    fprintf(stderr, "\nOdebrano wiadomosc od %s: %s\n", cl == 0 ? "klienta" : "admina", msg);

                    /*
                     * Pobieranie aktualnego czasu
                     */
                    if (time(&rawtime) == (time_t)-1) { ERR("time"); }
                    if ((info = localtime(&rawtime)) == NULL) { ERR("localtime"); }
                    if (asctime(info) == NULL) { ERR("asctime"); }

                    /*
                     * Dodawanie wpisu do logfile'a
                     */
                    if ((log_rec_size = snprintf(log_rec, MAX_LOG_REC_LENGTH, "%s Polaczono z %s\n", asctime(info), cl == 0 ? "klientem" : "adminem")) < 0) { ERR("snprintf"); }
                    if (TEMP_FAILURE_RETRY(write(log_fd, log_rec, log_rec_size)) == -1) { ERR("write"); }
                    fprintf(stderr, "Dodano wpis do logfile'a\n");

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
    /*
     * in_sock jest uzywany do komunikacji z klientami
     */
    int in_sock;
    int flags;

    /*
     * Log file descriptor
     */
    int log_fd;

    /*
     * Kolekcje do przechowywania uslug i klientow
     */
    service *services;
    client *clients;

    int services_num = 0, clients_num = 0;

    pthread_mutex_t services_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

    /*
     * 0. ./server
     * 1. port
     */
    if (argc != 2) { usage(argv[0]); }

    if ((log_fd = TEMP_FAILURE_RETRY(open("./log.txt", O_CREAT | O_RDWR | O_APPEND, S_IRWXU | S_IRWXG | S_IRWXO))) == -1) { ERR("open"); }

    services = (service *) malloc(services_num * sizeof(service));
    if (services == NULL) { ERR("malloc"); }

    clients = (client *) malloc(clients_num * sizeof(client));
    if (clients == NULL) { ERR("malloc"); }

    sethandler(SIG_IGN, SIGPIPE);
    sethandler(siginthandler, SIGINT);

    /*
     * Nasluchiwanie na polaczenia od klientow
     */
    in_sock = bind_tcp_socket(atoi(argv[1]));
    flags = fcntl(in_sock, F_GETFL) | O_NONBLOCK;
    if (fcntl(in_sock, F_SETFL, flags) == -1) { ERR("fcntl"); }

    manage_connections(&services, &clients, &services_num, &clients_num, in_sock, log_fd, &services_mutex, &clients_mutex);

    if (TEMP_FAILURE_RETRY(close(log_fd)) < 0) { ERR("close"); }
    if (TEMP_FAILURE_RETRY(close(in_sock)) < 0) { ERR("close"); }

    free(services);
    free(clients);

    return EXIT_SUCCESS;
}
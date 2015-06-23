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

void wait_for_activation(client *cl)
{
	if (pthread_mutex_lock(&(*cl).act_mutex) != 0) { ERR("pthread_mutex_lock"); }	
	
	while (1)
	{
		if ((*cl).active == 1)
		{
			if (pthread_cond_wait(&(*cl).act_cond, &(*cl).act_mutex) != 0) { ERR("pthread_cond_wait"); }
		}
		else
			break;
	}
		
	if (pthread_mutex_unlock(&(*cl).act_mutex) != 0) { ERR("pthread_mutex_unlock"); }	
}

void *client_thread_func(void *arg)
{
    thread_arg *targ = (thread_arg *) arg;
    
	int fd, del_num = 0, i, res, desc = *(targ->sock);
    int del_pos[4];

    char resp[MAX_PCKT_SIZE];
    ssize_t resp_size;

	// dane uslugi
    char *addr;
    int port;

    cl_msg client_msg;
	client **clients = targ->clients;
	int *cl_num = targ->clients_num;
	client *cl;

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);

    if (pthread_sigmask(SIG_BLOCK, &mask, NULL) != 0) { ERR("pthread_mask"); }


    if (sscanf(targ->msg, "%c %s %s %s %s", &client_msg.type, client_msg.data_size, client_msg.login, client_msg.serv_name, client_msg.data) != 5) { ERR("sscanf"); }

	// wyciaganie pakietu
    for (i = 0; i < targ->msg_size; ++i)
        if (targ->msg[i] == ' ' && del_num < 4)
            del_pos[del_num++] = i;

    memset(client_msg.data, 0, strlen(client_msg.data));
    memcpy(client_msg.data, targ->msg + del_pos[3] + 1, atoi(client_msg.data_size));

    // sprawdzanie, czy rzadany serwis istnieje
    if ((addr = (char *) malloc(sizeof(char))) == NULL) { ERR("malloc"); }
    if (pthread_mutex_lock(targ->serv_mutex) != 0 ) { ERR("pthread_mutex_lock"); }
    res = check_service(client_msg.serv_name, targ->services, targ->services_num, &addr, &port);
    if (pthread_mutex_unlock(targ->serv_mutex) != 0) { ERR("pthread_mutex_unlock"); }

    if (res == 1)
    {
        if (pthread_sigmask(SIG_UNBLOCK, &mask, NULL) != 0) { ERR("pthread_sigmask"); }
        if (TEMP_FAILURE_RETRY(close(*(targ->sock))) == -1) { ERR("close"); }

        free(addr);
        free(targ);
        return NULL;
    }

	for (i = 0; i < *cl_num; i++)
	{
		cl = &(*clients)[i];
		if (strncmp((*cl).login, client_msg.login, strlen(client_msg.login)) == 0)
		{
			break;
		}
		cl = NULL;
	}

	if (cl == NULL)
	{
        if (pthread_sigmask(SIG_UNBLOCK, &mask, NULL) != 0) { ERR("pthread_sigmask"); }
        if (TEMP_FAILURE_RETRY(close(*(targ->sock))) == -1) { ERR("close"); }

        free(addr);
        free(targ);
        return NULL;
	}

    fd = connect_socket(addr, port);

	wait_for_activation(cl);

    // komunikacja z usluga i wysylanie danych do klienta
    if (bulk_write(fd, client_msg.data, atoi(client_msg.data_size)) < 0) { ERR("write"); }
    if ((resp_size = TEMP_FAILURE_RETRY(recv(fd, resp, MAX_PCKT_SIZE * sizeof(char), 0))) == -1) { ERR("recv"); }
    if (bulk_write(desc, resp, resp_size) < 0) { ERR("write"); }

    if (pthread_sigmask(SIG_UNBLOCK, &mask, NULL) != 0) { ERR("pthread_sigmask"); }

    if (TEMP_FAILURE_RETRY(close(fd)) == -1) { ERR("close"); }
    if (TEMP_FAILURE_RETRY(close(*(targ->sock))) == -1) { ERR("close"); }

    free(targ);
    free(addr);
    return NULL;
}

void add_new_service(thread_arg *targ)
{
    service **services = targ->services;
    int *serv_num = targ->services_num;
    pthread_mutex_t *s_mutex = targ->serv_mutex;
    char *msg = targ->msg;
        
	char msg_type;
	service serv;

	if (sscanf(msg, "%c %s %s %d", &msg_type, serv.name, serv.host, &(serv.port)) != 4) { ERR("sscanf"); }

    pthread_mutex_lock(s_mutex);

	if ((*services = realloc(*services, (++(*serv_num))*sizeof(service))) == NULL) { ERR("realloc"); }
	(*services)[(*serv_num) - 1] = serv;

    pthread_mutex_unlock(s_mutex);
}

void add_client(thread_arg *targ)
{
	client **clients = targ->clients;
	int *cl_num = targ->clients_num;
	pthread_mutex_t *cl_mutex = targ->cl_mutex;
	char *msg = targ->msg;

	char msg_type;
	client cl;
        
	if (sscanf(msg, "%c %s %d %s %lf %lf", &msg_type, cl.login, &(cl.active), cl.tariff_plan, &(cl.bandwidth), &(cl.amount)) != 6) { ERR("sscanf"); }
	
	cl.act_mutex = (pthread_mutex_t)PTHREAD_MUTEX_INITIALIZER;
	cl.act_cond = (pthread_cond_t)PTHREAD_COND_INITIALIZER;

    pthread_mutex_lock(cl_mutex);

	if ((*clients = realloc(*clients, (++(*cl_num))*sizeof(client))) == NULL) { ERR("realloc"); }
    (*clients)[(*cl_num) - 1] = cl;

    pthread_mutex_unlock(cl_mutex);
}

void block_client(thread_arg *targ, int opt)
{
	int i;

	client **clients = targ->clients;
	int *cl_num = targ->clients_num;
	//pthread_mutex_t *cl_mutex = targ->cl_mutex;
	char *msg = targ->msg;

	char msg_type;

	char login[MAX_LOGIN_LENGTH];
	if (sscanf(msg, "%c %s", &msg_type, login) != 2) { ERR("sscanf"); }

	for (i = 0; i < *cl_num; i++)
	{
		if (strncmp((*clients)[i].login, login, 5) == 0)
		{
			pthread_mutex_lock(&((*clients)[i].act_mutex));
			(*clients)[i].active = opt;
			pthread_mutex_unlock(&((*clients)[i].act_mutex));

			pthread_mutex_lock(&((*clients)[i].act_mutex));
			pthread_cond_broadcast(&((*clients)[i].act_cond));
			pthread_mutex_unlock(&((*clients)[i].act_mutex));
			
			break;	
		}
	}
}

void *admin_thread_func(void *arg)
{
    thread_arg *targ = (thread_arg *)arg;
    char msg_type = (targ->msg)[0];

	// dodawanie nowej uslugi
    if (msg_type == '1')
    {
		add_new_service(targ);
    }
    // usuwanie uslugi
    else if (msg_type == '2')
    {

    }
    // dodawanie klienta
    else if (msg_type == '3')
    {
		add_client(targ);
    }
    // usuwanie klienta
    else if (msg_type == '4')
    {
    }
    // pobieranie wartosci licznikow
    else if (msg_type == '5')
    {
    }
    // blokowanie uzytkownika
    else if (msg_type == '6')
    {
		block_client(targ, 1);
    }
    // odblokowanie uzytkownika
    else if (msg_type == '7')
    {
		block_client(targ, 0);
    }
    else {}

	if (TEMP_FAILURE_RETRY(close(*(targ->sock))) == -1) { ERR("close"); }

	free(targ);
	return NULL;
}

void prepare_pthread_args(thread_arg **targ, service **services, client **clients, int *services_num, int *clients_num, pthread_mutex_t *serv_mutex, pthread_mutex_t *cl_mutex, int *sock, char *msg, ssize_t size)
{
	if ((*targ = (thread_arg *) calloc(1, sizeof(thread_arg))) == NULL) { ERR("calloc"); }
    
	(*targ)->services = services;
    (*targ)->clients = clients;
    (*targ)->services_num = services_num;
    (*targ)->clients_num = clients_num;
    (*targ)->serv_mutex = serv_mutex;
    (*targ)->cl_mutex = cl_mutex;
    (*targ)->sock = sock;
    (*targ)->msg = msg;
    (*targ)->msg_size = size;
}

void add_log_rec(int log_fd, int cl)
{
    char log_rec[MAX_LOG_REC_LENGTH];
    int log_rec_size;
    
	// aktualny czas
    time_t rawtime;
    struct tm *info;
	
	// pobieranie aktualnego czasu
	if (time(&rawtime) == (time_t)-1) { ERR("time"); }
    if ((info = localtime(&rawtime)) == NULL) { ERR("localtime"); }
    if (asctime(info) == NULL) { ERR("asctime"); }

	// dodawanie wpisu do logow
    if ((log_rec_size = snprintf(log_rec, MAX_LOG_REC_LENGTH + 1, "%s Polaczono z %s\n", asctime(info), cl == 0 ? "klientem" : "adminem")) < 0) { ERR("snprintf"); }
    if (TEMP_FAILURE_RETRY(write(log_fd, log_rec, log_rec_size)) == -1) { ERR("write"); }
}

void manage_connections(service **services, client **clients, int *services_num, int *clients_num, int sock, int log_fd, pthread_mutex_t *serv_mutex, pthread_mutex_t *cl_mutex)
{
	// cl ~ klient czy admin
    int client_sock, cl;

    char msg[MAX_MSG_SIZE];
    ssize_t size;

    pthread_t thread;
    thread_arg *targ;

	fd_set base_rfds, rfds;
    sigset_t mask, old_mask;

    FD_ZERO(&base_rfds);
    FD_SET(sock, &base_rfds);

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigprocmask(SIG_BLOCK, &mask, &old_mask);

    while (do_work)
    {
        rfds = base_rfds;

        if (pselect(sock + 1, &rfds, NULL, NULL, NULL, &old_mask) > 0)
        {
            if (FD_ISSET(sock, &rfds))
            {
                client_sock = add_new_client(sock);

                if (client_sock >= 0)
                {
                    cl = 1;

                    // odbieranie wiadomości od aplikacji klienckiej
                    if ((size = TEMP_FAILURE_RETRY(recv(client_sock, msg, MAX_MSG_SIZE, 0))) == -1) { ERR("recv"); }

                    if (atoi(&msg[0]) == 0) { cl = 0; }

    				add_log_rec(log_fd, cl);                
					prepare_pthread_args(&targ, services, clients, services_num, clients_num, serv_mutex, cl_mutex, &client_sock, msg, size);

                    // uruchomienie watkow
                    if (cl == 0)
                    {
                        if (pthread_create(&thread, NULL, client_thread_func, (void *)targ) != 0) { ERR("pthread_create"); }
                    }
                    else
                    {
                        if (pthread_create(&thread, NULL, admin_thread_func, (void *)targ) != 0) { ERR("pthread_create"); }
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
    int sock, flags, log_fd, i;

    // uslugi i klienci
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

	if (sethandler(SIG_IGN, SIGPIPE)) { ERR("Seting SIGPIPE"); }
	if (sethandler(siginthandler, SIGINT)) { ERR("Seting SIGINT"); }

	if ((services = (service *) calloc(1, sizeof(service))) == NULL) { ERR("calloc"); }
	if ((clients = (client *) calloc(1, sizeof(client))) == NULL) { ERR("calloc"); }

    // nasluchiwanie na polaczenia od klientow
   	sock = bind_tcp_socket(atoi(argv[1]));
    flags = fcntl(sock, F_GETFL) | O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) == -1) { ERR("fcntl"); }

    // komunikacja
	manage_connections(&services, &clients, &services_num, &clients_num, sock, log_fd, &services_mutex, &clients_mutex);

	fprintf(stderr, "Uslugi:\n");
	for (i = 0; i < services_num; i++)
	{
		fprintf(stderr, "%s %s %d\n", services[i].name, services[i].host, services[i].port);
	}
	
	fprintf(stderr, "Klienci:\n");
	for (i = 0; i < clients_num; i++)
	{
		fprintf(stderr, "%s %d %s %f %f\n", clients[i].login, clients[i].active, clients[i].tariff_plan, clients[i].bandwidth, clients[i].amount);
	}

    if (TEMP_FAILURE_RETRY(close(log_fd)) < 0) { ERR("close"); }
    if (TEMP_FAILURE_RETRY(close(sock)) < 0) { ERR("close"); }

    free(services);
    free(clients);

    return EXIT_SUCCESS;
}

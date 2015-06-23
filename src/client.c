/* client.c */

#include "header.h"

#define MAX_MSG_SIZE 65535

volatile sig_atomic_t do_work = 1;

void sigint_handler(int sig)
{
    do_work = 0;
}

void usage(char *name)
{
    fprintf(stderr, "USAGE: %s login domain port service port\n",name);
    exit(EXIT_FAILURE);
}

void prepare_message(char *msg, int *msg_size, char *login, char *service, char *packet, int pckt_size)
{
    // rozmiar pakietu jest trzymany w postaci stringa
    char num[MAX_PCKT_DIG_NUM];
    int num_length;

    char msg_type = '0';

    // konwertowanie rozmiaru pakietu na string
	if ((num_length = snprintf(num, MAX_PCKT_DIG_NUM + 1, "%d", pckt_size)) < 0) { ERR("snprintf"); }

   	/*
 	 * przygotowanie wiadomosci
     * TYPE PACKET_SIZE LOGIN SERVICE PACKET
     */
    if ((*msg_size = snprintf(msg, MAX_MSG_SIZE + 1, "%c %s %s %s %s", msg_type, num, login, service, packet)) < 0) { ERR("snprintf"); }
}

void communicate(int in_sock, char *domain, int port, char *login, char *service)
{
    int app_sock, out_sock;
	
	// dane wysylane przez aplikacje zewnetrzna
	char *packet;
	ssize_t pckt_size;

    // wiadomosc wysylana do serwera proxy
    char msg[MAX_MSG_SIZE];
    int msg_size = 0;

    // dpowiedz od serwera
    char resp[MAX_PCKT_SIZE];
    ssize_t resp_size;
    
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
                    // odbieranie danych od aplikacji zewnetrznej
					if ((packet = (char *) malloc(MAX_PCKT_SIZE*sizeof(char))) == NULL) { ERR("malloc"); }
                    if ((pckt_size = TEMP_FAILURE_RETRY(recv(app_sock, packet, MAX_PCKT_SIZE, 0))) == -1) { ERR("read"); }

                    // przygotowanie wiadomosci dla serwera proxy
                    prepare_message(msg, &msg_size, login, service, packet, pckt_size);
					
                   	// wysylanie danych do serwera proxy
                    out_sock = connect_socket(domain, port);
                    if (TEMP_FAILURE_RETRY(send(out_sock, msg, msg_size + 1, 0)) < 0) { ERR("send"); }

                    // czekanie na odpowiedz od serwera proxy
                    if ((resp_size = TEMP_FAILURE_RETRY(recv(out_sock, resp, MAX_PCKT_SIZE, MSG_WAITALL))) < 0) { ERR("read"); }

					// zwracanie odpowiedzi do aplikacji zewnetrznej
					if (TEMP_FAILURE_RETRY(send(app_sock, resp, resp_size, 0)) < 0) { ERR("send"); }

					free(packet);
					
					if (TEMP_FAILURE_RETRY(close(app_sock)) < 0) { ERR("close"); }
					if (TEMP_FAILURE_RETRY(close(out_sock)) < 0) { ERR("close"); }
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
    /* app <-> client <-> server proxy <-> service */

	// socket do komunikacji z aplikacja zewnetrzna
    int sock, flags;

    /*
     * 0. program name
     * 1. login
     * 2. proxy server address
     * 3. proxy server port
     * 4. service name
     * 5. port
     */
    if (argc != 6) { usage(argv[0]); }

    if (sethandler(SIG_IGN, SIGPIPE)) { ERR("Seting SIGPIPE"); }
	if (sethandler(sigint_handler, SIGINT)) { ERR("Seting SIGINT"); }

    // nasluchiwanie na polaczenie od aplikacji
    sock = bind_tcp_socket(atoi(argv[5]));
    flags = fcntl(sock, F_GETFL) | O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) == -1) { ERR("fcntl:"); }

    // glowna funkcja programu klienckiego
    communicate(sock, argv[2], atoi(argv[3]), argv[1], argv[4]);

    if (TEMP_FAILURE_RETRY(close(sock)) < 0) { ERR("close"); }
    return EXIT_SUCCESS;
}

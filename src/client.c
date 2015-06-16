/* client.c */

#include "header.h"

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


void prepare_message(char **msg, size_t *msg_size, conn_data cl_info, char *in_data, int in_size)
{
    /*
     * Rozmiar pakietu jest trzymany w tablicy char
     */
    char *num;
    int num_length;

    size_t login_length = strnlen(cl_info.login, MAX_LOGIN_LENGTH) + 1;
    size_t service_length = strnlen(cl_info.service, MAX_SERV_NAME_LENGTH) + 1;

    char msg_type = '0';

    /*
     * Sprawdzanie rozmiaru pakietu
     */
    num = (char *) malloc(MAX_INT_DIGITS_NUM * sizeof(char));
    if (num == NULL) { ERR("malloc"); }

    if  ((num_length = sprintf(num, "%d", in_size)) < 0) { ERR("sprintf"); }
    if ((num = realloc(num, num_length)) == NULL) { ERR("realloc"); }

    /*
     * +1 byte ze wzgledu na '\0', ktore snprintf dodaje na koncu
     */
    *msg_size = (2 + DELIMITERS_NUM + login_length + service_length + num_length + in_size) * sizeof(char);
    if ((*msg = realloc(*msg, *msg_size)) == NULL) { ERR("realloc"); }

    /*
     * TYPE SIZE_OF_DATA LOGIN SERVICE DATA
     */
    if (snprintf(*msg, *msg_size, "%c %s %s %s %s", msg_type, num, cl_info.login, cl_info.service, in_data) < 0) { ERR("snprintf"); }
}

void get_in_data(int in_sock, char *domain, int port, char *in_data, int *in_size, conn_data cl_info)
{
    int app_sock, out_sock;

    fd_set base_rfds, rfds;
    sigset_t mask, old_mask;

    FD_ZERO(&base_rfds);
    FD_SET(in_sock, &base_rfds);

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigprocmask(SIG_BLOCK, &mask, &old_mask);

    /*
     * Wiadomosc wysylana do serwera proxy
     */
    char *msg;
    size_t msg_size = 0;

    /*
     * Odpowiedz od serwera
     */
    char resp[MAX_IN_DATA_LENGTH];
    ssize_t resp_size;

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
                     * Odbieranie danych od aplikacji
                     */
                    if ((*in_size = TEMP_FAILURE_RETRY(recv(app_sock, in_data, MAX_IN_DATA_LENGTH, 0))) == -1) { ERR("read"); }

                    /*
                     * Przygotowanie wiadomosci dla serwera proxy
                     */
                    msg = (char *) malloc(sizeof(char));
                    prepare_message(&msg, &msg_size, cl_info, in_data, *in_size);

                    /*
                     * Nawiazywanie polaczenia z serwerem proxy
                     */
                    fprintf(stderr, "Domain: %s\n", domain);
                    out_sock = connect_socket(domain, port);

                    /*
                     * Wysylanie danych do serwera proxy
                     */
                    if (TEMP_FAILURE_RETRY(send(out_sock, msg, msg_size, 0)) < 0) { ERR("send"); }

                    /*
                     * Czekanie na odpowiedz od serwera proxy
                     */
                    if ((resp_size = TEMP_FAILURE_RETRY(recv(out_sock, resp, MAX_IN_DATA_LENGTH, MSG_WAITALL))) < 0) { ERR("read"); }

                    fprintf(stderr, "Response from server: %li\n", resp_size);
                    fprintf(stderr, "%s\n", resp);

					if (TEMP_FAILURE_RETRY(close(app_sock)) < 0) { ERR("close"); }
                    if (TEMP_FAILURE_RETRY(close(out_sock)) < 0) { ERR("close"); }
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
     * in_sock sluzy do komunikacji z aplikacja
     */
    int in_sock;
    int flags;

    /*
     * Zawartosc pakietu przechowywana jest w in_data
     */
    char *in_data;
    int in_size;

    /*
     * Tymczasowania struktura to trzymania loginu i nazwy serwera
     */
    conn_data cl_info;

    /*
     * 0. program name
     * 1. login
     * 2. proxy server address
     * 3. proxy server port
     * 4. service name
     * 5. port
     */
    if (argc != 6) { usage(argv[0]); }

    if (memcpy(cl_info.login, argv[1], strnlen(argv[1], MAX_LOGIN_LENGTH) + 1) == NULL) { ERR("memcpy"); };
    if (memcpy(cl_info.service, argv[4], strnlen(argv[4], MAX_SERV_NAME_LENGTH) + 1) == NULL) { ERR("memcpy"); };

    if (sethandler(SIG_IGN, SIGPIPE)) { ERR("Setting SIGPIPE:"); }
	if (sethandler(sigint_handler, SIGINT)) { ERR("Setting SIGINT"); }

    /*
     * ... z aplikacja
     */
    in_sock = bind_tcp_socket(atoi(argv[5]));
    flags = fcntl(in_sock, F_GETFL) | O_NONBLOCK;
    if (fcntl(in_sock, F_SETFL, flags) == -1) { ERR("fcntl:"); }

    in_data = (char *) calloc(MAX_IN_DATA_LENGTH, sizeof(char));

    /*
     * Glowna funkcja programu klienckiego
     */
    get_in_data(in_sock, argv[2], atoi(argv[3]), in_data, &in_size, cl_info);

    if (TEMP_FAILURE_RETRY(close(in_sock)) < 0) { ERR("close:"); }

    return EXIT_SUCCESS;
}
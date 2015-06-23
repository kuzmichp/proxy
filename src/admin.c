/* admin.c */

#include "header.h"

volatile sig_atomic_t do_work = 1;

void sigint_handler(int sig)
{
    do_work = 0;
}

void usage(char *name)
{
    fprintf(stderr, "USAGE: %s <proxy domain> <proxy port>\n", name);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    int i, sock;

    // pozycja menu 
    char menu_item;

	// wprowadzone dane
    char cmd[MAX_CMD_SIZE];

	// wiadomosc dla serwera
    char *msg;
	size_t msg_size;

    if (argc != 3) { usage(argv[0]); }

    if (sethandler(SIG_IGN, SIGPIPE)) { ERR("Seting SIGPIPE"); }
    if (sethandler(sigint_handler, SIGINT)) { ERR("Seting SIGINT"); }

    // obsluga menu
    while (do_work)
    {
        printf("\nMenu:\n"
                       "\n[1] - Dodaj nowy serwis\n"
                       "[2] - Usun istniejacy serwis\n"
                       "[3] - Dodaj nowego uzytkownika\n"
                       "[4] - Usun istniejacego uzytkownika\n"
                       "[5] - Pobierz wartosci licznikow dla uzytkownikow\n"
                       "[6] - Zablokuj uzytkownika\n"
                       "[7] - Odblokuj uzytkownika\n"
                       "[...] - Exit\n");
        printf("\nWybor: ");

        // wczytywanie pozycji menu
		if (scanf("%c", &menu_item) != 1) { ERR("scanf"); }
		while (menu_item != '\n' && getchar() != '\n');

		switch (menu_item)
		{
			case '1':
            	printf("Podaj dane serwisu, ktory chcesz dodac - <nazwa> <host> <port>: ");
				break;
			case '2':
            	printf("Podaj nazwe serwisu, ktory chcesz usunac: ");
				break;
			case '3':
            	printf("Podaj dane uzytkownika, ktorego chcesz dodac - <login> <aktywny> <plan taryfowy> <przepustowosc> <kwota>: ");
				break;
			case '4':
            	printf("Podaj login uzytkownika, ktorego chcesz usunac: ");
				break;
			case '5':
				break;
			case '6':
            	printf("Podaj login uzytkownika, ktorego chcesz zablokowac: ");
				break;
			case '7':
            	printf("Podaj login uzytkownika, ktorego chcesz odblokowac: ");
				break;
			default:
				printf("\nBledny wybor\n");			
				exit(EXIT_FAILURE);
		}

        // wczytywanie danych
        memset(cmd, 0x00, MAX_CMD_SIZE);
        if (fgets(cmd, MAX_CMD_SIZE, stdin) == NULL) { ERR("fgetc"); }

		// usuwanie znaku nowej linii
		i = strlen(cmd) - 1;
		if (cmd[i] == '\n') { cmd[i] = '\0'; }		

        // typ_wiadomosci + spacja + dane, zakonczone '\0'
        msg_size = strlen(cmd) + 2;
        if ((msg = (char *) calloc(msg_size, sizeof(char))) == NULL) { ERR("calloc"); }
        if (snprintf(msg, msg_size + 1, "%c %s", menu_item, cmd) < 0) { ERR("snprintf"); }

   		// laczenie sie z serwerem proxy
    	sock = connect_socket(argv[1], atoi(argv[2]));

        // wysylanie wiadomosci
        if (bulk_write(sock, msg, msg_size) < 0) { ERR("write"); }
        fprintf(stderr, "Wyslano wiadomosc do serwera proxy\n");

        free(msg);

    	if (TEMP_FAILURE_RETRY(close(sock)) < 0) { ERR("close"); }
    }

    return EXIT_SUCCESS;
}

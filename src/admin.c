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
    int i;
	int sock;

    // pozycja menu 
    char menu_item[2];

	// wprowadzone dane
    char cmd[MAX_CMD_SIZE + 1];

	// wiadomosc dla serwera
    char *msg;

	// odpowiedz od serwera
    char *resp;
    ssize_t resp_size;

    if (argc != 3) { usage(argv[0]); }

    if (sethandler(SIG_IGN, SIGPIPE)) { ERR("Seting SIGPIPE"); }
    if (sethandler(sigint_handler, SIGINT)) { ERR("Seting SIGINT"); }

    /* Manage user input */
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
        memset(menu_item, 0x00, 2*sizeof(char));
        if (fgets(menu_item, 2, stdin) == NULL) { ERR("fgetc"); }

		// usuwanie znaku nowej linii, jesli istnieje
		i = strlen(menu_item) - 1;
		if (menu_item[i] == '\n') { menu_item[i] = '\0'; }

		switch (menu_item[0])
		{
			case '1':
            	printf("Podaj dane serwisu, ktory chcesz dodac - [nazwa] [host] [port]: ");
				break;
			case '2':
            	printf("Podaj nazwe serwisu, ktory chcesz usunac: ");
				break;
			case '3':
            	printf("Podaj dane uzytkownika, ktorego chcesz dodac - [login] [aktywny] [plan taryfowy] [przepustowosc] [kwota]: ");
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
		memset(cmd, 0x00, MAX_CMD_SIZE + 1);
		if (fgets(cmd, MAX_CMD_SIZE + 1, stdin) == NULL) { ERR("fgets"); }
		
		i = strlen(cmd) - 1;
		if (cmd[i] == '\n') { cmd[i] = '\0'; }		

		fprintf(stderr, "Wczytane dane:\n");
		for (i = 0; i < strlen(cmd) + 1; i++)
		{
			fprintf(stderr, "%d", (int)cmd[i]);
		}

        // laczenie sie z serwerem proxy
        sock = connect_socket(argv[1], atoi(argv[2]));

        /*
         * Alokacja pamieci na wiadomosc (TYP_WIADOMOSCI DANE)
         * 3 = TYP + SPACJA + BYTE ZEROWY
         */
        if ((msg = (char *) malloc((strlen(cmd) + 3) * sizeof(char))) == NULL) { ERR("malloc"); }

        /*
         * Dodawanie typu wiadomosci (dodaje byte zerowy na koncu)
         */
        if (snprintf(msg, strlen(cmd) + 3, "%c %s", menu_item[0], cmd) < 0) { ERR("sprintf"); }

        /*
         * Wysylanie wiadomosci
         */
        if (bulk_write(sock, msg, strlen(cmd) + 3) < 0) { ERR("write"); }
        fprintf(stderr, "Wyslano wiadomosc do serwera proxy\n");

        /*
         * Odbieranie odpowiedzi
         */
        if ((resp = (char *) malloc(MAX_RESP_SIZE * sizeof(char))) == NULL) { ERR("malloc"); }
        if ((resp_size = bulk_read(sock, resp, MAX_RESP_SIZE)) < 0) { ERR("read"); }
        fprintf(stderr, "Otrzymano odpowiedz od serwera proxy: %s\n", resp);

        free(msg);

        if (TEMP_FAILURE_RETRY(close(sock)) < 0) { ERR("close"); }
    }

    return EXIT_SUCCESS;
}

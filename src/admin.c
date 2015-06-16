/* admin.c */

#include "header.h"

#define MAX_MENU_OPT_SIZE 5
#define MAX_CMD_SIZE 64

volatile sig_atomic_t do_work = 1;

void sigint_handler(int sig)
{
    do_work = 0;
}

void usage(char *name)
{
    fprintf(stderr, "USAGE: %s [proxy server address] [proxy server port]\n", name);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    /*
     * Pozycja menu
     */
    char *menu_item;

    char *cmd;
    size_t max_cmd_size = 64;
    ssize_t cmd_size;

    char *msg;

    int socket;

    int is_working = 0;

    char msg_type;

    /*
     * Odpowiedz od serwera
     */
    char *resp;
    ssize_t resp_size;

    /*
     * ./admin [server address] [server port]
     */
    if (argc != 3)
    {
        usage(argv[0]);
    }

    sethandler(SIG_IGN, SIGPIPE);
    if (sethandler(sigint_handler, SIGINT)) { ERR("Setting SIGINT"); }

    /* Manage user input */
    while (is_working == 0 && do_work)
    {
        printf("\nMenu:\n"
                       "\n[1] - Dodaj nowy serwis\n"
                       "[2] - Usun istniejacy serwis\n"
                       "[3] - Dodaj nowego klienta\n"
                       "[4] - Usun istniejacego klietna\n"
                       "[5] - Pobranie wartosci licznikow dla klientow\n"
                       "[6] - Zablokuj uzytkownika\n"
                       "[7] - Odblokuj uzytkownika\n"
                       "[...] - Exit\n");
        printf("\nWybor: ");

        /*
         * Pobieranie opcji wprowadzonej przez administratora
         */
        if ((menu_item = (char *) malloc((MAX_MENU_OPT_SIZE + 1) * sizeof(char))) == NULL) { ERR("malloc"); }
        if ((fgets(menu_item, MAX_MENU_OPT_SIZE, stdin)) == NULL) { ERR("fgetc"); }

        msg_type = menu_item[0];

        /*
         * Alokacja pamieci dla wprowadzonych danych
         */
        if ((cmd = (char *) malloc((MAX_CMD_SIZE) * sizeof(char))) == NULL) { ERR("calloc"); }

        /*
         * Wielki if else
         */
        if (msg_type == '1')
        {
            printf("Podaj dane serwisu, ktory chcesz dodac - [nazwa] [host] [port]: ");

            /*
             * Pobieranie danych
             */
            if ((cmd_size = getline(&cmd, &max_cmd_size, stdin)) < 0) { ERR("getline"); }
        }
        else if (msg_type == '2')
        {
            printf("Podaj nazwe serwisu, ktory chcesz usunac: ");

            if ((cmd_size = getline(&cmd, &max_cmd_size, stdin)) < 0) { ERR("getline"); }
        }
        else if (msg_type == '3')
        {
            printf("Podaj dane uzytkownika, ktorego chcesz dodac - [login] [aktywny] [plan taryfowy] [przepustowosc] [kwota]: ");

            if ((cmd_size = getline(&cmd, &max_cmd_size, stdin)) < 0) { ERR("getline"); }
        }
        else if (msg_type == '4')
        {
            printf("Podaj login uzytkownika, ktorego chcesz usunac: ");

            if ((cmd_size = getline(&cmd, &max_cmd_size, stdin)) < 0) { ERR("getline"); }
        }
        else if (msg_type == '5') { }
        else if (msg_type == '6')
        {
            printf("Podaj login uzytkownika, ktorego chcesz zablokowac: ");

            if ((cmd_size = getline(&cmd, &max_cmd_size, stdin)) < 0) { ERR("getline"); }
        }
        else if (msg_type == '7')
        {
            printf("Podaj login uzytkownika, ktorego chcesz odblokowac: ");

            if ((cmd_size = getline(&cmd, &max_cmd_size, stdin)) < 0) { ERR("getline"); }
        }
        else
        {
            printf("Bledny wybor\n");
            is_working = 1;
        }

        if ((cmd = realloc(cmd, cmd_size * sizeof(char))) == NULL) { ERR("realloc"); }

        /*
         * Laczenie sie z serwerem proxy
         */
        socket = connect_socket(argv[1], atoi(argv[2]));

        /*
         * Alokacja pamieci na wiadomosc (TYP_WIADOMOSCI DANE)
         * 3 = TYP + SPACJA + BYTE ZEROWY
         */
        if ((msg = (char *) malloc((cmd_size + 3) * sizeof(char))) == NULL) { ERR("malloc"); }

        /*
         * Dodawanie typu wiadomosci (dodaje byte zerowy na koncu)
         */
        fprintf(stderr, "Wiadomosc: %s\n", cmd);

        if (snprintf(msg, cmd_size + 3, "%c %s", msg_type, cmd) < 0) { ERR("sprintf"); }

        /*
         * Wysylanie wiadomosci
         */
        if (bulk_write(socket, msg, cmd_size + 3) < 0) { ERR("write"); }

        /*
         * Odbieranie odpowiedzi
         */
        if ((resp = (char *) malloc(MAX_RESP_SIZE * sizeof(char))) == NULL) { ERR("malloc"); }
        if ((resp_size = bulk_read(socket, resp, MAX_RESP_SIZE)) < 0) { ERR("read"); }

        fprintf(stderr, "%s\n", resp);

        free(msg);
        free(cmd);

        if (TEMP_FAILURE_RETRY(close(socket)) < 0) { ERR("close"); }
    }

    return EXIT_SUCCESS;
}
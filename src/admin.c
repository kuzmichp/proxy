/* admin.c */

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
#include <stdbool.h>
#include <netdb.h>
#include <time.h>

#define ERR(source) (perror(source),\
		     fprintf(stderr,"%s:%d\n",__FILE__,__LINE__),\
		     exit(EXIT_FAILURE))

#define HERR(source) (fprintf(stderr,"%s(%d) at %s:%d\n",source,h_errno,__FILE__,__LINE__),\
		     exit(EXIT_FAILURE))

#define MAX_MENU_OPT_SIZE 5
#define MAX_CMD_SIZE 64

struct sockaddr_in make_address(char *name, uint16_t port);

void usage(char *name);

struct sockaddr_in make_address(char *address, uint16_t port) {
    struct sockaddr_in addr;
    struct hostent *hostinfo;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    hostinfo = gethostbyname(address);
    if (hostinfo == NULL)
        HERR("gethostbyname");

    addr.sin_addr = *(struct in_addr*) hostinfo->h_addr;

    return addr;
}

int sethandler(void (*f)(int), int sigNo);

int connect_socket(char *name, uint16_t port);

void communicate(int socket);

int make_socket();

ssize_t bulk_write(int fd, char *buf, size_t count);

int main(int argc, char *argv[]) {
    /* Menu item */
    char *menu_item;

    /* Message size for proxy */
    char *cmd;
    size_t max_cmd_size = 64;
    ssize_t cmd_size;

    char *msg;

    /* FDs (sockets) */
    int socket;

    /* Check if not exit */
    bool is_working = true;

    /* ./admin [server address] [server port] */
    if (argc != 3) {
        usage(argv[0]);
    }

    sethandler(SIG_IGN, SIGPIPE);

    printf("*** admin ***\n");

    /* Manage user input */
    while (is_working == true) {
        printf("\nMenu:\n"
                       "\n[1] - Add new service\n"
                       "[2] - Remove existing service\n"
                       "[3] - Add new client\n"
                       "[...] - Exit\n");
        printf("\nYour choise: ");

        menu_item = (char *) malloc((MAX_MENU_OPT_SIZE + 1) * sizeof(char));

        if (menu_item == NULL) { ERR("malloc"); }
        if ((fgets(menu_item, MAX_MENU_OPT_SIZE, stdin)) == NULL) { ERR("fgetc"); }

        /* Manage all menu items */
        if (strncmp(menu_item, "1", 1) == 0) {
            printf("Enter service [name] [host] [port]: ");

            /* Allocate memory for the user command */
            cmd = (char *) malloc((MAX_CMD_SIZE + 1) * sizeof(char));
            if (cmd == NULL) { ERR("calloc"); }

            if ((cmd_size = getline(&cmd, &max_cmd_size, stdin)) < 0) { ERR("getline"); }

            if ((cmd = realloc(cmd, cmd_size)) == NULL) { ERR("realloc"); }

            socket = connect_socket(argv[1], atoi(argv[2]));

            /* Add message type */
            msg = (char *) malloc((cmd_size + 2) * sizeof(char));
            if (msg == NULL) { ERR("malloc"); }

            if (sprintf(msg, "1 %s", cmd) < 0) { ERR("sprintf"); }

            if (bulk_write(socket, msg, cmd_size + 2) < 0) { ERR("write"); }

            free((void *)msg);
            free((void *)cmd);

            if (TEMP_FAILURE_RETRY(close(socket)) < 0) { ERR("close"); }

            //TODO: Close socket
            //printf("\nData: %s\nSize: %li\n", msg, msg_size);
        } else {
            printf("Invalid option\n");
            is_working = false;
        }
    }

    return EXIT_SUCCESS;
}

ssize_t bulk_write(int fd, char *buf, size_t count) {
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

void communicate(int socket) {

}

int connect_socket(char *name, uint16_t port) {
    struct sockaddr_in addr;
    int socketfd;
    socketfd = make_socket();
    addr = make_address(name, port);
    if (connect(socketfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) < 0)
    {
        if (errno != EINTR)
            ERR("connect");
        else
        {
            fd_set wfds;
            int status;
            socklen_t size = sizeof(int);
            FD_ZERO(&wfds);
            FD_SET(socketfd, &wfds);
            if (TEMP_FAILURE_RETRY(select(socketfd + 1, NULL, &wfds, NULL, NULL)) < 0) { ERR("select"); }
            if (getsockopt(socketfd, SOL_SOCKET, SO_ERROR, &status, &size) < 0) { ERR("getsockopt"); }
            if (status != 0) { ERR("connect"); }
        }
    }
    return socketfd;
}

int make_socket() {
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

void usage(char *name) {
    fprintf(stderr, "USAGE: %s [proxy server address] [proxy server port]\n", name);
    exit(EXIT_FAILURE);
}

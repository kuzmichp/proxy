all: client server admin

client: client.c header.h
	gcc -o client client.c header.h -Wall -Werror -pedantic -g -std=c99

server: server.c header.h
	gcc -o server server.c header.h -lpthread -Wall -Werror -pedantic -g -std=c99

admin: admin.c header.h
	gcc -o admin admin.c header.h -Wall -Werror -pedantic -g -std=c99

clean:
	rm -f client server admin

.PHONY:
	all clean

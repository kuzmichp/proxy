all: client server admin

client: client.c
	gcc client.c -o client -Wall

server: server.c
	gcc server.c -o server -lpthread -Wall

admin: admin.c
	gcc admin.c -o admin -Wall

clean:
	rm -f client server admin

.PHONY:
	all clean

CC=gcc
CFLAGS=-O3
LIBS=-ligraph -lgsl

all:
	make op
op: op.c
	$(CC) $(CFLAGS) -o op op.c -I/usr/local/include/igraph -L/usr/local/lib $(LIBS)
#-I and -L options for gcc to consider igraph installation
clean: 
	rm *.exe
	touch *.c
pack:	
	tar cvfz src.tar.gz *.c *.h *sh Makefile

srcdir = .
CC = gcc
CFLAGS = -g -O2 -W -Wall -I.
LDFLAGS = 
LIBS = -lutil 
VERSION = 0.8


OBJ = attach.o master.o main.o
SRC = $(srcdir)/attach.c $(srcdir)/master.c $(srcdir)/main.c

TARFILES = $(srcdir)/README $(srcdir)/COPYING $(srcdir)/Makefile.in \
	   $(srcdir)/config.h.in $(SRC) \
	   $(srcdir)/dtach.h $(srcdir)/dtach.spec $(srcdir)/configure \
	   $(srcdir)/configure.ac $(srcdir)/dtach.1

dtach: $(OBJ)
	$(CC) -o $@ $(LDFLAGS) $(OBJ) $(LIBS)

clean:
	rm -f dtach $(OBJ) dtach-$(VERSION).tar.gz

distclean: clean
	rm -f config.h Makefile config.log config.status config.cache

tar:
	mkdir dtach-$(VERSION)
	cp $(TARFILES) dtach-$(VERSION)
	tar -cf dtach-$(VERSION).tar dtach-$(VERSION)/
	gzip -9f dtach-$(VERSION).tar
	rm -rf dtach-$(VERSION)

attach.o: ./attach.c ./dtach.h config.h
master.o: ./master.c ./dtach.h config.h
main.o: ./main.c ./dtach.h config.h


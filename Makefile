PREFIX	 = /usr/bin
OBJS	 = blocks.o \
	   child.o \
	   client.o \
	   fargs.o \
	   flist.o \
	   hash.o \
	   io.o \
	   log.o \
	   main.o \
	   mkpath.o \
	   receiver.o \
	   sender.o \
	   server.o

CFLAGS	+= -W -Wall -Wextra -Wno-unused-parameter

openrsync: $(OBJS)
	$(CC) -o $@ $(OBJS)

install: openrsync
	install -m 0555 openrsync $(PREFIX)
	ln -f $(PREFIX)/openrsync $(PREFIX)/rsync

uninstall:
	rm -f $(PREFIX)/openrsync
	rm -f $(PREFIX)/rsync

clean:
	rm -f $(OBJS) openrsync

$(OBJS): extern.h

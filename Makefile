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

rsync: $(OBJS)
	$(CC) -o $@ $(OBJS)

clean:
	rm -f $(OBJS) rsync

$(OBJS): extern.h

include Makefile.configure

OBJS	   = blocks.o \
	     client.o \
	     compats.o \
	     copy.o \
	     downloader.o \
	     fargs.o \
	     flist.o \
	     hash.o \
	     ids.o \
	     io.o \
	     log.o \
	     md4.o \
	     misc.o \
	     mkpath.o \
	     mktemp.o \
	     receiver.o \
	     rmatch.o \
	     rules.o \
	     sender.o \
	     server.o \
	     session.o \
	     socket.o \
	     symlinks.o \
	     uploader.o
ALLOBJS	   = $(OBJS) \
	     main.o

all: openrsync

openrsync: $(ALLOBJS)
	$(CC) -o $@ $(ALLOBJS) -lm $(LDADD_LIB_SOCKET) $(LDADD_SCAN_SCALED) $(LDFLAGS)

install: all
	mkdir -p $(DESTDIR)$(BINDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	mkdir -p $(DESTDIR)$(MANDIR)/man5
	$(INSTALL_MAN) openrsync.1 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL_MAN) rsync.5 rsyncd.5 $(DESTDIR)$(MANDIR)/man5
	$(INSTALL_PROGRAM) openrsync $(DESTDIR)$(BINDIR)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/openrsync
	rm -f $(DESTDIR)$(MANDIR)/man1/openrsync.1
	rm -f $(DESTDIR)$(MANDIR)/man5/rsync.5
	rm -f $(DESTDIR)$(MANDIR)/man5/rsyncd.5

clean:
	rm -f $(ALLOBJS) openrsync

distclean: clean
	rm -f Makefile.configure config.h config.log

regress: all

$(ALLOBJS): extern.h config.h md4.h

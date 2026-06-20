.PHONY: regress

include Makefile.configure

RSYNC	    = rsync

sinclude Makefile.local

OBJS	    = blocks.o \
	      client.o \
	      compats.o \
	      copy.o \
	      downloader.o \
	      fargs.o \
	      flist.o \
	      fmap.o \
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
	      strmode.o \
	      symlinks.o \
	      uploader.o
ALLOBJS	    = $(OBJS) \
	      main.o
UNAME 	   != uname
LDADD_FTS  != pkg-config --libs musl-fts 2>/dev/null || echo ""
CFLAGS_FTS != pkg-config --cflags musl-fts 2>/dev/null || echo ""
LDADD_Z	   != pkg-config --libs zlib 2>/dev/null || echo "-lz"
CFLAGS_Z   != pkg-config --cflags zlib 2>/dev/null || echo ""
UNAME      != uname

.if $(UNAME) == "Darwin" || $(UNAME) == "FreeBSD"
LDADD	  += -lsbuf
CFLAGS	  += -DHAVE_SBUF
.endif

CFLAGS	  += $(CFLAGS_FTS) $(CFLAGS_Z)
LDADD	  += -lm $(LDADD_LIB_SOCKET) $(LDADD_SCAN_SCALED) $(LDADD_Z) $(LDADD_FTS)

all: openrsync

openrsync: $(ALLOBJS)
	$(CC) -o $@ $(ALLOBJS) $(LDFLAGS) $(LDADD)

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

$(ALLOBJS): extern.h config.h md4.h

flist.o main.o receiver.o rules.o sender.o uploader.o: rules.h

rules.h: extern.h

# Doesn't work: regress/functional/test10b_perms.test
# Doesn't work: regress/functional/test84_archive.test

REGRESS_SUCCESS = regress/functional/test00_simple.test \
		  regress/functional/test0_noslash.test \
		  regress/functional/test1_minusa.test \
		  regress/functional/test2_minusexclude.test \
		  regress/functional/test3_minusexclude.test \
		  regress/functional/test3b_minusexclude.test \
		  regress/functional/test3c_minusexclude.test \
		  regress/functional/test3d_minusexclude.test \
		  regress/functional/test3e_minusexclude.test \
		  regress/functional/test4_excludedir.test \
		  regress/functional/test6_perms.test \
		  regress/functional/test6b_perms.test \
		  regress/functional/test7_symlinks.test \
		  regress/functional/test7b_symlinks.test \
		  regress/functional/test8_times.test \
		  regress/functional/test8b_times.test \
		  regress/functional/test9_norecurse.test \
		  regress/functional/test10_perms.test \
		  regress/functional/test11_middlediff.test \
		  regress/functional/test11b_middlediff.test \
		  regress/functional/test12_inex.test \
		  regress/functional/test12b_inex.test \
		  regress/functional/test12c_inex.test \
		  regress/functional/test13_perms.test \
		  regress/functional/test13b_perms.test \
		  regress/functional/test19_linkdest.test \
		  regress/functional/test19b_linkdest-rel.test \
		  regress/functional/test28_size_only.test \
		  regress/functional/test40_backup.test
REGRESS_FAIL 	= regress/functional/test12d_inex.test
REGRESS_MANUAL 	= 
RSYNC_VERBOSE	=

regress_functional:: all
	@OPENRSYNC=`readlink -f openrsync`; \
	OPWD=`pwd` ; \
	for OPTGROUP in "--protocol 27" "--protocol 27 -z" ; \
	do \
		for FIRST in $$OPENRSYNC $(RSYNC) ; \
		do \
			for SECOND in $$OPENRSYNC $(RSYNC) ; \
			do \
				if [ $$FIRST = $$SECOND ] && [ $$FIRST = $(RSYNC) ] ; \
				then \
					continue ; \
				fi ; \
				for f in $(REGRESS_MANUAL); \
				do \
					TEST=`readlink -f $$f` ; \
					TEMP=`mktemp -d` ; \
					cd $$TEMP ; \
					echo "$$TEST: $$FIRST -> $$SECOND (opts: $$OPTGROUP)" ; \
					set +e ; \
					tstdir="$$OPWD/regress/functional" \
					    rsync="$$FIRST $$OPTGROUP $(RSYNC_VERBOSE) --rsync-path=$$SECOND" \
					    sh $$TEST ; \
					set -e ; \
					cd $$OPWD ; \
					echo $$TMP ; \
				done ; \
				if [ -n "$(REGRESS_MANUAL)" ] ; \
				then \
					continue ; \
				fi ; \
				for f in $(REGRESS_SUCCESS); \
				do \
					TEST=`readlink -f $$f` ; \
					TEMP=`mktemp -d` ; \
					cd $$TEMP ; \
					echo "$$TEST: $$FIRST -> $$SECOND (opts: $$OPTGROUP)" ; \
					tstdir="$$OPWD/regress/functional" \
					    rsync="$$FIRST $$OPTGROUP $(RSYNC_VERBOSE) --rsync-path=$$SECOND" \
					    sh $$TEST || { \
						echo $$TMP ; \
						exit 1 ; \
					} ; \
					cd $$OPWD ; \
					rm -rf $$TEMP ; \
				done ; \
				for f in $(REGRESS_FAIL); \
				do \
					TEST=`readlink -f $$f` ; \
					TEMP=`mktemp -d` ; \
					cd $$TEMP ; \
					echo "$$TEST: $$FIRST -> $$SECOND (opts: $$OPTGROUP)" ; \
					tstdir="$$OPWD/regress/functional" \
					    rsync="$$FIRST $$OPTGROUP $(RSYNC_VERBOSE) --rsync-path=$$SECOND" \
					    sh $$TEST || { \
						cd $$OPWD ; \
						rm -rf $$TEMP ; \
						continue ; \
					} ; \
					echo $$TMP ; \
					exit 1 ; \
				done ; \
			done ; \
		done ; \
	done

regress:: regress_functional

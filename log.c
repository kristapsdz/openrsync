/*
 * Copyright (c) Kristaps Dzonsons <kristaps@bsd.lv>
 * Copyright (c) 2024, Klara, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "config.h"

#include <sys/stat.h>
#include COMPAT_ENDIAN_H

#if HAVE_SBUF
# if __APPLE__
#  include <usbuf.h>
# else
#  include <sys/sbuf.h>
# endif
#else
# include "compat_sbuf.h"
#endif
/*
 * NetBSD's humanize_number() doesn't support HN_IEC_PREFIXES.
 * It also lives in util.h, not libutil.h.
 */
#if HAVE_HUMANIZE_NUMBER
# include <libutil.h>
#else
# include "compat_humanize_number.h"
#endif

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "extern.h"

#define LOG_FORMAT_SUCCESS	(1 << 0)
// #define LOG_FORMAT_ITEMIZE	(1 << 1)
#define LOG_FORMAT_LATEPRINT	(1 << 2)
// #define LOG_FORMAT_OPERATION	(1 << 3)
// #define LOG_FORMAT_ITEMIZE_I	(1 << 4)

/*
 * If NULL (default), this will cause log messages to route into syslog.
 * If not stdout, this will receive all log messages.
 * If stdout, log messages will either go to stdout or stderr, depending
 * on their severity.
 * This should ONLY be set in rsync_set_logfile().
 */
static FILE *log_file;

/*
 * This must only be set by the server: it's the session connected to
 * the client, who should be sent all messages.
 * If NULL (default), this is assumed to be the client.
 * This should ONLY be set in rsync_set_logfile().
 */
static struct sess *log_sess;

/*
 * Close out any pre-existing logfile.
 * FIXME: remove this function.
 */
static void
rsync_logfile_changed(FILE *old_logfile, FILE *new_logfile)
{
	/* We're the last reference to the log file; close it. */

	if (old_logfile != stdout && old_logfile != stderr &&
	    old_logfile != NULL)
		fclose(old_logfile);
}

/*
 * Set the output stream for log messages and the session for log
 * messages.  This function can be called multiple times as the program
 * learns its mode of operation.
 *
 * The session is only set for the server; clients (or if not yet sure
 * whether a server) should pass NULL.  For the server, the logfile
 * should be stdout; for the client, it should be the destination of the
 * logs.
 *
 * If sess->opts is NULL, then we're in the daemon client handler before
 * we've figured out the client options and we can assume that things
 * will work out.
 */
void
rsync_set_logfile(FILE *new_logfile, struct sess *sess)
{
	FILE *prev_logfile;

	if (sess != NULL && sess->opts != NULL) {
		assert(new_logfile == stdout);
		assert(sess->opts->server);
		assert(sess->mplex_writes);
	}

	prev_logfile = log_file;
	log_file = new_logfile;
	log_sess = sess;

	rsync_logfile_changed(prev_logfile, new_logfile);
}

/*
 * Map the given log type into a syslog.h priority.
 */
static int
log_priority(enum log_type type)
{
	switch (type) {
	case LT_WARNING:
		return LOG_WARNING;
	case LT_ERROR:
		return LOG_ERR;
	case LT_CLIENT:
	case LT_INFO:
	case LT_LOG:
	default:
		return LOG_INFO;
	}
}

/*
 * FIXME: this function is a nightmare.
 *
 * Log the given message with the given log type.  This has a large
 * number of possible output destinations: syslog, stderr, or the remote
 * server.
 *
 * The behaviour of this depends upon rsync_set_logfile(), which sets
 * whether we're the server (all messages are routed to the client) or
 * the client, which sends its messages to specific places.
 *
 * If in server mode, passing a type of LT_CLIENT, LT_INFO, LT_WARNING,
 * or LT_ERROR are routed to the client as either INFO or ERROR.  LT_LOG
 * are dropped.
 *
 * If in client mode with a log file, everything goes into the log file
 * but LT_CLIENT.  Without a log file, everything is logged but LT_LOG.
 */
static void
log_vwritef(enum log_type type, const char *fmt, va_list ap)
{
	char		  msgbuf[BIGPATH_MAX]; /* message buffer */
	va_list		  cap; /* temporary varargs */
	void		**wbufp; /* wbuf */
	size_t		 *wbufszp; /* wbufsz */
	size_t		  pos; /* current wbufsz */
	int32_t		  tag, /* multiplexing tag */
			  tagbuf; /* tag as multiplex value */
	int		  n, /* message buffer length */
			  client = STDOUT_FILENO; /* output */
	const int	  pri = log_priority(type); /* log as type */

	/*
	 * If logging is configured, we'll send all non-client messages
	 * to it.  Note that in various places throughout here, we'll
	 * tap out a copy of the va_list -- there's a good chance we'll
	 * be logging to multiple places, so we want to avoid running
	 * off the end of the arg list.
	 */

	if (type != LT_CLIENT &&
	    (log_file == NULL || log_file != stdout)) {
		va_copy(cap, ap);
		if (log_file == NULL) {
			vsyslog(pri, fmt, cap);
		} else {
			assert(log_file != stdout);
			vfprintf(log_file, fmt, cap);
		}
		va_end(cap);
	}

	/* "Quiet" mode. */

	if (verbose < 0 && pri != LOG_ERR)
		return;

	/*
	 * We shouldn't route log messages to the client.  If write
	 * multiplexing isn't turned on, we may not have a client yet
	 * (in the daemon).
	 */

	if (log_sess != NULL && type != LT_LOG &&
	    log_sess->mplex_writes) {
		assert(log_sess->opts->server);

		va_copy(cap, ap);
		n = vsnprintf(msgbuf, sizeof(msgbuf), fmt, cap);
		va_end(cap);
		if (n < 1)
			return;

		if ((size_t)n > sizeof(msgbuf))
			n = sizeof(msgbuf);

		tag = (pri == LOG_ERR) ? IT_ERROR_XFER : IT_INFO;

		if (log_sess->wbufp == NULL) {
			if (log_sess->role != NULL)
				client = log_sess->role->client;
			io_write_buf_tagged_safe(log_sess, client,
			    msgbuf, n, tag);
		} else {
			wbufszp = log_sess->wbufszp;
			pos = *log_sess->wbufszp;
			wbufp = log_sess->wbufp;

			assert(log_sess->opts->sender);
			if (!io_lowbuffer_alloc_safe(log_sess, wbufp,
			    wbufszp, log_sess->wbufmaxp, n))
				return;
			tagbuf = htole32(((tag + IOTAG_OFFSET) << 24) +
			    n);
			io_buffer_int(*wbufp, &pos, *wbufszp, tagbuf);
			io_buffer_buf(*wbufp, &pos, *wbufszp, msgbuf,
			    n);
		}

		/*
		 * FIXME: superfluous: we only get here if log_sess is
		 * not NULL, so the message will be dropped below.
		 */

		if (type == LT_CLIENT)
			return;
	}

	/*
	 * Log messages stop here, every other type will trickle through
	 * and get routed to stderr/stdout as appropriate.
	 */

	if (type == LT_LOG || log_sess != NULL)
		return;

	switch (pri) {
	case LOG_INFO:
		vfprintf(stdout, fmt, ap);
		break;
	default:
		fflush(stdout);
		vfprintf(stderr, fmt, ap);
		break;
	}
}

/*
 * See log_vwritef().
 */
__attribute__((format(printf, 2, 3))) static void
log_writef(enum log_type type, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_vwritef(type, fmt, ap);
	va_end(ap);
}

/*
 * Map the given iotag into an error class and log the provided message.
 */
void
rsync_log_tag(enum iotag tag, const char *fmt, ...)
{
	enum log_type	type;
	va_list		ap;

	type = (tag == IT_ERROR_XFER) ? LT_WARNING : LT_INFO;

	va_start(ap, fmt);
	log_vwritef(type, fmt, ap);
	va_end(ap);
}

/*
 * Log a message at level "level", starting at zero, which corresponds
 * to the current verbosity level opts->verbose (whose verbosity starts
 * at one).
 */
void
rsync_log(int level, const char *fmt, ...)
{
	char	*buf = NULL;
	va_list	 ap;

	if (verbose < level + 1)
		return;

	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&buf, fmt, ap) == -1) {
			va_end(ap);
			return;
		}
		va_end(ap);
	}

	if (level <= 0 && buf != NULL)
		log_writef(LT_INFO, "%s\n", buf);
	else if (level > 0)
		log_writef(LT_INFO, "%s(%d)%s%s\n", getprogname(),
		    getpid(), (buf != NULL) ? ": " : "",
		    (buf != NULL) ? buf : "");
	free(buf);
}

/*
 * This reports an error---not a warning.
 * However, it is not like errx(3) in that it does not exit.
 */
void
rsync_errx(const char *fmt, ...)
{
	char	*buf = NULL;
	va_list	 ap;

	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&buf, fmt, ap) == -1) {
			va_end(ap);
			return;
		}
		va_end(ap);
	}

	log_writef(LT_ERROR, "%s(%d): error%s%s\n", getprogname(),
	    getpid(), (buf != NULL) ? ": " : "",
	    (buf != NULL) ? buf : "");
	free(buf);
}

/*
 * This reports an error---not a warning.
 * However, it is not like err(3) in that it does not exit.
 */
void
rsync_err(const char *fmt, ...)
{
	char	*buf = NULL;
	va_list	 ap;
	int	 er = errno;

	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&buf, fmt, ap) == -1) {
			va_end(ap);
			return;
		}
		va_end(ap);
	}

	log_writef(LT_ERROR, "%s(%d): error%s%s: %s\n", getprogname(),
	    getpid(), (buf != NULL) ? ": " : "",
	    (buf != NULL) ? buf : "", strerror(er));
	free(buf);
}

/*
 * Prints a non-terminal error message, that is, when reporting on the
 * chain of functions from which the actual warning occurred.
 */
void
rsync_errx1(const char *fmt, ...)
{
	char	*buf = NULL;
	va_list	 ap;

	if (verbose < 1)
		return;

	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&buf, fmt, ap) == -1) {
			va_end(ap);
			return;
		}
		va_end(ap);
	}

	log_writef(LT_ERROR, "%s(%d): error%s%s\n", getprogname(),
	    getpid(), (buf != NULL) ? ": " : "",
	    (buf != NULL) ? buf : "");
	free(buf);
}

/*
 * Prints a warning message if we're running -v.
 */
void
rsync_warnx1(const char *fmt, ...)
{
	char    *buf = NULL;
	va_list  ap;

	if (verbose < 1)
		return;

	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&buf, fmt, ap) == -1) {
			va_end(ap);
			return;
		}
		va_end(ap);
	}

	log_writef(LT_WARNING, "%s(%d): warning%s%s\n", getprogname(),
	    getpid(), (buf != NULL) ? ": " : "",
	    (buf != NULL) ? buf : "");
	free(buf);
}

/*
 * Prints a warning message.
 */
void
rsync_warnx(const char *fmt, ...)
{
	char	*buf = NULL;
	va_list	 ap;

	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&buf, fmt, ap) == -1) {
			va_end(ap);
			return;
		}
		va_end(ap);
	}

	log_writef(LT_WARNING, "%s(%d): warning%s%s\n", getprogname(),
	    getpid(), (buf != NULL) ? ": " : "",
	    (buf != NULL) ? buf : "");
	free(buf);
}

/*
 * Prints a warning with an errno.
 * It uses a level detector for when to inhibit printing.
 */
void
rsync_warn(int level, const char *fmt, ...)
{
	char	*buf = NULL;
	va_list	 ap;
	int	 er = errno;

	if (verbose < level)
		return;

	if (fmt != NULL) {
		va_start(ap, fmt);
		if (vasprintf(&buf, fmt, ap) == -1) {
			va_end(ap);
			return;
		}
		va_end(ap);
	}

	log_writef(LT_WARNING, "%s(%d): warning%s%s: %s\n", getprogname(),
	    getpid(), (buf != NULL) ? ": " : "",
	    (buf != NULL) ? buf : "", strerror(er));
	free(buf);
}

/*
 * Cut down printf implementation taken from printf(1) in FreeBSD
 * 15-current rev 30189156d325fbcc9d1997d791daedc9fa3bed20.
 * FIXME: move to top of file.
 */
static const char widthchars[] = "'+- 0123456789";

/*
 * Copies string 2 into string 1, which is quaranteed to be at least as
 * longly allocated as string 2, omitting "'".  Returns the number of
 * "'"s.
 */
static size_t
isit_human(char *s1, const char *s2)
{
	char		*p1;
	const char	*p2;
	size_t		 count = 0;

	for (p1 = s1, p2 = s2; *p2; p2++) {
		if (*p2 == '\'')
			count++;
		else
			*p1++ = *p2;
	}
	*p1 = '\0';

	return count;
}

/*
 * Do the 8-bit escaping as needed for `s`.  If `sbuf` is NULL, then the
 * result will be written to the log file.  Otherwise, it'll be stashed
 * in the sbuf passed in as requested.
 *
 * This filters out non-printables and octals.  If --8-bit-output, it
 * prints anything else; if not, only ASCII and 2-Byte UTF8 sequences
 * are printed.
 *
 * TODO: We used to print the names of items to be updated with a mix of
 * calls to LOG1() and print_7_or_8_bit().  With the former, embedded
 * control characters were not correctly escaped, but all other
 * characters were printed as if --8-bit-output were in effect (hence
 * unicode characters were preserved).  Conversely, with the latter,
 * unicode characters outside the portable set were all treated as
 * control characters and hence incorrectly escaped.
 *
 * We now call log_item() to print each item, which ends up calling this
 * function, which now handles control characters correctly and
 * partially deals with some range of unicode characters (e.g.
 * c2xx-dfxx) that we get with the C.UTF-8 locale.
 *
 * The correct fix seems to be to use iconv() where available, and print
 * all chars outside the portable set as if --8-bit-output were in
 * effect.
 */
bool
print_7_or_8_bit(const struct sess *sess, const char *fmt, const char *s,
    struct sbuf *sbuf)
{
	const char	*p;
	struct sbuf	*innerbuf;
	unsigned char 	 c, c2;

	innerbuf = sbuf_new_auto();
	if (innerbuf == NULL) {
		ERR("sbuf_new_auto");
		return false;
	}

	for (p = s; *p; p++) {
		c = *(unsigned char *)p;

		if (isprint(c) || c == '\t' || c == 0x7f) {
			/*
			 * Branch: printable, tab, delete.
			 * Test specially for octals now.
			 */
			if (c == '\\' &&
			    *(unsigned char *)(p + 1) == '#' &&
			    isdigit(*(unsigned char *)(p + 2)) &&
			    isdigit(*(unsigned char *)(p + 3)) &&
			    isdigit(*(unsigned char *)(p + 4)))
				sbuf_printf(innerbuf, "\\#%03o", '\\');
			else
				sbuf_putc(innerbuf, c);
		} else if (c < ' ') {
			/*
			 * Non-printable ASCII.
			 */
                        sbuf_printf(innerbuf, "\\#%03o", c);
		} else if (sess->opts->bit8) {
			/*
			 * 8bit (above ASCII).
			 */
                        sbuf_putc(innerbuf, c);
		} else if (c >= 0xc2 && c <= 0xdf) {
			c2 = *(unsigned char *)(p + 1);
			/*
			 * Two-byte UTF8 characters.
			 * TODO: Use iconv().
			 */
			if (c2 >= 0x80 && c2 <= 0xdf) {
				sbuf_putc(innerbuf, c);
				sbuf_putc(innerbuf, c2);
				p++;
			} else {
				sbuf_printf(innerbuf, "\\#%03o", c);
			}
		} else {
			sbuf_printf(innerbuf, "\\#%03o", c);
		}
	}

	if (sbuf_finish(innerbuf) != 0) {
		ERR("sbuf_finish");
		sbuf_delete(innerbuf);
		return false;
	}

	if (sbuf != NULL)
		sbuf_printf(sbuf, fmt, sbuf_data(innerbuf));
	else
		log_writef(LT_INFO, fmt, sbuf_data(innerbuf));

	sbuf_delete(innerbuf);
	return true;
}

/*
 * Format the escape at the first position of "fmt" and add its output
 * to "sbuf".  Returns the new position of the format string (the "fmt"
 * input).
 *
 * rval is filled with whether there is any argument that requires
 * late printing or whether itemization is requested.  See the
 * LOG_FORMAT_* flags.  (FIXME: currently not supported.)
 *
 * rval is expected to be initialized to zero before the first call.
 */
__attribute__((format(printf, 1, 0)))
static const char *
printf_doformat(const char *fmt, int *rval, const struct sess *sess,
    const struct flist *fl, struct sbuf *sbuf)
{
	static const char skip1[] = "'-+ 0"; /* field width chars */
	char		  widthstring[8192]; /* format string */
	char		  buf[8192]; /* temporary buffer */
	uint64_t	  bytes_transferred = 0; /* as it looks */
	const char	 *fmt_orig = fmt, /* "fmt" at start */
			 *path = fl->path, /* path alias */
			 *Lfmt = " -> %s"; /* %L format */
	char		 *cooked; /* temporary */
	time_t		  now; /* %t printing */
	size_t		  l, /* temporary */
			  humanlevel = 0; /* "human" 0-3 level */
	char		  convch; /* format escape */

	fmt++;

	widthstring[0] = '%';
	l = strspn(fmt, widthchars);

	/*
	 * We need a reserve of 4 chars for substitutions below, plus
	 * lead.
	 */

	if (l + 5u > sizeof(widthstring)) {
		ERRX("Insufficient buffer for width format");
		return NULL;
	}

	strlcpy(widthstring + 1, fmt, l + 1);

	if (strchr(widthstring, '\'')) {
		cooked = malloc(strlen(widthstring));
		if (cooked == NULL) {
			ERR("malloc");
			return NULL;
		}
		humanlevel = isit_human(cooked, widthstring);
		strlcpy(widthstring, cooked, l + 1);
		l -= humanlevel;
		free(cooked);
	}

	/* Skip to field width. */

	while (*fmt && strchr(skip1, *fmt) != NULL)
		fmt++;

	if (*fmt == '\0') {
		if (sbuf != NULL) {
			sbuf_putc(sbuf, fmt_orig[0]);
			fmt = fmt_orig + 1;
		}
		return fmt_orig + 1;
	}

	while (isdigit((unsigned char)*fmt))
		fmt++;

	convch = *fmt;
	fmt++;

	switch (convch) {
	case 'a':	/* Remote address (daemon) */
	case 'h':	/* Remote host (daemon) */
		break;	/* Nop in non-daemon mode. */
		/* FALLTHROUGH */
	case 'm':	/* Module */
	case 'P':	/* Module path */
	case 'u':  	/* Auth username */
		if (sbuf != NULL) {
			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			sbuf_printf(sbuf, widthstring, "");
		}
		break;
	case 'b':
		*rval |= LOG_FORMAT_LATEPRINT;

		if (sbuf == NULL)
			break;

		if (!sess->opts->dry_run) {
			bytes_transferred = sess->total_read;
			bytes_transferred += sess->total_write;
		}

		switch (humanlevel) {
		case 0:
			widthstring[l + 1] = 'l';
			widthstring[l + 2] = 'd';
			widthstring[l + 3] = '\0';
			sbuf_printf(sbuf, widthstring,
				    bytes_transferred);
			break;
		case 1:
			widthstring[l + 1] = 'l';
			widthstring[l + 2] = 'd';
			widthstring[l + 3] = '\0';
			sbuf_printf(sbuf, widthstring,
				    bytes_transferred);
			break;
		case 2:
			humanize_number(buf, 5, bytes_transferred, "",
			    HN_AUTOSCALE,
			    HN_DECIMAL|HN_NOSPACE);
			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			sbuf_printf(sbuf, widthstring, buf);
			break;
		case 3:
			humanize_number(buf, 5, bytes_transferred, "",
			    HN_AUTOSCALE,
			    HN_DECIMAL|HN_NOSPACE|HN_DIVISOR_1000);
			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			sbuf_printf(sbuf, widthstring, buf);
			break;
		}
		break;
	case 'B':
		/* Print mode human-readable */

		if (sbuf != NULL) {
			our_strmode(fl->st.mode, buf);
			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			sbuf_printf(sbuf, widthstring, buf);
		}
		break;
	case 'c':
		/* "%c the total size of the block checksums received for the
		   basis file (only when sending)" */
		/*
		 * I don't think smb rsync implements what it says in the
		 * manpage.
		 */
		*rval |= LOG_FORMAT_LATEPRINT;
		break;
#if 0
	case 'C': {

		/* This is a rsync 3.x feature */

		/* the full-file checksum if it is known for the file.
		 * For older rsync protocols/versions, the checksum
		 * was salted, and is thus not a useful value (and is
		 * not dis- played when that is the case). For the
		 * checksum to output for a file, either the
		 * --checksum option must be in-ef- fect or the file
		 * must have been transferred without a salted
		 * checksum being used.  See the --checksum-choice
		 * option for a way to choose the algorithm.
		*/

		break;
	}
#endif
	case 'f':
		/*
		 * "the filename (long form on sender; no trailing "/")"
		 */
		if (sbuf != NULL) {
			path = fl->path;
			if (sess->opts->relative)
				path = fl->wpath;
			while (*path == '/')
				path++;
			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			if (!print_7_or_8_bit(sess, widthstring, path,
			    sbuf)) {
				ERRX("print_7_or_8_bit");
				return NULL;
			}
		}
		break;
	case 'G':
		/* FIXME this is incorrect since gid 0 is also root */
		if (sbuf != NULL) {
			if (fl->st.gid) {
				widthstring[l + 1] = 'd';
				widthstring[l + 2] = '\0';
				sbuf_printf(sbuf, widthstring, fl->st.gid);
			} else {
				widthstring[l + 1] = 's';
				widthstring[l + 2] = '\0';
				sbuf_printf(sbuf, widthstring, "DEFAULT");
			}
		}
		break;
#if 0
	case 'I':
		*rval |= LOG_FORMAT_ITEMIZE_I;
		break;
	case 'i': {
		/* itemize string YXcstpogz */
		int32_t ifl;

		*rval |= LOG_FORMAT_ITEMIZE;
		if (sbuf != NULL) {
			ifl = fl->iflags;
			if (ifl & IFLAG_DELETED) {
				/* Handled by flist_gen_dels() */
				break;
			}

			/*
			 * We only use 10 bytes from buf[], but buf is very
			 * large so only zero the first few bytes.
			 */
			assert(sizeof(buf) >= 16);
			bzero(buf, 16);

			buf[0] = '.';
			if (ifl & IFLAG_LOCAL_CHANGE) {
				buf[0] = (ifl & IFLAG_HLINK_FOLLOWS) ? 'h' : 'c';
			} else if (ifl & IFLAG_TRANSFER) {
				buf[0] = sess->lreceiver ? '>' : '<';
			}

			if (S_ISDIR(fl->st.mode))
				buf[1] = 'd';
			if (S_ISLNK(fl->st.mode))
				buf[1] = 'L';
			if (S_ISSOCK(fl->st.mode) || S_ISFIFO(fl->st.mode))
				buf[1] = 'S';
			if (S_ISBLK(fl->st.mode) || S_ISCHR(fl->st.mode))
				buf[1] = 'D';
			if (buf[1] == '\0')
				buf[1] = 'f';

			if (ifl & IFLAG_CHECKSUM)
				buf[2] = 'c';
			else
				buf[2] = '.';

			if (ifl & IFLAG_SIZE)
				buf[3] = 's';
			else
				buf[3] = '.';

			buf[4] = '.';
			if (ifl & IFLAG_TIME) {
				if (!sess->opts->preserve_times ||
				    S_ISLNK(fl->st.mode)) {
					buf[4] = 'T';
				} else {
					buf[4] = 't';
				}
			}

			if (ifl & IFLAG_PERMS)
				buf[5] = 'p';
			else
				buf[5] = '.';

			if (ifl & IFLAG_OWNER)
				buf[6] = 'o';
			else
				buf[6] = '.';

			if (ifl & IFLAG_GROUP)
				buf[7] = 'g';
			else
				buf[7] = '.';

			buf[8] = '.';

			if (ifl & IFLAG_MISSING_DATA || ifl & IFLAG_NEW) {
				char c;

				if (ifl & IFLAG_NEW)
					c = '+';
				else
					c = '?';
				buf[2] = c; buf[3] = c; buf[4] = c;
				buf[5] = c; buf[6] = c; buf[7] = c;
				buf[8] = c;
			} else {
				int i;

				if (buf[0] == '.' || buf[0] == 'h' ||
				    (buf[0] == 'c' && buf[1] == 'f')) {
					for (i = 2; buf[i]; ++i) {
						if (buf[i] != '.')
							break;
					}
					if (buf[i] == '\0') {
						for (i = 2; buf[i]; ++i)
							buf[i] = ' ';
					}
				}
			}

			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			sbuf_printf(sbuf, widthstring, buf);
		}
		break;
	}
#endif
	case 'l':
		/* File length */
		if (sbuf != NULL) {
			switch (humanlevel) {
			case 0:
				widthstring[l + 1] = 'l';
				widthstring[l + 2] = 'd';
				widthstring[l + 3] = '\0';
				sbuf_printf(sbuf, widthstring, fl->st.size);
				break;
			case 1:
				/* TODO for 3.x: use a printf with "'" */
				widthstring[l + 1] = '\'';
				widthstring[l + 2] = 'l';
				widthstring[l + 3] = 'd';
				widthstring[l + 4] = '\0';
				sbuf_printf(sbuf, widthstring, fl->st.size);
				break;
			case 2:
				humanize_number(buf, 5, fl->st.size, "",
				    HN_AUTOSCALE,
				    HN_DECIMAL|HN_NOSPACE);
				widthstring[l + 1] = 's';
				widthstring[l + 2] = '\0';
				sbuf_printf(sbuf, widthstring, buf);
				break;
			case 3:
				humanize_number(buf, 5, fl->st.size, "",
				    HN_AUTOSCALE,
				    HN_DECIMAL|HN_NOSPACE|HN_DIVISOR_1000);
				widthstring[l + 1] = 's';
				widthstring[l + 2] = '\0';
				sbuf_printf(sbuf, widthstring, buf);
				break;
			}
		}
		break;
	case 'L':
#if 0
		/*
		 * Use "late print" here.  Theoretically late print is
		 * only needed when hardlink printing is requested.
		 * But with just the format string we can't tell
		 * whether there will ever be hardlinks.
		 */
		*rval |= LOG_FORMAT_LATEPRINT;
#endif

		if (sbuf != NULL) {
			if (fl->link != NULL &&
			    !(fl->iflags & IFLAG_BASIS_FOLLOWS)) {
				if (fl->iflags & IFLAG_HLINK_FOLLOWS)
					Lfmt = " => %s";

				snprintf(buf, sizeof(buf), Lfmt, fl->link);
				widthstring[l + 1] = 's';
				widthstring[l + 2] = '\0';
				if (!print_7_or_8_bit(sess, widthstring, buf,
				    sbuf)) {
					ERRX("print_7_or_8_bit");
					return NULL;
				}
			}
		}
		break;
	case 'M':
		/* Modification time of item */
		if (sbuf != NULL) {
			/* 2024/01/30-16:23:29 */
			strftime(buf, sizeof(buf), "%Y/%m/%d-%H:%M:%S",
			    localtime(&fl->st.mtime));
			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			sbuf_printf(sbuf, widthstring, buf);
		}
		break;
	case 'n':
		/* Alternate file name print */
		if (sbuf != NULL) {
			path = fl->wpath;
			if (sess->opts->relative)
				path = fl->path;
			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			/* "(short form; trailing "/" on dir)" */
			if (S_ISDIR(fl->st.mode)) {
				snprintf(buf, sizeof(buf), "%s/", path);
				path = buf;
			}
			if (!print_7_or_8_bit(sess, widthstring, path, sbuf)) {
				ERRX("print_7_or_8_bit");
				return NULL;
			}
		}
		break;
#if 0
	case 'o': {
		*rval |= LOG_FORMAT_OPERATION;

		/*
		 * "the operation, which is "send", "recv", or "del." (the
		 * latter includes the trailing period)"
		 */
		if (sbuf != NULL) {
			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			if (!print_7_or_8_bit(sess, widthstring,
			    sess->opts->sender ? "send" : "recv", sbuf)) {
				ERRX("print_7_or_8_bit");
				return NULL;
			}
		}
		break;
	}
#endif
	case 'p':
		/* PID as a number */
		if (sbuf != NULL) {
			widthstring[l + 1] = 'd';
			widthstring[l + 2] = '\0';
			/* TODO: capture top-level pid in main() */
			sbuf_printf(sbuf, widthstring, getpid());
		}
		break;
	case 't': {
		/* Current machine time */
		if (sbuf != NULL) {
			time(&now);
			strftime(buf, sizeof(buf), "%Y/%m/%d-%H:%M:%S",
			    localtime(&now));
			widthstring[l + 1] = 's';
			widthstring[l + 2] = '\0';
			sbuf_printf(sbuf, widthstring, buf);
		}
		break;
	}
	case 'U':
		/* FIXME this is incorrect since uid 0 is also root */
		if (sbuf != NULL) {
			if (fl->st.uid) {
				widthstring[l + 1] = 'd';
				widthstring[l + 2] = '\0';
				sbuf_printf(sbuf, widthstring, fl->st.uid);
			} else {
				widthstring[l + 1] = 's';
				widthstring[l + 2] = '\0';
				sbuf_printf(sbuf, widthstring, "DEFAULT");
			}
		}
		break;
	default:
		if (sbuf != NULL) {
			sbuf_putc(sbuf, fmt_orig[0]);
			fmt = fmt_orig + 1;
		}
		break;
	}

	return fmt;
}

/*
 * Step through a format string "format" and format "fl" and "sess"
 * according to "type".  Escapes in the format string are routed through
 * into print_doformat(), which does most of the work here.
 * Returns a bit-field of LOG_FORMAT_xxx values or zero on failure.
 */
int
log_format_type(enum log_type type, const struct sess *sess,
    const char *format, const struct flist *fl)
{
	const char	*start, /* start of word */
			*fmt = format; /* current word pos */
	struct sbuf	*sbuf = NULL; /* output sbuf */
	size_t	 	 len; /* length of format */
	int		 rval = 0; /* rc of print_doformat */
	const bool	 do_print = (fl != NULL); /* has printable */

	if (format == NULL)
		return 0;

	if (do_print) {
		sbuf = sbuf_new_auto();
		if (sbuf == NULL) {
			ERR("sbuf_new_auto");
			return 0;
		}
	}

	len = strlen(format);

	for (; *fmt;) {
		start = fmt;
		while (fmt < format + len) {
			if (fmt[0] == '%') {
				if (do_print)
					sbuf_bcat(sbuf, start, fmt - start);
				if (fmt[1] == '%') {
					/* %% prints a % */
					if (do_print)
						sbuf_putc(sbuf, '%');
					fmt += 2;
				} else {
					fmt = printf_doformat(fmt, &rval, sess,
					    fl, sbuf);
					if (fmt == NULL || *fmt == '\0')
						goto out;
				}
				start = fmt;
			} else
				fmt++;
		}
		if (do_print)
			sbuf_bcat(sbuf, start, fmt - start);
	}

out:
	if (do_print) {
		sbuf_putc(sbuf, '\n');

		if (sbuf_finish(sbuf) != 0) {
			ERR("sbuf_finish");
			sbuf_delete(sbuf);
			return 0;
		}

		log_writef(type, "%s", sbuf_data(sbuf));
		sbuf_delete(sbuf);
	} else {
		assert(sbuf == NULL);
	}

	return rval | LOG_FORMAT_SUCCESS;
}

/*
 * Study the logformat and outformat strings and set whether this
 * session will have late printing.
 */
void
log_format_init(struct sess *sess)
{
	int	flags; /* flags fom out_format */

	flags = log_format_type(LT_INFO, sess, sess->opts->out_format,
	    NULL);

	if (flags & LOG_FORMAT_SUCCESS) {
		sess->lateprint = (flags & LOG_FORMAT_LATEPRINT) != 0;
	}

	if (sess->opts->server)
		sess->lateprint = true;
}


/*
 * Print a number into the provided buffer depending on the current
 * --human-readable level.
 * Returns true on success, false if the buffer is too small.
 */
bool
rsync_humanize(const struct sess *sess, char *buf, size_t len,
    int64_t val)
{
	size_t	 res = 0; /* sprintf result */
	char	 tbuf[32]; /* buffer */

	switch (sess->opts->human_readable) {
	case 0:
		humanize_number(tbuf, sizeof(tbuf), val, "B", 0, 0);
		res = snprintf(buf, len, "%s", tbuf);
		break;
	case 1:
		humanize_number(tbuf, 9, val, "B",
		    HN_AUTOSCALE, HN_DECIMAL|HN_DIVISOR_1000);
		res = snprintf(buf, len, "%s", tbuf);
		break;
	case 2:
		humanize_number(tbuf, 10, val, "B",
		    HN_AUTOSCALE, HN_DECIMAL|HN_IEC_PREFIXES);
		res = snprintf(buf, len, "%s", tbuf);
		break;
	}

	return res < len;
}

bool
log_item_impl(enum log_type type, const struct sess *sess,
    const struct flist *f)
{
	const char	*outformat = sess->opts->out_format,
			*logformat = NULL;
	bool		 ok = true;

	if (outformat == NULL && (verbose > 0 || sess->opts->progress))
		outformat = "%n";
	if (type != LT_LOG && outformat != NULL && !sess->opts->server &&
	    !log_format_type(LT_CLIENT, sess, outformat, f))
		ok = false;
	if (type != LT_CLIENT && logformat != NULL &&
	    !log_format_type(LT_LOG, sess, logformat, f))
		ok = false;

	return ok;
}

/*
 * Log that an item (file, directory, etc.) has been transferred.
 * This is used by both the uploader and downloader.
 * Returns false on failure, true on success.
 */
bool
log_item(const struct sess *sess, const struct flist *f)
{
	enum log_type	type = (sess->opts->server ? LT_LOG : LT_INFO);
	bool		visible = false,
			sig = (f->iflags & SIGNIFICANT_IFLAGS),
			local = (f->iflags & IFLAG_LOCAL_CHANGE) && sig,
			link = (f->iflags & IFLAG_HLINK_FOLLOWS),
			filtered = true;

	if (verbose > 1 && f->iflags == 0 &&
	    sess->mode == FARGS_RECEIVER) {
		if (S_ISDIR(f->st.mode))
			return true;
		return print_7_or_8_bit(sess, "%s is uptodate\n",
		    f->wpath, NULL);
	}

	/*
	 * We don't generally log if we are the server, but there are
	 * exceptions.  If a custom outformat is set, then we should
	 * generate logs, except if the outformat is being overridden by
	 * using itemize that sets the outformat to include %i or %o.
	 */

	if (sess->opts->server) {
		return true;
	} else {
		if (visible || local)
			filtered = false;
		if (S_ISDIR(f->st.mode) && sig)
			filtered = false;
		if (link)
			filtered = false;

		/*
		 * This is technically wrong and should be fixed.  Some
		 * filtered subset will go to both the client and the
		 * log, while the more complete set may go to just the
		 * client.  For now, we send the filtered subset to both
		 * and only restrict insignificant stuff to client-only
		 * when -i hasn't been requested in the log file.
		 */

		if (filtered)
			return true;
		else if (!sig)
			type = LT_CLIENT;
	}

	return log_item_impl(type, sess, f);
}

/*
 * FIXME: this was in extern.h as an inline, but is now here.
 */
enum log_type
xfer_log_level(const struct sess *sess)
{
	return LT_LOG;
}

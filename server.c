/*
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
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

#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if HAVE_ERR
# include <err.h>
#endif

#include "extern.h"

static int
fcntl_nonblock(int fd)
{
	int	 fl;

	if ((fl = fcntl(fd, F_GETFL, 0)) == -1)
		ERR("fcntl: F_GETFL");
	else if (fcntl(fd, F_SETFL, fl|O_NONBLOCK) == -1)
		ERR("fcntl: F_SETFL");
	else
		return 1;

	return 0;
}

/*
 * The server (remote) side of the system.
 * This parses the arguments given it by the remote shell then moves
 * into receiver or sender mode depending upon those arguments.
 * Returns exit code 0 on success, 1 on failure, 2 on failure with
 * incompatible protocols.
 */
int
rsync_server(const struct opts *opts, size_t argc, char *argv[])
{
	struct sess	 sess;
	int		 fdin = STDIN_FILENO,
			 fdout = STDOUT_FILENO,
			 rc = 1;
	size_t		 i; /* temporary */

	if (pledge("stdio unix rpath wpath cpath dpath fattr chown getpw unveil",
	    NULL) == -1)
		err(ERR_IPC, "pledge");

	memset(&sess, 0, sizeof(struct sess));
	sess.opts = opts;
	sess.mode = sess.opts->sender ? FARGS_SENDER : FARGS_RECEIVER;

	/* Begin by making descriptors non-blocking. */

	if (!fcntl_nonblock(fdin) ||
	    !fcntl_nonblock(fdout)) {
		ERRX1("fcntl_nonblock");
		goto out;
	}

	/* Standard rsync preamble, server side. */

	sess.lver = sess.protocol = RSYNC_PROTOCOL;
	sess.seed = arc4random();

	if (!io_read_int(&sess, fdin, &sess.rver)) {
		ERRX1("io_read_int");
		goto out;
	} else if (!io_write_int(&sess, fdout, sess.lver)) {
		ERRX1("io_write_int");
		goto out;
	} else if (!io_write_int(&sess, fdout, sess.seed)) {
		ERRX1("io_write_int");
		goto out;
	}

	if (sess.rver < sess.lver) {
		ERRX("remote protocol %d is older than our own %d: "
		    "unsupported", sess.rver, sess.lver);
		rc = 2;
		goto out;
	}

	sess.mplex_writes = 1;
	rsync_set_logfile(stdout, &sess);

	LOG3("server detected client version %d, server version %d, "
	    "negotiated protocol version %d, seed %d",
	    sess.rver, sess.lver, sess.protocol, sess.seed);

	for (i = 0; argv[i] != NULL; i++)
		LOG3("exec[%zu] = %s", i, argv[i]);

	LOG4("Printing(%d): itemize %d late %d", getpid(), 0, 0);

	if (sess.opts->sender) {
		LOG3("server starting sender");

		/*
		 * At this time, I always get a period as the first
		 * argument of the command line.
		 * Let's make it a requirement until I figure out when
		 * that differs.
		 * rsync [flags] "." <source> <...>
		 */

		if (argc == 0) {
			ERRX("must have arguments");
			goto out;
		} else if (strcmp(argv[0], ".")) {
			ERRX("first argument must be a standalone period");
			goto out;
		} else if (argc == 1) {
			/*
			 * rsync 2.x can send "" as the source, in which case
			 * an implied "." is intended and must be fabricated.
			 * rsync 3.x always sends the implied "." If we only
			 * have 1 argv, reuse it to avoid making a new
			 * allocation.
			 */
		} else {
			argv++;
			argc--;
		}

		if (!rsync_sender(&sess, fdin, fdout, argc, argv)) {
			ERRX1("rsync_sender");
			goto out;
		}
	} else {
		LOG3("server starting receiver");

		/*
		 * I don't understand why this calling convention
		 * exists, but we must adhere to it.
		 * rsync [flags] "." <destination>
		 */

		/* TODO: merge with above, which is the same code. */

		if (argc == 0) {
			ERRX("must have arguments");
			goto out;
		} else if (strcmp(argv[0], ".")) {
			ERRX("first argument must be a standalone period");
			goto out;
		} else if (argc == 1) {
			/*
			 * rsync 2.x can send "" as the dest, in which case
			 * an implied "." is intended and must be fabricated.
			 * rsync 3.x always sends the implied "."
			 * If we only have 1 argv, reuse it to avoid making a
			 * new allocation.
			 */
		} else if (argc != 2) {
			ERRX("server receiver mode requires two argument");
			goto out;
		} else {
			argv++;
			argc--;
		}

		if (!rsync_receiver(&sess, fdin, fdout, argv[0])) {
			ERRX1("rsync_receiver");
			goto out;
		}
	}

	rc = 0;

	if (io_read_check(&sess, fdin)) {
		if (sess.mplex_read_remain > 0)
			ERRX1("data remains in read pipe");
		rc = ERR_IPC;
	}
out:
	sess_cleanup(&sess);
	/* 
	 * Disassociate sess from the logging subsystem before sess goes
	 * out of scope.
	 */
	rsync_set_logfile(stderr, NULL);
	return rc;
}

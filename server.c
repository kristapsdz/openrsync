/*	$Id$ */
/*
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
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
#include <sys/stat.h>

#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

static int
fcntl_nonblock(const struct opts *opts, int fd)
{
	int	 fl;

	if (-1 == (fl = fcntl(fd, F_GETFL, 0)))
		ERR(opts, "fcntl: F_GETFL");
	else if (-1 == fcntl(fd, F_SETFL, fl|O_NONBLOCK))
		ERR(opts, "fcntl: F_SETFL");
	else
		return 1;

	return 0;
}

/*
 * The server (remote) side of the system.
 * This parses the arguments given it by the remote shell then moves
 * into receiver or sender mode depending upon those arguments.
 *
 * Pledges: rpath, cpath, wpath, stdio.
 */
int
rsync_server(const struct opts *opts, size_t argc, char *argv[])
{
	struct sess	 sess;
	int	 	 fdin = STDIN_FILENO, 
			 fdout = STDOUT_FILENO, c = 0;

	/* Begin by making descriptors non-blocking. */

	if ( ! fcntl_nonblock(opts, fdin) || 
	     ! fcntl_nonblock(opts, fdout)) {
		ERRX1(opts, "fcntl_nonblock");
		goto out;
	}

	/* 
	 * Standard rsync preamble, server side.
	 * By sending a non-zero value following that, we trigger
	 * seeding of the MD5 hashes.
	 */

	sess.lver = RSYNC_PROTOCOL;
	sess.seed = arc4random();

	if ( ! io_read_int(opts, fdin, &sess.rver)) {
		ERRX1(opts, "io_read_int: version");
		goto out;
	} else if ( ! io_write_int(opts, fdout, sess.lver)) {
		ERRX1(opts, "io_write_int: version");
		goto out;
	} else if ( ! io_write_int(opts, fdout, sess.seed)) {
		ERRX1(opts, "io_write_int: seed");
		goto out;
	}

	LOG2(opts, "server detected client version %" PRId32 
		", server version %" PRId32 ", seed %" PRId32,
		sess.rver, sess.lver, sess.seed);

	if (opts->sender) {
		LOG2(opts, "server starting sender");

		/*
		 * At this time, I always get a period as the first
		 * argument of the command line.
		 * Let's make it a requirement until I figure out when
		 * that differs.
		 * rsync [flags] "." <source> <...>
		 */

		if (strcmp(argv[0], ".")) {
			ERRX(opts, "first argument must "
				"be a standalone period");
			goto out;
		}
		argv++;
		argc--;
		if (0 == argc) {
			ERRX(opts, "must have arguments");
			goto out;
		}

		c = rsync_sender(opts, &sess, 
			fdin, fdout, argc, argv);
		if ( ! c)
			ERRX1(opts, "rsync_sender");
	} else {
		LOG2(opts, "server starting receiver");

		/*
		 * I don't understand why this calling convention
		 * exists, but we must adhere to it.
		 * rsync [flags] "." <destination>
		 */

		if (2 != argc) {
			ERRX(opts, "server receiver mode "
				"requires two argument");
			goto out;
		} else if (strcmp(argv[0], ".")) {
			ERRX(opts, "first argument must "
				"be a standalone period");
			goto out;
		}

		c = rsync_receiver(opts, 
			&sess, fdin, fdout, argv[1]);
		if ( ! c)
			ERRX1(opts, "rsync_receiver");
	}

out:
	return c;
}

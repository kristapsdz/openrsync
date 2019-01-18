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
#include <sys/socket.h>

#include <err.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

int
main(int argc, char *argv[])
{
	struct opts	opts;
	pid_t	 	child;
	int	 	fds[2], flags, c;
	struct option	lopts[] = {
		{ "server",	no_argument,	&opts.server,	1 },
		{ "sender",	no_argument,	&opts.sender,	1 },
		{ "checksum-choice", required_argument,	NULL,	0 },
		{ NULL,		0,		NULL,		0 }};

	/* 
	 * Global pledge.
	 * This takes into account all possible pledge paths.
	 */

	if (-1 == pledge("unveil exec stdio rpath wpath cpath proc fattr", NULL))
		err(EXIT_FAILURE, "pledge");

	memset(&opts, 0, sizeof(struct opts));

	while (-1 != (c = getopt_long(argc, argv, "e:nptv", lopts, NULL)))
		switch (c) {
		case 'e':
			/* Ignore. */
			break;
		case 'n':
			opts.dry_run = 1;
			break;
		case 'p':
			opts.preserve_perms = 1;
			break;
		case 't':
			opts.preserve_times = 1;
			break;
		case 'v':
			opts.verbose++;
			break;
		case 0:
			break;
		default:
			goto usage;
		}

	argc -= optind;
	argv += optind;

	/* FIXME: GNU rsync accepts this. */

	if (argc < 2)
		goto usage;

	/*
	 * This is what happens when we're started with the "hidden"
	 * --server option, which is invoked for the rsync on the remote
	 * host by the parent.
	 */

	if (opts.server) {
		if (-1 == pledge("unveil rpath cpath wpath stdio fattr", NULL))
			err(EXIT_FAILURE, "pledge");
		c = rsync_server(&opts, (size_t)argc, argv);
		return c ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	/* 
	 * Now we know that we're the client on the local machine
	 * invoking rsync(1).
	 * At this point, we need to start the client and server
	 * initiation logic.
	 * The client is what we continue running on this host; the
	 * server is what we'll use to connect to the remote and
	 * invoke rsync with the --server option.
	 */

	flags = SOCK_STREAM | SOCK_NONBLOCK;

	if (-1 == socketpair(AF_UNIX, flags, 0, fds))
		err(EXIT_FAILURE, "socketpair");

	if (-1 == (child = fork())) {
		close(fds[0]);
		close(fds[1]);
		err(EXIT_FAILURE, "fork");
	}

	/* Drop the fork possibility. */

	if (-1 == pledge("unveil exec stdio rpath wpath cpath fattr", NULL)) {
		ERR(&opts, "pledge");
		exit(EXIT_FAILURE);
	}

	if (0 == child) {
		close(fds[0]);
		fds[0] = -1;
		if (-1 == pledge("exec stdio", NULL))
			err(EXIT_FAILURE, "pledge");
		rsync_child(&opts, fds[1], (size_t)argc, argv);
		/* NOTREACHED */
	}

	close(fds[1]);
	fds[1] = -1;
	if (-1 == pledge("unveil rpath cpath wpath stdio fattr", NULL))
		err(EXIT_FAILURE, "pledge");
	c = rsync_client(&opts, fds[0], (size_t)argc, argv);
	close(fds[0]);

	/* FIXME: waitpid. */

	return c ? EXIT_SUCCESS : EXIT_FAILURE;
usage:
	fprintf(stderr, "usage: %s [-nptv] src ... dst\n", getprogname());
	return EXIT_FAILURE;
}

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
#include <sys/wait.h>

#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

static void
fargs_free(struct fargs *p)
{
	size_t	 i;

	if (NULL == p)
		return;

	if (NULL != p->sources)
		for (i = 0; i < p->sourcesz; i++)
			free(p->sources[i]);

	free(p->sources);
	free(p->sink);
	free(p->host);
	free(p);
}

/*
 * A remote host is has a colon before the first path separator.
 * This works for rsh remote hosts (host:/foo/bar), implicit rsync
 * remote hosts (host::/foo/bar), and explicit (rsync://host/foo).
 * Return zero if local, non-zero if remote.
 */
static int
fargs_is_remote(const char *v)
{
	size_t	 pos;

	pos = strcspn(v, ":/");
	return ':' == v[pos];
}

/*
 * Test whether a remote host is specifically an rsync daemon.
 * Return zero if not, non-zero if so.
 */
static int
fargs_is_daemon(const char *v)
{
	size_t	 pos;

	if (0 == strncasecmp(v, "rsync://", 8))
		return 1;

	pos = strcspn(v, ":/");
	return ':' == v[pos] && ':' == v[pos + 1];
}

/*
 * Take the command-line filenames (e.g., rsync foo/ bar/ baz/) and
 * determine our operating mode.
 * For example, if the first argument is a remote file, this means that
 * we're going to transfer from the remote to the local.
 * We also make sure that the arguments are consistent, that is, if
 * we're going to transfer from the local to the remote, that no
 * filenames for the local transfer indicate remote hosts.
 * Always returns the parsed and sanitised options.
 */
static struct fargs *
fargs_parse(size_t argc, char *argv[])
{
	struct fargs	*f = NULL;
	char		*cp;
	size_t		 i, j, len = 0;

	/* Allocations. */

	if (NULL == (f = calloc(1, sizeof(struct fargs))))
		err(EXIT_FAILURE, "calloc");

	f->sourcesz = argc - 1;
	if (NULL == (f->sources = calloc(f->sourcesz, sizeof(char *))))
		err(EXIT_FAILURE, "calloc");

	for (i = 0; i < argc - 1; i++)
		if (NULL == (f->sources[i] = strdup(argv[i])))
			err(EXIT_FAILURE, "strdup");

	if (NULL == (f->sink = strdup(argv[i])))
		err(EXIT_FAILURE, "strdup");

	/*
	 * Test files for its locality.
	 * If the last is a remote host, then we're sending from the
	 * local to the remote host ("sender" mode).
	 * If the first, remote to local ("receiver" mode).
	 * If neither, a local transfer in sender style.
	 */

	f->mode = FARGS_LOCAL;

	if (fargs_is_remote(f->sink))
		f->mode = FARGS_SENDER;

	if (fargs_is_remote(f->sources[0])) {
		if (FARGS_SENDER == f->mode)
			errx(EXIT_FAILURE, "both source and "
				"destination cannot be remote files");
		f->mode = FARGS_RECEIVER;
	}

	/*
	 * Set our remote host depending upon the mode.
	 * Save the host, which is the NUL-terminated host name, and the
	 * buffer from which we got it that includes the colon.
	 */

	if (FARGS_RECEIVER == f->mode)
		f->host = strdup(argv[0]);
	else if (FARGS_SENDER == f->mode)
		f->host = strdup(argv[argc - 1]);

	if (FARGS_LOCAL != f->mode && NULL == f->host)
		err(EXIT_FAILURE, "strdup");

	if (NULL != f->host) {
		if (0 == strncasecmp(f->host, "rsync://", 8)) {
			/* rsync://host/module[/path] */
			f->remote = 1;
			len = strlen(f->host) - 8 + 1;
			memmove(f->host, f->host + 8, len);
			if (NULL == (cp = strchr(f->host, '/')))
				errx(EXIT_FAILURE, "rsync protocol "
					"requires a module name");
			*cp++ = '\0';
			f->module = cp;
			if (NULL != (cp = strchr(f->module, '/')))
				*cp = '\0';
		} else {
			/* host:[/path] */
			cp = strchr(f->host, ':');
			assert(NULL != cp);
			*cp++ = '\0';
			if (':' == *cp) {
				/* host::module[/path] */
				f->remote = 1;
				f->module = ++cp;
				cp = strchr(f->module, '/');
				if (NULL != cp)
					*cp = '\0';
			}
		}
		if (0 == (len = strlen(f->host)))
			errx(EXIT_FAILURE, "empty remote host");
		if (f->remote && 0 == strlen(f->module))
			errx(EXIT_FAILURE, "empty remote module");
	}

	/* Make sure we have the same "hostspec" for all files. */

	if ( ! f->remote) {
		if (FARGS_SENDER == f->mode ||
		    FARGS_LOCAL == f->mode)
			for (i = 0; i < f->sourcesz; i++) {
				if ( ! fargs_is_remote(f->sources[i]))
					continue;
				errx(EXIT_FAILURE, "remote file in "
					"list of local sources: %s",
					f->sources[i]);
			}
		if (FARGS_RECEIVER == f->mode)
			for (i = 0; i < f->sourcesz; i++) {
				if (fargs_is_remote(f->sources[i]) &&
				    ! fargs_is_daemon(f->sources[i]))
					continue;
				if (fargs_is_daemon(f->sources[i]))
					errx(EXIT_FAILURE, "remote "
						"daemon in list of "
						"remote sources: %s",
						f->sources[i]);
				errx(EXIT_FAILURE, "local file in "
					"list of remote sources: %s",
					f->sources[i]);
			}
	} else {
		if (FARGS_RECEIVER != f->mode)
			errx(EXIT_FAILURE, "sender mode for remote "
				"daemon receivers not yet supported");
		for (i = 0; i < f->sourcesz; i++) {
			if (fargs_is_daemon(f->sources[i]))
				continue;
			errx(EXIT_FAILURE, "non-remote daemon file "
				"in list of remote daemon sources: "
				"%s", f->sources[i]);
		}
	}

	/*
	 * If we're not remote and a sender, strip our hostname.
	 * Then exit if we're a sender or a local connection.
	 */

	if ( ! f->remote) {
		if (FARGS_SENDER == f->mode) {
			assert(NULL != f->host);
			assert(len > 0);
			j = strlen(f->sink);
			memmove(f->sink, f->sink + len + 1, j - len);
			return f;
		} else if (FARGS_RECEIVER != f->mode)
			return f;
	}

	/*
	 * Now strip the hostnames from the remote host.
	 *   rsync://host/module/path -> module/path
	 *   host::module/path -> module/path
	 *   host:path -> path
	 * Also make sure that the remote hosts are the same.
	 */

	assert(NULL != f->host);
	assert(len > 0);

	for (i = 0; i < f->sourcesz; i++) {
		cp = f->sources[i];
		j = strlen(cp);
		if (f->remote &&
		    0 == strncasecmp(cp, "rsync://", 8)) {
			/* rsync://path */
			cp += 8;
			if (strncmp(cp, f->host, len) ||
			    ('/' != cp[len] && '\0' != cp[len]))
				errx(EXIT_FAILURE, "different remote "
					"host: %s", f->sources[i]);
			memmove(f->sources[i],
				f->sources[i] + len + 8 + 1,
				j - len - 8);
		} else if (f->remote && 0 == strncmp(cp, "::", 2)) {
			/* ::path */
			memmove(f->sources[i],
				f->sources[i] + 2, j - 1);
		} else if (f->remote) {
			/* host::path */
			if (strncmp(cp, f->host, len) ||
			    (':' != cp[len] && '\0' != cp[len]))
				errx(EXIT_FAILURE, "different remote "
					"host: %s", f->sources[i]);
			memmove(f->sources[i],
				f->sources[i] + len + 2,
				j - len - 1);
		} else if (':' == cp[0]) {
			/* :path */
			memmove(f->sources[i], f->sources[i] + 1, j);
		} else {
			/* host:path */
			if (strncmp(cp, f->host, len) ||
			    (':' != cp[len] && '\0' != cp[len]))
				errx(EXIT_FAILURE, "different remote "
					"host: %s", f->sources[i]);
			memmove(f->sources[i],
				f->sources[i] + len + 1, j - len);
		}
	}

	return f;
}

int
main(int argc, char *argv[])
{
	struct opts	 opts;
	pid_t	 	 child;
	int	 	 fds[2], flags, c, st;
	struct fargs	*fargs;
	struct option	 lopts[] = {
		{ "server",	no_argument,	&opts.server,	1 },
		{ "sender",	no_argument,	&opts.sender,	1 },
		{ "checksum-choice", required_argument,	NULL,	0 },
		{ NULL,		0,		NULL,		0 }};

	/* Global pledge. */

	if (-1 == pledge("dns inet unveil exec stdio rpath wpath cpath proc fattr", NULL))
		err(EXIT_FAILURE, "pledge");

	memset(&opts, 0, sizeof(struct opts));

	for (;;) {
		c = getopt_long(argc, argv, "e:lnprtv", lopts, NULL);
		if (-1 == c)
			break;
		switch (c) {
		case 'e':
			/* Ignore. */
			break;
		case 'l':
			opts.preserve_links = 1;
			break;
		case 'n':
			opts.dry_run = 1;
			break;
		case 'p':
			opts.preserve_perms = 1;
			break;
		case 'r':
			opts.recursive = 1;
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
	}

	argc -= optind;
	argv += optind;

	/* FIXME: reference implementation rsync accepts this. */

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

	fargs = fargs_parse(argc, argv);
	assert(NULL != fargs);

	/*
	 * If we're contacting an rsync:// daemon, then we don't need to
	 * fork, because we won't start a server ourselves.
	 * Route directly into the socket code, in that case.
	 */

	if (fargs->remote) {
		assert(FARGS_RECEIVER == fargs->mode);
		if (-1 == pledge("dns inet unveil stdio rpath wpath cpath fattr", NULL))
			err(EXIT_FAILURE, "pledge");
		c = rsync_socket(&opts, fargs);
		fargs_free(fargs);
		return c ? EXIT_SUCCESS : EXIT_FAILURE;
	}

	/* Drop the dns/inet possibility. */

	if (-1 == pledge("unveil exec stdio rpath wpath cpath proc fattr", NULL))
		err(EXIT_FAILURE, "pledge");

	/* Create a bidirectional socket and start our child. */

	flags = SOCK_STREAM | SOCK_NONBLOCK;

	if (-1 == socketpair(AF_UNIX, flags, 0, fds))
		err(EXIT_FAILURE, "socketpair");

	if (-1 == (child = fork())) {
		close(fds[0]);
		close(fds[1]);
		err(EXIT_FAILURE, "fork");
	}

	/* Drop the fork possibility. */

	if (-1 == pledge("unveil exec stdio rpath wpath cpath fattr", NULL))
		err(EXIT_FAILURE, "pledge");

	if (0 == child) {
		close(fds[0]);
		fds[0] = -1;
		if (-1 == pledge("exec stdio", NULL))
			err(EXIT_FAILURE, "pledge");
		rsync_child(&opts, fds[1], fargs);
		/* NOTREACHED */
	}

	close(fds[1]);
	fds[1] = -1;
	if (-1 == pledge("unveil rpath cpath wpath stdio fattr", NULL))
		err(EXIT_FAILURE, "pledge");
	c = rsync_client(&opts, fds[0], fargs);
	fargs_free(fargs);
	close(fds[0]);

	if (-1 == waitpid(child, &st, 0))
		err(EXIT_FAILURE, "waitpid");

	if ( ! (WIFEXITED(st) && EXIT_SUCCESS == WEXITSTATUS(st)))
		c = 0;

	return c ? EXIT_SUCCESS : EXIT_FAILURE;
usage:
	fprintf(stderr, "usage: %s [-lnprtv] src ... dst\n",
		getprogname());
	return EXIT_FAILURE;
}

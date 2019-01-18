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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

/*
 * Convert an fargs into a command-line suitable for invoking rsync on a
 * remote machine.
 * This goes from the input to "ssh foo rsync...".
 * Returns the NULL-terminated array unless an error occurs, which
 * should always be considered fatal.
 */
char **
fargs_cmdline(const struct opts *opts, const struct fargs *f)
{
	char	**args;
	size_t	  i = 0, j, argsz = 0;

	assert(NULL != f);
	assert(f->sourcesz > 0);

	/* Be explicit with array size. */

	argsz += 1; 	/* dot separator */
	argsz += 1; 	/* sink file */
	argsz += 5; 	/* per-mode maximum */
	argsz += 10;	/* shared args */
	argsz += 1;	/* NULL pointer */
	argsz += f->sourcesz;

	args = calloc(argsz, sizeof(char *));
	if (NULL == args) {
		ERR(opts, "calloc");
		return NULL;
	}

	if (FARGS_RECEIVER == f->mode || FARGS_SENDER == f->mode) {
		assert(NULL != f->host);
		args[i++] = "ssh";
		args[i++] = f->host;
		args[i++] = "rsync";
		args[i++] = "--server";
		if (FARGS_RECEIVER == f->mode)
			args[i++] = "--sender";
	} else {
		args[i++] = "rsync";
		args[i++] = "--server";
	}

	/* Shared arguments. */

	if (opts->verbose > 3)
		args[i++] = "-v";
	if (opts->verbose > 2)
		args[i++] = "-v";
	if (opts->verbose > 1)
		args[i++] = "-v";
	if (opts->verbose > 0)
		args[i++] = "-v";
	if (opts->dry_run)
		args[i++] = "-n";
	if (opts->preserve_times)
		args[i++] = "-t";
	if (opts->preserve_perms)
		args[i++] = "-p";
	if (opts->recursive)
		args[i++] = "-r";

	/*
	 * This is for reference implementation rsync servers.
	 * We want to use an old protocol, but the old implementation of
	 * MD4 was also broken in a way we don't want to support.
	 * Force it to use MD5, even though we'll stipulate that we use
	 * the old protocol.
	 */

	args[i++] = "--checksum-choice";
	args[i++] = "md5";

	/* Terminate with a full-stop for reasons unknown. */

	args[i++] = ".";

	if (FARGS_RECEIVER == f->mode) {
		for (j = 0; j < f->sourcesz; j++)
			args[i++] = f->sources[j];
	} else
		args[i++] = f->sink;

	args[i] = NULL;
	return args;
}

/*
 * This is run on the client machine to initiate a connection with the
 * remote machine in --server mode.
 * It does not return, as it executes into the remote shell.
 *
 * Pledges: exec, stdio.
 */
void
rsync_child(const struct opts *opts, int fd, size_t argc, char *argv[])
{
	struct fargs	 *f;
	char 		**args;
	size_t		  i;

	assert(argc > 1);

	/*
	 * Parse the files we want from the command-line, then construct
	 * the remote shell command from that information.
	 */

	if (NULL == (f = fargs_parse(opts, argc, argv))) {
		ERRX1(opts, "fargs_parse");
		exit(EXIT_FAILURE);
	} else if (NULL == (args = fargs_cmdline(opts, f))) {
		ERRX1(opts, "fargs_cmdline");
		exit(EXIT_FAILURE);
	}

	for (i = 0; NULL != args[i]; i++) 
		LOG2(opts, "exec[%zu] = %s", i, args[i]);

	/* Make sure the child's stdin is from the sender. */

	if (-1 == dup2(fd, STDIN_FILENO)) {
		ERR(opts, "dup2");
		exit(EXIT_FAILURE);
	} if (-1 == dup2(fd, STDOUT_FILENO)) {
		ERR(opts, "dup2");
		exit(EXIT_FAILURE);
	}

	/* Here we go... */

	execvp(args[0], args);

	ERR(opts, "execvp: %s", args[0]);
	exit(EXIT_FAILURE);
	/* NOTREACHED */
}

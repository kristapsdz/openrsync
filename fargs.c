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
#include <stdlib.h>
#include <string.h>

#include "extern.h"

/*
 * A remote host is has a colon before the first path separator.
 * Return zero if local, non-zero if remote.
 */
static int
fargs_is_remote(const char *v)
{
	size_t	 pos;

	pos = strcspn(v, ":/");
	return ':' == v[pos];
}

void
fargs_free(struct fargs *p)
{
	size_t	 i;

	if (NULL == p)
		return;

	for (i = 0; i < p->sourcesz; i++)
		free(p->sources[i]);

	free(p->sources);
	free(p->sink);
	free(p->host);
	free(p);
}

/*
 * Take the command-line filenames (e.g., rsync foo/ bar/ baz/) and
 * determine our operating mode.
 * For example, if the first argument is a remote file, this means that
 * we're going to transfer from the remote to the local.
 * We also make sure that the arguments are consistent, that is, if
 * we're going to transfer from the local to the remote, that no
 * filenames for the local transfer indicate remote hosts.
 * Returns the parsed and sanitised options or NULL on failure (always
 * fatal regardless).
 */
struct fargs *
fargs_parse(const struct opts *opts, size_t argc, char *argv[])
{
	struct fargs	 *f = NULL;
	char		 *cp;
	size_t		  i, j, len;

	assert(argc > 1);

	/* Sanity-check: no rsync:// or plain :: arguments. */

	for (i = 0; i < argc; i++) {
		if (0 == strncmp(argv[i], "rsync://", 8)) {
			ERRX(opts, "rsync protocol sources "
				"not supported: %s", argv[i]);
			return NULL;
		}
		j = strcspn(argv[i], ":/");
		if (':' == argv[i][j] && ':' == argv[i][j + 1]) {
			ERRX(opts, "rsync protocol (implicit) "
				"sources not supported: %s", argv[i]);
			return NULL;
		}
	}

	/* Allocations. */

	if (NULL == (f = calloc(1, sizeof(struct fargs)))) {
		ERR(opts, "calloc");
		return NULL;
	}

	f->sourcesz = argc - 1;
	if (NULL == (f->sources = calloc(f->sourcesz, sizeof(char *)))) {
		ERR(opts, "calloc");
		fargs_free(f);
		return NULL;
	}

	for (i = 0; i < argc - 1; i++)
		if (NULL == (f->sources[i] = strdup(argv[i]))) {
			ERR(opts, "strdup");
			fargs_free(f);
			return NULL;
		}

	if (NULL == (f->sink = strdup(argv[i]))) {
		ERR(opts, "strdup");
		fargs_free(f);
		return NULL;
	}

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
		if (FARGS_SENDER == f->mode) {
			ERRX(opts, "both source and destination "
				"cannot be remote files");
			fargs_free(f);
			return NULL;
		}
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

	if (FARGS_LOCAL != f->mode && NULL == f->host) {
		ERR(opts, "strdup");
		fargs_free(f);
		return NULL;
	}

	if (NULL != f->host) {
		cp = strchr(f->host, ':');
		assert(NULL != cp);
		*cp = '\0';
		if (0 == (len = strlen(f->host))) {
			ERRX(opts, "empty remote host");
			fargs_free(f);
			return NULL;
		}
	}

	/* Sanity check: mix of remote and local files. */

	if (FARGS_SENDER == f->mode || FARGS_LOCAL == f->mode)
		for (i = 0; i < f->sourcesz; i++)
			if (fargs_is_remote(f->sources[i])) {
				ERRX(opts, "remote file in list of "
					"local sources: %s", 
					f->sources[i]);
				fargs_free(f);
				return NULL;
			}

	if (FARGS_RECEIVER == f->mode)
		for (i = 0; i < f->sourcesz; i++)
			if ( ! fargs_is_remote(f->sources[i])) {
				ERRX(opts, "local file in list of "
					"remote sources: %s", 
					f->sources[i]);
				fargs_free(f);
				return NULL;
			}

	/* Now strip our hostname. */

	if (FARGS_SENDER == f->mode) {
		assert(NULL != f->host);
		assert(len > 0);
		j = strlen(f->sink);
		memmove(f->sink, f->sink + len + 1, j - len);
	} else if (FARGS_RECEIVER == f->mode) {
		assert(NULL != f->host);
		assert(len > 0);
		for (i = 0; i < f->sourcesz; i++) {
			j = strlen(f->sources[i]);
			if (':' == f->sources[i][0]) {
				memmove(f->sources[i],
					f->sources[i] + 1,
					j);
				continue;
			}
			if (strncmp(f->sources[i], f->host, len) ||
			    ':' != f->sources[i][len]) {
				ERRX(opts, "remote host does not "
					"match %s, %s", f->host, 
					f->sources[i]);
				fargs_free(f);
				return NULL;
			} 
			memmove(f->sources[i], 
				f->sources[i] + len + 1,
				j - len);
		}
	}

	return f;
}

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
	argsz += 7;	/* shared args */
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

	/*
	 * This is for GNU rsync servers.
	 * We want to use an old protocol, but the old implementation of
	 * MD4 was also broken in a way we don't want to support.
	 * Force it to use MD5, even though we'll stipulate that we use
	 * the old protocol.
	 */

	args[i++] = "--checksum-choice";
	args[i++] = "md5";

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

	args[i++] = ".";

	if (FARGS_RECEIVER == f->mode) {
		for (j = 0; j < f->sourcesz; j++)
			args[i++] = f->sources[j];
	} else
		args[i++] = f->sink;

	args[i] = NULL;
	return args;
}

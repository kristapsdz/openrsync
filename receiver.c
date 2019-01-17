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

#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

/*
 * At the end of the transmission, we have some statistics to read.
 * Return zero on failure, non-zero on success.
 */
static int
stats(const struct opts *opts, int fdin)
{
	size_t	 tread, twrite, tsize;

	/* No statistics in server mode. */

	if (opts->server)
		return 1;

	if ( ! io_read_size(opts, fdin, &tread)) {
		ERRX1(opts, "io_read_size: total read");
		return 0;
	} else if ( ! io_read_size(opts, fdin, &twrite)) {
		ERRX1(opts, "io_read_size: total write");
		return 0;
	} else if ( ! io_read_size(opts, fdin, &tsize)) {
		ERRX1(opts, "io_read_size: total size");
		return 0;
	} 

	LOG1(opts, "stats: %zu B read, %zu B written, %zu B size",
		tread, twrite, tsize);
	return 1;
}

/*
 * The receiver code is run on the machine that will actually write data
 * to its discs.
 * It processes all files requests and sends block hashes to the sender,
 * then waits to get the missing pieces.
 * It writes into a temporary file, then renames the temporary file.
 * Return zero on failure, non-zero on success.
 *
 * Pledges: unveil, rpath, cpath, wpath, stdio.
 */
int
rsync_receiver(const struct opts *opts, const struct sess *sess, 
	int fdin, int fdout, const char *root)
{
	struct flist	*fl = NULL;
	size_t		 i, flsz = 0, csum_length = CSUM_LENGTH_PHASE1;
	char		*tofree;
	int		 rc = 0, dfd = -1, phase = 0;
	int32_t	 	 ioerror, idx;

	if (-1 == pledge("unveil rpath cpath wpath stdio", NULL)) {
		ERR(opts, "pledge");
		goto out;
	}

	umask(0);

	/* XXX: what does this do? */

	if ( ! opts->server) {
		if ( ! io_write_int(opts, fdout, 0)) {
			ERRX1(opts, "io_write_int: zero premable");
			goto out;
		} 
	}

	/*
	 * Start by receiving the list of filenames.
	 * These we're going to be touching on our local system.
	 */

	if (NULL == (fl = flist_recv(opts, fdin, &flsz))) {
		ERRX1(opts, "flist_recv");
		goto out;
	} else if ( ! io_read_int(opts, fdin, &ioerror)) {
		ERRX1(opts, "io_read_int: io_error");
		goto out;
	} else if (0 != ioerror) {
		ERRX1(opts, "io_error is non-zero");
		goto out;
	}

	/* Create the path for our destination directory. */

	if (NULL == (tofree = strdup(root))) {
		ERR(opts, "strdup");
		goto out;
	} else if (mkpath(opts, tofree) < 0) {
		ERRX1(opts, "mkpath: %s", root);
		free(tofree);
		goto out;
	}
	free(tofree);

	/*
	 * Make our entire view of the file-system be limited to what's
	 * in the root directory.
	 * This prevents us from accidentally (or "under the influence")
	 * writing into other parts of the file-system.
	 */

	if (-1 == unveil(root, "rwc")) {
		ERR(opts, "unveil: %s", root);
		goto out;
	} else if (-1 == unveil(NULL, NULL)) {
		ERR(opts, "unveil: %s", root);
		goto out;
	}

	/* 
	 * Open the destination directory.
	 * This will be the basis of all future files.
	 */

	if (-1 == (dfd = open(root, O_RDONLY | O_DIRECTORY, 0))) {
		ERR(opts, "open: %s", root);
		goto out;
	}

	/*
	 * FIXME: I never use the full checksum amount; but if I were,
	 * here is where the "again" label would go.
	 * This has been demonstrated to work, but I just don't use it
	 * til I understand the need.
	 */

	LOG2(opts, "receiver ready for %zu-checksum "
		"data: %s", csum_length, root);

	for (i = 0; i < flsz; i++) {
		if ( ! io_write_int(opts, fdout, i)) {
			ERRX1(opts, "io_write_int: index");
			goto out;
		}

		/* Dry-run short circuits. */

		if (opts->dry_run) {
			if ( ! io_read_int(opts, fdin, &idx)) {
				ERRX1(opts, "io_read_int: "
					"send ack (dry-run)");
				goto out;
			} else if (idx < 0 || (size_t)idx != i) {
				ERRX(opts, "wrong index value "
					"received from sender");
				goto out;
			}
			continue;
		}

		/* 
		 * Now synchronise the local to the remote.
		 * This performs most of the work.
		 */

		if ( ! blk_send(opts, fdin, fdout, 
		    dfd, &fl[i], i, sess, csum_length)) {
			ERRX1(opts, "blk_send");
			goto out;
		}
	}

	/* Properly close us out by progressing through the phases. */

	if (0 == phase) {
		if ( ! io_write_int(opts, fdout, -1)) {
			ERRX1(opts, "io_write_int: index");
			goto out;
		} else if ( ! io_read_int(opts, fdin, &ioerror)) {
			ERRX1(opts, "io_read_int: phase ack");
			goto out;
		} else if (-1 != ioerror) {
			ERRX(opts, "expected phase ack");
			goto out;
		}
		phase++;
		csum_length = CSUM_LENGTH_PHASE2;

		/* 
		 * FIXME: under what conditions should we resend files?
		 * What kind of failure?  This is never specified.
		 * goto again;
		 */
	}

	if (1 == phase) {
		if ( ! io_write_int(opts, fdout, -1)) {
			ERRX1(opts, "io_write_int: send complete");
			goto out;
		} else if ( ! io_read_int(opts, fdin, &ioerror)) {
			ERRX1(opts, "io_read_int: phase ack");
			goto out;
		} else if (-1 != ioerror) {
			ERRX(opts, "expected phase ack");
			goto out;
		}
		phase++;
	}

	if ( ! stats(opts, fdin)) {
		ERRX1(opts, "stats");
		goto out;
	}

	LOG2(opts, "receiver finished updating");
	rc = 1;
out:
	if (-1 != dfd)
		close(dfd);
	flist_free(fl, flsz);
	return rc;
}

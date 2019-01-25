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
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

/*
 * The rsync client runs on the operator's local machine.
 * It can either be in sender or receiver mode.
 * In the former, it synchronises local files from a remote sink.
 * In the latter, the remote sink synchronses to the local files.
 *
 * Pledges: stdio, rpath, wpath, cpath, unveil, fattr.
 *
 * Pledges (dry-run): -cpath, -wpath, -fattr.
 * Pledges (!preserve_times): -fattr.
 */
int
rsync_client(const struct opts *opts, int fd, const struct fargs *f)
{
	struct sess	 sess;
	int		 rc = 0;

	/* Standard rsync preamble, sender side. */

	memset(&sess, 0, sizeof(struct sess));
	sess.opts = opts;
	sess.lver = RSYNC_PROTOCOL;

	if ( ! io_write_int(&sess, fd, sess.lver)) {
		ERRX1(&sess, "io_write_int: version");
		goto out;
	} else if ( ! io_read_int(&sess, fd, &sess.rver)) {
		ERRX1(&sess, "io_read_int: version");
		goto out;
	} else if ( ! io_read_int(&sess, fd, &sess.seed)) {
		ERRX1(&sess, "io_read_int: seed");
		goto out;
	}

	if (sess.rver < sess.lver) {
		ERRX(&sess, "remote protocol is older "
			"than our own (%" PRId32 " < %" PRId32 "): "
			"this is not supported",
			sess.rver, sess.lver);
		goto out;
	}

	LOG2(&sess, "client detected client version %" PRId32
		", server version %" PRId32 ", seed %" PRId32,
		sess.lver, sess.rver, sess.seed);

	sess.mplex_reads = 1;

	/*
	 * Now we need to get our list of files.
	 * Senders (and locals) send; receivers receive.
	 */

	if (FARGS_RECEIVER != f->mode) {
		LOG2(&sess, "client starting sender: %s",
			NULL == f->host ? "(local?)" : f->host);
		if ( ! rsync_sender(&sess, fd, fd,
				f->sourcesz, f->sources)) {
			ERRX1(&sess, "rsync_sender");
			goto out;
		}
	} else {
		LOG2(&sess, "client starting receiver: %s",
			NULL == f->host ? "(local?)" : f->host);
		if ( ! rsync_receiver(&sess, fd, fd, f->sink)) {
			ERRX1(&sess, "rsync_receiver");
			goto out;
		}
	}

	if (io_read_check(&sess, fd))
		WARNX(&sess, "data remains in read pipe");

	rc = 1;
out:
	return rc;
}

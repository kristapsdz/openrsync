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

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if HAVE_ERR
# include <err.h>
#endif

#include "extern.h"

/*
 * The rsync client runs on the operator's local machine.
 * It can either be in sender or receiver mode.
 * In the former, it synchronises local files from a remote sink.
 * In the latter, the remote sink synchronses to the local files.
 * Returns exit code 0 on success, 1 on failure, 2 on failure with
 * incompatible protocols.
 */
int
rsync_client(const struct opts *opts, int fd, const struct fargs *f)
{
	struct sess	 sess;
	int		 rc = 1;

	/* Standard rsync preamble, sender side. */

	if (pledge("stdio unix rpath wpath cpath dpath fattr chown getpw unveil",
	    NULL) == -1)
		err(ERR_IPC, "pledge");

	memset(&sess, 0, sizeof(struct sess));
	sess.opts = opts;
	sess.mode = f->mode;
	sess.lver = sess.protocol = RSYNC_PROTOCOL;

	LOG4("Printing(%d): itemize %d late %d", getpid(), 0, 0);

	if (!io_write_int(&sess, fd, sess.lver)) {
		ERRX1("io_write_int");
		goto out;
	} else if (!io_read_int(&sess, fd, &sess.rver)) {
		ERRX1("io_read_int");
		goto out;
	} else if (!io_read_int(&sess, fd, &sess.seed)) {
		ERRX1("io_read_int");
		goto out;
	}

	if (sess.rver < sess.lver) {
		ERRX("remote protocol %d is older than our own %d: "
		    "unsupported", sess.rver, sess.lver);
		rc = 2;
		goto out;
	}

	LOG3("client detected client version %d, server version %d, "
	    "negotiated protocol version %d, seed %d",
	    sess.lver, sess.rver, sess.protocol, sess.seed);

	sess.mplex_reads = 1;

	if (verbose > 1 && f->mode == FARGS_RECEIVER)
		LOG0("Delta transmission %s for this transfer",
		    sess.opts->whole_file ? "disabled" : "enabled");

	/*
	 * Now we need to get our list of files.
	 * Senders (and locals) send; receivers receive.
	 */

	if (f->mode != FARGS_RECEIVER) {
		LOG3("client starting sender: %s",
		    f->host == NULL ? "(local)" : f->host);

		sess.lreceiver = (f->host == NULL);

		if (!rsync_sender(&sess, fd, fd, f->sourcesz,
		    f->sources)) {
			ERRX1("rsync_sender");
			goto out;
		}
	} else {
		LOG3("client starting receiver: %s",
		    f->host == NULL ? "(local)" : f->host);

		sess.lreceiver = true;

		if (!rsync_receiver(&sess, fd, fd, f->sink)) {
			ERRX1("rsync_receiver");
			goto out;
		}
	}

	/*
	 * Make sure we flush out any remaining log messages or whatnot
	 * before we leave.  This is especially important with higher
	 * verbosity levels as smb rsync will be a lot more chatty with
	 * non-data messages over the wire.  If there's still
	 * data-tagged messages in after a flush, then.
	 */

	rc = 0;
	if (!io_read_close(&sess, fd)) {
		if (sess.mplex_read_remain > 0)
			ERRX1("data remains in read pipe");
		rc = ERR_IPC;
	}
out:
	sess_cleanup(&sess);
	return rc;
}

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

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "extern.h"

/*
 * Accept how much we've read, written, and file-size, and print them in
 * a human-readable fashion (with GB, MB, etc. prefixes).
 * This only prints as the client.
 */
static void
stats_log(struct sess *sess,
	uint64_t tread, uint64_t twrite, uint64_t tsize)
{
	double		 tr, tw, ts;
	const char	*tru = "B", *twu = "B", *tsu = "B";
	int		 trsz = 0, twsz = 0, tssz = 0;

	assert(verbose);
	if (sess->opts->server)
		return;

	if (tread >= 1024 * 1024 * 1024) {
		tr = tread / (1024.0 * 1024.0 * 1024.0);
		tru = "GB";
		trsz = 3;
	} else if (tread >= 1024 * 1024) {
		tr = tread / (1024.0 * 1024.0);
		tru = "MB";
		trsz = 2;
	} else if (tread >= 1024) {
		tr = tread / 1024.0;
		tru = "KB";
		trsz = 1;
	} else
		tr = tread;

	if (twrite >= 1024 * 1024 * 1024) {
		tw = twrite / (1024.0 * 1024.0 * 1024.0);
		twu = "GB";
		twsz = 3;
	} else if (twrite >= 1024 * 1024) {
		tw = twrite / (1024.0 * 1024.0);
		twu = "MB";
		twsz = 2;
	} else if (twrite >= 1024) {
		tw = twrite / 1024.0;
		twu = "KB";
		twsz = 1;
	} else
		tw = twrite;

	if (tsize >= 1024 * 1024 * 1024) {
		ts = tsize / (1024.0 * 1024.0 * 1024.0);
		tsu = "GB";
		tssz = 3;
	} else if (tsize >= 1024 * 1024) {
		ts = tsize / (1024.0 * 1024.0);
		tsu = "MB";
		tssz = 2;
	} else if (tsize >= 1024) {
		ts = tsize / 1024.0;
		tsu = "KB";
		tssz = 1;
	} else
		ts = tsize;

	LOG1("Transfer complete: "
	    "%.*lf %s sent, %.*lf %s read, %.*lf %s file size",
	    trsz, tr, tru,
	    twsz, tw, twu,
	    tssz, ts, tsu);
}

/*
 * At the end of transmission, we write our statistics if we're the
 * server, then log only if we're not the server.
 * Either way, only do this if we're in verbose mode.
 * Returns false on failure, true on success.
 */
bool
sess_stats_send(struct sess *sess, int fd)
{
	uint64_t	 tw, tr, ts;

	tw = sess->total_write;
	tr = sess->total_read;
	ts = sess->total_size;

	if (verbose > 0)
		stats_log(sess, tr, tw, ts);

	if (!sess->opts->server && verbose == 0)
		return true;

	if (sess->opts->server) {
		if (!io_write_ulong(sess, fd, tr)) {
			ERRX1("io_write_ulong");
			return false;
		} else if (!io_write_ulong(sess, fd, tw)) {
			ERRX1("io_write_ulong");
			return false;
		} else if (!io_write_ulong(sess, fd, ts)) {
			ERRX1("io_write_ulong");
			return false;
		}
	}

	return true;
}

/*
 * At the end of the transmission, we have some statistics to read.
 * Only do this (1) if we're in verbose mode and (2) if we're the
 * server.
 * Then log the findings.
 * Return false on failure, true on success.
 */
bool
sess_stats_recv(struct sess *sess, int fd)
{
	uint64_t tr, tw, ts;

	if (sess->opts->server)
		return true;

	if (!io_read_ulong(sess, fd, &tw)) {
		ERRX1("io_read_ulong");
		return false;
	} else if (!io_read_ulong(sess, fd, &tr)) {
		ERRX1("io_read_ulong");
		return false;
	} else if (!io_read_ulong(sess, fd, &ts)) {
		ERRX1("io_read_ulong");
		return false;
	}

	if (verbose > 0)
		stats_log(sess, tr, tw, ts);
	return true;
}


/*
 * Clean up a download session.  Should be called before discarding a
 * session object to ensure all accumlated resources are released.
 */
void
sess_cleanup(struct sess *sess)
{
	free(sess->token_dbuf);
	sess->token_dbuf = NULL;
	free(sess->token_cbuf);
	sess->token_cbuf = NULL;
	free(sess->token_buf);
	sess->token_buf = NULL;
}


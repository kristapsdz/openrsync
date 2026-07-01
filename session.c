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
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

/*
 * To make the summary log output more closely resemble that of standard
 * rsync we remove the space from between the number and the suffix
 * character, and eliminate any 'B' suffix.
 */
static void
stats_log_fixup(const size_t bufsz, char *buf)
{
	char	*p;

	p = strchr(buf, ' ');
	if (p != NULL && p[1] != '\0') {
		if (p[1] == 'B') {
			p[0] = '\0';
		} else {
			p[0] = p[1];
			p[1] = '\0';
		}
	}
}

/*
 * Accept how much we've read, written, and file-size, and print them in
 * a human-readable fashion (with GB, MB, etc. prefixes).  This only
 * prints as the client.
 * FIXME: does not check return value of rsync_humanize().
 */
static void
stats_log(const struct sess *sess, uint64_t tread, uint64_t twrite,
    uint64_t tsize)
{
	char	 rbuf[32], wbuf[32], sbuf[32], ratebuf[32];
	int64_t	 rate;

	if (sess->opts->server)
		return;

	if (verbose > 0 || sess->opts->stats) {
		rate = (tread + twrite) / ((sess->xfer_time + 0.1) / 1000);

		rsync_humanize(sess, rbuf, sizeof(rbuf), tread);
		rsync_humanize(sess, wbuf, sizeof(wbuf), twrite);
		rsync_humanize(sess, sbuf, sizeof(sbuf), tsize);
		rsync_humanize(sess, ratebuf, sizeof(ratebuf), rate);

		stats_log_fixup(sizeof(rbuf), rbuf);
		stats_log_fixup(sizeof(wbuf), wbuf);
		stats_log_fixup(sizeof(sbuf), sbuf);
		stats_log_fixup(sizeof(ratebuf), ratebuf);

		LOG0("\nsent %s bytes  received %s bytes  %s bytes/sec",
		     wbuf, rbuf, ratebuf);
		LOG0("total size is %s  speedup is %.2lf",
		     sbuf, tsize / (tread + twrite + 0.001));
	}

	LOG3("File list generation time: %.3f seconds, "
	    "transfer time: %.3f seconds",
	    (double)sess->flist_build / 1000,
	    (double)sess->flist_xfer / 1000);
}

/*
 * Output detailed statistics on transfer rates.
 * FIXME: does not check return value of rsync_humanize().
 */
static void
stats_output(const struct sess *sess)
{
	char	*tbuf[32];

	LOG0("Number of files: %" PRIu64, sess->total_files);
	LOG0("Number of files transferred: %" PRIu64, sess->total_files_xfer);
	rsync_humanize(sess, (char*)&tbuf, sizeof(tbuf), sess->total_size);
	LOG0("Total file size: %s", (char*)&tbuf);
	rsync_humanize(sess, (char*)&tbuf, sizeof(tbuf), sess->total_xfer_size);
	LOG0("Total transferred file size: %s", (char*)&tbuf);
	rsync_humanize(sess, (char*)&tbuf, sizeof(tbuf), sess->total_unmatched);
	LOG0("Unmatched data: %s", (char*)&tbuf);
	rsync_humanize(sess, (char*)&tbuf, sizeof(tbuf), sess->total_matched);
	LOG0("Matched data: %s", (char*)&tbuf);
	rsync_humanize(sess, (char*)&tbuf, sizeof(tbuf), sess->flist_size);
	LOG0("File list size: %s", (char*)&tbuf);
	if (sess->flist_build) {
		LOG0("File list generation time: %.3f seconds",
		    (double)sess->flist_build / 1000);
		LOG0("File list transfer time: %.3f seconds",
		    (double)sess->flist_xfer / 1000);
	}
	rsync_humanize(sess, (char*)&tbuf, sizeof(tbuf), sess->total_write);
	LOG0("Total sent: %s", (char*)&tbuf);
	rsync_humanize(sess, (char*)&tbuf, sizeof(tbuf), sess->total_read);
	LOG0("Total received: %s", (char*)&tbuf);
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
	int		 statfd = -1;

	tw = sess->total_write;
	tr = sess->total_read;
	ts = sess->total_size;

	if (sess->opts->stats)
		stats_output(sess);

	if (verbose > 0 || sess->opts->stats)
		stats_log(sess, tr, tw, ts);

	if (!sess->opts->server && sess->wbatch_fd == -1 && verbose == 0)
		return true;

	/*
	 * The client-sender doesn't need to send stats, unless we're
	 * writing a batch file; they're going to be read by a
	 * client-receiver, and will be expecting stats.  In that case,
	 * we'll just write the stats directly to the batch file.
	 */

	if (sess->opts->server || sess->wbatch_fd != -1) {
		if (sess->opts->server)
			statfd = fd;
		else
			statfd = sess->wbatch_fd;
	}

	if (statfd != -1) {
		if (!io_write_ulong(sess, statfd, tr)) {
			ERRX1("io_write_ulong");
			return false;
		} else if (!io_write_ulong(sess, statfd, tw)) {
			ERRX1("io_write_ulong");
			return false;
		} else if (!io_write_ulong(sess, statfd, ts)) {
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
	uint64_t	 tr, tw, ts;

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

	if (verbose > 0 || sess->opts->stats)
		stats_log(sess, tr, tw, ts);
	if (sess->opts->stats)
		stats_output(sess);

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


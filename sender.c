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
#include <md5.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

/*
 * A client sender manages the read-only source files and sends data to
 * the receiver as requested.
 * First it sends its list of files, then it waits for the server to
 * request updates to individual files.
 * Returns zero on failure, non-zero on success.
 *
 * Pledges: stdio, rpath.
 */
int
rsync_sender(const struct opts *opts, const struct sess *sess, 
	int fdin, int fdout, size_t argc, char **argv)
{
	struct flist	*fl = NULL;
	size_t		 flsz = 0, phase = 0,
			 csum_length = CSUM_LENGTH_PHASE1;
	int		 rc = 0, c;
	int32_t		 idx;
	struct blkset	*blks = NULL;

	if (-1 == pledge("stdio rpath", NULL)) {
		ERR(opts, "pledge");
		return 0;
	}

	/*
	 * Generate the list of files we want to send from our
	 * command-line input.
	 * This will also remove all invalid files.
	 */

	if (NULL == (fl = flist_gen(opts, argc, argv, &flsz))) {
		ERRX1(opts, "flist_gen");
		goto out;
	}

	/* Now send them to the receiver server. */

	if ( ! flist_send(opts, fdout, fl, flsz)) {
		ERRX1(opts, "flist_send");
		goto out;
	} else if ( ! io_write_int(opts, fdout, 0)) {
		ERRX1(opts, "io_write_int: io_error");
		goto out;
	}

	/*
	 * We have two phases: the first has a two-byte checksum, the
	 * second has a full 16-byte checksum.
	 */

	LOG2(opts, "sender transmitting "
		"%zu-checksum data", csum_length);

	for (;;) {
		if ( ! io_read_int(opts, fdin, &idx)) {
			ERRX1(opts, "io_read_int: index");
			goto out;
		} 

		/* 
		 * If we receive an invalid index (-1), then we're
		 * either promoted to the second phase or it's time to
		 * exit, depending upon which phase we're in.
		 */

		if (-1 == idx) {
			if (phase++)
				break;
			csum_length = CSUM_LENGTH_PHASE2;
			if ( ! io_write_int(opts, fdout, -1)) {
				ERRX1(opts, "io_write_int: phase ack");
				goto out;
			}
			LOG2(opts, "sender transmitting "
				"%zu-checksum data", csum_length);
			continue;
		}

		/* Valid index? */

		if (idx < 0 || (uint32_t)idx >= flsz) {
			ERRX(opts, "file index out of bounds: "
				"invalid %" PRId32 " out of %zu",
				idx, flsz);
			goto out;
		}

		/* Dry-run doesn't do anything. */

		if (opts->dry_run) {
			if ( ! io_write_int(opts, fdout, idx)) {
				ERRX1(opts, "io_write_int: "
					"send ack (dry-run)");
				goto out;
			}
			continue;
		}

		LOG1(opts, "%s", fl[idx].path);

		/*
		 * The server will now send us its view of the file.
		 * It does so by cutting a file into a series of blocks
		 * and checksumming each block.
		 * We can then compare the blocks in our file and those
		 * in theirs, and send them blocks they're missing or
		 * don't have.
		 */

		blks = blk_recv(opts, fdin, csum_length, fl[idx].path);
		if (NULL == blks) {
			ERRX1(opts, "blk_recv");
			goto out;
		} else if ( ! blk_recv_ack(opts, fdout, blks, idx)) {
			ERRX1(opts, "blk_recv_ack");
			goto out;
		}

		c = blk_match(opts, sess, fdout, 
			blks, fl[idx].path, csum_length);
		blkset_free(blks);

		if ( ! c) {
			ERRX1(opts, "blk_match");
			goto out;
		}
	}

	/* Write our final acknowledgement. */

	if ( ! io_write_int(opts, fdout, -1)) {
		ERRX1(opts, "io_write_int: send complete");
		goto out;
	}

	LOG2(opts, "sender finished updating");
	rc = 1;
out:
	flist_free(fl, flsz);
	return rc;
}

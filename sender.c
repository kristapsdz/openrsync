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

#if HAVE_SYS_QUEUE
# include <sys/queue.h>
#endif
#include <sys/stat.h>
#include <sys/time.h> /* gettimeofday */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <zlib.h>

#include "extern.h"
#include "rules.h"

/*
 * A request from the receiver to download updated file data.
 */
struct	send_dl {
	int32_t			 idx; /* index in our file list */
	struct blkset		*blks; /* the sender's block information */
	size_t			 blkidx; /* last block index read */
	enum send_dl_state	 dlstate; /* current blk recv state */
	struct vstring		 linkstr; /* (itemized) link string data */
	TAILQ_ENTRY(send_dl)	 entries;
};

static enum zlib_state	 comp_state; /* compression state */
static z_stream		 cctx; /* compression context */

static bool
send_iflags(struct sess *, void **, size_t *, size_t *, size_t *,
    const struct flist *, int32_t); /* TODO: put in correct place */

/*
 * The current file being "updated": sent from sender to receiver.
 * If there is no file being uploaded, "cur" is NULL.
 */
struct	send_up {
	struct send_dl	*cur; /* file being updated or NULL */
	struct blkstat	 stat; /* status of file being updated */
};

TAILQ_HEAD(send_dlq, send_dl);

/*
 * We have finished updating the receiver's file with sender data.
 * Deallocate and wipe clean all resources required for that.
 */
static void
send_up_reset(struct send_up *p)
{
	assert(p != NULL);

	/* Free the download request, if applicable. */

	if (p->cur != NULL) {
		free(p->cur->blks);
		free(p->cur);
		p->cur = NULL;
	}

	/* If we mapped a file for scanning, unmap it and close. */

	fmap_close(p->stat.map);
	p->stat.map = NULL;
	p->stat.mapsz = 0;

	if (p->stat.fd != -1)
		close(p->stat.fd);

	p->stat.fd = -1;

	/* Now clear the in-transfer information. */

	p->stat.offs = 0;
	p->stat.hint = 0;
	p->stat.curst = BLKSTAT_NONE;
	p->stat.error = false;
}

/*
 * Initialise the zlib compression state. Returns true on success, false
 * on error.
 */
static bool
compress_reinit(struct sess *sess)
{

	if (comp_state == COMPRESS_INIT) {
		cctx.zalloc = NULL;
		cctx.zfree = NULL;
		cctx.next_in = NULL;
		cctx.avail_in = 0;
		cctx.next_out = NULL;
		cctx.avail_out = 0;
		if (deflateInit2(&cctx, sess->opts->compression_level,
		    Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
			ERRX("deflateInit2");
			return false;
		}
		comp_state = COMPRESS_RUN;
	} else if (comp_state >= COMPRESS_DONE) {
		cctx.next_in = NULL;
		cctx.avail_in = 0;
		cctx.next_out = NULL;
		cctx.avail_out = 0;
		deflateReset(&cctx);
		comp_state = COMPRESS_RUN;
	}

	return true;
}

/*
 * Buffer zeroes in place of file contents if there's failure when
 * touching the file map.
 * Returns false on failure, true on success.
 */
static bool
sender_terminate_file_data(struct sess *sess, size_t padsz, void **wb,
	size_t pos, size_t *wbsz, size_t *wbmax)
{
	const char	 zerobuf[1024] = { 0 }; /* all zeroes */
	bool		 need_alloc = false; /* only alloc if needed */
	size_t		 chunksz; /* size to buffer */

	while (padsz != 0) {
		/*
		 * The caller has allocated enough for one frame + data
		 * buffer, but if our block size exceeds the size of
		 * zerobuf then we need multiple frames to cover it.
		 * Thus, we need an allocation for any subsequent write
		 * to the buffer to handle multiplexing correctly.
		 */

		if (need_alloc &&
		    !io_lowbuffer_alloc(sess, wb, wbsz, wbmax, 0)) {
			ERRX("io_lowbuffer_alloc");
			return false;
		}

		chunksz = MINIMUM(padsz, sizeof(zerobuf));
		io_lowbuffer_buf(sess, *wb, &pos, *wbsz, zerobuf, chunksz);
		need_alloc = true;
		padsz -= chunksz;
	}

	return true;
}

/*
 * Stop sending information on the file.
 */
static void
sender_terminate_file(struct sess *sess, struct send_up *up)
{
	up->stat.error = true;
	if (sess->opts->compress) {
		up->stat.curst = BLKSTAT_FLUSH;
	} else {
		up->stat.curst = BLKSTAT_TOK;
		up->stat.curtok = 0;
	}
}

/*
 * Fast forward through part of the file the other side already
 * has while keeping compression state intact.
 * Returns true on success, false on error.
 */
static bool
token_ff_compressed(struct sess *sess, struct send_up *up, size_t tok,
    struct flist *fl)
{
	const char	*buf;
	char		*cbuf;
	size_t		 sz, clen, rlen;
	off_t		 off;
	int		 res;

	if (tok >= up->cur->blks->blksz) {
		ERRX("token not in block set: %zu (have %zu blocks)",
		    tok, up->cur->blks->blksz);
		return false;
	}

	sz = (tok == up->cur->blks->blksz - 1 && up->cur->blks->rem) ?
	    up->cur->blks->rem : up->cur->blks->len;
	assert(sz);
	assert(up->stat.map != NULL);

	off = up->stat.curpos;
	assert(sz == up->cur->blks->len || sz == up->stat.mapsz - off);

	if (!fmap_trap(up->stat.map)) {
		sender_terminate_file(sess, up);
		WARNX("%s: file truncated while reading",
		    fl[up->cur->idx].path);
		return 0;
	}
	buf = fmap_data(up->stat.map, off, sz);

	cbuf = sess->token_cbuf;
	if (sess->token_cbufsz < MAX_CHUNK_BUF) {
		cbuf = malloc(MAX_CHUNK_BUF);
		if (cbuf == NULL) {
			ERRX1("malloc");
			fmap_untrap(up->stat.map);
			return false;
		}
		free(sess->token_cbuf);
		sess->token_cbuf = cbuf;
		sess->token_cbufsz = MAX_CHUNK_BUF;
	}

	if (!compress_reinit(sess)) {
		ERRX1("compress_reinit");
		fmap_untrap(up->stat.map);
		return false;
	}

	cctx.avail_in = 0;
	rlen = sz;
	clen = 0;
	while (rlen > 0) {
		clen = rlen;
		if (clen > MAX_CHUNK)
			clen = MAX_CHUNK;
		rlen -= clen;
		cctx.next_in = (Bytef *)buf;
		cctx.avail_in = (uInt)clen;
		buf += clen;
		do {
			cctx.next_out = (Bytef *)cbuf;
			cctx.avail_out = TOKEN_MAX_DATA;
			res = deflate(&cctx, Z_SYNC_FLUSH);
			if (res != Z_OK) {
				fmap_untrap(up->stat.map);
				ERRX("deflate ff res=%d", res);
				return false;
			}
		} while (cctx.avail_in != 0 || cctx.avail_out == 0);
	}

	fmap_untrap(up->stat.map);
	return true;
}

/*
 * This is like send_up_fsm() except for sending compressed blocks
 * Returns false on failure, true on success.
 */
static bool
send_up_fsm_compressed(struct sess *sess, size_t *phase,
    struct send_up *up, void **wb, size_t *wbsz, size_t *wbmax,
    struct flist *fl)
{
	unsigned char	 fmd[MD4_DIGEST_LENGTH]; /* file hash */
	char		 buf[16]; /* block header buffer */
	const char	*sbuf; /* buffer to be compressed */
	char		*cbuf; /* compressed buffer */
	off_t		 sz, /* temporary */
			 ssz; /* temporary */
	size_t		 pos = *wbsz; /* current pos in write buffer */
	const size_t	 dsz = MD4_DIGEST_LENGTH, /* write length */
			 isz = sizeof(int32_t); /* write length */
	int		 res, /* compression result */
			 flush = Z_NO_FLUSH; /* whether to flush */

	switch (up->stat.curst) {
	case BLKSTAT_DATA:
		/*
		 * A data segment to be written: buffer both the length
		 * and the data.
		 * If we've finished the transfer, move on to the token;
		 * otherwise, keep sending data.
		 */

		sz = MINIMUM(MAX_CHUNK,
			up->stat.curlen - up->stat.curpos);

		if (!fmap_trap(up->stat.map)) {
			sender_terminate_file(sess, up);
			WARNX("%s: file truncated while reading",
			    fl[up->cur->idx].path);
			return 1;
		}
		sbuf = fmap_data(up->stat.map, up->stat.curpos, sz);

		cbuf = sess->token_cbuf;
		if (sess->token_cbufsz < TOKEN_MAX_BUF) {
			cbuf = malloc(TOKEN_MAX_BUF);
			if (cbuf == NULL) {
				ERRX1("malloc");
				fmap_untrap(up->stat.map);
				return false;
			}

			free(sess->token_cbuf);
			sess->token_cbuf = cbuf;
			sess->token_cbufsz = TOKEN_MAX_BUF;
		}

		if (!compress_reinit(sess)) {
			ERRX1("compress_reinit");
			fmap_untrap(up->stat.map);
			return false;
		}

		assert(comp_state == COMPRESS_RUN);
		cctx.next_in = (Bytef *)sbuf;
		cctx.avail_in = (uInt)sz;
		cctx.next_out = (Bytef *)(cbuf + 2);
		cctx.avail_out = TOKEN_MAX_DATA;

		if ((up->stat.curpos + sz) == up->stat.curlen)
			flush = Z_SYNC_FLUSH;

		while ((res = deflate(&cctx, flush)) == Z_OK) {
			ssz = TOKEN_MAX_DATA - cctx.avail_out;
			if (flush != Z_NO_FLUSH) {
				assert(ssz >= 4);
				ssz -= 4;
			}
			if (ssz == 0)
				break;

			/*
			 * Write: [block-xchng-com-1a].
			 * Write: [block-xchng-com-1b].
			 */

			if (!io_lowbuffer_alloc(sess, wb, wbsz, wbmax, ssz + 2)) {
				fmap_untrap(up->stat.map);
				ERRX("io_lowbuffer_alloc");
				return false;
			}
			cbuf[0] = (TOKEN_DEFLATED + (ssz >> 8)) & 0xff;
			cbuf[1] = ssz & 0xff;
			io_lowbuffer_buf(sess, *wb, &pos, *wbsz, cbuf, ssz + 2);

			if (cctx.avail_out != 0)
				break;
			if (cctx.avail_out == 0) {
				cctx.next_out = (Bytef *)(cbuf + 2);
				/* Save room for the 4 byte trailer */
				cctx.avail_out = TOKEN_MAX_DATA;
				if (flush != Z_NO_FLUSH) {
					memcpy(cctx.next_out, cbuf+TOKEN_MAX_DATA-2, 4);
					cctx.next_out += 4;
					cctx.avail_out -= 4;
				}
			}
		}
		fmap_untrap(up->stat.map);
		if (res != Z_OK && res != Z_BUF_ERROR) {
			ERRX("deflate res=%d", res);
			return false;
		}
		up->stat.curpos += sz;
		if (up->stat.curpos == (off_t)up->stat.mapsz)
			up->stat.curst = BLKSTAT_FLUSH;
		else if (up->stat.curpos == up->stat.curlen)
			up->stat.curst = BLKSTAT_TOK;

		return true;
	case BLKSTAT_TOK:
		/*
		 * The data token tells the receiver to copy a block of
		 * data from the existing file they have, instead of having
		 * us send the data.
		 * It's followed by a hash or another data segment,
		 * depending on the token.
		 */

		up->stat.curst = up->stat.curtok ?
			BLKSTAT_NEXT : BLKSTAT_FLUSH;

		if (up->stat.curtok == 0) {
			/* Empty files just need an END token */

			if (!compress_reinit(sess)) {
				ERRX1("compress_reinit");
				return false;
			}

			/* Write: [block-xchng-com-1] (no more). */

			if (!io_lowbuffer_alloc(sess, wb, wbsz, wbmax, 1)) {
				ERRX1("io_lowbuffer_alloc");
				return false;
			}
			io_lowbuffer_byte(sess, *wb, &pos, *wbsz, TOKEN_END);
			comp_state = COMPRESS_DONE;
			up->stat.curst = BLKSTAT_HASH;
			return true;
		}

		/* Write: [block-xchng-com-1]. */

		if (!io_lowbuffer_alloc(sess, wb, wbsz, wbmax, 1)) {
			ERRX1("io_lowbuffer_alloc");
			return false;
		}
		io_lowbuffer_byte(sess, *wb, &pos, *wbsz, TOKEN_LONG);

		/* Write: [block-xchng-com-1c]. */

		if (!io_lowbuffer_alloc(sess, wb, wbsz, wbmax, isz)) {
			ERRX1("io_lowbuffer_alloc");
			return false;
		}
		io_lowbuffer_int(sess, *wb, &pos, *wbsz,
		    -(up->stat.curtok + 1));

		token_ff_compressed(sess, up, -(up->stat.curtok + 1), fl);
		return true;
	case BLKSTAT_HASH:
		/*
		 * The hash following transmission of all file contents.
		 * This is always followed by the state that we're
		 * finished with the file.
		 * FIXME: replicated in uncompressed case.
		 */

		if (!up->stat.error &&
		    !hash_fmap(fl[up->cur->idx].path, up->stat.map,
		     up->stat.mapsz, fmd, sess)) {
			ERRX1("hash_fmap");
			up->stat.error = true;
		}

		if (up->stat.error) {
			/*
			 * At some point the file got truncated, so we
			 * pass off a bogus hash to force a redo.  XXX
			 * This would be cleaner if we kept a running
			 * hash as the transfer progressed, as we just
			 * finalize it and +1 for a more certain
			 * mismatch.
			 */
			memset(fmd, 0, dsz);
			fmd[0]++;
		}

		/* Write: [block-xchng-com-2]. */

		if (!io_lowbuffer_alloc(sess, wb, wbsz, wbmax, dsz)) {
			ERRX1("io_lowbuffer_alloc");
			return 0;
		}
		io_lowbuffer_buf(sess, *wb, &pos, *wbsz, fmd, dsz);
		up->stat.curst = BLKSTAT_DONE;
		return true;
	case BLKSTAT_FLUSH:
		/*
		 * Flush the end of the compressed stream.
		 */

		if (!up->stat.error) {
			cbuf = sess->token_cbuf;
			if (sess->token_cbufsz < TOKEN_MAX_BUF) {
				cbuf = malloc(TOKEN_MAX_BUF);
				if (cbuf == NULL) {
					ERRX1("malloc");
					return false;
				}

				free(sess->token_cbuf);
				sess->token_cbuf = cbuf;
				sess->token_cbufsz = TOKEN_MAX_BUF;
			}

			cctx.avail_in = 0;
			cctx.next_in = NULL;
			cctx.next_out = (Bytef *)(cbuf + 2);
			cctx.avail_out = TOKEN_MAX_DATA;

			while ((res = deflate(&cctx, Z_SYNC_FLUSH)) == Z_OK) {
				ssz = TOKEN_MAX_DATA - cctx.avail_out;
				assert(ssz >= 4);
				ssz -= 4; /* Trim off the trailer bytes */
				if (ssz != 0 && res != Z_BUF_ERROR) {
					/*
					 * Write: [block-xchng-com-1d].
					 * Write: [block-xchng-com-1e].
					 * (I think?)
					 */

					if (!io_lowbuffer_alloc(sess, wb, wbsz,
					    wbmax, ssz + 2)) {
						ERRX("io_lowbuffer_alloc");
						return false;
					}
					cbuf[0] = (TOKEN_DEFLATED + (ssz >> 8)) & 0xff;
					cbuf[1] = ssz & 0xff;
					io_lowbuffer_buf(sess, *wb, &pos, *wbsz,
					    cbuf, ssz + 2);
				}
				cctx.next_out = (Bytef *)(cbuf + 2);
				cctx.avail_out = TOKEN_MAX_DATA;
				memcpy(cctx.next_out, cbuf+TOKEN_MAX_DATA-2, 4);
				cctx.next_out += 4;
				cctx.avail_out -= 4;
			}

			if (res != Z_OK && res != Z_BUF_ERROR)
				LOG2("final deflate() res=%d", res);
		}

		/* Write: [block-xchng-com-1] (no more blocks). */

		if (!io_lowbuffer_alloc(sess, wb, wbsz, wbmax, 1)) {
			ERRX("io_lowbuffer_alloc");
			return false;
		}
		io_lowbuffer_byte(sess, *wb, &pos, *wbsz, TOKEN_END);
		comp_state = COMPRESS_DONE;
		up->stat.curst = BLKSTAT_HASH;
		return true;
	case BLKSTAT_DONE:
		/*
		 * The data has been written.
		 * Clear our current send file and allow the block below
		 * to find another.
		 */
		if (!sess->opts->dry_run)
			LOG3("%s: flushed %jd KB total, %.2f%% uploaded",
			    fl[up->cur->idx].path,
			    (intmax_t)up->stat.total / 1024,
			    100.0 * up->stat.dirty / up->stat.total);
		log_item_impl(LT_LOG, sess, &fl[up->cur->idx]);
		send_up_reset(up);
		return true;
	case BLKSTAT_PHASE:
		/*
		 * This is where we actually stop the algorithm: we're
		 * already at the second phase.
		 */

		comp_state = COMPRESS_DONE;
		send_up_reset(up);
		(*phase)++;
		sess->role->append = false;
		return true;
	case BLKSTAT_NEXT:
		/*
		 * Our last case: we need to find the
		 * next block (and token) to transmit to
		 * the receiver.
		 * These will drive the finite state
		 * machine in the first few conditional
		 * blocks of this set.
		 */

		assert(up->stat.fd != -1);
		if (!blk_match(sess, up->cur->blks,
		    fl[up->cur->idx].path, &up->stat))
			sender_terminate_file(sess, up);

		return true;
	case BLKSTAT_NONE:
		break;
	}

	assert(BLKSTAT_NONE == up->stat.curst);

	/*
	 * We've either hit the phase change following the last file (or
	 * start, or prior phase change), or we need to prime the next
	 * file for transmission.
	 * We special-case dry-run mode.
	 */

	if (up->cur->idx < 0) {
		/* Write: [file-index]. */

		if (!io_lowbuffer_alloc(sess, wb, wbsz, wbmax, isz)) {
			ERRX1("io_lowbuffer_alloc");
			return false;
		}
		io_lowbuffer_int(sess, *wb, &pos, *wbsz, -1);
		up->stat.curst = BLKSTAT_PHASE;
	} else if (sess->opts->dry_run) {
		(void)send_iflags(sess, wb, wbsz, wbmax, &pos, fl, up->cur->idx);
		up->stat.curst = BLKSTAT_DONE;
	} else {
		assert(up->stat.fd != -1);

		/* Write: [file-index]. */

		(void)send_iflags(sess, wb, wbsz, wbmax, &pos, fl, up->cur->idx);

		/*
		 * Write [file-block-count].
		 * Write [file-block-length].
		 * Write [file-block-cs-length].
		 * Write [file-block-rem].
		 */

		assert(sizeof(buf) == 16);
		if (!io_lowbuffer_alloc(sess, wb, wbsz, wbmax, sizeof(buf))) {
			ERRX1("io_lowbuffer_alloc");
			return false;
		}
		blk_recv_ack(buf, up->cur->blks, up->cur->idx);
		io_lowbuffer_buf(sess, *wb, &pos, *wbsz, buf, sizeof(buf));

		LOG3("%s: primed for %jd B total",
		    fl[up->cur->idx].path, (intmax_t)up->cur->blks->size);
		up->stat.curst = BLKSTAT_NEXT;
	}

	return true;
}

/*
 * This is the bulk of the sender work for [block-xchng].
 * Here we tend to an output buffer that responds to receiver requests
 * for data.
 * This does not act upon the output descriptor itself so as to avoid
 * blocking, which otherwise would deadlock the protocol.
 * Returns false on failure, true on success.
 */
static bool
send_up_fsm(struct sess *sess, size_t *phase, struct send_up *up,
    void **wb, size_t *wbsz, size_t *wbmax, const struct flist *fl)
{
	char		 buf[16]; /* temporary bufer */
	unsigned char	 fmd[MD4_DIGEST_LENGTH]; /* file hash */
	off_t		 sz; /* temporary */
	size_t		 pos = 0; /* position in buffer */
	const size_t	 isz = sizeof(int32_t), /* int32 length */
			 dsz = MD4_DIGEST_LENGTH; /* md4 length */

	switch (up->stat.curst) {
	case BLKSTAT_DATA:
		/*
		 * Write: [block-xchng-unc-1] with remote length.
		 * A data segment to be written: buffer both the length
		 * and the data.
		 * If we've finished the transfer, move on to the token;
		 * otherwise, keep sending data.
		 */

		sz = MINIMUM(MAX_CHUNK,
			up->stat.curlen - up->stat.curpos);
		if (!io_lowbuffer_alloc(sess, wb, wbsz, wbmax, isz)) {
			ERRX1("io_lowbuffer_alloc");
			return false;
		}
		io_lowbuffer_int(sess, *wb, &pos, *wbsz, sz);
		if (!io_lowbuffer_alloc(sess, wb, wbsz, wbmax, sz)) {
			ERRX1("io_lowbuffer_alloc");
			return false;
		}

		if (!fmap_trap(up->stat.map)) {
			if (!sender_terminate_file_data(sess, sz, wb,
			    pos, wbsz, wbmax)) {
				/* Allocation error, fatal */
				return false;
			}
			sender_terminate_file(sess, up);
			WARNX("%s: file truncated while reading",
			    fl[up->cur->idx].path);
			return true;
		}

		/* Write: [block-xchng-unc-1a]. */

		io_lowbuffer_buf(sess, *wb, &pos, *wbsz,
		    fmap_data(up->stat.map, up->stat.curpos, sz), sz);
		fmap_untrap(up->stat.map);

		up->stat.curpos += sz;
		if (up->stat.curpos == up->stat.curlen)
			up->stat.curst = BLKSTAT_TOK;
		return true;
	case BLKSTAT_TOK:
		/*
		 * Write: [block-xchng-unc-1] with token.
		 * The data token following (maybe) a data segment.
		 * These can also come standalone if, say, the file's
		 * being fully written.
		 * It's followed by a hash or another data segment,
		 * depending on the token.
		 */

		if (!io_lowbuffer_alloc(sess, wb, wbsz, wbmax, isz)) {
			ERRX1("io_lowbuffer_alloc");
			return false;
		}
		io_lowbuffer_int(sess, *wb,
			&pos, *wbsz, up->stat.curtok);
		up->stat.curst = up->stat.curtok ?
			BLKSTAT_NEXT : BLKSTAT_HASH;
		return true;
	case BLKSTAT_HASH:
		/*
		 * The hash following transmission of all file contents.
		 * This is always followed by the state that we're
		 * finished with the file.
		 * FIXME: replicated in compressed case.
		 */

		if (!up->stat.error &&
		    !hash_fmap(fl[up->cur->idx].path, up->stat.map,
		     up->stat.mapsz, fmd, sess)) {
			ERRX1("hash_fmap");
			up->stat.error = true;
		}

		if (up->stat.error) {
			/*
			 * At some point the file got truncated, so we
			 * pass off a bogus hash to force a redo.  XXX
			 * This would be cleaner if we kept a running
			 * hash as the transfer progressed, as we just
			 * finalize it and +1 for a more certain
			 * mismatch.
			 */
			memset(fmd, 0, dsz);
			fmd[0]++;
		}

		if (!io_lowbuffer_alloc(sess, wb, wbsz, wbmax, dsz)) {
			ERRX1("io_lowbuffer_alloc");
			return false;
		}

		/* Write: [block-xchng-unc-2]. */

		io_lowbuffer_buf(sess, *wb, &pos, *wbsz, fmd, dsz);
		up->stat.curst = BLKSTAT_DONE;
		return true;
	case BLKSTAT_FLUSH:
		assert(0);
		break;
	case BLKSTAT_DONE:
		/*
		 * The data has been written.
		 * Clear our current send file and allow the block below
		 * to find another.
		 */

		if (!sess->opts->dry_run)
			LOG3("%s: flushed %jd KB total, %.2f%% uploaded",
			    fl[up->cur->idx].path,
			    (intmax_t)up->stat.total / 1024,
			    100.0 * up->stat.dirty / up->stat.total);
		log_item_impl(LT_LOG, sess, &fl[up->cur->idx]);
		send_up_reset(up);
		return true;
	case BLKSTAT_PHASE:
		/*
		 * This is where we actually stop the algorithm: we're
		 * already at the second phase.
		 */

		send_up_reset(up);
		(*phase)++;
		sess->role->append = false;
		return true;
	case BLKSTAT_NEXT:
		/*
		 * Our last case: we need to find the
		 * next block (and token) to transmit to
		 * the receiver.
		 * These will drive the finite state
		 * machine in the first few conditional
		 * blocks of this set.
		 */

		assert(up->stat.fd != -1);
		if (!blk_match(sess, up->cur->blks,
		    fl[up->cur->idx].path, &up->stat))
			sender_terminate_file(sess, up);
		return true;
	case BLKSTAT_NONE:
		break;
	}

	assert(BLKSTAT_NONE == up->stat.curst);

	/*
	 * We've either hit the phase change following the last file (or
	 * start, or prior phase change), or we need to prime the next
	 * file for transmission.
	 * We special-case dry-run mode.
	 */

	if (up->cur->idx < 0) {
		/* Write: [file-index] */

		if (!io_lowbuffer_alloc(sess, wb, wbsz, wbmax, isz)) {
			ERRX1("io_lowbuffer_alloc");
			return false;
		}
		io_lowbuffer_int(sess, *wb, &pos, *wbsz, -1);
		up->stat.curst = BLKSTAT_PHASE;
	} else if (sess->opts->dry_run == DRY_FULL) {
		/* Write: [file-index] */

		(void)send_iflags(sess, wb, wbsz, wbmax, &pos, fl, up->cur->idx);
		up->stat.curst = BLKSTAT_DONE;
	} else {
		assert(up->stat.fd != -1);

		/* Write: [file-index] */

		(void)send_iflags(sess, wb, wbsz, wbmax, &pos, fl, up->cur->idx);

		/* 
		 * Write:
		 *   [file-block-count]
		 *   [file-block-length]
		 *   [file-block-cs-length]
		 *   [file-block-rem]
		 */

		assert(sizeof(buf) == 16);
		if (!io_lowbuffer_alloc(sess, wb, wbsz, wbmax, sizeof(buf))) {
			ERRX1("io_lowbuffer_alloc");
			return false;
		}
		blk_recv_ack(buf, up->cur->blks, up->cur->idx);
		io_lowbuffer_buf(sess, *wb, &pos, *wbsz, buf, sizeof(buf));

		LOG3("%s: primed for %jd B total",
		    fl[up->cur->idx].path, (intmax_t)up->cur->blks->size);
		up->stat.curst = BLKSTAT_NEXT;
	}


	return true;
}

/*
 * Enqueue a download request, getting it off the read channel as
 * quickly a possible.
 * This frees up the read channel for further incoming requests.
 * We'll handle each element in turn, up to and including the last
 * request (phase change), which is always a -1 idx.
 * Returns zero on failure, non-zero on success.
 */
static bool
send_dl_enqueue(struct sess *sess, struct send_dlq *q, int32_t idx,
    struct flist *fl, size_t flsz, int fd, struct iobuf *buf,
    struct send_dl **mdl)
{
	struct send_dl	*s; /* new download request */
	int32_t		 iflags; /* iflags */

	/* End-of-phase marker. */

	if (idx == -1) {
		if ((s = calloc(1, sizeof(struct send_dl))) == NULL) {
			ERR("calloc");
			return false;
		}
		s->idx = -1;
		s->blks = NULL;
		s->dlstate = SDL_DONE;
		TAILQ_INSERT_TAIL(q, s, entries);
		*mdl = NULL;
		return true;
	} else if (idx < 0 || (uint32_t)idx >= flsz) {
		ERRX("file index out of bounds: invalid %d out of %zu",
		    idx, flsz);
		return false;
	}

	/* Validate the index. */

	iflags = IFLAG_TRANSFER | IFLAG_MISSING_DATA;

	if (iflags == IFLAG_NEW) {
		/* Keep alive packet, do nothing... */
		if ((uint32_t)idx == flsz)
			return true;
		ERRX("invalid index %d of %zu for keep alive packet",
		     idx, flsz);
		return false;
	} else if ((uint32_t)idx == flsz) {
		ERRX("invalid item flags 0x%x for index %d of %zu",
		     iflags, idx, flsz);
		return false;
	}

	fl[idx].iflags = iflags;

	if (!(iflags & IFLAG_TRANSFER)) {
		/* We can't return early due to the state machine */
	} else if (S_ISDIR(fl[idx].st.mode)) {
		ERRX("blocks requested for "
			"directory: %s", fl[idx].path);
		return false;
	} else if (S_ISLNK(fl[idx].st.mode)) {
		ERRX("blocks requested for "
			"symlink: %s", fl[idx].path);
		return false;
	} else if (!S_ISREG(fl[idx].st.mode)) {
		ERRX("blocks requested for "
			"special: %s", fl[idx].path);
		return false;
	}

	if (iflags & IFLAG_HLINK_FOLLOWS) {
		free(fl[idx].link);
		fl[idx].link = NULL;
		if (!iobuf_alloc(sess, buf, PATH_MAX)) {
			ERRX1("iobuf_alloc");
			return 0;
		}
	}

	if ((s = calloc(1, sizeof(struct send_dl))) == NULL) {
		ERR("callloc");
		return false;
	}
	s->idx = idx;
	s->blks = NULL;

	/*
	 * If we're not doing a dry-run then we need to go through the
	 * blk_recv machinery, but dry-runs have nothing left to read
	 * for this file; we can just push it directly into the queue
	 * and move on.
	 */

	if (sess->opts->dry_run != DRY_FULL) {
		s->dlstate = SDL_META;
		*mdl = s;
	} else {
		s->dlstate = SDL_DONE;
		*mdl = s;
	}

	return true;
}

/*
 * Deal with the conditional "follows" flags for extra iflag metadata.
 * Returns -1 on error, 0 for incomplete, 1 when complete.
 */
static int
sender_get_iflags(struct iobuf *buf, struct flist *fl,
    struct send_dl *sdl)
{
	uint8_t	 basis; /* raw "follows" byte */
	int	 ret; /* vstring return code */

	fl = &fl[sdl->idx];
	if (fl->iflags & IFLAG_BASIS_FOLLOWS) {
		if (iobuf_get_readsz(buf) < sizeof(uint8_t)) {
			if (iobuf_seen_eof(buf)) {
				ERR("hangup while awaiting iflags");
				return -1;
			}
			return 0;
		}

		iobuf_read_byte(buf, &basis);
		fl->basis = basis;

		if ((fl->iflags & IFLAG_HLINK_FOLLOWS) != 0) {
			fl->iflags |= IFLAG_HAD_BASIS;
			fl->iflags &= ~IFLAG_BASIS_FOLLOWS;
		}
	}

	if (fl->iflags & IFLAG_HLINK_FOLLOWS) {
		ret = iobuf_read_vstring(buf, &sdl->linkstr);
		if (ret <= 0)
			return ret;

		fl->link = sdl->linkstr.vstring_buffer;
		if ((fl->iflags & IFLAG_HAD_BASIS) != 0) {
			fl->iflags &= ~IFLAG_HAD_BASIS;
			fl->iflags |= IFLAG_BASIS_FOLLOWS;
		}
	}

	return 1;
}


/*
 * Send the itemization flags for an index over the wire.  Deal with the
 * conditional "follows" flags for extra metadata.  Returns true on
 * success, false on failure.
 */
static bool
send_iflags(struct sess *sess, void **wb, size_t *wbsz, size_t *wbmax,
    size_t *pos, const struct flist *fl, int32_t idx)
{
	if (!io_lowbuffer_alloc(sess, wb, wbsz, wbmax, sizeof(int32_t))) {
		ERRX1("io_lowbuffer_alloc");
		return false;
	}
	io_lowbuffer_int(sess, *wb, pos, *wbsz, idx);
	return true;
}

/*
 * Read off the last file index, which should be -1.
 * Returns false on failure, true on success.
 */
static bool
sender_finalize(struct sess *sess, struct iobuf *rbuf, int fdin)
{
	int32_t	 idx = 0;

	/* Fill up for last index. */

	while (iobuf_get_readsz(rbuf) < sizeof(idx)) {
		if (!iobuf_fill(sess, rbuf, fdin)) {
			ERRX1("iobuf_fill on final goodbye");
			return false;
		}
	}

	iobuf_read_int(rbuf, &idx);

	if (idx != -1) {
		ERRX("read incorrect update complete ack");
		return false;
	}

	return true;
}

/*
 * The sender sends files, whether as the client (local host) or server
 * (remote host).  Its mirror is rsync_receiver().
 * First it sends its list of files, then it waits for the receiver to
 * request updates to individual files.
 * It queues requests for updates as soon as it receives them.
 * Returns true on success, false on failure.
 */
bool
rsync_sender(struct sess *sess, int fdin, int fdout, size_t argc,
    char **argv)
{
	char		    buf[PATH_MAX]; /* temporary buffer */
	struct timeval	    tv; /* temporary time calculations */
	struct role	    sender; /* sender role */
	struct iobuf	    rbuf = { 0 }; /* read buffer */
	struct pollfd	    pfd[3]; /* poll listeners */
	struct send_dlq	    sdlq; /* download queue */
	struct send_up	    up; /* current file being updated */
	struct stat	    st; /* temporary */
	struct fl	    fl; /* array of flists */
	double		    now, rate, sleeptime, diff; /* FIXME: move to function */
	const struct flist *f, /* current flist */
	      		   *nextfl; /* temporary flist */
	const char	   *opath; /* nextfl path */
	struct send_dl	   *dl, /* file being downloaded */
			   *mdl = NULL; /* metadata being downloaded */
	void		   *wbuf = NULL; /* working buffer */
	size_t		    i, /* temporary */
			    phase = 0, /* transfer phase */
			    wbufpos = 0, /* position in buffer */
			    wbufsz = 0, /* current size of buffer */
			    wbufmax = 0, /* allocated size of buffer */
			    avail, /* temporary */
			    flinfosz,
			    pos, /* temporary */
			    markers = 0,
			    metadata_phase = 0;
	ssize_t		    writesz; /* temporary: size written */
	const size_t	    max_phase = 1; /* sess->protocol >= 29 ? 2 : 1; */
	int		    c, /* temporary */
			    dirfd, /* openat() first argument */
			    nlinkflag, /* openat() argument */
			    oflags, /* openat() argument */
			    bret; /* temporary */
	int32_t		    idx; /* current block index */
	ssize_t		    ssz; /* temporary */
	bool		    ret, /* temporary */
			    shutdown = false, /* in shutdown */
			    rc = false; /* function return code */

	/*
	 * Each time we start a new file, we want to be able to grab at
	 * least the index and its iflags.  It's safe to assume we'll
	 * get at least this much even near the end of the transfer,
	 * because the goodbye indicator is another int32_t -- we'll
	 * just accidentally see part of the goodbye indicator as
	 * available, but we won't over-read into it so everything works
	 * out.
	 */

	flinfosz = sizeof(int32_t);
	fl_init(sess, &fl);

	if (pledge("stdio getpw rpath", NULL) == -1) {
		ERR("pledge");
		return 0;
	}

	memset(&sender, 0, sizeof(sender));
	sender.append = false;
	sender.phase = &metadata_phase;

	if (sess->opts->server)
		sender.client = fdout;
	else
		sender.client = -1;

	sess->role = &sender;

	memset(&up, 0, sizeof(struct send_up));
	TAILQ_INIT(&sdlq);
	up.stat.fd = -1;
	up.stat.map = NULL;
	up.stat.blktab = blkhash_alloc();

	/*
	 * Client sends rules.  If in a position to send, check whether
	 * the negotiated protocol is satisfied beforehand.
	 */

	if (!sess->opts->server) {
		check_send_rules(sess);
		/* Client sends zero-length exclusions if deleting. */
		if (sess->opts->del && !sess->opts->del_excl)
			send_rules(sess, fdout);
	}

	/* If we're the server, read our rules. */

	if (sess->opts->server)
		recv_rules(sess, fdin);

	/*
	 * Generate the list of files we want to send from our
	 * command-line input.  This will also remove all invalid files.
	 */

	if (!flist_gen(sess, argc, argv, &fl)) {
		ERRX1("flist_gen");
		goto out;
	}
	assert(fl.flp != NULL || fl.sz == 0);

	/*
	 * Then the file list in any mode.
	 * Finally, the IO error (always zero for us).
	 * Write: [io-error-value].
	 */

	if (!flist_send(sess, fdin, fdout, fl.flp, fl.sz)) { /* FIXME: &fl */
		ERRX1("flist_send");
		goto out;
	} else if (!io_write_int(sess, fdout, 0)) {
		ERRX1("io_write_int");
		goto out;
	}

	/* Exit if we're the server with zero files. */

	if (fl.sz == 0 && sess->opts->server) {
		WARNX("sender has empty file list: exiting");
		rc = true;
		goto out;
	} else if (!sess->opts->server)
		LOG1("Transfer starting: %zu files", fl.sz);

	/* Use rbuf from this point forward. */

	if (!iobuf_alloc(sess, &rbuf, sizeof(int32_t) * 5)) {
		ERRX1("iobuf_alloc");
		goto out;
	}

	/*
	 * If we're the server then arrange for log_vwritef() to append
	 * all tagged log messages to the sender's output buffer.
	 */

	if (sess->opts->server) {
		sess->wbufp = &wbuf;
		sess->wbufszp = &wbufsz;
		sess->wbufmaxp = &wbufmax;
	}

	/*
	 * Set up our poll events.
	 * We start by polling only in receiver requests, enabling other
	 * poll events on demand.
	 */

	pfd[0].fd = fdin; /* from receiver */
	pfd[0].events = POLLIN;
	pfd[1].fd = -1; /* to receiver */
	pfd[1].events = POLLOUT;
	pfd[2].fd = -1; /* from local file */
	pfd[2].events = POLLIN;

	for (;;) {
#define	READ_AVAIL(pfd, iobuf) \
	(((pfd)[0].revents & POLLIN) != 0 || \
	 iobuf_get_readsz((iobuf)) != 0)
		assert(pfd[0].fd != -1 || iobuf_seen_eof(&rbuf));

		/*
		 * If there's data already in the read buffer, do a
		 * non-blocking poll() just to pick off what's remaining
		 * in there.  Else, block with a timeout.
		 */

		if (iobuf_get_readsz(&rbuf) > 0) {
			c = poll(pfd, 3, 0);
			if (c == -1) {
				if (errno == EINTR)
					continue;
				ERR("poll");
				goto out;
			}
		} else if ((c = poll(pfd, 3, poll_timeout)) == -1) {
			if (errno == EINTR)
				continue;
			ERR("poll");
			goto out;
		} else if (c == 0) {
			ERRX("poll: timeout");
			goto out;
		}

		/* Walk through poll events and process. */

		for (i = 0; i < 3; i++)
			if (pfd[i].revents & (POLLERR|POLLNVAL)) {
				ERRX("poll: bad fd");
				goto out;
			} else if (pfd[i].revents & POLLHUP) {
				/*
				 * We still ignore POLLHUP on pfd[1] if
				 * we have data still to process,
				 * because we may not need to respond.
				 */
				if (i >= 2 ||
				    !READ_AVAIL(pfd, &rbuf)) {
					ERRX("poll: hangup on sender "
					    "idx %zd iobuf capacity "
					    "%zu", i,
					    iobuf_get_readsz(&rbuf));
					goto out;
				}
			}

		/*
		 * Check if there's anything on the wire after cleaning out any
		 * multiplexed messages.  If there's nothing, hit the
		 * encompassing for loop again.
		 */

		if (sess->mplex_reads && (pfd[0].revents & POLLIN)) {
			if (!io_read_flush(sess, fdin)) {
				ERRX1("io_read_flush");
				goto out;
			}
			if (sess->mplex_read_remain == 0 && !shutdown) {
				c = io_read_check(sess, fdin);
				if (c < 0) {
					ERRX1("io_read_check");
					goto out;
				} else if (c > 0)
					continue;
				pfd[0].revents &= ~POLLIN;
			}
		}

		/*
		 * Pull pending data in as quickly as possible into our buffer.
		 * Start by seeing if we have a log message.  If we do, pop it
		 * off, then see if we have anything left and hit it again if
		 * so (read priority).
		 */

		if ((pfd[0].revents & POLLIN) &&
		    (!sess->mplex_reads ||
		     sess->mplex_read_remain > 0)) {
			if (!iobuf_fill(sess, &rbuf, fdin)) {
				ERRX1("iobuf_fill");
				goto out;
			}

			pfd[0].revents &= ~POLLIN;

			/*
			 * If the other side hung up, we can stop polling this
			 * fd and mark the readbuf as finished.
			 */

			if ((pfd[0].revents & POLLHUP) != 0) {
				pfd[0].fd = -1;
				iobuf_eof(&rbuf);
			}
		}

		/*
		 * Now that we've handled reading log messages, process
		 * metadata messages first.  Enqueue message requests.
		 */

		if (READ_AVAIL(pfd, &rbuf) && mdl == NULL && !shutdown) {
			avail = iobuf_get_readsz(&rbuf);
			if (avail == sizeof(int32_t) &&
			    iobuf_peek_int(&rbuf) == -1) {
				/*
				 * End-of-phase markers won't have any
				 * follow-up until we ack the
				 * end-of-phase, we should just pass
				 * these through.
				 */
			} else if (avail < flinfosz)
				goto check_other;

			/* Read: [file-cont-index]. */

			iobuf_read_int(&rbuf, &idx);

			/*
			 * Start to spin down; most notably, we need to avoid
			 * trying to enqueue anything else because we should
			 * only observe the end-of-transmission marker after
			 * this.  We could also see other non-data messages come
			 * in via fdin, so we should *only* stop reading indices
			 * from fdin and continue flushing out any pending
			 * messages above.
			 */

			if (idx == -1) {
				if (++markers >= max_phase + 1)
					shutdown = 1;

				/*
				 * We track the metadata phase separately
				 * because blk_find() needs to observe that the
				 * overall session is still in append mode, but
				 * send_dl_enqueue() needs to know that it
				 * should look for any incoming block
				 * information.
				 */
				metadata_phase++;
			}

			assert(mdl == NULL);
			if (!send_dl_enqueue(sess, &sdlq, idx, fl.flp, fl.sz,
			    fdin, &rbuf, &mdl)) {
				ERRX1("send_dl_enqueue");
				goto out;
			}

			if (idx == -1)
				assert(mdl == NULL);
		}

		if (READ_AVAIL(pfd, &rbuf) && mdl != NULL) {
			/*
			 * Read: [block-cont-index].
			 */
			if (mdl->dlstate == SDL_IFLAGS) {
				bret = sender_get_iflags(&rbuf, fl.flp, mdl);
				if (bret < 0) {
					ERRX1("sender_get_iflags");
					goto out;
				} else if (bret == 0)
					goto check_other;

				if (!(fl.flp[mdl->idx].iflags & IFLAG_TRANSFER))
					mdl->dlstate = SDL_DONE;
				else if (sess->opts->dry_run == DRY_FULL)
					mdl->dlstate = SDL_DONE;
				else
					mdl->dlstate = SDL_META;
			}

			/*
			 * Read:
			 *   [block-cont-count]
			 *   [block-cont-length]
			 *   [block-cont-cs-length]
			 *   [block-cont-rem]
			 *   [block-cont-block-cs-short]
			 *   [block-cont-block-cs-long]
			 */

			if (mdl->dlstate == SDL_BLOCKS ||
			    mdl->dlstate == SDL_META) {
				mdl->blks = blk_recv(sess, fdin, &rbuf,
				    fl.flp[mdl->idx].path, mdl->blks,
				    &mdl->blkidx, &mdl->dlstate);
				if (mdl->dlstate != SDL_META &&
				    mdl->blks == NULL) {
					ERRX1("blk_recv");
					goto out;
				}
			}

			if (mdl->dlstate == SDL_DONE) {
				TAILQ_INSERT_TAIL(&sdlq, mdl, entries);
				mdl = NULL;
			}

			pfd[0].revents &= ~POLLIN;

			c = io_read_check(sess, fdin);
			if (c < 0) {
				ERRX1("io_read_check");
				goto out;
			} else if (c > 0)
				continue;
		}

		/*
		 * One of our local files has been opened in response to
		 * a receiver request and now we can map it.  We'll
		 * respond to the event by looking at the map when the
		 * writer is available.  Here we also enable the poll
		 * event for output.
		 */

	  check_other:
		if (pfd[2].revents & POLLIN) {
			assert(up.cur != NULL);
			assert(up.stat.fd != -1);
			assert(up.stat.map == NULL);
			assert(up.stat.mapsz == 0);
			f = &fl.flp[up.cur->idx];

			if (fstat(up.stat.fd, &st) == -1) {
				ERR("%s: fstat", f->path);
				goto out;
			}

			/*
			 * If the file is zero-length, the map will
			 * fail, but either way we want to unset that
			 * we're waiting for the file to open and set
			 * that we're ready for the output channel.
			 */

			if ((up.stat.mapsz = st.st_size) > 0) {
				up.stat.map = fmap_open(f->path, up.stat.fd,
				    st.st_size);
				if (up.stat.map == NULL)
					goto out;
			}

			pfd[2].fd = -1;
			pfd[1].fd = fdout;
		}

		/*
		 * If we have buffers waiting to write, write them out
		 * as soon as we can in a non-blocking fashion.
		 * We must not be waiting for any local files.
		 * ALL WRITES MUST HAPPEN HERE.
		 * This keeps the sender deadlock-free.
		 */

		if ((pfd[1].revents & POLLOUT) && wbufsz > 0) {
			assert(pfd[2].fd == -1);
			assert(wbufsz - wbufpos);

			ssz = write(fdout, wbuf + wbufpos, wbufsz - wbufpos);
			if (ssz == -1) {
				ERR("write");
				goto out;
			}

			if (!io_data_written(sess, fdout,
			    wbuf + wbufpos, ssz)) {
				ERRX1("io_data_written");
				goto out;
			}

			wbufpos += ssz;
			if (wbufpos == wbufsz)
				wbufpos = wbufsz = 0;
			pfd[1].revents &= ~POLLOUT;

			/* 
			 * Enforce that our average bandwidth not exceed
			 * bwlimit by sleeping if we're up against the
			 * limit.  FIXME: move to a function.
			 */

			if (sess->opts->bwlimit) {
				gettimeofday(&tv, NULL);
				now = (double)tv.tv_sec + (double)tv.tv_usec / 
					1000000.0;
				if (sess->start_time == 0.0) {
					sess->start_time = now;
					rate = (double)sess->total_write;
					diff = 0.0;
				} else {
					diff = now - sess->start_time;
					rate = (double)sess->total_write / diff;
				}
				if (rate > sess->opts->bwlimit) {
					sleeptime = (double)sess->total_write /
					    sess->opts->bwlimit - diff;
					if (sleeptime > 0.0)
						usleep(sleeptime * 1000 * 1000);
				}
			}
		}

		/*
		 * Engage the FSM for the current transfer.  If we're in the
		 * BLKSTAT_PHASE state, then we won't need to write and it's
		 * sufficient to enter the fsm with just data to read.
		 *
		 * If our phase changes, stop processing.
		 */

		if (((up.stat.curst == BLKSTAT_PHASE && READ_AVAIL(pfd, &rbuf)) ||
		    (pfd[1].revents & POLLOUT)) && up.cur != NULL) {
			assert(pfd[2].fd == -1);
			assert(wbufpos == 0 && wbufsz == 0);
			if (sess->opts->compress)
				ret = send_up_fsm_compressed(sess, &phase, &up,
				    &wbuf, &wbufsz, &wbufmax, fl.flp);
			else
				ret = send_up_fsm(sess, &phase, &up,
				    &wbuf, &wbufsz, &wbufmax, fl.flp);

			if (!ret) {
				ERRX1("send_up_fsm");
				goto out;
			} else if (phase > max_phase)
				break;
		}

		/*
		 * Incoming queue management.
		 * If we have no queue component that we're waiting on,
		 * then pull off the receiver-request queue and start
		 * processing the request.
		 */

		if (up.cur == NULL) {
			assert(pfd[2].fd == -1);
			assert(up.stat.fd == -1);
			assert(up.stat.map == NULL);
			assert(up.stat.mapsz == 0);

			/*
			 * Wait until all pending output has been written before
			 * starting on the next download request.  This prevents
			 * the wbuf from growing without bound.
			 */
			if (wbufsz > 0) {
				pfd[1].fd = fdout;
				continue;
			}

			assert(wbufsz == 0 && wbufpos == 0);
			pfd[1].fd = -1;

			/*
			 * If there's nothing in the queue, then keep
			 * the output channel disabled and wait for
			 * whatever comes next from the reader.
			 */

			if ((up.cur = TAILQ_FIRST(&sdlq)) == NULL)
				continue;
			assert(up.cur->dlstate == SDL_DONE);
			TAILQ_REMOVE(&sdlq, up.cur, entries);

			/* Hash our blocks. */

			blkhash_set(up.stat.blktab, up.cur->blks);

			/*
			 * End of phase: enable channel to receiver.
			 * We'll need our output buffer enabled in order
			 * to process this event.
			 */

			if (up.cur->idx == -1) {
				pfd[1].fd = fdout;
				continue;
			}

			f = &fl.flp[up.cur->idx];

			if (!(f->iflags & IFLAG_TRANSFER)) {
				pos = wbufsz;
				send_iflags(sess, &wbuf, &wbufsz,
				    &wbufmax, &pos, fl.flp, up.cur->idx);
				send_up_reset(&up);
				pfd[1].fd = fdout;
				continue;
			}

			/*
			 * Non-blocking open of file.
			 * This will be picked up in the state machine
			 * block of not being primed.
			 *
			 * Some flist entries may be synthesized or redirected
			 * by the platform implementation, so call into the
			 * flist-specified open if provided.
			 */
			nextfl = &fl.flp[up.cur->idx];
			nlinkflag = 0;
			oflags = O_RDONLY | O_NONBLOCK;
			dirfd = AT_FDCWD;
			opath = nextfl->path;
			nlinkflag = O_NOFOLLOW;

			/*
			 * Room for improvement: --copy-links should really
			 * cause us to record the path at the time of flist
			 * generation and specifically send *that* file here,
			 * rather than relying on the link dereferencing to the
			 * same file twice.  At that point, we should be able
			 * to pick O_NOFOLLOW back up unconditionally.
			 */

			oflags |= nlinkflag;

			up.stat.fd = openat(dirfd, opath, oflags, 0);

			if (up.stat.fd == -1) {
				ERR("%s: open (2) in %s",
				    fl.flp[up.cur->idx].path,
				    getcwd(buf, sizeof(buf)));

				send_up_reset(&up);
				pfd[1].fd = fdout;
				continue;
			}
			pfd[2].fd = up.stat.fd;
		}
	}

	/*
	 * At this point there shouldn't be any data remaining
	 * in the sender's output buffer.
	 */

	assert(wbufsz == 0);
	sess->wbufp = NULL;

	if (!TAILQ_EMPTY(&sdlq)) {
		ERRX("phases complete with files still queued");
		goto out;
	}

	if (!sess_stats_send(sess, fdout)) {
		ERRX1("sess_stats_end");
		goto out;
	}

	/* Final "goodbye" message. */

	if (!sender_finalize(sess, &rbuf, fdin)) {
		ERRX1("sender_finalize");
		goto out;
	}

	LOG3("sender finished updating");
	rc = true;
out:
	send_up_reset(&up);
	while ((dl = TAILQ_FIRST(&sdlq)) != NULL) {
		TAILQ_REMOVE(&sdlq, dl, entries);
		free(dl->blks);
		free(dl);
	}
	flist_free(fl.flp, fl.sz);
	blkhash_free(up.stat.blktab);

	/*
	 * If we're the server and there was an error then try to flush
	 * any data remaining in the output buffer as it likely contains
	 * an error message.
	 */

	if (sess->wbufp != NULL) {
		/* Don't try to log errors over the socket anymore. */
		sess->wbufp = NULL;
		while (wbufsz > 0 && wbufpos != wbufsz) {
			assert(wbufsz > wbufpos);
			writesz = write(fdout, wbuf + wbufpos,
			    wbufsz - wbufpos);
			if (writesz == -1) {
				if (errno == EINTR)
					continue;

				/*
				 * Just stop at the first sign of problems, log
				 * it in case we're the daemon.
				 */

				ERRX1("write");
				break;
			} else if (writesz == 0)
				break;
			wbufpos += writesz;
		}
	}

	free(wbuf);
	iobuf_free(&rbuf);
	return rc;
}

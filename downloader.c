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
#include COMPAT_ENDIAN_H

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <zlib.h>
#include "extern.h"

/*
 * A small optimisation: have a 1 MB pre-write buffer.
 * Disable the pre-write buffer by having this be zero.
 * (It doesn't affect performance much.)
 */
#define	OBUF_SIZE	(1024 * 1024)

enum curst {
	COPY_FLUSH,
	COPY_WRITEBUF,
	COPY_DONE
};

enum	downloadst {
	DOWNLOAD_READ_NEXT = 0,
	DOWNLOAD_READ_LOCAL,
	DOWNLOAD_READ_REMOTE,
	DOWNLOAD_FLUSH_REMOTE,	/* I/O error -- flush until EOF */
};

static enum zlib_state   dec_state; /* decompression state */
static z_stream          dectx; /* decompression context */
static bool decompress_reinit(void); /* TODO: move to correct place in file */
static int buf_copy(const char *, size_t, struct download *, struct sess *); /* TODO: move to correct place in file */

/*
 * Like struct upload, but used to keep track of what we're downloading.
 * This also is managed by the receiver process.
 */
struct	download {
	enum downloadst	    state; /* state of affairs */
	size_t		    idx; /* index of current file */
	struct blkset	    blk; /* its blocks */
	struct fmap	   *map; /* mmap of current file */
	int		    ofd; /* open origin file */
	int		    fd; /* open output file */
	char		   *fname; /* output filename */
	MD4_CTX		    ctx; /* current hashing context */
	off_t		    downloaded; /* total downloaded */
	off_t		    total; /* total in file */
	struct flist	   *fl; /* file list */
	size_t		    flsz; /* size of file list */
	int		    rootfd; /* destination directory */
	int		    fdin; /* read descriptor from sender */
	char		   *obuf; /* pre-write buffer */
	size_t		    obufsz; /* current size of obuf */
	size_t		    obufmax; /* max size we'll wbuffer */
	bool		    needredo; /* needs redo phase */
	size_t		    curtok; /* current token (compression) */
};


/*
 * Reinitialise a download context w/o overwriting the persistent parts
 * of the structure (like p->fl or p->flsz) for index "idx".
 * The MD4 context is pre-seeded.
 */
static void
download_reinit(struct sess *sess, struct download *p, size_t idx)
{
	int32_t seed = htole32(sess->seed);

	assert(p->state == DOWNLOAD_READ_NEXT);

	p->idx = idx;
	memset(&p->blk, 0, sizeof(struct blkset));
	p->map = NULL;
	p->ofd = -1;
	p->fd = -1;
	p->fname = NULL;
	MD4_Init(&p->ctx);
	p->downloaded = p->total = 0;
	/* Don't touch p->fl. */
	/* Don't touch p->flsz. */
	/* Don't touch p->rootfd. */
	/* Don't touch p->fdin. */
	/* Don't touch p->obufsz. */
	/* Don't touch p->obufmax. */
	/* Don't touch p->needredo. */
	p->curtok = 0;
	MD4_Update(&p->ctx, &seed, sizeof(int32_t));
	(void)decompress_reinit();
}

static inline bool
download_is_inplace(struct sess *sess, struct download *p,
    bool resumed_only)
{
	return false;
}

/*
 * Cleanup any partial bits of a transfer.  This may mean anything from
 * do nothing to moving the file into place if we've been instructed to.
 * It may be called from a signal context, so we should take care to
 * only do async-signal-safe things.
 *
 * This function may fail if we couldn't move the file into place for
 * some reason, but p->fd is guaranteed to be cleaned up either way.
 */
static bool
download_cleanup_partial(struct sess *sess, struct download *p)
{
	struct flist	*f;

	if (p->fl == NULL)
		return true;

	f = &p->fl[p->idx];
	if (p->fd == -1 || (f->flstate & FLIST_SUCCESS))
		return 1;

	/* Flush any buffered writes to the file */

	buf_copy(NULL, 0, p, sess);
	close(p->fd);
	p->fd = -1;

	if (p->fname == NULL)
		return true;

	(void)unlinkat(p->rootfd, p->fname, 0);
	return true;
}

/*
 * Free a download context.  If "cleanup" is set, we also try to clean
 * up the temporary file, assuming that it has been opened in p->fd.
 */
static void
download_cleanup(struct sess *sess, struct download *p, bool cleanup)
{
	fmap_close(p->map);
	p->map = NULL;

	if (p->ofd != -1) {
		close(p->ofd);
		p->ofd = -1;
	}

	if (cleanup && !download_cleanup_partial(sess, p)) {
		ERR("%s: partial cleanup failed, left at %s",
		    p->fl[p->idx].path, p->fname);
	}

	/*
	 * download_cleanup_partial() may not close the fd if we did
	 * succeed and we just want to cleanup the partial dir that we
	 * resumed out of, so we double-check here just in case.
	 */

	if (p->fd != -1) {
		close(p->fd);
		p->fd = -1;
	}

	free(p->fname);
	p->fname = NULL;
	p->state = DOWNLOAD_READ_NEXT;
}

/*
 * Initial allocation of the download object using the file list "fl" of
 * size "flsz", the destination "rootfd", and the sender read "fdin".
 * Returns NULL on allocation failure.
 * On success, download_free() must be called with the pointer.
 */
struct download *
download_alloc(struct sess *sess, int fdin, struct flist *fl,
    size_t flsz, int rootfd)
{
	struct download	*p;

	if ((p = malloc(sizeof(struct download))) == NULL) {
		ERR("malloc");
		return NULL;
	}

	p->state = DOWNLOAD_READ_NEXT;
	p->fl = fl;
	p->flsz = flsz;
	p->rootfd = rootfd;
	p->fdin = fdin;
	p->needredo = false;
	download_reinit(sess, p, 0);
	p->obufsz = 0;
	p->obuf = NULL;
	p->obufmax = OBUF_SIZE;
	if (p->obufmax && (p->obuf = malloc(p->obufmax)) == NULL) {
		ERR("malloc");
		free(p);
		return NULL;
	}
	return p;
}

bool
download_needs_redo(const struct download *p)
{
	return p->needredo;
}

/*
 * Perform all cleanups (including removing stray files) and free.
 * Passing a NULL to this function is ok.
 */
void
download_free(struct sess *sess, struct download *p)
{

	if (p == NULL)
		return;
	download_cleanup(sess, p, 1);
	free(p->obuf);
	free(p);
}

/*
 * Write all data in the buffer.
 * Returns true on success, false on failure.
 */
static bool
downloader_write(const struct download *p, const char *buf, size_t sz)
{
	ssize_t	 ssz; /* amount written */
retry:
	ssz = write(p->fd, buf, sz);
	if (ssz == -1) {
		if (errno == EINTR)
			goto retry;
		ERR("%s: write", p->fname);
		return false;
	} else if ((size_t)ssz != sz) {
		ERRX("%s: short write", p->fname);
		return false;
	}

	return true;
}

static bool
buf_copy_chunk(struct download *p, const char **pwritebuf,
    size_t *pwritesz)
{
	size_t		 clipsz = (size_t)-1;
	const char	*writebuf = *pwritebuf;
	size_t		 writesz = *pwritesz;

	clipsz = MINIMUM(clipsz, writesz);
	assert(clipsz != 0);

	if (!downloader_write(p, writebuf, clipsz))
		return false;

	/*
	 * If we clipped it, then we should adjust our writesz/writebuf
	 * and restart at the beginning of this state with re-evaluating
	 * the new block.
	 */

	*pwritebuf += clipsz;
	*pwritesz -= clipsz;
	return true;
}

/*
 * Optimisation: instead of dumping directly into the output file, keep
 * a buffer and write as much as we can into the buffer.  That way, we
 * can avoid calling write() too much, and instead call it with big
 * buffers.  To flush the buffer w/o changing it, pass 0 as "sz".
 * Returns zero on failure, non-zero on success.
 */
static int
buf_copy(const char *buf, size_t sz, struct download *p,
    struct sess *sess)
{
	const char	*writebuf;
	size_t		*pwritesz;
	size_t	 	 rem,
			 tocopy,
			 origsz;
	enum curst	 curst = COPY_FLUSH;

	assert(p->obufsz <= p->obufmax);

	/*
	 * Copy as much as we can.
	 * If we've copied everything, exit.
	 * If we have no pre-write buffer (obufmax of zero), this never
	 * gets called, so we never buffer anything.
	 */

	if (sz && p->obufsz < p->obufmax) {
		assert(p->obuf != NULL);
		rem = p->obufmax - p->obufsz;
		assert(rem > 0);
		tocopy = rem < sz ? rem : sz;
		memcpy(p->obuf + p->obufsz, buf, tocopy);
		sz -= tocopy;
		buf += tocopy;
		p->obufsz += tocopy;
		assert(p->obufsz <= p->obufmax);
		if (sz == 0)
			return 1;
	}

	/* Drain the main buffer. */

	if (p->obufsz) {
		assert(p->obufmax);
		assert(p->obufsz <= p->obufmax);
		assert(p->obuf != NULL);
	}

	/* If the file is gone, we're just here to zap the obuf. */

	if (p->fd < 0) {
		p->obufsz = 0;
		return 1;
	}

	while (curst != COPY_DONE) {
		/*
		 * There's an obvious progression here: we want to drain
		 * anything left in the output buffer, then we can write
		 * out anything that's left in the buf passed in.  In
		 * order to get sparsity right, we need identical
		 * treatment for both buffers or we'll end up missing
		 * opportunities to create holes.
		 */

		switch (curst) {
		case COPY_FLUSH:
			/*
			 * Don't actually lose our p->obuf position,
			 * just adjust the stack pointer to it.
			 */
			writebuf = p->obuf;
			pwritesz = &p->obufsz;
			break;
		case COPY_WRITEBUF:
			writebuf = buf;
			pwritesz = &sz;
			break;
		default:
			assert(0 && "Unreachable");
			break;
		}

		origsz = *pwritesz;
		while (*pwritesz != 0) {
			if (!buf_copy_chunk(p, &writebuf, pwritesz))
				return 0;
			/* Confirm that our math isn't off somewhere. */
			assert(*pwritesz <= origsz);
		}

		curst++;
	}

	return 1;
}

/*
 * Fix metadata of the temp file based on the original destination file.
 * This is the logical inverse of rsync_set_metadata*() as we're
 * determining which of the metadata won't be clobbered by preseration
 * of the source file.  Returns true on success, false on failure.
 */
static bool
download_fix_metadata(const struct sess *sess, const char *fname,
    int fd, const struct stat *ost)
{
	uid_t	 uid = (uid_t)-1, puid = (uid_t)-1;
	gid_t	 gid = (gid_t)-1, pgid = (gid_t)-1;
	mode_t	 mode;

	if (!sess->opts->preserve_uids) {
		puid = geteuid();
		if (puid != ost->st_uid && puid == 0)
			uid = ost->st_uid;
	}

	if (!sess->opts->preserve_gids) {
		pgid = getegid();
		if (pgid != ost->st_gid)
			gid = ost->st_gid;
	}

	/*
	 * Unlike rsync_set_metadata, we're using perms from the local
	 * system and thus, we'll trust them a little bit more.
	 */

	mode = ost->st_mode & ALLPERMS;
	if (uid != (uid_t)-1 || gid != (gid_t)-1) {
		if (fchown(fd, uid, gid) == -1) {
			if (errno != EPERM) {
				ERR("%s: fchown", fname);
				return false;
			}
			if (geteuid() == 0)
				WARNX("%s: identity unknown or not "
				    "available to user.group: %u.%u",
				    fname, uid, gid);
		}
	}

	if (!sess->opts->preserve_perms && fchmod(fd, mode) == -1) {
		ERR("%s: fchmod", fname);
		return false;
	}

	return true;
}

/*
 * Deal with the conditional "follows" flags for extra metadata.
 * Returns false on failure, true on success.
 */
static int
download_get_iflags(struct sess *sess, int fd, struct flist *f)
{
	int32_t	 iflags = f->iflags;
	uint8_t	 basis;

	if (iflags & IFLAG_BASIS_FOLLOWS) {
		if (!io_read_byte(sess, fd, &basis)) {
			ERRX1("io_read_byte");
			return false;
		}
		f->basis = basis;
	}
	if (iflags & IFLAG_HLINK_FOLLOWS) {
		if (f->link != NULL) {
			free(f->link);
			f->link = NULL;
		}
		if (!io_read_vstring(sess, fd, &f->link)) {
			ERRX1("io_read_vstring");
			return false;
		}
	}
	return true;
}

/*
 * The "token" stands in as the header of each block.  This is the
 * return code from parsing the token.
 */
enum protocol_token_result {
	TOKEN_ERROR,
	TOKEN_EOF,
	TOKEN_NEXT,
	TOKEN_RETRY,
};

static void
dec_state_change(enum zlib_state newstate)
{
	LOG4("decompress_state transition %d -> %d", dec_state, newstate);
	dec_state = newstate;
}

/*
 * Stream has been fully read: flush out remaining bytes in the
 * compressed buffer into the file.  Returns false on failure, true on
 * success.
 */
static bool
protocol_token_cflush(struct sess *sess, struct download *p,
    const char *dbuf)
{                       
	int              res;
	size_t           dsz;
	char             tbuf[4];

	if (dectx.next_out == NULL)
		return true;

	assert(dbuf != NULL);

	dectx.avail_in = 0;
	dectx.avail_out = MAX_CHUNK_BUF;
	res = inflate(&dectx, Z_SYNC_FLUSH);
	if (res != Z_OK && res != Z_BUF_ERROR) {
		ERRX("inflate protocol_token_cflush res=%d", res);
		if (dectx.msg)
			ERRX("inflate error: %s", dectx.msg);
		return false;
	}

	dsz = MAX_CHUNK_BUF - dectx.avail_out;
	if (dsz != 0 && res != Z_BUF_ERROR) {
		if (!buf_copy(dbuf, dsz, p, sess)) {
			ERRX("buf_copy dbuf");
			return false;
		}
		MD4_Update(&p->ctx, dbuf, dsz);
	}       

	/* Check for compressor sync: 0x00 0x00 0xff 0xff */             

	if ((res = inflateSyncPoint(&dectx)) != 1) {
		ERRX("inflateSyncPoint res=%d", res);
		return false;
	}

	dectx.avail_in = 4;
	dectx.next_in = (Bytef *)&tbuf;
	tbuf[0] = 0;
	tbuf[1] = 0;
	tbuf[2] = 0xff;
	tbuf[3] = 0xff;

	/* "res" not checked on purpose, this is only to sync state. */
	res = inflate(&dectx, Z_SYNC_FLUSH);
	(void)res;

	return true;
}

/*
 * Initialise the zlib decompression state. Returns true on success,
 * false on error.
 */
static bool
decompress_reinit(void)
{  
	int ret;

	if (dec_state == COMPRESS_INIT) {
		dectx.zalloc = NULL;
		dectx.zfree = NULL;
		dectx.next_in = NULL;
		dectx.avail_in = 0;
		dectx.next_out = NULL;
		dectx.avail_out = 0;
		if ((ret = inflateInit2(&dectx, -15)) != Z_OK) {
			ERRX("inflateInit2 res=%d", ret);
			return false;
		}
		dec_state_change(COMPRESS_READY);
	} else if (dec_state >= COMPRESS_DONE) {
		dectx.next_in = NULL;
		dectx.avail_in = 0;
		dectx.next_out = NULL;
		dectx.avail_out = 0;
		inflateReset(&dectx);
		dec_state_change(COMPRESS_READY);
	}

	return true; 
}

/*
 * Decompress the block at index "tok".  Return true on success, false
 * on failure.
 */
static bool
protocol_token_ff_compress(struct sess *sess, struct download *p,
    size_t tok)
{
	const char	*buf;
	char		*dbuf;
	size_t		 sz, clen, rlen;
	off_t		 off;
	unsigned char	 hdr[5];
	int		 res;

	if (tok >= p->blk.blksz) {
		ERRX("%s: token not in block set: %zu (have %zu blocks)",
		    p->fname, tok, p->blk.blksz);
		return false;
	}
	sz = (tok == p->blk.blksz - 1 && p->blk.rem) ?
	    p->blk.rem : p->blk.len;
	assert(sz);
	if (p->map == NULL) {
		WARNX1("no map file (removed or truncated)");
		p->state = DOWNLOAD_FLUSH_REMOTE;
		return true;
	}

	off = tok * p->blk.len;
	if (!fmap_access_valid(p->map, off, sz)) {
		/*
		 * We can easily have a mismatch here: the uploader
		 * sends our initial file information, and the
		 * downloader independently opens the file and maps it
		 * Nothing stops the file from changing in between the
		 * two, so we have to cope with possibilities like this
		 * and trigger redo.
		 */
		WARNX1("%s: block at %lld outside of local file sized %zu",
		    p->fname, off, fmap_size(p->map));
		p->state = DOWNLOAD_FLUSH_REMOTE;
		return TOKEN_NEXT;
	} else if (!fmap_trap(p->map)) {
		p->state = DOWNLOAD_FLUSH_REMOTE;
		return TOKEN_NEXT;
	}

	buf = fmap_data(p->map, off, sz);

	if (!decompress_reinit()) {
		ERRX("decompress_reinit");
		fmap_untrap(p->map);
		return false;
	}

	dbuf = sess->token_dbuf;
	if (sess->token_dbufsz < MAX_CHUNK_BUF) {
		/* TODO: use realloc */
		dbuf = malloc(MAX_CHUNK_BUF);
		if (dbuf == NULL) {
			ERRX1("malloc");
			fmap_untrap(p->map);
			return false;
		}
		free(sess->token_dbuf);
		sess->token_dbuf = dbuf;
		sess->token_dbufsz = MAX_CHUNK_BUF;
	}

	dectx.avail_in = 0;
	rlen = sz;
	clen = 0;
	hdr[0] = '\0';
	res = Z_OK;

	while (res == Z_OK) {
		if (dectx.avail_in == 0) {
			if (clen == 0) {
				/* Provide a stored-block header */
				clen = rlen;
				if (clen > 0xffff)
					clen = 0xffff;
				hdr[1] = clen;
				hdr[2] = clen >> 8;
				hdr[3] = ~hdr[1];
				hdr[4] = ~hdr[2];
				dectx.next_in = (Bytef *)hdr;
				dectx.avail_in = 5;
			} else {
				dectx.next_in = (Bytef *)buf;
				dectx.avail_in = (uInt)clen;
				rlen -= clen;
				clen = 0;
			}
		}
		dectx.next_out = (Bytef *)dbuf;
		dectx.avail_out = MAX_CHUNK_BUF;

		res = inflate(&dectx, Z_SYNC_FLUSH);

		if (res != Z_OK) {
			fmap_untrap(p->map);
			ERRX("inflate ff res=%d", res);
			if (dectx.msg)
				ERRX("inflate error: %s", dectx.msg);
			return false;
		}
		if (dectx.avail_out == 0)
			continue;
		else if (rlen == 0)
			break;
	}

	fmap_untrap(p->map);
	return true;
}

/*
 * Local copy following [block-xchng-unc-1] at token "tok".
 * Returns TOKEN_ERROR on failure, TOKEN_RETRY on success and immediate
 * retry, and TOKEN_NEXT on success and wait.
 */
static enum protocol_token_result
protocol_token_ff(struct sess *sess, struct download *p, size_t tok)
{
	const char	*buf; /* pointer to copy from */
	size_t		 sz; /* size to copy */
	off_t		 off; /* offset in buffer */
	int		 c; /* temporary */

	assert(p->state != DOWNLOAD_FLUSH_REMOTE);

	if (tok >= p->blk.blksz) {
		ERRX("%s: token not in block set: %zu (have %zu blocks)",
		    p->fname, tok, p->blk.blksz);
		return TOKEN_ERROR;
	}

	sz = (tok == p->blk.blksz - 1 && p->blk.rem) ?
	    p->blk.rem : p->blk.len;
	assert(sz);
	if (p->map == NULL) {
		WARNX1("no map file (removed or truncated)");
		p->state = DOWNLOAD_FLUSH_REMOTE;
		return TOKEN_NEXT;
	}

	off = tok * p->blk.len;
	if (!fmap_access_valid(p->map, off, sz)) {
		/*
		 * We can easily have a mismatch here: the uploader
		 * sends our initial file information, and the
		 * downloader independently opens the file and maps it
		 * Nothing stops the file from changing in between the
		 * two, so we have to cope with possibilities like this
		 * and trigger redo.
		 */
		WARNX1("%s: block at %lld outside of local file sized %zu",
		    p->fname, off, fmap_size(p->map));
		p->state = DOWNLOAD_FLUSH_REMOTE;
		return TOKEN_NEXT;
	} else if (!fmap_trap(p->map)) {
		p->state = DOWNLOAD_FLUSH_REMOTE;
		return TOKEN_NEXT;
	}

	buf = fmap_data(p->map, off, sz);

	/*
	 * Now we read from our block.
	 * We should only be at this point if we have a block to read
	 * from, i.e., if we were able to map our origin file and create
	 * a block profile from it.
	 */

	if (!buf_copy(buf, sz, p, sess)) {
		fmap_untrap(p->map);
		ERRX("buf_copy");
		return TOKEN_ERROR;
	}

	fmap_untrap(p->map);

	if (!sess->opts->dry_run && !buf_copy(NULL, 0, p, sess)) {
		ERRX("buf_copy");
		return TOKEN_ERROR;
	}

	if (sess->opts->compress) {
		if (!protocol_token_ff_compress(sess, p, tok)) {
			ERRX1("protocol_token_ff_compress");
			return TOKEN_ERROR;
		}
		if (p->state == DOWNLOAD_FLUSH_REMOTE)
			return TOKEN_NEXT;
	}

	p->total += sz;
	LOG4("%s: copied %zu B", p->fname, sz);

	if (!fmap_trap(p->map)) {
		p->state = DOWNLOAD_FLUSH_REMOTE;
		return TOKEN_NEXT;
	}
	MD4_Update(&p->ctx, buf, sz);
	fmap_untrap(p->map);

	/* Fast-track more reads as they arrive. */

	if ((c = io_read_check(sess, p->fdin)) < 0) {
		ERRX1("io_read_check");
		return TOKEN_ERROR;
	} else if (c > 0)
		return TOKEN_RETRY;

	return TOKEN_RETRY; /* TODO: make TOKEN_NEXT */
}

/*
 * Read compressed block data.
 * Returns TOKEN_ERROR on failure, TOKEN_RETRY if there's data
 * immediately to read, TOKEN_NEXT to wait for more data, or TOKEN_EOF
 * for end of blocks.
 */
static enum protocol_token_result
protocol_token_compressed(struct sess *sess, struct download *p)
{
	int32_t		 tok = (int32_t)p->curtok; /* current token */
	uint8_t		 flag; /* header flag */
	size_t		 runsize, /* number of blocks to deco */
			 dsz; /* temporary */
	bool		 need_count = false; /* need more data */
	int		 res; /* temporary */
	char		*buf, /* block (compressed) buffer */
			*dbuf; /* decompressed buffer */
	uint16_t 	 bufsz; /* size of buf to read */
	uint8_t		 sizelo,
			 part;

	/* Reads [block-xchng-com-1]. */

	if (!io_read_byte(sess, p->fdin, &flag)) {
		ERRX1("io_read_byte");
		return TOKEN_ERROR;
	}

	/* Allocate decompression buffer. */

	dbuf = sess->token_dbuf;
	if (sess->token_dbufsz < MAX_CHUNK_BUF) {
		/* FIXME: realloc() */
		dbuf = malloc(MAX_CHUNK_BUF);
		if (dbuf == NULL) {
			ERRX1("malloc");
			return TOKEN_ERROR;
		}
		free(sess->token_dbuf);
		sess->token_dbuf = dbuf;
		sess->token_dbufsz = MAX_CHUNK_BUF;
	}

	if ((flag & TOKEN_RUN_RELATIVE) == TOKEN_DEFLATED) {
		/* Reads [block-xchng-com-1a]. */
		if (!io_read_byte(sess, p->fdin, &sizelo)) {
			ERRX1("io_read_int");
			return TOKEN_ERROR;
		}

		/* Combine bytes for deflation buffer size. */

		bufsz = ((flag & ~TOKEN_DEFLATED) << 8) | sizelo;

		buf = sess->token_buf;
		if (sess->token_bufsz < bufsz) {
			/* FIXME: realloc() */
			buf = malloc(bufsz);
			if (buf == NULL) {
				ERRX1("malloc");
				return TOKEN_ERROR;
			}
			free(sess->token_buf);
			sess->token_buf = buf;
			sess->token_bufsz = bufsz;
		}

		/* Reads [block-xchng-com-1b]. */

		if (!io_read_buf(sess, p->fdin, buf, bufsz)) {
			ERRX1("io_read_buf");
			return TOKEN_ERROR;
		}

		if (p->state == DOWNLOAD_FLUSH_REMOTE)
			return TOKEN_NEXT;

		dec_state_change(COMPRESS_RUN);

		dectx.next_in = (Bytef *)buf;
		dectx.avail_in = bufsz;
		dectx.next_out = (Bytef *)dbuf;
		dectx.avail_out = MAX_CHUNK_BUF;

		while (dectx.avail_in != 0 &&
		    (res = inflate(&dectx, Z_NO_FLUSH)) == Z_OK) {
			dsz = MAX_CHUNK_BUF - dectx.avail_out;
			if (!buf_copy(dbuf, dsz, p, sess)) {
				ERRX("buf_copy dbuf");
				return TOKEN_ERROR;
			}
			MD4_Update(&p->ctx, dbuf, dsz);
			p->total += dsz;
			p->downloaded += bufsz;
			dectx.next_out = (Bytef *)dbuf;
			dectx.avail_out = MAX_CHUNK_BUF;
		}

		if (res != Z_OK && res != Z_BUF_ERROR) {
			ERRX("inflate res=%d", res);
			if (dectx.msg != NULL)
				ERRX("inflate error: %s", dectx.msg);
			return TOKEN_ERROR;
		}

		/* Input stream exhausted: write out remaining data. */

		dsz = MAX_CHUNK_BUF - dectx.avail_out;
		if (dsz != 0) {
			if (!buf_copy(dbuf, dsz, p, sess)) {
				ERRX("buf_copy");
				return TOKEN_ERROR;
			}
			MD4_Update(&p->ctx, dbuf, dsz);
		}

		p->total += dsz;
		p->downloaded += bufsz;
		assert(dectx.avail_in == 0);
		dec_state_change(COMPRESS_DONE);
		return TOKEN_RETRY;
	} else if (dec_state == COMPRESS_DONE) {
		LOG4("decompress_state: flushing end of stream");
		if (!protocol_token_cflush(sess, p, dbuf)) {
			ERRX("protocol_token_cflush");
			return TOKEN_ERROR;
		}
		dec_state_change(COMPRESS_READY);
	}

	/* End of file case. */

	if (flag == 0) {
		dec_state_change(COMPRESS_INIT);
		return TOKEN_EOF;
	}

	if (flag & TOKEN_RELATIVE) {
		/*
		 * Matches both TOKEN_RELATIVE and TOKEN_RUN_RELATIVE.
		 * The token is the lower 6 bits of flag.
		 * Token is relative to where we previously wrote.
		 * If this is TOKEN_RUN_RELATIVE, it will be followed by a
		 * 16 bit run count, (we set need_count to read this below).
		 */
		tok += (flag & ~TOKEN_RUN_RELATIVE);
		flag >>= 6;
		need_count = (flag & 1);
	} else if (flag & TOKEN_LONG) {
		/* Read [block-xchng-com-1c]. */
		if (!io_read_int(sess, p->fdin, &tok)) {
			ERRX1("io_read_int");
			return TOKEN_ERROR;
		}
		need_count = (flag & 1);
	}

	/*
	 * How many consecutive blocks to decompress?  If "need_count",
	 * then get that from the server; otherwise, assume it's one.
	 */

	runsize = 0;
	if (need_count) {
		/* Read [block-xchng-com-1d-a, block-xchng-com-1d-b]. */
		if (!io_read_byte(sess, p->fdin, &part)) {
			ERRX1("io_read_byte");
			return TOKEN_ERROR;
		}
		runsize = part;
		if (!io_read_byte(sess, p->fdin, &part)) {
			ERRX1("io_read_byte");
			return TOKEN_ERROR;
		}
		runsize |= part << 8;
		dec_state_change(COMPRESS_SEQUENCE);
	}

	for (dsz = 0;
	    dsz < runsize + 1 && p->state != DOWNLOAD_FLUSH_REMOTE;
	    dsz++) {
		if (dsz == runsize)
			dec_state_change(COMPRESS_READY);
		res = protocol_token_ff(sess, p, tok++);
		if (res != TOKEN_RETRY) {
			if (p->state != DOWNLOAD_FLUSH_REMOTE)
				ERRX("protocol_token_ff res=%d", res);
			return res;
		}
	}

	p->curtok = tok - 1;
	return TOKEN_RETRY;
}

/*
 * Read uncompressed block data.
 * Returns TOKEN_ERROR on failure, TOKEN_RETRY if there's data
 * immediately to read, TOKEN_NEXT to wait for more data, or TOKEN_EOF
 * for end of blocks.
 */
static enum protocol_token_result
protocol_token_raw(struct sess *sess, struct download *p)
{
	char            *buf; /* block buffer */
	size_t           sz, /* size of block buffer */
			 tok; /* on-disc token */
	int32_t          rawtok; /* size/inv-block token */
	int              c; /* temporary value */

	/* Reads [block-xchng-unc-1] */

	if (!io_read_int(sess, p->fdin, &rawtok)) {
		ERRX1("io_read_int");
		return TOKEN_ERROR;
	}

	if (rawtok > 0) {
		/*
		 * Block is for copying from file stream.
		 * Interpret rawtok as the size to read.
		 * Reads [block-xchng-unc-1a].
		 */
		sz = rawtok;
		buf = sess->token_buf;
		if (sess->token_bufsz < sz) {
			/* FIXME: use realloc() */
			buf = malloc(sz);
			if (buf == NULL) {
				ERRX1("malloc");
				return TOKEN_ERROR;
			}
			free(sess->token_buf);
			sess->token_buf = buf;
			sess->token_bufsz = sz;
		}
		if (!io_read_buf(sess, p->fdin, buf, sz)) {
			ERRX1("io_read_buf");
			return TOKEN_ERROR;
		} else if (p->state != DOWNLOAD_FLUSH_REMOTE &&
		    !buf_copy(buf, sz, p, sess)) {
			ERRX("buf_copy");
			return TOKEN_ERROR;
		}
		p->total += sz;
		p->downloaded += sz;
		LOG4("%s: received %zu B block", p->fname, sz);
		MD4_Update(&p->ctx, buf, sz);

		/* Fast-track more reads as they arrive. */

		if ((c = io_read_check(sess, p->fdin)) < 0) {
			ERRX1("io_read_check");
			return TOKEN_ERROR;
		} else if (c > 0)
			return TOKEN_RETRY;

		return TOKEN_NEXT;
	} else if (rawtok < 0) {
		tok = -rawtok - 1;
		/*
		 * On errors, ignore remaining blocks.
		 */
		if (p->state == DOWNLOAD_FLUSH_REMOTE)
			return TOKEN_NEXT;
		/*
		 * Block is for local copying.
		 * Interpret rawtok as the index to copy.
		 */
		return protocol_token_ff(sess, p, tok);
	}

	/* Block is at the end of file (no data). */

	return TOKEN_EOF;
}

/*
 * The downloader waits on a file the sender is going to give us, opens
 * and mmaps the existing file, opens a temporary file, dumps the file
 * (or metadata) into the temporary file, then renames.
 * This happens in several possible phases to avoid blocking.
 * Returns <0 on failure, 0 on no more data (end of phase), >0 on
 * success (more data to be read from the sender).
 */
int
rsync_downloader(struct download *p, struct sess *sess, int *ofd)
{
	int32_t		 		 idx = -1, /* file index */
					 sendidx, /* sender index */
					 iflags; /* sender flags */
	struct flist			*f = NULL; /* file at index */
	struct stat	 		 st; /* original file */
	unsigned char	 		 ourmd[MD4_DIGEST_LENGTH],
			 		 md[MD4_DIGEST_LENGTH];
	enum protocol_token_result	 tokres; 
	const char			*path; /* path to open */
	int				 rootfd, /* where path rooted */
					 fromfd; /* temporary */
	char            		*usethis = NULL;
	bool				 newfile;

	/*
	 * If we don't have a download already in session, then the next
	 * one is coming in.
	 * Read either the stop (phase) signal from the sender or block
	 * metadata, in which case we open our file and wait for data.
	 */

	if (p->state == DOWNLOAD_READ_NEXT) {
		/* Read [file-index]. */
		if (!io_read_int(sess, p->fdin, &sendidx)) {
			ERRX1("io_read_int");
			return -1;
		} else if (sendidx < 0) {
			LOG3("downloader: phase complete");
			return 0;
		}

		/*
		 * Get the itemise flags.  This tool currently doesn't
		 * support itemisation (TODO), so hard-code this to the
		 * following.
		 */

		iflags = IFLAG_TRANSFER | IFLAG_MISSING_DATA;

		if ((uint32_t)sendidx == sess->sender_flsz) {
			ERRX1("invalid item flags 0x%x for sendidx %d",
			    iflags, sendidx);
			return -1;
		}

		/* TODO: translation when trimming duplicates. */

		idx = sendidx;

		if (idx == -1) {
			ERRX1("sendidx %d translation failed", sendidx);
			return -1;
		}

		f = &p->fl[idx];
		f->iflags = iflags;

		if (!download_get_iflags(sess, p->fdin, f)) {
			ERRX1("download_get_iflags");
			return -1;
		}

		if (!(f->iflags & IFLAG_TRANSFER)) {
			/*
			 * Untransferred items are subject to
			 * conditional logging.
			 */
			log_item(sess, f);
			return 1;
		}

		if (sess->opts->dry_run)
			log_item_impl(LT_CLIENT, sess, f);

		/*
		 * Short-circuit: dry_run mode does nothing, with one
		 * exception: if we're the client on an
		 * --only-write-batch transfer, we need to receive the
		 *  data, record it and throw it away.
		 */

		if (sess->opts->dry_run)
			return 1;

		/*
		 * Now get our block information.
		 * This is all we'll need to reconstruct the file from
		 * the map, as block sizes are regular.
		 * Reads [file-xxxx].
		 */

		download_reinit(sess, p, idx);
		if (!blk_send_ack(sess, p->fdin, &p->blk)) {
			ERRX1("blk_send_ack");
			goto out;
		}

		/*
		 * Next, we want to open the existing file for using as
		 * block input.
		 * We do this in a non-blocking way, so if the open
		 * succeeds, then we'll go reentrant til the file is
		 * readable and we can mmap() it.
		 * Set the file descriptor that we want to wait for.
		 */

		p->state = DOWNLOAD_READ_LOCAL;

		rootfd = p->rootfd;
		path = f->path;

		p->ofd = openat(p->rootfd, f->path, O_RDONLY | O_NONBLOCK);

		if (p->ofd == -1 && errno != ENOENT && rootfd != -1) {
			ERR("%s: rsync_downloader: openat", path);
			goto out;
		} else if (p->ofd != -1) {
			/*
			 * We need to double-check that the existing
			 * entry is actually a file, because it could be
			 * a symlink to a directory or some other
			 * non-file if we're racing something else.
			 * We're not too concerned about the file having
			 * been replaced completely after the uploader
			 * sent block information, as we'll just
			 * assemble a likely incorrect file and fail the
			 * checksum at the end to trigger a redo.
			 */
			if (fstat(p->ofd, &st) == -1 ) {
				ERR("%s: fstat", f->path);
				close(p->ofd);
				p->ofd = -1;
				goto out;
			}

			if (!S_ISREG(st.st_mode)) {
				close(p->ofd);
				p->ofd = -1;
			} else {
				*ofd = p->ofd;
				return 1;
			}
		}

		/* Fall-through: there's no file. */
	}

	/*
	 * At this point, the server is sending us data and we want to
	 * hoover it up as quickly as possible or we'll deadlock.
	 * We want to be pulling off of f->fdin as quickly as possible,
	 * so perform as much buffering as we can.
	 */

	f = &p->fl[p->idx];

	/*
	 * Next in sequence: we have an open download session but
	 * haven't created our temporary file.
	 * This means that we've already opened (or tried to open) the
	 * original file in a nonblocking way, and we can map it.
	 */

	if (p->state == DOWNLOAD_READ_LOCAL) {
		assert(p->fname == NULL);

		if (sess->opts->dry_run) {
			/*
			 * Ideally we'd just be able to drive the token
			 * protocol a little more cleanly.
			 */
			*ofd = -1;
			p->state = DOWNLOAD_READ_REMOTE;
			return 1;
		}

		/*
		 * Try to fstat() the file descriptor if valid and make
		 * sure that we're still a regular file.
		 * Then, if it has non-zero size, mmap() it for hashing.
		 */

		if (p->ofd != -1 && fstat(p->ofd, &st) == -1) {
			ERR("%s: fstat", f->path);
			goto out;
		} else if (p->ofd != -1 && !S_ISREG(st.st_mode)) {
			WARNX("%s: not regular", f->path);
			goto out;
		}

		if (p->ofd != -1 && st.st_size > 0) {
			p->map = fmap_open(f->path, p->ofd, st.st_size);
			if (p->map == NULL)
				goto out;
		}

		/* Success either way: we don't need this. */

		*ofd = -1;

		/* Create the temporary file. */

		if (mktemplate(&p->fname, f->path,
		    sess->opts->recursive || strchr(f->path, '/') != NULL,
		    false) == -1) {
			ERRX1("mktemplate");
			goto out;
		}

		if ((p->fd = mkstempat(p->rootfd, p->fname)) == -1) {
			ERR("mkstempat: %s", p->fname);
			goto out;
		} else if (p->ofd != -1)
			if (!download_fix_metadata(sess, p->fname,
			    p->fd, &st))
				goto out;

		/*
		 * FIXME: we can technically wait until the temporary
		 * file is writable, but since it's guaranteed to be
		 * empty, I don't think this is a terribly expensive
		 * operation as it doesn't involve reading the file into
		 * memory beforehand.
		 */

		LOG3("%s: temporary: %s", f->path, p->fname);

		p->state = DOWNLOAD_READ_REMOTE;
		return 1;
	}

	/*
	 * This matches the sequence in blk_flush().
	 * If we've gotten here, then we have a possibly-open map file
	 * (not for new files) and our temporary file is writable.
	 * We read the size/token, then optionally the data.
	 * The size >0 for reading data, 0 for no more data, and <0 for
	 * a token indicator.
	 */

again:
	assert(p->state == DOWNLOAD_READ_REMOTE ||
	    p->state == DOWNLOAD_FLUSH_REMOTE);
	assert(p->fname != NULL || sess->opts->dry_run);
	assert(p->fdin != -1);

	if (sess->opts->compress)
		tokres = protocol_token_compressed(sess, p);
	else
		tokres = protocol_token_raw(sess, p);

	switch (tokres) { 
	case TOKEN_EOF:
		break;  
	case TOKEN_RETRY:
		goto again;
	case TOKEN_NEXT: 
		return 1;
	case TOKEN_ERROR:
		/* FALLTHROUGH */
	default:
		goto out;
	}

	if (!sess->opts->dry_run && p->state == DOWNLOAD_READ_REMOTE &&
	    !buf_copy(NULL, 0, p, sess)) {
		ERRX1("buf_copy");
		goto out;
	}

	/*
	 * Just clear anything that was left in the output buffer; we weren't
	 * going to waste disk writes on a failed file.
	 */

	if (p->state == DOWNLOAD_FLUSH_REMOTE) {
		WARNX("%s: file truncated while reading",
		    p->fl[p->idx].path);
		p->obufsz = 0;
	}

	assert(p->fd == -1 || p->obufsz == 0 || sess->opts->dry_run);
	assert(tokres == TOKEN_EOF);

	/*
	 * Make sure our resulting MD4 hashes match.
	 * FIXME: if the MD4 hashes don't match, then our file has
	 * changed out from under us.
	 * This should require us to re-run the sequence in another
	 * phase.
	 */

	MD4_Final(ourmd, &p->ctx);

	/* Read: [block-xchng-com-2] OR [block-xchng-unc-2]. */

	if (!io_read_buf(sess, p->fdin, md, MD4_DIGEST_LENGTH)) {
		ERRX1("io_read_buf");
		goto out;
	} else if (p->state == DOWNLOAD_FLUSH_REMOTE ||
	    memcmp(md, ourmd, MD4_DIGEST_LENGTH)) {
		/*
		 * If this is our second shot at a file and it still
		 * doesn't match, we'll just give up.
		 */
		WARNX1("%s: hash does not match, %s redo", p->fname,
		    (f->flstate & FLIST_REDO) != 0 ?
		     "will not" : "will");

		if (f->flstate & FLIST_REDO) {
			f->flstate |= FLIST_FAILED;
			goto out;
		}

		f->flstate |= FLIST_REDO;
		goto done;
	}

	/*
	 * Once we successfully transfer the file, unmark it for redo so
	 * that we don't erroneously clean it up later.
	 */

	f->flstate = (f->flstate & ~FLIST_REDO) | FLIST_COMPLETE;

	/* We can still get here with a DRY_XFER in some cases. */

	if (p->fd < 0 || sess->opts->dry_run)
		goto done;

	usethis = f->path;

	/*
	 * For fresh files, we may have had a hole at the end of the
	 * file that we wouldn't have written after; thus, the size ends
	 * up being incorrect.
	 */

	//if (ftruncate(p->fd, p->fdpos) == -1)
	//	ERR("%s: ftruncate", f->path);

	if (!download_is_inplace(sess, p, false)) {
		fromfd = TMPDIR_FD;
		if (!move_file(fromfd, p->fname, p->rootfd, usethis,
		    usethis == f->path, true)) {
			ERR("%s: move_file: %s", p->fname, usethis);
			goto out;
		}
	}

	f->flstate |= FLIST_SUCCESS;

	/*
	 * This file has been transferred, so unmark it to be
	 * hardlinked, and it will be come the "leader" of this group of
	 * hardlinks, and the other files will be linked to this first
	 * transferred file in the group.
	 */

	f->flstate &= ~FLIST_NEED_HLINK;

	log_item_impl(LT_LOG, sess, f);
done:
	/*
	 * If we're redoing it, then we need to go ahead and clean up the file
	 * or move it into a --partial-dir.  If we succeeded, we can also go
	 * ahead and cleanup the --partial-dir if it was a relative path.
	 */
	download_cleanup(sess, p,
	    (f->flstate & (FLIST_REDO | FLIST_SUCCESS)) != 0);

	if (!(f->flstate & FLIST_REDO)) {
		if (usethis == NULL)
			usethis = f->path;

		/*
		 * Adjust our file metadata (uid, mode, etc.) now that
		 * we've closed the file.  The timing here is to avoid
		 * suboptimal behavior in samba, at least, which will
		 * update the mtime on last close even if we issued a
		 * futimens(2) after our last write(2).
		 */

		newfile = (f->iflags & IFLAG_NEW);
		if (!rsync_set_metadata_at(sess, newfile, p->rootfd, f,
		    usethis)) {
			ERRX1("rsync_set_metadata_at");
			goto out;
		}
	}

	return 1;
out:
	if (f != NULL)
		f->flstate |= FLIST_FAILED;
	download_cleanup(sess, p, 1);
	return -1;
}

/*
 * Utility function returning final component of file path.
 */
const char *
download_partial_filepath(const struct flist *f)
{
	const char *path;

	path = strrchr(f->path, '/');
	if (path != NULL)
		path++;
	else
		path = f->path;
	return path;
}

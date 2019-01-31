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
#include <sys/mman.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "extern.h"
#include "md4.h"

/*
 * Use this to keep track of what we're downloading.
 */
struct	download {
	size_t	 	 idx; /* index of current file */
	struct blkset	 blk; /* its blocks */
	void		*map; /* mmap of current file */
	size_t		 mapsz; /* length of mapsz */
	int		 ofd; /* open origin file */
	int		 fd; /* open output file */
	char		*fname; /* output filename */
	MD4_CTX	 	 ctx; /* current hashing context */
	off_t		 downloaded;
	off_t		 total;
};

/*
 * Simply log the filename.
 */
static void
log_file(struct sess *sess, 
	const struct download *dl, const struct flist *f)
{
	float	 frac;

	if (sess->opts->server)
		return;

	frac = 0 == dl->total ? 100.0 : 
		100.0 * dl->downloaded / dl->total;

	if (dl->total > 1024 * 1024 * 1024) 
		LOG1(sess, "%s (%.3f GB, %.1f%% downloaded)", 
			f->path, 
			dl->total / (1024. * 1024. * 1024.), 
			frac);
	else if (dl->total > 1024 * 1024)
		LOG1(sess, "%s (%.2f MB, %.1f%% downloaded)", 
			f->path, dl->total / (1024. * 1024.), frac);
	else if (dl->total > 1024)
		LOG1(sess, "%s (%.1f KB, %.1f%% downloaded)", 
			f->path, dl->total / 1024., frac);
	else
		LOG1(sess, "%s (%jd B, %.1f%% downloaded)", 
			f->path, dl->total, frac);
}

/*
 * Allocate and initialise a download context.
 * The MD4 context is pre-seeded.
 */
static struct download *
download_alloc(struct sess *sess, size_t idx)
{
	struct download	*p;
	int32_t		 seed;

	p = calloc(1, sizeof(struct download));
	if (NULL == p) {
		ERR(sess, "calloc");
		return NULL;
	}

	p->idx = idx;
	p->map = MAP_FAILED;
	p->ofd = p->fd = -1;
	MD4_Init(&p->ctx);
	seed = htole32(sess->seed);
	MD4_Update(&p->ctx, &seed, sizeof(int32_t));
	return p;
}

/*
 * Free a download context.
 * If "cleanup" is non-zero, we also try to clean up the temporary file,
 * assuming that it has been opened in p->fd.
 */
static void
download_free(struct download *p, int rootfd, int cleanup)
{

	if (NULL == p)
		return;

	if (MAP_FAILED != p->map) {
		assert(p->mapsz);
		munmap(p->map, p->mapsz);
	}
	if (-1 != p->ofd)
		close(p->ofd);
	if (-1 != p->fd)
		close(p->fd);
	if (-1 != p->fd && cleanup) {
		assert(NULL != p->fname);
		unlinkat(rootfd, p->fname, 0);
	}
	free(p->fname);
	free(p);
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
rsync_downloader(int fd, int rootfd, struct download **pp,
	const struct flist *fl, size_t flsz, struct sess *sess)
{
	int32_t		 idx, rawtok;
	uint32_t	 hash;
	struct download	*p = *pp;
	const struct flist *f;
	size_t		 sz, dirlen, tok;
	const char	*cp;
	mode_t		 perm;
	struct stat  	 st;
	ssize_t		 ssz;
	char		*buf = NULL;
	unsigned char	 ourmd[16], md[16];
	struct timespec	 tv[2];

	/*
	 * If we don't have a download already in session, then the next
	 * one is coming in.
	 * Read either the stop (phase) signal from the sender or block
	 * metadata, in which case we open our file and wait for data.
	 */

	if (NULL == p) {
		if ( ! io_read_int(sess, fd, &idx)) {
			ERRX1(sess, "io_read_int: index");
			return -1;
		} else if (idx >= 0 && (size_t)idx >= flsz) {
			ERRX(sess, "index out of bounds");
			return -1;
		} else if (idx < 0) {
			LOG3(sess, "downloader: phase complete");
			return 0;
		}

		/* Short-circuit: dry_run mode does nothing. */

		if (sess->opts->dry_run)
			return 1;

		/* 
		 * Now get our block information.
		 * This is all we'll need to reconstruct the file from
		 * the map, as block sizes are regular.
		 */

		if (NULL == (p = download_alloc(sess, idx))) {
			ERRX(sess, "download_alloc");
			return -1;
		} else if ( ! blk_send_ack(sess, fd, &p->blk)) {
			ERRX1(sess, "blk_send_ack");
			goto out;
		}

		*pp = p;

		/* 
		 * Next, we want to open the existing file for using as
		 * block input.
		 * We do this in a non-blocking way, so if the open
		 * succeeds, then we'll go reentrant til the file is
		 * readable and we can mmap() it.
		 */

		f = &fl[idx];
		p->ofd = openat(rootfd, f->path, 
			O_RDONLY | O_NONBLOCK, 0);

		if (-1 == p->ofd && ENOENT != errno) {
			ERR(sess, "%s: openat", f->path);
			goto out;
		} else if (-1 != p->ofd)
			return 1;

		/* Fall-through: there's no file. */
	}

	assert(NULL != p);
	f = &fl[p->idx];

	/*
	 * Next in sequence: we have an open download session but
	 * haven't created our temporary file.
	 * This means that we've already opened (or tried to open) the
	 * original file in a nonblocking way, and we can map it.
	 */

	if (NULL == p->fname) {
		if (-1 != p->ofd) {
			if (-1 == fstat(p->ofd, &st)) {
				ERR(sess, "%s: fstat", f->path);
				goto out;
			}
			p->mapsz = st.st_size;
			p->map = mmap(NULL, p->mapsz, 
				PROT_READ, MAP_SHARED, p->ofd, 0);
			if (MAP_FAILED == p->map) {
				ERR(sess, "%s: mmap", f->path);
				goto out;
			}
		}

		/* Create the temporary file. */

		hash = arc4random();

		if (sess->opts->recursive &&
		    NULL != (cp = strrchr(f->path, '/'))) {
			dirlen = cp - f->path;
			if (asprintf(&p->fname, "%.*s/.%s.%" PRIu32,
			    (int)dirlen, f->path,
			    f->path + dirlen + 1, hash) < 0)
				p->fname = NULL;
		} else {
			if (asprintf(&p->fname, ".%s.%" PRIu32, 
			    f->path, hash) < 0)
				p->fname = NULL;
		}

		if (NULL == p->fname) {
			ERR(sess, "asprintf");
			goto out;
		}

		if ( ! sess->opts->preserve_perms)
			perm = -1 == p->ofd ? f->st.mode : st.st_mode;
		else
			perm = f->st.mode;

		p->fd = openat(rootfd, p->fname, 
			O_WRONLY | O_CREAT | O_EXCL, perm);

		if (-1 == p->fd) {
			ERR(sess, "%s: openat", p->fname);
			goto out;
		}

		/* 
		 * FIXME: we can technically wait until the temporary
		 * file is writable, but since it's guaranteed to be
		 * empty, I don't think this is a terribly expensive
		 * operation as it doesn't involve reading the file into
		 * memory beforehand.
		 */

		LOG3(sess, "%s: temporary: %s", f->path, p->fname);
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

	assert(NULL != p->fname);
	assert(-1 != p->fd);
	assert(-1 != fd);

	if ( ! io_read_int(sess, fd, &rawtok)) {
		ERRX1(sess, "io_read_int: data block size");
		goto out;
	} 

	/* 
	 * FIXME: we can avoid writing so much by buffering all of these
	 * writes, then flushing them out after a certain point.
	 */

	if (rawtok > 0) {
		sz = rawtok;
		if (NULL == (buf = malloc(sz))) {
			ERR(sess, "realloc");
			goto out;
		}
		if ( ! io_read_buf(sess, fd, buf, sz)) {
			ERRX1(sess, "io_read_int: data block");
			goto out;
		}
		if ((ssz = write(p->fd, buf, sz)) < 0) {
			ERR(sess, "%s: write", p->fname);
			goto out;
		} else if ((size_t)ssz != sz) {
			ERRX(sess, "%s: short write", p->fname);
			goto out;
		}

		p->total += sz;
		p->downloaded += sz;
		LOG4(sess, "%s: received %zu B block", p->fname, sz);
		MD4_Update(&p->ctx, buf, sz);
		free(buf);
		return 1;
	} else if (rawtok < 0) {
		tok = -rawtok - 1;
		if (tok >= p->blk.blksz) {
			ERRX(sess, "%s: token not in block "
				"set: %zu (have %zu blocks)", 
				p->fname, tok, p->blk.blksz);
			goto out;
		}
		sz = tok == p->blk.blksz - 1 ? p->blk.rem : p->blk.len;
		buf = p->map + (tok * p->blk.len);

		/*
		 * Now we read from our block.
		 * We should only be at this point if we have a
		 * block to read from, i.e., if we were able to
		 * map our origin file and create a block
		 * profile from it.
		 */

		assert(MAP_FAILED != p->map);
		if ((ssz = write(p->fd, buf, sz)) < 0) {
			ERR(sess, "%s: write", p->fname);
			goto out;
		} else if ((size_t)ssz != sz) {
			ERRX(sess, "%s: short write", p->fname);
			goto out;
		}

		p->total += sz;
		LOG4(sess, "%s: copied %zu B", p->fname, sz);
		MD4_Update(&p->ctx, buf, sz);
		return 1;
	}

	assert(0 == rawtok);
	LOG4(sess, "%s: finished", p->fname);

	/* 
	 * Make sure our resulting MD4 hashes match.
	 * FIXME: if the MD4 hashes don't match, then our file has
	 * changed out from under us.
	 * This should require us to re-run the sequence in another
	 * phase.
	 */

	MD4_Final(ourmd, &p->ctx);

	if ( ! io_read_buf(sess, fd, md, MD4_DIGEST_LENGTH)) {
		ERRX1(sess, "io_read_buf: data blocks hash");
		goto out;
	} else if (memcmp(md, ourmd, MD4_DIGEST_LENGTH)) {
		ERRX(sess, "%s: hash does not match", p->fname);
		goto out;
	}

	if (sess->opts->preserve_times) {
		tv[0].tv_sec = time(NULL);
		tv[0].tv_nsec = 0;
		tv[1].tv_sec = f->st.mtime;
		tv[1].tv_nsec = 0;
		if (-1 == futimens(p->fd, tv)) {
			ERR(sess, "%s: futimens", p->fname);
			goto out;
		}
		LOG4(sess, "%s: updated date", f->path);
	}

	/* Finally, rename the temporary to the real file. */

	if (-1 == renameat(rootfd, p->fname, rootfd, f->path)) {
		ERR(sess, "%s: renameat: %s", p->fname, f->path);
		goto out;
	}

	log_file(sess, p, f);
	download_free(p, rootfd, 0);
	*pp = NULL;
	return 1;
out:
	download_free(p, rootfd, 1);
	*pp = NULL;
	return -1;
}

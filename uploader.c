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

/*
 * Log a directory by emitting the file and a trailing slash, just to
 * show the operator that we're a directory.
 */
static void
log_dir(struct sess *sess, const struct flist *f)
{
	size_t	 sz;

	if (sess->opts->server)
		return;
	sz = strlen(f->path);
	assert(sz > 0);
	LOG1(sess, "%s%s", f->path, 
		'/' == f->path[sz - 1] ? "" : "/");
}

/*
 * Log a link by emitting the file and the target, just to show the
 * operator that we're a link.
 */
static void
log_link(struct sess *sess, const struct flist *f)
{

	if ( ! sess->opts->server)
		LOG1(sess, "%s -> %s", f->path, f->link);
}

/*
 * Simply log the filename.
 */
static void
log_file(struct sess *sess, const struct flist *f)
{

	if ( ! sess->opts->server)
		LOG1(sess, "%s", f->path);
}

/*
 * Prepare the overall block set's metadata.
 * We always have at least one block.
 * The block size is an important part of the algorithm.
 * I use the same heuristic as the reference rsync, but implemented in a
 * bit more of a straightforward way.
 * In general, the individual block length is the rounded square root of
 * the total file size.
 * The minimum block length is 700.
 */
static void
init_blkset(struct blkset *p, off_t sz)
{
	double	 v;

	if (sz >= (BLOCK_SIZE_MIN * BLOCK_SIZE_MIN)) {
		/* Simple rounded-up integer square root. */

		v = sqrt(sz);
		p->len = ceil(v);

		/* 
		 * Always be a multiple of eight.
		 * There's no reason to do this, but rsync does.
		 */

		if ((p->len % 8) > 0)
			p->len += 8 - (p->len % 8);
	} else
		p->len = BLOCK_SIZE_MIN;

	p->size = sz;
	if (0 == (p->blksz = sz / p->len))
		p->rem = sz;
	else
		p->rem = sz % p->len;

	/* If we have a remainder, then we need an extra block. */

	if (p->rem)
		p->blksz++;
}

/*
 * For each block, prepare the block's metadata.
 * We use the mapped "map" file to set our checksums.
 */
static void
init_blk(struct blk *p, const struct blkset *set, off_t offs,
	size_t idx, const void *map, const struct sess *sess)
{

	assert(MAP_FAILED != map);

	/* Block length inherits for all but the last. */

	p->idx = idx;
	p->len = idx < set->blksz - 1 ? set->len : set->rem;
	p->offs = offs;

	p->chksum_short = hash_fast(map + offs, p->len);
	hash_slow(map + offs, p->len, p->chksum_long, sess);
}

/*
 * Return <0 on failure 0 on success.
 */
static int
prep_link(struct sess *sess, int root, const struct flist *f)
{
	int		 rc, newlink = 0;
	char		*b;
	struct stat	 st;
	struct timespec	 tv[2];

	if ( ! sess->opts->preserve_links) {
		WARNX(sess, "%s: ignoring symlink", f->path);
		return 0;
	} else if (sess->opts->dry_run) {
		log_link(sess, f);
		return 0;
	}

	/* See if the symlink already exists. */

	assert(-1 != root);
	rc = fstatat(root, f->path, &st, AT_SYMLINK_NOFOLLOW);
	if (-1 != rc && ! S_ISLNK(st.st_mode)) {
		WARNX(sess, "%s: not a symlink", f->path);
		return -1;
	} else if (-1 == rc && ENOENT != errno) {
		WARN(sess, "%s: fstatat", f->path);
		return -1;
	}

	/*
	 * If the symbolic link already exists, then make sure that it
	 * points to the correct place.
	 */

	if (-1 == rc) {
		LOG3(sess, "%s: creating "
			"symlink: %s", f->path, f->link);
		if (-1 == symlinkat(f->link, root, f->path)) {
			WARN(sess, "symlinkat: %s", f->path);
			return -1;
		}
		newlink = 1;
	} else {
		b = symlinkat_read(sess, root, f->path);
		if (NULL == b) {
			ERRX1(sess, "%s: symlinkat_read", f->path);
			return -1;
		}
		if (strcmp(f->link, b)) {
			free(b);
			b = NULL;
			LOG3(sess, "%s: updating "
				"symlink: %s", f->path, f->link);
			if (-1 == unlinkat(root, f->path, 0)) {
				WARN(sess, "%s: unlinkat", f->path);
				return -1;
			}
			if (-1 == symlinkat(f->link, root, f->path)) {
				WARN(sess, "%s: symlinkat", f->path);
				return -1;
			}
			newlink = 1;
		} 
		free(b);
	}

	/* Optionally preserve times/perms on the symlink. */

	if (sess->opts->preserve_times) {
		tv[0].tv_sec = time(NULL);
		tv[0].tv_nsec = 0;
		tv[1].tv_sec = f->st.mtime;
		tv[1].tv_nsec = 0;
		rc = utimensat(root, f->path, tv, AT_SYMLINK_NOFOLLOW);
		if (-1 == rc) {
			ERR(sess, "%s: utimensat", f->path);
			return -1;
		}
		LOG4(sess, "%s: updated symlink date", f->path);
	}
	
	/* 
	 * FIXME: if newlink is set because we updated the symlink, we
	 * want to carry over the permissions from the last.
	 */

	if (newlink || sess->opts->preserve_perms) {
		rc = fchmodat(root, f->path,
			f->st.mode, AT_SYMLINK_NOFOLLOW);
		if (-1 == rc) {
			ERR(sess, "%s: fchmodat", f->path);
			return -1;
		}
		LOG4(sess, "%s: updated symlink mode", f->path);
	}

	log_link(sess, f);
	return 0;
}

/*
 * Return <0 on failure 0 on success.
 */
static int
prep_dir(struct sess *sess, mode_t oumask,
	int rootfd, const struct flist *f, int *newdir)
{
	struct stat	 st;
	int	 	 rc;

	if ( ! sess->opts->recursive) {
		WARNX(sess, "%s: ignoring directory", f->path);
		return 0;
	} else if (sess->opts->dry_run) {
		log_dir(sess, f);
		return 0;
	}

	assert(-1 != rootfd);
	rc = fstatat(rootfd, f->path, &st, AT_SYMLINK_NOFOLLOW);
	if (-1 == rc && ENOENT != errno) {
		WARN(sess, "%s: fstatat", f->path);
		return -1;
	} else if (-1 != rc && ! S_ISDIR(st.st_mode)) {
		WARNX(sess, "%s: not a directory", f->path);
		return -1;
	} else if (-1 != rc) {
		/* 
		 * FIXME: we should fchmod the permissions here as well,
		 * as we may locally have shut down writing into the
		 * directory and that doesn't work.
		 */
		LOG3(sess, "%s: updating directory", f->path);
		return 0;
	}

	/*
	 * We want to make the directory with default permissions (using
	 * our old umask, which we've since unset), then adjust
	 * permissions (assuming preserve_perms or new) afterward in
	 * case it's u-w or something.
	 */

	LOG3(sess, "%s: creating directory", f->path);
	if (-1 == mkdirat(rootfd, f->path, 0777 & ~oumask)) {
		WARN(sess, "%s: mkdirat", f->path);
		return -1;
	}

	*newdir = 1;
	log_dir(sess, f);
	return 0;
}

/*
 * Return <0 on failure, 0 on success w/nothing to be done, >0 on
 * success and the file needs attention.
 */
static int
prep_file(int fd, int rootfd, int *filefd, 
	size_t idx, const struct flist *f, struct sess *sess)
{

	if (sess->opts->dry_run) {
		log_file(sess, f);
		if ( ! io_write_int(sess, fd, idx)) {
			ERRX1(sess, "io_write_int: index");
			return -1;
		}
		return 0;
	}

	*filefd = openat(rootfd, f->path,
		O_RDONLY | O_NOFOLLOW | O_NONBLOCK, 0);

	/* FIXME: check that we're a regular file still. */

	if (-1 != *filefd || ENOENT == errno)
		return 1;

	ERR(sess, "%s: openat", f->path);
	return -1;
}

/*
 * Uploader routine.
 * This iterates through all available files and conditionally gets the
 * file ready for processing to check whether it's up to date.
 * If not up to date, it sends the file's information to the sender.
 * If it returns 0, that means that we've processed all files there
 * are to process.
 * If it returns >0, we should establish a POLLIN in "filefd" (assert
 * that it is not -1) and call this function when that succeeds.
 * Otherwise it returns <0, which is an error.
 */
int
rsync_uploader(int fd, int rootfd, size_t *idx, 
	int *filefd, const struct flist *fl, size_t flsz,
	struct sess *sess, size_t csumlen, mode_t oumask, 
	int *newdir)
{
	struct blkset	 blk;
	struct stat	 st;
	void		*map;
	size_t		 i, mapsz;
	off_t		 offs;
	int		 c;

again:
	/*
	 * If we invoke the uploader without a file currently open, then
	 * we iterate through til the next available regular file and
	 * start the opening process.
	 */

	if (-1 == *filefd) {
		for ( ; *idx < flsz; (*idx)++) {
			if (S_ISDIR(fl[*idx].st.mode))
				c = prep_dir(sess, oumask, 
					rootfd, &fl[*idx], &newdir[*idx]);
			else if (S_ISLNK(fl[*idx].st.mode))
				c = prep_link(sess, rootfd, &fl[*idx]);
			else if (S_ISREG(fl[*idx].st.mode))
				c = prep_file(fd, rootfd, 
					filefd, *idx, &fl[*idx], sess);
			else
				c = 0;
			if (c < 0)
				return -1;
			else if (c > 0)
				break;
		}

		/* We've finished all of our files. */

		if (*idx == flsz) {
			assert(-1 == *filefd);
			LOG4(sess, "uploader: phase complete");
			if ( ! io_write_int(sess, fd, -1)) {
				ERRX1(sess, "io_write_int: index");
				return -1;
			}
			return 0;
		}
	}

	/* 
	 * Either have a nonexistent file or an open *filefd.
	 * If the file is already open, stat it and see if it's already
	 * up to date, in which case close it and go to the next one.
	 */

	if (-1 != *filefd) {
		if (-1 == fstat(*filefd, &st)) {
			WARN(sess, "%s: fstat", fl[*idx].path);
			close(*filefd);
			return -1;
		} else if ( ! S_ISREG(st.st_mode)) {
			WARNX(sess, "%s: not regular", fl[*idx].path);
			close(*filefd);
			return -1;
		}
		if (st.st_size == fl[*idx].st.size &&
		    st.st_mtime == fl[*idx].st.mtime) {
			LOG3(sess, "%s: skipping: up to date", fl[*idx].path);
			close(*filefd);
			*filefd = -1;
			(*idx)++;
			goto again;
		}
	}

	/* Initialies our blocks. */

	LOG4(sess, "%s: uploader initialising blocks", fl[*idx].path);
	memset(&blk, 0, sizeof(struct blkset));
	blk.csum = csumlen;

	if (-1 != *filefd && st.st_size > 0) {
		mapsz = st.st_size;
		map = mmap(NULL, mapsz, 
			PROT_READ, MAP_SHARED, *filefd, 0);
		if (MAP_FAILED == map) {
			WARN(sess, "%s: mmap", fl[*idx].path);
			close(*filefd);
			return -1;
		}

		init_blkset(&blk, st.st_size);
		assert(blk.blksz);

		blk.blks = calloc(blk.blksz, sizeof(struct blk));
		if (NULL == blk.blks) {
			ERR(sess, "calloc");
			munmap(map, mapsz);
			close(*filefd);
			return -1;
		}

		offs = 0;
		for (i = 0; i < blk.blksz; i++) {
			init_blk(&blk.blks[i], &blk, offs, i, map, sess);
			offs += blk.len;
		}

		munmap(map, mapsz);
		close(*filefd);
		*filefd = -1;

		LOG3(sess, "%s: mapped %jd B with %zu blocks",
			fl[*idx].path, (intmax_t)blk.size, blk.blksz);
	} else {
		if (-1 != *filefd) {
			close(*filefd);
			*filefd = -1;
		}
		blk.len = MAX_CHUNK; /* Doesn't matter. */
		LOG3(sess, "%s: not mapped", fl[*idx].path);
	}

	/* Send our blocks. */

	if ( ! blk_send(sess, fd, *idx, &blk, fl[*idx].path)) {
		ERRX1(sess, "%s: blk_send", fl[*idx].path);
		free(blk.blks);
		return -1;
	} 

	/* Proceed to next index. */

	assert(-1 == *filefd);
	free(blk.blks);
	if (flsz == ++(*idx)) {
		LOG4(sess, "uploader: finished");
		if ( ! io_write_int(sess, fd, -1)) {
			ERRX1(sess, "io_write_int: index");
			return -1;
		}
		return 0;
	}
	return 1;
}

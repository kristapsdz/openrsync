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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "extern.h"

/*
 * Prepare the overall block set's metadata.
 * We always have at least one block.
 */
static void
init_blkset(struct blkset *p, off_t sz)
{

	/* For now, hard-code the block size. */

	p->size = sz;
	p->len = MAX_CHUNK;
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
 * We need to process our directories in post-order.
 * This is because touching files within the directory will change the
 * directory file; and also, if our mode is not writable, we wouldn't be
 * able to write to that directory!
 * Returns zero on failure, non-zero on success.
 */
static int
post_process_dir(struct sess *sess, 
	int root, const struct flist *f, int newdir)
{
	struct timespec	 tv[2];
	int		 rc;

	/* XXX: re-check that this is a directory? */

	if (sess->opts->preserve_times) {
		tv[0].tv_sec = time(NULL);
		tv[0].tv_nsec = 0;
		tv[1].tv_sec = f->st.mtime;
		tv[1].tv_nsec = 0;
		rc = utimensat(root, f->path, tv, 0);
		if (-1 == rc) {
			ERR(sess, "utimensat: %s", f->path);
			return 0;
		} 
	}

	if (newdir || sess->opts->preserve_perms) {
		rc = fchmodat(root, f->path, f->st.mode, 0);
		if (-1 == rc) {
			ERR(sess, "fchmodat: %s", f->path);
			return 0;
		}
	}

	return 1;
}

/*
 * Create (or not) the given directory entry.
 * If something already exists in its place, then make sure that it,
 * too, is a directory.
 * Returns zero on failure, non-zero on success.
 */
static int
pre_process_dir(struct sess *sess, mode_t oumask, 
	int root, const struct flist *f, int *newdir)
{
	struct stat	 st;
	int	 	 rc;

	assert(sess->opts->recursive);
	if (sess->opts->dry_run)
		return 1;

	/* First, see if the directory already exists. */
	
	rc = fstatat(root, f->path, &st, AT_SYMLINK_NOFOLLOW);
	if (-1 == rc) {
		if (ENOENT != errno) {
			WARN(sess, "fstatat: %s", f->path);
			return 0;
		}

		/*
		 * We want to make the directory with default
		 * permissions (using our old umask, which we've since
		 * unset), then adjust permissions (assuming
		 * preserve_perms or new) afterward in case it's u-w or
		 * something.
		 */

		if (-1 == mkdirat(root, f->path, 0777 & ~oumask)) {
			WARN(sess, "mkdirat: %s", f->path);
			return 0;
		}
		*newdir = 1;
		LOG3(sess, "created: %s", f->path);
		return 1;
	} else if ( ! S_ISDIR(st.st_mode)) {
		WARNX(sess, "file not directory: %s", f->path);
		return 0;
	}

	/* FIXME: do we fchmod to have writable perms? */

	LOG3(sess, "updating: %s", f->path);
	return 1;
}

/*
 * Process a symbolic link.
 * New links are given the source's permissions and the current time.
 * Updated links retain permissions and have times automatically updated
 * unless preserve_times and/or preserve_perms are set.
 * This operates on the link itself, not the target.
 * Returns zero on failure, non-zero on success.
 */
static int
process_link(struct sess *sess, int root, const struct flist *f)
{
	int		 rc, newlink = 0;
	char		*b;
	struct stat	 st;
	struct timespec	 tv[2];

	assert(sess->opts->preserve_links);
	if (sess->opts->dry_run)
		return 1;

	/* See if the symlink already exists. */

	rc = fstatat(root, f->path, &st, AT_SYMLINK_NOFOLLOW);
	if (-1 == rc) {
		if (-1 == symlinkat(f->link, root, f->path)) {
			WARN(sess, "symlinkat: %s", f->path);
			return 0;
		}
		LOG3(sess, "created: %s -> %s (%o)", 
			f->path, f->link, f->st.mode);
		newlink = 1;
	} else if ( ! S_ISLNK(st.st_mode)) {
		WARNX(sess, "file not symlink: %s", f->path);
		return 0;
	} else {
		/*
		 * If the symbolic link already exists, then make sure
		 * that it points to the correct place.
		 * If not, fix it.
		 */

		b = symlinkat_read(sess, root, f->path);
		if (NULL == b) {
			ERRX1(sess, "symlinkat_read");
			return 0;
		} 

		if (strcmp(f->link, b)) {
			free(b);
			LOG2(sess, "updating: %s", f->path);
			if (-1 == unlinkat(root, f->path, 0)) {
				WARN(sess, "unlinkat: %s", f->path);
				return 0;
			} 
			if (-1 == symlinkat(f->link, root, f->path)) {
				WARN(sess, "unlinkat: %s", f->path);
				return 0;
			}
		} else
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
			ERR(sess, "utimensat: %s", f->path);
			return 0;
		} 
	}

	if (newlink || sess->opts->preserve_perms) {
		rc = fchmodat(root, f->path, 
			f->st.mode, AT_SYMLINK_NOFOLLOW);
		if (-1 == rc) {
			ERR(sess, "fchmodat: %s", f->path);
			return 0;
		}
	}

	return 1;
}

/*
 * Open the existing file (if found), the temporary file, read new data
 * (and good blocks) from the sender, reconstruct the file, and rename
 * it.
 * After opening the origin file (if found), check if it should be
 * updated at all.
 * Return zero on failure, non-zero on success.
 */
static int
process_file(struct sess *sess, int fdin, int fdout, int root, 
	const struct flist *f, size_t idx, size_t csumlen)
{
	struct blkset	*p = NULL;
	int		 ffd = -1, rc = 0, tfd = -1;
	off_t		 offs = 0;
	struct stat	 st;
	size_t		 i, mapsz = 0, dirlen;
	void		*map = MAP_FAILED;
	char		*tmpfile = NULL;
	const char	*cp;
	uint32_t	 hash;
	struct timespec	 tv[2];
	mode_t		 perm;

	/* Dry-run short circuits. */

	if (sess->opts->dry_run) {
		if ( ! io_write_int(sess, fdout, idx)) {
			ERRX1(sess, "io_write_int: index");
			goto out;
		} else if ( ! io_read_size(sess, fdin, &i)) {
			ERRX1(sess, "io_read_size: send ack");
			goto out;
		} else if (idx != i) {
			ERRX(sess, "wrong index value");
			goto out;
		}
		return 1;
	}

	/* 
	 * Not having a file is fine: it just means that we'll need to
	 * download the full file (i.e., have zero blocks).
	 * If this is the case, map will stay at MAP_FAILED.
	 * If we're recursive, then ignore the absolute indicator.
	 */

	ffd = openat(root, f->path, O_RDONLY | O_NOFOLLOW, 0);

	if (-1 == ffd) {
		if (ENOENT == errno)
			WARN2(sess, "openat: %s", f->path);
		else
			WARN1(sess, "openat: %s", f->path);
	}

	/*
	 * If we have a file, then we need to make sure that we have a
	 * regular file (for now).
	 * Here we're also going to see if we really need to do this: if
	 * the file is up to date, we don't need new data.
	 */

	if (-1 != ffd) {
		if (-1 == fstat(ffd, &st)) {
			WARN(sess, "fstat: %s", f->path);
			goto out;
		} else if ( ! S_ISREG(st.st_mode)) {
			WARNX(sess, "file not regular: %s", f->path);
			goto out;
		} 

		/* Skip if the size and mtime are the same. */

		if (st.st_size == f->st.size &&
		    st.st_mtime == f->st.mtime) {
			LOG3(sess, "%s: skipping: up to date", f->path);
			return 1;
		} 
		LOG3(sess, "updating: %s", f->path);
	} else
		LOG3(sess, "creating: %s", f->path);

	/* We need this file's data: start the transfer. */

	if ( ! io_write_int(sess, fdout, idx)) {
		ERRX1(sess, "io_write_int: index");
		goto out;
	}

	if (NULL == (p = calloc(1, sizeof(struct blkset)))) {
		ERR(sess, "calloc");
		goto out;
	}

	/* 
	 * If open, try to map the file into memory.
	 * If we fail doing this, then we have a problem: we don't need
	 * the file, but we need to be able to mmap() it.
	 */

	p->csum = csumlen;

	if (-1 != ffd) {
		mapsz = st.st_size;
		map = mmap(NULL, mapsz, PROT_READ, MAP_SHARED, ffd, 0);

		if (MAP_FAILED == map) {
			WARN(sess, "mmap: %s", f->path);
			goto out;
		}

		init_blkset(p, st.st_size);
		assert(p->blksz);

		p->blks = calloc(p->blksz, sizeof(struct blk));
		if (NULL == p->blks) {
			ERR(sess, "calloc");
			goto out;
		}

		for (i = 0; i < p->blksz; i++, offs += p->len)
			init_blk(&p->blks[i], p, offs, i, map, sess);

		LOG3(sess, "%s: mapped %jd B with %zu blocks", 
			f->path, (intmax_t)p->size, p->blksz);
	} else {
		p->len = MAX_CHUNK;
		LOG3(sess, "%s: not mapped", f->path);
	}

	/* 
	 * Open our writable temporary file.
	 * To make this reasonably unique, make the file into a dot-file
	 * and give it a random suffix.
	 * Use the mode on our remote system.
	 */

	hash = arc4random();

	if (sess->opts->recursive && 
	    NULL != (cp = strrchr(f->path, '/'))) {
		dirlen = cp - f->path;
		if (asprintf(&tmpfile, "%.*s/.%s.%" PRIu32, 
		    (int)dirlen, f->path, 
		    f->path + dirlen + 1, hash) < 0) {
			ERR(sess, "asprintf");
			tmpfile = NULL;
			goto out;
		} 
	} else {
		if (asprintf(&tmpfile, ".%s.%" PRIu32, f->path, hash) < 0) {
			ERR(sess, "asprintf");
			tmpfile = NULL;
			goto out;
		} 
	}
	/* 
	 * If we have -p, then copy over the file's mode only if we're
	 * updating an existing file, not making one anew.
	 */

	if (-1 == ffd) 
		perm = f->st.mode;
	else if (sess->opts->preserve_perms)
		perm = f->st.mode;
	else
		perm = st.st_mode;

	tfd = openat(root, tmpfile, O_RDWR|O_CREAT|O_EXCL, perm);
	if (-1 == tfd) {
		ERR(sess, "openat: %s", tmpfile);
		goto out;
	}

	LOG3(sess, "%s: temporary: %s (%o)", f->path, tmpfile, perm);

	/* Now transmit the metadata for set and blocks. */

	if ( ! blk_send(sess, fdout, p, f->path)) {
		ERRX1(sess, "blk_send");
		goto out;
	} else if ( ! blk_send_ack(sess, fdin, p, idx)) {
		ERRX1(sess, "blk_send_ack");
		goto out;
	}

	/* 
	 * Now we respond to matches.
	 * We write all of the data into "tfd", which we're going to
	 * rename as the original file.
	 */

	if ( ! blk_merge(sess, fdin, ffd, p, tfd, f->path, map, mapsz)) {
		ERRX1(sess, "blk_merge");
		goto out;
	}

	/* Optionally preserve times for the output file. */

	if (sess->opts->preserve_times) {
		tv[0].tv_sec = time(NULL);
		tv[0].tv_nsec = 0;
		tv[1].tv_sec = f->st.mtime;
		tv[1].tv_nsec = 0;
		if (-1 == futimens(tfd, tv)) {
			ERR(sess, "futimens: %s", tmpfile);
			goto out;
		}
	}

	/* Finally, rename the temporary to the real file. */

	if (-1 == renameat(root, tmpfile, root, f->path)) {
		ERR(sess, "renameat: %s, %s", tmpfile, f->path);
		goto out;
	}

	close(tfd);
	tfd = -1;
	rc = 1;
out:
	if (MAP_FAILED != map)
		munmap(map, mapsz);
	if (-1 != ffd)
		close(ffd);

	/* On failure, clean up our temporary file. */

	if (-1 != tfd) {
		close(tfd);
		remove(tmpfile);
	}

	free(tmpfile);
	blkset_free(p);
	return rc;
}

/*
 * At the end of the transmission, we have some statistics to read.
 * Return zero on failure, non-zero on success.
 */
static int
stats(struct sess *sess, int fdin)
{
	size_t	 tread, twrite, tsize;

	/* No statistics in server mode. */

	if (sess->opts->server)
		return 1;

	if ( ! io_read_size(sess, fdin, &tread)) {
		ERRX1(sess, "io_read_size: total read");
		return 0;
	} else if ( ! io_read_size(sess, fdin, &twrite)) {
		ERRX1(sess, "io_read_size: total write");
		return 0;
	} else if ( ! io_read_size(sess, fdin, &tsize)) {
		ERRX1(sess, "io_read_size: total size");
		return 0;
	} 

	LOG1(sess, "stats: %zu B read, %zu B written, %zu B size",
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
 * Pledges: unveil, rpath, cpath, wpath, stdio, fattr.
 *
 * Pledges (dry-run): -cpath, -wpath, -fattr.
 * Pledges (!preserve_times): -fattr.
 */
int
rsync_receiver(struct sess *sess, 
	int fdin, int fdout, const char *root)
{
	struct flist	*fl = NULL;
	size_t		 i, flsz = 0, csum_length = CSUM_LENGTH_PHASE1;
	char		*tofree;
	int		 rc = 0, dfd = -1, phase = 0, c;
	int32_t	 	 ioerror;
	int		*newdir = NULL;
	mode_t		 oumask;

	if (-1 == pledge("unveil rpath cpath wpath stdio fattr", NULL)) {
		ERR(sess, "pledge");
		goto out;
	}

	/* XXX: what does this do? */

	if ( ! sess->opts->server &&
	     ! io_write_int(sess, fdout, 0)) {
		ERRX1(sess, "io_write_int: zero premable");
		goto out;
	}

	/*
	 * Start by receiving the list of filenames.
	 * These we're going to be touching on our local system.
	 */

	if (NULL == (fl = flist_recv(sess, fdin, &flsz))) {
		ERRX1(sess, "flist_recv");
		goto out;
	} else if ( ! io_read_int(sess, fdin, &ioerror)) {
		ERRX1(sess, "io_read_int: io_error");
		goto out;
	} else if (0 != ioerror) {
		ERRX1(sess, "io_error is non-zero");
		goto out;
	}

	/* 
	 * Create the path for our destination directory.
	 * This uses our current umask.
	 */

	if (NULL == (tofree = strdup(root))) {
		ERR(sess, "strdup");
		goto out;
	} else if (mkpath(sess, tofree) < 0) {
		ERRX1(sess, "mkpath: %s", root);
		free(tofree);
		goto out;
	}
	free(tofree);

	/* Disable umask() so we can set permissions fully. */

	oumask = umask(0);

	/*
	 * Make our entire view of the file-system be limited to what's
	 * in the root directory.
	 * This prevents us from accidentally (or "under the influence")
	 * writing into other parts of the file-system.
	 */

	if (-1 == unveil(root, "rwc")) {
		ERR(sess, "unveil: %s", root);
		goto out;
	} else if (-1 == unveil(NULL, NULL)) {
		ERR(sess, "unveil: %s", root);
		goto out;
	}

	/* 
	 * Open the destination directory.
	 * This will be the basis of all future files.
	 */

	LOG2(sess, "receiver writing into: %s", root);

	if (-1 == (dfd = open(root, O_RDONLY | O_DIRECTORY, 0))) {
		ERR(sess, "open: %s", root);
		goto out;
	}

	/*
	 * FIXME: I never use the full checksum amount; but if I were,
	 * here is where the "again" label would go.
	 * This has been demonstrated to work, but I just don't use it
	 * til I understand the need.
	 */

	LOG2(sess, "receiver ready for phase 1 data: %s", root);

	if (NULL == (newdir = calloc(flsz, sizeof(int)))) {
		ERR(sess, "calloc");
		goto out;
	}

	for (i = 0; i < flsz; i++) {
		if (S_ISDIR(fl[i].st.mode))
			c = pre_process_dir(sess, oumask, 
				dfd, &fl[i], &newdir[i]);
		else if (S_ISLNK(fl[i].st.mode))
			c = process_link(sess, dfd, &fl[i]);
		else
			c = process_file(sess, fdin, fdout, 
				dfd, &fl[i], i, csum_length);
		if ( ! c) 
			goto out;
	}

	/* Fix up the directory permissions and times post-order. */

	if (sess->opts->preserve_times ||
	    sess->opts->preserve_perms)
		for (i = 0; i < flsz; i++) {
			if ( ! S_ISDIR(fl[i].st.mode))
				continue;
			c = post_process_dir(sess, 
				dfd, &fl[i], newdir[i]);
			if ( ! c)
				goto out;
		}

	/* Properly close us out by progressing through the phases. */

	if (0 == phase) {
		if ( ! io_write_int(sess, fdout, -1)) {
			ERRX1(sess, "io_write_int: index");
			goto out;
		} else if ( ! io_read_int(sess, fdin, &ioerror)) {
			ERRX1(sess, "io_read_int: phase ack");
			goto out;
		} else if (-1 != ioerror) {
			ERRX(sess, "expected phase ack");
			goto out;
		}
		phase++;
		csum_length = CSUM_LENGTH_PHASE2;
		LOG2(sess, "receiver ready for "
			"phase 2 data: %s", root);

		/* 
		 * FIXME: under what conditions should we resend files?
		 * What kind of failure?  This is never specified.
		 * goto again;
		 */
	}

	if (1 == phase) {
		if ( ! io_write_int(sess, fdout, -1)) {
			ERRX1(sess, "io_write_int: send complete");
			goto out;
		} else if ( ! io_read_int(sess, fdin, &ioerror)) {
			ERRX1(sess, "io_read_int: phase ack");
			goto out;
		} else if (-1 != ioerror) {
			ERRX(sess, "expected phase ack");
			goto out;
		}
		phase++;
	}

	if ( ! stats(sess, fdin)) {
		ERRX1(sess, "stats");
		goto out;
	}

	/* Final "goodbye" message. */

	if ( ! io_write_int(sess, fdout, -1)) {
		ERRX1(sess, "io_write_int: update complete");
		goto out;
	}

	LOG2(sess, "receiver finished updating");

	rc = 1;
out:
	if (-1 != dfd)
		close(dfd);
	flist_free(fl, flsz);
	free(newdir);
	return rc;
}

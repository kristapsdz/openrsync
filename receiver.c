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

	p->len = MAX_CHUNK;

	/* Set our initial block size and remainder. */

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
 * Open the existing file (if found), the temporary file, read new data
 * (and good blocks) from the sender, reconstruct the file, and rename
 * it.
 * After opening the origin file (if found), check if it should be
 * updated at all.
 * Return zero on failure, non-zero on success.
 */
static int
process(const struct opts *opts, int fdin, int fdout, int root, 
	const struct flist *f, size_t idx, const struct sess *sess,
	size_t csumlen)
{
	struct blkset	*p = NULL;
	int		 ffd = -1, rc = 0, tfd = -1;
	off_t		 offs = 0;
	struct stat	 st;
	size_t		 i, mapsz = 0;
	void		*map = MAP_FAILED;
	char		*tmpfile = NULL;
	uint32_t	 hash;
	struct timeval	 tv[2];
	mode_t		 perm;

	/* 
	 * Not having a file is fine: it just means that we'll need to
	 * download the full file (i.e., have zero blocks).
	 * If this is the case, map will stay at MAP_FAILED.
	 */

	if (-1 == (ffd = openat(root, f->path, O_RDONLY, 0))) {
		if (ENOENT == errno)
			WARN2(opts, "openat: %s", f->path);
		else
			WARN1(opts, "openat: %s", f->path);
	}

	/*
	 * If we have a file, then we need to make sure that we have a
	 * regular file (for now).
	 * Here we're also going to see if we really need to do this: if
	 * the file is up to date, we don't need new data.
	 */

	if (-1 != ffd) {
		if (-1 == fstat(ffd, &st)) {
			WARN(opts, "fstat: %s", f->path);
			goto out;
		} else if ( ! S_ISREG(st.st_mode)) {
			WARNX(opts, "not a regular file: %s", f->path);
			goto out;
		} 

		/* Skip if the size and mtime are the same. */

		if (st.st_size == f->st.size &&
		    st.st_mtime == f->st.mtime) {
			LOG3(opts, "%s: skipping file", f->path);
			return 1;
		} 
	}

	/* We need this file's data: start the transfer. */

	if ( ! io_write_int(opts, fdout, idx)) {
		ERRX1(opts, "io_write_int: index");
		goto out;
	}

	/* Dry-run short circuits. */

	if (opts->dry_run) {
		if ( ! io_read_size(opts, fdin, &i)) {
			ERRX1(opts, "io_read_size: send ack");
			goto out;
		} else if (idx != i) {
			ERRX(opts, "wrong index value");
			goto out;
		}
		return 1;
	}

	if (NULL == (p = calloc(1, sizeof(struct blkset)))) {
		ERR(opts, "calloc");
		goto out;
	}

	/* 
	 * If open, try to map the file into memory.
	 * If we fail doing this, then we have a problem: we don't need
	 * the file, but we need to be able to mmap() it.
	 */

	if (-1 != ffd) {
		mapsz = st.st_size;
		map = mmap(NULL, mapsz, PROT_READ, MAP_SHARED, ffd, 0);

		if (MAP_FAILED == map) {
			WARN(opts, "mmap: %s", f->path);
			goto out;
		}

		init_blkset(p, st.st_size);
		assert(p->blksz);

		p->blks = calloc(p->blksz, sizeof(struct blk));
		if (NULL == p->blks) {
			ERR(opts, "calloc");
			goto out;
		}

		for (i = 0; i < p->blksz; i++, offs += p->len)
			init_blk(&p->blks[i], p, offs, i, map, sess);

		LOG3(opts, "%s: mapped %llu B with %zu "
			"blocks", f->path, p->size, p->blksz);
	} else {
		p->len = MAX_CHUNK;
		LOG3(opts, "%s: not mapped", f->path);
	}

	/* 
	 * Open our writable temporary file.
	 * To make this reasonably unique, make the file into a dot-file
	 * and give it a random suffix.
	 * Use the mode on our remote system.
	 */

	hash = arc4random();
	if (asprintf(&tmpfile, ".%s.%" PRIu32, f->path, hash) < 0) {
		ERR(opts, "asprintf");
		tmpfile = NULL;
		goto out;
	} 

	/* 
	 * If we have -p, then copy over the file's mode only if we're
	 * updating an existing file, not making one anew.
	 */

	if (-1 == ffd) 
		perm = f->st.mode;
	else if (opts->preserve_perms)
		perm = f->st.mode;
	else
		perm = st.st_mode;

	tfd = openat(root, tmpfile, O_RDWR|O_CREAT|O_EXCL, perm);
	if (-1 == tfd) {
		ERR(opts, "openat: %s", tmpfile);
		goto out;
	}

	LOG3(opts, "%s: temporary: %s", f->path, tmpfile);

	/* Now transmit the metadata for set and blocks. */

	if ( ! blk_send(opts, fdout, csumlen, p, f->path)) {
		ERRX1(opts, "blk_send");
		goto out;
	} else if ( ! blk_send_ack(opts, fdin, p, idx)) {
		ERRX1(opts, "blk_send_ack");
		goto out;
	}

	/* 
	 * Now we respond to matches.
	 * We write all of the data into "tfd", which we're going to
	 * rename as the original file.
	 */

	if ( ! blk_merge(opts, fdin, ffd, p, tfd, f->path, map, mapsz)) {
		ERRX1(opts, "blk_merge");
		goto out;
	}

	/* Optionally preserve times for the output file. */

	if (opts->preserve_times) {
		tv[0].tv_sec = time(NULL);
		tv[0].tv_usec = 0;
		tv[1].tv_sec = f->st.mtime;
		tv[1].tv_usec = 0;
		if (-1 == futimes(tfd, tv)) {
			ERR(opts, "futimes: %s", f->path);
			goto out;
		}
		LOG3(opts, "matching futimes: %s", f->path);
	}

	/* Finally, rename the temporary to the real file. */

	if (-1 == renameat(root, tmpfile, root, f->path)) {
		ERR(opts, "renameat: %s, %s", tmpfile, f->path);
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
stats(const struct opts *opts, int fdin)
{
	size_t	 tread, twrite, tsize;

	/* No statistics in server mode. */

	if (opts->server)
		return 1;

	if ( ! io_read_size(opts, fdin, &tread)) {
		ERRX1(opts, "io_read_size: total read");
		return 0;
	} else if ( ! io_read_size(opts, fdin, &twrite)) {
		ERRX1(opts, "io_read_size: total write");
		return 0;
	} else if ( ! io_read_size(opts, fdin, &tsize)) {
		ERRX1(opts, "io_read_size: total size");
		return 0;
	} 

	LOG1(opts, "stats: %zu B read, %zu B written, %zu B size",
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
rsync_receiver(const struct opts *opts, const struct sess *sess, 
	int fdin, int fdout, const char *root)
{
	struct flist	*fl = NULL;
	size_t		 i, flsz = 0, csum_length = CSUM_LENGTH_PHASE1;
	char		*tofree;
	int		 rc = 0, dfd = -1, phase = 0;
	int32_t	 	 ioerror;

	if (-1 == pledge("unveil rpath cpath wpath stdio fattr", NULL)) {
		ERR(opts, "pledge");
		goto out;
	}

	/* XXX: what does this do? */

	if ( ! opts->server &&
	     ! io_write_int(opts, fdout, 0)) {
		ERRX1(opts, "io_write_int: zero premable");
		goto out;
	}

	/*
	 * Start by receiving the list of filenames.
	 * These we're going to be touching on our local system.
	 */

	if (NULL == (fl = flist_recv(opts, fdin, &flsz))) {
		ERRX1(opts, "flist_recv");
		goto out;
	} else if ( ! io_read_int(opts, fdin, &ioerror)) {
		ERRX1(opts, "io_read_int: io_error");
		goto out;
	} else if (0 != ioerror) {
		ERRX1(opts, "io_error is non-zero");
		goto out;
	}

	/* 
	 * Create the path for our destination directory.
	 * This uses our current umask.
	 */

	if (NULL == (tofree = strdup(root))) {
		ERR(opts, "strdup");
		goto out;
	} else if (mkpath(opts, tofree) < 0) {
		ERRX1(opts, "mkpath: %s", root);
		free(tofree);
		goto out;
	}
	free(tofree);

	/* Disable umask() so we can set permissions fully. */

	umask(0);

	/*
	 * Make our entire view of the file-system be limited to what's
	 * in the root directory.
	 * This prevents us from accidentally (or "under the influence")
	 * writing into other parts of the file-system.
	 */

	if (-1 == unveil(root, "rwc")) {
		ERR(opts, "unveil: %s", root);
		goto out;
	} else if (-1 == unveil(NULL, NULL)) {
		ERR(opts, "unveil: %s", root);
		goto out;
	}

	/* 
	 * Open the destination directory.
	 * This will be the basis of all future files.
	 */

	if (-1 == (dfd = open(root, O_RDONLY | O_DIRECTORY, 0))) {
		ERR(opts, "open: %s", root);
		goto out;
	}

	/*
	 * FIXME: I never use the full checksum amount; but if I were,
	 * here is where the "again" label would go.
	 * This has been demonstrated to work, but I just don't use it
	 * til I understand the need.
	 */

	LOG2(opts, "receiver ready for %zu-checksum "
		"data: %s", csum_length, root);

	for (i = 0; i < flsz; i++)
		if ( ! process(opts, fdin, fdout, 
		    dfd, &fl[i], i, sess, csum_length)) {
			ERRX1(opts, "process");
			goto out;
		}

	/* Properly close us out by progressing through the phases. */

	if (0 == phase) {
		if ( ! io_write_int(opts, fdout, -1)) {
			ERRX1(opts, "io_write_int: index");
			goto out;
		} else if ( ! io_read_int(opts, fdin, &ioerror)) {
			ERRX1(opts, "io_read_int: phase ack");
			goto out;
		} else if (-1 != ioerror) {
			ERRX(opts, "expected phase ack");
			goto out;
		}
		phase++;
		csum_length = CSUM_LENGTH_PHASE2;

		/* 
		 * FIXME: under what conditions should we resend files?
		 * What kind of failure?  This is never specified.
		 * goto again;
		 */
	}

	if (1 == phase) {
		if ( ! io_write_int(opts, fdout, -1)) {
			ERRX1(opts, "io_write_int: send complete");
			goto out;
		} else if ( ! io_read_int(opts, fdin, &ioerror)) {
			ERRX1(opts, "io_read_int: phase ack");
			goto out;
		} else if (-1 != ioerror) {
			ERRX(opts, "expected phase ack");
			goto out;
		}
		phase++;
	}

	if ( ! stats(opts, fdin)) {
		ERRX1(opts, "stats");
		goto out;
	}

	LOG2(opts, "receiver finished updating");
	rc = 1;
out:
	if (-1 != dfd)
		close(dfd);
	flist_free(fl, flsz);
	return rc;
}

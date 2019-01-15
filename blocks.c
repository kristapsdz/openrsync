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
#include <fcntl.h>
#include <inttypes.h>
#include <md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

/*
 * Flush out "size" bytes of buffer "buf".
 * This does all of the appropriate chunking of the data.
 * Return zero on failure, non-zero on success.
 */
static int
blkset_match_flush(const struct opts *opts, 
	int fd, const void *buf, off_t size)
{
	off_t	i = 0, sz;

	while (i < size) {
		sz = MAX_CHUNK < (size - i) ? 
			MAX_CHUNK : (size - i);
		if ( ! io_write_int(opts, fd, sz)) {
			ERRX1(opts, "io_write_int: data block size");
			return 0;
		} else if ( ! io_write_buf(opts, fd, buf + i, sz)) {
			ERRX1(opts, "io_write_buf: data block");
			return 0;
		}
		i += sz;
	}

	return 1;
}

/*
 * From our current position of "offs" in buffer "buf" of total size
 * "size", see if we can find a matching block in our list of blocks.
 * Returns the blk or NULL if no matching block was found.
 */
static struct blk *
blkset_match_find(const struct opts *opts, const void *buf, 
	off_t size, off_t offs, const struct blkset *blks, 
	const struct sess *sess, size_t csum_length)
{
	unsigned char	 md[MD5_DIGEST_LENGTH];
	uint32_t	 fhash;
	off_t		 remain, osz;
	size_t		 i;
	int		 have_md = 0;

	/* 
	 * First, compute our fast hash.
	 * FIXME: yes, this can be a rolling computation, but I'm
	 * deliberately making it simple first.
	 */

	remain = size - offs;
	assert(remain);
	osz = remain < (off_t)blks->len ? remain : (off_t)blks->len;
	fhash = hash_fast(buf + offs, (size_t)osz);
	have_md = 0;

	/* 
	 * Now look for the fast hash.
	 * If it's found, move on to the slow hash.
	 */

	for (i = 0; i < blks->blksz; i++) {
		if (fhash != blks->blks[i].chksum_short) 
			continue;
		if ((size_t)osz != blks->blks[i].len)
			continue;

		LOG3(opts, "sender found matching fast match: "
			"position %llu, block %zu "
			"(position %llu, size %zu): 0x%08x",
			offs, blks->blks[i].idx, blks->blks[i].offs,
			blks->blks[i].len, fhash);

		/* Compute slow hash on demand. */

		if (0 == have_md) {
			hash_slow(buf + offs, (size_t)osz, md, sess);
			have_md = 1;
		}

		if (memcmp(md, blks->blks[i].chksum_long, csum_length))
			continue;

		LOG3(opts, "sender verifies slow match");
		return &blks->blks[i];
	}

	return NULL;
}

/*
 * The main reconstruction algorithm on the sender side.
 * Scans byte-wise over the input file, looking for matching blocks in
 * what the server sent us.
 * If a block is found, emit all data up until the block, then the token
 * for the block.
 * The receiving end can then reconstruct the file trivially.
 * Return zero on failure, non-zero on success.
 */
static int
blkset_match_blocks(const struct opts *opts, int fd, 
	const void *buf, off_t size, const struct blkset *blks,
	const struct sess *sess, size_t csum_length)
{
	off_t	 	 offs, last, end, nf;
	struct blk	*blk;

	/* 
	 * Stop searching at the length of the file minus the size of
	 * the last block.
	 * The reason for this being that we don't need to do an
	 * incremental hash within the last block---if it doesn't match,
	 * it doesn't match.
	 */

	end = size + 1 - blks->blks[blks->blksz - 1].len;

	nf = 0;
	for (last = offs = 0; offs < end; offs++) {
		blk = blkset_match_find(opts, buf, 
			size, offs, blks, sess, csum_length);
		nf++;
		if (NULL == blk)
			continue;

		LOG3(opts, "sender flushing %llu "
			"bytes before block of %zu", 
			offs - last, blk->len);
		nf = 0;

		/* Flush what we have and follow with our tag. */

		if ( ! blkset_match_flush(opts, fd, buf + last, offs - last)) {
			ERRX1(opts, "blkset_match_flush");
			return 0;
		} else if ( ! io_write_int(opts, fd, -(blk->idx + 1))) {
			ERRX1(opts, "io_write_int: token");
			return 0;
		}

		offs += blk->len - 1;
		last = offs + 1;
	}

	LOG3(opts, "sender flushing %llu remaining bytes", size - last);

	/* Emit remaining data and send terminator. */

	if ( ! blkset_match_flush(opts, fd, buf + last, size - last))
		ERRX1(opts, "blkset_match_flush");
	else if ( ! io_write_int(opts, fd, 0))
		ERRX1(opts, "io_write_int: data block size");

	return 1;
}

/*
 * Simply pushes the entire file over the wire.
 * Return zero on failure, non-zero on success.
 */
static int
blkset_match_full(const struct opts *opts, 
	int fd, const void *buf, off_t size)
{

	/* Flush, then indicate that we have no more data to send. */

	if ( ! blkset_match_flush(opts, fd, buf, size))
		ERRX1(opts, "blkset_match_flush");
	else if ( ! io_write_int(opts, fd, 0))
		ERRX1(opts, "io_write_int: data block size");
	else
		return 1;

	return 0;
}

/*
 * Given a local file "path" and the blocks created by a remote machine,
 * find out which blocks of our file they don't have and send them.
 */
int
blkset_match(const struct opts *opts, const struct sess *sess,
	int fd, const struct blkset *blks, const char *path, 
	size_t csum_length)
{
	int	 	 nfd, rc = 0;
	struct stat	 st;
	void		*map;
	size_t		 mapsz;
	unsigned char	 filemd[MD5_DIGEST_LENGTH];

	/* Start by mapping our file into memory. */

	if (-1 == (nfd = open(path, O_RDONLY, 0))) {
		ERR(opts, "open: %s", path);
		return 0;
	} else if (-1 == fstat(nfd, &st)) {
		ERR(opts, "fstat: %s", path);
		close(nfd);
		return 0;
	}

	mapsz = st.st_size;
	map = mmap(NULL, mapsz, PROT_READ, MAP_SHARED, nfd, 0);
	if (MAP_FAILED == map) {
		ERR(opts, "mmap: %s", path);
		close(nfd);
		return 0;
	}

	/*
	 * If the file's empty or we don't have any blocks from the
	 * sender, then simply send the whole file.
	 * Otherwise, run the hash matching routine.
	 */

	if (st.st_size && blks->blksz) {
		LOG2(opts, "transmitting %zu blocks of %llu "
			"bytes: %s", blks->blksz, st.st_size, path);
		blkset_match_blocks(opts, fd, map, 
			st.st_size, blks, sess, csum_length);
	} else {
		LOG2(opts, "transmitting full file "
			"of %llu bytes: %s", st.st_size, path);
		blkset_match_full(opts, fd, map, st.st_size);
	}

	hash_file(map, st.st_size, filemd);

	if ( ! io_write_buf(opts, fd, filemd, MD5_DIGEST_LENGTH)) {
		ERRX1(opts, "io_write_buf: data blocks hash");
		goto out;
	}

	LOG2(opts, "transmitted blocks: %s", path);
	rc = 1;
out:
	munmap(map, mapsz);
	close(nfd);
	return rc;
}

void
blkset_free(struct blkset *p)
{

	if (NULL == p)
		return;
	free(p->blks);
	free(p);
}

/*
 * Sent from the client to the server to indicate that the block set has
 * been received (with blkset_recv).
 * Returns zero on failure, non-zero on success.
 */
int
blkset_recv_ack(const struct opts *opts, 
	int fd, const struct blkset *blocks, int32_t idx)
{

	if ( ! io_write_int(opts, fd, idx))
		ERRX1(opts, "io_write_int: send ack");
	else if ( ! io_write_int(opts, fd, blocks->blksz))
		ERRX1(opts, "io_write_int: send ack: block count");
	else if ( ! io_write_int(opts, fd, blocks->len))
		ERRX1(opts, "io_write_int: send ack: block size");
	else if ( ! io_write_int(opts, fd, blocks->rem))
		ERRX1(opts, "io_write_int: send ack: remainder");
	else
		return 1;

	return 0;
}

/*
 * Read all of the checksums for a file's blocks.
 * Returns the set of blocks or NULL on failure.
 */
struct blkset *
blkset_recv(const struct opts *opts, 
	int fd, size_t csum_length, const char *path)
{
	struct blkset	*s;
	int32_t		 i;
	size_t		 j;
	struct blk	*b;
	off_t		 offs = 0;

	if (NULL == (s = calloc(1, sizeof(struct blkset)))) {
		ERR(opts, "calloc");
		return NULL;
	}

	/*
	 * The block prologue consists of a few values that we'll need
	 * in reading the individual blocks for this file.
	 */

	if ( ! io_read_int(opts, fd, &i)) {
		ERRX1(opts, "io_read_int: block count");
		goto out;
	} else if (i < 0) {
		ERRX1(opts, "negative block count");
		goto out;
	}
	s->blksz = i;
	
	if ( ! io_read_int(opts, fd, &i)) {
		ERRX1(opts, "io_read_int: block length");
		goto out;
	} else if (i < 0) {
		ERRX1(opts, "negative block length");
		goto out;
	}
	s->len = i;

	if ( ! io_read_int(opts, fd, &i)) {
		ERRX1(opts, "io_read_int: block remainder");
		goto out;
	} else if (i < 0) {
		ERRX1(opts, "negative block remainder");
		goto out;
	}
	s->rem = i;

	LOG2(opts, "read block prologue: %zu blocks of "
		"%zu bytes, %zu remainder", 
		s->blksz, s->len, s->rem);

	/* Short-circuit: we have no blocks to read. */

	if (0 == s->blksz)
		return s;

	s->blks = calloc(s->blksz, sizeof(struct blk));
	if (NULL == s->blks) {
		ERR(opts, "calloc");
		goto out;
	}

	/* Read each block individually. */

	for (j = 0; j < s->blksz; j++) {
		b = &s->blks[j];
		if ( ! io_read_int(opts, fd, &i)) {
			ERRX1(opts, "io_read_int: short checksum");
			goto out;
		}
		b->chksum_short = i;
		assert(csum_length <= sizeof(b->chksum_long));
		if ( ! io_read_buf(opts, fd, b->chksum_long, csum_length)) {
			ERRX1(opts, "io_read_buf: long checksum");
			goto out;
		}
		b->offs = offs;
		b->idx = j;

		/*
		 * If we're the last block, then we're assigned the
		 * remainder of the data.
		 */

		b->len = (j == (s->blksz - 1) && s->rem) ? s->rem : s->len;
		offs += b->len;

		LOG2(opts, "read block %zu, length %zu, checksum=0x%08x", 
			b->idx, b->len, b->chksum_short);
	}

	s->size = offs;
	LOG2(opts, "read blocks: %zu blocks, %llu "
		"total filesize", s->blksz, s->size);
	return s;
out:
	free(s);
	return NULL;
}

/*
 * Symmetrise blkset_recv_ack().
 */
int
blkset_send_ack(const struct opts *opts, 
	int fd, const struct blkset *blocks, size_t idx)
{
	int32_t		 blksz, len, rem, nidx;

	if ( ! io_read_int(opts, fd, &nidx))
		ERRX1(opts, "io_read_int: read ack");
	else if ((int32_t)idx != nidx)
		ERRX1(opts, "read ack: indices don't match");
	else if ( ! io_read_int(opts, fd, &blksz))
		ERRX1(opts, "io_read_int: read ack: block count");
	else if ((uint32_t)blksz != blocks->blksz)
		ERRX1(opts, "read ack: block counts don't match");
	else if ( ! io_read_int(opts, fd, &len))
		ERRX1(opts, "io_read_int: read ack: block size");
	else if ((uint32_t)len != blocks->len)
		ERRX1(opts, "read ack: block sizes don't match "
			"(%" PRId32 ", %zu)", len, blocks->len);
	else if ( ! io_read_int(opts, fd, &rem))
		ERRX1(opts, "io_read_int: read ack: remainder");
	else if ((uint32_t)rem != blocks->rem)
		ERRX1(opts, "read ack: block remainders don't match");
	else
		return 1;

	return 0;
}

static int
blkset_merge(const struct opts *opts, int fd, int ffd,
	const struct blkset *block, int outfd, const void *map, 
	size_t mapsz)
{
	int32_t		 sz, tok;
	char		*buf = NULL;
	void		*pp;
	ssize_t		 ssz;
	int		 rc = 0;
	unsigned char	 md[MD5_DIGEST_LENGTH];
	off_t		 total = 0;

	for (;;) {
		if ( ! io_read_int(opts, fd, &sz)) {
			ERRX1(opts, "io_read_int: data block size");
			goto out;
		} else if (sz < 0) {
			ERRX(opts, "negative data block size");
			goto out;
		} else if (NULL == (pp = realloc(buf, sz))) {
			ERR(opts, "realloc");
			goto out;
		} 

		buf = pp;
		if ( ! io_read_buf(opts, fd, buf, sz)) {
			ERRX1(opts, "io_read_int: data block");
			goto out;
		}

		total += sz;
		LOG2(opts, "received %llu data bytes", total);

		if ((ssz = write(outfd, buf, sz)) < 0) {
			ERR(opts, "write: temporary file");
			goto out;
		} else if (ssz != sz) {
			ERRX(opts, "write: short write");
			goto out;
		}

		if ( ! io_read_int(opts, fd, &tok)) {
			ERRX1(opts, "io_read_int: token");
			goto out;
		} else if (tok < 0) {
			ERRX(opts, "negative token index");
			goto out;
		} else if (0 == tok)
			break;

		if ((size_t)tok >= block->blksz) {
			ERRX(opts, "token not in block set");
			goto out;
		}

		LOG2(opts, "merged %zu data block", 
			block->blks[tok].len);
		total += block->blks[tok].len;

		ssz = write(outfd, 
			map + block->blks[tok].offs, 
			block->blks[tok].len);

		if (ssz < 0) {
			ERR(opts, "write: temporary file");
			goto out;
		} else if (ssz != sz) {
			ERRX(opts, "write: short write");
			goto out;
		}
	}

	if ( ! io_read_buf(opts, fd, md, MD5_DIGEST_LENGTH)) {
		ERRX1(opts, "io_read_buf: data blocks hash");
		goto out;
	}

	LOG2(opts, "merged %llu total bytes", total);
	rc = 1;
out:
	free(buf);
	return rc;
}

/*
 * This is the main function for the receiver.
 * Open the existing file (if found), the temporary file, read new data
 * (and good blocks) from the sender, reconstruct the file, and rename
 * it.
 * Return zero on failure, non-zero on success.
 */
int
blkset_send(const struct opts *opts, int fdin, int fdout, int root, 
	const char *path, size_t idx, const struct sess *sess)
{
	struct blkset	*p;
	int		 ffd = -1, rc = 0, tfd = -1;
	off_t		 offs = 0;
	struct stat	 st;
	size_t		 i, mapsz;
	void		*map = MAP_FAILED;
	char		*tmpfile = NULL;
	uint32_t	 hash;
	struct blk	*b;

	if (NULL == (p = calloc(1, sizeof(struct blkset)))) {
		ERR(opts, "calloc");
		return 0;
	}

	/* 
	 * Generate the block hash list from the existing file.
	 * Not having a file is fine: it just means that we'll need to
	 * download the full file.
	 */

	if (-1 != (ffd = openat(root, path, O_RDONLY, 0))) {
		if (-1 == fstat(ffd, &st)) {
			WARN(opts, "warn: %s", path);
			close(ffd);
			ffd = -1;
		} else 
			p->size = st.st_size;
	} else
		WARN(opts, "openat: %s", path);

	/* 
	 * If open, try to map the file into memory.
	 * If we fail doing this, then we have a problem.
	 */

	p->len = MAX_CHUNK;

	if (-1 != ffd) {
		mapsz = st.st_size;
		map = mmap(NULL, mapsz, 
			PROT_READ, MAP_SHARED, ffd, 0);

		if (MAP_FAILED == map) {
			WARN(opts, "mmap: %s", path);
			goto out;
		}

		p->blksz = mapsz / MAX_CHUNK;
		p->rem = mapsz % MAX_CHUNK;

		p->blks = calloc(p->blksz, sizeof(struct blk));
		if (NULL == p->blks) {
			ERR(opts, "calloc");
			goto out;
		}
		for (i = 0; i < p->blksz; i++) {
			p->blks[i].idx = i;
			p->blks[i].len = 
				i < p->blksz - 1 ? p->blksz : p->rem;
			p->blks[i].offs = offs;
			p->blks[i].chksum_short = hash_fast
				(map + offs, p->blks[i].len);
			hash_slow(map + offs, p->blks[i].len, 
				p->blks[i].chksum_long, sess);
			offs += p->len;
		}
		LOG2(opts, "mapped %llu bytes with %zu "
			"blocks: %s", p->size, p->blksz, path);
	} else
		LOG2(opts, "unmapped %llu bytes: %s", p->size, path);

	/* 
	 * Regardless the situation of our origin file (which may not
	 * exist, of course), we want to open our temporary file so that
	 * we can write into it.
	 * This can't fail.
	 */

	hash = arc4random();
	if (asprintf(&tmpfile, ".%s.%" PRIu32, path, hash) < 0) {
		ERR(opts, "asprintf");
		tmpfile = NULL;
		goto out;
	} 

	LOG2(opts, "prepared temporary: %s -> %s", path, tmpfile);

	tfd = openat(root, tmpfile, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (-1 == tfd) {
		ERR(opts, "openat: %s", tmpfile);
		goto out;
	}

	/* Now transmit the generated blocks. */

	if ( ! io_write_int(opts, fdout, p->blksz)) {
		ERRX1(opts, "io_write_int: block count");
		goto out;
	} else if ( ! io_write_int(opts, fdout, p->len)) {
		ERRX1(opts, "io_write_int: block length");
		goto out;
	} else if ( ! io_write_int(opts, fdout, p->rem)) {
		ERRX1(opts, "io_write_int: block remainder");
		goto out;
	} 

	LOG2(opts, "sent block prologue: %zu blocks of "
		"%zu bytes, %zu remainder", 
		p->blksz, p->len, p->rem);

	for (i = 0; i < p->blksz; i++) {
		b = &p->blks[i];
		if ( ! io_write_int(opts, fdout, b->chksum_short)) {
			ERRX1(opts, "io_write_int: short checksum");
			goto out;
		}
		if ( ! io_write_buf(opts, fdout, b->chksum_long, 2)) {
			ERRX1(opts, "io_write_int: long checksum");
			goto out;
		}
	}
	
	/* Now read back our acknowledgement. */

	if ( ! blkset_send_ack(opts, fdin, p, idx)) {
		ERRX1(opts, "blkset_send_ack");
		goto out;
	}

	/* 
	 * Now we respond to matches.
	 * We write all of the data into "tfd", which we're going to
	 * rename as the original file.
	 */

	if ( ! blkset_merge(opts, fdin, ffd, p, tfd, map, mapsz)) {
		ERRX1(opts, "blkset_mege");
		goto out;
	} else if (-1 == renameat(root, tmpfile, root, path)) {
		ERR(opts, "renameat: %s, %s", tmpfile, path);
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
	if (-1 != tfd) {
		close(tfd);
		remove(tmpfile);
	}

	free(tmpfile);
	blkset_free(p);
	return rc;
}

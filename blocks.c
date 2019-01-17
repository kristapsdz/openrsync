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
#include <md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

/*
 * Flush out "size" bytes of the buffer, doing all of the appropriate
 * chunking of the data.
 * Return zero on failure, non-zero on success.
 */
static int
blk_flush(const struct opts *opts, int fd, const void *b, off_t size)
{
	off_t	i = 0, sz;

	while (i < size) {
		sz = MAX_CHUNK < (size - i) ? 
			MAX_CHUNK : (size - i);
		if ( ! io_write_int(opts, fd, sz)) {
			ERRX1(opts, "io_write_int: data block size");
			return 0;
		} else if ( ! io_write_buf(opts, fd, b + i, sz)) {
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
blk_find(const struct opts *opts, const void *buf, 
	off_t size, off_t offs, const struct blkset *blks, 
	const struct sess *sess, size_t csum_length,
	const char *path)
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

		LOG4(opts, "%s: found matching fast match: "
			"position %llu, block %zu "
			"(position %llu, size %zu): 0x%08x", path,
			offs, blks->blks[i].idx, blks->blks[i].offs,
			blks->blks[i].len, fhash);

		/* Compute slow hash on demand. */

		if (0 == have_md) {
			hash_slow(buf + offs, (size_t)osz, md, sess);
			have_md = 1;
		}

		if (memcmp(md, blks->blks[i].chksum_long, csum_length))
			continue;

		LOG4(opts, "%s: sender verifies slow match", path);
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
blk_match_part(const struct opts *opts, const char *path,
	int fd, const void *buf, off_t size, 
	const struct blkset *blks, const struct sess *sess, 
	size_t csum_length)
{
	off_t	 	 offs, last, end, fromcopy = 0, fromdown = 0;
	struct blk	*blk;

	/* 
	 * Stop searching at the length of the file minus the size of
	 * the last block.
	 * The reason for this being that we don't need to do an
	 * incremental hash within the last block---if it doesn't match,
	 * it doesn't match.
	 */

	end = size + 1 - blks->blks[blks->blksz - 1].len;

	for (last = offs = 0; offs < end; offs++) {
		blk = blk_find(opts, buf, size, offs, 
			blks, sess, csum_length, path);
		if (NULL == blk)
			continue;

		fromdown += offs - last;
		LOG4(opts, "%s: flushed %llu B before %zu B block (%zu)", 
			path, offs - last, blk->len, blk->idx);

		/* Flush what we have and follow with our tag. */

		if ( ! blk_flush(opts, fd, buf + last, offs - last)) {
			ERRX1(opts, "blk_flush");
			return 0;
		} else if ( ! io_write_int(opts, fd, -(blk->idx + 1))) {
			ERRX1(opts, "io_write_int: token");
			return 0;
		}

		fromcopy += blk->len;
		offs += blk->len - 1;
		last = offs + 1;
	}

	LOG4(opts, "%s: flushed remaining %llu B", path, size - last);
	LOG3(opts, "%s: %.2f%% upload", path, 
		100.0 * fromdown / (fromcopy + fromdown));

	/* Emit remaining data and send terminator. */

	if ( ! blk_flush(opts, fd, buf + last, size - last))
		ERRX1(opts, "blk_flush");
	else if ( ! io_write_int(opts, fd, 0))
		ERRX1(opts, "io_write_int: data block size");

	return 1;
}

/*
 * Simply pushes the entire file over the wire.
 * Return zero on failure, non-zero on success.
 */
static int
blk_match_full(const struct opts *opts, 
	int fd, const void *buf, off_t size)
{

	/* Flush, then indicate that we have no more data to send. */

	if ( ! blk_flush(opts, fd, buf, size))
		ERRX1(opts, "blk_flush");
	else if ( ! io_write_int(opts, fd, 0))
		ERRX1(opts, "io_write_int: data block size");
	else
		return 1;

	return 0;
}

/*
 * Given a local file "path" and the blocks created by a remote machine,
 * find out which blocks of our file they don't have and send them.
 * Return zero on failure, non-zero on success.
 */
int
blk_match(const struct opts *opts, const struct sess *sess,
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
		blk_match_part(opts, path, fd, map, 
			st.st_size, blks, sess, csum_length);
		LOG3(opts, "%s: sent chunked %zu blocks of "
			"%zu B (%zu B remainder)", path, blks->blksz, 
			blks->len, blks->rem);
	} else {
		blk_match_full(opts, fd, map, st.st_size);
		LOG3(opts, "%s: sent un-chunked %llu B", path, st.st_size);
	}

	/* Now write the full file hash. */

	hash_file(map, st.st_size, filemd);

	if ( ! io_write_buf(opts, fd, filemd, MD5_DIGEST_LENGTH)) {
		ERRX1(opts, "io_write_buf: data blocks hash");
		goto out;
	}

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
 * Sent from the sender to the receiver to indicate that the block set
 * has been received.
 * Symmetrises blk_send_ack().
 * Returns zero on failure, non-zero on success.
 */
int
blk_recv_ack(const struct opts *opts, 
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
blk_recv(const struct opts *opts, int fd, 
	size_t csum_length, const char *path)
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

	if ( ! io_read_size(opts, fd, &s->blksz)) {
		ERRX1(opts, "io_read_size: block count");
		goto out;
	} else if ( ! io_read_size(opts, fd, &s->len)) {
		ERRX1(opts, "io_read_sisze: block length");
		goto out;
	} else if ( ! io_read_size(opts, fd, &s->rem)) {
		ERRX1(opts, "io_read_int: block remainder");
		goto out;
	} else if (s->rem >= s->len) {
		ERRX(opts, "block remainder is "
			"greater than block sie");
		goto out;
	}

	LOG3(opts, "%s: read block prologue: %zu blocks of "
		"%zu B, %zu B remainder", path, s->blksz, 
		s->len, s->rem);

	if (s->blksz) {
		s->blks = calloc(s->blksz, sizeof(struct blk));
		if (NULL == s->blks) {
			ERR(opts, "calloc");
			goto out;
		}
	}

	/* Read each block individually. */

	for (j = 0; j < s->blksz; j++) {
		b = &s->blks[j];
		if ( ! io_read_int(opts, fd, &i)) {
			ERRX1(opts, "io_read_int: fast checksum");
			goto out;
		}
		b->chksum_short = i;

		assert(csum_length <= sizeof(b->chksum_long));
		if ( ! io_read_buf(opts, 
		    fd, b->chksum_long, csum_length)) {
			ERRX1(opts, "io_read_buf: slow checksum");
			goto out;
		}

		/*
		 * If we're the last block, then we're assigned the
		 * remainder of the data.
		 */

		b->offs = offs;
		b->idx = j;
		b->len = (j == (s->blksz - 1) && s->rem) ? s->rem : s->len;
		offs += b->len;

		LOG4(opts, "%s: read block %zu, length %zu B, "
			"checksum=0x%08x", path, b->idx, b->len, 
			b->chksum_short);
	}

	s->size = offs;
	LOG3(opts, "%s: read blocks: %zu blocks, %llu "
		"B total blocked data", path, s->blksz, s->size);
	return s;
out:
	blkset_free(s);
	return NULL;
}

/*
 * Symmetrise blk_recv_ack().
 * Return zero on failure, non-zero on success.
 */
int
blk_send_ack(const struct opts *opts, 
	int fd, const struct blkset *blocks, size_t idx)
{
	size_t		 rem, len, blksz, nidx;

	if ( ! io_read_size(opts, fd, &nidx))
		ERRX1(opts, "io_read_size: read ack");
	else if (idx != nidx)
		ERRX1(opts, "read ack: indices don't match");
	else if ( ! io_read_size(opts, fd, &blksz))
		ERRX1(opts, "io_read_size: read ack: block count");
	else if (blksz != blocks->blksz)
		ERRX1(opts, "read ack: block counts don't match");
	else if ( ! io_read_size(opts, fd, &len))
		ERRX1(opts, "io_read_size: read ack: block size");
	else if (len != blocks->len)
		ERRX1(opts, "read ack: block sizes don't match");
	else if ( ! io_read_size(opts, fd, &rem))
		ERRX1(opts, "io_read_size: read ack: remainder");
	else if (rem != blocks->rem)
		ERRX1(opts, "read ack: block remainders don't match");
	else
		return 1;

	return 0;
}

/*
 * The receiver now reads raw data and block indices from the sender,
 * and merges them into the temporary file.
 * Returns zero on failure, non-zero on success.
 */
static int
blk_merge(const struct opts *opts, int fd, int ffd,
	const struct blkset *block, int outfd, const char *path, 
	const void *map, size_t mapsz)
{
	size_t		 sz, tok;
	int32_t		 rawtok;
	char		*buf = NULL;
	void		*pp;
	ssize_t		 ssz;
	int		 rc = 0;
	unsigned char	 md[MD5_DIGEST_LENGTH],
			 ourmd[MD5_DIGEST_LENGTH];
	off_t		 total = 0, fromcopy = 0, fromdown = 0;
	MD5_CTX		 ctx;

	MD5Init(&ctx);

	for (;;) {
		if ( ! io_read_int(opts, fd, &rawtok)) {
			ERRX1(opts, "io_read_int: data block size");
			goto out;
		} else if (0 == rawtok) 
			break;

		if (rawtok > 0) {
			sz = rawtok;
			if (NULL == (pp = realloc(buf, sz))) {
				ERR(opts, "realloc");
				goto out;
			} 
			buf = pp;
			if ( ! io_read_buf(opts, fd, buf, sz)) {
				ERRX1(opts, "io_read_int: data block");
				goto out;
			}

			if ((ssz = write(outfd, buf, sz)) < 0) {
				ERR(opts, "write: temporary file");
				goto out;
			} else if ((size_t)ssz != sz) {
				ERRX(opts, "write: short write");
				goto out;
			}

			fromdown += sz;
			total += sz;
			LOG4(opts, "%s: received %zd bytes, "
				"now %llu total", path, ssz, total);

			MD5Update(&ctx, buf, sz);
		} else {
			tok = -rawtok - 1;
			if (tok >= block->blksz) {
				ERRX(opts, "token not in block set");
				goto out;
			}

			/* 
			 * Now we read from our block.
			 * We should only be at this point if we have a
			 * block to read from, i.e., if we were able to
			 * map our origin file and create a block
			 * profile from it.
			 */

			assert(MAP_FAILED != map);

			ssz = write(outfd, 
				map + block->blks[tok].offs, 
				block->blks[tok].len);

			if (ssz < 0) {
				ERR(opts, "write: temporary file");
				goto out;
			} else if ((size_t)ssz != block->blks[tok].len) {
				ERRX(opts, "write: short write");
				goto out;
			}

			fromcopy += block->blks[tok].len;
			total += block->blks[tok].len;
			LOG4(opts, "%s: copied %zu bytes, now %llu total", 
				path, block->blks[tok].len, total);

			MD5Update(&ctx, 
				map + block->blks[tok].offs, 
				block->blks[tok].len);
		}
	}

	/* Make sure our resulting MD5 hashes match. */

	if ( ! io_read_buf(opts, fd, md, MD5_DIGEST_LENGTH)) {
		ERRX1(opts, "io_read_buf: data blocks hash");
		goto out;
	}

	MD5Final(ourmd, &ctx);

	if (memcmp(md, ourmd, MD5_DIGEST_LENGTH)) {
		ERRX(opts, "file hash does not match");
		goto out;
	}

	LOG3(opts, "%s: merged %llu total bytes", path, total);
	LOG3(opts, "%s: %.2f%% upload", path, 100.0 * fromdown / total);
	rc = 1;
out:
	free(buf);
	return rc;
}

/*
 * Prepare the overall block set's metadata.
 * We always have at least one block.
 */
static void
blk_set_blocksize(struct blkset *p, off_t sz)
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
 */
static void
blk_set_blockparams(struct blk *p, const struct blkset *set,
	off_t offs, size_t idx, const void *map, 
	const struct sess *sess)
{

	/* Block length inherits for all but the last. */

	p->idx = idx;
	p->len = idx < set->blksz - 1 ? set->len : set->rem;
	p->offs = offs;
	p->chksum_short = hash_fast(map + offs, p->len);
	hash_slow(map + offs, p->len, p->chksum_long, sess);
}

/*
 * This is the main function for the receiver.
 * Open the existing file (if found), the temporary file, read new data
 * (and good blocks) from the sender, reconstruct the file, and rename
 * it.
 * Return zero on failure, non-zero on success.
 */
int
blk_send(const struct opts *opts, int fdin, int fdout, int root, 
	const char *path, size_t idx, const struct sess *sess,
	size_t csumlen)
{
	struct blkset	*p;
	int		 ffd = -1, rc = 0, tfd = -1;
	off_t		 offs = 0;
	struct stat	 st;
	size_t		 i, mapsz = 0;
	void		*map = MAP_FAILED;
	char		*tmpfile = NULL;
	uint32_t	 hash;
	struct blk	*b;

	if (NULL == (p = calloc(1, sizeof(struct blkset)))) {
		ERR(opts, "calloc");
		return 0;
	}

	p->len = MAX_CHUNK;

	/* 
	 * Not having a file is fine: it just means that we'll need to
	 * download the full file (i.e., have zero blocks).
	 * If this is the case, map will stay at MAP_FAILED.
	 */

	if (-1 != (ffd = openat(root, path, O_RDONLY, 0))) {
		if (-1 == fstat(ffd, &st)) {
			WARN(opts, "warn: %s", path);
			close(ffd);
			ffd = -1;
		} else 
			p->size = st.st_size;
	} else if (ENOENT == errno) {
		WARN2(opts, "openat: %s", path);
	} else
		WARN1(opts, "openat: %s", path);

	/* 
	 * If open, try to map the file into memory.
	 * If we fail doing this, then we have a problem: we don't need
	 * the file, but we need to be able to mmap() it.
	 */

	if (-1 != ffd) {
		mapsz = st.st_size;
		map = mmap(NULL, mapsz, PROT_READ, MAP_SHARED, ffd, 0);

		if (MAP_FAILED == map) {
			WARN(opts, "mmap: %s", path);
			goto out;
		}

		blk_set_blocksize(p, st.st_size);
		assert(p->blksz);

		p->blks = calloc(p->blksz, sizeof(struct blk));
		if (NULL == p->blks) {
			ERR(opts, "calloc");
			goto out;
		}

		for (i = 0; i < p->blksz; i++, offs += p->len)
			blk_set_blockparams
				(&p->blks[i], p, offs, i, map, sess);

		LOG3(opts, "%s: mapped %llu B with %zu "
			"blocks", path, p->size, p->blksz);
	} else
		LOG3(opts, "%s: not mapped", path);

	/* 
	 * Open our writable temporary file (failure is an error). 
	 * To make this reasonably unique, make the file into a dot-file
	 * and give it a random suffix.
	 */

	hash = arc4random();
	if (asprintf(&tmpfile, ".%s.%" PRIu32, path, hash) < 0) {
		ERR(opts, "asprintf");
		tmpfile = NULL;
		goto out;
	} 

	tfd = openat(root, tmpfile, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (-1 == tfd) {
		ERR(opts, "openat: %s", tmpfile);
		goto out;
	}

	LOG3(opts, "%s: temporary: %s", path, tmpfile);

	/* Now transmit the metadata for set and blocks. */

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

	for (i = 0; i < p->blksz; i++) {
		b = &p->blks[i];
		if ( ! io_write_int(opts, fdout, b->chksum_short)) {
			ERRX1(opts, "io_write_int: short checksum");
			goto out;
		}
		if ( ! io_write_buf(opts, fdout, b->chksum_long, csumlen)) {
			ERRX1(opts, "io_write_int: long checksum");
			goto out;
		}
	}

	LOG3(opts, "%s: sent block metadata: %zu blocks of %zu B, "
		"%zu B remainder", path, p->blksz, p->len, p->rem);
	
	/* Read back acknowledgement. */

	if ( ! blk_send_ack(opts, fdin, p, idx)) {
		ERRX1(opts, "blk_send_ack");
		goto out;
	}

	/* 
	 * Now we respond to matches.
	 * We write all of the data into "tfd", which we're going to
	 * rename as the original file.
	 */

	if ( ! blk_merge(opts, fdin, ffd, p, tfd, path, map, mapsz)) {
		ERRX1(opts, "blk_merge");
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

	/* On failure, clean up our temporary file. */

	if (-1 != tfd) {
		close(tfd);
		remove(tmpfile);
	}

	free(tmpfile);
	blkset_free(p);
	return rc;
}

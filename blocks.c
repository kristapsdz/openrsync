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
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "md4.h"
#include "extern.h"

/*
 * Flush out "size" bytes of the buffer, doing all of the appropriate
 * chunking of the data.
 * FIXME: put the token write in here as well.
 * Return zero on failure, non-zero on success.
 */
static int
blk_flush(struct sess *sess, int fd, const void *b, off_t size)
{
	off_t	i = 0, sz;

	while (i < size) {
		sz = MAX_CHUNK < (size - i) ?
			MAX_CHUNK : (size - i);
		if ( ! io_write_int(sess, fd, sz)) {
			ERRX1(sess, "io_write_int: data block size");
			return 0;
		} else if ( ! io_write_buf(sess, fd, b + i, sz)) {
			ERRX1(sess, "io_write_buf: data block");
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
blk_find(struct sess *sess, const void *buf, off_t size,
	off_t offs, const struct blkset *blks, const char *path)
{
	unsigned char	 md[MD4_DIGEST_LENGTH];
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

		LOG4(sess, "%s: found matching fast match: "
			"position %jd, block %zu "
			"(position %jd, size %zu)", path,
			(intmax_t)offs, blks->blks[i].idx,
			(intmax_t)blks->blks[i].offs,
			blks->blks[i].len);

		/* Compute slow hash on demand. */

		if (0 == have_md) {
			hash_slow(buf + offs, (size_t)osz, md, sess);
			have_md = 1;
		}

		if (memcmp(md, blks->blks[i].chksum_long, blks->csum))
			continue;

		LOG4(sess, "%s: sender verifies slow match", path);
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
blk_match_part(struct sess *sess, const char *path, int fd,
	const void *buf, off_t size, const struct blkset *blks)
{
	off_t	 	 offs, last, end, fromcopy = 0, fromdown = 0,
			 total = 0;
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
		blk = blk_find(sess, buf, size, offs, blks, path);
		if (NULL == blk)
			continue;

		fromdown += offs - last;
		total += offs - last;
		LOG4(sess, "%s: flushed %jd B before %zu B block "
			"(%zu)", path, (intmax_t)(offs - last),
			blk->len, blk->idx);

		/* Flush what we have and follow with our tag. */

		if ( ! blk_flush(sess, fd, buf + last, offs - last)) {
			ERRX1(sess, "blk_flush");
			return 0;
		} else if ( ! io_write_int(sess, fd, -(blk->idx + 1))) {
			ERRX1(sess, "io_write_int: token");
			return 0;
		}

		fromcopy += blk->len;
		total += blk->len;
		offs += blk->len - 1;
		last = offs + 1;
	}

	/* Emit remaining data and send terminator. */

	total += size - last;
	fromdown += size - last;

	LOG4(sess, "%s: flushed remaining %jd B",
		path, (intmax_t)(size - last));

	if ( ! blk_flush(sess, fd, buf + last, size - last))
		ERRX1(sess, "blk_flush");
	else if ( ! io_write_int(sess, fd, 0))
		ERRX1(sess, "io_write_int: data block size");

	LOG3(sess, "%s: %.2f%% upload",
		path, 100.0 * fromdown / total);

	return 1;
}

/*
 * Simply pushes the entire file over the wire.
 * Return zero on failure, non-zero on success.
 */
static int
blk_match_full(struct sess *sess, int fd, const void *buf, off_t size)
{

	/* Flush, then indicate that we have no more data to send. */

	if ( ! blk_flush(sess, fd, buf, size))
		ERRX1(sess, "blk_flush");
	else if ( ! io_write_int(sess, fd, 0))
		ERRX1(sess, "io_write_int: data block size");
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
blk_match(struct sess *sess, int fd,
	const struct blkset *blks, const char *path)
{
	int	 	 nfd, rc = 0;
	struct stat	 st;
	void		*map;
	size_t		 mapsz;
	unsigned char	 filemd[MD4_DIGEST_LENGTH];

	/* Start by mapping our file into memory. */

	if (-1 == (nfd = open(path, O_RDONLY, 0))) {
		ERR(sess, "open: %s", path);
		return 0;
	} else if (-1 == fstat(nfd, &st)) {
		ERR(sess, "fstat: %s", path);
		close(nfd);
		return 0;
	}

	mapsz = st.st_size;
	map = mmap(NULL, mapsz, PROT_READ, MAP_SHARED, nfd, 0);
	if (MAP_FAILED == map) {
		ERR(sess, "mmap: %s", path);
		close(nfd);
		return 0;
	}

	/*
	 * If the file's empty or we don't have any blocks from the
	 * sender, then simply send the whole file.
	 * Otherwise, run the hash matching routine.
	 */

	if (st.st_size && blks->blksz) {
		blk_match_part(sess, path, fd, map, st.st_size, blks);
		LOG3(sess, "%s: sent chunked %zu blocks of "
			"%zu B (%zu B remainder)", path, blks->blksz,
			blks->len, blks->rem);
	} else {
		blk_match_full(sess, fd, map, st.st_size);
		LOG3(sess, "%s: sent un-chunked %jd B",
			path, (intmax_t)st.st_size);
	}

	/* Now write the full file hash. */

	hash_file(map, st.st_size, filemd, sess);

	if ( ! io_write_buf(sess, fd, filemd, MD4_DIGEST_LENGTH)) {
		ERRX1(sess, "io_write_buf: data blocks hash");
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
blk_recv_ack(struct sess *sess,
	int fd, const struct blkset *blocks, int32_t idx)
{

	if ( ! io_write_int(sess, fd, idx))
		ERRX1(sess, "io_write_int: send ack");
	else if ( ! io_write_int(sess, fd, blocks->blksz))
		ERRX1(sess, "io_write_int: send ack: block count");
	else if ( ! io_write_int(sess, fd, blocks->len))
		ERRX1(sess, "io_write_int: send ack: block size");
	else if ( ! io_write_int(sess, fd, blocks->csum))
		ERRX1(sess, "io_write_int: send ack: checksum length");
	else if ( ! io_write_int(sess, fd, blocks->rem))
		ERRX1(sess, "io_write_int: send ack: remainder");
	else
		return 1;

	return 0;
}

/*
 * Read all of the checksums for a file's blocks.
 * Returns the set of blocks or NULL on failure.
 */
struct blkset *
blk_recv(struct sess *sess, int fd, const char *path)
{
	struct blkset	*s;
	int32_t		 i;
	size_t		 j;
	struct blk	*b;
	off_t		 offs = 0;

	if (NULL == (s = calloc(1, sizeof(struct blkset)))) {
		ERR(sess, "calloc");
		return NULL;
	}

	/*
	 * The block prologue consists of a few values that we'll need
	 * in reading the individual blocks for this file.
	 */

	if ( ! io_read_size(sess, fd, &s->blksz)) {
		ERRX1(sess, "io_read_size: block count");
		goto out;
	} else if ( ! io_read_size(sess, fd, &s->len)) {
		ERRX1(sess, "io_read_sisze: block length");
		goto out;
	} else if ( ! io_read_size(sess, fd, &s->csum)) {
		ERRX1(sess, "io_read_int: checksum length");
		goto out;
	} else if ( ! io_read_size(sess, fd, &s->rem)) {
		ERRX1(sess, "io_read_int: block remainder");
		goto out;
	} else if (s->rem && s->rem >= s->len) {
		ERRX(sess, "block remainder is "
			"greater than block size");
		goto out;
	}

	LOG3(sess, "%s: read block prologue: %zu blocks of "
		"%zu B, %zu B remainder, %zu B checksum", path,
		s->blksz, s->len, s->rem, s->csum);

	if (s->blksz) {
		s->blks = calloc(s->blksz, sizeof(struct blk));
		if (NULL == s->blks) {
			ERR(sess, "calloc");
			goto out;
		}
	}

	/* Read each block individually. */

	for (j = 0; j < s->blksz; j++) {
		b = &s->blks[j];
		if ( ! io_read_int(sess, fd, &i)) {
			ERRX1(sess, "io_read_int: fast checksum");
			goto out;
		}
		b->chksum_short = i;

		assert(s->csum <= sizeof(b->chksum_long));
		if ( ! io_read_buf(sess,
		    fd, b->chksum_long, s->csum)) {
			ERRX1(sess, "io_read_buf: slow checksum");
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

		LOG4(sess, "%s: read block %zu, length %zu B, "
			"checksum=0x%08x", path, b->idx, b->len,
			b->chksum_short);
	}

	s->size = offs;
	LOG3(sess, "%s: read blocks: %zu blocks, %jd B total "
		"blocked data", path, s->blksz, (intmax_t)s->size);
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
blk_send_ack(struct sess *sess, int fd,
	const struct blkset *blocks, size_t idx)
{
	size_t		 rem, len, blksz, nidx, csum;

	if ( ! io_read_size(sess, fd, &nidx))
		ERRX1(sess, "io_read_size: read ack");
	else if (idx != nidx)
		ERRX1(sess, "read ack: indices don't match");
	else if ( ! io_read_size(sess, fd, &blksz))
		ERRX1(sess, "io_read_size: read ack: block count");
	else if (blksz != blocks->blksz)
		ERRX1(sess, "read ack: block counts don't match");
	else if ( ! io_read_size(sess, fd, &len))
		ERRX1(sess, "io_read_size: read ack: block size");
	else if (len != blocks->len)
		ERRX1(sess, "read ack: block sizes don't match");
	else if ( ! io_read_size(sess, fd, &csum))
		ERRX1(sess, "io_read_size: read ack: checksum length");
	else if (csum != blocks->csum)
		ERRX1(sess, "read ack: checksum lengths don't match");
	else if ( ! io_read_size(sess, fd, &rem))
		ERRX1(sess, "io_read_size: read ack: remainder");
	else if (rem != blocks->rem)
		ERRX1(sess, "read ack: block remainders don't match");
	else
		return 1;

	return 0;
}

/*
 * The receiver now reads raw data and block indices from the sender,
 * and merges them into the temporary file.
 * Returns zero on failure, non-zero on success.
 */
int
blk_merge(struct sess *sess, int fd, int ffd,
	const struct blkset *block, int outfd, const char *path,
	const void *map, size_t mapsz)
{
	size_t		 sz, tok;
	int32_t		 rawtok;
	char		*buf = NULL;
	void		*pp;
	ssize_t		 ssz;
	int		 rc = 0;
	unsigned char	 md[MD4_DIGEST_LENGTH],
			 ourmd[MD4_DIGEST_LENGTH];
	off_t		 total = 0, fromcopy = 0, fromdown = 0;
	MD4_CTX		 ctx;

	MD4_Init(&ctx);

	rawtok = htole32(sess->seed);
	MD4_Update(&ctx, (unsigned char *)&rawtok, sizeof(int32_t));

	for (;;) {
		if ( ! io_read_int(sess, fd, &rawtok)) {
			ERRX1(sess, "io_read_int: data block size");
			goto out;
		} else if (0 == rawtok)
			break;

		if (rawtok > 0) {
			sz = rawtok;
			if (NULL == (pp = realloc(buf, sz))) {
				ERR(sess, "realloc");
				goto out;
			}
			buf = pp;
			if ( ! io_read_buf(sess, fd, buf, sz)) {
				ERRX1(sess, "io_read_int: data block");
				goto out;
			}

			if ((ssz = write(outfd, buf, sz)) < 0) {
				ERR(sess, "write: temporary file");
				goto out;
			} else if ((size_t)ssz != sz) {
				ERRX(sess, "write: short write");
				goto out;
			}

			fromdown += sz;
			total += sz;
			LOG4(sess, "%s: received %zd bytes, now %jd "
				"total", path, ssz, (intmax_t)total);

			MD4_Update(&ctx, buf, sz);
		} else {
			tok = -rawtok - 1;
			if (tok >= block->blksz) {
				ERRX(sess, "token not in block set");
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
				ERR(sess, "write: temporary file");
				goto out;
			} else if ((size_t)ssz != block->blks[tok].len) {
				ERRX(sess, "write: short write");
				goto out;
			}

			fromcopy += block->blks[tok].len;
			total += block->blks[tok].len;
			LOG4(sess, "%s: copied %zu bytes, now %jd "
				"total", path, block->blks[tok].len,
				(intmax_t)total);

			MD4_Update(&ctx,
				map + block->blks[tok].offs,
				block->blks[tok].len);
		}
	}

	/* Make sure our resulting MD4_ hashes match. */

	if ( ! io_read_buf(sess, fd, md, MD4_DIGEST_LENGTH)) {
		ERRX1(sess, "io_read_buf: data blocks hash");
		goto out;
	}

	MD4_Final(ourmd, &ctx);

	if (memcmp(md, ourmd, MD4_DIGEST_LENGTH)) {
		ERRX(sess, "file hash does not match");
		goto out;
	}

	LOG3(sess, "%s: merged %jd total bytes",
		path, (intmax_t)total);
	LOG3(sess, "%s: %.2f%% upload", path, 100.0 * fromdown / total);
	rc = 1;
out:
	free(buf);
	return rc;
}

/*
 * Transmit the metadata for set and blocks.
 * Return zero on failure, non-zero on success.
 */
int
blk_send(struct sess *sess, int fd,
	const struct blkset *p, const char *path)
{
	size_t	 i;
	const struct blk *b;

	if ( ! io_write_int(sess, fd, p->blksz)) {
		ERRX1(sess, "io_write_int: block count");
		return 0;
	} else if ( ! io_write_int(sess, fd, p->len)) {
		ERRX1(sess, "io_write_int: block length");
		return 0;
	} else if ( ! io_write_int(sess, fd, p->csum)) {
		ERRX1(sess, "io_write_int: checksum length");
		return 0;
	} else if ( ! io_write_int(sess, fd, p->rem)) {
		ERRX1(sess, "io_write_int: block remainder");
		return 0;
	}

	for (i = 0; i < p->blksz; i++) {
		b = &p->blks[i];
		if ( ! io_write_int(sess, fd, b->chksum_short)) {
			ERRX1(sess, "io_write_int: short checksum");
			return 0;
		}
		if ( ! io_write_buf(sess, fd, b->chksum_long, p->csum)) {
			ERRX1(sess, "io_write_int: long checksum");
			return 0;
		}
	}

	LOG3(sess, "%s: sent block prologue: %zu blocks of %zu B, "
		"%zu B remainder, %zu B checksum", path,
		p->blksz, p->len, p->rem, p->csum);
	return 1;
}

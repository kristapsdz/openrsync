/*
 * Copyright (c) 2019 Kristaps Dzonsons <kristaps@bsd.lv>
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

#include <assert.h>
#include COMPAT_ENDIAN_H
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

/* I/O failure in blk_find() */
#define	BLK_IOFAIL	((void *)-1)

struct	blkhash {
	const struct blk	*blk;
	TAILQ_ENTRY(blkhash)	 entries;
};

TAILQ_HEAD(blkhashq, blkhash);

/*
 * Table used by the sender for looking up blocks.
 * The blocks are those sent by the receiver; we're looking up using
 * hashes computed from our local file.
 */
struct	blktab {
	struct blkhashq	*q; /* entries in the hashtable */
	size_t		 qsz; /* size of the hashtable */
	struct blkhash	*blks; /* pre-allocated hashtable entries */
};

/*
 * This is the number of buckets in the hashtable.
 * Use the same that GPL rsync uses.
 * (It should be dynamic?)
 */
#define	BLKTAB_SZ	  65536

/*
 * Initialise an empty hashtable with BLKTAB_SZ entries in it.
 * Populate it for each file with blkhash_set.
 * When we've processed all files, call blkhash_free.
 * Returns NULL on allocation failure.
 */
struct blktab *
blkhash_alloc(void)
{
	struct blktab	*p;

	if ((p = calloc(1, sizeof(struct blktab))) == NULL) {
		ERR("calloc");
		return NULL;
	}
	p->qsz = BLKTAB_SZ;
	p->q = calloc(p->qsz, sizeof(struct blkhashq));
	if (p->q == NULL) {
		ERR("calloc");
		free(p);
		return NULL;
	}
	return p;
}

/*
 * Populate the hashtable with an incoming file's blocks.
 * This will clear out any existing hashed data.
 * Returns false on allocation failure, true otherwise.
 */
bool
blkhash_set(struct blktab *p, const struct blkset *bset)
{
	size_t	 i, /* current block index */
		 idx; /* queue position of hashed block */
	void	*pp; /* reallocation */

	if (bset == NULL || bset->blksz == 0)
		return true;

	/* Wipe clean the table. */

	for (i = 0; i < p->qsz; i++)
		TAILQ_INIT(&p->q[i]);

	/* bset->blks will be NULL in append mode. */

	if (bset->blks == NULL)
		return true;

	/* Fill in the hashtable. */

	if (bset->blksz == 0)
		return true;

	pp = reallocarray(p->blks, bset->blksz, sizeof(struct blkhash));
	if (pp == NULL) {
		ERR("reallocarray");
		return false;
	}
	p->blks = pp;

	for (i = 0; i < bset->blksz; i++) {
		p->blks[i].blk = &bset->blks[i];
		idx = bset->blks[i].chksum_short % p->qsz;
		assert(idx < p->qsz);
		TAILQ_INSERT_TAIL(&p->q[idx], &p->blks[i], entries);
	}

	return true;
}

/*
 * Free as allocated with blkhash_alloc().
 */
void
blkhash_free(struct blktab *p)
{
	free(p->blks);
	free(p->q);
	free(p);
}

/*
 * From our current position of "offs" in buffer "buf" of total size
 * "size", see if we can find a matching block in our list of blocks.
 * The "hint" refers to the block that *might* work.
 * Returns the blk or NULL if no matching block was found.
 */
static const struct blk *
blk_find(struct sess *sess, struct blkstat *st,
	const struct blkset *blks, const char *path, int recomp)
{
	unsigned char		 md[MD4_DIGEST_LENGTH];
	off_t			 remain, osz;
	uint32_t		 fhash;
	const char		*map;
	const struct blkhashq	*q;
	const struct blkhash	*ent;
	bool			 have_md = false;

	remain = st->mapsz - st->offs;
	assert(remain);
	osz = MINIMUM(remain, (off_t)blks->len);

	/*
	 * First, compute our fast hash the hard way (if we're
	 * reentering this function from a previous block match, or the
	 * first time) or from our existing s1 and s2 values.
	 */

	if (!recomp) {
		fhash = (st->s1 & 0xFFFF) | (st->s2 << 16);
	} else {
		if (!fmap_trap(st->map)) {
			WARNX("%s: file truncated while reading", path);
			return BLK_IOFAIL;
		}
		fhash = hash_fast(fmap_data(st->map, st->offs,
		    (size_t)osz), (size_t)osz);
		fmap_untrap(st->map);
		st->s1 = fhash & 0xFFFF;
		st->s2 = fhash >> 16;
	}

	/*
	 * Start with our match hint.
	 * This just runs the fast and slow check with the hint.
	 */

	if (st->hint < blks->blksz &&
	    fhash == blks->blks[st->hint].chksum_short &&
	    (size_t)osz == blks->blks[st->hint].len) {
		if (!fmap_trap(st->map)) {
			WARNX("%s: file truncated while reading", path);
			return BLK_IOFAIL;
		}
		hash_slow(fmap_data(st->map, st->offs, (size_t)osz),
		    (size_t)osz, md, sess);
		fmap_untrap(st->map);
		have_md = true;
		if (memcmp(md, blks->blks[st->hint].chksum_long,
		    blks->csum) == 0) {
			LOG4("%s: found matching hinted match: "
			    "position %jd, block %zu (position "
			    "%jd, size %zu)", path,
			    (intmax_t)st->offs,
			    blks->blks[st->hint].idx,
			    (intmax_t)blks->blks[st->hint].offs,
			    blks->blks[st->hint].len);
			return &blks->blks[st->hint];
		}
	}

	/*
	 * Look for the fast hash modulus in our hashtable, filter for
	 * those matching the full hash and length, then move to the
	 * slow hash.
	 * The slow hash is computed only once.
	 */

	q = &st->blktab->q[fhash % st->blktab->qsz];

	TAILQ_FOREACH(ent, q, entries) {
		if (fhash != ent->blk->chksum_short ||
		    (size_t)osz != ent->blk->len)
			continue;

		LOG4("%s: found matching fast match: "
		    "position %jd, block %zu (position %jd, size %zu)",
		    path, (intmax_t)st->offs, ent->blk->idx,
		    (intmax_t)ent->blk->offs, ent->blk->len);

		if (!have_md) {
			if (!fmap_trap(st->map)) {
				WARNX("%s: file truncated while "
				    "reading", path);
				return BLK_IOFAIL;
			}
			hash_slow(fmap_data(st->map, st->offs,
			    (size_t)osz), (size_t)osz, md, sess);
			fmap_untrap(st->map);
			have_md = true;
		}

		if (memcmp(md, ent->blk->chksum_long, blks->csum))
			continue;

		LOG4("%s: sender verifies slow match", path);
		return ent->blk;
	}

	/*
	 * Adjust our partial sums for the hashing.
	 * We first remove the first byte from the sum.
	 * We then, if we have space, add the first byte of the next
	 * block in the sequence.
	 */

	if (!fmap_trap(st->map)) {
		WARNX("%s: file truncated while reading", path);
		return BLK_IOFAIL;
	}
	map = fmap_data(st->map, st->offs, osz +
	    (osz >= remain ? 0 : 1));

	st->s1 -= map[0];
	st->s2 -= osz * map[0];

	if (osz < remain) {
		st->s1 += map[osz];
		st->s2 += st->s1;
	}
	fmap_untrap(st->map);

	return NULL;
}

/*
 * Given a local file "path" and the blocks created by a remote machine,
 * find out which blocks of our file they don't have and send them.
 * This function is reentrant: it must be called while there's still
 * data to send.
 */
bool
blk_match(struct sess *sess, const struct blkset *blks,
	const char *path, struct blkstat *st)
{
	off_t		  last, end = 0, sz;
	int32_t		  tok;
	size_t		  i;
	const struct blk *blk;

	/*
	 * If the file's empty or we don't have any blocks from the
	 * sender, then simply send the whole file.
	 * Otherwise, run the hash matching routine and send raw chunks
	 * and subsequent matching tokens.
	 */

	if (st->mapsz && blks->blksz) {
		if (sess->role->append) {
			assert((off_t)st->mapsz >= blks->size);
			st->offs = blks->size;
			last = st->offs;
			goto append;
		}
		/*
		 * Stop searching at the length of the file minus the
		 * size of the last block.  The reason for this being
		 * that we don't need to do an incremental hash within
		 * the last block---if it doesn't match, it doesn't
		 * match.
		 */

		end = st->mapsz + 1 - blks->blks[blks->blksz - 1].len;
		last = st->offs;

		for (i = 0; st->offs < end; st->offs++, i++) {
			blk = blk_find(sess, st, blks, path, i == 0);
			if (blk == NULL)
				continue;
			else if (blk == BLK_IOFAIL) /* FIXME: gross */
				return false;

			sz = st->offs - last;
			st->dirty += sz;
			st->total += sz;
			LOG4("%s: flushing %jd B before %zu B block %zu",
			    path, (intmax_t)sz,
			    blk->len, blk->idx);
			tok = (int32_t)-(blk->idx + 1);

			/*
			 * Write the data we have, then follow it with
			 * the tag of the block that matches.
			 */

			st->curpos = last;
			st->curlen = st->curpos + sz;
			st->curtok = tok;
			assert(st->curtok != 0);
			st->curst = sz ? BLKSTAT_DATA : BLKSTAT_TOK;
			st->total += blk->len;
			st->offs += blk->len;
			st->hint = blk->idx + 1;
			return true;
		}

		/* Emit remaining data and send terminator token. */

append:
		sz = st->mapsz - last;
		LOG4("%s: flushing remaining %jd B",
		    path, (intmax_t)sz);

		st->total += sz;
		st->dirty += sz;
		st->curpos = last;
		st->curlen = st->curpos + sz;
		st->curtok = 0;
		st->curst = sz ? BLKSTAT_DATA : BLKSTAT_TOK;
	} else {
		st->curpos = 0;
		st->curlen = st->mapsz;
		st->curtok = 0;
		st->curst = st->mapsz ? BLKSTAT_DATA : BLKSTAT_TOK;
		st->dirty = st->total = st->mapsz;
		LOG4("%s: flushing whole file %zu B",
		    path, st->mapsz);
	}

	return true;
}

/*
 * Buffer the message from sender to the receiver indicating that the
 * block set has been received.
 * Symmetrises blk_send_ack().
 */
void
blk_recv_ack(char buf[16], const struct blkset *blocks, int32_t idx)
{
	size_t	 pos = 0, sz;

	sz = sizeof(int32_t) + /* block count */
	    sizeof(int32_t) + /* block length */
	    sizeof(int32_t) + /* checksum length */
	    sizeof(int32_t); /* block remainder */
	assert(sz == 16);

	io_buffer_int(buf, &pos, sz, (int)blocks->blksz);
	io_buffer_int(buf, &pos, sz, (int)blocks->len);
	io_buffer_int(buf, &pos, sz, (int)blocks->csum);
	io_buffer_int(buf, &pos, sz, (int)blocks->rem);
	assert(pos == sz);
}

/*
 * Read all of the checksums for a file's blocks, storing the read state
 * in "state" as we go.
 * Returns the set of blocks or NULL on failure.
 * blk_recv() is designed to be re-entrant, so that we can collect
 * everything over a number of calls rather than blocking if we don't
 * have everything available just yet.
 */
struct blkset *
blk_recv(struct sess *sess, int fd, struct iobuf *buf, const char *path,
    struct blkset *s, size_t *blkidx, enum send_dl_state *state)
{
	int32_t		 i; /* temporary (conversion) */
	size_t		 j, /* temporary */
			 bufsz; /* temporary */
	struct blk	*b; /* current block being analysed */
	off_t		 offs = 0; /* current block offset in file */
	const bool	 first = (s == NULL); /* first time called */

	assert(*state == SDL_META || *state == SDL_BLOCKS);

	if (first && (s = calloc(1, sizeof(struct blkset))) == NULL) {
		ERR("calloc");
		return NULL;
	}

	if (first) {
		/*
		 * We'll make sure we have enough to read the metadata in the
		 * meta phase, and somewhere around ~64 blocks after that.  Each
		 * block is a 4-byte fast checksum and somewhere between 2 and
		 * 16 byte slow (MD4) checksum, so we're not necessarily
		 * allocating massive buffers for this...
		 *
		 * For !meta, we only enlarge the buffer on the first read.
		 */
		bufsz = 64 * (sizeof(int32_t) + 16);
		if (!iobuf_alloc(sess, buf, bufsz)) {
			ERRX1("iobuf_alloc");
			goto out;
		}
	}

	/*
	 * At metadata phase of reading.
	 * The block prologue consists of a few values that we'll need
	 * in reading the individual blocks for this file.
	 */

	if (*state == SDL_META) {
		if (iobuf_get_readsz(buf) < (4 * sizeof(int32_t))) {
			if (iobuf_seen_eof(buf)) {
				ERR("hangup awaiting block prologue");
				goto out;
			}
			return s;
		}

		if (!iobuf_read_size(buf, &s->blksz)) {
			ERRX1("iobuf_read_size");
			goto out;
		} else if (!iobuf_read_size(buf, &s->len)) {
			ERRX1("iobuf_read_size");
			goto out;
		} else if (!iobuf_read_size(buf, &s->csum)) {
			ERRX1("iobuf_read_size");
			goto out;
		} else if (!iobuf_read_size(buf, &s->rem)) {
			ERRX1("iobuf_read_size");
			goto out;
		} else if (s->rem && s->rem >= s->len) {
			ERRX("block remainder %zu is "
				"greater than block size %zu", s->rem, s->len);
			goto out;
		}

		LOG3("%s: read block prologue: %zu blocks of "
		    "%zu B, %zu B remainder, %zu B checksum", path,
		    s->blksz, s->len, s->rem, s->csum);

		*state = SDL_BLOCKS;
		*blkidx = 0;
	}

	assert(*state == SDL_BLOCKS);

	if (s->blksz && s->blks == NULL) {
		if (*sess->role->phase == 0 && sess->role->append) {
			if (s->rem > 0)
				offs = (s->blksz - 1) * s->len + s->rem;
			else
				offs = s->blksz * s->len;
			goto skipmap;
		}
		s->blks = calloc(s->blksz, sizeof(struct blk));
		if (s->blks == NULL) {
			ERR("calloc");
			goto out;
		}
	} else if (*blkidx != 0)
		offs = *blkidx * s->len;

	/* Read each block individually. */

	for (j = *blkidx; j < s->blksz; j++) {
		if (iobuf_get_readsz(buf) < sizeof(int32_t) + s->csum) {
			if (iobuf_seen_eof(buf)) {
				ERR("hangup awaiting block information");
				goto out;
			}
			break;
		}

		b = &s->blks[j];
		iobuf_read_int(buf, &i);
		b->chksum_short = i;

		assert(s->csum <= sizeof(b->chksum_long));
		iobuf_read_buf(buf, b->chksum_long, s->csum);

		/*
		 * If we're the last block, then we're assigned the
		 * remainder of the data.
		 */

		b->offs = offs;
		b->idx = j;
		b->len = (j == (s->blksz - 1) && s->rem) ?
			s->rem : s->len;
		assert(b->len != 0);
		offs += b->len;

		LOG4("%s: read block %zu, length %zu B",
		    path, b->idx, b->len);
	}

	/*
	 * If we still haven't read the full set, just return without a
	 * state transition.
	 */

	*blkidx = j;
	if (j < s->blksz)
		return s;

skipmap:
	*state = SDL_DONE;
	s->size = offs;
	LOG3("%s: read blocks: %zu blocks, %jd B total blocked data",
	    path, s->blksz, (intmax_t)s->size);
	return s;

out:
	free(s->blks);
	free(s);
	return NULL;
}

/*
 * Symmetrise blk_recv_ack(), except w/o the leading identifier.
 * Return zero on failure, non-zero on success.
 */
bool
blk_send_ack(struct sess *sess, int fd, struct blkset *p)
{
	char	 buf[16];
	size_t	 pos = 0, sz;

	/* Put the entire send routine into a buffer. */

	sz = sizeof(int32_t) + /* block count */
	    sizeof(int32_t) + /* block length */
	    sizeof(int32_t) + /* checksum length */
	    sizeof(int32_t); /* block remainder */
	assert(sz <= sizeof(buf));

	if (!io_read_buf(sess, fd, buf, sz)) {
		ERRX1("io_read_buf");
		return false;
	}

	if (!io_unbuffer_size(buf, &pos, sz, &p->blksz))
		ERRX1("io_unbuffer_size");
	else if (!io_unbuffer_size(buf, &pos, sz, &p->len))
		ERRX1("io_unbuffer_size");
	else if (!io_unbuffer_size(buf, &pos, sz, &p->csum))
		ERRX1("io_unbuffer_size");
	else if (!io_unbuffer_size(buf, &pos, sz, &p->rem))
		ERRX1("io_unbuffer_size");
	else if (p->len && p->rem >= p->len)
		ERRX1("non-zero length is less than remainder");
	else if ((int)p->csum < 0 || p->csum > 16)
		ERRX1("inappropriate checksum length");
	else
		return true;

	return false;
}

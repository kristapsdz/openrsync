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

#include <sys/types.h>

#include <assert.h>
#include COMPAT_ENDIAN_H
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include "extern.h"

/*
 * A fast 32-bit hash.
 * Described in Tridgell's "Efficient Algorithms for Sorting and
 * Synchronization" thesis and the "Rolling checksum" document.
 */
uint32_t
hash_fast(const void *buf, size_t len)
{
	size_t			 i = 0;
	uint32_t		 a = 0, /* part of a(k, l) */
				 b = 0; /* b(k, l) */
	const signed char	*dat = buf;

	if (len > 4)
		for ( ; i < len - 4; i += 4) {
			b += 4 * (a + dat[i]) +
			    3 * dat[i + 1] +
			    2 * dat[i + 2] +
			    dat[i + 3];
			a += dat[i + 0] +
			    dat[i + 1] +
			    dat[i + 2] +
			    dat[i + 3];
		}

	for ( ; i < len; i++) {
		a += dat[i];
		b += a;
	}

	/* s(k, l) = (eps % M) + 2^16 b(k, l) % M */

	return (a & 0xffff) + (b << 16);
}

/*
 * Slow MD4-based hash with trailing seed.
 */
void
hash_slow(const void *buf, size_t len,
	unsigned char *md, const struct sess *sess)
{
	MD4_CTX		 ctx;
	int32_t		 seed = htole32(sess->seed);

	MD4_Init(&ctx);
	MD4_Update(&ctx, buf, len);
	MD4_Update(&ctx, (unsigned char *)&seed, sizeof(int32_t));
	MD4_Final(md, &ctx);
}

/*
 * Hash an entire file.
 * This is similar to hash_slow() except the seed is hashed at the end
 * of the sequence, not the beginning.
 */
void
hash_file_start(MD4_CTX *ctx, const struct sess *sess)
{
	int32_t		 seed = htole32(sess->seed);

	MD4_Init(ctx);
	MD4_Update(ctx, (unsigned char *)&seed, sizeof(int32_t));
}

void
hash_file_buf(MD4_CTX *ctx, const void *buf, size_t len)
{
	MD4_Update(ctx, buf, len);
}
void
hash_file_final(MD4_CTX *ctx, unsigned char *md)
{
	MD4_Final(md, ctx);
}

static void
hash_fmap_chunks(const struct fmap *map, size_t mapsz, MD4_CTX *ctx)
{
	off_t		 offset = 0;
	size_t		 cursz;
	const void	*data;

	while (mapsz != 0) {
		cursz = MINIMUM(HASH_LARGE_CHUNK_SIZE, mapsz);
		data = fmap_data(map, offset, cursz);
		MD4_Update(ctx, data, cursz);
		offset += cursz;
		mapsz -= cursz;
	}
}

/* FIXME: mapsz is in fmap */
bool
hash_fmap(const char *path, const struct fmap *map, size_t mapsz,
    unsigned char *md, const struct sess *sess)
{
	MD4_CTX	 ctx;
	int32_t	 seed;

	MD4_Init(&ctx);
	if (sess != NULL) {
		seed = htole32(sess->seed);
		MD4_Update(&ctx, &seed, sizeof(int32_t));
	}

	if (!fmap_trap(map)) {
		ERRX("%s: file truncated while hashing", path);
		return false;
	}

	hash_fmap_chunks(map, mapsz, &ctx);
	fmap_untrap(map);
	MD4_Final(md, &ctx);
	return true;
}

/*
 * Hash an entire file.
 * This is similar to hash_slow() except the seed is hashed at the end
 * of the sequence, not the beginning.
 * Note that if sess is NULL then the seed is not included (this
 * feature is used to compute seedless hashes for --checksum).
 */
static void
hash_file(const void *buf, size_t len, unsigned char *md,
    const struct sess *sess)
{
	MD4_CTX	 ctx;
	int32_t	 seed;

	MD4_Init(&ctx);
	if (sess != NULL) {
		seed = htole32(sess->seed);
		MD4_Update(&ctx, &seed, sizeof(int32_t));
	}
	if (len > 0)
		MD4_Update(&ctx, buf, len);
	MD4_Final(md, &ctx);
}

/*
 * This function is primarily used to compute whole-file seedless
 * checksums for the --checksum option, for contexts in which the file
 * is not already open nor mapped.
 */
bool
hash_file_by_path(int rootfd, const char *path, size_t len,
    unsigned char *md)
{
	int		 fd, save;
	struct fmap	*map;
	bool		 rc;

	if (len == 0) {
		hash_file(NULL, len, md, NULL);
		return true;
	}

	fd = openat(rootfd, path, O_RDONLY | O_NOFOLLOW);
	if (fd == -1)
		return false;

	map = fmap_open(path, fd, len);
	if (map == NULL) {
		save = errno;
		close(fd);
		errno = save;
		return false;
	}

	rc = hash_fmap(path, map, len, md, NULL);
	save = errno;

	fmap_close(map);
	close(fd);

	errno = save;
	return rc;
}

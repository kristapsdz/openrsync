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
#include <sys/types.h>

#include <assert.h>
#include <md5.h>
#include <stdlib.h>

#include "extern.h"

/*
 * A fast 32-bit hash.
 * Described in Tridgell's "Efficient Algorithms for Sorting and
 * Synchronization" thesis.
 */
uint32_t
hash_fast(const void *buf, size_t len)
{
	size_t 	 	 i = 0;
	uint32_t 	 s1 = 0, s2 = 0;
	const signed char *dat = buf;

	if (len > 4)
		for ( ; i < len - 4; i += 4) {
			s2 += 4 * (s1 + dat[i]) + 
			      3 * dat[i + 1] + 
			      2 * dat[i + 2] + 
			          dat[i + 3];
			s1 += dat[i + 0] + 
			      dat[i + 1] + 
			      dat[i + 2] + 
			      dat[i + 3];
		}

	for ( ; i < len; i++) {
		s1 += dat[i]; 
		s2 += s1;
	}

	return (s1 & 0xffff) + (s2 << 16);
}

/*
 * Slow MD5-based hash with leading seed.
 */
void
hash_slow(const void *buf, size_t len, 
	unsigned char *md, const struct sess *sess)
{
	MD5_CTX		 ctx;
	int32_t		 seed;

	/*
	 * This seems to be optional, as passing a zero value as the
	 * seed will create the same hash value each time.
	 * However, it's harmless to keep it in here.
	 */

	MD5Init(&ctx);
	MD5Update(&ctx, buf, len);
	seed = htole32(sess->seed);
	MD5Update(&ctx, (unsigned char *)&seed, sizeof(int32_t));
	MD5Final(md, &ctx);
}

/*
 * Hash an entire file (sized buffer).
 */
void
hash_file(const void *buf, off_t len, unsigned char *md)
{
	MD5_CTX		 ctx;

	MD5Init(&ctx);
	MD5Update(&ctx, buf, len);
	MD5Final(md, &ctx);
}

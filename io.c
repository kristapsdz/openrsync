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
#include <sys/stat.h>

#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

int
io_read_check(struct sess *sess, int fd)
{
	struct pollfd	pfd;

	pfd.fd = fd;
	pfd.events = POLLIN;

	if (poll(&pfd, 1, 0) < 0) {
		ERR(sess, "poll");
		return -1;
	}
	return pfd.revents & POLLIN;
}

/*
 * Write buffer to non-blocking descriptor.
 * Returns zero on failure, non-zero on success (zero or more bytes).
 */
int
io_write_nonblocking(struct sess *sess,
	int fd, const void *buf, size_t bsz, size_t *sz)
{
	struct pollfd	pfd;
	ssize_t		wsz;

	*sz = 0;

	if (0 == bsz)
		return 1;

	pfd.fd = fd;
	pfd.events = POLLOUT;

	if (poll(&pfd, 1, INFTIM) < 0) {
		ERR(sess, "poll");
		return 0;
	}
	if ((pfd.revents & (POLLERR|POLLNVAL))) {
		ERRX(sess, "poll: bad fd");
		return 0;
	} else if ((pfd.revents & POLLHUP)) {
		ERRX(sess, "poll: hangup");
		return 0;
	} else if ( ! (pfd.revents & POLLOUT)) {
		ERRX(sess, "poll: unknown event");
		return 0;
	}

	if ((wsz = write(fd, buf, bsz)) < 0) {
		ERR(sess, "write");
		return 0;
	}

	*sz = wsz;
	return 1;
}

/*
 * Blocking write of the full size of the buffer.
 * Returns 0 on failure, non-zero on success (all bytes written).
 */
int
io_write_blocking(struct sess *sess,
	int fd, const void *buf, size_t sz)
{
	size_t		wsz;
	int		c;

	while (sz > 0) {
		c = io_write_nonblocking(sess, fd, buf, sz, &wsz);
		if ( ! c) {
			ERRX1(sess, "io_write_nonblocking");
			return 0;
		} else if (0 == wsz) {
			ERRX(sess, "io_write_nonblocking: short write");
			return 0;
		}
		buf += wsz;
		sz -= wsz;
	}

	return 1;
}

/*
 * Write "buf" of size "sz" to non-blocking descriptor.
 * Returns zero on failure, non-zero on success (all bytes written to
 * the descriptor).
 */
int
io_write_buf(struct sess *sess, int fd, const void *buf, size_t sz)
{
	int32_t	 tag, tagbuf;
	size_t	 wsz;

	if ( ! sess->mplex_writes)
		return io_write_blocking(sess, fd, buf, sz);

	while (sz > 0) {
		wsz = sz & 0xFFFFFF;
		tag = (7 << 24) + wsz;
		tagbuf = htole32(tag);
		if ( ! io_write_blocking(sess, fd, &tagbuf, sizeof(tagbuf))) {
			ERRX1(sess, "io_write_blocking");
			return 0;
		}
		if ( ! io_write_blocking(sess, fd, buf, wsz)) {
			ERRX1(sess, "io_write_blocking");
			return 0;
		}
		sz -= wsz;
		buf += wsz;
	}

	return 1;
}

/*
 * Write "line" (NUL-terminated) followed by a newline.
 * Returns zero on failure, non-zero on succcess.
 */
int
io_write_line(struct sess *sess, int fd, const char *line)
{

	if ( ! io_write_buf(sess, fd, line, strlen(line)))
		ERRX1(sess, "io_write_buf");
	else if ( ! io_write_byte(sess, fd, '\n'))
		ERRX1(sess, "io_write_byte");
	else
		return 1;

	return 0;
}

/*
 * Read buffer from non-blocking descriptor.
 * Returns zero on failure, non-zero on success (zero or more bytes).
 */
int
io_read_nonblocking(struct sess *sess,
	int fd, void *buf, size_t bsz, size_t *sz)
{
	struct pollfd	pfd;
	ssize_t		rsz;

	*sz = 0;

	if (0 == bsz)
		return 1;

	pfd.fd = fd;
	pfd.events = POLLIN;

	if (poll(&pfd, 1, INFTIM) < 0) {
		ERR(sess, "poll");
		return 0;
	}
	if ((pfd.revents & (POLLERR|POLLNVAL))) {
		ERRX(sess, "poll: bad fd");
		return 0;
	} else if ( ! (pfd.revents & (POLLIN|POLLHUP))) {
		ERRX(sess, "poll: unknown event");
		return 0;
	}

	if ((rsz = read(fd, buf, bsz)) < 0) {
		ERR(sess, "read");
		return 0;
	}

	*sz = rsz;
	return 1;
}

/*
 * Blocking read of the full size of the buffer.
 * Returns 0 on failure, non-zero on success (all bytes read).
 */
int
io_read_blocking(struct sess *sess,
	int fd, void *buf, size_t sz)
{
	size_t	 rsz;
	int	 c;

	while (sz > 0) {
		c = io_read_nonblocking(sess, fd, buf, sz, &rsz);
		if ( ! c) {
			ERRX1(sess, "io_read_nonblocking");
			return 0;
		} else if (0 == rsz) {
			ERRX(sess, "io_read_nonblocking: short read");
			return 0;
		}
		buf += rsz;
		sz -= rsz;
	}

	return 1;
}

/*
 * Read buffer from non-blocking descriptor, possibly in multiplex read
 * mode.
 * Returns zero on failure, non-zero on success (all bytes read from
 * the descriptor).
 */
int
io_read_buf(struct sess *sess, int fd, void *buf, size_t sz)
{
	char	 mpbuf[1024];
	int32_t	 tagbuf, tag;
	size_t	 rsz;

	/* If we're not multiplexing, read directly. */

	if ( ! sess->mplex_reads) {
		assert(0 == sess->mplex_read_remain);
		return io_read_blocking(sess, fd, buf, sz);
	}

	while (sz > 0) {
		/*
		 * First, check to see if we have any regular data
		 * hanging around waiting to be read.
		 * If so, read the lesser of that data and whatever
		 * amount we currently want.
		 */

		if (sess->mplex_read_remain) {
			rsz = sess->mplex_read_remain < sz ?
				sess->mplex_read_remain : sz;
			if ( ! io_read_blocking(sess, fd, buf, rsz)) {
				ERRX1(sess, "io_read_blocking: "
					"multiplexed normal data");
				return 0;
			}
			sz -= rsz;
			sess->mplex_read_remain -= rsz;
			buf += rsz;
			continue;
		}

		/*
		 * We're multiplexing.
		 * First, read the 4-byte multiplex tag.
		 * The first byte is the tag identifier (7 for normal
		 * data, !7 for out-of-band data), the last three are
		 * for the remaining data size.
		 */

		assert(0 == sess->mplex_read_remain);
		if ( ! io_read_blocking(sess, fd, &tagbuf, sizeof(tagbuf))) {
			ERRX1(sess, "io_read_blocking: "
				"multiplex tag identifier");
			return 0;
		}
		tag = le32toh(tagbuf);
		sess->mplex_read_remain = tag & 0xFFFFFF;
		tag >>= 24;
		if (7 == tag)
			continue;
		tag -= 7;

		if (sess->mplex_read_remain > sizeof(mpbuf)) {
			ERRX(sess, "multiplex buffer overflow");
			return 0;
		} else if (0 == sess->mplex_read_remain)
			continue;

		if ( ! io_read_blocking(sess, fd,
		    mpbuf, sess->mplex_read_remain)) {
			ERRX1(sess, "io_read_blocking: "
				"multiplexed out-of-band data");
			return 0;
		}
		if ('\n' == mpbuf[sess->mplex_read_remain - 1])
			mpbuf[--sess->mplex_read_remain] = '\0';

		/* The tag seems to indicate severity...? */

		switch (tag) {
		case 3:
			LOG2(sess, "server (debug): %.*s",
				(int)sess->mplex_read_remain, mpbuf);
			break;
		case 2:
			LOG1(sess, "server (info): %.*s",
				(int)sess->mplex_read_remain, mpbuf);
			break;
		case 1:
			WARNX(sess, "server (error): %.*s",
				(int)sess->mplex_read_remain, mpbuf);
			break;
		default:
			LOG3(sess, "server (unknown channel): %.*s",
				(int)sess->mplex_read_remain, mpbuf);
			break;
		}

		sess->mplex_read_remain = 0;
	}

	return 1;
}

int
io_write_long(struct sess *sess, int fd, int64_t val)
{
	int64_t	nv;

	/* Short-circuit: send as an integer if possible. */

	if (val <= INT32_MAX && val >= 0)
		return io_write_int(sess, fd, (int32_t)val);

	/* Otherwise, pad with max integer, then send 64-bit. */

	nv = htole64(val);

	if ( ! io_write_int(sess, fd, INT32_MAX))
		ERRX(sess, "io_write_int");
	else if ( ! io_write_buf(sess, fd, &nv, sizeof(int64_t)))
		ERRX(sess, "io_write_buf");
	else
		return 1;

	return 0;
}

int
io_write_int(struct sess *sess, int fd, int32_t val)
{
	int32_t	nv;

	nv = htole32(val);

	if ( ! io_write_buf(sess, fd, &nv, sizeof(int32_t))) {
		ERRX(sess, "io_write_buf");
		return 0;
	}
	return 1;
}

int
io_read_long(struct sess *sess, int fd, int64_t *val)
{
	int64_t	oval;
	int32_t sval;

	/* Start with the short-circuit: read as an int. */

	if ( ! io_read_int(sess, fd, &sval)) {
		ERRX(sess, "io_read_int");
		return 0;
	} else if (INT32_MAX != sval) {
		*val = sval;
		return 1;
	}

	/* If the int is maximal, read as 64 bits. */

	if ( ! io_read_buf(sess, fd, &oval, sizeof(int64_t))) {
		ERRX(sess, "io_read_buf");
		return 0;
	}

	*val = le64toh(oval);
	return 1;
}

/*
 * One thing we often need to do is read a size_t.
 * These are transmitted as int32_t, so make sure that the value
 * transmitted is not out of range.
 * FIXME: I assume that size_t can handle int32_t's max.
 */
int
io_read_size(struct sess *sess, int fd, size_t *val)
{
	int32_t	oval;

	if ( ! io_read_int(sess, fd, &oval)) {
		ERRX(sess, "io_read_int");
		return 0;
	} else if (oval < 0) {
		ERRX(sess, "io_read_size: negative value");
		return 0;
	}

	*val = oval;
	return 1;
}

int
io_read_int(struct sess *sess, int fd, int32_t *val)
{
	int32_t	oval;

	if ( ! io_read_buf(sess, fd, &oval, sizeof(int32_t))) {
		ERRX(sess, "io_read_buf");
		return 0;
	}

	*val = le32toh(oval);
	return 1;
}

int
io_read_byte(struct sess *sess, int fd, uint8_t *val)
{

	if ( ! io_read_buf(sess, fd, val, sizeof(uint8_t))) {
		ERRX(sess, "io_read_buf");
		return 0;
	}
	return 1;
}

int
io_write_byte(struct sess *sess, int fd, uint8_t val)
{

	if ( ! io_write_buf(sess, fd, &val, sizeof(uint8_t))) {
		ERRX(sess, "io_write_buf");
		return 0;
	}
	return 1;
}


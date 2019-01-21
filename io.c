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
#include <sys/socket.h>
#include <sys/stat.h>

#include <endian.h>
#include <errno.h>
#include <inttypes.h> /* debugging */
#include <poll.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

/*
 * Write buffer to non-blocking descriptor.
 * Returns zero on failure, non-zero on success (all bytes written to
 * the descriptor).
 */
int
io_write_buf(struct sess *sess, int fd, const void *buf, size_t sz)
{
	struct pollfd	pfd;
	size_t		bsz = sz;
	ssize_t		wsz;

	pfd.fd = fd;
	pfd.events = POLLOUT;

	while (bsz > 0) {
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
		} else if (0 == wsz) {
			ERRX(sess, "write: short write");
			return 0;
		}
		buf += wsz;
		bsz -= wsz;
	}

	return 1;
}

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
io_read_buf_nonblock(struct sess *sess, 
	int fd, void *buf, size_t bsz, size_t *sz)
{
	struct pollfd	pfd;
	ssize_t		rsz;

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
static int
io_read_block(struct sess *sess, int fd, void *buf, size_t sz)
{
	size_t	 bsz = sz, rsz;
	int	 c;

	while (bsz > 0) {
		c = io_read_buf_nonblock(sess, fd, buf, bsz, &rsz);
		if ( ! c) {
			ERRX1(sess, "io_read_buf_nonblock");
			return 0;
		}else if (0 == rsz) {
			ERRX(sess, "io_read_buf_nonblock: short read");
			return 0;
		}
		buf += rsz;
		bsz -= rsz;
	}

	return 1;
}

/*
 * Read buffer from non-blocking descriptor.
 * Returns zero on failure, non-zero on success (all bytes read from
 * the descriptor).
 */
int
io_read_buf(struct sess *sess, int fd, void *buf, size_t sz)
{
	return io_read_block(sess, fd, buf, sz);
#if 0
	char	 mplexbuf[1024];
	int32_t	 tagbuf, tag;
	size_t	 rsz, rem;

	if (0 == sz)
		return 1;

	if ( ! opts->multiplex_reads) 
		return io_read_block(opts, fd, buf, sz);

	while (sz > 0) {
		LOG1(opts, "reading multiplex tag");
		if ( ! io_read_block(opts, fd, &tagbuf, sizeof(tagbuf))) {
			ERRX1(opts, "io_read_block: multiplex tag");
			return 0;
		}
		tag = letoh32(tagbuf);
		rem = tag & 0xFFFFFF;
		tag >>= 24;
		LOG1(opts, "multiplex tag: %" PRId32, tag);
		if (7 == tag) {
			while (rem > 0) {
				rsz = rem > sz ? sz : rem;
				if ( ! io_read_block(opts, fd, buf, rsz)) {
					ERRX1(opts, "io_read_block: multiplexed data");
					return 0;
				}
				sz -= rsz;
				buf += rsz;
				continue;
			}
		}
		tag -= 7;
		if (rem >= sizeof(mplexbuf)) {
			ERRX(opts, "multiplex buffer overflow");
			return 0;
		}
		if ( ! io_read_block(opts, fd, mplexbuf, rem)) {
			ERRX1(opts, "io_read_block: multiplexed subchannel");
			return 0;
		}
		if ('\n' == mplexbuf[rem - 1])
			mplexbuf[--rem] = '\0';
		LOG1(opts, "multiplexed: %.*s", (int)rem, mplexbuf);
	}

	return 1;
#endif
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

	*val = letoh64(oval);
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

	*val = letoh32(oval);
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

/*
 * Waits for a connection to complete.
 * Unlike other functions, this doesn't just return true/false.
 * If it manages to connect, it returns >1.
 * If it fails to connect because the host cannot be found or the
 * connection was terminaed, it returns 0.
 * If it fails because of non-endpoint-related errors, <0.
 */
int
io_connect_wait(struct sess *sess, int fd)
{
	struct pollfd	pfd[1];
	int 		er = 0;
	socklen_t 	len = sizeof(int);

	pfd[0].fd = fd;
	pfd[0].events = POLLOUT;

	if (-1 == poll(pfd, 1, INFTIM)) {
		ERR(sess, "poll");
		return -1;
	}

	if (-1 == getsockopt(fd, SOL_SOCKET, SO_ERROR, &er, &len)) {
		ERR(sess, "getsockopt");
		return -1;
	} else if (er != 0) {
		if (ECONNREFUSED == er || EHOSTUNREACH == er) {
			return 0;
		}
		errno = er;
		ERR(sess, "connect");
		return -1;
	}

	return 1;
}


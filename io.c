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

#include <endian.h>
#include <poll.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#include "extern.h"

/*
 * Write buffer to non-blocking descriptor.
 * Returns zero on failure, non-zero on success (all bytes written to
 * the descriptor).
 */
int
io_write_buf(const struct opts *opts, 
	int fd, const void *buf, size_t sz)
{
	struct pollfd	pfd;
	size_t		bsz = sz;
	ssize_t		wsz;

	pfd.fd = fd;
	pfd.events = POLLOUT;

	while (bsz > 0) {
		if (poll(&pfd, 1, INFTIM) < 0) {
			ERR(opts, "poll");
			return 0;
		}
		if ((pfd.revents & (POLLERR|POLLNVAL))) {
			ERRX(opts, "poll: bad fd");
			return 0;
		} else if ((pfd.revents & POLLHUP)) {
			ERRX(opts, "poll: hangup");
			return 0;
		} else if ( ! (pfd.revents & POLLOUT)) {
			ERRX(opts, "poll: unknown event");
			return 0;
		}

		if ((wsz = write(fd, buf, bsz)) < 0) {
			ERR(opts, "write");
			return 0;
		} else if (0 == wsz) {
			ERRX(opts, "write: short write");
			return 0;
		}
		buf += wsz;
		bsz -= wsz;
	}

	return 1;
}

/*
 * Read buffer from non-blocking descriptor.
 * Returns zero on failure, non-zero on success (all bytes read from
 * the descriptor).
 */
int
io_read_buf(const struct opts *opts, 
	int fd, void *buf, size_t sz)
{
	struct pollfd	pfd;
	size_t		bsz = sz;
	ssize_t		rsz;

	pfd.fd = fd;
	pfd.events = POLLIN;

	while (bsz > 0) {
		if (poll(&pfd, 1, INFTIM) < 0) {
			ERR(opts, "poll");
			return 0;
		}
		if ((pfd.revents & (POLLERR|POLLNVAL))) {
			ERRX(opts, "poll: bad fd");
			return 0;
		} else if ( ! (pfd.revents & (POLLIN|POLLHUP))) {
			ERRX(opts, "poll: unknown event");
			return 0;
		}

		if ((rsz = read(fd, buf, bsz)) < 0) {
			ERR(opts, "read");
			return 0;
		} else if (0 == rsz) {
			ERRX(opts, "read: short read");
			return 0;
		}
		buf += rsz;
		bsz -= rsz;
	}

	return 1;
}

int
io_write_long(const struct opts *opts, int fd, int64_t val)
{
	int64_t	nv;

	/* Short-circuit: send as an integer if possible. */

	if (val <= INT32_MAX && val >= 0)
		return io_write_int(opts, fd, (int32_t)val);

	/* Otherwise, pad with max integer, then send 64-bit. */

	nv = htole64(val);

	if ( ! io_write_int(opts, fd, INT32_MAX))
		ERRX(opts, "io_write_int");
	else if ( ! io_write_buf(opts, fd, &nv, sizeof(int64_t)))
		ERRX(opts, "io_write_buf");
	else
		return 1;

	return 0;
}

int
io_write_int(const struct opts *opts, int fd, int32_t val)
{
	int32_t	nv;

	nv = htole32(val);

	if ( ! io_write_buf(opts, fd, &nv, sizeof(int32_t))) {
		ERRX(opts, "io_write_buf");
		return 0;
	}
	return 1;
}

int
io_read_long(const struct opts *opts, int fd, int64_t *val)
{
	int64_t	oval;
	int32_t sval;

	/* Start with the short-circuit: read as an int. */

	if ( ! io_read_int(opts, fd, &sval)) {
		ERRX(opts, "io_read_int");
		return 0;
	} else if (INT32_MAX != sval) {
		*val = sval;
		return 1;
	}

	/* If the int is maximal, read as 64 bits. */

	if ( ! io_read_buf(opts, fd, &oval, sizeof(int64_t))) {
		ERRX(opts, "io_read_buf");
		return 0;
	}

	*val = letoh64(oval);
	return 1;
}

int
io_read_int(const struct opts *opts, int fd, int32_t *val)
{
	int32_t	oval;

	if ( ! io_read_buf(opts, fd, &oval, sizeof(int32_t))) {
		ERRX(opts, "io_read_buf");
		return 0;
	}

	*val = letoh32(oval);
	return 1;
}

int
io_read_byte(const struct opts *opts, int fd, uint8_t *val)
{

	if ( ! io_read_buf(opts, fd, val, sizeof(uint8_t))) {
		ERRX(opts, "io_read_buf");
		return 0;
	}
	return 1;
}

int
io_write_byte(const struct opts *opts, int fd, uint8_t val)
{

	if ( ! io_write_buf(opts, fd, &val, sizeof(uint8_t))) {
		ERRX(opts, "io_write_buf");
		return 0;
	}
	return 1;
}

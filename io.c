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

#include <sys/ioctl.h>
#include <sys/param.h> /* roundup */
#include <sys/stat.h>
#include <sys/uio.h> /* iovec */

#include <assert.h>
#include COMPAT_ENDIAN_H
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

/*
 * struct iobuf repack and allocation thresholds.
 */
#define IOBUF_MIN_REPACK	(1024 * 4)
#define IOBUF_MAX_REPACK	(1024 * 128)
#define IOBUF_MIN_ALLOC		(1024 * 128)

/*
 * A non-blocking check to see whether there's POLLIN data in fd.
 * Returns <0 on failure, 0 if there's no data, >0 if there is (or
 * multiplexed data remains).
 */
int
io_read_check(const struct sess *sess, int fd)
{
	struct pollfd	pfd;

	if (sess->mplex_read_remain)
		return 1;

	pfd.fd = fd;
	pfd.events = POLLIN;

	if (poll(&pfd, 1, 0) == -1) {
		ERR("poll");
		return -1;
	}
	return (pfd.revents & POLLIN);
}

/*
 * Close out the read-side of the pipe.  This procedure is most
 * important for client side, to make sure that we're not losing any log
 * messages that the server tries to send on its way out.  The server
 * could also have multiplexed reads, though.
 * Returns true if we can cleanly close the pipe, false if we cannot.
 */
bool
io_read_close(struct sess *sess, int fd)
{
	struct pollfd	 pfd;
	int		 nbrecv, /* FIONREAD result */
			 rc; /* temporary return code */
	bool		 hup = false;

	pfd.fd = fd;
	pfd.events = POLLIN;

	while (!hup) {
		rc = poll(&pfd, 1, INFTIM);
		if (rc == -1) {
			if (errno == EINTR)
				continue;
			ERR("poll");
			break;
		}

		/*
		 * FIONREAD == 0 on POLLIN to check for EOF of a socket,
		 * instead of relying on a non-portable POLLRDHUP or
		 * whatnot.
		 */

		if ((pfd.revents & POLLIN) == 0)
			nbrecv = -1;
		else if (ioctl(fd, FIONREAD, &nbrecv) == -1)
			break;

		if (nbrecv == 0 || (pfd.revents & POLLHUP)) {
			hup = 1;

			/*
			 * We'll give the below flush a chance to push
			 * anything out of the pipeline, then we'll
			 * terminate rather than poll() again.
			 */
			if (nbrecv <= 0)
				break;
		}

		/*
		 * Flush out anything remaining in the pipe.  If they
		 * were log messages, that's not necessarily a problem;
		 * we'll write those out to make sure they don't get
		 * lost.  If it contained actual data, we seem to have
		 * violated the protocol somewhere.
		 *
		 * We'll keep going as long as we're only getting
		 * out-of-band messages.
		 */

		if (!io_read_flush(sess, fd) || sess->mplex_read_remain) {
			/* Force an error for both of these cases. */
			hup = 0;
			break;
		}

		if (pfd.revents & (POLLERR | POLLNVAL)) {
			ERRX("socket error, poll=%x", pfd.revents);
			hup = false;
			break;
		}
	}

	close(fd);
	return hup;
}

/*
 * Write buffer to non-blocking descriptor.
 * Optionally allow errors to be suppressed in case we're called in a
 * logging path.
 * Returns false on failure, true on success (zero or more bytes).
 * On success, fills in "sz" with the amount written.
 */
static bool
io_write_nonblocking(int fd, const void *buf, size_t bsz, size_t *sz,
    bool raise_errors)
{
	struct pollfd	pfd; /* pollfds */
	ssize_t		wsz; /* size written */
	int		c; /* poll retval */

	*sz = 0;

	if (bsz == 0)
		return true;

	pfd.fd = fd;
	pfd.events = POLLOUT;

	/* Poll and check for all possible errors. */

	if ((c = poll(&pfd, 1, poll_timeout)) == -1) {
		if (raise_errors)
			ERR("poll");
		return false;
	} else if (c == 0) {
		if (raise_errors)
			ERRX("poll: timeout");
		return false;
	} else if ((pfd.revents & (POLLERR|POLLNVAL))) {
		if (raise_errors)
			ERRX("poll: bad fd");
		return false;
	} else if ((pfd.revents & POLLHUP)) {
		if (raise_errors)
			ERRX("poll: hangup");
		return false;
	} else if (!(pfd.revents & POLLOUT)) {
		if (raise_errors)
			ERRX("poll: unknown event");
		return false;
	}

	/* Now the non-blocking write. */

	if ((wsz = write(fd, buf, bsz)) == -1) {
		if (raise_errors)
			ERR("write");
		return false;
	}

	*sz = wsz;
	return true;
}

/*
 * Blocking write of the full size of the buffer.
 * Optionally allow errors to be suppressed in case we're called in a
 * logging path.
 * Returns false on failure, true on success (all bytes written).
 */
static bool
io_write_blocking_impl(int fd, const void *buf, size_t sz, bool raise_errors)
{
	size_t	 wsz; /* amount written */

	while (sz > 0) {
		if (!io_write_nonblocking(fd, buf, sz, &wsz, raise_errors)) {
			if (raise_errors)
				ERRX1("io_write_nonblocking");
			return false;
		} else if (wsz == 0) {
			if (raise_errors)
				ERRX("io_write_nonblocking: short write");
			return false;
		}
		buf += wsz;
		sz -= wsz;
	}

	return true;
}

bool
io_write_blocking(int fd, const void *buf, size_t sz)
{
	return io_write_blocking_impl(fd, buf, sz, true);
}

/*
 * Blocking write of the full length of iov[].  Modifies iov[] if unable
 * to write the full request in one call to writev().
 * Makes at most one pass over iov[], skipping zero-length iovecs when
 * encountered.
 * Leverages writev() to validate function parameters.
 *
 * Returns false on failure, true on success (all bytes written).
 */
static bool
io_writev_blocking(int fd, struct iovec *iov, int iovcnt,
    bool raise_errors)
{
	struct pollfd	 pfd = {
		.fd = fd,
		.events = POLLOUT,
	};
	int		 skip = 0;
	ssize_t		 cc;
	int		 n, i;

	for (;;) {
		skip = 0;
		cc = writev(fd, iov, iovcnt);
		if (cc == -1 && errno != EAGAIN && errno != EINTR) {
			if (raise_errors)
				ERRX("io_writev_blocking: %s",
				    strerror(errno));
			return false;
		}

		for (i = 0; i < iovcnt && cc >= 0; ++i) {
			if ((size_t)cc < iov[i].iov_len) {
				iov[i].iov_base += cc;
				iov[i].iov_len -= cc;
				break;
			}
			cc -= iov[i].iov_len;
			skip++;
		}

		if (skip >= iovcnt)
			break;

		iov += skip;
		iovcnt -= skip;

		n = poll(&pfd, 1, poll_timeout);
		if (n != 1) {
			if (n == -1 && errno == EINTR)
				continue;
			if (raise_errors)
				ERRX("io_writev_blocking: %s",
				    (n == 0) ? "timeout" :
				    strerror(errno));
			return false;
		}

		if (pfd.revents & (POLLERR | POLLNVAL | POLLHUP)) {
			if (raise_errors)
				ERRX("io_writev_blocking: %s",
				    ((pfd.revents & POLLHUP) != 0) ?
				    "hangup" : "bad fd");
			return false;
		}

		if (!(pfd.revents & POLLOUT)) {
			if (raise_errors)
				ERRX("io_writev_blocking: unknown "
				    "event");
			return false;
		}
	}

	return true;
}

/*
 * Record data written to fdout outside of the io layer.  For example,
 * file data may be sent out-of-band to avoid write multiplexing.
 * Returns zero on failure, non-zero on success.  io_data_written() will
 * only fail if we're writing a batch file and for some reason couldn't
 * write to it.
 */
bool
io_data_written(struct sess *sess, int fdout, const void *buf, size_t bsz)
{
	sess->total_write += bsz;
	return true;
}

/*
 * Write "buf" of size "sz" to non-blocking descriptor.
 * Returns false on failure, true on success (all bytes written to
 * the descriptor).
 * Optionally avoid raising errors, as we may be called in a logging
 * path.
 */
static bool
io_write_buf_tagged_impl(struct sess *sess, int fd, const void *buf, size_t sz,
    enum iotag iotag, bool raise_errors)
{
	struct iovec	 iov[2];
	int32_t		 tag, tagbuf;
	size_t		 wsz;
	bool		 c; /* temporary return value */

	if (!sess->mplex_writes) {
		/*
		 * If we try to write non-data to a non-multiplexed
		 * socket, then we're going to have a bad time.
		 */
		assert(iotag == IT_DATA);
		c = io_write_blocking_impl(fd, buf, sz, raise_errors);
		sess->total_write += sz;
		return c;
	}

	/*
	 * Some things can send 0-byte buffers in the reference
	 * implementation, but I think those are all peer messages
	 * rather than client <-> server
	 *
	 * We might be here as the result of a POLLOUT event for which
	 * the caller has carefully arranged to write no more data
	 * (incl. tag) than there is space available (so as not to
	 * block).  However, if we write the tag and data in separate
	 * output operations then we'll likely block unnecessarily.
	 * Therefore, to avoid blocking, we try to write them both in
	 * one single output operation via writev().
	 */

	while (sz > 0) {
		wsz = (sz < 0xFFFFFF) ? sz : 0xFFFFFF;
		tag = ((iotag + IOTAG_OFFSET) << 24) + (int)wsz;
		tagbuf = htole32(tag);
		iov[0].iov_base = &tagbuf;
		iov[0].iov_len = sizeof(tagbuf);
		iov[1].iov_base = (void *)buf;
		iov[1].iov_len = wsz;

		if (!io_writev_blocking(fd, iov, 2, raise_errors)) {
			if (raise_errors)
				ERRX1("io_writev_blocking");
			return false;
		}

		sess->total_write += wsz;
		sz -= wsz;
		buf += wsz;
	}
	return true;
}

/*
 * Like io_write_buf_tagged_impl, but always raising errors.
 */
static bool
io_write_buf_tagged(struct sess *sess, int fd, const void *buf,
    size_t sz, enum iotag iotag)
{
	return io_write_buf_tagged_impl(sess, fd, buf, sz, iotag, true);
}

/*
 * See above -- don't raise errors to avoid recursion.
 */
bool
io_write_buf_tagged_safe(struct sess *sess, int fd, const void *buf,
    size_t sz, enum iotag iotag)
{
	return io_write_buf_tagged_impl(sess, fd, buf, sz, iotag, false);
}

/*
 * Write "buf" of size "sz" to non-blocking descriptor.
 * Returns false on failure, true on success (all bytes written to
 * the descriptor).
 */
bool
io_write_buf(struct sess *sess, int fd, const void *buf, size_t sz)
{
	return io_write_buf_tagged(sess, fd, buf, sz, IT_DATA);
}

/*
 * Write "line" (NUL-terminated) followed by a newline.
 * Returns false on failure, true on success.
 */
bool
io_write_line(struct sess *sess, int fd, const char *line)
{

	if (!io_write_buf(sess, fd, line, strlen(line)))
		ERRX1("io_write_buf");
	else if (!io_write_byte(sess, fd, '\n'))
		ERRX1("io_write_byte");
	else
		return true;

	return false;
}

/*
 * Read buffer from non-blocking descriptor.
 * Returns false on failure, true on success (zero or more bytes).
 * Stores the number of bytes read in "sz" or zero on failure.
 */
static bool
io_read_nonblocking(int fd, void *buf, size_t bsz, size_t *sz,
    bool eof_ok)
{
	struct pollfd	pfd;
	ssize_t		rsz;
	int		c;

	*sz = 0;

	if (bsz == 0)
		return true;

	pfd.fd = fd;
	pfd.events = POLLIN;

	/* Poll and check for all possible errors. */

	if ((c = poll(&pfd, 1, poll_timeout)) == -1) {
		ERR("poll");
		return false;
	} else if (c == 0) {
		ERRX("poll: timeout");
		return false;
	} else if ((pfd.revents & (POLLERR|POLLNVAL))) {
		ERRX("poll: bad fd");
		return false;
	} else if (!(pfd.revents & (POLLIN|POLLHUP))) {
		ERRX("poll: unknown event");
		return false;
	}

	/* Now the non-blocking read, checking for EOF. */

	if ((rsz = read(fd, buf, bsz)) == -1) {
		ERR("read");
		return false;
	} else if (rsz == 0 && !eof_ok) {
		ERRX("unexpected end of file");
		return false;
	}

	*sz = rsz;
	return true;
}

/*
 * Blocking read of the full size of the buffer.
 * This can be called from either the error type message or a regular
 * message---or for that matter, multiplexed or not.
 * Returns false on failure, true on success (all bytes read).
 */
static bool
io_read_blocking(int fd, void *buf, size_t sz)
{
	size_t	 rsz; /* size read into buffer */

	while (sz > 0) {
		if (!io_read_nonblocking(fd, buf, sz, &rsz, false)) {
			ERRX1("io_read_nonblocking");
			return false;
		} else if (rsz == 0) {
			ERRX("io_read_nonblocking: short read");
			return false;
		}
		buf += rsz;
		sz -= rsz;
	}

	return true;
}

/*
 * When we do a lot of writes in a row (such as when the sender emits
 * the file list), the server might be sending us multiplexed log
 * messages.
 * If it sends too many, it clogs the socket.
 * This function looks into the read buffer and clears out any log
 * messages pending.
 * If called when there are valid data reads available, this function
 * does nothing.
 * Returns false on failure, true on success (or nothing to be flushed).
 */
bool
io_read_flush(struct sess *sess, int fd)
{
	int32_t	 tagbuf, /* raw value from fd */
		 tag; /* tag extracted from tagbuf */
	char	 mpbuf[BIGPATH_MAX + 1];
	size_t	 mpbufsz;

	if (sess->mplex_read_remain)
		return true;

	/*
	 * First, read the 4-byte multiplex tag.
	 * The first byte is the tag identifier (7 for normal
	 * data, !7 for out-of-band data), the last three are
	 * for the remaining data size.
	 */

	if (!io_read_blocking(fd, &tagbuf, sizeof(tagbuf))) {
		ERRX1("io_read_blocking");
		return false;
	}
	tag = le32toh(tagbuf);
	sess->mplex_read_remain = tag & 0xFFFFFF;
	tag >>= 24;
	tag -= IOTAG_OFFSET;

	/* Validate tag. */

	switch (tag) {
	case IT_DATA:
		return true;
	case IT_ERROR_XFER:
	case IT_INFO:
	case IT_ERROR:
	case IT_WARNING:
	case IT_SUCCESS:
	case IT_DELETED:
	case IT_NO_SEND:
		break;
	default:
		ERRX("unexpected tag %d (0x%x), len %zu",
		     tag, le32toh(tagbuf), sess->mplex_read_remain);
		return false;
	}

	if (sess->mplex_read_remain >= sizeof(mpbuf)) {
		ERRX("multiplex buffer overflow (tag %d 0x%x, len %zu)",
		     tag, le32toh(tagbuf), sess->mplex_read_remain);
		return false;
	}

	if ((mpbufsz = sess->mplex_read_remain) != 0) {
		if (!io_read_blocking(fd, mpbuf, mpbufsz)) {
			ERRX1("io_read_blocking");
			return 0;
		}
		if (mpbuf[mpbufsz - 1] == '\n')
			mpbuf[--mpbufsz] = '\0';

		/*
		 * We'll either handle the payload or it will get
		 * dropped; in either case, there's nothing persisting
		 * for the caller to be able to read -- zap the size.
		 */

		sess->mplex_read_remain = 0;
	}

	/*
	 * Always print the server's messages, as the server will
	 * control its own log leveling.
	 */

	if (tag >= IT_ERROR_XFER && tag <= IT_WARNING) {
		if (mpbufsz > 0) {
			mpbuf[mpbufsz] = '\0';
			LOG0("%s", mpbuf);
		}
		if (tag == IT_ERROR_XFER || tag == IT_ERROR) {
			if (tag != IT_ERROR_XFER) {
				ERRX1("error from remote host");
				return false;
			}
		}
	}

	return true;
}

/*
 * Read buffer from non-blocking descriptor, possibly in multiplex read
 * mode.
 * Returns false on failure, true on success (all bytes read from the
 * descriptor).
 */
bool
io_read_buf(struct sess *sess, int fd, void *buf, size_t sz)
{
	size_t	 rsz; /* size to tbe read */
	bool	 c; /* temporary return code */

	/* If we're not multiplexing, read directly. */

	if (!sess->mplex_reads) {
		assert(sess->mplex_read_remain == 0);
		c = io_read_blocking(fd, buf, sz);
		sess->total_read += sz;
		return c;
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
			if (!io_read_blocking(fd, buf, rsz)) {
				ERRX1("io_read_blocking");
				return false;
			}
			sz -= rsz;
			sess->mplex_read_remain -= rsz;
			buf += rsz;
			sess->total_read += rsz;
			continue;
		}

		assert(sess->mplex_read_remain == 0);
		if (!io_read_flush(sess, fd)) {
			ERRX1("io_read_flush");
			return false;
		}
	}

	return true;
}

/*
 * Like io_write_buf(), but for a long (which is a composite type).
 * Returns false on failure, true on success.
 */
bool
io_write_ulong(struct sess *sess, int fd, uint64_t val)
{
	uint64_t	nv;
	int64_t		sval = (int64_t)val;

	/* Short-circuit: send as an integer if possible. */

	if (sval <= INT32_MAX && sval >= 0) {
		if (!io_write_int(sess, fd, (int32_t)val)) {
			ERRX1("io_write_int");
			return false;
		}
		return true;
	}

	/* Otherwise, pad with -1 32-bit, then send 64-bit. */

	nv = htole64(val);

	if (!io_write_int(sess, fd, -1))
		ERRX1("io_write_int");
	else if (!io_write_buf(sess, fd, &nv, sizeof(int64_t)))
		ERRX1("io_write_buf");
	else
		return true;

	return false;
}

bool
io_write_long(struct sess *sess, int fd, int64_t val)
{
	return io_write_ulong(sess, fd, (uint64_t)val);
}

static bool
io_write_uint_tagged(struct sess *sess, int fd, uint32_t val,
    enum iotag tag)
{
	uint32_t	nv;

	nv = htole32(val);

	if (!io_write_buf_tagged(sess, fd, &nv, sizeof(nv), tag)) {
		ERRX1("io_write_buf");
		return false;
	}
	return true;
}

/*
 * Like io_write_buf(), but for an unsigned integer.
 * Returns false on failure, true on success.
 */
bool
io_write_uint(struct sess *sess, int fd, uint32_t val)
{

	return io_write_uint_tagged(sess, fd, val, IT_DATA);
}

bool
io_write_int_tagged(struct sess *sess, int fd, int32_t val,
    enum iotag tag)
{
	return io_write_uint_tagged(sess, fd, (uint32_t)val, tag);
}

/*
 * Like io_write_buf(), but for an integer.
 * Returns false on failure, true on success.
 */
bool
io_write_int(struct sess *sess, int fd, int32_t val)
{
	return io_write_uint(sess, fd, (uint32_t)val);
}

/*
 * A simple assertion-protected memory copy from th einput "val" or size
 * "valsz" into our buffer "buf", full size "buflen", position "bufpos".
 * Increases our "bufpos" appropriately.
 * This has no return value, but will assert() if the size of the buffer
 * is insufficient for the new data.
 */
void
io_buffer_buf(void *buf, size_t *bufpos, size_t buflen, const void *val,
    size_t valsz)
{

	assert(*bufpos + valsz <= buflen);
	memcpy(buf + *bufpos, val, valsz);
	*bufpos += valsz;
}

/*
 * Like io_buffer_buf(), but also accommodating for multiplexing codes.
 * This should NEVER be passed to io_write_buf(), but instead passed
 * directly to a write operation.
 */
void
io_lowbuffer_buf(struct sess *sess, void *buf,
	size_t *bufpos, size_t buflen, const void *val, size_t valsz)
{
	int32_t	tagbuf;

	if (valsz == 0)
		return;

	if (!sess->mplex_writes) {
		io_buffer_buf(buf, bufpos, buflen, val, valsz);
		return;
	}

	assert(*bufpos + valsz + sizeof(int32_t) <= buflen);
	assert(valsz == (valsz & 0xFFFFFF));
	tagbuf = htole32((7 << 24) + valsz);

	io_buffer_int(buf, bufpos, buflen, tagbuf);
	io_buffer_buf(buf, bufpos, buflen, val, valsz);
}

/*
 * Allocate the space needed for io_lowbuffer_buf() and friends.
 * Optionally allow errors to be suppressed in case we're called in a
 * logging path.
 * This should be called for *each* lowbuffer operation, so:
 *
 *   io_lowbuffer_alloc(... sizeof(int32_t));
 *   io_lowbuffer_int(...);
 *   io_lowbuffer_alloc(... sizeof(int32_t));
 *   io_lowbuffer_int(...);
 *
 * And not sizeof(int32_t) * 2 or whatnot.
 * Returns false on failure, true on success.
 */
static bool
io_lowbuffer_alloc_impl(struct sess *sess, void **buf,
    size_t *bufsz, size_t *bufmax, size_t sz, bool raise_errors)
{
	void	*pp; /* allocation */
	size_t	 extra; /* how much extra to allocate */

	extra = sess->mplex_writes ? sizeof(int32_t) : 0;

	if (*bufsz + sz + extra > *bufmax) {
		pp = realloc(*buf, *bufsz + sz + extra);
		if (pp == NULL) {
			if (raise_errors)
				ERR("realloc");
			return false;
		}
		*buf = pp;
		*bufmax = *bufsz + sz + extra;
	}
	*bufsz += sz + extra;
	return true;
}

/*
 * Alias of io_lowbuffer_alloc with raising errors.
 */
bool
io_lowbuffer_alloc(struct sess *sess, void **buf, size_t *bufsz,
    size_t *bufmax, size_t sz)
{
	return io_lowbuffer_alloc_impl(sess, buf, bufsz, bufmax, sz,
	    true);
}

bool
io_lowbuffer_alloc_safe(struct sess *sess, void **buf, size_t *bufsz,
    size_t *bufmax, size_t sz)
{
	return io_lowbuffer_alloc_impl(sess, buf, bufsz, bufmax, sz, false);
}

/*
 * Like io_lowbuffer_buf(), but for a single integer.
 */
void
io_lowbuffer_int(struct sess *sess, void *buf,
	size_t *bufpos, size_t buflen, int32_t val)
{
	int32_t	nv = htole32(val);

	io_lowbuffer_buf(sess, buf, bufpos, buflen, &nv, sizeof(int32_t));
}

/*
 * Like io_lowbuffer_buf(), but for a single byte.
 */
void
io_lowbuffer_byte(struct sess *sess, void *buf,
	size_t *bufpos, size_t buflen, int8_t val)
{
	int8_t	nv = val;

	io_lowbuffer_buf(sess, buf, bufpos, buflen, &nv, sizeof(nv));
}

/*
 * Like io_buffer_buf(), but for a single integer.
 */
void
io_buffer_int(void *buf, size_t *bufpos, size_t buflen, int32_t val)
{
	int32_t	nv = htole32(val);

	io_buffer_buf(buf, bufpos, buflen, &nv, sizeof(int32_t));
}

/*
 * Like io_read_buf(), but for a long >=0.
 * Returns false on failure, true on success.
 */
bool
io_read_long(struct sess *sess, int fd, int64_t *val)
{
	uint64_t	uoval; /* raw value read */

	if (!io_read_ulong(sess, fd, &uoval)) {
		ERRX1("io_read_long");
		return false;
	}
	*val = (int64_t)uoval;
	if (*val < 0) {
		ERRX1("io_read_long negative");
		return false;
	}
	return true;
}

/*
 * Like io_read_buf(), but for a long.
 * Returns false on failure, true on success.
 */
bool
io_read_ulong(struct sess *sess, int fd, uint64_t *val)
{
	uint64_t	 oval; /* 64-bit value read */
	int32_t		 sval; /* raw value read */

	/* Start with the short-circuit: read as an int. */

	if (!io_read_int(sess, fd, &sval)) {
		ERRX1("io_read_int");
		return false;
	}
	if (sval != -1) {
		*val = sval;
		return true;
	}

	/* If the int is -1, read as 64 bits. */

	if (!io_read_buf(sess, fd, &oval, sizeof(uint64_t))) {
		ERRX1("io_read_buf");
		return false;
	}

	*val = le64toh(oval);
	return true;
}

/*
 * One thing we often need to do is read a size_t.
 * These are transmitted as int32_t, so make sure that the value
 * transmitted is not out of range.
 * FIXME: I assume that size_t can handle int32_t's max.
 * Returns zero on failure, non-zero on success.
 */
bool
io_read_size(struct sess *sess, int fd, size_t *val)
{
	int32_t	 oval; /* value read */

	if (!io_read_int(sess, fd, &oval)) {
		ERRX1("io_read_int");
		return false;
	} else if (oval < 0) {
		ERRX("io_read_size: negative value");
		return false;
	}

	*val = oval;
	return true;
}

/*
 * Like io_read_buf(), but for an unsigned integer.
 * Returns false on failure, true on success.
 */
bool
io_read_uint(struct sess *sess, int fd, uint32_t *val)
{
	uint32_t	oval; /* raw value read */

	if (!io_read_buf(sess, fd, &oval, sizeof(uint32_t))) {
		ERRX1("io_read_buf");
		return false;
	}

	*val = le32toh(oval);
	return true;
}

/*
 * Like io_read_buf(), but for a signed integer.
 * Returns false on failure, true on success.
 */
bool
io_read_int(struct sess *sess, int fd, int32_t *val)
{
	return io_read_uint(sess, fd, (uint32_t *)val);
}

/*
 * Copies "valsz" from "buf", full size "bufsz" at position" bufpos",
 * into "val".
 * Calls assert() if the source doesn't have enough data.
 * Increases "bufpos" to the new position.
 */
void
io_unbuffer_buf(const void *buf, size_t *bufpos, size_t bufsz, void *val,
    size_t valsz)
{

	assert(*bufpos + valsz <= bufsz);
	memcpy(val, buf + *bufpos, valsz);
	*bufpos += valsz;
}

/*
 * Calls io_unbuffer_buf() and converts.
 */
void
io_unbuffer_int(const void *buf, size_t *bufpos, size_t bufsz, int32_t *val)
{
	int32_t	oval;

	io_unbuffer_buf(buf, bufpos, bufsz, &oval, sizeof(int32_t));
	*val = le32toh(oval);
}

/*
 * Calls io_unbuffer_buf() and converts.
 * Returns false on (conversion) failure, true on success.
 */
bool
io_unbuffer_size(const void *buf, size_t *bufpos, size_t bufsz, size_t *val)
{
	int32_t	 oval; /* raw value */

	io_unbuffer_int(buf, bufpos, bufsz, &oval);
	if (oval < 0) {
		ERRX("io_unbuffer_size: negative value");
		return false;
	}
	*val = oval;
	return true;
}

/*
 * Like io_read_buf(), but for a single byte >=0.
 * Returns false on failure, true on success.
 */
bool
io_read_byte(struct sess *sess, int fd, uint8_t *val)
{
	if (!io_read_buf(sess, fd, val, sizeof(uint8_t))) {
		ERRX1("io_read_buf");
		return false;
	}
	return true;
}

/*
 * Like io_write_buf(), but for a single byte.
 * Returns false on failure, true on success.
 */
bool
io_write_byte(struct sess *sess, int fd, uint8_t val)
{
	if (!io_write_buf(sess, fd, &val, sizeof(uint8_t))) {
		ERRX1("io_write_buf");
		return false;
	}
	return true;
}

/*
 * Read a string length and data directly off the wire, blocking until
 * all data is read or there is an error.  Allocates storage for the
 * string and returns a NUL terminated pointer to it, or a NULL pointer
 * if the length of the string is zero.
 * Returns false on failure, true on success.
 */
bool
io_read_vstring(struct sess *sess, int fd, char **strp)
{
	uint8_t	 bval;
	size_t	 len = 0;

	*strp = NULL;

	if (!io_read_byte(sess, fd, &bval)) {
		ERRX1("io_read_vstring byte 1");
		return false;
	}

	if (bval & 0x80) {
		len = (bval - 0x80) << 8;
		if (!io_read_byte(sess, fd, &bval)) {
			ERRX1("io_read_vstring byte 1");
			return false;
		}
	}

	len |= bval;

	if (len > 0) {
		*strp = malloc(len + 1);
		if (*strp == NULL) {
			ERRX1("io_read_vstring: malloc(%zu) failed", len + 1);
			return false;
		}

		if (!io_read_buf(sess, fd, *strp, len)) {
			ERRX1("io_read_vstring buf");
			return false;
		}

		(*strp)[len] = '\0';
	}

	return true;
}

/*
 * Re-pack the buffer such that the valid portion is at the beginning,
 * leaving us with more room at the tail.  We'll do this for each
 * allocation, as well as when we attempt to fill the buffer.
 *
 * For allocation, we'll likely do few allocations so it's not a big
 * deal to add this kind of overhead.  We could see quite a few buffer
 * fills, but odds are we won't be seeing a lot of fill/read interlaced
 * unless we have enough contiguous data to make it worth our while to
 * repack (e.g., when we're reading block metadata; we'd repack after
 * each set of blocks and potentially pay the penalty of this memory
 * copy, but at the same time we'll be able to read(2) more in the next
 * go-around).
 */
static void
iobuf_repack(struct iobuf *buf)
{
	if (buf->offset == 0)
		return;

	if (buf->resid != 0)
		memmove(&buf->buffer[0], &buf->buffer[buf->offset],
		    buf->resid);

	buf->offset = 0;
}

static bool
iobuf_alloc_common(const struct sess *sess, struct iobuf *buf,
    size_t sz, bool framed)
{
	void	*pp; /* allocation result */
	size_t	 room, /* room left in iobuf */
		 newsz; /* new allocation size */

	if (framed)
		sz += sizeof(int32_t);	/* multiplexing tag */

	room = buf->size - buf->offset - buf->resid;
	if (room > sz)
		return true;

	if ((buf->offset > IOBUF_MIN_REPACK &&
	     buf->resid < IOBUF_MIN_REPACK) ||
	    (buf->offset > IOBUF_MAX_REPACK))
		iobuf_repack(buf);

	room = buf->size - buf->offset - buf->resid;
	if (sz >= room) {
		newsz = buf->size + roundup(sz - room + 1, IOBUF_MIN_ALLOC);
		pp = realloc(buf->buffer, newsz);
		if (pp == NULL) {
			ERR("realloc");
			return false;
		}
		buf->buffer = pp;
		buf->size = newsz;
	}

	return true;
}

bool
iobuf_alloc(const struct sess *sess, struct iobuf *buf, size_t rsz)
{

	return iobuf_alloc_common(sess, buf, rsz, false);
}

/*
 * Get the amount of data that's been read into the buffer.
 */
size_t
iobuf_get_readsz(const struct iobuf *buf)
{
	return buf->resid;
}

/*
 * Set that the EOF has been seen.  After this, iobuf_seen_eof() will
 * return true.
 */
void
iobuf_eof(struct iobuf *buf)
{
	buf->eof = true;
}

/*
 * Return whether EOF has been seen.
 */
bool
iobuf_seen_eof(const struct iobuf *buf)
{
	return buf->eof;
}

/*
 * Fill up an iobuf with as much data as is currently available.
 * Return true on success, false on error.
 */
bool
iobuf_fill(struct sess *sess, struct iobuf *buf, int fd)
{
	size_t	 pos, /* position in buffer */
		 read, /* how much read */
		 remain; /* how much remains */
	int	 check; /* data remains to be read */
	bool	 read_any = false, /* data has been read */
		 ret = true; /* return code */

	assert(buf->size != 0);

	if ((buf->offset > IOBUF_MIN_REPACK &&
	     buf->resid < IOBUF_MIN_REPACK) ||
	    (buf->offset > IOBUF_MAX_REPACK))
		iobuf_repack(buf);

	read_any = false;
	check = 0;

	while ((check = io_read_check(sess, fd)) > 0) {
		/*
		 * Flush any log messages first, we may not actually
		 * have any data to read.
		 */

		if (sess->mplex_reads && sess->mplex_read_remain == 0) {
			if (!io_read_flush(sess, fd)) {
				ERRX1("io_read_flush");
				return 0;
			}
			continue;
		}

		/*
		 * Read into the end of the currently valid portion of
		 * the buffer.
		 */

		pos = buf->offset + buf->resid;
		remain = buf->size - pos;
		if (remain == 0)
			break;

		/*
		 * If we're multiplexing, we need to be careful not to
		 * overread and accidentally slurp up the next tag.
		 */

		if (sess->mplex_reads &&
		    remain > sess->mplex_read_remain)
			remain = sess->mplex_read_remain;

		ret = io_read_nonblocking(fd, &buf->buffer[pos],
		    remain, &read, true);
		if (!ret) {
			ERRX1("io_read_nonblocking");
			break;
		} else if (read == 0) {
			/*
			 * EOF is only fatal for us if we weren't able
			 * to pull any data at all; clearly the caller
			 * was expecting something.  If it wasn't
			 * enough, they'll come back and get an error.
			 */
			if (!read_any) {
				ERRX1("unexpected eof");
				ret = false;
			}
			break;
		}

		read_any = true;
		buf->resid += read;

		/*
		 * Update our session accounting; we may not have read
		 * all of the data buffer that was available, in which
		 * case we'll likely return.
		 */

		sess->total_read += read;
		if (sess->mplex_read_remain != 0) {
			assert(read <= sess->mplex_read_remain);
			sess->mplex_read_remain -= read;
		}

		if (read == remain)
			break;
	}

	if (check < 0)
		ret = false;
	return ret;
}

/*
 * Copies "valsz" from "buf".
 * Calls assert() if the source doesn't have enough data.
 * Does not advance our read pointer, caller must do that if it's
 * actually consuming the data.
 */
static void
iobuf_peek_buf(const struct iobuf *buf, void *val, size_t valsz)
{

	assert(valsz <= buf->resid);
	memcpy(val, &buf->buffer[buf->offset], valsz);
}

/*
 * Copies "valsz" from "buf".
 * Calls assert() if the source doesn't have enough data.
 */
void
iobuf_read_buf(struct iobuf *buf, void *val, size_t valsz)
{

	iobuf_peek_buf(buf, val, valsz);
	buf->resid -= valsz;

	/*
	 * We can just reset our offset to 0 to start over if we hit the
	 * end of the valid portion, otherwise we'll move along.  This
	 * just saves us a tiny bit of time determining if we need to
	 * repack the buffer.
	 */

	if (buf->resid == 0)
		buf->offset = 0;
	else
		buf->offset += valsz;
}

/*
 * Like iobuf_read_buf(), but for a single byte.
 */
void
iobuf_read_byte(struct iobuf *buf, uint8_t *val)
{
	iobuf_read_buf(buf, val, sizeof(*val));
}

/*
 * Calls iobuf_peek_buf() and converts.
 */
int32_t
iobuf_peek_int(const struct iobuf *buf)
{
	int32_t	 oval; /* raw value in buffer */

	iobuf_peek_buf(buf, &oval, sizeof(int32_t));
	return le32toh(oval);
}

/*
 * Calls iobuf_read_buf() and converts.
 */
void
iobuf_read_int(struct iobuf *buf, int32_t *val)
{
	int32_t	oval;

	iobuf_read_buf(buf, &oval, sizeof(int32_t));
	*val = le32toh(oval);
}

/*
 * Calls iobuf_read_buf() and converts.
 * Returns true on successful conversion, false on failure.
 */
bool
iobuf_read_size(struct iobuf *buf, size_t *val)
{
	int32_t	 oval; /* raw value */

	iobuf_read_int(buf, &oval);
	if (oval < 0) {
		ERRX("%s: negative value", __func__);
		return false;
	}
	*val = oval;
	return true;
}

/*
 * Reads a variable-length string no longer than `sz` into `str`.  This
 * function is re-entrant, since we don't know exactly how much data we
 * need to fill the buffer and it may be that we need multiple read()
 * calls to grab it all.
 *
 * Returns -1 on error, 0 if `str` is not yet complete, 1 if `str` is
 * now complete.
 */
int
iobuf_read_vstring(struct iobuf *buf, struct vstring *vstr)
{
	uint8_t	 bval;
	size_t	 avail, /* how much data is available */
		 len = 0,
		 needed;

	avail = iobuf_get_readsz(buf);

	if (avail == 0)
		return 0;

	if (vstr->vstring_buffer == NULL) {
		/*
		 * Need at least one of the potentially two length
		 * bytes.
		 */
		if (avail < sizeof(bval))
			return 0;

		/* 
		 * If bit 7 of the first byte is set then wait for both
		 * bytes.
		 */

		iobuf_peek_buf(buf, &bval, sizeof(bval));
		if ((bval & 0x80) && (avail < sizeof(bval) * 2))
			return 0;

		iobuf_read_byte(buf, &bval);
		if (bval & 0x80) {
			len = (bval - 0x80) << 8;
			iobuf_read_byte(buf, &bval);
		}

		len |= bval;

		if (len == 0)
			return 1;

		vstr->vstring_size = len;
		vstr->vstring_buffer = malloc(vstr->vstring_size + 1);
		if (vstr->vstring_buffer == NULL) {
			ERR("malloc");
			return -1;
		}
		avail = iobuf_get_readsz(buf);
	}

	needed = vstr->vstring_size - vstr->vstring_offset;
	if (avail > needed)
		avail = needed;

	iobuf_read_buf(buf,
	    &vstr->vstring_buffer[vstr->vstring_offset], avail);
	vstr->vstring_offset += avail;
	vstr->vstring_buffer[vstr->vstring_size] = '\0';
	return vstr->vstring_offset == vstr->vstring_size ? 1 : 0;
}


/*
 * Copyright (c) 2024, Klara, Inc.
 * Copyright (c) Kristaps Dzonsons <kristaps@bsd.lv>
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

#include <sys/param.h> /* roundup */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h> /* PATH_MAX */
#include <unistd.h>

#include "extern.h"

/*
 * Allocate space for a readlink(2) invocation.
 * Returns NULL on failure or a buffer otherwise.
 * The buffer must be passed to free() by the caller.
 */
char *
symlink_read(const char *path, size_t sz)
{
	char	*buf = NULL;
	ssize_t	 nsz = 0;
	void	*pp;

	while (true) {
		if ((pp = realloc(buf, sz + 1)) == NULL) {
			ERR("realloc");
			free(buf);
			return NULL;
		}
		buf = pp;

		if ((nsz = readlink(path, buf, sz + 1)) == -1) {
			ERR("%s: readlink", path);
			free(buf);
			return NULL;
		} else if (nsz == 0) {
			ERRX("%s: empty link", path);
			free(buf);
			return NULL;
		} else if ((size_t)nsz < sz + 1)
			break;

		sz = roundup(sz + 1, PATH_MAX);
	}

	assert(buf != NULL);
	assert(nsz > 0);
	buf[nsz] = '\0';
	return buf;
}

/*
 * Allocate space for a readlinkat(2) invocation.
 * Returns NULL on failure or a buffer otherwise.
 * The buffer must be passed to free() by the caller.
 */
char *
symlinkat_read(int fd, const char *path, size_t sz)
{
	char	*buf = NULL;
	ssize_t	 nsz = 0;
	void	*pp;

	while (true) {
		if ((pp = realloc(buf, sz + 1)) == NULL) {
			ERR("realloc");
			free(buf);
			return NULL;
		}
		buf = pp;

		if ((nsz = readlinkat(fd, path, buf, sz + 1)) == -1) {
			ERR("%s: readlinkat", path);
			free(buf);
			return NULL;
		} else if (nsz == 0) {
			ERRX("%s: empty link", path);
			free(buf);
			return NULL;
		} else if ((size_t)nsz < sz + 1)
			break;

		sz = roundup(sz + 1, PATH_MAX);
	}

	assert(buf != NULL);
	assert(nsz > 0);
	buf[nsz] = '\0';
	return buf;
}

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

#include <sys/mman.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "extern.h"

struct fmap {
	void		*map;
	unsigned char	*buf;
	int		 fd;
	size_t		 mapsz;
};

static bool
fmap_open_mmap(struct fmap *fm, const char *path, int fd, size_t sz)
{
	fm->mapsz = sz;
	fm->map = mmap(NULL, sz, PROT_READ, MAP_SHARED, fd, 0);
	if (fm->map == MAP_FAILED) {
		ERR("%s: mmap", path);
		return false;
	}

	return true;
}

/*
 * Open a mapping of the given fd.
 */
struct fmap *
fmap_open(const char *path, int fd, size_t sz)
{
	struct fmap	*fm;

	fm = calloc(1, sizeof(*fm));
	if (fm == NULL)
		return NULL;

	fm->fd = fd;
	if (fmap_open_mmap(fm, path, fd, sz))
		return fm;

	free(fm);
	return NULL;
}

bool
fmap_access_valid(const struct fmap *fm, off_t offset, size_t datasz)
{
	if (fm == NULL)
		return false;
	return offset + datasz <= fm->mapsz;
}

const void *
fmap_data(const struct fmap *fm, off_t offset, size_t datasz)
{

	if (fm == NULL)
		return NULL;

	assert(fmap_access_valid(fm, offset, datasz));
	/* Temporary diagnostics */
	if (offset + datasz > fm->mapsz)
		WARNX1("Invalid access; mapsz=%zu, [%llu, %llu) requested",
		    fm->mapsz, offset, offset + datasz);
	return &fm->map[offset];
}

/*
 * What is the size of the mapped file or 0 if there is no file.
 */
size_t
fmap_size(const struct fmap *fm)
{
	return fm == NULL ? 0 : fm->mapsz;
}

/*
 * Close out an fmap.  Does nothing if "fm" is NULL already.
 */
void
fmap_close(struct fmap *fm)
{
	if (fm == NULL)
		return;
	(void)munmap(fm->map, fm->mapsz);
	free(fm);
}

bool
fmap_trap(const struct fmap *fm)
{
	return true;
}

void
fmap_untrap(const struct fmap *fm)
{
}

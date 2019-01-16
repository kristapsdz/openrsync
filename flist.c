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
#include <sys/param.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <fts.h>
#include <stdlib.h>
#include <string.h>

#include "extern.h"

/*
 * These flags are part of the rsync protocol.
 * They are sent as the first byte for a file transmission and encode
 * information that affects subsequent transmissions.
 */
#define FLIST_DIR	 0x0001 /* directory? */
#define FLIST_MODE_SAME  0x0002 /* mode is repeat */
#define	FLIST_NAME_SAME  0x0020 /* name is repeat */
#define FLIST_NAME_LONG	 0x0040 /* name >255 bytes */
#define FLIST_TIME_SAME  0x0080 /* time is repeat */

static int
flist_cmp(const void *p1, const void *p2)
{
	const struct flist *f1 = p1, *f2 = p2;

	return strcmp(f1->path, f2->path);
}

void
flist_free(struct flist *f, size_t sz)
{
	size_t	 i;

	for (i = 0; i < sz; i++)
		free(f[i].path);
	free(f);
}

/*
 * Serialise our file list to the wire.
 * Return zero on failure, non-zero on success.
 */
int
flist_send(const struct opts *opts, 
	int fd, const struct flist *fl, size_t flsz)
{
	size_t		 i, fnlen;
	uint8_t		 flag;
	const struct flist *f;
	const char	*fn;

	LOG2(opts, "sending file metadata list: %zu", flsz);

	for (i = 0; i < flsz; i++) {
		f = &fl[i];
		fn = opts->recursive ? f->path : f->filename;
		fnlen = opts->recursive ? f->pathlen : f->filenamelen;

		/*
		 * For ease, make all of our filenames be "long"
		 * regardless their actual length.
		 * This also makes sure that we don't transmit a zero
		 * byte unintentionally.
		 */

		flag = FLIST_NAME_LONG;
		if (S_ISDIR(f->st.mode))
			flag |= FLIST_DIR;

		LOG3(opts, "sending file metadata: %s "
			"(size %llu, mtime %lld, mode %o)",
			f->path, f->st.size, f->st.mtime, f->st.mode);

		/* Now write to the wire. */

		if ( ! io_write_byte(opts, fd, flag))
			ERRX1(opts, "io_write_byte: flags");
		else if ( ! io_write_int(opts, fd, fnlen))
			ERRX1(opts, "io_write_int: filename length");
		else if ( ! io_write_buf(opts, fd, fn, fnlen))
			ERRX1(opts, "io_write_buf: filename");
		else if ( ! io_write_long(opts, fd, f->st.size))
			ERRX1(opts, "io_write_long: file size");
		else if ( ! io_write_int(opts, fd, f->st.mtime))
			ERRX1(opts, "io_write_int: file mtime");
		else if ( ! io_write_int(opts, fd, f->st.mode))
			ERRX1(opts, "io_write_int: file mode");
		else
			continue;

		return 0;
	}

	if ( ! io_write_byte(opts, fd, 0)) {
		ERRX1(opts, "io_write_byte: zero flag");
		return 0;
	}

	return 1;
}

/*
 * Read the filename.
 * This is the most expensive part of the file list transfer, so a lot
 * of attention has gone into transmitting as little as possible.
 * Fills in "f" with the full path on success.
 * Returns zero on failure, non-zero on success.
 */
static int
flist_recv_filename(const struct opts *opts, int fd, 
	struct flist *f, uint8_t flags, char last[MAXPATHLEN])
{
	int32_t		 ival;
	uint8_t		 bval;
	size_t		 partial = 0;
	size_t		 pathlen = 0;

	/*
	 * Read our filename.
	 * If we have FLIST_NAME_SAME, we inherit some of the last
	 * transmitted name.
	 */

	if (FLIST_NAME_SAME & flags) {
		if ( ! io_read_byte(opts, fd, &bval)) {
			ERRX1(opts, "io_read_byte: "
				"filename partial length");
			return 0;
		}
		partial = bval;
	}

	/* Get the (possibly-remaining) filename length. */

	if (FLIST_NAME_LONG & flags) {
		if ( ! io_read_int(opts, fd, &ival)) {
			ERRX1(opts, "io_read_int: "
				"filename length");
			return 0;
		} else if (ival < 0) {
			ERRX(opts, "negative filename length");
			return 0;
		}
		pathlen = ival;
	} else {
		if ( ! io_read_byte(opts, fd, &bval)) {
			ERRX1(opts, "io_read_byte: "
				"filename length");
			return 0;
		} 
		pathlen = bval;
	}

	/* Allocate our full filename length. */

	f->pathlen = pathlen + partial;
	f->path = malloc(f->pathlen + 1);
	f->path[f->pathlen] = '\0';

	if (FLIST_NAME_SAME & flags)
		memcpy(f->path, last, partial);

	if ( ! io_read_buf(opts, fd, f->path + partial, pathlen)) {
		ERRX1(opts, "io_read_buf: filename");
		return 0;
	}

	strlcpy(last, f->path, MAXPATHLEN);

	f->filename = strrchr(f->path, '/');
	if (NULL == f->filename)
		f->filename = f->path;
	else
		f->filename++;
	f->filenamelen = strlen(f->filename);
	return 1;
}

/*
 * Receive a file list of length "sz" from the wire.
 * Return the file list or NULL on failure ("sz" will be zero).
 */
struct flist *
flist_recv(const struct opts *opts, int fd, size_t *sz)
{
	struct flist	*fl = NULL;
	struct flist	*ff;
	const struct flist *fflast;
	size_t		 flsz = 0, flmax = 0;
	uint8_t		 flag;
	void		*pp;
	char		 lastname[MAXPATHLEN];
	int64_t		 lval; /* temporary values... */
	int32_t		 ival;

	*sz = 0;
	lastname[0] = '\0';
	fflast = NULL;

	for (;;) {
		if ( ! io_read_byte(opts, fd, &flag)) {
			ERRX1(opts, "io_read_byte: flags");
			goto out;
		} else if (0 == flag)
			break;

		if (flsz + 1 > flmax) {
			pp = recallocarray
				(fl, flmax, flmax + 1024, 
				 sizeof(struct flist));
			if (NULL == pp) {
				ERR(opts, "recallocarray");
				goto out;
			}
			fl = pp;
			flmax += 1024;
		}
		flsz++;
		ff = &fl[flsz - 1];

		if ( ! flist_recv_filename
		    (opts, fd, ff, flag, lastname)) {
			ERRX1(opts, "flist_recv_filename");
			goto out;
		}

		/* Read the timestamp. */

		if ( ! io_read_long(opts, fd, &lval)) {
			ERRX1(opts, "io_read_long: file size");
			goto out;
		}
		ff->st.size = lval;

		/* Read the modification time. */

		if ( ! (FLIST_TIME_SAME & flag)) {
			if ( ! io_read_int(opts, fd, &ival)) {
				ERRX1(opts, "io_read_int: file mtime");
				goto out;
			}
			ff->st.mtime = ival;
		} else if (NULL == fflast) {
			ERRX(opts, "same time without last entry");
			goto out;
		}  else
			ff->st.mtime = fflast->st.mtime;

		/* Read the file mode. */

		if ( ! (FLIST_MODE_SAME & flag)) {
			if ( ! io_read_int(opts, fd, &ival)) {
				ERRX1(opts, "io_read_int: file mode");
				goto out;
			}
			ff->st.mode = ival;
		} else if (NULL == fflast) {
			ERRX(opts, "same mode without last entry");
			goto out;
		} else
			ff->st.mode = fflast->st.mode;

		LOG3(opts, "received file metadata: %s "
			"(size %llu, mtime %lld, mode %o)",
			ff->path, ff->st.size, ff->st.mtime, ff->st.mode);
		fflast = ff;
	}

	LOG2(opts, "received file metadata list: %zu", flsz);
	*sz = flsz;
	qsort(fl, *sz, sizeof(struct flist), flist_cmp);
	return fl;
out:
	flist_free(fl, flsz);
	return NULL;
}

/*
 * Copy necessary elements in "st" into the fields of "f".
 */
static void
flist_copy_stat(struct flist *f, const struct stat *st)
{

	f->st.mode = st->st_mode;
	f->st.uid = st->st_uid;
	f->st.gid = st->st_gid;
	f->st.size = st->st_size;
	f->st.mtime = st->st_mtime;
}

/*
 * Generate a flist recursively given the array of directories (or
 * files, doesn't matter) specified in argv.
 */
static struct flist *
flist_gen_recursive(const struct opts *opts, 
	size_t argc, char **argv, size_t *sz)
{
	char		**cargv;
	int		  rc = 0;
	FTS		 *fts;
	FTSENT		 *ent;
	struct flist	 *fl = NULL, *f;
	size_t		  i, flsz = 0, flmax = 0;
	void		 *pp;

	*sz = 0;

	assert(opts->recursive);

	if (NULL == (cargv = calloc(argc + 1, sizeof(char *)))) {
		ERR(opts, "calloc");
		return NULL;
	}

	/* The arguments to fts_open must be NULL-terminated. */

	for (i = 0; i < argc; i++)
		cargv[i] = argv[i];
	cargv[i] = NULL;

	/*
	 * If we're recursive, then we need to take down all of the
	 * files and directory components, so use fts(3).
	 * Copying the information file-by-file into the flstat.
	 * We'll make sense of it in flist_send.
	 */

	if (NULL == (fts = fts_open(cargv, FTS_LOGICAL, NULL))) {
		ERR(opts, "fts_open");
		free(cargv);
		return NULL;
	}

	errno = 0;
	while (NULL != (ent = fts_read(fts))) {
		if (FTS_DC == ent->fts_info) {
			WARNX(opts, "skipping directory "
				"cycle: %s", ent->fts_path);
			continue;
		}
		if (flsz + 1 > flmax) {
			pp = recallocarray
				(fl, flmax, flmax + 1024, 
				 sizeof(struct flist));
			if (NULL == pp) {
				ERR(opts, "recallocarray");
				goto out;
			}
			fl = pp;
			flmax += 1024;
		}
		flsz++;
		f = &fl[flsz - 1];

		if (NULL == (f->path = strdup(ent->fts_path))) {
			ERR(opts, "strdup");
			goto out;
		}
		f->pathlen = ent->fts_pathlen;
		f->filename = strrchr(f->path, '/');
		if (NULL == f->filename)
			f->filename = f->path;
		else
			f->filename++;
		flist_copy_stat(f, ent->fts_statp);
		errno = 0;
	}
	if (errno) {
		ERR(opts, "fts_read");
		goto out;
	}

	rc = 1;
	LOG2(opts, "recursively generated %zu filenames", flsz);
out:
	fts_close(fts);
	if ( ! rc) {
		flist_free(fl, flsz);
		fl = NULL;
	} else
		*sz = flsz;

	free(cargv);
	return fl;
}

struct flist *
flist_gen(const struct opts *opts, size_t argc, char **argv, size_t *sz)
{
	struct flist	*fl = NULL;
	size_t		 i;
	struct stat	 st;
	int		 rc = 0;

	/* Recursive is managed elsewhere. */

	if (opts->recursive) 
		return flist_gen_recursive(opts, argc, argv, sz);

	*sz = 0;

	/* We'll have at most argc. */

	fl = calloc(argc, sizeof(struct flist));
	if (NULL == fl) {
		ERR(opts, "calloc");
		return NULL;
	}

	/*
	 * Loop over all files and fstat them straight up.
	 * Don't allow anything but regular files for now.
	 */

	for (i = 0; i < argc; i++) {
		if (-1 == lstat(argv[i], &st)) {
			ERR(opts, "fstat: %s", argv[i]);
			goto out;
		} else if (S_ISDIR(st.st_mode)) {
			WARNX(opts, "skipping directory: %s", argv[i]);
			continue;
		} else if ( ! S_ISREG(st.st_mode)) {
			WARNX(opts, "skipping non-regular: %s", argv[i]);
			goto out;
		}

		fl[*sz].path = strdup(argv[i]);
		if (NULL == fl[*sz].path) {
			ERR(opts, "strdup");
			goto out;
		}
		fl[*sz].pathlen = strlen(argv[i]);
		fl[*sz].filename = strrchr(fl[*sz].path, '/');
		if (NULL == fl[*sz].filename)
			fl[*sz].filename = fl[*sz].path;
		else
			fl[*sz].filename++;
		fl[*sz].filenamelen = strlen(fl[*sz].filename);
		flist_copy_stat(&fl[*sz], &st);
		(*sz)++;
	}

	rc = 1;
	LOG2(opts, "non-recursively generated %zu filenames", *sz);
	qsort(fl, *sz, sizeof(struct flist), flist_cmp);
out:
	if (0 == rc) {
		/* Use original size to catch last entry. */
		flist_free(fl, argc);
		*sz = 0;
		fl = NULL;
	}
	return fl;
}

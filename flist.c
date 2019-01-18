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
 * We allocate our file list in chunk sizes so as not to do it one by
 * one.
 * Preferrably we get one or two allocation.
 */
#define	FLIST_CHUNK_SIZE (1024)

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

/*
 * This is a list of all of the mode bits that we accept.
 * Specifically, we only allow for permissions: no sticky bits, no
 * setuid or setgid, no special bits.
 */
static	const mode_t whitelist_modes[] = {
	S_IRUSR, /* R for owner */
	S_IWUSR, /* W for owner */
	S_IXUSR, /* X for owner */
	S_IRGRP, /* R for group */
	S_IWGRP, /* W for group */
	S_IXGRP, /* X for group */
	S_IROTH, /* R for other */
	S_IWOTH, /* W for other */
	S_IXOTH, /* X for other */
	S_IFREG, /* regular */
	S_IFDIR, /* directory */
	0
};

/*
 * Straightforward way to sort a filename list.
 * This allows us to easily deduplicate.
 * FIXME: we need to canonicalise paths before doing this.
 */
static int
flist_cmp(const void *p1, const void *p2)
{
	const struct flist *f1 = p1, *f2 = p2;

	return strcmp(f1->path, f2->path);
}

/*
 * Sort and deduplicate our file list.
 */
static void
flist_fixup(const struct opts *opts, struct flist *fl, size_t *sz)
{
	size_t	 i;

	qsort(fl, *sz, sizeof(struct flist), flist_cmp);

	for (i = 0; i < *sz - 1; i++) {
		if (strcmp(fl[i].path, fl[i + 1].path))
			continue;
		WARN2(opts, "duplicate path: %s", fl[i + 1].path);
		/* TODO. */
	}
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
 * Construct pathname-related fields of flist.
 * Note that the filename component can be empty in the event of
 * directories, so that's not checked for zero length.
 */
static void
flist_copy_path(struct flist *f)
{

	assert(NULL != f->path);
	assert(f->pathlen);

	if (NULL == (f->filename = strrchr(f->path, '/')))
		f->filename = f->path;
	else
		f->filename++;

	f->filenamelen = strlen(f->filename);
	if (f->filename == f->path)
		f->dirlen = 0;
	else
		f->dirlen = f->filename - f->path - 1;
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

		/*
		 * If we're recursive, send the full path.
		 * Otherwise, send just the filename portion.
		 */

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
	uint8_t		 bval;
	size_t		 partial = 0;
	size_t		 pathlen = 0;

	/*
	 * Read our filename.
	 * If we have FLIST_NAME_SAME, we inherit some of the last
	 * transmitted name.
	 * If we have FLIST_NAME_LONG, then the string length is greater
	 * than byte-size.
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
		if ( ! io_read_size(opts, fd, &pathlen)) {
			ERRX1(opts, "io_read_size: "
				"filename length");
			return 0;
		}
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
	if (0 == f->pathlen) {
		ERRX(opts, "zero-length pathname");
		return 0;
	}

	if (NULL == (f->path = malloc(f->pathlen + 1))) {
		ERR(opts, "malloc");
		return 0;
	}
	f->path[f->pathlen] = '\0';

	if (FLIST_NAME_SAME & flags)
		memcpy(f->path, last, partial);

	if ( ! io_read_buf(opts, fd, f->path + partial, pathlen)) {
		ERRX1(opts, "io_read_buf: filename");
		return 0;
	}

	/* 
	 * Security: don't allow backtracking along the path.
	 * Our sender should canonicalise the path, so we shouldn't get
	 * anything like this.
	 */

	if (NULL != strstr(f->path, "/../") ||
	    (f->pathlen >= 3 && 
	     0 == strncmp(f->path, "../", 3)) ||
	    (f->pathlen >= 3 && 
	     0 == strcmp(f->path + f->pathlen - 3, "/.."))) {
		ERRX(opts, "backtracking path: %s", f->path);
		return 0;
	}

	/* Record our last path and construct our filename. */

	strlcpy(last, f->path, MAXPATHLEN);
	flist_copy_path(f);
	return 1;
}

static int
flist_recv_mode(const struct opts *opts, int fd, 
	struct flist *f, uint8_t flag, const struct flist *flast)
{
	int32_t	 ival;
	size_t	 i;
	mode_t	 m;

	/* Read the file mode. */

	if ( ! (FLIST_MODE_SAME & flag)) {
		if ( ! io_read_int(opts, fd, &ival)) {
			ERRX1(opts, "io_read_int: file mode");
			return 0;
		}
		m = ival;
	} else if (NULL == flast) {
		ERRX(opts, "same mode without last entry");
		return 0;
	} else
		m = flast->st.mode;

	/*
	 * We can have all sorts of weird modes: instead of trying to
	 * strip them all out here, we instead white-list the modes that
	 * we accept and only work with those.
	 */

	if (opts->recursive) {
		if ( ! S_ISREG(m) && ! S_ISDIR(m)) {
			ERRX(opts, "non-regular non-directory file "
				"in recursive mode: %s", f->path);
			return 0;
		}
	} else {
		if ( ! S_ISREG(m)) {
			ERRX(opts, "non-regular file in "
				"non-recursive mode: %s", f->path);
			return 0;
		} 
	}

	f->st.mode = 0;
	for (i = 0; 0 != whitelist_modes[i]; i++) {
		if ( ! (whitelist_modes[i] & m))
			continue;
		m &= ~whitelist_modes[i];
		f->st.mode |= whitelist_modes[i];
	}
	if (m)
		WARNX(opts, "some file modes not "
			"whitelisted: %8o: %s", m, f->path);

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

		/* Allocate in chunks instead of one by one. */

		if (flsz + 1 > flmax) {
			pp = recallocarray(fl, flmax, 
				flmax + FLIST_CHUNK_SIZE, 
				 sizeof(struct flist));
			if (NULL == pp) {
				ERR(opts, "recallocarray");
				goto out;
			}
			fl = pp;
			flmax += FLIST_CHUNK_SIZE;
		}
		flsz++;

		ff = &fl[flsz - 1];
		fflast = flsz > 1 ? &fl[flsz - 2] : NULL;

		if ( ! flist_recv_filename
		    (opts, fd, ff, flag, lastname)) {
			ERRX1(opts, "flist_recv_filename");
			goto out;
		}

		/* Read the file size. */

		if ( ! io_read_long(opts, fd, &lval)) {
			ERRX1(opts, "io_read_long: file size");
			goto out;
		} else if (lval < 0) {
			ERRX(opts, "negative file size");
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

		if ( ! flist_recv_mode(opts, fd, ff, flag, fflast)) {
			ERRX(opts, "flist_recv_mode");
			goto out;
		} 

		LOG3(opts, "received file metadata: %s "
			"(size %llu, mtime %lld, mode %o)",
			ff->path, ff->st.size, ff->st.mtime, ff->st.mode);
	}

	if (0 == flsz) {
		ERRX(opts, "zero-length file list");
		goto out;
	}

	*sz = flsz;
	LOG2(opts, "received file metadata list: %zu", *sz);
	flist_fixup(opts, fl, sz);
	return fl;
out:
	flist_free(fl, flsz);
	return NULL;
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
		/*
		 * Filter through the read file information.
		 * We want directories (pre-order) and regular files.
		 * Everything else is skipped.
		 */

		if (FTS_DC == ent->fts_info) {
			WARNX(opts, "skipping directory "
				"cycle: %s", ent->fts_path);
			continue;
		} else if (FTS_DNR == ent->fts_info) {
			errno = ent->fts_errno;
			WARN(opts, "unreadable directory: "
				"%s", ent->fts_path);
			continue;
		} else if (FTS_DOT == ent->fts_info) {
			WARNX(opts, "skipping dot-file: "
				"%s", ent->fts_path);
			continue;
		} else if (FTS_ERR == ent->fts_info) {
			errno = ent->fts_errno;
			WARN(opts, "unreadable file: %s",
				ent->fts_path);
			continue;
		} else if (FTS_DEFAULT == ent->fts_info) {
			WARNX(opts, "skipping non-regular "
				"file: %s", ent->fts_path);
			continue;
		} else if (FTS_NS == ent->fts_info) {
			errno = ent->fts_errno;
			WARN(opts, "could not stat: %s",
				ent->fts_path);
			continue;
		} else if (FTS_SL == ent->fts_info) {
			WARNX(opts, "skipping symbolic link: "
				"%s", ent->fts_path);
			continue;
		} else if (FTS_SLNONE == ent->fts_info) {
			WARNX(opts, "skipping bad symbolic link: "
				"%s", ent->fts_path);
			continue;
		} else if (FTS_DP == ent->fts_info)
			continue;

		if (flsz + 1 > flmax) {
			pp = recallocarray(fl, flmax, 
				flmax + FLIST_CHUNK_SIZE, 
				 sizeof(struct flist));
			if (NULL == pp) {
				ERR(opts, "recallocarray");
				goto out;
			}
			fl = pp;
			flmax += FLIST_CHUNK_SIZE;
		}
		flsz++;
		f = &fl[flsz - 1];

		if (NULL == (f->path = strdup(ent->fts_path))) {
			ERR(opts, "strdup");
			goto out;
		}
		f->pathlen = ent->fts_pathlen;
		flist_copy_path(f);
		flist_copy_stat(f, ent->fts_statp);
		errno = 0;
	}
	if (errno) {
		ERR(opts, "fts_read");
		goto out;
	} else if (0 == flsz) {
		ERRX1(opts, "zero-length file list");
		goto out;
	}

	LOG2(opts, "recursively generated %zu filenames", flsz);
	rc = 1;
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

/*
 * The non-recursive version is simply going to 
 */
static struct flist *
flist_gen_nonrecursive(const struct opts *opts, 
	size_t argc, char **argv, size_t *sz)
{
	struct flist	*fl = NULL;
	size_t		 i;
	struct stat	 st;
	int		 rc = 0;

	/* We'll have at most argc. */

	if (NULL == (fl = calloc(argc, sizeof(struct flist)))) {
		ERR(opts, "calloc");
		return NULL;
	}

	/*
	 * Loop over all files and fstat them straight up.
	 * Don't allow anything but regular files for now.
	 */

	for (i = 0; i < argc; i++) {
		if ('\0' == argv[i][0]) 
			continue;
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

		/* 
		 * On the receiving end, we'll strip out all bits on the
		 * mode except for the file permissions.
		 * No need to warn about it here.
		 */

		fl[*sz].path = strdup(argv[i]);
		if (NULL == fl[*sz].path) {
			ERR(opts, "strdup");
			goto out;
		}
		fl[*sz].pathlen = strlen(argv[i]);
		flist_copy_path(&fl[*sz]);

		/* Any filename should have a filename part. */

		assert(fl[*sz].filenamelen);
		flist_copy_stat(&fl[*sz], &st);
		(*sz)++;
	}

	if (0 == *sz) {
		ERRX1(opts, "zero-length file list");
		goto out;
	}

	LOG2(opts, "non-recursively generated %zu filenames", *sz);
	rc = 1;
out:
	if (0 == rc) {
		/* Use original size to catch last entry. */
		flist_free(fl, argc);
		*sz = 0;
		fl = NULL;
	}
	return fl;
}

struct flist *
flist_gen(const struct opts *opts, size_t argc, char **argv, size_t *sz)
{
	struct flist	*f;

	*sz = 0;
	f = opts->recursive ?
		flist_gen_recursive(opts, argc, argv, sz) :
		flist_gen_nonrecursive(opts, argc, argv, sz);

	if (NULL != f)
		flist_fixup(opts, f, sz);

	return f;
}

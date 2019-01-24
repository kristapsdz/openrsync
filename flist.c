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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
	S_IFLNK, /* symbolic link */
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

	return strcmp(f1->wpath, f2->wpath);
}

/*
 * Sort and deduplicate our file list.
 */
static void
flist_fixup(struct sess *sess, struct flist *fl, size_t *sz)
{
	size_t	 i;

	qsort(fl, *sz, sizeof(struct flist), flist_cmp);

	for (i = 0; i < *sz - 1; i++) {
		if (strcmp(fl[i].path, fl[i + 1].path))
			continue;
		WARNX(sess, "duplicate path: %s", fl[i + 1].path);
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

void
flist_free(struct flist *f, size_t sz)
{
	size_t	 i;

	if (NULL == f)
		return;

	for (i = 0; i < sz; i++) {
		free(f[i].path);
		free(f[i].link);
	}
	free(f);
}

/*
 * Serialise our file list to the wire.
 * Return zero on failure, non-zero on success.
 */
int
flist_send(struct sess *sess, int fd, 
	const struct flist *fl, size_t flsz)
{
	size_t		 i, fnlen;
	uint8_t		 flag;
	const struct flist *f;
	const char	*fn;

	LOG2(sess, "sending file metadata list: %zu", flsz);

	for (i = 0; i < flsz; i++) {
		f = &fl[i];
		fn = f->wpath;
		fnlen = strlen(f->wpath);
		assert(fnlen > 0);

		/*
		 * For ease, make all of our filenames be "long"
		 * regardless their actual length.
		 * This also makes sure that we don't transmit a zero
		 * byte unintentionally.
		 */

		flag = FLIST_NAME_LONG;

		LOG3(sess, "sending file metadata: %s "
			"(size %jd, mtime %jd, mode %o)",
			fn, (intmax_t)f->st.size, 
			(intmax_t)f->st.mtime, f->st.mode);

		/* Now write to the wire. */

		if ( ! io_write_byte(sess, fd, flag)) {
			ERRX1(sess, "io_write_byte: flags");
			return 0;
		} else if ( ! io_write_int(sess, fd, fnlen)) {
			ERRX1(sess, "io_write_int: filename length");
			return 0;
		} else if ( ! io_write_buf(sess, fd, fn, fnlen)) {
			ERRX1(sess, "io_write_buf: filename");
			return 0;
		} else if ( ! io_write_long(sess, fd, f->st.size)) {
			ERRX1(sess, "io_write_long: file size");
			return 0;
		} else if ( ! io_write_int(sess, fd, f->st.mtime)) {
			ERRX1(sess, "io_write_int: file mtime");
			return 0;
		} else if ( ! io_write_int(sess, fd, f->st.mode)) {
			ERRX1(sess, "io_write_int: file mode");
			return 0; 
		}

		/* Optional link information. */

		if (S_ISLNK(f->st.mode)) {
			assert(sess->opts->preserve_links);
			fn = f->link;
			fnlen = strlen(f->link);
			if ( ! io_write_int(sess, fd, fnlen)) {
				ERRX1(sess, "io_write_int: link size");
				return 0;
			} 
			if ( ! io_write_buf(sess, fd, fn, fnlen)) {
				ERRX1(sess, "io_write_int: link");
				return 0;
			}
		}
	}

	if ( ! io_write_byte(sess, fd, 0)) {
		ERRX1(sess, "io_write_byte: zero flag");
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
flist_recv_filename(struct sess *sess, int fd, 
	struct flist *f, uint8_t flags, char last[MAXPATHLEN])
{
	uint8_t		 bval;
	size_t		 partial = 0;
	size_t		 pathlen = 0, fpathlen;

	/*
	 * Read our filename.
	 * If we have FLIST_NAME_SAME, we inherit some of the last
	 * transmitted name.
	 * If we have FLIST_NAME_LONG, then the string length is greater
	 * than byte-size.
	 */

	if (FLIST_NAME_SAME & flags) {
		if ( ! io_read_byte(sess, fd, &bval)) {
			ERRX1(sess, "io_read_byte: "
				"filename partial length");
			return 0;
		}
		partial = bval;
	}

	/* Get the (possibly-remaining) filename length. */

	if (FLIST_NAME_LONG & flags) {
		if ( ! io_read_size(sess, fd, &pathlen)) {
			ERRX1(sess, "io_read_size: "
				"filename length");
			return 0;
		}
	} else {
		if ( ! io_read_byte(sess, fd, &bval)) {
			ERRX1(sess, "io_read_byte: "
				"filename length");
			return 0;
		} 
		pathlen = bval;
	}

	/* Allocate our full filename length. */

	fpathlen = pathlen + partial;
	if (0 == fpathlen) {
		ERRX(sess, "zero-length pathname");
		return 0;
	}

	if (NULL == (f->path = malloc(fpathlen + 1))) {
		ERR(sess, "malloc");
		return 0;
	}
	f->path[fpathlen] = '\0';

	if (FLIST_NAME_SAME & flags)
		memcpy(f->path, last, partial);

	if ( ! io_read_buf(sess, fd, f->path + partial, pathlen)) {
		ERRX1(sess, "io_read_buf: filename");
		return 0;
	}

	/* 
	 * FIXME: security checks.
	 * No absolute paths.
	 * No path backtracking.
	 */

	/* Record our last path and construct our filename. */

	strlcpy(last, f->path, MAXPATHLEN);
	f->wpath = f->path;
	return 1;
}

static int
flist_recv_mode(struct sess *sess, int fd, 
	struct flist *f, uint8_t flag, const struct flist *flast)
{
	int32_t	 ival;
	size_t	 i;
	mode_t	 m;

	/* Read the file mode. */

	if ( ! (FLIST_MODE_SAME & flag)) {
		if ( ! io_read_int(sess, fd, &ival)) {
			ERRX1(sess, "io_read_int: file mode");
			return 0;
		}
		m = ival;
	} else if (NULL == flast) {
		ERRX(sess, "same mode without last entry");
		return 0;
	} else
		m = flast->st.mode;

	/*
	 * We can have all sorts of weird modes: instead of trying to
	 * strip them all out here, we instead white-list the modes that
	 * we accept and only work with those.
	 */

	if (S_ISDIR(m)) {
		if ( ! sess->opts->recursive) {
			ERRX(sess, "directory: %s", f->path);
			return 0;
		}
	} else if (S_ISLNK(m)) {
		if ( ! sess->opts->preserve_links) {
			ERRX(sess, "symlink file: %s", f->path);
			return 0;
		}
	} else if ( ! S_ISREG(m)) {
		ERRX(sess, "non-regular file: %s", f->path);
		return 0;
	}

	/* Scrub the mode. */

	f->st.mode = 0;
	for (i = 0; 0 != whitelist_modes[i]; i++) {
		if ( ! (whitelist_modes[i] & m))
			continue;
		m &= ~whitelist_modes[i];
		f->st.mode |= whitelist_modes[i];
	}
	if (m)
		WARNX(sess, "some file modes not "
			"whitelisted: %8o: %s", m, f->path);

	return 1;
}

/*
 * Receive a file list of length "sz" from the wire.
 * Return the file list or NULL on failure ("sz" will be zero).
 */
struct flist *
flist_recv(struct sess *sess, int fd, size_t *sz)
{
	struct flist	*fl = NULL;
	struct flist	*ff;
	const struct flist *fflast;
	size_t		 flsz = 0, flmax = 0, lsz;
	uint8_t		 flag;
	void		*pp;
	char		 lastname[MAXPATHLEN];
	int64_t		 lval; /* temporary values... */
	int32_t		 ival;

	*sz = 0;
	lastname[0] = '\0';
	fflast = NULL;

	for (;;) {
		if ( ! io_read_byte(sess, fd, &flag)) {
			ERRX1(sess, "io_read_byte: flags");
			goto out;
		} else if (0 == flag)
			break;

		/* Allocate in chunks instead of one by one. */

		if (flsz + 1 > flmax) {
			pp = recallocarray(fl, flmax, 
				flmax + FLIST_CHUNK_SIZE, 
				 sizeof(struct flist));
			if (NULL == pp) {
				ERR(sess, "recallocarray");
				goto out;
			}
			fl = pp;
			flmax += FLIST_CHUNK_SIZE;
		}
		flsz++;

		ff = &fl[flsz - 1];
		fflast = flsz > 1 ? &fl[flsz - 2] : NULL;

		if ( ! flist_recv_filename
		    (sess, fd, ff, flag, lastname)) {
			ERRX1(sess, "flist_recv_filename");
			goto out;
		}

		/* Read the file size. */

		if ( ! io_read_long(sess, fd, &lval)) {
			ERRX1(sess, "io_read_long: file size");
			goto out;
		} else if (lval < 0) {
			ERRX(sess, "negative file size");
			goto out;
		}
		ff->st.size = lval;

		/* Read the modification time. */

		if ( ! (FLIST_TIME_SAME & flag)) {
			if ( ! io_read_int(sess, fd, &ival)) {
				ERRX1(sess, "io_read_int: file mtime");
				goto out;
			}
			ff->st.mtime = ival;
		} else if (NULL == fflast) {
			ERRX(sess, "same time without last entry");
			goto out;
		}  else
			ff->st.mtime = fflast->st.mtime;

		/* 
		 * Read the file mode.
		 * This will make sure that, if we return with success,
		 * the file (directory, link, regular) is acceptable.
		 */

		if ( ! flist_recv_mode(sess, fd, ff, flag, fflast)) {
			ERRX(sess, "flist_recv_mode");
			goto out;
		} 

		/* Optionally read the link information. */

		if (S_ISLNK(ff->st.mode)) {
			assert(sess->opts->preserve_links);
			if ( ! io_read_size(sess, fd, &lsz)) {
				ERRX1(sess, "io_read_size: link size");
				goto out;
			} else if (0 == lsz) {
				ERRX(sess, "empty link name");
				goto out;
			}
			ff->link = calloc(lsz + 1, 1);
			if (NULL == ff->link) {
				ERR(sess, "calloc");
				goto out;
			}
			if ( ! io_read_buf(sess, fd, ff->link, lsz)) {
				ERRX1(sess, "io_read_buf: link");
				goto out;
			}
		}

		LOG3(sess, "received file metadata: %s "
			"(size %jd, mtime %jd, mode %o)",
			ff->path, (intmax_t)ff->st.size, 
			(intmax_t)ff->st.mtime, ff->st.mode);
	}

	if (0 == flsz) {
		/* FIXME: shouldn't be an error. */
		ERRX(sess, "zero-length file list");
		goto out;
	}

	*sz = flsz;
	LOG2(sess, "received file metadata list: %zu", *sz);
	flist_fixup(sess, fl, sz);
	return fl;
out:
	flist_free(fl, flsz);
	return NULL;
}

static int
flist_gen_recursive_entry(struct sess *sess, char *root, 
	struct flist **fl, size_t *sz, size_t *max)
{
	char		*cargv[2], *cp;
	int		 rc = 0;
	FTS		*fts;
	FTSENT		*ent;
	struct flist	*f;
	size_t		 flsz = 0, stripdir;
	void		*pp;
	struct stat	 st;

	cargv[0] = root;
	cargv[1] = NULL;

	/* 
	 * If we're a file, then revert to the same actions we use for
	 * the non-recursive scan.
	 * FIXME: abstract this part.
	 */

	if (-1 == lstat(root, &st)) {
		ERR(sess, "lstat: %s", root);
		return 0;
	} else if (S_ISREG(st.st_mode)) {
		if (*sz + 1 > *max) {
			pp = recallocarray(*fl, *max, 
				*max + FLIST_CHUNK_SIZE, 
				sizeof(struct flist));
			if (NULL == pp) {
				ERR(sess, "recallocarray");
				return 0;
			}
			*fl = pp;
			*max += FLIST_CHUNK_SIZE;
		}
		f = &(*fl)[(*sz)++];
		assert(NULL != f);
		if (NULL == (f->path = strdup(root))) {
			ERR(sess, "strdup");
			return 0;
		}
		if (NULL == (f->wpath = strrchr(f->path, '/')))
			f->wpath = f->path;
		else
			f->wpath++;

		flist_copy_stat(f, &st);
		return 1;
	} else if ( ! S_ISDIR(st.st_mode)) {
		WARNX(sess, "neither directory nor file: %s", root);
		return 0;
	}

	/*
	 * If we end with a slash, it means that we're not supposed to
	 * copy the directory part itself---only the contents.
	 * So set "stripdir" to be what we take out.
	 */

	stripdir = strlen(root);
	assert(stripdir > 0);
	if ('/' != root[stripdir - 1])
		stripdir = 0;

	/*
	 * If we're not stripping anything, then see if we need to strip
	 * out the leading material in the path up to and including the
	 * last directory component.
	 */

	if (0 == stripdir) 
		if (NULL != (cp = strrchr(root, '/')))
			stripdir = cp - root + 1;

	/*
	 * If we're recursive, then we need to take down all of the
	 * files and directory components, so use fts(3).
	 * Copying the information file-by-file into the flstat.
	 * We'll make sense of it in flist_send.
	 */

	if (NULL == (fts = fts_open(cargv, FTS_LOGICAL, NULL))) {
		ERR(sess, "fts_open");
		return 0;
	}

	errno = 0;
	while (NULL != (ent = fts_read(fts))) {
		/*
		 * Filter through the read file information.
		 * We want directories (pre-order) and regular files.
		 * Everything else is skipped.
		 */

		if (FTS_DC == ent->fts_info) {
			WARNX(sess, "skipping directory "
				"cycle: %s", ent->fts_path);
			continue;
		} else if (FTS_DNR == ent->fts_info) {
			errno = ent->fts_errno;
			WARN(sess, "unreadable directory: "
				"%s", ent->fts_path);
			continue;
		} else if (FTS_DOT == ent->fts_info) {
			WARNX(sess, "skipping dot-file: "
				"%s", ent->fts_path);
			continue;
		} else if (FTS_ERR == ent->fts_info) {
			errno = ent->fts_errno;
			WARN(sess, "unreadable file: %s",
				ent->fts_path);
			continue;
		} else if (FTS_DEFAULT == ent->fts_info) {
			WARNX(sess, "skipping non-regular "
				"file: %s", ent->fts_path);
			continue;
		} else if (FTS_NS == ent->fts_info) {
			errno = ent->fts_errno;
			WARN(sess, "could not stat: %s",
				ent->fts_path);
			continue;
		} else if (FTS_SL == ent->fts_info) {
			WARNX(sess, "skipping symbolic link: "
				"%s", ent->fts_path);
			continue;
		} else if (FTS_SLNONE == ent->fts_info) {
			WARNX(sess, "skipping bad symbolic link: "
				"%s", ent->fts_path);
			continue;
		} else if (FTS_DP == ent->fts_info)
			continue;

		if (*sz + 1 > *max) {
			pp = recallocarray(*fl, *max, 
				*max + FLIST_CHUNK_SIZE, 
				sizeof(struct flist));
			if (NULL == pp) {
				ERR(sess, "recallocarray");
				goto out;
			}
			*fl = pp;
			*max += FLIST_CHUNK_SIZE;
		}
		(*sz)++;
		flsz++;
		f = &(*fl)[*sz - 1];

		if ('\0' == ent->fts_path[stripdir]) {
			if (asprintf(&f->path, "%s.", ent->fts_path) < 0) {
				ERR(sess, "asprintf");
				goto out;
			}
		} else {
			if (NULL == (f->path = strdup(ent->fts_path))) {
				ERR(sess, "strdup");
				goto out;
			}
		}
		f->wpath = f->path + stripdir;
		flist_copy_stat(f, ent->fts_statp);
		errno = 0;
	}
	if (errno) {
		ERR(sess, "fts_read");
		goto out;
	}

	LOG3(sess, "generated %zu filenames: %s", flsz, root);
	rc = 1;
out:
	fts_close(fts);
	return rc;
}

/*
 * Generate a flist recursively given the array of directories (or
 * files, doesn't matter) specified in argv.
 */
static struct flist *
flist_gen_recursive(struct sess *sess, 
	size_t argc, char **argv, size_t *sz)
{
	int		 rc;
	struct flist	*fl = NULL;
	size_t		 max = 0;
	size_t		 i;

	for (i = 0; i < argc; i++) {
		rc = flist_gen_recursive_entry
			(sess, argv[i], &fl, sz, &max);
		if (0 == rc)
			break;
	}

	if (i < argc) {
		ERRX1(sess, "flist_gen_recursive_entry");
		flist_free(fl, *sz);
		fl = NULL;
		*sz = 0;
	} else if (0 == *sz) {
		/* FIXME: shouldn't be an error. */
		ERRX(sess, "zero-length file list");
		flist_free(fl, *sz);
		fl = NULL;
	} else
		LOG2(sess, "recursively generated %zu filenames", *sz);

	return fl;
}

static struct flist *
flist_gen_nonrecursive(struct sess *sess, 
	size_t argc, char **argv, size_t *sz)
{
	struct flist	*fl = NULL, *f;
	size_t		 i;
	struct stat	 st;
	int		 rc = 0;

	/* We'll have at most argc. */

	if (NULL == (fl = calloc(argc, sizeof(struct flist)))) {
		ERR(sess, "calloc");
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
			ERR(sess, "fstat: %s", argv[i]);
			goto out;
		} else if (S_ISDIR(st.st_mode)) {
			WARNX(sess, "skipping directory: %s", argv[i]);
			continue;
		} else if (S_ISLNK(st.st_mode)) {
			if ( ! sess->opts->preserve_links) {
				WARNX(sess, "skipping symbolic "
					"link: %s", argv[i]);
				continue;
			}
		} else if ( ! S_ISREG(st.st_mode)) {
			WARNX(sess, "skipping non-regular: %s", argv[i]);
			continue;
		}

		f = &fl[(*sz)++];
		assert(NULL != f);

		/* 
		 * Copy the full path for local addressing and transmit
		 * only the filename part for the receiver.
		 */

		if (NULL == (f->path = strdup(argv[i]))) {
			ERR(sess, "strdup");
			goto out;
		}

		if (NULL == (f->wpath = strrchr(f->path, '/')))
			f->wpath = f->path;
		else
			f->wpath++;

		/* 
		 * On the receiving end, we'll strip out all bits on the
		 * mode except for the file permissions.
		 * No need to warn about it here.
		 */

		flist_copy_stat(f, &st);

		/* Optionally copy link information. */

		if (S_ISLNK(st.st_mode)) {
			f->link = symlink_read(sess, f->path);
			if (NULL == f->link) {
				ERRX1(sess, "symlink_read");
				goto out;
			}
		}
	}

	/* FIXME: shouldn't be an error. */

	if (0 == *sz) {
		ERRX1(sess, "zero-length file list");
		goto out;
	}

	LOG2(sess, "non-recursively generated %zu filenames", *sz);
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
flist_gen(struct sess *sess, size_t argc, char **argv, size_t *sz)
{
	struct flist	*f;

	*sz = 0;
	f = sess->opts->recursive ?
		flist_gen_recursive(sess, argc, argv, sz) :
		flist_gen_nonrecursive(sess, argc, argv, sz);

	if (NULL != f)
		flist_fixup(sess, f, sz);

	return f;
}

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
#include <fcntl.h>
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
 * Requied way to sort a filename list.
 */
static int
flist_cmp(const void *p1, const void *p2)
{
	const struct flist *f1 = p1, *f2 = p2;

	return strcmp(f1->wpath, f2->wpath);
}

/*
 * Deduplicate our file list (which may be zero-length).
 * Returns zero on failure, non-zero on success.
 */
static int
flist_dedupe(struct sess *sess, struct flist **fl, size_t *sz)
{
	size_t	 	 i, j;
	struct flist	*new;
	struct flist	*f, *fnext;

	if (0 == *sz)
		return 1;

	/* Create a new buffer, "new", and copy. */

	new = calloc(*sz, sizeof(struct flist));
	if (NULL == new) {
		ERR(sess, "calloc");
		return 0;
	}

	for (i = j = 0; i < *sz - 1; i++) {
		f = &(*fl)[i];
		fnext = &(*fl)[i + 1];

		if (strcmp(f->wpath, fnext->wpath)) {
			new[j++] = *f;
			continue;
		}

		/*
		 * Our working (destination) paths are the same.
		 * If the actual file is the same (as given on the
		 * command-line), then we can just discard the first.
		 * Otherwise, we need to bail out: it means we have two
		 * different files with the relative path on the
		 * destination side.
		 */

		if (0 == strcmp(f->path, fnext->path)) {
			new[j++] = *f;
			i++;
			WARNX(sess, "duplicate path: %s (%s)",
				f->wpath, f->path);
			free(fnext->path);
			free(fnext->link);
			fnext->path = fnext->link = NULL;
			continue;
		} 

		ERRX(sess, "duplicate working path for "
			"possibly different file: %s: %s, %s",
			f->wpath, f->path, fnext->path);
		free(new);
		return 0;
	}

	/* Don't forget the last entry. */

	if (i == *sz - 1)
		new[j++] = (*fl)[i];

	/* 
	 * Reassign to the deduplicated array.
	 * If we started out with *sz > 0, which we check for at the
	 * beginning, then we'll always continue having *sz > 0.
	 */

	free(*fl);
	*fl = new;
	*sz = j;
	assert(*sz);
	return 1;
}

/*
 * Filter through the fts() file information.
 * We want directories (pre-order), regular files, and symlinks.
 * Everything else is skipped and possibly warned about.
 * Return zero to skip, non-zero to examine.
 */
static int
flist_fts_check(struct sess *sess, FTSENT *ent)
{

	if (FTS_F == ent->fts_info ||
	    FTS_D == ent->fts_info ||
	    FTS_SL == ent->fts_info ||
	    FTS_SLNONE == ent->fts_info)
		return 1;

	if (FTS_DC == ent->fts_info) {
		WARNX(sess, "directory cycle: %s", ent->fts_path);
	} else if (FTS_DNR == ent->fts_info) {
		errno = ent->fts_errno;
		WARN(sess, "unreadable directory: %s", ent->fts_path);
	} else if (FTS_DOT == ent->fts_info) {
		WARNX(sess, "skipping dot-file: %s", ent->fts_path);
	} else if (FTS_ERR == ent->fts_info) {
		errno = ent->fts_errno;
		WARN(sess, "%s", ent->fts_path);
	} else if (FTS_DEFAULT == ent->fts_info) {
		WARNX(sess, "skipping special: %s", ent->fts_path);
	} else if (FTS_NS == ent->fts_info) {
		errno = ent->fts_errno;
		WARN(sess, "could not stat: %s", ent->fts_path);
	} 

	return 0;
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
 * Serialise our file list (which may be zero-length) to the wire.
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

		if (S_ISLNK(f->st.mode) &&
		    sess->opts->preserve_links) {
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
 * Read the filename of a file list.
 * This is the most expensive part of the file list transfer, so a lot
 * of attention has gone into transmitting as little as possible.
 * Micro-optimisation, but whatever.
 * Fills in "f" with the full path on success.
 * Returns zero on failure, non-zero on success.
 */
static int
flist_recv_name(struct sess *sess, int fd, 
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
	/* FIXME: maximum pathname length. */

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

/*
 * Reallocate a file list in chunks of FLIST_CHUNK_SIZE;
 * Returns zero on failure, non-zero on success.
 */
static int
flist_realloc(struct sess *sess, 
	struct flist **fl, size_t *sz, size_t *max)
{
	void	*pp;

	if (*sz + 1 <= *max)  {
		(*sz)++;
		return 1;
	}

	pp = recallocarray(*fl, *max, 
		*max + FLIST_CHUNK_SIZE, sizeof(struct flist));
	if (NULL == pp) {
		ERR(sess, "recallocarray");
		return 0;
	}
	*fl = pp;
	*max += FLIST_CHUNK_SIZE;
	(*sz)++;
	return 1;
}

/*
 * Copy a regular or symbolic link file "path" into "f".
 * This handles the correct path creation and symbolic linking.
 * Returns zero on failure, non-zero on success.
 */
static int
flist_append(struct sess *sess, struct flist *f, 
	struct stat *st, const char *path)
{

	/* 
	 * Copy the full path for local addressing and transmit
	 * only the filename part for the receiver.
	 */

	if (NULL == (f->path = strdup(path))) {
		ERR(sess, "strdup");
		return 0;
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

	flist_copy_stat(f, st);

	/* Optionally copy link information. */

	if (S_ISLNK(st->st_mode)) {
		f->link = symlink_read(sess, f->path);
		if (NULL == f->link) {
			ERRX1(sess, "symlink_read");
			return 0;
		}
	}

	return 1;
}

/*
 * Receive a file list from the wire, filling in length "sz" (which may
 * possibly be zero) and list "flp" on success.
 * Return zero on failure, non-zero on success.
 */
int
flist_recv(struct sess *sess, int fd, struct flist **flp, size_t *sz)
{
	struct flist	*fl = NULL;
	struct flist	*ff;
	const struct flist *fflast = NULL;
	size_t		 flsz = 0, flmax = 0, lsz;
	uint8_t		 flag;
	char		 last[MAXPATHLEN];
	int64_t		 lval; /* temporary values... */
	int32_t		 ival;

	last[0] = '\0';

	for (;;) {
		if ( ! io_read_byte(sess, fd, &flag)) {
			ERRX1(sess, "io_read_byte: flags");
			goto out;
		} else if (0 == flag)
			break;

		if ( ! flist_realloc(sess, &fl, &flsz, &flmax)) {
			ERRX1(sess, "flist_realloc");
			goto out;
		}

		ff = &fl[flsz - 1];
		fflast = flsz > 1 ? &fl[flsz - 2] : NULL;

		/* Filename first. */

		if ( ! flist_recv_name(sess, fd, ff, flag, last)) {
			ERRX1(sess, "flist_recv_name");
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

		/* Read the file mode. */

		if ( ! (FLIST_MODE_SAME & flag)) {
			if ( ! io_read_int(sess, fd, &ival)) {
				ERRX1(sess, "io_read_int: file mode");
				goto out;
			}
			ff->st.mode = ival;
		} else if (NULL == fflast) {
			ERRX(sess, "same mode without last entry");
			goto out;
		} else
			ff->st.mode = fflast->st.mode;

		/* Optionally read the link information. */

		if (S_ISLNK(ff->st.mode) &&
		    sess->opts->preserve_links) {
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

	/* Remember to order the received list. */

	qsort(fl, flsz, sizeof(struct flist), flist_cmp);
	LOG2(sess, "received file metadata list: %zu", flsz);
	*sz = flsz;
	*flp = fl;
	return 1;
out:
	flist_free(fl, flsz);
	*sz = 0;
	*flp = NULL;
	return 0;
}

/*
 * Generate a flist possibly-recursively given a file root, which may
 * also be a regular file or symlink.
 * On success, augments the generated list in "flp" of length "sz".
 * Returns zero on failure, non-zero on success.
 */
static int
flist_gen_dirent(struct sess *sess, char *root, 
	struct flist **fl, size_t *sz, size_t *max)
{
	char		*cargv[2], *cp;
	int		 rc = 0;
	FTS		*fts;
	FTSENT		*ent;
	struct flist	*f;
	size_t		 flsz = 0, stripdir;
	struct stat	 st;

	cargv[0] = root;
	cargv[1] = NULL;

	/* 
	 * If we're a file, then revert to the same actions we use for
	 * the non-recursive scan.
	 */

	if (-1 == lstat(root, &st)) {
		ERR(sess, "lstat: %s", root);
		return 0;
	} else if (S_ISREG(st.st_mode)) {
		if ( ! flist_realloc(sess, fl, sz, max)) {
			ERRX1(sess, "flist_realloc");
			return 0;
		}
		f = &(*fl)[(*sz) - 1];
		assert(NULL != f);
		if ( ! flist_append(sess, f, &st, root)) {
			ERRX1(sess, "flist_append");
			return 0;
		}
		return 1;
	} else if (S_ISLNK(st.st_mode)) {
		if ( ! sess->opts->preserve_links) {
			WARNX(sess, "skipping symlink: %s", root);
			return 1;
		} else if ( ! flist_realloc(sess, fl, sz, max)) {
			ERRX1(sess, "flist_realloc");
			return 0;
		}
		f = &(*fl)[(*sz) - 1];
		assert(NULL != f);
		if ( ! flist_append(sess, f, &st, root)) {
			ERRX1(sess, "flist_append");
			return 0;
		}
		return 1;
	} else if ( ! S_ISDIR(st.st_mode)) {
		WARNX(sess, "skipping special: %s", root);
		return 1;
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

	if (NULL == (fts = fts_open(cargv, FTS_PHYSICAL, NULL))) {
		ERR(sess, "fts_open");
		return 0;
	}

	errno = 0;
	while (NULL != (ent = fts_read(fts))) {
		if ( ! flist_fts_check(sess, ent)) {
			errno = 0;
			continue;
		}

		/* We don't allow symlinks without -l. */

		assert(NULL != ent->fts_statp);
		if (S_ISLNK(ent->fts_statp->st_mode) && 
		    ! sess->opts->preserve_links) {
			WARNX(sess, "skipping "
				"symlink: %s", ent->fts_path);
			continue;
		} 

		/* Allocate a new file entry. */

		if ( ! flist_realloc(sess, fl, sz, max)) {
			ERRX1(sess, "flist_realloc");
			goto out;
		}
		flsz++;
		f = &(*fl)[*sz - 1];

		/* Our path defaults to "." for the root. */

		if ('\0' == ent->fts_path[stripdir]) {
			if (asprintf(&f->path, "%s.", ent->fts_path) < 0) {
				ERR(sess, "asprintf");
				f->path = NULL;
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

		/* Optionally copy link information. */

		if (S_ISLNK(ent->fts_statp->st_mode)) {
			f->link = symlink_read(sess, f->path);
			if (NULL == f->link) {
				ERRX1(sess, "symlink_read");
				goto out;
			}
		}

		/* Reset errno for next fts_read() call. */
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
 * files, symlinks, doesn't matter) specified in argv (argc >0).
 * On success, stores the generated list in "flp" with length "sz",
 * which may be zero.
 * Returns zero on failure, non-zero on success.
 */
static int
flist_gen_dirs(struct sess *sess, size_t argc, 
	char **argv, struct flist **flp, size_t *sz)
{
	size_t		 i, max = 0;

	for (i = 0; i < argc; i++)
		if ( ! flist_gen_dirent(sess, argv[i], flp, sz, &max))
			break;

	if (i == argc) {
		LOG2(sess, "recursively generated %zu filenames", *sz);
		return 1;
	}

	ERRX1(sess, "flist_gen_dirent");
	flist_free(*flp, max);
	*flp = NULL;
	*sz = 0;
	return 0;
}

/*
 * Generate list of files from the command-line argc (>0) and argv.
 * On success, stores the generated list in "flp" with length "sz",
 * which may be zero.
 * Returns zero on failure, non-zero on success.
 */
static int
flist_gen_files(struct sess *sess, size_t argc, 
	char **argv, struct flist **flp, size_t *sz)
{
	struct flist	*fl = NULL, *f;
	size_t		 i, flsz = 0;
	struct stat	 st;

	assert(argc);

	if (NULL == (fl = calloc(argc, sizeof(struct flist)))) {
		ERR(sess, "calloc");
		return 0;
	}

	for (i = 0; i < argc; i++) {
		if ('\0' == argv[i][0]) 
			continue;
		if (-1 == lstat(argv[i], &st)) {
			ERR(sess, "lstat: %s", argv[i]);
			goto out;
		}

		/* 
		 * File type checks.
		 * In non-recursive mode, we don't accept directories.
		 * We also skip symbolic links without -l.
		 * Beyond that, we only accept regular files.
		 */

		if (S_ISDIR(st.st_mode)) {
			WARNX(sess, "skipping directory: %s", argv[i]);
			continue;
		} else if (S_ISLNK(st.st_mode)) {
			if ( ! sess->opts->preserve_links) {
				WARNX(sess, "skipping "
					"symlink: %s", argv[i]);
				continue;
			}
		} else if ( ! S_ISREG(st.st_mode)) {
			WARNX(sess, "skipping special: %s", argv[i]);
			continue;
		}

		f = &fl[flsz++];
		assert(NULL != f);
		if ( ! flist_append(sess, f, &st, argv[i])) {
			ERRX1(sess, "flist_append");
			goto out;
		}
	}

	LOG2(sess, "non-recursively generated %zu filenames", flsz);
	*sz = flsz;
	*flp = fl;
	return 1;
out:
	flist_free(fl, argc);
	*sz = 0;
	*flp = NULL;
	return 0;
}

/*
 * Generate a sorted, de-duplicated list of file metadata.
 * In non-recursive mode (the default), we use only the files we're
 * given.
 * Otherwise, directories are recursively examined.
 * Returns zero on failure, non-zero on success.
 * On success, "fl" will need to be freed with flist_free().
 */
int
flist_gen(struct sess *sess, size_t argc, 
	char **argv, struct flist **flp, size_t *sz)
{
	int	 rc;

	assert(argc > 0);
	rc = sess->opts->recursive ?
		flist_gen_dirs(sess, argc, argv, flp, sz) :
		flist_gen_files(sess, argc, argv, flp, sz);
	if ( ! rc)
		return 0;

	qsort(*flp, *sz, sizeof(struct flist), flist_cmp);

	if (flist_dedupe(sess, flp, sz))
		return 1;

	ERRX1(sess, "flist_dedupe");
	flist_free(*flp, *sz);
	*flp = NULL;
	*sz = 0;
	return 0;
}

/*
 * Generate a sorted list of files starting at (but not including)
 * "root" and descended into recursively.
 * Only handles symbolic links, directories, and regular files.
 * Returns zero on failure, non-zero on success.
 * On success, "fl" will need to be freed with flist_free().
 */
int
flist_gen_local(struct sess *sess, 
	const char *root, struct flist **fl, size_t *sz)
{
	char		*cargv[2];
	int		 rc = 0;
	FTS		*fts;
	FTSENT		*ent;
	struct flist	*f;
	size_t		 max = 0, stripdir;

	if (NULL == (cargv[0] = strdup(root))) {
		ERR(sess, "strdup");
		return 0;
	}
	cargv[1] = NULL;

	/* Strip away the root, since everything is relative to it. */

	stripdir = strlen(root) + 1;

	/* 
	 * XXX: this only runs properly prior to unveil().
	 * The caller needs to make sure that unveil() is not called
	 * prior to this function.
	 */

	if (NULL == (fts = fts_open(cargv, FTS_PHYSICAL, NULL))) {
		ERR(sess, "fts_open");
		free(cargv[0]);
		return 0;
	}

	errno = 0;
	while (NULL != (ent = fts_read(fts))) {
		if ( ! flist_fts_check(sess, ent)) {
			errno = 0;
			continue;
		} else if (stripdir >= ent->fts_pathlen)
			continue;

		if ( ! flist_realloc(sess, fl, sz, &max)) {
			ERRX1(sess, "flist_realloc");
			goto out;
		}
		f = &(*fl)[*sz - 1];

		if (NULL == (f->path = strdup(ent->fts_path))) {
			ERR(sess, "strdup");
			goto out;
		}
		f->wpath = f->path + stripdir;
		assert(NULL != ent->fts_statp);
		flist_copy_stat(f, ent->fts_statp);
		errno = 0;
	}

	if (errno) {
		ERR(sess, "fts_read");
		goto out;
	}

	qsort(*fl, *sz, sizeof(struct flist), flist_cmp);
	rc = 1;
out:
	fts_close(fts);
	free(cargv[0]);
	return rc;
}

/*
 * Given the files that the system has ("have") and what we're going to
 * update ("want"), delete all files and directories in "have" not found
 * in "want".
 * If dry_run is specified, simply write what would be done.
 * Return zero on failure, non-zero on success.
 */
int
flist_del(struct sess *sess, int root, 
	const struct flist *have, size_t havesz, 
	const struct flist *want, size_t wantsz)
{
	size_t	 j;
	ssize_t	 i;
	int	 fl;

	/*
	 * This is run in reverse order to catch files before
	 * directories.
	 */

	for (i = (ssize_t)havesz - 1; i >= 0; i--) {
		for (j = 0; j < wantsz; j++)
			if (0 == strcmp(have[i].wpath, want[j].wpath))
				break;
		if (j < wantsz)
			continue;
		fl = S_ISDIR(have[i].st.mode) ? AT_REMOVEDIR : 0;
		LOG1(sess, "deleting: %s", have[i].wpath);
		if (sess->opts->dry_run)
			continue;
		if (-1 == unlinkat(root, have[i].wpath, fl)) {
			ERR(sess, "unlinkat: %s", have[i].wpath);
			return 0;
		}
	}

	return 1;
}

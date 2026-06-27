/*
 * Copyright (c) Kristaps Dzonsons <kristaps@bsd.lv>
 * Copyright (c) 2019 Florian Obser <florian@openbsd.org>
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

#include <sys/types.h>
#include COMPAT_MAJOR_MINOR_H
#include <sys/param.h>
#include <sys/stat.h>
#ifdef __sun
# include <sys/mkdev.h>
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <limits.h>
#include <inttypes.h>
#include <search.h>
#include <stddef.h> /* ptrdiff_t */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"
#include "rules.h"

/*
 * We allocate our file list in chunk sizes so as not to do it one by
 * one.
 * Preferably we get one or two allocation.
 */
#define	FLIST_CHUNK_SIZE (1024)

/*
 * These flags are part of the rsync protocol.
 * They are sent as the first byte for a file transmission and encode
 * information that affects subsequent transmissions.
 */
#define FLIST_TOP_LEVEL	 0x0001 /* needed for remote --delete */
#define FLIST_MODE_SAME  0x0002 /* mode is repeat */

#define	FLIST_RDEV_SAME  0x0004 /* rdev is repeat */
#define	FLIST_UID_SAME	 0x0008 /* uid is repeat */
#define	FLIST_GID_SAME	 0x0010 /* gid is repeat */
#define	FLIST_NAME_SAME  0x0020 /* name is repeat */
#define FLIST_NAME_LONG	 0x0040 /* name >255 bytes */
#define FLIST_TIME_SAME  0x0080 /* time is repeat */

/*
 * Assert that path is non-NULL and non-empty.
 */
static inline void
flist_assert_wpath_len(const char *wpath)
{
	assert(wpath != NULL);
	assert(wpath[0] != '\0');
}

/*
 * Required way to sort a filename list before protocol 29.
 */
static int
flist_cmp(const void *p1, const void *p2)
{
	const struct flist *f1 = p1, *f2 = p2;

	return strcmp(f1->wpath, f2->wpath);
}

/*
 * Like flist_cmp(), but we need to guarantee the relative order of
 * directory contents to their directory.
 */
int
flist_dir_cmp(const void *p1, const void *p2)
{
	const struct flist	*f1 = p1, *f2 = p2;
	size_t			 s1, s2;

	s1 = strlen(f1->wpath);
	s2 = strlen(f2->wpath);

	if (strncmp(f1->wpath, f2->wpath, MINIMUM(s1, s2)) == 0) {
		/*
		 * One is the prefix of the other, sort the longer one
		 * later.
		 */
		return s2 > s1 ? 1 : -1;
	}

	return strcmp(f1->wpath, f2->wpath);
}

/*
 * Deduplicate our file list (which may be zero-length).
 */
static void
flist_dedupe(const struct opts *opts, struct flist **fl, size_t *sz)
{
	size_t		 i, j;
	struct flist	*f, *fnext;

	if (*sz < 2)
		return;

	for (i = 0, j = 1; j < *sz; j++) {
		f = &(*fl)[i];
		fnext = &(*fl)[j];

		if (strcmp(f->wpath, fnext->wpath) == 0 &&
		    strcmp(f->path, fnext->path) == 0)
			continue;

		if (++i >= j)
			continue;

		f = &(*fl)[i];
		free(f->path);
		free(f->link);

		*f = *fnext;

		fnext->path = NULL;
		fnext->link = NULL;
	}

	*sz = i + 1;
}

/*
 * Return true if "child" is a subdirectory of "cparent".
 */
static bool
flist_is_subdir(const struct flist *child, const struct flist *cparent)
{
	size_t	 parlen;

	parlen = strlen(cparent->path);
	if (strncmp(cparent->path, child->path, parlen) != 0)
		return false;

	return child->path[parlen] == '/';
}

/*
 * We're now going to find our top-level directories.
 * This only applies to recursive mode.
 * If we have the first element as the ".", then that's the "top
 * directory" of our transfer.
 * Otherwise, mark up all top-level directories in the set.
 */
static void
flist_topdirs(struct sess *sess, struct flist *fl, size_t flsz)
{
	size_t		 i; /* temporary */
	const char	*cp, /* temporary */
	      		*wpath; /* current file's wpath */
	struct flist	*ltop; /* local top-level directory */

	if (!(sess->opts->recursive || sess->opts->dirs))
		return;

	ltop = NULL;
	for (i = 0; i < flsz; i++) {
		if (!S_ISDIR(fl[i].st.mode))
			continue;
		if (ltop != NULL && flist_is_subdir(&fl[i], ltop))
			continue;

		wpath = fl[i].wpath;

		/*
		 * In --recursive mode, we don't need to worry about any
		 * of this, as all directories specified are
		 * top-directories.  In
		 * --dirs mode, we have to be more careful to only mark
		 *  those that end in '/' or '.'.
		 */

		if (!sess->opts->recursive && strcmp(wpath, ".") != 0) {
			/* Otherwise, only those ending in '/' or '/.'. */
			cp = strrchr(fl[i].wpath, '/');
			if (cp == NULL)
				continue;

			cp++;
			if (*cp != '\0' && strcmp(cp, ".") != 0)
				continue;
		}

		ltop = &fl[i];
		fl[i].st.flags |= FLSTAT_TOP_DIR;
		LOG4("%s: top-level", fl[i].wpath);
	}
}

/*
 * Filter through the fts() file information.
 * We want directories (pre-order), regular files, and symlinks.
 * Everything else is skipped and possibly warned about.
 * Return false to skip, true to examine.
 */
bool
flist_fts_check(struct sess *sess, FTSENT *ent, enum fmode fmode)
{
	if (ent->fts_info == FTS_F  ||
	    ent->fts_info == FTS_D)
		return true;

	if (ent->fts_info == FTS_DC) {
		WARNX("%s: directory cycle", ent->fts_path);
	} else if (ent->fts_info == FTS_DNR) {
		errno = ent->fts_errno;
		WARN("%s: unreadable directory", ent->fts_path);
	} else if (ent->fts_info == FTS_DOT) {
		WARNX("%s: skipping dot-file", ent->fts_path);
	} else if (ent->fts_info == FTS_ERR) {
		errno = ent->fts_errno;
		WARN("%s", ent->fts_path);
	} else if (ent->fts_info == FTS_SLNONE) {
		return sess->opts->preserve_links;
	} else if (ent->fts_info == FTS_SL) {
		/*
		 * If we're the receiver, we need to skip symlinks
		 * unless we're doing --preserve-links or
		 * --copy-dirlinks.  If we're the sender, we need to
		 *  send the link along.
		 */
		if (sess->opts->preserve_links ||
		    fmode == FARGS_SENDER)
			return true;
		WARNX("%s: skipping symlink (5)", ent->fts_path);
	} else if (ent->fts_info == FTS_DEFAULT) {
		if ((sess->opts->devices && (S_ISBLK(ent->fts_statp->st_mode) ||
		    S_ISCHR(ent->fts_statp->st_mode))) ||
		    (sess->opts->specials &&
		    (S_ISFIFO(ent->fts_statp->st_mode) ||
		    S_ISSOCK(ent->fts_statp->st_mode))) ||
		    fmode == FARGS_SENDER) {
			return true;
		}
		WARNX("%s: skipping special", ent->fts_path);
	} else if (ent->fts_info == FTS_NS) {
		errno = ent->fts_errno;
		WARN("%s: could not stat", ent->fts_path);
	}

	return false;
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
	f->st.rdev = st->st_rdev;
	f->st.device = st->st_dev;
	f->st.inode = st->st_ino;
	f->st.nlink = st->st_nlink;
}

void
flist_free(struct flist *f, size_t sz)
{
	size_t	 i;
	bool	 sender;

	if (f == NULL)
		return;

	sender = f->fmode == FARGS_SENDER;
	for (i = 0; i < sz; i++) {
		if (sender && f[i].froot != NULL) {
			froot_release(f[i].froot);
			f[i].froot = NULL;
		}
		free(f[i].path);
		free(f[i].link);
	}
	free(f);
}

/*
 * Serialise our file list (which may be zero-length) to the wire.
 * Makes sure that the receiver isn't going to block on sending us
 * return messages on the log channel.
 * Return false on failure, true on success.
 */
bool
flist_send(struct sess *sess, int fdin, int fdout, const struct flist *fl,
    size_t flsz)
{
	size_t			 i, sz, gidsz = 0, uidsz = 0, sendidsz;
	uint16_t		 flag;
	const struct flist	*f;
	const char		*fn;
	struct ident		*gids = NULL, *uids = NULL;
	bool		 	 rc = false;

	/* Double-check that we've no pending multiplexed data. */

	LOG3("sending file metadata list: %zu", flsz);

	/* Remember the flist size for keep-alive detection. */

	sess->sender_flsz = flsz;

	for (i = 0; i < flsz; i++) {
		f = &fl[i];
		fn = f->wpath;
		sz = strlen(f->wpath);
		assert(sz > 0);
		assert(sz < INT32_MAX);

		/*
		 * If applicable, unclog the read buffer.
		 * This happens when the receiver has a lot of log
		 * messages and all we're doing is sending our file list
		 * without checking for messages.
		 */

		if (sess->mplex_reads &&
		    io_read_check(sess, fdin) &&
		    !io_read_flush(sess, fdin)) {
			ERRX1("io_read_flush");
			goto out;
		}

		/*
		 * For ease, make all of our filenames be "long"
		 * regardless their actual length.
		 * This also makes sure that we don't transmit a zero
		 * byte unintentionally.
		 */

		flag = FLIST_NAME_LONG;
		if ((FLSTAT_TOP_DIR & f->st.flags))
			flag |= FLIST_TOP_LEVEL;

		LOG3("%s: sending file metadata: "
			"size %jd, mtime %jd, mode %o, flag %o",
			fn, (intmax_t)f->st.size,
			(intmax_t)f->st.mtime, f->st.mode, flag);

		/* Now write to the wire. */
		/* FIXME: buffer this. */

		/* Write: [flist-status]. */

		if (!io_write_byte(sess, fdout, flag)) {
			ERRX1("io_write_byte");
			goto out;
		}

		/* Write: [flist-name-len-long] (FIXME: condition). */
		/* Write: [flist-name]. */
		/* Write: [flist-length]. */
		/* Write: [flist-mtime]. */
		/* Write: [flist-mode]. */

		/* FIXME: compact uids/gids/etc. */

		if (!io_write_int(sess, fdout, (int)sz)) {
			ERRX1("io_write_int");
			goto out;
		} else if (!io_write_buf(sess, fdout, fn, sz)) {
			ERRX1("io_write_buf");
			goto out;
		} else if (!io_write_long(sess, fdout, f->st.size)) {
			ERRX1("io_write_long");
			goto out;
		} else if (!io_write_uint(sess, fdout, (uint32_t)f->st.mtime)) {
			ERRX1("io_write_uint");
			goto out;
		} else if (!io_write_uint(sess, fdout, f->st.mode)) {
			ERRX1("io_write_uint");
			goto out;
		}

		/* Conditional part: uid. */

		if (sess->opts->preserve_uids) {
			/* Write: [flist-uid]. */
			if (!io_write_uint(sess, fdout, f->st.uid)) {
				ERRX1("io_write_uint");
				goto out;
			}
			if (!idents_add(0, &uids, &uidsz, f->st.uid)) {
				ERRX1("idents_add");
				goto out;
			}
		}

		/* Conditional part: gid. */

		if (sess->opts->preserve_gids) {
			/* Write: [flist-gid]. */
			if (!io_write_uint(sess, fdout, f->st.gid)) {
				ERRX1("io_write_uint");
				goto out;
			}
			if (!idents_add(1, &gids, &gidsz, f->st.gid)) {
				ERRX1("idents_add");
				goto out;
			}
		}

		/* Conditional part: devices & special files. */

		if ((sess->opts->devices && (S_ISBLK(f->st.mode) ||
		    S_ISCHR(f->st.mode))) ||
		    (sess->opts->specials && (S_ISFIFO(f->st.mode) ||
		    S_ISSOCK(f->st.mode)))) {
			/* Write: [flist-rdev]. */
			if (!io_write_int(sess, fdout, f->st.rdev)) {
				ERRX1("io_write_int");
				goto out;
			}
		}

		/* Conditional part: symbolic link. */

		if (S_ISLNK(f->st.mode) &&
		    sess->opts->preserve_links) {
			fn = f->link;
			sz = strlen(f->link);
			assert(sz < INT32_MAX);
			/* Write: [flist-link-len]. */
			if (!io_write_int(sess, fdout, (int)sz)) {
				ERRX1("io_write_int");
				goto out;
			}
			/* Write: [flist-link]. */
			if (!io_write_buf(sess, fdout, fn, sz)) {
				ERRX1("io_write_buf");
				goto out;
			}
		}

		if (S_ISREG(f->st.mode) || S_ISLNK(f->st.mode))
			sess->total_size += f->st.size;

		/*
		 * In protocols 28 and newer, we don't send the checksum
		 * if the item is not a regular file.
		 */

		if (sess->opts->checksum) {
			/* Write: [flist-checksum]. */
			if (!io_write_buf(sess, fdout, f->md, sizeof(f->md))) {
				ERRX1("io_write_buf checksum");
				goto out;
			}
		}
	}

	/* Signal end of file list. */
	/* Write: [flist-status]. */

	if (!io_write_byte(sess, fdout, 0)) {
		ERRX1("io_write_byte");
		goto out;
	}

	/* Conditionally write identifier lists. */

	if (sess->opts->preserve_uids &&
	    sess->opts->numeric_ids != NIDS_FULL) {
		/* 
		 * Account for "stealth" --numeric-ids, don't always
		 * send it.
		 */
		if (!sess->opts->numeric_ids)
			sendidsz = uidsz;
		else
			sendidsz = 0;
		LOG3("sending uid list: %zu", sendidsz);
		if (!idents_send(sess, fdout, uids, sendidsz)) {
			ERRX1("idents_send");
			goto out;
		}
	}

	if (sess->opts->preserve_gids &&
	    sess->opts->numeric_ids != NIDS_FULL) {
		/* 
		 * Account for "stealth" --numeric-ids, don't always
		 * send it. 
		 */
		if (!sess->opts->numeric_ids)
			sendidsz = gidsz;
		else
			sendidsz = 0;
		LOG3("sending gid list: %zu", sendidsz);
		if (!idents_send(sess, fdout, gids, sendidsz)) {
			ERRX1("idents_send");
			goto out;
		}
	}

	rc = true;
out:
	idents_free(gids, gidsz);
	idents_free(uids, uidsz);
	return rc;
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
flist_recv_name(struct sess *sess, int fd, struct flist *f, uint8_t flags,
    char last[PATH_MAX])
{
	uint8_t		 bval;
	size_t		 partial = 0;
	size_t		 pathlen = 0, len;

	/*
	 * Read our filename.
	 * If we have FLIST_NAME_SAME, we inherit some of the last
	 * transmitted name.
	 * If we have FLIST_NAME_LONG, then the string length is greater
	 * than byte-size.
	 */

	if (flags & FLIST_NAME_SAME) {
		/* Read: [flist-name-offset]. */
		if (!io_read_byte(sess, fd, &bval)) {
			ERRX1("io_read_byte");
			return 0;
		}
		partial = bval;
	}

	/* Get the (possibly-remaining) filename length. */

	if (flags & FLIST_NAME_LONG) {
		/* Read: [flist-name-len-long]. */
		if (!io_read_size(sess, fd, &pathlen)) {
			ERRX1("io_read_size");
			return 0;
		}
	} else {
		/* Read: [flist-name-len-short]. */
		if (!io_read_byte(sess, fd, &bval)) {
			ERRX1("io_read_byte");
			return 0;
		}
		pathlen = bval;
	}

	/* Allocate our full filename length. */
	/* FIXME: maximum pathname length. */

	if ((len = pathlen + partial) == 0) {
		ERRX("security violation: zero-length pathname");
		return 0;
	}

	if (len >= PATH_MAX) {
		ERRX("pathname too long");
		return 0;
	}

	if ((f->path = malloc(len + 1)) == NULL) {
		ERR("malloc");
		return 0;
	}
	f->path[len] = '\0';

	if (flags & FLIST_NAME_SAME)
		memcpy(f->path, last, partial);

	/* Read: [flist-name]. */

	if (!io_read_buf(sess, fd, f->path + partial, pathlen)) {
		ERRX1("io_read_buf");
		return 0;
	}

	if (f->path[0] == '/' && !sess->opts->relative) {
		ERRX("security violation: absolute pathname: %s",
		    f->path);
		return 0;
	}

	if (strstr(f->path, "/../") != NULL ||
	    (len > 2 && strcmp(f->path + len - 3, "/..") == 0) ||
	    (len > 2 && strncmp(f->path, "../", 3) == 0) ||
	    strcmp(f->path, "..") == 0) {
		ERRX("%s: security violation: backtracking pathname",
		    f->path);
		return 0;
	}

	/* Record our last path and construct our filename. */

	strlcpy(last, f->path, PATH_MAX);

	/* If relative, strip and append. */

	if (sess->opts->relative && f->path[0] == '/') {
		f->wpath = f->path;
		while (f->wpath[0] == '/') {
			f->wpath++;
			len--;
		}
		flist_assert_wpath_len(f->wpath);

		/*
		 * f->path is allocated on the heap, so we just preserve
		 * that as the beginning of the path instead of having
		 * to add another pointer to retain the start of the
		 * buffer.
		 */

		memmove(f->path, f->wpath, len + 1);
	}
	f->wpath = f->path;
	return 1;
}

/*
 * Reallocate a file list in chunks of FLIST_CHUNK_SIZE;
 * Returns false on failure, true on success.
 */
static bool
flist_realloc(struct flist **fl, size_t *sz, size_t *max,
    enum fmode mode)
{
	void		*pp;
	struct flist	*flent;
	size_t		 i;

	if (*sz + 1 <= *max)  {
		(*sz)++;
		return true;
	}

	pp = recallocarray(*fl, *max,
		*max + FLIST_CHUNK_SIZE, sizeof(struct flist));
	if (pp == NULL) {
		ERR("recallocarray");
		return false;
	}
	*fl = pp;
	*max += FLIST_CHUNK_SIZE;
	for (i = *sz; i < *max; i++) {
		flent = &(*fl)[i];
		flent->fmode = mode;
	}
	(*sz)++;
	return true;
}

static struct froot *
froot_open(const char *path)
{
	struct froot *froot;

	assert(path[0] != '\0');
	froot = malloc(sizeof(*froot));
	if (froot == NULL) {
		ERR("malloc froot");
		return NULL;
	}

	froot->rootpath = strdup(path);
	if (froot->rootpath == NULL) {
		ERR("strdup frootpath");
		free(froot);
		return NULL;
	}

	froot->refcount = 1;
	froot->rootfd = open(path, O_DIRECTORY);
	if (froot->rootfd == -1) {
		ERR("open %s", path);
		free(froot->rootpath);
		free(froot);
		return NULL;
	}

	return froot;
}

struct froot *
froot_acquire(struct froot *froot)
{
	/*
	 * We allow NULL here to simplify our caller's logic; they don't
	 * need to care if they're part of a recursive scan or not.
	 */
	if (froot == NULL)
		return NULL;

	assert(froot->refcount > 0);
	froot->refcount++;
	return froot;
}

void
froot_release(struct froot *froot)
{

	assert(froot->refcount > 0);
	if (--froot->refcount != 0)
		return;

	close(froot->rootfd);
	free(froot->rootpath);
	free(froot);
}


/*
 * Reallocate a file list in chunks of FLIST_CHUNK_SIZE;
 * Returns -1 on failure, index of new element on success.
 */
static ssize_t
fl_new_index(struct fl *fl)
{
	if (!flist_realloc(&fl->flp, &fl->sz, &fl->max, fl->sess->mode))
		return -1;
	return fl->sz - 1;
}

/*
 * Returns a pointer to the new element, or NULL on error.
 */
struct flist *
fl_new(struct fl *fl)
{
	ssize_t	index;

	index = fl_new_index(fl);
	if (index == -1)
		return NULL;
	return &(fl->flp[index]);
}

void
fl_pop(struct fl *fl)
{
	assert(fl->sz > 0);
	fl->sz--;
}

/*
 * Initialise a new "fl" structure and set its session.
 */
void
fl_init(struct sess *sess, struct fl *fl)
{
	memset(fl, 0, sizeof(*fl));
	fl->sess = sess;
}

/*
 * FIXME: get the "fl" at index "idx" and check for a bad read.  Returns
 * NULL on a bad read.  This should assert, as nobody checks to make
 * sure that this returns NULL.
 */
static struct flist *
fl_atindex(struct fl *fl, size_t idx)
{
	if (idx >= fl->sz) {
		ERRX("flist index error");
		return NULL;
	}
	return &(fl->flp[idx]);
}

/*
 * Copy all the elements of path that are directories.  We need those
 * for --relative, because we need to restore their stat(2) values.
 * (Unless --no-implied-dirs is given.)
 */
static bool
flist_append_dirs(struct sess *sess, const char *path, struct fl *fl)
{
	struct stat	 st;
	const char	*wbegin;
	char		*pos, *begin;
	struct flist	*f;

	/* Skip past leading slashes. */

	wbegin = path;
	while (wbegin[0] == '/')
		wbegin++;

	/*
	 * Iterate through the path to each path component, then add
	 * that to the fl array.
	 */

	if ((pos = strrchr(wbegin, '/')) != NULL) {
		if ((begin = strdup(path)) == NULL) {
			ERR("strdup");
			return false;
		}

		wbegin = begin + (wbegin - path);
		pos = begin + (pos - path);
		*pos = '\0';

		if ((stat(begin, &st)) == -1) {
			ERR("%s: stat", begin);
			free(begin);
			return false;
		}

		if ((f = fl_new(fl)) == NULL) {
			ERRX1("flist_realloc");
			free(begin);
			return false;
		}

		f->path = begin;
		f->wpath = wbegin;
		flist_assert_wpath_len(f->wpath);
		flist_copy_stat(f, &st);

		if (strchr(wbegin, '/') != NULL) {
			if (!flist_append_dirs(sess, begin, fl)) {
				ERRX1("flist_append_dirs");
				return false;
			}
		}
	}

	return true;
}

/*
 * Copy a regular or symbolic link file "path" into "f".  This handles
 * the correct path creation and symbolic linking.  Returns false on
 * failure, true on success.
 */
static bool
flist_append(struct sess *sess, const struct stat *st,
    const char *path, struct fl *fl, const char *prefix,
    struct froot *froot)
{
	struct flist	*f;
	char 		*link;
	ssize_t		 oldidx;
	size_t	 	 prefixlen;

	if ((oldidx = fl_new_index(fl)) == -1) {
		ERRX("fl_new failed");
		return false;
	}

	/*
	 * Copy the full path for local addressing and transmit only the
	 * filename part for the receiver, unless
	 * --relative is given.
	 */

	f = fl_atindex(fl, oldidx);
	if ((f->path = strdup(path)) == NULL) {
		ERR("strdup");
		return false;
	}

	f->froot = froot_acquire(froot);

	if (!sess->opts->relative) {
		/*
		 * If absolute, remove prefix from path if it is not an
		 * exact match.
		 */
		prefixlen = strlen(prefix);
		if (strcmp(f->path, prefix) == 0) {
			if ((f->wpath = strrchr(f->path, '/')) == NULL)
				f->wpath = f->path;
			else
				f->wpath++;
		} else if (strncmp(f->path, prefix, prefixlen) == 0) {
			f->wpath = f->path + prefixlen;
		} else
			f->wpath = f->path;

		flist_assert_wpath_len(f->wpath);
	} else {
		/*
		 * ...otherwise, append to the relative directory.
		 */
		f->wpath = f->path;
		while (f->wpath[0] == '/')
			f->wpath++;
		flist_assert_wpath_len(f->wpath);
		if (!flist_append_dirs(sess, f->path, fl))
			return false;

		/*
		 * flist_append_dirs() may re-allocate our flist out
		 * from underneath us, reload the flist entry we're
		 * working on as needed.
		 */

		f = fl_atindex(fl, oldidx);
	}

	/*
	 * On the receiving end, we'll strip out all bits on the
	 * mode except for the file permissions.
	 * No need to warn about it here.
	 */

	flist_copy_stat(f, st);

	/* Optionally copy link information. */

	if (S_ISLNK(st->st_mode)) {
		link = symlink_read(f->path, st->st_size);
		if (link == NULL) {
			ERRX1("symlink_read");
			return false;
		}
		f->link = link;
	}

	if (sess->opts->checksum && S_ISREG(f->st.mode)) {
		if (!hash_file_by_path(AT_FDCWD, f->path, f->st.size, f->md)) {
			ERRX1("hash_file_by_path");
			return false;
		}
	}

	return true;
}


/*
 * Receive a file list from the wire, filling in length "sz" (which may
 * possibly be zero) and list "flp" on success.
 * Return false on failure, true on success.
 */
bool
flist_recv(struct sess *sess, int fdin, int fdout, struct flist **flp,
    size_t *sz)
{
	struct flist	*fl = NULL;
	struct flist	*ff;
	char 		*link;
	const struct flist *fflast = NULL;
	size_t		 i, flsz = 0, flmax = 0, lsz, gidsz = 0, uidsz = 0;
	uint8_t		 flag, bval;
	char		 last[PATH_MAX];
	int64_t		 lval; /* temporary values... */
	int32_t		 ival;
	uint32_t	 uival;
	struct ident	*gids = NULL, *uids = NULL;

	last[0] = '\0';

	for (;;) {
		/* 
		 * Read: [flist-status].
		 * If zero, stop processing the flist.
		 */

		if (!io_read_byte(sess, fdin, &bval)) {
			ERRX1("io_read_byte");
			goto out;
		}
		flag = bval;
		if (flag == 0)
			break;

		/*
		 * The protocol uses ints for indexing, so we can't go
		 * too crazy here.
		 */

		if (flsz == INT_MAX) {
			ERR("remote sent too many files");
			goto out;
		}

		if (!flist_realloc(&fl, &flsz, &flmax, FARGS_RECEIVER)) {
			ERRX1("flist_realloc");
			goto out;
		}

		ff = &fl[flsz - 1];
		fflast = flsz > 1 ? &fl[flsz - 2] : NULL;

		/* Filename first ([flist-name] et al.). */

		if (!flist_recv_name(sess, fdin, ff, flag, last)) {
			ERRX1("flist_recv_name");
			goto out;
		}

		/* Read: [flist-length]. */

		if (!io_read_long(sess, fdin, &lval)) {
			ERRX1("io_read_long");
			goto out;
		}
		ff->st.size = lval;

		/* Read: [flist-mtime]. */

		if (!(flag & FLIST_TIME_SAME)) {
			if (!io_read_uint(sess, fdin, &uival)) {
				ERRX1("io_read_uint");
				goto out;
			}
			ff->st.mtime = uival;	/* beyond 2038 */
		} else if (fflast == NULL) {
			ff->st.mtime = 0;
		}  else
			ff->st.mtime = fflast->st.mtime;

		ff->dstat.atime.tv_nsec = UTIME_NOW;
		ff->dstat.mtime.tv_sec = ff->st.mtime;

		/* Read: [flist-mode]. */

		if (!(flag & FLIST_MODE_SAME)) {
			if (!io_read_uint(sess, fdin, &uival)) {
				ERRX1("io_read_uint");
				goto out;
			}
			ff->st.mode = uival;
		} else if (fflast == NULL) {
			WARNX1("same mode without last entry");
			ff->st.mode = 0;
		} else
			ff->st.mode = fflast->st.mode;

		ff->dstat.mode = ff->st.mode;
		if (S_ISDIR(ff->st.mode) && (flag & FLIST_TOP_LEVEL))
			ff->st.flags |= FLSTAT_TOP_DIR;

		/* Conditional part: uid. */

		if (sess->opts->preserve_uids) {
			if (!(flag & FLIST_UID_SAME)) {
				/* Read: [flist-uid]. */
				if (!io_read_uint(sess, fdin, &uival)) {
					ERRX1("io_read_int");
					goto out;
				}
				ff->st.uid = uival;
			} else if (fflast == NULL) {
				/*
				 * rsync 2.6.9 would sometimes send some
				 * of these because it used a comparison
				 * against a static 0 for uid/gid in
				 * determining this without checking if
				 * it had actually send a file before.
				 */
				WARNX1("same uid without last entry");
				ff->st.uid = 0;
			} else
				ff->st.uid = fflast->st.uid;

			ff->dstat.uid = ff->st.uid;
		} else
			ff->dstat.uid = -1;

		/* Conditional part: gid. */

		if (sess->opts->preserve_gids) {
			if (!(flag & FLIST_GID_SAME)) {
				/* Read: [flist-gid]. */
				if (!io_read_uint(sess, fdin, &uival)) {
					ERRX1("io_read_uint");
					goto out;
				}
				ff->st.gid = uival;
			} else if (fflast == NULL) {
				/*
				 * rsync 2.6.9 would sometimes send some
				 * of these because it used a comparison
				 * against a static 0 for uid/gid in
				 * determining this without checking if
				 * it had actually send a file before.
				 */
				WARNX1("same gid without last entry");
				ff->st.gid = 0;
			} else
				ff->st.gid = fflast->st.gid;

			ff->dstat.gid = ff->st.gid;
		} else
			ff->dstat.gid = -1;

		/* Conditional part: devices & special files. */

		if ((sess->opts->devices && (S_ISBLK(ff->st.mode) ||
		    S_ISCHR(ff->st.mode))) ||
		    (sess->opts->specials && (S_ISFIFO(ff->st.mode) ||
		    S_ISSOCK(ff->st.mode)))) {
			/*
			 * Protocols less than 28, the device number is
			 * transmitted as a single int.
			 * Read: [file-rdev]. 
			 */
			if (!(flag & FLIST_RDEV_SAME)) {
				if (!io_read_int(sess, fdin, &ival)) {
					ERRX1("io_read_int");
					goto out;
				}
				ff->st.rdev = ival;
			} else if (fflast == NULL) {
				WARNX1("same device without last entry");
				ff->st.rdev = 0;
			} else
				ff->st.rdev = fflast->st.rdev;
		}

		/* Conditional part: link. */

		if (S_ISLNK(ff->st.mode) &&
		    sess->opts->preserve_links) {
			/* Read: [file-link-length]. */
			if (!io_read_size(sess, fdin, &lsz)) {
				ERRX1("io_read_size");
				goto out;
			} else if (lsz == 0) {
				ERRX("empty link name");
				goto out;
			}
			link = calloc(lsz + 1, 1);
			if (link == NULL) {
				ERR("calloc");
				goto out;
			}
			/* Read: [file-link]. */
			if (!io_read_buf(sess, fdin, link, lsz)) {
				free(link);
				ERRX1("io_read_buf");
				goto out;
			}

			ff->link = link;
		}

		LOG3("%s: received file metadata: "
			"size %jd, mtime %jd, mode %o, rdev (%d, %d)",
			ff->path, (intmax_t)ff->st.size,
			(intmax_t)ff->st.mtime, ff->st.mode,
			major(ff->st.rdev), minor(ff->st.rdev));

		if (S_ISREG(ff->st.mode))
			sess->total_size += ff->st.size;

		/*
		 * In protocols 28 and newer, we don't get the checksum
		 * if the item is not a regular file.
		 */

		if (sess->opts->checksum) {
			/* Read: [file-checksum]. */
			if (!io_read_buf(sess, fdin, ff->md, sizeof(ff->md))) {
				ERRX1("io_read_buf");
				goto out;
			}
		}
	}

	/* Conditionally read the user/group list. */

	if (sess->opts->preserve_uids &&
	    sess->opts->numeric_ids != NIDS_FULL) {
		if (!idents_recv(sess, fdin, &uids, &uidsz)) {
			ERRX1("idents_recv");
			goto out;
		}
		LOG3("received uid list: %zu", uidsz);
	}

	if (sess->opts->preserve_gids &&
	    sess->opts->numeric_ids != NIDS_FULL) {
		if (!idents_recv(sess, fdin, &gids, &gidsz)) {
			ERRX1("idents_recv");
			goto out;
		}
		LOG3("received gid list: %zu", gidsz);
	}

	/* Remember to order the received list. */

	LOG3("received file metadata list: %zu", flsz);

	/* Remember the sender's flist size for keep-alive detection. */

	sess->sender_flsz = flsz;

	qsort(fl, flsz, sizeof(struct flist), flist_cmp);

	/*
	 * It's important that we keep track of the send index now,
	 * because we may want to trim or dedupe the flist before we
	 * proceed.  Neither openrsync nor the reference rsync will
	 * dedupe on the sender side in order to give receivers
	 * flexibility in how they handle it.
	 */

	for (i = 0; i < flsz; i++)
		fl[i].sendidx = (int)i;

	flist_dedupe(sess->opts, &fl, &flsz);

	*sz = flsz;
	*flp = fl;

	/* Conditionally remap and reassign identifiers. */

	if (sess->opts->preserve_uids && !sess->opts->numeric_ids) {
		idents_remap(sess, 0, uids, uidsz);
		idents_assign_uid(sess, fl, flsz, uids, uidsz);
	}

	if (sess->opts->preserve_gids && !sess->opts->numeric_ids) {
		idents_remap(sess, 1, gids, gidsz);
		idents_assign_gid(sess, fl, flsz, gids, gidsz);
	}

	idents_free(gids, gidsz);
	idents_free(uids, uidsz);
	return true;
out:
	flist_free(fl, flsz);
	idents_free(gids, gidsz);
	idents_free(uids, uidsz);
	*sz = 0;
	*flp = NULL;
	return false;
}

static int
flist_gen_dirent_file(struct sess *sess, const char *type,
    const char *root, struct fl *fl, const struct stat *st,
    const char *prefix, struct froot *froot)
{
	/* Filter files. */

	if (rules_match(root, S_ISDIR(st->st_mode), FARGS_SENDER, 0) == -1) {
		WARNX("%s: skipping excluded %s", root, type);
		return 1;
	}

	/* Add it to our world view. */

	if (!flist_append(sess, st, root, fl, prefix, froot)) {
		ERRX1("flist_append");
		return 0;
	}

	return 1;
}

/*
 * Return true if the path should be recursed.
 */
static bool
flist_dir_recurse(const char *root)
{
	char tc;

	if (root == NULL || root[0] == '\0')
		return false;

	tc = root[strlen(root) - 1];
	return tc == '/' || tc == '.';
}

static void
flist_dirent_normalize(const FTSENT * const ent, char *pathbuf,
    size_t pathbufsz, ssize_t *stripdirp, char **pathp, size_t *lenp)
{
	size_t		 fts_pathlen = ent->fts_pathlen;
	char		*fts_path = ent->fts_path;
	const char	*src;
	char		*dst;
	ptrdiff_t 	 delta;

	if (fts_pathlen > 2) {
		if (strncmp(fts_path, "./", 2) == 0) {
			if (*stripdirp >= 2)
				*stripdirp -= 2;
			fts_pathlen -= 2;
			fts_path += 2;
			while (*fts_path == '/') {
				if (*stripdirp > 0)
					*stripdirp -= 1;
				fts_pathlen--;
				fts_path++;
			}
			assert(*fts_path != '\0');
		}
	}

	assert(pathbufsz > fts_pathlen);

	/*
	 * On macOS/Darwin fts_read() returns an extra slash when
	 * fts_open() is called with a directory name ending in "/".
	 * For example, if fts_open is given a directory named "./" or
	 * "some/path/", then fts_read() will return ".//file" or
	 * "some/path//file", respectively.
	 */

	for (src = fts_path; *src != '\0'; src++) {
		if (src[0] == '/' && src[1] == '/') {
			delta = src - fts_path;
			dst = pathbuf;

			memcpy(dst, fts_path, delta);
			dst += delta;
			memcpy(dst, src + 1, fts_pathlen - delta + 1);

			fts_path = pathbuf;
			fts_pathlen--;

			if (*stripdirp > delta + 1)
				*stripdirp = delta + 1;
			break;
		}
	}

	assert(fts_path[0] != '\0');

	*lenp = fts_pathlen;
	*pathp = fts_path;
}

/*
 * Normalise a file path into pathbuf.
 *  - remove leading relative or absolute
 *  - remove trailing self-paths and directory
 *  - remove inner self-paths and double slashes
 *  Returns the new size of the path.
 */
static size_t
flist_path_normalize(const char *path, char *pathbuf, size_t pathbufsz)
{
	size_t	 pathlen;
	char 	*pc;

	pathlen = strlen(path);

	while (pathlen > 1 && path[0] == '/' && path[1] == '/') {
		pathlen--;
		path++; /* Remove leading "/" */
	}

	while (pathlen > 2 && path[0] == '.' && path[1] == '/') {
		pathlen -= 2;
		path += 2; /* Remove leading "./" */

		while (*path == '/') {
			pathlen--;
			path++;
		}
	}

	if (pathlen > 1 && path[pathlen - 1] == '.' &&
	    path[pathlen - 2] == '/')
		pathlen--; /* Remove trailing "." */

	for (;;) {
		while (pathlen > 1 && path[pathlen - 1] == '/' &&
		    path[pathlen - 2] == '/')
			pathlen--; /* Remove trailing "/" */

		if (pathlen < 3 ||
		    strncmp(&path[pathlen - 3], "/./", 3) != 0)
			break;

		pathlen -= 2; /* Remove trailing "./" */
	}

	if (pathlen == 0) {
		pathlen = 1;
		path = ".";
	}

	assert(pathbufsz > 0);
	memcpy(pathbuf, path, MIN(pathlen, pathbufsz - 1));
	pathbuf[MIN(pathlen, pathbufsz - 1)] = '\0';

	/*
	 * At this point we've inexpensively trimmed all unneeded
	 * leading and trailing combinations of "./" and slashes from
	 * the path path and copied it into pathbuf[].
	 *
	 * Although unlikely, there may still be some combinations of
	 * "./" and/or "//" within the remaining path.  For example,
	 * paths like "src/./.././src" and ".//src///..///src/" should
	 * reduce to "src/../src" and "src/../src/", respectively.
	 */

	for (pc = pathbuf; *pc != '\0'; /* do nothing */) {
		if (pc[0] == '/') {
			if (pc[1] == '.' && pc[2] == '/') {
				memmove(pc, pc + 2,
				    pathlen - (pc - pathbuf) - 1);
				pathlen -= 2;
				continue;
			}

			if (pc[1] == '/') {
				memmove(pc, pc + 1,
				    pathlen - (pc - pathbuf));
				pathlen--;
				continue;
			}
		}

		pc++;
	}

	return pathlen;
}

/*
 * Return the length of "root" after stripping down to the directory
 * portion of the path.
 * XXX: this is a "ssize_t" to conform to the caller's conventions: this
 * never returns a negative number.
 */
static ssize_t
flist_dirent_strip(struct sess *sess, const char *root)
{
	char	 *cp;
	ssize_t	 stripdir;

	if (sess->opts->relative)
		return 0;

	/*
	 * If we end with a slash, it means that we're not supposed to
	 * copy the directory part itself---only the contents.  So set
	 * "stripdir" to be what we take out.
	 */

	stripdir = strlen(root);
	assert(stripdir > 0);
	if (root[stripdir - 1] == '/')
		return stripdir;

	/*
	 * If we're not stripping anything, then see if we need to strip
	 * out the leading material in the path up to but not including
	 * the last component.
	 */

	if ((cp = strrchr(root, '/')) != NULL)
		return cp - root + 1;

	return 0;
}

/*
 * Shim for platforms that may not handle lstat(2) with a link name
 * ending in '/' the way we expect.  We expect a directory, so we should
 * chase it down all the way to the end and error out if it's not a
 * directory, as opposed to the usual lstat(2) behavior.
 */
static int
rsync_lstat(const char *path, struct stat *sb)
{
	size_t	 pathlen;
	int	 error;

	pathlen = strlen(path);

	/* No expectation of a directory, just lstat(2) as usual. */

	if (path[pathlen - 1] != '/')
		return lstat(path, sb);

	/*
	 * We want a directory, so stat() it and coerce an error if the
	 * end result is not a directory.
	 */

	error = stat(path, sb);
	if (error != 0)
		return error;
	if (!S_ISDIR(sb->st_mode)) {
		errno = ENOTDIR;
		return -1;
	}

	return 0;
}

/*
 * Generate a flist possibly-recursively given a file root, which may
 * also be a regular file or symlink.
 * On success, augments the generated list in "flp" of length "sz".
 * Returns false on failure, true on success.
 */
static bool
flist_gen_dirent(struct sess *sess, const char *root, struct fl *fl,
    ssize_t stripdir, const char *prefix, struct froot *froot)
{
	char		 fts_pathbuf[PATH_MAX];
	struct stat	 st;
	const char	*cargv[2]; /* fts_open args */
	char		*fts_path;
	int		 fts_options;
	int              ret;
	FTS		*fts;
	FTSENT		*ent;
	struct flist	*f;
	size_t		 fts_pathlen;
	ssize_t		 stripdir_saved;
	bool		 rootfilter = true;
	bool		 rc = false;

	/*
	 * If we're a file, then revert to the same actions we use for
	 * the non-recursive scan.
	 */

	ret = rsync_lstat(root, &st);

	if (ret == -1) {
		ERR("%s: (l)stat", root);
		return false;
	} else if (S_ISREG(st.st_mode)) {
		return flist_gen_dirent_file(sess, "file", root, fl,
		    &st, prefix, froot);
	} else if (S_ISLNK(st.st_mode)) {
		return flist_gen_dirent_file(sess, "symlink", root, fl,
		    &st, prefix, froot);
	} else if (!S_ISDIR(st.st_mode)) {
		return flist_gen_dirent_file(sess, "special", root, fl,
		    &st, prefix, froot);
	}

	/*
	 * If we're non-recursive, just --dirs, then we may just need to
	 * add the entry if it's specified as "foo" and not "foo/".
	 */

	if (sess->opts->dirs && !sess->opts->recursive &&
	    (stripdir != -1 || !flist_dir_recurse(root))) {
		return flist_gen_dirent_file(sess, "dir", root, fl,
		    &st, prefix, froot);
	}

	if (stripdir == -1)
		stripdir = flist_dirent_strip(sess, root);

	/*
	 * This is set relatively late because we only want to setup a
	 * froot at top-level directories.  The above can be hit without
	 * having traversed into a directory for non-directory entries
	 * specified on the command line, and for those we need to be
	 * sure that we aren't trying to use a dirfd.  Their non-NULL
	 * `froot` would come from recursive calls in the loop below.
	 */

	if (froot == NULL) {
		froot = froot_open(root);
		if (froot == NULL) {
			ERRX1("froot_open");
			return false;
		}
	}

	cargv[0] = root;
	cargv[1] = NULL;

	/*
	 * We don't want to filter the root directory if the trailing
	 * slash was specified to sync its contents over and not the
	 * directory itself.
	 */

	assert(root[0] != '\0');
	if (root[strlen(root) - 1] == '/')
		rootfilter = false;

	/*
	 * If we're recursive, then we need to take down all of the
	 * files and directory components, so use fts(3).
	 * Copying the information file-by-file into the flstat.
	 * We'll make sense of it in flist_send.
	 */

	fts_options = FTS_PHYSICAL | FTS_NOCHDIR | FTS_COMFOLLOW;
	fts = fts_open((char * const *)cargv, fts_options, NULL);
	if (fts == NULL) {
		if (froot != NULL)
			froot_release(froot);
		ERR("fts_open");
		return false;
	}

	stripdir_saved = stripdir;
	errno = 0;

	while ((ent = fts_read(fts)) != NULL) {
		stripdir = stripdir_saved;

		flist_dirent_normalize(ent, fts_pathbuf,
		    sizeof(fts_pathbuf), &stripdir, &fts_path,
		    &fts_pathlen);

		if (ent->fts_info == FTS_D && ent->fts_level > 0 &&
		    !sess->opts->recursive)
			fts_set(fts, ent, FTS_SKIP);

		if (ent->fts_info == FTS_DP)
			rules_dir_pop(fts_path, stripdir);

		if (!flist_fts_check(sess, ent, FARGS_SENDER)) {
			errno = 0;
			continue;
		}

		if (ent->fts_info == FTS_D)
			rules_dir_push(fts_path, stripdir, '\n');

		/* We don't allow symlinks without -l. */

		assert(ent->fts_statp != NULL);

		/* This is for macOS fts, which returns "foo//bar" */

		/*
		 * It is no longer possible for "//" to appear in
		 * fts_path, but the code below cannot currently be
		 * removed because it has a side-effect wherein it
		 * strips the leading "/" from an absolute root path in
		 * --relative mode.
		 */

		if (fts_path[stripdir] == '/') {
			stripdir++;
		}

		/* Filter files .*/

		if ((ent->fts_level != 0 || rootfilter) &&
		    rules_match(fts_path + stripdir,
		    (ent->fts_info == FTS_D), FARGS_SENDER, 0) == -1) {
			LOG2("hiding file %s because of pattern",
			    fts_path + stripdir);
			fts_set(fts, ent, FTS_SKIP);
			continue;
		}

		/* Allocate a new file entry. */

		if ((f = fl_new(fl)) == NULL) {
			ERRX1("flist_realloc");
			goto out;
		}

		/* Our path defaults to "." for the root. */

		if (fts_path[stripdir] == '\0') {
			assert(stripdir > 0 &&
			    fts_path[stripdir - 1] == '/');
			if (asprintf(&f->path, "%s.", fts_path) == -1) {
				ERR("asprintf");
				f->path = NULL;
				goto out;
			}
		} else {
			if ((f->path = strdup(fts_path)) == NULL) {
				ERR("strdup");
				goto out;
			}
			if (f->path[fts_pathlen - 1] == '/') {
				assert(stripdir < (ssize_t)fts_pathlen);
				assert(fts_pathlen > 1);
				f->path[fts_pathlen - 1] = '\0';
			}
		}

		f->froot = froot_acquire(froot);
		f->wpath = f->path + stripdir;
		flist_assert_wpath_len(f->wpath);
		flist_copy_stat(f, ent->fts_statp);

		/* Optionally copy link information. */

		if (S_ISLNK(ent->fts_statp->st_mode)) {
			f->link = symlink_read(ent->fts_accpath,
			    ent->fts_statp->st_size);
			if (f->link == NULL) {
				ERRX1("symlink_read");
				fl_pop(fl);
				continue;
			}
		}

		/* Reset errno for next fts_read() call. */

		errno = 0;
	}
	if (errno) {
		ERR("fts_read");
		goto out;
	}

	LOG3("generated %zu filenames: %s", fl->sz, root);
	rc = true;
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
static bool
flist_gen_dirs(struct sess *sess, size_t argc, char **argv,
    struct fl *fl, struct froot *froot)
{
	char		 dname[PATH_MAX]; /* directory path */
	size_t		 dnamelen, /* directory length */
			 i, /* temporary */
			 errors = 0; /* count of errors */

	for (i = 0; i < argc; i++) {
		dnamelen = flist_path_normalize(argv[i], dname,
		    sizeof(dname));
		if (dnamelen >= sizeof(dname)) {
			errno = ENAMETOOLONG;
			ERR("'%s' flist_path_normalize", dname);
			errors++;
			continue;
		}

		if (dname[0] == '\0')
			strcpy(dname, ".");

		rules_base(dname);
		if (sess->opts->relative) {
			if (!flist_append_dirs(sess, dname, fl))
				return false;
		}
		if (!flist_gen_dirent(sess, dname, fl, -1, dname, froot))
			errors++;
	}

	LOG3("recursively generated %zu filenames", fl->sz);
	return errors ? false : true;
}

/*
 * Generate list of files from the command-line argc (>0) and argv.
 * On success, stores the generated list in "flp" with length "sz",
 * which may be zero.
 * Returns false on failure, true on success.
 */
static bool
flist_gen_files(struct sess *sess, size_t argc, char **argv,
    struct fl *fl)
{
	char		 fname[PATH_MAX]; /* file name */
	size_t		 fnamelen, /* length in fname */
			 i; /* temporary */
	struct stat	 st; /* stat of file */
	int              ret; /* temporary retcode */

	assert(argc);

	rules_base(".");
	if ((fl->flp = calloc(argc, sizeof(struct flist))) == NULL) {
		ERR("calloc");
		return false;
	}
	fl->max = argc;
	fl->sz = 0;

	for (i = 0; i < argc; i++) {
		fnamelen = flist_path_normalize(argv[i], fname,
		    sizeof(fname));
		if (fnamelen >= sizeof(fname)) {
			errno = ENAMETOOLONG;
			ERR("'%s' flist_path_normalize", fname);
			continue;
		}

		if (fname[0] == '\0')
			strcpy(fname, ".");

		ret = rsync_lstat(fname, &st);

		if (ret == -1) {
			ERR("'%s': (l)stat", fname);
			continue;
		}

		/*
		 * File type checks.
		 * In non-recursive mode, we don't accept directories.
		 * We also skip symbolic links without -l.
		 * Beyond that, we only accept regular files unless we're
		 * allowing specials or devices.
		 */

		if (S_ISDIR(st.st_mode)) {
			if (!sess->opts->dirs) {
				LOG0("skipping directory %s", fname);
				continue;
			}
		}

		/* Filter files. */

		if (rules_match(fname, S_ISDIR(st.st_mode), FARGS_SENDER,
		    0) == -1) {
			WARNX("%s: skipping excluded file", fname);
			continue;
		}

		/* Add this file to our file-system worldview. */

		if (!flist_append(sess, &st, fname, fl, fname, NULL)) {
			ERRX1("flist_append");
			goto out;
		}
	}

	LOG2("non-recursively generated %zu filenames", fl->sz);
	return true;
out:
	flist_free(fl->flp, argc);
	fl->flp = NULL;
	fl->sz = 0;
	return false;

}

#if 0
/*
 * Generate a list of files from a syncfile that are contained within
 * the arguments given on the command line.
 * This overrides everything we're given on the command line.
 * TODO: mmap() the file to avoid the billion reads.
 * Returns zero on failure, non-zero on success.
 */
static int
flist_gen_syncfile(struct sess *sess, size_t argc, char **argv,
	struct flist **flp, size_t *sz)
{
	int		 fd, first = 1;
	ssize_t		 ssz;
	char		*path = NULL, *link = NULL;
	struct flist	*fl;
	struct stat	 st;
	size_t		 tmpsz, pathsz, linksz, i, stripdir = 0;
	const char	*cp;

	if ((fd = open(sess->opts->syncfile, O_RDONLY, 0)) == -1) {
		ERR("%s", sess->opts->syncfile);
		return 0;
	}

	/* Read until end of file. */

	while ((ssz = read(fd, &pathsz, sizeof(size_t))) != 0) {
		free(path);
		free(link);
		path = link = NULL;
		if (ssz < 0) {
			ERR("%s", sess->opts->syncfile);
			goto out;
		} else if ((size_t)ssz != sizeof(size_t)) {
			ERRX("%s: short read", sess->opts->syncfile);
			goto out;
		} else if ((path = calloc(pathsz + 1, 1)) == NULL) {
			ERR("calloc");
			goto out;
		} else if ((ssz = read(fd, path, pathsz)) < 0) {
			ERR("%s", sess->opts->syncfile);
			goto out;
		} else if ((size_t)ssz != pathsz) {
			ERRX("%s: short read", sess->opts->syncfile);
			goto out;
		} else if ((ssz = read(fd, &st, sizeof(struct stat))) < 0) {
			ERR("%s", sess->opts->syncfile);
			goto out;
		} else if ((size_t)ssz != sizeof(struct stat)) {
			ERR("%s", sess->opts->syncfile);
			goto out;
		}

		if (S_ISLNK(st.st_mode)) {
			if ((ssz = read(fd, &linksz, sizeof(size_t))) < 0) {
				ERR("%s", sess->opts->syncfile);
				goto out;
			} else if ((size_t)ssz != sizeof(size_t)) {
				ERRX("%s: short read", sess->opts->syncfile);
				goto out;
			} else if ((link = calloc(linksz + 1, 1)) == NULL) {
				ERR("calloc");
				goto out;
			} else if ((ssz = read(fd, link, linksz)) < 0) {
				ERR("%s", sess->opts->syncfile);
				goto out;
			} else if ((size_t)ssz != linksz) {
				ERRX("%s: short read", sess->opts->syncfile);
				goto out;
			}
		}

		/*
		 * We want to make sure that the requested file is part
		 * of the set in our syncfile.
		 * If the request is recursive, we check that the
		 * syncfile has at least the requested root.
		 * If it's non-recursive, it must exist exactly.
		 */

		if (!sess->opts->recursive) {
			for (i = 0; i < argc; i++)
				if (strcmp(argv[i], path) == 0)
					break;
			if (i == argc)
				continue;

			if (S_ISDIR(st.st_mode)) {
				WARNX("%s: skipping directory", path);
				continue;
			} else if (S_ISLNK(st.st_mode)) {
				if (!sess->opts->preserve_links) {
					WARNX("%s: skipping symlink", path);
					continue;
				}
			} else if (!S_ISREG(st.st_mode)) {
				WARNX("%s: skipping special", path);
				continue;
			}
		} else {
			for (i = 0; i < argc; i++) {
				tmpsz = strlen(argv[i]);
				if (pathsz < tmpsz)
					continue;
				if (strncmp(argv[i], path, tmpsz))
					continue;
				if (path[tmpsz] == '\0' || path[tmpsz] == '/')
					break;
			}
			if (i == argc)
				continue;
		}

		/* 
		 * We need to find the common root that we're going to
		 * build in the receiver, so use the first entry as a
		 * referent.
		 * If it ends with a slash, we're going to omit the
		 * directory altogether, so the stripdir will be the
		 * full length of the file.
		 * Otherwise, we take the final path component.
		 */

		if (first) {
			if ((stripdir = strlen(path)) == 0) {
				ERRX("%s: empty root", sess->opts->syncfile);
				goto out;
			} else if (path[stripdir - 1] != '/') {
				if ((cp = strrchr(path, '/')) != NULL)
					stripdir = cp - path + 1;
			}
			first = 0;
		}

		/* Create the entry. */

		*flp = reallocarray(*flp, *sz + 1, sizeof(struct flist));
		if (*flp == NULL) {
			ERR("reallocarray");
			goto out;
		}
		fl = &(*flp)[*sz];
		(*sz)++;
		memset(fl, 0, sizeof(struct flist));
		fl->path = path;
		fl->link = link;
		fl->wpath = fl->path + stripdir;
		flist_copy_stat(fl, &st);
		path = link = NULL;
	}
out:
	LOG2("syncfile generated %zu filenames", *sz);
	free(path);
	free(link);
	close(fd);
	return 1;
}
#endif

/*
 * Generate a sorted, de-duplicated list of file metadata.
 * In non-recursive mode (the default), we use only the files we're
 * given.
 * Otherwise, directories are recursively examined.
 * Returns false on failure, true on success.
 * On success, "fl"s contents will need to be freed with flist_free().
 */
bool
flist_gen(struct sess *sess, size_t argc, char **argv, struct fl *fl)
{
	bool	 rc;

#if 0
	if (sess->opts->syncfile == NULL) {
#endif
	assert(argc > 0);
	rc = sess->opts->recursive || sess->opts->dirs ?
		flist_gen_dirs(sess, argc, argv, fl, NULL) :
		flist_gen_files(sess, argc, argv, fl);
#if 0
	} else
		rc = flist_gen_syncfile(sess, argc, argv, flp, sz);
#endif

	/*
	 * If our flist_gen_*() call failed and we didn't have any
	 * transfer errors, then consider the situation fatal and bail
	 * out.  Otherwise, we'll still proceed with what we have.
	 */

	if (!rc)
		return false;

	qsort(fl->flp, fl->sz, sizeof(struct flist), flist_cmp);
	flist_topdirs(sess, fl->flp, fl->sz); /* FIXME: use fl */
	return true;
}

/*
 * Generate a list of files in root to delete that are within the
 * top-level directories stipulated by "wfl".
 * Only handles symbolic links, directories, and regular files.
 * Returns false on failure (fl and flsz will be NULL and zero), true
 * on success.
 * On success, "fl" will need to be freed with flist_free().
 */
bool
flist_gen_dels(struct sess *sess, const char *root, struct flist **fl,
    size_t *sz,	const struct flist *wfl, size_t wflsz)
{
	char		**cargv = NULL, **skipv = NULL;
	const char	 *kpath, *topdir, *rpath;
	int		  c;
	FTS		 *fts = NULL;
	FTSENT		 *ent, *perish_ent = NULL;
	struct flist	 *f;
	size_t		  cargvs = 0, i, j, max = 0, stripdir, dj,
			  skipc = 0;
	ENTRY		  hent;
	ENTRY		 *hentp;
	bool		  have_dotdir = false, skip_post = false,
			  rc = false;

	*fl = NULL;
	*sz = 0;

	/* Only run this code when we're recursive or in dir mode. */

	if (!(sess->opts->recursive || sess->opts->dirs))
		return 1;

	/*
	 * Gather up all top-level directories for scanning.
	 * This is stipulated by rsync's --delete behaviour, where we
	 * only delete things in the top-level directories given on the
	 * command line.
	 */

	for (i = 0; i < wflsz; i++)
		if (wfl[i].st.flags & FLSTAT_TOP_DIR) {
			cargvs++; 
			if (!have_dotdir && strcmp(wfl[i].wpath, ".") == 0)
				have_dotdir = true;
		}


	if (cargvs == 0)
		return 1;

	if ((cargv = calloc(cargvs + 1, sizeof(char *))) == NULL) {
		ERR("calloc");
		return 0;
	}

	if (have_dotdir)
		if ((skipv = calloc(cargvs + 1, sizeof(char *))) == NULL) {
			ERR("calloc");
			return 0;
		}

	for (i = j = 0; i < wflsz; i++) {
		if (!(wfl[i].st.flags & FLSTAT_TOP_DIR))
			continue;
		assert(S_ISDIR(wfl[i].st.mode));
		c = asprintf(&cargv[j], "%s/%s", root, wfl[i].wpath);
		if (c == -1) {
			ERR("asprintf");
			cargv[j] = NULL;
			goto out;
		}

		/*
		 * We generally shouldn't have that many top-dirs in a
		 * transfer, so this shouldn't be a major drag on
		 * performance and will save us from some extra
		 * redundant directory walks later on.
		 */

		for (dj = 0; dj < j; dj++)
			if (strcmp(cargv[dj], cargv[j]) == 0) {
				free(cargv[j]);
				cargv[j] = NULL;
				break;
			}

		if (cargv[j] == NULL) {
			cargvs--;
			continue;
		}

		if (have_dotdir && strcmp(wfl[i].wpath, ".") != 0) {
			c = asprintf(&skipv[skipc], "%s/./%s", root,
			    wfl[i].wpath);
			if (c == -1) {
				ERR("asprintf");
				skipv[skipc] = NULL;
				goto out;
			}
			skipc++;
		}

		LOG4("%s: will scan for deletions", cargv[j]);
		j++;
	}

	cargv[j] = NULL;

	LOG3("delete from %zu directories", cargvs);

	/*
	 * Next, use the standard hcreate(3) hashtable interface to hash
	 * all of the files that we want to synchronise.
	 * This way, we'll be able to determine which files we want to
	 * delete in O(n) time instead of O(n * search) time.
	 * Plus, we can do the scan in-band and only allocate the files
	 * we want to delete.
	 */

	if (!hcreate(wflsz)) {
		ERR("hcreate");
		goto out;
	}

	for (i = 0; i < wflsz; i++) {
		memset(&hent, 0, sizeof(ENTRY));
		kpath = wfl[i].wpath;
		while (strncmp(kpath, "./", 2) == 0)
			kpath += 2;
		if ((hent.key = strdup(kpath)) == NULL) {
			ERR("strdup");
			goto out;
		}
		if ((hentp = hsearch(hent, ENTER)) == NULL) {
			ERR("hsearch");
			goto out;
		} else if (hentp->key != hent.key) {
			/*
			 * Duplicate entry; this may happen if we had a
			 * single src spec listed multiple times, so
			 * just drop it.
			 */
			free(hent.key);
		}
	}

	/*
	 * Now we're going to try to descend into all of the top-level
	 * directories stipulated by the file list.
	 * If the directories don't exist, it's ok.
	 */

	if ((fts = fts_open(cargv, FTS_PHYSICAL, NULL)) == NULL) {
		ERR("fts_open");
		goto out;
	}

	stripdir = strlen(root) + 1;
	topdir = NULL;
	errno = 0;
	while ((ent = fts_read(fts)) != NULL) {
		if (ent->fts_info == FTS_NS)
			continue;

		/*
		 * skip_post indicates that we just skipped recursing
		 * into this dir, so we should also not consider it for
		 * deletion (which is all we do in post-order).
		 */

		if (skip_post && ent->fts_info == FTS_DP) {
			skip_post = false;
			continue;
		}

		/*
		 * Skip subdirs of ${root}/. that are also top-level
		 * dirs.  This prevents visiting them more than once
		 * (i.e., once via ${root}/./topdir and once via
		 * ${root}/topdir).  We'll prefer to traverse top dirs
		 * via the latter path, which also allows us to
		 * determine the directory name needed for "deleting in
		 * ${topdir}" messages.
		 */

		if (ent->fts_info == FTS_D) {
			assert(!skip_post);

			for (j = 0; j < skipc; ++j) {
				if (strcmp(ent->fts_path, skipv[j]) == 0) {
					fts_set(fts, ent, FTS_SKIP);
					skip_post = true;
					break;
				}
			}

			if (skip_post)
				continue;
		}

		/*
		 * Determine the name of the top-level directory that
		 * we're currently traversing, to be used for "deleting
		 * in ${topdir}" messages.
		 */

		if (ent->fts_info == FTS_D) {
			for (j = 0; j < cargvs; ++j) {
				if (strcmp(ent->fts_path, cargv[j]) == 0) {
					topdir = cargv[j];
					break;
				}
			}
		}

		/*
		 * Here we want directories in post-order because that's
		 * where we'll ultimately schedule a directory for
		 * deletion.
		 */

		if (ent->fts_info != FTS_DP &&
		    !flist_fts_check(sess, ent, FARGS_RECEIVER)) {
			ent->fts_parent->fts_number++;
			errno = 0;
			continue;
		} else if (stripdir >= ent->fts_pathlen)
			continue;

		assert(ent->fts_statp != NULL);

		/* This is for macOS fts, which returns "foo//bar" */

		if (ent->fts_path[stripdir] == '/')
			stripdir++;

		/*
		 * Normalize the path by stripping any leading "./"
		 * components so that we don't have any false-negatives
		 * leading to a bogus deletion.
		 */

		rpath = ent->fts_path + stripdir;
		while (strncmp(rpath, "./", 2) == 0)
			rpath += 2;

		/* Filter files on delete. */

		if (!sess->opts->del_excl && ent->fts_info != FTS_DP &&
		    rules_match(rpath, (ent->fts_info == FTS_D),
		    FARGS_RECEIVER, perish_ent != NULL) == -1) {
			LOG2("skip excluded file %s", rpath);
			if (ent->fts_info == FTS_D)
				skip_post = true;
			ent->fts_parent->fts_number++;
			fts_set(fts, ent, FTS_SKIP);
			continue;
		}

		/*
		 * We only check directories in pre-order when we have
		 * not descended down a tree that we already know is
		 * perishing.
		 */

		if (ent->fts_info == FTS_D && perish_ent != NULL)
			continue;

		/* Look up in hashtable. */

		memset(&hent, 0, sizeof(ENTRY));
		hent.key = (char *)rpath;
		if (hsearch(hent, FIND) != NULL) {
			if (ent->fts_info == FTS_D &&
			    !sess->opts->recursive &&
			    strcmp(rpath, ".") != 0) { 
				assert(sess->opts->dirs);
				fts_set(fts, ent, FTS_SKIP);
			}
			continue;
		}

		/*
		 * Pre-order isn't used for deleting directories because
		 * we may have some files inside that are excluded from
		 * deletion, but we still want to do the above search in
		 * case we need to set the perish bit.
		 */

		if (ent->fts_info == FTS_D) {
			perish_ent = ent;
			continue;
		} else if (ent == perish_ent) {
			assert(ent->fts_info == FTS_DP);
			perish_ent = NULL;
		}

		if (ent->fts_info == FTS_DP && ent->fts_number > 0) {
			/*
			 * Just warn that we have some files inside that
			 * are not scheduled to be deleted, and
			 * propagate the exception in case we would have
			 * deleted the parent directory.
			 */
			WARNX("%s: not empty, cannot delete", ent->fts_path);
			ent->fts_parent->fts_number++;
			continue;
		}

		/* Not found: we'll delete it. */

		if (!flist_realloc(fl, sz, &max, FARGS_RECEIVER)) {
			ERRX1("flist_realloc");
			goto out;
		}
		f = &(*fl)[*sz - 1];

		if ((f->path = strdup(ent->fts_path)) == NULL) {
			ERR("strdup");
			goto out;
		}

		f->wpath = f->path + stripdir;
		flist_assert_wpath_len(f->wpath);
		flist_copy_stat(f, ent->fts_statp);

		assert(topdir != NULL);
		f->link = strdup(topdir + stripdir);
		if (f->link == NULL) {
			ERR("strdup");
			goto out;
		}

		errno = 0;
	}

	if (errno) {
		ERR("fts_read");
		goto out;
	}

	if (*fl != NULL)
		qsort(*fl, *sz, sizeof(struct flist), flist_cmp);
	rc = true;
out:
	if (fts != NULL)
		fts_close(fts);
	for (i = 0; i < cargvs; i++)
		free(cargv[i]);
	for (i = 0; i < skipc; i++)
		free(skipv[i]);
	free(cargv);
	free(skipv);
	hdestroy();
	return rc;
}

/*
 * Add a file to be deleted (after transfers are complete).
 * Return true on success, false on failure.
 */
bool
flist_add_del(struct sess *sess, const char *path, size_t stripdir,
    struct flist **fl, size_t *sz, size_t *flmax, const struct stat *st)
{
	struct flist *f;

	if (!flist_realloc(fl, sz, flmax, FARGS_RECEIVER)) {
		ERRX1("flist_realloc");
		return false;
	}

	f = &(*fl)[*sz - 1];
	if ((f->path = strdup(path)) == NULL) {
		ERR("strdup");
		return false;
	}

	f->wpath = f->path + stripdir;
	flist_assert_wpath_len(f->wpath);
	flist_copy_stat(f, st);
	return true;
}

/*
 * Delete all files and directories in "fl".
 * If called with a zero-length "fl", does nothing.
 * If dry_run is specified, simply write what would be done.
 */
void
flist_del(const struct sess *sess, int root, const struct flist *fl,
    size_t flsz)
{
	char		 buf[PATH_MAX]; /* backup file buffer */
	const char	*path, /* temporary fl path */
	      		*fmt; /* log message format */
	ssize_t		 inc; /* read forward (1) or backward (-1) */
	size_t		 i, /* temporary */
			 begin, /* index to start with */
			 end, /* index to end with */
			 del_limit = flsz; /* limit number deleted */
	int		 flag; /* unlinkat flag */

	if (flsz == 0)
		return;

	assert(sess->opts->del != DMODE_NONE);
	assert(sess->opts->recursive || sess->opts->dirs);

	begin = flsz - 1;
	end = begin - del_limit;
	inc = -1;

	for (i = begin; i != end; i += inc) {
		if (verbose > 0) {
			path = fl[i].wpath;

			/*
			 * Append a "/" to the "deleting ..." message
			 * format if the file is a directory:
			 */

			if (S_ISDIR(fl[i].st.mode))
				fmt = "*deleting %s/\n";
			else
				fmt = "*deleting %s\n";

			/* 
			 * Suppress the leading "*" from the "deleting
			 * ..." message format if not itemizing:
			 */

			fmt++;

			/*
			 * Strip all redundant leading "./" from the
			 * path:
			 */

			while (strncmp(path, "./", 2) == 0 &&
			    path[2] != '\0')
				path += 2;

			/* 
			 * Print "deleting in <topdir>" once for each
			 * unique top-level directory specified as a
			 * top-level dir in the flist (and hence scanned
			 * by flist_gen_dels()).  So, irrespective of
			 * fl[]'s order by file type, print "deleting in
			 * <topdir>" exactly once for any given topdir,
			 * before any "deleting <file>" messages are
			 * printed for files within that top-level
			 * directory.
			 */

			if (fl[i].link) {
				if (i == begin ||
				    strcmp(fl[i].link, fl[i - inc].link) != 0) {
					LOG2("deleting in %s", fl[i].link);
				}
			}

			print_7_or_8_bit(sess, fmt, path, NULL);
		}

		if (sess->opts->dry_run)
			continue;

		assert(root != -1);
		flag = S_ISDIR(fl[i].st.mode) ? AT_REMOVEDIR : 0;

		if (sess->opts->backup) {
			if (!S_ISDIR(fl[i].st.mode)) {
				LOG3("%s: doing backup", fl[i].wpath);
				if (snprintf(buf, sizeof(buf), "%s%s",
				    fl[i].wpath,
				    sess->opts->backup_suffix) >=
				    (int)sizeof(buf)) {
					ERR("%s: backup: compound "
					    "backup path too long: "
					    "%s%s > %d", fl[i].wpath,
					    fl[i].wpath,
					    sess->opts->backup_suffix,
					    (int)sizeof(buf));
					continue;
				}
				if (!backup_file(root, fl[i].wpath,
				    root, buf, 1, &fl[i].dstat)) {
					ERR("%s: backup_file: %s",
					    fl[i].wpath, buf);
					continue;
				}
			}
		}

		if (unlinkat(root, fl[i].wpath, flag) == -1 &&
		    errno != ENOENT) {
			ERR("%s: unlinkat", fl[i].wpath);
			continue;
		}
	}
}

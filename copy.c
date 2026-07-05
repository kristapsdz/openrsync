/*
 * Copyright (c) 2021 Claudio Jeker <claudio@openbsd.org>
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

#include <sys/stat.h>

#include <assert.h>
#if HAVE_ERR
# include <err.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

#define _MAXBSIZE (64 * 1024)

/*
 * We're using AT_RESOLVE_BENEATH in a couple of places just for some additional
 * safety on platforms that support it, so it's not a hard requirement.
 */
#ifndef AT_RESOLVE_BENEATH
#define	AT_RESOLVE_BENEATH	0
#endif

/*
 * Return true if all bytes in buffer are zero.
 * A buffer of zero length is also considered a zero buffer.
 * FIXME: is there a faster way to do this?
 */
bool
iszerobuf(const void *b, size_t len)
{
	const unsigned char *c = b;

	for (; len > 0; len--)
		if (*c++ != '\0')
			return false;

	return true;
}

/*
 * Calculate the depth of a path (in directories).  Account for ../, and
 * return -1 if the depth drops below zero.
 *
 * Note that in strict mode, non-leading ../ components are assumed to
 * be unsafe and will return -1 as well because we do not know if the
 * previous components would be replaced with a symlink that makes it
 * unsafe.
 */
static ssize_t
count_dir_depth(const char *path, ssize_t dirdepth, bool strict)
{
	const char	*dp, /* current position in path */
	      		*lastp; /* last seen position */
	bool		 leading = true; /* leading component */

	/* Empty paths have zero depth. */

	if (path == NULL || *path == '\0')
		return 0;

	dp = lastp = path;
	while (dp != NULL) {
		/* Skip any excess slashes */
		while (*dp == '/')
			dp++;

		if (strncmp(dp, "../", 3) == 0) {
			/* Traversing up directory depth */
			if (strict && !leading)
				return -1;
			dirdepth--;
		} else if (strncmp(dp, "./", 2) == 0) {
			/*
			 * No Change in directory depth This is more
			 * strict than we need to be, but it matches
			 * what rsync 3.x did.  Presumably openrsync
			 * won't be running on a machine where ./ could
			 * be replaced.
			 */
			leading = false;
		} else if (strchr(dp, '/') != NULL) {
			/* Traversing down directory depth */
			dirdepth++;

			/*
			 * If we didn't hit one of the above cases, then
			 * we're no longer a leading component.  We're
			 * defining leading here as everything up to the
			 * first non-..  and non-. component.
			 * Subsequent ../ should fail.
			 */
			leading = false;
		}

		/* If we ever go above the starting point, fail. */

		if (strict && dirdepth < 0)
			return -1;

		lastp = dp;
		dp = strchr(dp, '/');
		if (dp != NULL) {
			dp++;
			/*
			 * If we had a trailing '/', we'll zap lastp and
			 * break so that we don't examine the last
			 * component.
			 */
			if (*dp == '\0') {
				lastp = NULL;
				break;
			}
		}
	}

	/*
	 * lastp will be NULL if we had a trailing slash, as we don't
	 * need to inspect anything else -- it was properly accounted
	 * for in the loop.
	 */

	if (lastp != NULL && strcmp(lastp, "..") == 0) {
		dirdepth--;
		if (strict && !leading)
			return -1;
	}

	return dirdepth;
}

/*
 * Determine if the target of a symlink is "safe", relative to the src
 * (the path of the symlink).  Absolute symlinks are unsafe.  Any
 * symlink target that reaches above the root, is unsafe.
 * This function returns a negative ("it's unsafe").  Be warned.
 */
bool
is_unsafe_link(const char *link, const char *src, const char *root)
{
	size_t	 rootlen; /* length of the root */
	ssize_t	 srcdepth, /* depth of the source */
		 linkdepth; /* depth of the link dir */

	/* Blank or absolute symlinks are always unsafe */

	if (link == NULL || *link == '\0' || *link == '/')
		return true;

	if (root != NULL) {
		rootlen = strlen(root);
		if (strncmp(src, root, rootlen) == 0) {
			/* Make src relative to root */
			src += rootlen;
			if (*src == '/') {
				src++;
			}
		} else {
			/* src is outside of the root, this is unsafe */
			WARNX("%s: is_unsafe_link: src file is outside "
			    "of the root: %s\n", src, root);
			return true;
		}
	}

	srcdepth = count_dir_depth(src, 0, false);
	if (srcdepth < 0) {
		/* src escapes the root, this in unsafe */
		WARNX("%s: is_unsafe_link: src escaped the root: "
		    "%s\n", src, root);
		return true;
	}

	linkdepth = count_dir_depth(link, srcdepth, true);
	return linkdepth < 0;
}

/*
 * Drain from one descriptor into another, truncating the resulting file
 * to the last position written.
 * FIXME: are there faster ways of doing this?
 * Returns false on failure, true on success.
 */
static bool
copy_internal(int fromfd, int tofd)
{
	char	 buf[_MAXBSIZE]; /* transfer buffer */
	ssize_t	 r, /* read result */
		 w; /* write result */

	while ((r = read(fromfd, buf, sizeof(buf))) > 0) {
		if (iszerobuf(buf, sizeof(buf))) {
			if (lseek(tofd, r, SEEK_CUR) == -1)
				return false;
		} else {
			w = write(tofd, buf, r);
			if (r != w || w == -1)
				return false;
		}
	}
	if (r == -1)
		return false;
	if (ftruncate(tofd, lseek(tofd, 0, SEEK_CUR)) == -1)
		return false;
	return true;
}

/*
 * Create the directory struction required for storing backups.  The
 * fname will be the relative filename prefixed with the backup_dir.  We
 * then check the deepest directory and see if we can mkdir it, if we
 * can (or it exists), we advance to the second step.  If the mkdir
 * fails with ENOENT because the parent doesn't exist, we work backwards
 * through the provided path until we find a directory that exists or
 * that we can create.
 *
 * In the second step, we work forwards through the path again and
 * create the child directories required, and chown/chmod them match the
 * directories that we are backing up.
 */
static bool
mk_backup_dir(const struct sess *sess, int rootfd, const char *fname)
{
	struct stat	 st; /* temporary stat */
	char		*bpath, /* path */
			*bporig, /* path strdup copy */
			*bpend, /* end of path */
			*bpp, /* temporary path part */
			*rpath = NULL; /* relative path part */
	const mode_t	 mode = S_IRWXU | S_IRGRP | S_IXGRP | 
				S_IROTH | S_IXOTH; /* create mode */
	bool		 rc = false; /* return code */

	bporig = bpath = strdup(fname);
	if (bpath == NULL)
		return false;

	bpend = bpath + strlen(bpath);
	while (strncmp(bpath, "./", 2) == 0)
		bpath += 2;

	rpath = bpath + strlen(sess->opts->backup_dir);
	assert(rpath < bpend);
	if (*rpath == '/')
		rpath++;

	/*
	 * Walk backwards through the backup path to find the deepest
	 * directory that already exists.
	 */

	while ((bpp = strrchr(bpath, '/')) != NULL) {
		*bpp = '\0';
		if (mkdirat(rootfd, bpath, mode) == 0 ||
		    errno == EEXIST) {
			/*
			 * Found a directory that exists or that we
			 * could create.
			 */
			break;
		} else if (errno != ENOENT) {
			ERR("%s: mkdir", bpath);
			goto out;
		}
	}

	/*
	 * Walk forwards through the backup path creating the ancestor
	 * directories as we go.
	 */

	bpp = bpath + strlen(bpath);
	assert(bpp < bpend);

	while (true) {
		if ((rpath + strlen(rpath)) != bpend &&
		    *rpath != '\0') {
			if (fstatat(rootfd, rpath, &st,
			    AT_RESOLVE_BENEATH) < 0) {
				ERR("%s: stat", rpath);
				goto out;
			} else {
				/* FIXME: errors... */
				fchownat(rootfd, bpath, st.st_uid,
				    st.st_gid, AT_SYMLINK_NOFOLLOW);
				fchmodat(rootfd, bpath, st.st_mode,
				    AT_SYMLINK_NOFOLLOW);
			}
		}
		*bpp = '/';
		bpp += strlen(bpp);
		if (bpp == bpend)
			break;

		assert(bpp < bpend);
		if (mkdirat(rootfd, bpath, mode) < 0) {
			ERR("%s: mkdir", bpath);
			goto out;
		}
	}

	rc = true;
out:
	free(bporig);
	return rc;
}

/*
 * Same arguments as move_file(), but matching the metadata of the given
 * "dstat".  This is often used when backing up an existing file by
 * moving it to another file of the same name and a suffix.
 */
bool
backup_file(int fromdfd, const char *fname, int todfd,
    const char *tname, bool replace, const struct fldstat *dstat)
{
	struct stat	 st; /* stat of new file */
	int		 rc; /* temporary return code */

	if (!move_file(fromdfd, fname, todfd, tname, replace, false))
		return false;

	if (fstatat(todfd, tname, &st, 0) == -1)
		return false;

	/*
	 * Set metadata on the backup file to match the metadata from
	 * the original destination file.
	 */

	if (st.st_mtim.tv_sec != dstat->mtime.tv_sec ||
	    st.st_mtim.tv_nsec != dstat->mtime.tv_nsec) {
		const struct timespec ts[] = {
			dstat->atime, dstat->mtime,
		};

		rc = utimensat(todfd, tname, ts, AT_SYMLINK_NOFOLLOW);
		if (rc != 0)
			ERR("%s: utimensat", tname);
	}

	if (st.st_mode != dstat->mode) {
		rc = fchmodat(todfd, tname, dstat->mode,
		    AT_SYMLINK_NOFOLLOW);
		if (rc != 0)
			ERR("%s: fchmodat", tname);
	}

	if (st.st_uid != dstat->uid || st.st_gid != dstat->gid) {
		const uid_t uid = dstat->uid;
		const uid_t gid = dstat->gid;

		if (uid != (uid_t)-1 || gid != (gid_t)-1) {
			rc = fchownat(todfd, tname, uid, gid,
			    AT_SYMLINK_NOFOLLOW);
			if (rc != 0)
				ERR("%s: fchownat", tname);
		}
	}

	return true;
}

/*
 * Like backup_file(), except into a directory.
 * Returns true on success, false on failure.
 */
bool
backup_to_dir(const struct sess *sess, int rootfd,
    const struct flist *f, const char *dest, mode_t mode)
{
	struct stat	 st;

	/* Can't backup files that do not exist. */

	if (fstatat(rootfd, f->path, &st, AT_SYMLINK_NOFOLLOW) < 0)
		return true;

	if (!mk_backup_dir(sess, rootfd, dest)) {
		ERR("%s: mk_backup_dir: %s", f->path, dest);
		return false;
	}

	/* Make an empty directory as the backup. */

	if (S_ISDIR(mode)) {
		/* FIXME: downstream has this reversed. */
		if (mkdirat(rootfd, dest, mode) < 0) {
			ERR("%s: mkdirat", dest);
			return false;
		}
		/* FIXME: log error. */
		unlinkat(rootfd, f->path, AT_REMOVEDIR);
	} else if (sess->opts->preserve_links && S_ISLNK(mode)) {
		/* Apply safe_symlinks here. */
		/* FIXME: log error. */
		unlinkat(rootfd, dest, AT_RESOLVE_BENEATH);
		if (symlinkat(f->link, rootfd, dest) < 0) {
			ERR("%s: symlinkat", dest);
			return false;
		}
		/* FIXME: log error. */
		unlinkat(rootfd, f->path, AT_RESOLVE_BENEATH);
	} else if (!S_ISREG(mode)) {
		WARNX("backup_to_dir: skipping non-regular file "
		    "%s\n", f->path);
		return true;
	} else {
		if (!backup_file(rootfd, f->path, rootfd, dest, 1,
		    &f->dstat)) {
			ERR("%s: backup_file: %s", f->path, dest);
			return false;
		}
	}

	return true;
}

/*
 * Move the file in fromdfd named 'fname' to the path named by toodfd +
 * 'tname'.  "replace" is set to indicate that we aren't surprised if a
 * file does exist there already, but we won't complain if it doesn't.
 * "skip_metadata" may be set if the caller intends to, e.g., set times
 * and permissions immediately after anyways.  This can avoid some
 * classes of errors if we weren't going to preserve the src file
 * anyways.
 * Returns false on failure, true on success.
 */
bool
move_file(int fromdfd, const char *fname, int todfd, const char *tname,
    bool replace, bool skip_metadata)
{
	int          fromfd, /* "from" descriptor */
		     tofd, /* "to" descriptor */
		     ret,
		     serrno, 
		     toflags = O_WRONLY | O_NOFOLLOW | O_TRUNC | O_CREAT;
	bool         rc = false;
	struct stat  fromst, tost;

	if (!replace)
		toflags |= O_EXCL;

	/* We'll try a rename(2) first. */

	ret = renameat(fromdfd, fname, todfd, tname);
	if (ret == 0)
		return true;
	if (ret == -1 && errno != EXDEV) {
		ERR("renameat");
		return false;
	}

	/* Fallback to a copy. */

	fromfd = openat(fromdfd, fname, O_RDONLY | O_NOFOLLOW);
	if (fromfd == -1) {
		ERR("openat from (%s)", fname);
		return false;
	}

	/* Unlink tname if it exists and is not writeable */

	if (faccessat(todfd, tname, W_OK, AT_RESOLVE_BENEATH) == -1 &&
	    errno == EACCES)
		unlinkat(todfd, tname, AT_RESOLVE_BENEATH);

	tofd = openat(todfd, tname, toflags, 0600);
	if (tofd == -1) {
		serrno = errno;
		close(fromfd);
		errno = serrno;
		ERR("openat to (%s)", fname);
		return false;
	}

	if (copy_internal(fromfd, tofd) && !skip_metadata) {
		ret = fstat(tofd, &tost);
		if (ret)
			goto errout;

		ret = fstat(fromfd, &fromst);
		if (ret)
			goto errout;

		if (fromst.st_mode != tost.st_mode) {
			ret = fchmod(tofd, fromst.st_mode);
			if (ret == -1)
				ERR("%s: fchmod", tname);
		}

		if (fromst.st_uid != tost.st_uid ||
		    fromst.st_gid != tost.st_gid) {
			ret = fchown(tofd, fromst.st_uid, fromst.st_gid);
			if (ret == -1)
				ERR("%s: fchown to %d.%d", tname, fromst.st_uid,
						fromst.st_gid);
		}

		if (fromst.st_mtime != tost.st_mtime) {
			struct timespec ts[] = {
				fromst.st_atim, fromst.st_mtim
			};
			ret = futimens(tofd, ts);
			if (ret == -1)
				ERR("%s: futimens", tname);
		}
	}

	rc = true;
errout:
	serrno = errno;
	close(fromfd);
	close(tofd);
	errno = serrno;

	if (rc)
		(void)unlinkat(fromdfd, fname, 0);

	return rc;
}

/*
 * Copy the file from "f" within "basedir" offset from "rootfd" directly
 * into "rootfd".  WARNING: this function calls err() and exits on
 * failure.
 */
void
copy_file(int rootfd, const char *basedir, const struct flist *f)
{
	int fromfd, tofd, dfd;

	dfd = openat(rootfd, basedir, O_RDONLY | O_DIRECTORY);
	if (dfd == -1)
		err(ERR_FILE_IO, "%s: copy_file dfd: openat", basedir);

	fromfd = openat(dfd, f->path, O_RDONLY | O_NOFOLLOW);
	if (fromfd == -1)
		err(ERR_FILE_IO, "%s/%s: copy_file fromfd: openat", basedir, f->path);
	close(dfd);

	tofd = openat(rootfd, f->path,
	    O_WRONLY | O_NOFOLLOW | O_TRUNC | O_CREAT, 0600);
	if (tofd == -1)
		err(ERR_FILE_IO, "%s: copy_file tofd: openat", f->path);

	if (!copy_internal(fromfd, tofd))
		err(ERR_FILE_IO, "%s: copy file", f->path);

	close(fromfd);
	close(tofd);
}

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
#if HAVE_ERR
# include <err.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
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
static bool
iszerobuf(const void *b, size_t len)
{
	const unsigned char *c = b;

	for (; len > 0; len--)
		if (*c++ != '\0')
			return false;

	return true;
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

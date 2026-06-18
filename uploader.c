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

#include <sys/poll.h>
#include <sys/stat.h>

#include <assert.h>
#if HAVE_ERR
# include <err.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <search.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"
#include "rules.h"

enum	uploadst {
	UPLOAD_FIND_NEXT = 0, /* find next to upload to sender */
	UPLOAD_WRITE, /* wait to write to sender */
	UPLOAD_FINISHED /* nothing more to do in phase */
};

/*
 * Used to keep track of data flowing from the receiver to the sender.
 * This is managed by the receiver process.
 */
struct	upload {
	enum uploadst	 state;
	char		*buf; /* if not NULL, pending upload */
	size_t		 bufsz; /* size of buf */
	size_t		 bufmax; /* maximum size of buf */
	size_t		 bufpos; /* position in buf */
	size_t		 idx; /* current transfer index */
	size_t		 chunksz; /* max send/write size to sender */
	mode_t		 oumask; /* umask for creating files */
	char		*root; /* destination directory path */
	int		 rootfd; /* destination directory */
	size_t		 csumlen; /* checksum length */
	int		 fdout; /* write descriptor to sender */
	struct flist 	*fl; /* file list */
	size_t		 flsz; /* size of file list */
	size_t		 nextack; /* next idx to acknowledge */
	struct flist	*dfl; /* delayed delete file list */
	size_t		 dflsz; /* size of delayed delete list */
	size_t		 dflmax; /* allocated size of delayed delete list */
	int		*newdir; /* non-zero if mkdir'd */
	size_t		 phase; /* current uploader phase (transfer, redo) */
#define	PHASE_XFER	 0 /* FIXME: phase should be enum? */
#define	PHASE_REDO	 1  		 
#define	PHASE_DLUPDATES	 2 /* not supported: protocol 29 */
	bool		 pre_dir_delete_done; /* recursive guard */
};

static bool pre_dir_delete(struct upload *, struct sess *, enum delmode); /* FIXME: move */
static bool check_path(int, const char *); /* FIXME: move into place */

static bool
force_delete_applicable(const struct upload *p __unused,
    const struct sess *sess, mode_t mode)
{
	return sess->opts->del == DMODE_BEFORE;
}

/*
 * Save the original destination file metadata so that it can be applied
 * to the backup file.
 */
static void
dstat_save(const struct stat *st, struct fldstat *dstat)
{
	dstat->mode = st->st_mode;
	dstat->atime = st->st_atimespec;
	dstat->mtime = st->st_mtimespec;
	dstat->uid = st->st_uid;
	dstat->gid = st->st_gid;
}

static int32_t
itemize_changes(const struct sess *sess, const struct stat *st,
    const struct flist *f)
{
	bool superuser = false;

	int32_t iflags = 0;

	if (sess->opts->preserve_perms && st->st_mode != f->st.mode &&
	    (superuser || st->st_uid == geteuid()))
		iflags |= IFLAG_PERMS;

	if (st->st_mtime != f->st.mtime && !S_ISLNK(f->st.mode)) {
		if (sess->opts->preserve_times) {
			if (!S_ISDIR(f->st.mode) || !sess->opts->omit_dir_times)
				iflags |= IFLAG_TIME;
		} else {
			if (S_ISREG(f->st.mode) ||
			    S_ISBLK(f->st.mode) || S_ISCHR(f->st.mode)) {
				iflags |= IFLAG_TIME;
			}
		}
	}

	if (st->st_size != f->st.size && S_ISREG(f->st.mode))
		iflags |= IFLAG_SIZE;

	if (sess->opts->preserve_uids && st->st_uid != f->st.uid &&
	    f->st.uid != (uid_t)(-1) && superuser)
		iflags |= IFLAG_OWNER;

	if (sess->opts->preserve_gids && st->st_gid != f->st.gid &&
	    f->st.gid != (gid_t)(-1) && (superuser || getegid() == f->st.gid))
		iflags |= IFLAG_GROUP;

	return iflags;
}

/*
 * Prepare the overall block set's metadata.
 * We always have at least one block.
 * The block size is an important part of the algorithm.
 * I use the same heuristic as the reference rsync, but implemented in a
 * bit more of a straightforward way.
 * In general, if not overriden, the individual block length is the
 * rounded square root of the total file size.
 * The minimum block length is 700.
 */
static void
init_blkset(struct blkset *p, off_t sz, long block_size)
{
	double	 v;

	if (block_size > 0)
		p->len = block_size;
	else if (sz >= (BLOCK_SIZE_MIN * BLOCK_SIZE_MIN)) {
		/* Simple rounded-up integer square root. */

		v = sqrt(sz);
		p->len = ceil(v);

		/*
		 * Always be a multiple of eight.
		 * There's no reason to do this, but rsync does.
		 */

		if ((p->len % 8) > 0)
			p->len += 8 - (p->len % 8);
	} else
		p->len = BLOCK_SIZE_MIN;

	p->size = sz;
	if ((p->blksz = sz / p->len) == 0)
		p->rem = sz;
	else
		p->rem = sz % p->len;

	/* If we have a remainder, then we need an extra block. */

	if (p->rem)
		p->blksz++;
}

/*
 * For each block, prepare the block's metadata.
 * We use the mapped "map" file to set our checksums.
 */
static void
init_blk(struct blk *p, const struct blkset *set, off_t offs,
	size_t idx, const void *map, const struct sess *sess)
{

	p->idx = idx;
	/* Block length inherits for all but the last. */
	p->len = (idx == set->blksz - 1 && set->rem) ? set->rem : set->len;
	p->offs = offs;

	p->chksum_short = hash_fast(map, p->len);
	hash_slow(map, p->len, p->chksum_long, sess);
}

/*
 * Handle a symbolic link.
 * If we encounter directories existing in the symbolic link's place,
 * then try to unlink the directory.
 * Otherwise, simply overwrite with the symbolic link by renaming.
 * Return <0 on failure 0 on success.
 */
static int
pre_symlink(struct upload *p, struct sess *sess)
{
	struct flist	 bf; /* copy of "f" */
	struct stat	 st; /* stat of current file path */
	struct flist	*f; /* current file */
	char		*b, /* symlink filename buffer */
			*temp = NULL; /* temporary template */
	struct flist	*dfl = NULL; /* deletion flist array */
	int		 rc; /* temporary return code */
	size_t		 dflsz = 0; /* array size of dfl */
	bool		 updatelink = false, /* rename link */
			 newlink = false; /* build link */

	f = &p->fl[p->idx];
	assert(S_ISLNK(f->st.mode));

	if (!sess->opts->preserve_links) {
		LOG0("skipping non-regular file \"%s\"", f->path);
		return 0;
	}

	/* See if the symlink already exists. */

	rc = fstatat(p->rootfd, f->path, &st, AT_SYMLINK_NOFOLLOW);
	if (rc == -1) {
		if (sess->opts->dry_run) {
			f->iflags = IFLAG_NEW | IFLAG_LOCAL_CHANGE;
			return 0;
		}
		if (errno != ENOENT) {
			ERR("%s: fstatat", f->path);
			return -1;
		}
	}

	/*
	 * If the symlink is a directory, then try to unlink the
	 * directory prior to overwriting with a symbolic link.  If it's
	 * a non-directory, we just overwrite it.
	 */

	if (rc != -1 && !S_ISLNK(st.st_mode)) {
		if (!sess->opts->dry_run) {
			if (force_delete_applicable(p, sess, st.st_mode) &&
			    S_ISDIR(st.st_mode)) {
				memcpy(&bf, f, sizeof(bf));
				bf.st.flags |= FLSTAT_TOP_DIR;
				bf.st.mode = st.st_mode;
				if (!flist_gen_dels(sess, p->root,
				    &dfl, &dflsz, &bf, 1)) {
					ERRX1("flist_gen_dels symlink");
					return -1;
				}
				flist_del(sess, p->rootfd, dfl, dflsz);
			}
			if (S_ISDIR(st.st_mode) && unlinkat(p->rootfd,
			    f->path, S_ISDIR(st.st_mode) ? AT_REMOVEDIR : 0) == -1) {
				ERR("%s: unlinkat", f->path);
				return -1;
			}
		}
		rc = -1;
	}

	/*
	 * If the symbolic link already exists, then make sure that it
	 * points to the correct place.
	 */

	if (rc != -1) {
		b = symlinkat_read(p->rootfd, f->path, st.st_size);
		if (b == NULL) {
			ERRX1("symlinkat_read");
			return -1;
		}
		if (strcmp(f->link, b) != 0) {
			free(b);
			b = NULL;
			LOG3("%s: updating symlink: %s", f->path, f->link);
			updatelink = true;
		}
		free(b);
		b = NULL;
		f->iflags |= itemize_changes(sess, &st, f);
	} else
		f->iflags = IFLAG_NEW | IFLAG_LOCAL_CHANGE;

	if (sess->opts->dry_run)
		return 0;

	/*
	 * Create the temporary file as a symbolic link, then rename the
	 * temporary file as the real one, overwriting anything there.
	 */

	if (rc == -1 || updatelink) {
		LOG3("%s: creating symlink: %s", f->path, f->link);
		if (mktemplate(&temp, f->path,
		    sess->opts->recursive || strchr(f->path, '/') != NULL,
		    IS_TMPDIR) == -1) {
			ERRX1("mktemplate");
			return -1;
		}
		if (mkstemplinkat(f->link, TMPDIR_FD, temp) == NULL) {
			ERR("mkstemplinkat");
			free(temp);
			return -1;
		}
		newlink = true;
	}

	if (rc != -1)
		dstat_save(&st, &f->dstat);

	rsync_set_metadata_at(sess, newlink, p->rootfd, f,
	    newlink && temp != NULL ? temp : f->path);

	if (newlink && temp != NULL) {
		if (!move_file(TMPDIR_FD, temp, p->rootfd, f->path, 1, 0)) {
			ERR("%s: move file %s", temp, f->path);
			(void)unlinkat(TMPDIR_FD, temp, 0);
			free(temp);
			return -1;
		}
		free(temp);
	}

	return 0;
}

/*
 * See pre_symlink(), but for devices.
 * FIXME: this is very similar to the other pre_xxx() functions.
 * Return <0 on failure 0 on success.
 */
static int
pre_dev(struct upload *p, struct sess *sess)
{
	struct stat	 st; /* stat of current file path */
	struct flist	*f; /* current file index */
	char		*temp = NULL; /* template buffer */
	int		 rc; /* temporary return code */
	bool		 newdev = false, /* new device */
			 updatedev = false; /* updated device */

	f = &p->fl[p->idx];
	assert(S_ISBLK(f->st.mode) || S_ISCHR(f->st.mode));

	if (!sess->opts->devices || getuid() != 0) {
		WARNX("skipping non-regular file %s", f->path);
		return 0;
	}

	/* See if the dev already exists. */

	rc = fstatat(p->rootfd, f->path, &st, AT_SYMLINK_NOFOLLOW);
	if (rc == -1) {
		if (sess->opts->dry_run) {
			f->iflags = IFLAG_NEW | IFLAG_LOCAL_CHANGE;
			return 0;
		}
		if (errno != ENOENT) {
			ERR("%s: fstatat", f->path);
			return -1;
		}
	}

	/*
	 * If a non-device exists in its place, we'll replace that.  If
	 * it replaces a directory, remove the directory first.
	 */

	if (rc != -1 && !(S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode))) {
		if (!sess->opts->dry_run) {
			if (force_delete_applicable(p, sess, st.st_mode))
				if (pre_dir_delete(p, sess, DMODE_DURING) == 0)
					return -1;
			if (S_ISDIR(st.st_mode) &&
			    unlinkat(p->rootfd, f->path, AT_REMOVEDIR) == -1) {
				ERR("%s: unlinkat", f->path);
				return -1;
			}
		}
		rc = -1;
	}

	/* Make sure existing device is of the correct type. */

	if (rc != -1) {
		if ((f->st.mode & (S_IFCHR|S_IFBLK)) !=
		    (st.st_mode & (S_IFCHR|S_IFBLK)) ||
		    f->st.rdev != st.st_rdev) {
			LOG3("%s: updating device", f->path);
			updatedev = true;
		}
		f->iflags |= itemize_changes(sess, &st, f);
	} else
		f->iflags = IFLAG_NEW | IFLAG_LOCAL_CHANGE;

	if (sess->opts->dry_run)
		return 0;

	if (rc == -1 || updatedev) {
		if (mktemplate(&temp, f->path,
		    sess->opts->recursive || strchr(f->path, '/') != NULL,
		    IS_TMPDIR) == -1) {
			ERRX1("mktemplate");
			return -1;
		}
		if (mkstempnodat(TMPDIR_FD, temp,
		    f->st.mode & (S_IFCHR|S_IFBLK), f->st.rdev) == NULL) {
			ERR("mkstempnodat");
			free(temp);
			return -1;
		}
		newdev = true;
	}

	if (rc != -1)
		dstat_save(&st, &f->dstat);

	rsync_set_metadata_at(sess, newdev, TMPDIR_FD, f,
	    newdev && temp != NULL ? temp : f->path);

	if (newdev && temp != NULL) {
		if (!move_file(TMPDIR_FD, temp, p->rootfd, f->path, 1, 0)) {
			ERR("%s: move_file %s", temp, f->path);
			(void)unlinkat(TMPDIR_FD, temp, 0);
			free(temp);
			return -1;
		}
		free(temp);
	}

	return 0;
}

/*
 * See pre_symlink(), but for FIFOs.
 * FIXME: this is very similar to the other pre_xxx() functions.
 * Return <0 on failure 0 on success.
 */
static int
pre_fifo(struct upload *p, struct sess *sess)
{
	struct stat	 st; /* stat of current file path */
	struct flist	*f; /* current file */
	int		 rc; /* temporary return code */
	char		*temp = NULL; /* template buffer */
	bool		 newfifo = false; /* new fifo created */

	f = &p->fl[p->idx];
	assert(S_ISFIFO(f->st.mode));

	if (!sess->opts->specials) {
		WARNX("skipping non-regular file %s", f->path);
		return 0;
	}

	/* See if the fifo already exists.  */

	rc = fstatat(p->rootfd, f->path, &st, AT_SYMLINK_NOFOLLOW);
	if (rc == -1) {
		if (sess->opts->dry_run) {
			f->iflags = IFLAG_NEW | IFLAG_LOCAL_CHANGE;
			return 0;
		}
		if (errno != ENOENT) {
			ERR("%s: fstatat", f->path);
			return -1;
		}
	}

	/*
	 * If it exists as a non-FIFO, unlink it (if a directory) then mark it
	 * from replacement.
	 */

	if (rc != -1 && !S_ISFIFO(st.st_mode)) {
		if (!sess->opts->dry_run) {
			if (force_delete_applicable(p, sess, st.st_mode))
				if (!pre_dir_delete(p, sess, DMODE_DURING))
					return -1;
			if (S_ISDIR(st.st_mode) &&
			    unlinkat(p->rootfd, f->path, AT_REMOVEDIR) == -1) {
				ERR("%s: unlinkat", f->path);
				return -1;
			}
		}
		rc = -1;
	}

	if (rc == -1) {
		if (!sess->opts->dry_run) {
			if (mktemplate(&temp, f->path,
			    sess->opts->recursive || strchr(f->path, '/') != NULL,
			    IS_TMPDIR) == -1) {
				ERRX1("mktemplate");
				return -1;
			}
			if (mkstempfifoat(TMPDIR_FD, temp) == NULL) {
				ERR("mkstempfifoat");
				free(temp);
				return -1;
			}
		}
		f->iflags = IFLAG_NEW | IFLAG_LOCAL_CHANGE;
		newfifo = true;
	} else {
		LOG3("%s: updating fifo", f->path);
		f->iflags |= itemize_changes(sess, &st, f);
	}

	if (rc != -1)
		dstat_save(&st, &f->dstat);

	if (sess->opts->dry_run)
		return 0;

	rsync_set_metadata_at(sess, newfifo, TMPDIR_FD, f,
	    newfifo && temp != NULL ? temp : f->path);

	if (newfifo && temp != NULL) {
		if (!move_file(TMPDIR_FD, temp, p->rootfd, f->path, 1, 0)) {
			ERR("%s: move_file %s", temp, f->path);
			(void)unlinkat(TMPDIR_FD, temp, 0);
			free(temp);
			return -1;
		}
		free(temp);
	}

	return 0;
}

/*
 * See pre_symlink(), but for socket files.
 * FIXME: this is very similar to the other pre_xxx() functions.
 * Return <0 on failure 0 on success.
 */
static int
pre_sock(struct upload *p, struct sess *sess)
{
	struct stat	 st; /* stat of current file */
	struct flist	*f; /* current file */
	int		 rc; /* temporary return code */
	char		*temp = NULL; /* template buffer */
	bool		 newsock = false; /* new sock created */

	f = &p->fl[p->idx];
	assert(S_ISSOCK(f->st.mode));

	if (!sess->opts->specials) {
		WARNX("skipping non-regular file %s", f->path);
		return 0;
	}

	/* See if the fifo already exists. */

	rc = fstatat(p->rootfd, f->path, &st, AT_SYMLINK_NOFOLLOW);
	if (rc == -1) {
		if (sess->opts->dry_run) {
			f->iflags = IFLAG_NEW | IFLAG_LOCAL_CHANGE;
			return 0;
		}
		if (errno != ENOENT) {
			ERR("%s: fstatat", f->path);
			return -1;
		}
	}

	/*
	 * If it exists as a non-FIFO, unlink it (if a directory) then mark it
	 * from replacement.
	 */

	if (rc != -1 && !S_ISSOCK(st.st_mode)) {
		if (!sess->opts->dry_run) {
			if (S_ISDIR(st.st_mode) &&
			    unlinkat(p->rootfd, f->path, AT_REMOVEDIR) == -1) {
				ERR("%s: unlinkat", f->path);
				return -1;
			}
		}
		rc = -1;
	}

	if (rc == -1) {
		if (!sess->opts->dry_run) {
			if (mktemplate(&temp, f->path,
			    sess->opts->recursive || strchr(f->path, '/') != NULL,
			    IS_TMPDIR) == -1) {
				ERRX1("mktemplate");
				return -1;
			}
			if (mkstempsock(p->root, temp) == NULL) {
				ERR("mkstempsock");
				free(temp);
				return -1;
			}
		}
		f->iflags = IFLAG_NEW | IFLAG_LOCAL_CHANGE;
		newsock = true;
	} else {
		LOG3("%s: updating sock", f->path);
		f->iflags |= itemize_changes(sess, &st, f);
	}

	if (sess->opts->dry_run)
		return 0;

	rsync_set_metadata_at(sess, newsock, TMPDIR_FD, f,
	    newsock && temp != NULL ? temp : f->path);

	if (newsock && temp != NULL) {
		if (!move_file(TMPDIR_FD, temp, p->rootfd, f->path, 1, 0)) {
			ERR("%s: move_file %s", temp, f->path);
			(void)unlinkat(TMPDIR_FD, temp, 0);
			free(temp);
			return -1;
		}
		free(temp);
	}

	return 0;
}

/*
 * Called before we update a directory to see if we need to delete any
 * files inside in the process.
 * Return false on failure, true on success.
 */
static bool
pre_dir_delete(struct upload *p, struct sess *sess, enum delmode delmode)
{
	struct flist	*cf, /* current file p->fl */
			*f; /* current indexed file in p->fl */
	char		*dirpath, /* path in root */
			*parg[2], /* fts_open path */
			*slp;
	FTS		*fts = NULL; /* fts traversal */
	FTSENT		*ent, *perish_ent = NULL;
	size_t		 stripdir, /* length of path to strip */
			 i, /* temporary */
			 slpos;
	ENTRY		 hent, *hentp; /* table entries */
	bool		 isroot, /* if path is cwd */
			 ret = false; /* return code */

	f = &p->fl[p->idx];
	isroot = strcmp(f->path, ".") == 0;

	/*
	 * Ignore subdirs of "." in --dirs mode with recursion disabled
	 * so that we don't try to delete them multiple times.
	 */

	if (!sess->opts->recursive) {
		if (p->pre_dir_delete_done)
			return 1;
		if (isroot)
			p->pre_dir_delete_done = true;
	}

	if (asprintf(&dirpath, "%s/%s", p->root,
	    isroot ? "" : f->path) == -1) {
		ERRX1("%s: asprintf", f->path);
		return ret;
	}

	if (!hcreate(p->flsz)) {
		ERR("hcreate");
		goto out;
	}

	/*
	 * Generate a list of just the paths in this directory that
	 * should exist.
	 */

	stripdir = strlen(f->path) + 1;
	for (i = p->idx; i < p->flsz; i++) {
		/*
		 * Stop scanning once we're backed out of the directory
		 * we're looking at.
		 */
		cf = &p->fl[i];

		if (strcmp(cf->wpath, ".") == 0)
			continue;

		if (!isroot &&
		    strncmp(f->path, cf->wpath, stripdir - 1) != 0)
			break;

		/* Omit subdirectories' contents */

		slp = strrchr(cf->wpath, '/');
		slpos = (slp != NULL ? slp - cf->wpath : 0);

		if (isroot) {
			if (slpos != 0)
				continue;
		} else if (slpos >= stripdir)
			continue;

		memset(&hent, 0, sizeof(hent));
		if ((hent.key = strdup(cf->wpath)) == NULL) {
			ERR("strdup");
			goto out;
		}

		if ((hentp = hsearch(hent, ENTER)) == NULL) {
			ERR("hsearch");
			goto out;
		} else if (hentp->key != hent.key) {
			ERRX("%s: duplicate", cf->wpath);
			free(hent.key);
			goto out;
		}
	}

	parg[0] = dirpath;
	parg[1] = NULL;

	rules_base(dirpath);

	if ((fts = fts_open(parg, FTS_PHYSICAL, NULL)) == NULL) {
		ERR("fts_open");
		goto out;
	}

	stripdir = strlen(p->root) + 1;
	while ((ent = fts_read(fts)) != NULL) {
		if (ent->fts_info == FTS_NS)
			continue;
		else if (stripdir >= ent->fts_pathlen)
			continue;

		if (ent->fts_info != FTS_DP &&
		    !flist_fts_check(sess, ent, FARGS_RECEIVER)) {
			if (ent->fts_errno != 0) {
				if (ent->fts_info == FTS_DNR)
					LOG1("%.*s",
					    (int)ent->fts_namelen,
					    ent->fts_name);
			}
			errno = 0;
			continue;
		}

		assert(ent->fts_statp != NULL);

		/* This is for macOS fts, which returns "foo//bar" */

		if (ent->fts_path[stripdir] == '/')
			stripdir++;

		if (!sess->opts->del_excl && ent->fts_info != FTS_DP &&
		    rules_match(ent->fts_path + stripdir,
		    (ent->fts_info == FTS_D), FARGS_RECEIVER,
		    perish_ent != NULL) == -1) {
			LOG2("skip excluded file %s",
			    ent->fts_path + stripdir);
			fts_set(fts, ent, FTS_SKIP);
			ent->fts_parent->fts_number++;
			continue;
		}

		if (ent->fts_info == FTS_D && perish_ent != NULL)
			continue;

		/*
		 * If we visit a directory in post-order and perish_ent isn't
		 * set, then we must have skipped it in pre-order (e.g., due to
		 * a rule match) and we must not schedule it for deletion now.
		 */

		if (ent->fts_info == FTS_DP && perish_ent == NULL)
			continue;

		/* Look up in the hashtable. */

		memset(&hent, 0, sizeof(hent));
		hent.key = ent->fts_path + stripdir;
		if (hsearch(hent, FIND) != NULL) {
			if (ent->fts_info == FTS_D &&
			    strcmp(ent->fts_path, parg[0]) != 0) {
				fts_set(fts, ent, FTS_SKIP);
			}
			continue;
		}

		if (ent->fts_info == FTS_D) {
			perish_ent = ent;
			continue;
		} else if (ent == perish_ent) {
			assert(ent->fts_info == FTS_DP);
			perish_ent = NULL;
		}

		if (ent->fts_info != FTS_D) {
			if (ent->fts_info == FTS_DP &&
			    ent->fts_number != 0) {
				WARNX("%s: not empty, cannot delete",
				    ent->fts_path);
				ent->fts_parent->fts_number++;
				continue;
			}

			assert(delmode == DMODE_DURING ||
			    delmode == DMODE_DELAY);
			flist_add_del(sess, ent->fts_path, stripdir,
			    &p->dfl, &p->dflsz, &p->dflmax,
			    ent->fts_statp);
		}
	}

	ret = true;
out:
	if (delmode == DMODE_DURING) {
		qsort(p->dfl, p->dflsz, sizeof(struct flist), flist_dir_cmp);
		flist_del(sess, p->rootfd, p->dfl, p->dflsz);
		flist_free(p->dfl, p->dflsz);
		p->dfl = NULL;
		p->dflsz = p->dflmax = 0;
	}

	fts_close(fts);
	free(dirpath);
	hdestroy();
	return ret;
}

/*
 * Fix the mode of the file/directory in place for the flist entry.
 * This deals with upgrading permissions just enough to allow us to
 * progress.
 * Returns <0 on failure, 0 on success.
 */
static int
uploader_fix_mode(const struct upload *p, const struct sess *sess,
    const struct flist *f, const struct stat *st)
{
	mode_t		 want_mode;
	int		 rc;
	const bool	 fixing_dir = S_ISDIR(f->st.mode);

	/*
	 * For the uploader, our primary focus is upgrading the mode
	 * only as much as we need to.  For directories with --perms,
	 * we'll just upgrade them all the way and include our upgrade
	 * so that we can write into it; they'll be downgraded to the
	 * final mode after we're done inside.
	 *
	 * For files with or without --perms, we're likely looking at
	 * the original file or a backup file rather than the final file
	 * and should only go as far as to make them readable to be
	 * minimally invasive to the file that's about to get replaced.
	 * This also gives us a better chance of not breaking if the
	 * ownership of the file isn't quite ideal.
	 */
	if (f->st.mode == 0 || !fixing_dir ||
	    !sess->opts->preserve_perms)
		want_mode = st->st_mode;
	else
		want_mode = f->st.mode;

	if (geteuid() != 0) {
		/*
		 * For directories, we want to make sure we're writable
		 * at least.  For files, we're expecting to open these
		 * r/o and thus need at least u+r.
		 */
		if (fixing_dir)
			want_mode |= S_IWUSR;
		else
			want_mode |= S_IRUSR;
	}

	rc = 0;
	if (st->st_mode != want_mode) {
		rc = fchmodat(p->rootfd, f->path, want_mode,
		    AT_SYMLINK_NOFOLLOW);
		if (rc != 0)
			ERRX("%s: unable to escalate mode", f->path);
	}

	return rc;
}

/*
 * If not found, create the destination directory in prefix order.
 * Create directories using the existing umask.
 * Return <0 on failure 0 on success.
 */
static int
pre_dir(struct upload *p, struct sess *sess)
{
	struct stat	 st; /* stat of indexed file */
	struct flist	*f; /* indexed file */
	int		 rc; /* temporary return code */

	f = &p->fl[p->idx];
	assert(S_ISDIR(f->st.mode));

	if (!sess->opts->recursive && !sess->opts->dirs) {
		WARNX("%s: ignoring directory", f->path);
		return 0;
	}

	rc = fstatat(p->rootfd, f->path, &st, AT_SYMLINK_NOFOLLOW);
	if (rc == -1) {
		if (sess->opts->dry_run) {
			f->iflags |= IFLAG_NEW | IFLAG_LOCAL_CHANGE;
			return 0;
		}
		if (errno != ENOENT) {
			ERR("%s: fstatat", f->path);
			return -1;
		}
	}

	if (sess->opts->dry_run) {
		if (!check_path(p->rootfd, f->path)) {
			f->iflags |= IFLAG_NEW | IFLAG_LOCAL_CHANGE;
			return 0;
		}
	}

	if (rc != -1 && !S_ISDIR(st.st_mode)) {
		/*
		 * Incoming item is a directory, but there is a
		 * non-directory in the way, so we need to remove it.
		 */
		if (!sess->opts->dry_run) {
			if (unlinkat(p->rootfd, f->path, 0) == -1) {
				ERRX("%s: unable to replace file with "
				    "a directory", f->path);
				return -1;
			}
		}
	} else if (rc != -1) {
		if ((f->iflags & IFLAG_NEW) == 0) {
			LOG3("%s: updating directory", f->path);
			f->iflags |= itemize_changes(sess, &st, f);
		}

		/*
		 * We fchmod() here to ensure that we can actually
		 * update or populate the directory as needed -- it may
		 * not be writable, so we would elevate the permissions
		 * just as long as we need to in order to create new
		 * files (or write a temporary file), then we'll fix it
		 * up in post-order to reflect what the flist called
		 * for.
		 *
		 * This uses the target permissions when it can to avoid
		 * creating way too wide of a permission window if,
		 * e.g., it shouldn't have any 'other' bits.
		 */
		if (!sess->opts->dry_run)
			rc = uploader_fix_mode(p, sess, f, &st);

		if (sess->opts->del == DMODE_DURING ||
		    sess->opts->del == DMODE_DELAY)
			pre_dir_delete(p, sess, sess->opts->del);

		return sess->opts->dry_run ? 0 : rc;
	}

	f->iflags = IFLAG_NEW | IFLAG_LOCAL_CHANGE;

	if (sess->opts->dry_run)
		return 0;

	/*
	 * We want to make the directory with default permissions (using
	 * our old umask, which we've since unset), then adjust
	 * permissions (assuming preserve_perms or new) afterward in
	 * case it's u-w or something.
	 */

	if (mkpathat(p->rootfd, f->path, 0777 & ~p->oumask) == -1 &&
	    errno != EEXIST) {
		ERR("%s: mkpathat", f->path);
		return -1;
	} else
		LOG3("%s: created directory", f->path);

	p->newdir[p->idx] = 1;
	return 0;
}

/*
 * Process the directory time and mode for "idx" in the file list.
 * Returns false on failure, true on success.
 */
static bool
post_dir(const struct sess *sess, const struct upload *u, size_t idx)
{
	struct stat 	 st;
	struct flist 	*f;

	f = &u->fl[idx];
	assert(S_ISDIR(f->st.mode));

	/* We already warned about the directory in pre_process_dir(). */

	if (!sess->opts->recursive)
		return true;
	if (sess->opts->dry_run)
		return true;

	if (fstatat(u->rootfd, f->path, &st, AT_SYMLINK_NOFOLLOW) == -1) {
		ERR("%s: fstatat", f->path);
		return false;
	}
	if (!S_ISDIR(st.st_mode)) {
		WARNX("%s: not a directory", f->path);
		return false;
	}

	return rsync_set_metadata_at(sess, u->newdir[idx], u->rootfd, f,
	    f->path);
}

/*
 * Returns true if each and every component of the given path (except
 * the last) exists and is a real directory (i.e., not a symlink).
 * Returns false otherwise.
 * Caches the function's return value in static memory so that
 * subsequent requests need not incur the expense.
 */
static bool
check_path(int rootfd, const char *path)
{
	struct stat	 sb; /* current path stat */
	static char	 prev_pathbuf[PATH_MAX]; /* cached from last */
	static size_t	 prev_pathlen; /* cached from last */
	static bool	 prev_isdir; /* cached from last */
	char		 pathbuf[PATH_MAX]; /* path build */
	size_t		 pathlen; /* size of path */
	bool		 isdir = false;
	char		*pc;

	pc = strrchr(path, '/');
	if (pc == NULL || pc[1] == '\0')
		return true;

	pathlen = pc - path;
	assert(pathlen + 1 < sizeof(pathbuf));

	if (pathlen >= prev_pathlen && prev_pathlen > 0 &&
	    strncmp(prev_pathbuf, path, prev_pathlen) == 0) {
		return prev_isdir;
	}

	memcpy(pathbuf, path, pathlen);
	pathbuf[pathlen] = '\0';

	for (;;) {
		if (fstatat(rootfd, pathbuf, &sb, AT_SYMLINK_NOFOLLOW) == -1)
			return true;

		isdir = S_ISDIR(sb.st_mode);
		if (!isdir)
			break;

		pc = strrchr(pathbuf, '/');
		if (pc == NULL || pc[1] == '\0')
			break;

		*pc = '\0';

		if (prev_pathlen == (size_t)(pc - pathbuf) &&
		    strcmp(prev_pathbuf, pathbuf) == 0) {
			isdir = prev_isdir;
			break;
		}
	}

	/*
	 * Cache the result to (hopefully) reduce the expense of the
	 * next call.
	 */

	memcpy(prev_pathbuf, path, pathlen);
	prev_pathbuf[pathlen] = '\0';
	prev_pathlen = pathlen;
	prev_isdir = isdir;
	return isdir;
}

/*
 * Check if file exists in the specified root directory.
 * Returns (FIXME: make into local enum):
 *    -1 on error
 *     0 if file is considered the same
 *     1 if file exists and is possible match
 *     2 if file exists but quick check failed
 *     3 if file does not exist
 *     3 if file does not exist
 *     4 if file exists but should be ignored
 * The stat pointer st is only valid for 0, 1, and 2 returns.
 */
static int
check_file(int rootfd, struct flist *f, struct stat *st,
    struct sess *sess)
{
	const char	*path = f->path;

	/* The root directory must exist. */

	if (rootfd == -1) {
		return 3;
	}

	if (fstatat(rootfd, f->path, st, AT_SYMLINK_NOFOLLOW) == -1) {
		if (errno == ENOENT) {
			f->iflags = IFLAG_NEW | IFLAG_TRANSFER;
			return 3;
		}
		if (sess->opts->dry_run) {
			f->iflags = IFLAG_NEW | IFLAG_TRANSFER;
			return 2;
		}
		ERR("%s: fstatat", f->path);
		return -1;
	}

	/*
	 * In non-dry-run mode with either --copy-links and/or --copy-dirlinks
	 * pre_dir() will have removed any component of path[] that is a
	 * symlink, in which case the fstatat() above will fail and we cannot
	 * reach this point.  However, in dry-run mode the fstatat() above will
	 * succeed, so we must report that this is a new file if any component
	 * of path contains a symlink.
	 *
	 * Note that the reference rsync does not send the -k nor -L options to
	 * the receiver so we cannot key on those options here to avoid the
	 * check.
	 *
	 * Note also that if neither --copy-links nor --copy-dirlinks are in
	 * play then all components of f->path (except the last) should be a
	 * real directory (i.e., never a symlink to a directory).
	 */

	if (sess->opts->dry_run) {
		if (!check_path(rootfd, path)) {
			f->iflags = IFLAG_NEW | IFLAG_TRANSFER;
			return 3;
		}
	}

	/* Non-regular file needs attention. */

	if (!S_ISREG(st->st_mode))
		return 2;

	f->iflags |= itemize_changes(sess, st, f);

	if (sess->role->append) {
		if (st->st_size >= f->st.size) {
			LOG1("Skip append '%s'", f->path);
			return 4;
		}
		return 2;
	}

	/* Quick check if file is the same. */

	if (st->st_size == f->st.size) {
		if (sess->opts->size_only)
			return 0;
		if (!sess->opts->ignore_times) {
			if (labs(f->st.mtime - st->st_mtime) <= 0) {
				if (f->st.mtime != st->st_mtime)
					LOG3("%s: fits time modify window",
						f->path);
				return 0;
			}
			return 1;
		}
	}

	/* File needs attention. */

	return 2;
}

/*
 * Check an alternate dir (e.g., copy dest mode dir) for a suitable
 * version of the file.
 *
 * Returns -1 on error, 0 on success, or 1 to keep trying further dirs.
 * The *savedfd will be updated if we determine a match is a viable
 * candidate for *matchdir.
 */
static int
pre_file_check_altdir(struct sess *sess, const struct upload *p,
    const char **matchdir, struct stat *st, const char *root,
    struct flist *f, int rc, int *savedfd)
{
	int32_t saved_iflags = f->iflags;
	int dfd, x;

	dfd = openat(p->rootfd, root, O_RDONLY | O_DIRECTORY);
	if (dfd == -1) {
		if (errno == ENOENT || errno == EACCES)
			return 1;
		err(ERR_FILE_IO, "%s: pre_file_check_altdir: openat", root);
	}

	f->iflags = 0;
	x = check_file(dfd, f, st, sess);
	if (x == 0) {
		/* found a match */
		if (rc >= 0) {
			/* found better match, delete file in rootfd */
			if (unlinkat(p->rootfd, f->path, 0) == -1 &&
			    errno != ENOENT) {
				ERR("%s: unlinkat", f->path);
				close(dfd);
				return -1;
			}
		}

		f->iflags |= itemize_changes(sess, st, f);

		LOG3("%s: skipping: up to date in %s", f->path, root);
		close(dfd);
		return 0;
	}

	if ((x == 1 || x == 2) && *matchdir == NULL) {
		/* found a local file that is a close match */
		LOG3("%s: found close match in %s", f->path,
		    root);
		f->iflags |= itemize_changes(sess, st, f);
		*matchdir = root;
		if (savedfd != NULL) {
			int prevfd;

			if ((prevfd = *savedfd) != -1)
				close(prevfd);
			*savedfd = dfd;
			/* Don't close() it. */
			dfd = -1;
		}
		return 1;
	}

	f->iflags = saved_iflags;
	close(dfd);

	return 1;
}

/*
 * Try to open the file at the current index.
 * If the file does not exist, returns with >0.
 * Return <0 on failure, 0 on success w/nothing to be done, >0 on
 * success and the file needs attention.
 */
static int
pre_file(struct upload *p, int *filefd, off_t *size, struct sess *sess)
{
	struct flist	*f; /* file being examined */
	struct stat	 st; /* stat of file being examined */
	const char	*matchdir = NULL;
	int		 i, /* temporary */
			 ret, /* temporary */
			 rc, /* result of check_file() */
			 uflags = 0; /* unlinkat flags */
	bool 		 do_unlink = false, /* unlink dir */
			 dry_run = false, /* dry-run */
			 dry_full = false, /* full dry-run */
			 fix_metadata, /* fix up metadata */
			 failed; /* fix_metadata failed */
	const int32_t	 hlink = IFLAG_HLINK_FOLLOWS | IFLAG_LOCAL_CHANGE;

	f = &p->fl[p->idx];
	assert(S_ISREG(f->st.mode));

	if (sess->opts->max_size >= 0 && f->st.size > sess->opts->max_size) {
		WARNX("skipping over max-size file %s", f->path);
		return 0;
	}
	if (sess->opts->min_size >= 0 && f->st.size < sess->opts->min_size) {
		WARNX("skipping under min-size file %s", f->path);
		return 0;
	}

	/*
	 * For non dry-run cases, we'll write the acknowledgement later
	 * in the rsync_uploader() function.
	 */

	if (sess->opts->dry_run)
		dry_run = dry_full = true;

	*size = 0;
	*filefd = -1;

	/* FIXME: switch statement */

	rc = check_file(p->rootfd, f, &st, sess);

	if (rc == -1)
		return 0;

	if (rc == 4) {
		f->flstate |= FLIST_SKIPPED;
		return 0;
	}

	if (rc == 2 && !S_ISREG(st.st_mode)) {
		if (force_delete_applicable(p, sess, st.st_mode))
			if (pre_dir_delete(p, sess, DMODE_DURING) == 0)
				return -1;

		/*
		 * If we're operating --inplace, need to clear out any stale
		 * non-file entries since we'll want to just open or create it
		 * and get to it.
		 */

		do_unlink = S_ISDIR(st.st_mode);
		if (S_ISDIR(st.st_mode))
			uflags |= AT_REMOVEDIR;
		if (do_unlink && !dry_run &&
		    unlinkat(p->rootfd, f->path, uflags) == -1) {
			ERR("%s: unlinkat", f->path);
			return -1;
		}

		/*
		 * Fix the return value so that we don't try to set
		 * metadata of what we unlinked below.
		 */

		if (do_unlink)
			rc = 3;

		f->iflags = IFLAG_NEW | IFLAG_TRANSFER;
	}

	/*
	 * If the file exists, we need to fix permissions *before* we
	 * try to update it or we risk not being able to open it in the
	 * first place if the permissions are thoroughly messed up.
	 */

	if (rc >= 0 && rc < 3) {
		fix_metadata = !dry_run;

		/*
		 * If the file is a hardlink to another file (or will
		 * become one) then we must not change the metadata here
		 * as this file might not currently link to the correct
		 * file.  In this case we'll fix the metadata at the end
		 * of phase 2.
		 */

		if (fix_metadata) {
			if ((f->iflags & hlink) == hlink)
				fix_metadata = false;
			else if (st.st_nlink > 1 && S_ISREG(f->st.mode))
				fix_metadata = false;
		}

		if (!fix_metadata)
			goto fixed;

		dstat_save(&st, &f->dstat);
		if (rc == 0)
			failed = !rsync_set_metadata_at(sess, false,
			    p->rootfd, f, f->path);
		else
			failed = uploader_fix_mode(p, sess, f, &st) != 0;

		if (failed) {
			if (errno != EACCES && errno != EPERM) {
				ERRX1("rsync_set_metadata");
				return -1;
			}

			/* 
			 * Before unlinking the file check to see if it
			 * can be opened for read.  If not, then
			 * increment the error count in order to
			 * reproduce rsync's exit code semantics.
			 */

			if (unlinkat(p->rootfd, f->path, 0) == -1) {
				ERR("%s: unlinkat", f->path);
				return -1;
			}

			f->iflags |= IFLAG_NEW | IFLAG_TRANSFER;
			rc = 3;
		}
fixed:
		if (rc == 0) {
			LOG3("%s: skipping: up to date", f->path);
			return 0;
		}
	}

	/* Check alternative locations for better match. */

	for (i = 0; sess->opts->basedir[i] != NULL; i++) {
		ret = pre_file_check_altdir(sess, p, &matchdir, &st,
		    sess->opts->basedir[i], f, rc, NULL);
		if (ret <= 0)
			return ret;
	}

	/*
	 * partialdir is a special case, we'll work on it from there.
	 */

	if (matchdir != NULL) {
		/* copy match from basedir into root as a start point */
		copy_file(p->rootfd, matchdir, f);
		if (fstatat(p->rootfd, f->path, &st,
		    AT_SYMLINK_NOFOLLOW) == -1) {
			ERR("%s: fstatat", f->path);
			return -1;
		}
	}

	if (!dry_full && rc < 3) {
		*size = 0;
		*filefd = openat(p->rootfd, f->path, O_RDONLY | O_NOFOLLOW);
		if (*filefd == -1 && (errno == EACCES || errno == EPERM)) {
			if (!dry_run && unlinkat(p->rootfd, f->path, 0) == -1) {
				ERR("%s: unlinkat", f->path);
				return -1;
			}

			return 1;
		}
		if (*filefd != -1)
			*size = st.st_size;
	} else {
		assert(*filefd == -1);
		assert(*size == 0);
		errno = ENOENT;
	}

	if (dry_run) {
		if (*filefd != -1) {
			close(*filefd);
			*filefd = -1;
		}
		*size = 0;
		f->iflags |= IFLAG_TRANSFER;
		return 0;
	}

	/*
	 * If there is a symlink in our way, we will get EMLINK,
	 * except on MacOS where they use ELOOP instead.
	 */
	if (*filefd == -1 && errno != ENOENT && errno != EMLINK &&
	    errno != ELOOP) {
		ERR("%s: pre_file: openat", f->path);
		return -1;
	}

	/* file needs attention */
	f->iflags |= IFLAG_TRANSFER;
	return 1;
}

/*
 * Allocate an uploader object in the correct state to start.  Returns
 * NULL on failure or the pointer otherwise.
 * On success, upload_free() must be called with the allocated pointer.
 */
struct upload *
upload_alloc(const char *root, int rootfd, int fdout, size_t clen,
    struct flist *fl, size_t flsz, size_t chunksz, mode_t msk)
{
	struct upload	*p;

	if ((p = calloc(1, sizeof(struct upload))) == NULL) {
		ERR("calloc");
		return NULL;
	}

	p->state = UPLOAD_FIND_NEXT;
	p->chunksz = chunksz;
	p->oumask = msk;
	p->root = strdup(root);
	if (p->root == NULL) {
		ERR("strdup");
		free(p);
		return NULL;
	}
	p->rootfd = rootfd;
	p->csumlen = clen;
	p->fdout = fdout;
	p->fl = fl;
	p->flsz = flsz;
	p->nextack = 0;
	p->pre_dir_delete_done = false;

	p->newdir = calloc(flsz, sizeof(p->newdir[0]));
	if (p->newdir == NULL) {
		ERR("calloc");
		free(p->root);
		free(p);
		return NULL;
	}
	return p;
}

/*
 * The upload has finished [to the downloader]: start processing in the
 * next phase.
 */
void
rsync_uploader_next_phase(struct upload *p, struct sess *sess,
    int fdout)
{
	size_t	 idx; /* file index */

	assert(p->state == UPLOAD_FINISHED);

	/* Reset for the redo phase. */

	p->state = UPLOAD_FIND_NEXT;
	p->nextack = 0;
	p->idx = 0;
	p->phase++;
	p->csumlen = CSUM_LENGTH_PHASE2;

	if (p->phase != PHASE_REDO)
		return;

	/*
	 * Reset the iflags when we're entering the redo phase; we don't
	 * want to end up with a weird and invalid combination with
	 * flags carried over from the previous attempt.
	 */

	for (idx = 0; idx < p->flsz; idx++) {
		if (!(p->fl[idx].flstate & FLIST_REDO))
			continue;
		p->fl[idx].iflags = 0;
	}
}

/*
 * Perform all cleanups and free.
 * Passing a NULL to this function is ok.
 */
void
upload_free(struct upload *p)
{
	if (p == NULL)
		return;
	free(p->root);
	free(p->newdir);
	free(p->buf);
	free(p);
}

/*
 * The upload has finished to the downloader, so finish up any remaining
 * acknowledgements.
 */
void
rsync_uploader_ack_complete(struct upload *p, struct sess *sess,
    int fdout)
{
	struct flist	*fl; /* current file */
	size_t		 idx; /* index of current file */

	assert(p->state != UPLOAD_WRITE);
	if (p->nextack == p->flsz)
		return;

	/*
	 * We'll halt at the next file the uploader needs to process
	 * since the status of flist entries after that are irrelevant.
	 */

	for (idx = p->nextack; idx < p->idx; idx++) {
		fl = &p->fl[idx];

		/* Skip dirs */

		if (S_ISDIR(fl->st.mode))
			continue;

		/* Entry not yet processed by the downloader. */

		if (!(fl->flstate & FLIST_DONE_MASK))
			break;

		/*
		 * Failed is only set if there's no hope of recovering,
		 * so we can just skip this one entirely.
		 */

		if (fl->flstate & FLIST_FAILED)
			continue;

		/*
		 * Redo entries in the redo phase have also not been
		 * processed,
		 */

		if (p->phase > 0 && (fl->flstate & FLIST_REDO))
			break;

		/*
		 * Any redo left, we can skip over -- they won't be
		 * completing, if we're in the redo phase the downloader
		 * would have either cleared the redo flag if it
		 * succeeded, or it would have additionally marked it as
		 * having FAILED.
		 */

		if (fl->flstate & FLIST_REDO)
			continue;

		if ((fl->flstate & (FLIST_SUCCESS | FLIST_SUCCESS_ACKED)) ==
		    FLIST_SUCCESS) {
			if (!io_write_int_tagged(sess, fdout, (int)idx,
			    IT_SUCCESS))
				break;
			fl->flstate |= FLIST_SUCCESS_ACKED;
		}
	}

	p->nextack = idx;
}

/*
 * Iterates through all available files and conditionally gets the file
 * ready for processing to check whether it's up to date.
 * If not up to date or empty, sends file information to the sender.
 * If returns 0, we've processed all files there are to process.
 * If returns >0, we're waiting for POLLIN or POLLOUT data.
 * Otherwise returns <0, which is an error.
 */
int
rsync_uploader(struct upload *u, struct sess *sess, int revents,
    int *fileinfd, int *fileoutfd)
{
	struct blkset	    blk;
	void		   *mbuf, *bufp;
	ssize_t		    msz;
	size_t		    i, pos, sz;
	off_t		    offs, filesize;
	int		    c;

	if (sess->role->phase == NULL)
		sess->role->phase = &u->phase;

	/* Once finished this should never get called again. */

	assert(u->state != UPLOAD_FINISHED);

	/*
	 * If we have an upload in progress, then keep writing until the
	 * buffer has been fully written.
	 * We must only have the output file descriptor working and also
	 * have a valid buffer to write.
	 */

	if (u->state == UPLOAD_WRITE) {
		assert(u->buf != NULL);
		assert(*fileoutfd != -1);
		assert(*fileinfd == -1);

		if (!(revents & POLLOUT))
			return 1;

		/*
		 * Unfortunately, we need to chunk these: if we're
		 * the server side of things, then we're multiplexing
		 * output and need to wrap this in chunks.
		 * This is a major deficiency of rsync.
		 * FIXME: add a "fast-path" mode that simply dumps out
		 * the buffer non-blocking if we're not mplexing.
		 *
		 * At this point there should be at least u->chunksz
		 * bytes of space available in u->fdout, and the sender
		 * might currently be blocked trying to write to the
		 * receiver.  Hence, in order to avoid a deadlock we
		 * must not block here, and the only way to ensure that
		 * is to write no more than u->chunksz bytes to fdout
		 * per any single POLLOUT event.
		 *
		 * All bets are off if someone issues a write to
		 * u->fdout between the return from poll() in
		 * rsync_receiver() and the call below to
		 * io_write_buf().
		 */

		if (u->bufpos < u->bufsz) {
			sz = u->chunksz < (u->bufsz - u->bufpos) ?
				u->chunksz : (u->bufsz - u->bufpos);
			c = io_write_buf(sess, u->fdout,
				u->buf + u->bufpos, sz);
			if (c == 0) {
				ERRX1("io_write_nonblocking");
				return -1;
			}
			u->bufpos += sz;
			if (u->bufpos < u->bufsz)
				return 1;

			assert(u->bufsz == u->bufpos);
			u->bufsz = 0;
			u->bufpos = 0;

			/*
			 * Wait for the next POLLOUT event before trying
			 * to write more to u->fdout to ensure we don't
			 * block in write.
			 */
			if (u->idx == u->flsz)
				return 1;
		}

		if (u->idx == u->flsz) {
			if (!io_write_int(sess, u->fdout, -1)) {
				ERRX1("io_write_int");
				return -1;
			}

			u->state = UPLOAD_FINISHED;
			*fileoutfd = -1;
			LOG4("uploader: finished");
			return 0;
		}

		/*
		 * Let the UPLOAD_FIND_NEXT state handle things if we
		 * finish, as we'll need to write a POLLOUT message and
		 * not have a writable descriptor yet.
		 */

		u->state = UPLOAD_FIND_NEXT;
		return 1;
	}

	pos = u->bufsz;

	/*
	 * If we invoke the uploader without a file currently open, then
	 * we iterate through til the next available regular file and
	 * start the opening process.
	 * This means we must have the output file descriptor working.
	 */

	if (u->state == UPLOAD_FIND_NEXT) {
		assert(*fileinfd == -1);
		assert(*fileoutfd != -1);

		for ( ; u->idx < u->flsz; u->idx++) {
			assert(u->fl[u->idx].sendidx != -1);
			if (u->phase == PHASE_REDO &&
			    (u->fl[u->idx].flstate & FLIST_REDO) == 0)
				continue;
			else if (u->phase == PHASE_DLUPDATES)
				continue;

			if (S_ISDIR(u->fl[u->idx].st.mode))
				c = pre_dir(u, sess);
			else if (S_ISLNK(u->fl[u->idx].st.mode))
				c = pre_symlink(u, sess);
			else if (S_ISREG(u->fl[u->idx].st.mode))
				c = pre_file(u, fileinfd, &filesize, sess);
			else if (S_ISBLK(u->fl[u->idx].st.mode) ||
			    S_ISCHR(u->fl[u->idx].st.mode))
				c = pre_dev(u, sess);
			else if (S_ISFIFO(u->fl[u->idx].st.mode))
				c = pre_fifo(u, sess);
			else if (S_ISSOCK(u->fl[u->idx].st.mode))
				c = pre_sock(u, sess);
			else
				c = 0;

			/*
			 * In the redo phase specifically, the file is
			 * no longer new by definition of the fact that
			 * we're redoing the transfer.
			 */

			if (u->fl[u->idx].flstate & FLIST_REDO)
				u->fl[u->idx].iflags &= ~IFLAG_NEW;

			if (c < 0) {
				u->fl[u->idx].flstate |= FLIST_FAILED;
				continue;
			} else if (c > 0)
				break;

			u->fl[u->idx].flstate |= FLIST_SUCCESS;
			log_item(sess, &u->fl[u->idx]);
			continue;
		}

		/*
		 * Whether we've finished writing files or not, we
		 * disable polling on the output channel.
		 */

		*fileoutfd = -1;
		if (u->idx == u->flsz) {
			assert(*fileinfd == -1);
			if (u->bufsz > 0) {
				u->state = UPLOAD_WRITE;
				*fileoutfd = u->fdout;
				return 1;
			}
			if (!io_write_int(sess, u->fdout, -1)) {
				ERRX1("io_write_int");
				return -1;
			}
			u->state = UPLOAD_FINISHED;
			LOG4("uploader: finished");
			return 0;
		}

		/* Go back to the event loop, if necessary. */

		u->state = UPLOAD_WRITE;
	}

	assert(S_ISREG(u->fl[u->idx].st.mode));

	/* Initialies our blocks. */

	assert(u->state == UPLOAD_WRITE);
	memset(&blk, 0, sizeof(struct blkset));
	blk.csum = u->csumlen;

	if (*fileinfd != -1 && filesize > 0) {
		init_blkset(&blk, filesize, sess->opts->block_size);
		assert(blk.blksz);

		if (u->phase == 0 && sess->role->append)
			goto skipmap;

		assert(blk.blksz);
		blk.blks = calloc(blk.blksz, sizeof(struct blk));
		if (blk.blks == NULL) {
			ERR("calloc");
			close(*fileinfd);
			*fileinfd = -1;
			return -1;
		}

		if ((mbuf = malloc(blk.len)) == NULL) {
			ERR("malloc");
			close(*fileinfd);
			*fileinfd = -1;
			free(blk.blks);
			return -1;
		}

		offs = 0;
		i = 0;
		do {
			msz = pread(*fileinfd, mbuf, blk.len, offs);
			if ((size_t)msz != blk.len &&
			    (size_t)msz != blk.rem) {
				if (msz != -1) {
					u->fl[u->idx].iflags =
					    IFLAG_NEW | IFLAG_TRANSFER;
					WARNX1("%s: destination file "
					    "truncated; falling back "
					    "to whole file transfer", 
					    u->fl[u->idx].path);
				} else
					ERR("pread");
				close(*fileinfd);
				*fileinfd = -1;
				free(mbuf);
				free(blk.blks);
				blk.blks = NULL;
				blk.blksz = 0;
				if (msz == -1)
					return -1;

				/*
				 * We can still do this file, but it
				 * seems to have changed out from
				 * underneath us.  We'll treat it as a
				 * --whole-file to be safe.
				 */

				goto skipmap;
			}
			init_blk(&blk.blks[i], &blk, offs, i, mbuf, sess);
			offs += blk.len;
			LOG4("i=%ld, offs=%lld, msz=%ld, blk.len=%lu, "
			    "blk.rem=%lu", i, (long long)offs, msz,
			    blk.len, blk.rem);
			i++;
		} while (i < blk.blksz);

		free(mbuf);
		LOG3("%s: mapped %jd B with %zu blocks",
		    u->fl[u->idx].path, (intmax_t)blk.size,
		    blk.blksz);
skipmap:
		close(*fileinfd);
		*fileinfd = -1;
	} else {
		if (*fileinfd != -1) {
			close(*fileinfd);
			*fileinfd = -1;
		}
		blk.len = MAX_CHUNK; /* Doesn't matter. */
		LOG3("%s: not mapped", u->fl[u->idx].path);
	}

	assert(*fileinfd == -1);

	/* Make sure the block metadata buffer is big enough. */

	u->bufsz +=
	    sizeof(int32_t) + /* identifier */
	    sizeof(int32_t) + /* block count */
	    sizeof(int32_t) + /* block length */
	    sizeof(int32_t) + /* checksum length */
	    sizeof(int32_t);  /* block remainder */

	if (u->phase > 0 || !sess->role->append)
		u->bufsz += blk.blksz *
		    (sizeof(int32_t) + /* short checksum */
		     blk.csum); /* long checksum */

	if (u->bufsz > u->bufmax) {
		if ((bufp = realloc(u->buf, u->bufsz)) == NULL) {
			ERR("realloc");
			free(blk.blks);
			return -1;
		}
		u->buf = bufp;
		u->bufmax = u->bufsz;
	}

	io_buffer_int(u->buf, &pos, u->bufsz, u->fl[u->idx].sendidx);
	io_buffer_int(u->buf, &pos, u->bufsz, (int)blk.blksz);
	io_buffer_int(u->buf, &pos, u->bufsz, (int)blk.len);
	io_buffer_int(u->buf, &pos, u->bufsz, (int)blk.csum);
	io_buffer_int(u->buf, &pos, u->bufsz, (int)blk.rem);

	/*
	 * Error cases above may leave us without a blk.blks.
	 */

	if (!sess->role->append && blk.blks != NULL) {
		for (i = 0; i < blk.blksz; i++) {
			io_buffer_int(u->buf, &pos, u->bufsz,
				      blk.blks[i].chksum_short);
			io_buffer_buf(u->buf, &pos, u->bufsz,
				      blk.blks[i].chksum_long, blk.csum);
		}
	}
	assert(pos == u->bufsz);

	u->idx++;

	/* Reenable the output poller and clean up. */

	*fileoutfd = u->fdout;
	free(blk.blks);
	return 1;
}

/*
 * Fix up the directory permissions and times post-order.
 * We can't fix up directory permissions in place because the server may
 * want us to have overly-tight permissions---say, those that don't
 * allow writing into the directory.
 * We also need to do our directory times post-order because making
 * files within the directory will change modification times.
 * Returns false on failure, true on success.
 */
bool
rsync_uploader_tail(struct upload *u, struct sess *sess)
{
	size_t	 i;


	if (!sess->opts->preserve_times && !sess->opts->preserve_perms)
		return 1;

	LOG3("fixing up directory times and permissions");

	for (i = 0; i < u->flsz; i++)
		if (S_ISDIR(u->fl[i].st.mode))
			(void)post_dir(sess, u, i);

	return true;
}

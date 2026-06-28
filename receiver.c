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

#include <sys/socket.h>
#include <sys/stat.h>

#include <assert.h>
#include <dirent.h> /* IFTODT */
#if HAVE_ERR
# include <err.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h> /* PIPE_BUF */
#include <math.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"
#include "rules.h"

#ifndef S_ISTXT
#define S_ISTXT S_ISVTX
#endif

enum	pfdt {
	PFD_SENDER_IN = 0, /* input from the sender */
	PFD_UPLOADER_IN, /* uploader input from a local file */
	PFD_DOWNLOADER_IN, /* downloader input from a local file */
	PFD_SENDER_OUT, /* output to the sender */
	PFD__MAX
};

bool
rsync_set_metadata_at(const struct sess *sess, bool newfile, int rootfd,
    const struct flist *f, const char *path)
{
	struct timespec	 ts[2];
	uid_t		 uid = (uid_t)-1;
	gid_t		 gid = (gid_t)-1;
	mode_t		 mode;
	int		 serrno; /* temporary */

	if (sess->opts->dry_run || (f->flstate & FLIST_SKIP_METADATA))
		return true;

	/* Conditionally adjust file modification time. */

	if (sess->opts->preserve_times &&
	    (!S_ISDIR(f->st.mode) || !sess->opts->omit_dir_times)) {
		ts[0].tv_nsec = UTIME_NOW;
		ts[1].tv_sec = f->st.mtime;
		ts[1].tv_nsec = 0;
		if (utimensat(rootfd, path, ts, AT_SYMLINK_NOFOLLOW) == -1) {
			serrno = errno;
			ERR("%s: utimensat", path);
			errno = serrno;
			return false;
		}
		LOG4("%s: updated date", f->path);
	}

	/*
	 * Conditionally adjust identifiers.
	 * If we have an EPERM, report it but continue on: this just
	 * means that we're mapping into an unknown (or disallowed)
	 * group identifier.
	 */

	if (getuid() == 0 && sess->opts->preserve_uids)
		uid = f->st.uid;
	if (sess->opts->preserve_gids)
		gid = f->st.gid;

	mode = f->st.mode;
	if (uid != (uid_t)-1 || gid != (gid_t)-1) {
		if (fchownat(rootfd, path, uid, gid, AT_SYMLINK_NOFOLLOW) == -1) {
			if (errno != EPERM) {
				serrno = errno;
				ERR("%s: fchownat", path);
				errno = serrno;
				return false;
			}
			if (geteuid() == 0)
				WARNX("%s: identity unknown or not available "
				    "to user.group: %u.%u", f->path, uid, gid);
		} else
			LOG4("%s: updated uid and/or gid", f->path);
	}

	/* Conditionally adjust file permissions. */

	if (newfile || sess->opts->preserve_perms) {
		if (mode != 0) {
			if (fchmodat(rootfd, path, mode, AT_SYMLINK_NOFOLLOW) == -1) {
				if (!(S_ISLNK(f->st.mode) && errno == EOPNOTSUPP)) {
					serrno = errno;
					ERR("%s: fchmodat (1)", path);
					errno = serrno;
					return false;
				}
			}
			LOG4("%s: updated permissions", f->path);
		}
	}

	return true;
}

/*
 * Node in the hardlink table.  FIXME: move to top of file.
 */
struct hardlink {
	int64_t			 device; /* from flist */
	int64_t			 inode; /* from flist */
	int64_t			 st_dev; /* from stat of disk file */
	int64_t			 st_ino; /* from stat of disk file */
	mode_t			 st_mode; /* from stat of disk file */
	int			 weight;
	const struct flist	*ref; /* points to full entry */
};

/*
 * List of hardlinks.  FIXME: move to top of file.
 */
struct hardlinks {
	struct hardlink		*infos;
	size_t			 infosz;
};

/*
 * Sort hardlink objects by device and inode, returning sort order like
 * for qsort().
 */
static int
hardlink_compare(const void *onep, const void *twop)
{
	const struct hardlink	*one = onep,
	      		 	*two = twop;

	if (one->inode == two->inode) {
		if (one->device < two->device)
			return -1;
		if (one->device > two->device)
			return 1;
	}
	if (one->inode < two->inode)
		return -1;
	if (one->inode > two->inode)
		return 1;
	assert(one->inode == two->inode);
	return 0;
}

/*
 * Compare hardlinks, keeping their ordering in the flist if being the
 * same.  Returns sort order like for qsort().
 */
static int
build_for_hardlinks_cmp(const void *onep, const void *twop)
{
	int			 rc;
	const struct hardlink	*one = onep,
	      		 	*two = twop;

	rc = hardlink_compare(onep, twop);

	/* Preserve flist relative ordering */

	return rc == 0 ? 0 : one->weight - two->weight;
}

/*
 * Build the sorted table of hardlinks.  Links are sorted by
 * device/inode, with position in the "fl" preserved for similar links.
 * Important: this needs to happen after fl is sorted.
 * Returns the size of the array.
 */
static size_t
build_for_hardlinks(const struct sess *sess, struct hardlink *hl,
    const struct flist *const fl, const size_t flsz, int rootfd)
{
	struct stat	 st; /* stat of current file */
	size_t		 i, /* temporary */
			 hlsz = 0; /* size of array */

	for (i = 0; i < flsz; i++) {

		if (fl[i].st.inode == 0 && fl[i].st.device == 0)
			continue;

		hl[hlsz].device = fl[i].st.device;
		hl[hlsz].inode = fl[i].st.inode;

		if (fstatat(rootfd, fl[i].path, &st,
		    AT_SYMLINK_NOFOLLOW) == 0) {
			if (sess->opts->update &&
			    st.st_mtime > fl[i].st.mtime)
				continue;

			hl[hlsz].st_dev = st.st_dev;
			hl[hlsz].st_ino = st.st_ino;
			hl[hlsz].st_mode = st.st_mode;
		}

		hl[hlsz].weight = hlsz;
		hl[hlsz++].ref = &fl[i];
	}

	qsort(hl, hlsz, sizeof(*hl), build_for_hardlinks_cmp);
	return hlsz;
}

/*
 * Find the first "fl" hardlink for a real file in the "hl" table.
 * Optionally if rootfd is >= 0 and lst is not NULL, make sure that the
 * leader exits on the local FS and matches its type.  Returns the
 * hardlink or NULL if there is none.
 * FIXME: move to hl.c or equiv.
 */
const struct flist *
find_hl_impl(const struct flist *const this,
    const struct hardlinks *const hl, int rootfd, struct stat *lst)
{
	struct hardlink		 searchfor, /* searching for.. .*/
				*found; /* hardlink found */
	const struct flist	*first = NULL, /* first link */
	      			*leader = NULL; /* actual file */
	size_t			 i; /* position in map */

	/*
	 * "hl" is a copy of the flist sorted by device/inode.
	 * Generally, the first file with identical device/inode is
	 * written to disk.  Every subsequent one is not written and
	 * later hardlinked.  However, in some cases it isn't the first
	 * file that actually got written to disk.  If any file has
	 * already been written, it becomes the "leader" of the group of
	 * hardlinks.
	 */

	/*
	 * bsearch(3) will return an unspecified match when multiple
	 * matches are found.  We always have at least one match and we
	 * are interested in multiple matches.  So we use bsearch(3),
	 * then go backwards to the first match.
	 */

	searchfor.device = this->st.device;
	searchfor.inode = this->st.inode;
	found = bsearch(&searchfor, hl->infos, hl->infosz,
	    sizeof(struct hardlink), hardlink_compare);
	if (found == NULL)
		return NULL;

	assert(found->device == this->st.device);
	assert(found->inode == this->st.inode);

	/* FIXME: use ptrdiff_t. */

	i = ((void *)found - (void *)hl->infos) /
	    sizeof(struct hardlink);

	/* Go back to the first match */

	while (i > 0 && this->st.inode == hl->infos[i - 1].inode &&
	    this->st.device == hl->infos[i - 1].device)
		i--;

	first = hl->infos[i].ref;
	while (i < hl->infosz && this->st.inode == hl->infos[i].inode &&
		this->st.device == hl->infos[i].device) {
		if (!(hl->infos[i].ref->flstate & FLIST_NEED_HLINK)) {
			leader = hl->infos[i].ref;
			if (rootfd < 0 || lst == NULL)
				break;

			/*
			 * If caller specified both a valid rootfd and
			 * stat buf then it wants to be certain that the
			 * leader exists on the local FS and matches its
			 * flist file type.
			 */

			if (rootfd >= 0 && lst != NULL &&
			    hl->infos[i].st_ino > 0 &&
			    IFTODT(leader->st.mode) ==
			    IFTODT(hl->infos[i].st_mode)) {
				memset(lst, 0, sizeof(*lst));
				lst->st_dev = hl->infos[i].st_dev;
				lst->st_ino = hl->infos[i].st_ino;
				break;
			}

			leader = NULL;
		}
		i++;
	}

	/*
	 * If a file has been written already, use it as the "leader" of
	 * this group of hardlinks.
	 */

	if (leader && this->st.inode == leader->st.inode &&
	    this->st.device == leader->st.device) {
		if (this == leader)
			return NULL;
		else
			return leader;
	}

	/* Otherwise use the first link in the group. */

	if (this->st.inode == first->st.inode &&
	    this->st.device == first->st.device) {
		if (this == first)
			return NULL;
		else
			return first;
	}

	return NULL;
}

/*
 * Get the "fl" that's the hardlink to the given file.  Returns NULL if
 * there is none.
 */
const struct flist *
find_hl(const struct flist *const this, const struct hardlinks *const hl)
{
	return find_hl_impl(this, hl, -1, NULL);
}

/*
 * Make the hardlinks backing certain files in the fl.
 */
static void
make_hardlinks(struct sess *sess, const struct flist *fl, size_t flsz,
    const struct hardlinks *hl, int rootfd)
{
	const struct flist	*f = NULL, /* current flist */
	     			*hl_p = NULL; /* hardlink file */
	int64_t			 prev_device = 0; /* last dev seen */
	int64_t			 prev_inode = 0; /* last inode seen */
	size_t			 i; /* position in fl array */

	for (i = 0; i < flsz; i++) {
		f = &fl[i];
		if (f->st.inode == 0 && f->st.device == 0)
			continue;
		if (!(f->flstate & FLIST_NEED_HLINK)) {
			if (f->st.device != prev_device) {
				prev_device = f->st.device;
				prev_inode = 0;
			}
			if (f->st.inode != prev_inode && f->iflags != 0) {
				(void)rsync_set_metadata_at(sess, 0,
				    rootfd, f, f->path);
				prev_inode = f->st.inode;
			}
			continue;
		}

		hl_p = find_hl(f, hl);
		if (hl_p == NULL)
			continue;

		if (unlinkat(rootfd, f->path, 0) == -1 &&
		    errno != ENOENT) {
			if (unlinkat(rootfd, f->path, AT_REMOVEDIR) == -1)
				ERR("unlink");
		}

		if (linkat(rootfd, hl_p->path, rootfd, f->path,
		    0) == -1) {
			ERR("linkat");
			LOG0("Error while making hard link '%s => %s'",
			    f->path, hl_p->path);
			continue;
		}

		log_item(sess, f);
	}
}

/*
 * The receiver receives files, whether as the client (local host) or
 * server (remote host).  Its mirror is rsync_sender().
 * This function should be invoked after the client or server has
 * completed the initial version handshake, and serves to coordinate the
 * exchange (in this case, receive) of file data.
 * It accepts the session, input and output file descriptors, and the
 * root into which to receive files.
 * Returns true on success, false on failure.
 */
bool
rsync_receiver(struct sess *sess, int fdin, int fdout, const char *root)
{
	struct hardlinks hls = {0}; /* hardlink array */
	struct role	 receiver; /* receiver role */
	struct stat	 st; /* temporary file stats */
	struct pollfd	 pfd[PFD__MAX]; /* polling */
	struct flist	*fl = NULL, /* flist */
			*dfl = NULL; /* deletion flist */
	struct download	*dl = NULL; /* downloader */
	struct upload	*ul = NULL; /* uploader */
	char		*rpath, /* temporary */
			*derived_root = NULL, /* cooked root dir */
			*tofree; /* XXX: merge with derived_root */
	const char	*wpath; /* temporary */
	struct hardlink *hl; /* hardlink table */
	size_t		 i, /* temporary */
			 flist_bytes = 0, /* flist bytes read */
			 flsz = 0, /* size of fl */
			 dflsz = 0, /* size of dfl */
			 chunksz; /* max send/write size to sender */
	int		 dfd = -1, /* delete directory fd */
			 phase = 0, /* metadata phase */
			 c, /* temporary: return code */
			 sndlowat, /* for getsockopt() */
			 revents; /* revents to send to uploader */
	int32_t		 ioerror; /* error after file list */
	mode_t		 oumask; /* old umask */
	socklen_t	 optlen; /* for getsockopt() */
	const int	 max_phase = 1;
	bool		 root_missing = false, /* missing root dir */
			 implied_dir = false, /* root is really cwd */
			 rc = false; /* function return code */

	if (pledge("stdio unix rpath wpath cpath dpath fattr chown getpw unveil", NULL) == -1)
		err(ERR_IPC, "pledge");

	/*
	 * The receiver's metadata phase is actually tracked in the
	 * uploader, so we'll just leave it NULL for now and let the
	 * uploader set it.  It won't be used in anything the receiver
	 * calls for now, but it's good to keep track of it properly
	 * anyways.
	 */
	memset(&receiver, 0, sizeof(receiver));
	receiver.append = false;
	receiver.phase = NULL;

	if (sess->opts->server)
		receiver.client = fdout;
	else
		receiver.client = -1;

	sess->role = &receiver;

	/*
	 * If the root doesn't exist, we may be substituting cwd instead
	 * as the root if we're only transferring a single file.  We
	 * won't know until after the file list is transferred, so we
	 * open it up to cwd proactively.
	 */

	if (stat(root, &st) == -1 && errno == ENOENT) {
		root_missing = true;
		if (unveil(".", "rwc") == -1)
			err(ERR_IPC, ".: unveil");
		memset(&st, 0, sizeof(st));
	}

	/*
	 * Make our entire view of the file-system be limited to what's
	 * in the root directory.
	 * This prevents us from accidentally (or "under the influence")
	 * writing into other parts of the file-system.
	 */

	if (sess->opts->basedir[0]) {
		/*
		 * XXX just unveil everything for read.
		 * Could unveil each basedir or maybe a common path
		 * also the fact that relative path are relative to the
		 * root does not help.
		 */
		if (unveil("/", "r") == -1)
			err(ERR_IPC, "%s: unveil", root);
	}

#if 0
	/*
	 * This was moved to below because "root" may not exist yet.
	 * FIXME: conditionally unveil if the root exists.
	 * FIXME: allow for ~/.cvsignore
	 */
	if (unveil(root, "rwc") == -1)
		err(ERR_IPC, "%s: unveil", root);
	if (unveil(NULL, NULL) == -1)
		err(ERR_IPC, "unveil");
#endif

	/*
	 * Client sends rules.  If in a position to send, check whether
	 * the negotiated protocol is satisfied beforehand.
	 */

	if (!sess->opts->server) {
		check_send_rules(sess);
		send_rules(sess, fdout);
	}

	/* Server receives rules if delete is on. */

	if (sess->opts->server &&
	    (sess->opts->del && !sess->opts->del_excl))
		recv_rules(sess, fdin);

	/*
	 * Start by receiving the file list and our mystery number.
	 * These we're going to be touching on our local system.
	 */

	flist_bytes = sess->total_read;
	if (!flist_recv(sess, fdin, fdout, &fl, &flsz)) {
		ERRX1("flist_recv");
		goto out;
	}

	sess->total_files = flsz;
	sess->flist_size = sess->total_read - flist_bytes;

	/* 
	 * Read: [io-error-value].
	 * The IO error is sent after the file list.
	 */

	if (!io_read_int(sess, fdin, &ioerror)) {
		ERRX1("io_read_int");
		goto out;
	} else if (ioerror != 0) {
		ERRX1("io_error is non-zero");
		goto out;
	}

	if (flsz == 0 && !sess->opts->server) {
		WARNX("receiver has empty file list: exiting");
		rc = true;
		goto out;
	} else if (!sess->opts->server)
		LOG1("Transfer starting: %zu files", flsz);

	LOG2("%s: receiver destination", root);

	/*
	 * Create the path for our destination directory, if we're not
	 * in dry-run mode (which would otherwise crash w/the pledge).
	 * This uses our current umask: we might set the permissions on
	 * this directory in post_dir().
	 */

	if (!sess->opts->dry_run) {
		if (flsz == 0)
			implied_dir = true;
		else if (flsz > 1)
			implied_dir = true;
		else if (sess->opts->relative && strchr(fl[0].path, '/') != NULL)
			implied_dir = true;
		else if (root[strlen(root) - 1] == '/')
			implied_dir = true;
		else if (S_ISDIR(fl[0].st.mode))
			implied_dir = true;

		/*
		 * If we're only transferring a single non-directory,
		 * then the root is actually cwd and the destination
		 * specified in args is the filename ("implied_dir").
		 *
		 * The receiver doesn't do this if the destination has a
		 * trailing slash to indicate that it's actually a
		 * directory.
		 */

		if (!implied_dir &&
		    (root_missing || !S_ISDIR(st.st_mode))) {
			/*
			 * If we're not in relative mode, we strip the
			 * leading directory part anyways.  If we are in
			 * relative mode, we're not hitting this path
			 * unless it's in the current directory.
			 */

			wpath = strrchr(root, '/');
			if (wpath != NULL) {
				wpath++;
				derived_root = strndup(root,
				    wpath - root);
				if (derived_root == NULL) {
					ERR("strdup");
					rc = true;
					goto out;
				}
				rpath = strdup(wpath);
				if (rpath == NULL) {
					ERR("strdup");
					rc = true;
					goto out;
				}
				wpath = rpath;
				root = derived_root;
			} else {
				/* Current directory, just copy. */
				wpath = rpath = strdup(root);
				if (rpath == NULL) {
					ERR("strdup");
					rc = true;
					goto out;
				}
				root = ".";
			}
			free(fl[0].path);
			fl[0].path = rpath;
			fl[0].wpath = wpath;
		} else {
			if ((tofree = strdup(root)) == NULL)
				err(ERR_NOMEM, NULL);
			if (mkpath(tofree, 0755) < 0)
				err(ERR_FILE_IO, "%s: mkpath", tofree);
			free(tofree);

			/*
			 * If we created the destination directory and
			 * the first file in the flist is "." then we
			 * must set iflags here because the uploader
			 * (i.e., pre_dir()) can't tell that it was
			 * newly created.
			 */

			if (root_missing && flsz > 0 &&
			    S_ISDIR(fl[0].st.mode) &&
			    strcmp(fl[0].path, ".") == 0)
				fl[0].iflags |= IFLAG_NEW |
				    IFLAG_LOCAL_CHANGE;
		}
	}

	if (unveil(root, "rwc") == -1)
		err(ERR_IPC, "%s: unveil", root);
	if (unveil(NULL, NULL) == -1)
		err(ERR_IPC, "unveil");

	/*
	 * Disable umask() so we can set permissions fully.
	 * Then open the directory if we're not in dry_run.
	 */

	oumask = umask(0);

	/*
	 * Try opening the root directory.  If we're in dry_run and
	 * fail, just report the error and continue on---don't try to
	 * create the directory.
	 */

#ifdef O_DIRECTORY
	dfd = open(root, O_RDONLY | O_DIRECTORY, 0);
	if (dfd == -1) {
		if (!sess->opts->dry_run && flsz != 0) {
			ERR("%s: open", root);
			goto out;
		} else if (!sess->opts->dry_run)
			WARN("%s: open", root);
	}
#else
	if ((dfd = open(root, O_RDONLY, 0)) == -1) {
		if (!sess->opts->dry_run && flsz != 0) {
			ERR("%s: open", root);
			goto out;
		} else
			WARN("%s: open", root);
	} else if (dfd != -1) {
		if (fstat(dfd, &st) == -1) {
			if (!sess->opts->dry_run) {
				ERR("%s: fstat", root);
				goto out;
			} else {
				WARN("%s: fstat", root);
				close(dfd);
				dfd = -1;
			}
		} else if (!S_ISDIR(st.st_mode)) {
			if (!sess->opts->dry_run) {
				ERRX("%s: not a directory", root);
				goto out;
			} else {
				WARN("%s: fstat", root);
				close(dfd);
				dfd = -1;
			}
		}
	}
#endif
	if (dfd != -1)
		LOG3("%s: root directory opened", root);

	/*
	 * Now that we have the root fd we can build the hardlinks
	 * table.  Use calloc() to allocate the hl array so as to
	 * minimize the amount of physmem actually allocated (because
	 * flsz could be very large whereas hl is typically very small).
	 */

	if (sess->opts->hard_links) {
		hl = calloc(flsz, sizeof(*hl));
		if (hl == NULL) {
			ERRX1("calloc hl");
			goto out;
		}
		hls.infosz = build_for_hardlinks(sess, hl, fl, flsz, dfd);
		hls.infos = hl;
	}

	/*
	 * Begin by conditionally getting all files we have currently
	 * available in our destination.
	 */

	if (sess->opts->del == DMODE_BEFORE) {
		if (!flist_gen_dels(sess, root, &dfl, &dflsz, fl,
		    flsz)) {
			ERRX1("rsync_receiver");
			goto out;
		}

		/* If we have a local set, go for the deletion. */

		flist_del(sess, dfd, dfl, dflsz);
	}

	/* Initialise poll events to listen from the sender. */

	pfd[PFD_SENDER_IN].fd = fdin;
	pfd[PFD_UPLOADER_IN].fd = -1;
	pfd[PFD_DOWNLOADER_IN].fd = -1;
	pfd[PFD_SENDER_OUT].fd = fdout;

	pfd[PFD_SENDER_IN].events = POLLIN;
	pfd[PFD_UPLOADER_IN].events = POLLIN;
	pfd[PFD_DOWNLOADER_IN].events = POLLIN;
	pfd[PFD_SENDER_OUT].events = POLLOUT;

	/*
	 * We avoid deadlocks between the sender and uploader by writing
	 * no more data to the socket/pipe than there is space
	 * available.  If PFD_SENDER_OUT is a socket then we try to
	 * obtain the send low-watermark and maybe try to set it to our
	 * preferred chunk size. If PFD_SENDER_OUT is a pipe then we use
	 * PIPE_BUF as the send low-watermark, and in both cases we'll
	 * adjust our chunk size to accomodate a multiplex tag.
	 */

	optlen = sizeof(sndlowat);
	sndlowat = 0;

	c = getsockopt(pfd[PFD_SENDER_OUT].fd, SOL_SOCKET, SO_SNDLOWAT,
	    &sndlowat, &optlen);

	if (c == 0 && sndlowat < MAX_CHUNK) {
		sndlowat = MAX_CHUNK;
		c = setsockopt(pfd[PFD_SENDER_OUT].fd, SOL_SOCKET,
		    SO_SNDLOWAT, &sndlowat, sizeof(sndlowat));
	}

	chunksz = (c == 0 && sndlowat > 0) ? sndlowat : PIPE_BUF;
	if (sess->mplex_writes)
		chunksz -= sizeof(int32_t);
	rc = false;

	ul = upload_alloc(root, dfd, fdout, CSUM_LENGTH_PHASE1, fl, flsz,
	    chunksz, oumask);

	if (ul == NULL) {
		ERRX1("upload_alloc");
		goto out;
	}

	dl = download_alloc(sess, fdin, fl, flsz, dfd);
	if (dl == NULL) {
		ERRX1("download_alloc");
		goto out;
	}

	LOG2("%s: ready for phase 1 data", root);

	for (;;) {
		if ((c = poll(pfd, PFD__MAX, poll_timeout)) == -1) {
			ERR("poll");
			goto out;
		} else if (c == 0) {
			ERRX("poll: timeout");
			goto out;
		}

		for (i = 0; i < PFD__MAX; i++)
			if (pfd[i].revents & (POLLERR|POLLNVAL)) {
				ERRX("poll: bad fd");
				goto out;
			} else if (pfd[i].revents & POLLHUP) {
				ERRX("poll: hangup");
				goto out;
			}

		/*
		 * If we have a read event and we're multiplexing, we
		 * might just have error messages in the pipe.
		 * It's important to flush these out so that we don't
		 * clog the pipe.
		 * Unset our polling status if there's nothing that
		 * remains in the pipe.
		 */

		if (sess->mplex_reads &&
		    (pfd[PFD_SENDER_IN].revents & POLLIN)) {
			if (!io_read_flush(sess, fdin)) {
				ERRX1("io_read_flush");
				goto out;
			} else if (sess->mplex_read_remain == 0)
				pfd[PFD_SENDER_IN].revents &= ~POLLIN;
		}

		/*
		 * We run the uploader if we have files left to examine
		 * (i < flsz) or if we have a file that we've opened and
		 * is read to mmap.
		 */

		if ((pfd[PFD_UPLOADER_IN].revents & POLLIN) ||
		    (pfd[PFD_SENDER_OUT].revents & POLLOUT)) {
			revents = pfd[PFD_UPLOADER_IN].revents & POLLIN;
			revents |= pfd[PFD_SENDER_OUT].revents & POLLOUT;
			c = rsync_uploader(ul, sess, revents,
				&pfd[PFD_UPLOADER_IN].fd,
				&pfd[PFD_SENDER_OUT].fd, &hls);
			if (c < 0) {
				ERRX1("rsync_uploader");
				goto out;
			}
		}

		/*
		 * We need to run the downloader when we either have
		 * read events from the sender or an asynchronous local
		 * open is ready.
		 * XXX: we don't disable PFD_SENDER_IN like with the
		 * uploader because we might stop getting error
		 * messages, which will otherwise clog up the pipes.
		 */

		if ((pfd[PFD_SENDER_IN].revents & POLLIN) ||
		    (pfd[PFD_DOWNLOADER_IN].revents & POLLIN)) {
			c = rsync_downloader(dl, sess,
			    &pfd[PFD_DOWNLOADER_IN].fd);
			if (c < 0) {
				ERRX1("rsync_downloader");
				goto out;
			} else if (c == 0) {
				assert(phase >= 0 && phase <= max_phase);

				/*
				 * Downloader finished the last of this
				 * phase, so finish up the tail end of
				 * acks.
				 */

				rsync_uploader_ack_complete(ul, sess,
				    fdout);
				phase++;
				if (phase == max_phase + 1)
					break;

				if (sess->opts->hard_links &&
				    phase == 2 &&
				    sess->opts->dry_run == DRY_DISABLED)
					make_hardlinks(sess, fl, flsz, &hls, dfd);

				LOG3("%s: receiver ready for phase %d "
				    "data (%d to redo)", root,
				    phase + 1, 0);

				sess->role->append = false;

				/*
				 * Signal the uploader to start over,
				 * and re-enable polling.
				 */

				rsync_uploader_next_phase(ul, sess, fdout);
				pfd[PFD_SENDER_OUT].fd = fdout;
				continue;
			}
		}
	}

	assert(phase == max_phase + 1);

	/*
	 * Now all of our transfers are complete, so we can fix up our
	 * directory permissions.
	 */

	if (!rsync_uploader_tail(ul, sess)) {
		ERRX1("rsync_uploader_tail");
		goto out;
	}

	/* Process server statistics and say good-bye. */

	if (!sess_stats_recv(sess, fdin)) {
		ERRX1("sess_stats_recv");
		goto out;
	}
	if (!io_write_int(sess, fdout, -1)) {
		ERRX1("io_write_int");
		goto out;
	}

	LOG3("receiver finished updating");
	rc = true;
out:
	free(derived_root);
	upload_free(ul);
	download_free(sess, dl);

	if (dfd != -1)
		close(dfd);

	flist_free(fl, flsz);
	flist_free(dfl, dflsz);
	return rc;
}

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
#include <sys/mman.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "md4.h"
#include "extern.h"

enum	pfdt {
	PFD_SENDER_IN = 0, /* input from the sender */
	PFD_UPLOADER_IN, /* uploader input from a local file */
	PFD_DOWNLOADER_IN, /* downloader input from a local file */
	PFD_SENDER_OUT, /* output to the sender */
	PFD__MAX
};

/*
 * We need to process our directories in post-order.
 * This is because touching files within the directory will change the
 * directory file; and also, if our mode is not writable, we wouldn't be
 * able to write to that directory!
 * Returns zero on failure, non-zero on success.
 * FIXME: put in uploader.c.
 */
static int
post_dir(struct sess *sess, int root, const struct flist *f, int newdir)
{
	struct timespec	 tv[2];
	int		 rc;
	struct stat	 st;

	/* We already warned about the directory in pre_process_dir(). */

	if ( ! sess->opts->recursive)
		return 1;
	else if (sess->opts->dry_run)
		return 1;

	if (-1 == fstatat(root, f->path, &st, AT_SYMLINK_NOFOLLOW)) {
		ERR(sess, "%s: fstatat", f->path);
		return 0;
	} else if ( ! S_ISDIR(st.st_mode)) {
		WARNX(sess, "%s: not a directory", f->path);
		return 0;
	}

	/* 
	 * Update the modification time if we're a new directory *or* if
	 * we're preserving times and the time has changed.
	 */

	if (newdir || 
	    (sess->opts->preserve_times && 
	     st.st_mtime != f->st.mtime)) {
		tv[0].tv_sec = time(NULL);
		tv[0].tv_nsec = 0;
		tv[1].tv_sec = f->st.mtime;
		tv[1].tv_nsec = 0;
		rc = utimensat(root, f->path, tv, 0);
		if (-1 == rc) {
			ERR(sess, "%s: utimensat", f->path);
			return 0;
		}
		LOG4(sess, "%s: updated date", f->path);
	}

	/*
	 * Update the mode if we're a new directory *or* if we're
	 * preserving modes and it has changed.
	 */

	if (newdir || 
	    (sess->opts->preserve_perms &&
	     st.st_mode != f->st.mode)) {
		rc = fchmodat(root, f->path, f->st.mode, 0);
		if (-1 == rc) {
			ERR(sess, "%s: fchmodat", f->path);
			return 0;
		}
		LOG4(sess, "%s: updated mode", f->path);
	}

	return 1;
}

/* 
 * Pledges: unveil, rpath, cpath, wpath, stdio, fattr.
 * Pledges (dry-run): -cpath, -wpath, -fattr.
 */
int
rsync_receiver(struct sess *sess,
	int fdin, int fdout, const char *root)
{
	struct flist	*fl = NULL, *dfl = NULL;
	size_t		 i, j, flsz = 0, dflsz = 0;
	char		*tofree;
	int		 rc = 0, dfd = -1, phase = 0, c;
	int32_t	 	 ioerror;
	struct pollfd	 pfd[PFD__MAX];
	struct download	*dl = NULL;
	struct upload 	 ul;

	memset(&ul, 0, sizeof(struct upload));

	if (-1 == pledge("unveil rpath cpath wpath stdio fattr", NULL)) {
		ERR(sess, "pledge");
		goto out;
	}

	/* XXX: what does this do? */

	if ( ! sess->opts->server &&
	     ! io_write_int(sess, fdout, 0)) {
		ERRX1(sess, "io_write_int");
		goto out;
	}

	/*
	 * Start by receiving the file list and our mystery number.
	 * These we're going to be touching on our local system.
	 */

	if ( ! flist_recv(sess, fdin, &fl, &flsz)) {
		ERRX1(sess, "flist_recv");
		goto out;
	} else if ( ! io_read_int(sess, fdin, &ioerror)) {
		ERRX1(sess, "io_read_int");
		goto out;
	} else if (0 != ioerror) {
		ERRX1(sess, "io_error is non-zero");
		goto out;
	}

	if (0 == flsz && ! sess->opts->server) {
		WARNX(sess, "receiver has empty file list: exiting");
		rc = 1;
		goto out;
	} else if ( ! sess->opts->server)
		LOG1(sess, "Transfer starting: %zu files", flsz);

	LOG2(sess, "%s: receiver destination", root);

	/*
	 * Create the path for our destination directory, if we're not
	 * in dry-run mode (which would otherwise crash w/the pledge).
	 * This uses our current umask: we might set the permissions on
	 * this directory in post_dir().
	 */

	if ( ! sess->opts->dry_run) {
		if (NULL == (tofree = strdup(root))) {
			ERR(sess, "strdup");
			goto out;
		} else if (mkpath(sess, tofree) < 0) {
			ERRX1(sess, "%s: mkpath", root);
			free(tofree);
			goto out;
		}
		free(tofree);
	}

	/*
	 * Disable umask() so we can set permissions fully.
	 * Then open the directory iff we're not in dry_run.
	 */

	ul.oumask = umask(0);

	if ( ! sess->opts->dry_run) {
		dfd = open(root, O_RDONLY | O_DIRECTORY, 0);
		if (-1 == dfd) {
			ERR(sess, "%s: open", root);
			goto out;
		}
	}

	/*
	 * Begin by conditionally getting all files we have currently
	 * available in our destination.
	 * XXX: do this *before* the unveil() because fts_read() doesn't
	 * work properly afterward.
	 */

	if (sess->opts->del && sess->opts->recursive)
		if ( ! flist_gen_local(sess, root, &dfl, &dflsz)) {
			ERRX1(sess, "flist_gen_local");
			goto out;
		}

	/*
	 * Make our entire view of the file-system be limited to what's
	 * in the root directory.
	 * This prevents us from accidentally (or "under the influence")
	 * writing into other parts of the file-system.
	 */

	if (-1 == unveil(root, "rwc")) {
		ERR(sess, "%s: unveil", root);
		goto out;
	} else if (-1 == unveil(NULL, NULL)) {
		ERR(sess, "%s: unveil (lock down)", root);
		goto out;
	}

	/* If we have a local set, go for the deletion. */

	if (NULL != dfl)
		if ( ! flist_del(sess, dfd, dfl, dflsz, fl, flsz)) {
			ERRX1(sess, "flist_del");
			goto out;
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

	ul.rootfd = dfd;
	ul.csumlen = CSUM_LENGTH_PHASE1;
	ul.fdout = fdout;
	ul.fl = fl;
	ul.flsz = flsz;
	ul.newdir = calloc(flsz, sizeof(int));
	if (NULL == ul.newdir) {
		ERR(sess, "calloc");
		goto out;
	}

	dl = download_alloc(sess, fdin, fl, flsz, dfd);
	if (NULL == dl) {
		ERRX1(sess, "download_alloc");
		goto out;
	}

	LOG2(sess, "%s: ready for phase 1 data", root);

	for (;;) {
		if (-1 == (c = poll(pfd, PFD__MAX, INFTIM))) {
			ERR(sess, "poll");
			goto out;
		} 

		for (j = 0; j < PFD__MAX; j++) 
			if (pfd[j].revents & (POLLERR|POLLNVAL)) {
				ERRX(sess, "poll: bad fd");
				goto out;
			} else if (pfd[j].revents & POLLHUP) {
				ERRX(sess, "poll: hangup");
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
		    (POLLIN & pfd[PFD_SENDER_IN].revents)) {
			if ( ! io_read_flush(sess, fdin)) {
				ERRX1(sess, "io_read_flush");
				goto out;
			} else if (0 == sess->mplex_read_remain)
				pfd[PFD_SENDER_IN].revents &= ~POLLIN;
		}


		/*
		 * We run the uploader if we have files left to examine
		 * (i < flsz) or if we have a file that we've opened and
		 * is read to mmap.
		 */

		if ((POLLIN & pfd[PFD_UPLOADER_IN].revents) ||
		    (POLLOUT & pfd[PFD_SENDER_OUT].revents)) {
			c = rsync_uploader(&ul, 
				&pfd[PFD_UPLOADER_IN].fd, 
				sess, &pfd[PFD_SENDER_OUT].fd);
			if (c < 0) {
				ERRX1(sess, "rsync_uploader");
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

		if ((POLLIN & pfd[PFD_SENDER_IN].revents) || 
		    (POLLIN & pfd[PFD_DOWNLOADER_IN].revents)) {
			c = rsync_downloader(dl, sess, 
				&pfd[PFD_DOWNLOADER_IN].fd);
			if (c < 0) {
				ERRX1(sess, "rsync_downloader");
				goto out;
			} else if (0 == c) {
				assert(0 == phase);
				phase++;
				LOG2(sess, "%s: receiver ready "
					"for phase 2 data", root);
				break;
			}

			/*
			 * FIXME: if we have any errors during the
			 * download, most notably files getting out of
			 * sync between the send and the receiver, then
			 * here we should bump our checksum length and
			 * go into the second phase.
			 */
		} 
	}

	/* Fix up the directory permissions and times post-order. */

	if (sess->opts->preserve_times ||
	    sess->opts->preserve_perms)
		for (i = 0; i < flsz; i++) {
			if ( ! S_ISDIR(fl[i].st.mode))
				continue;
			if ( ! post_dir(sess, dfd, &fl[i], ul.newdir[i]))
				goto out;
		}

	/* Properly close us out by progressing through the phases. */

	if (1 == phase) {
		if ( ! io_write_int(sess, fdout, -1)) {
			ERRX1(sess, "io_write_int");
			goto out;
		} else if ( ! io_read_int(sess, fdin, &ioerror)) {
			ERRX1(sess, "io_read_int");
			goto out;
		} else if (-1 != ioerror) {
			ERRX(sess, "expected phase ack");
			goto out;
		}
	}

	/* Process server statistics and say good-bye. */

	if ( ! sess_stats_recv(sess, fdin)) {
		ERRX1(sess, "sess_stats_recv");
		goto out;
	} else if ( ! io_write_int(sess, fdout, -1)) {
		ERRX1(sess, "io_write_int");
		goto out;
	}

	LOG2(sess, "receiver finished updating");
	rc = 1;
out:
	if (-1 != dfd)
		close(dfd);
	flist_free(fl, flsz);
	flist_free(dfl, dflsz);
	free(ul.newdir);
	free(ul.buf);
	download_free(dl);
	return rc;
}

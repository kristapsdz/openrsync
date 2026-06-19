/*
 * Copyright (c) Kristaps Dzonsons <kristaps@bsd.lv>
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

#include <sys/param.h> /* MAX() */
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <assert.h>
#if HAVE_ERR
# include <err.h>
#endif
#if !HAVE_SOCK_NONBLOCK
# include <fcntl.h>
#endif
#include <getopt.h>
#include <limits.h> /* CHAR_MAX */
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#if HAVE_SCAN_SCALED
# include <util.h> /* scan_scaled */
#endif

#include "extern.h"
#include "rules.h"

static struct opts opts;
typedef int (rsync_option_filter)(struct sess *, int, const struct option *);

int verbose;
int poll_contimeout;
int poll_timeout;

/*
 * A remote host is has a colon before the first path separator.
 * This works for rsh remote hosts (host:/foo/bar), implicit rsync
 * remote hosts (host::/foo/bar), and explicit (rsync://host/foo).
 * Return false if local, true if remote.
 */
static bool
fargs_is_remote(const char *v)
{
	size_t	 pos;

	if (v == NULL)
		return false;

	pos = strcspn(v, ":/");
	return v[pos] == ':';
}

/*
 * Test whether a remote host is specifically an rsync daemon.
 * Return false if not, true if so.
 */
static bool
fargs_is_daemon(const char *v)
{
	size_t	 pos;

	if (strncasecmp(v, "rsync://", 8) == 0)
		return true;
	pos = strcspn(v, ":/");
	return v[pos] == ':' && v[pos + 1] == ':';
}

/*
 * Strips the hostnames from the remote host.
 *   rsync://host/module/path -> module/path
 *   host::module/path -> module/path
 *   host:path -> path
 * Also make sure that the remote hosts are the same.
 */
static void
fargs_normalize_spec(const struct fargs *f, char *spec, size_t hostlen)
{
	char	*cp, *ccp, *host_part, *module_part;
	size_t	 j;

	cp = spec;
	j = strlen(cp);
	if (f->remote && strncasecmp(cp, "rsync://", 8) == 0) {
		/* rsync://[user@]host[:port]/path */

		/* cp is the host part */
		host_part = cp + 8;
		if ((ccp = strchr(host_part, '@')) != NULL)
			host_part = ccp + 1;

		/* skip :port */
		if ((ccp = strchr(host_part, ':')) != NULL) {
			*ccp = '\0';
			ccp++;
		} else {
			ccp = host_part;
		}

		/*
		 * ccp is the part just after our hostname, which may include a
		 * port number.
		 */
		module_part = strchr(ccp + 1, '/');
		if (module_part != NULL)
			module_part++;
		else
			module_part = &ccp[strlen(ccp) - 1];

		if (strncmp(host_part, f->host, hostlen) ||
		    (host_part[hostlen] != '/' && host_part[hostlen] != '\0'))
			errx(ERR_SYNTAX, "different remote host: %s", spec);

		memmove(spec, module_part, strlen(module_part) + 1);
	} else if (f->remote && strncmp(cp, "::", 2) == 0) {
		/* ::path */
		memmove(spec, spec + 2, j - 1);
	} else if (f->remote) {
		/* host::path */
		if (strncmp(cp, f->host, hostlen) ||
		    (cp[hostlen] != ':' && cp[hostlen] != '\0'))
			errx(ERR_SYNTAX, "different remote host: %s", spec);
		memmove(spec, spec + hostlen + 2, j - hostlen - 1);
	} else if (cp[0] == ':') {
		/* :path */
		memmove(spec, spec + 1, j);
	} else {
		/* host:path */
		if (strncmp(cp, f->host, hostlen) ||
		    (cp[hostlen] != ':' && cp[hostlen] != '\0'))
			errx(ERR_SYNTAX, "different remote host: %s", spec);
		memmove(spec, spec + hostlen + 1, j - hostlen);
	}
}

/*
 * Take the command-line filenames (e.g., rsync foo/ bar/ baz/) and
 * determine our operating mode.
 * For example, if the first argument is a remote file, this means that
 * we're going to transfer from the remote to the local.
 * We also make sure that the arguments are consistent, that is, if
 * we're going to transfer from the local to the remote, that no
 * filenames for the local transfer indicate remote hosts.
 * Always returns the parsed and sanitised options.
 */
static struct fargs *
fargs_parse(size_t argc, char *argv[], struct opts *opts)
{
	struct fargs	*f; /* returned arguments */
	char		*cp; /* temporary */
	size_t		 i, /* temporary */
			 j, /* temporary */
			 hostlen = 0;
	size_t		 sinkarg; /* write into this host */

	/* Allocations. */

	if ((f = calloc(1, sizeof(struct fargs))) == NULL)
		err(ERR_NOMEM, NULL);

	if (argc > 1) {
		sinkarg = argc - 1;
		f->sourcesz = argc - 1;
	} else {
		sinkarg = argc;
		f->sourcesz = 1;
	}

	if (f->sourcesz > 0) {
		f->sources = calloc(f->sourcesz, sizeof(char *));
		if (f->sources == NULL)
			err(ERR_NOMEM, NULL);
		for (i = 0; i < sinkarg; i++)
			if ((f->sources[i] = strdup(argv[i])) == NULL)
				err(ERR_NOMEM, NULL);
	}

	if (argv[sinkarg] != NULL &&
	    (f->sink = strdup(argv[sinkarg])) == NULL)
		err(ERR_NOMEM, NULL);

	/*
	 * Test files for its locality.
	 * If the last is a remote host, then we're sending from the
	 * local to the remote host ("sender" mode).
	 * If the first, remote to local ("receiver" mode).
	 * If neither, a local transfer in sender style unless we're doing an
	 * implied --list-only.
	 */

	f->mode = f->sink == NULL ? FARGS_RECEIVER : FARGS_SENDER;

	if (f->sink != NULL && fargs_is_remote(f->sink)) {
		f->mode = FARGS_SENDER;
		if ((f->host = strdup(f->sink)) == NULL)
			err(ERR_NOMEM, NULL);
	}

	if (fargs_is_remote(f->sources[0])) {
		if (f->host != NULL)
			errx(ERR_SYNTAX, "both source and destination "
			    "cannot be remote files");
		f->mode = FARGS_RECEIVER;
		if ((f->host = strdup(f->sources[0])) == NULL)
			err(ERR_NOMEM, NULL);
	}

	if (f->host != NULL) {
		if (strncasecmp(f->host, "rsync://", 8) == 0) {
			/* rsync://[user@]host[:port]/module[/path] */

			f->remote = 1;
			hostlen = strlen(f->host) - 8;

			/* [user@]host --> extract host */

			if ((cp = strchr(f->host + 8, '@')) != NULL) {
				f->user = strndup(f->host + 8,
				    cp - (f->host + 8));
				if (f->user == NULL)
					err(ERR_NOMEM, NULL);

				cp++;
				hostlen = strlen(cp);
			} else {
				cp = f->host + 8;
			}

			memmove(f->host, cp, hostlen + 1 /* NUL */);

			if ((cp = strchr(f->host, '/')) == NULL &&
			    f->sink != NULL) {
				errx(ERR_SYNTAX,
				    "rsync protocol requires a module name");
			}

			if (cp != NULL) {
				*cp++ = '\0';
				f->module = cp;
				if ((cp = strchr(f->module, '/')) != NULL)
					*cp = '\0';
			} else {
				f->module = "";
			}

			if ((cp = strchr(f->host, ':')) != NULL) {
				/* host:port --> extract port */
				*cp++ = '\0';
				opts->port = cp;
			}
		} else {
			/* host:[/path] */
			cp = strchr(f->host, ':');
			assert(cp != NULL);
			*cp++ = '\0';
			if (*cp == ':') {
				/* host::module[/path] */
				f->remote = 1;
				f->module = ++cp;
				cp = strchr(f->module, '/');
				if (cp != NULL)
					*cp = '\0';
			}
		}

		if ((hostlen = strlen(f->host)) == 0)
			errx(ERR_SYNTAX, "empty remote host");

		/*
		 * Leaving off the module is fine if we're just
		 * requesting a listing.
		 */

		if (f->remote &&
		    (f->module == NULL || strlen(f->module) == 0) &&
		    f->sink != NULL)
			errx(ERR_SYNTAX, "empty remote module");
	}

	/*
	 * For an implied --list-only transfer, we don't need to verify
	 * anything here because there's just the one arg.
	 */

	if (f->sink == NULL)
		goto skipverify;

	/* Make sure we have the same "hostspec" for all files. */

	if (!f->remote) {
		if (f->mode == FARGS_SENDER)
			for (i = 0; i < f->sourcesz; i++) {
				if (!fargs_is_remote(f->sources[i]))
					continue;
				errx(ERR_SYNTAX,
				    "remote file in list of local sources: %s",
				    f->sources[i]);
			}
		if (f->mode == FARGS_RECEIVER)
			for (i = 0; i < f->sourcesz; i++) {
				if (fargs_is_remote(f->sources[i]) &&
				    !fargs_is_daemon(f->sources[i]))
					continue;
				if (fargs_is_daemon(f->sources[i]))
					errx(ERR_SYNTAX,
					    "remote daemon in list of remote "
					    "sources: %s", f->sources[i]);
				errx(ERR_SYNTAX, "local file in list of "
				    "remote sources: %s", f->sources[i]);
			}
	} else {
		if (f->mode == FARGS_SENDER)
			for (i = 0; i < f->sourcesz; i++) {
				if (!fargs_is_remote(f->sources[i]))
					continue;
				errx(ERR_SYNTAX,
				    "remote file in list of local sources: %s",
				    f->sources[i]);
			}
		if (f->mode == FARGS_RECEIVER)
			for (i = 0; i < f->sourcesz; i++) {
				if (fargs_is_daemon(f->sources[i]))
					continue;
				errx(ERR_SYNTAX, "non-remote daemon file "
					"in list of remote daemon sources: "
					"%s", f->sources[i]);
			}
	}

skipverify:
	/*
	 * If we're not remote and a sender, strip our hostname.
	 * Then exit if we're a sender or a local connection.
	 */
	if (!f->remote) {
		if (f->host == NULL)
			return f;
		if (f->mode == FARGS_SENDER) {
			assert(f->host != NULL);
			assert(hostlen > 0);
			if (f->sink != NULL) {
				j = strlen(f->sink);
				memmove(f->sink, f->sink + hostlen + 1,
				    j - hostlen);
			}
			return f;
		} else if (f->mode != FARGS_RECEIVER)
			return f;
	}

	assert(f->host != NULL);
	assert(hostlen > 0);

	if (f->mode == FARGS_RECEIVER) {
		for (i = 0; i < f->sourcesz; i++)
			fargs_normalize_spec(f, f->sources[i], hostlen);
	} else if (f->sink != NULL) {
		/*
		 * ssh and local transfers bailed out earlier and
		 * stripped the host: part as needed.  If we got here,
		 * we're connecting to a daemon as a sender.
		 */
		assert(f->remote);
		fargs_normalize_spec(f, f->sink, hostlen);
	}

	return f;
}

enum {
	OP_ADDRESS = CHAR_MAX + 1,
	OP_PORT,
	OP_RSYNCPATH,
	OP_PROTOCOL,
	OP_TIMEOUT,
	OP_EXCLUDE,
	OP_INCLUDE,
	OP_EXCLUDE_FROM,
	OP_INCLUDE_FROM,
	OP_COMP_DEST,
	OP_COPY_DEST,
	OP_LINK_DEST,
	OP_MAX_SIZE,
	OP_MIN_SIZE,
	OP_CONTIMEOUT,
	OP_SET_BOOL_FALSE,
	OP_SET_BOOL_TRUE,
};

const char rsync_shopts[] = "468B:CDFade:f:ghIJlnOoprtVvWxz";
const struct option	 lopts[] = {
    { "8-bit-output",	no_argument,	NULL,			'8' },
    { "address",	required_argument, NULL,		OP_ADDRESS },
    { "archive",	no_argument,	NULL,			'a' },
    { "block-size",	required_argument, NULL,		'B' },
    { "compare-dest",	required_argument, NULL,		OP_COMP_DEST },
    { "copy-dest",	required_argument, NULL,		OP_COPY_DEST },
    { "link-dest",	required_argument, NULL,		OP_LINK_DEST },
    { "compress",	no_argument,	NULL,			'z' },
    { "contimeout",	required_argument, NULL,		OP_CONTIMEOUT },
    { "cvs-exclude",	no_argument,	NULL,			'C' },
    { "del",		no_argument,	NULL,			OP_SET_BOOL_TRUE },
    { "delete",		no_argument,	NULL,			OP_SET_BOOL_TRUE },
    { "devices",	no_argument,	NULL,			OP_SET_BOOL_TRUE },
    { "dry-run",	no_argument,	NULL,			'n' },
    { "exclude",	required_argument, NULL,		OP_EXCLUDE },
    { "exclude-from",	required_argument, NULL,		OP_EXCLUDE_FROM },
    { "filter",		required_argument, NULL,		'f' },
    { "group",		no_argument,	NULL,			OP_SET_BOOL_TRUE },
    { "help",		no_argument,	NULL,			'h' },
    { "ignore-times",	no_argument,	NULL,			'I' },
    { "include",	required_argument, NULL,		OP_INCLUDE },
    { "include-from",	required_argument, NULL,		OP_INCLUDE_FROM },
    { "ipv4",           no_argument,    NULL,                   '4' },
    { "ipv6",           no_argument,    NULL,                   '6' },
    { "links",		no_argument,	NULL,			OP_SET_BOOL_TRUE },
    { "max-size",	required_argument, NULL,		OP_MAX_SIZE },
    { "min-size",	required_argument, NULL,		OP_MIN_SIZE },
    { "no-J",		no_argument,	NULL, 			OP_SET_BOOL_FALSE }, /* XXX */
    { "no-O",		no_argument,	NULL,			OP_SET_BOOL_FALSE }, /* XXX */
    { "no-devices",	no_argument,	NULL,			OP_SET_BOOL_FALSE },
    { "no-group",	no_argument,	NULL,			OP_SET_BOOL_FALSE },
    { "no-links",	no_argument,	NULL,			OP_SET_BOOL_FALSE },
    { "no-motd",	no_argument,	NULL,			OP_SET_BOOL_FALSE },
    { "no-omit-dir-times", no_argument,	NULL,			OP_SET_BOOL_FALSE },
    { "no-omit-link-times", no_argument, NULL,			OP_SET_BOOL_FALSE },
    { "no-owner",	no_argument,	NULL,			OP_SET_BOOL_FALSE },
    { "no-perms",	no_argument,	NULL,			OP_SET_BOOL_FALSE },
    { "no-recursive",	no_argument,	NULL,			OP_SET_BOOL_FALSE },
    { "no-specials",	no_argument,	NULL,			OP_SET_BOOL_FALSE },
    { "no-times",	no_argument,	NULL,			OP_SET_BOOL_FALSE },
    { "no-verbose",	no_argument,	&verbose,		0 },
    { "numeric-ids",	no_argument,	NULL,			OP_SET_BOOL_TRUE },
    { "omit-dir-times",	no_argument,	NULL,			'O' },
    { "omit-link-times", no_argument,	NULL,			'J' },
    { "one-file-system", no_argument,	NULL,			'x' },
    { "owner",		no_argument,	NULL,			OP_SET_BOOL_TRUE },
    { "perms",		no_argument,	NULL,			OP_SET_BOOL_TRUE },
    { "port",		required_argument, NULL,		OP_PORT },
    { "protocol",	required_argument, NULL,		OP_PROTOCOL },
    { "recursive",	no_argument,	NULL,			'r' },
    { "rsh",		required_argument, NULL,		'e' },
    { "rsync-path",	required_argument, NULL,		OP_RSYNCPATH },
    { "sender",		no_argument,	NULL,			OP_SET_BOOL_TRUE },
    { "server",		no_argument,	NULL,			OP_SET_BOOL_TRUE },
    { "size-only",	no_argument,	NULL,			OP_SET_BOOL_TRUE },
    { "specials",	no_argument,	NULL,			OP_SET_BOOL_TRUE },
    { "timeout",	required_argument, NULL,		OP_TIMEOUT },
    { "times",		no_argument,	NULL,			OP_SET_BOOL_TRUE },
    { "verbose",	no_argument,	NULL,			'v' },
    { "version",	no_argument,	NULL,			'V' },
    { "whole-file",	no_argument,	NULL,			'W' },
    { "no-whole-file",	no_argument,	NULL,			OP_SET_BOOL_FALSE },
    { "no-W",		no_argument,	NULL,			OP_SET_BOOL_FALSE },
    { "dirs",		no_argument,	NULL,			'd' },
    { NULL,		0,		NULL,			0 }
#if 0
    { "sync-file",	required_argument, NULL,		6 },
#endif
};

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-DF]\n"
	    "\t[--8-bit-output, -8]\n"
	    "\t[--address=sourceaddr]\n"
	    "\t[--archive, -a]\n"
	    "\t[--block-size=size, -B size]\n"
	    "\t[--compare-dest=dir]\n"
	    "\t[--contimeout=seconds]\n"
	    "\t[--cvs-exclude, -C]\n"
	    "\t[--del, --delete]\n"
	    "\t[--devices]\n"
	    "\t[--dirs, -d]\n"
	    "\t[--dry-run, -n]\n"
	    "\t[--exclude-from=file]\n"
	    "\t[--exclude=pattern]\n"
	    "\t[--filter=filter, -f filter]\n"
	    "\t[--group, -g]\n"
	    "\t[--ignore-times, -I]\n"
	    "\t[--include-from=file]\n"
	    "\t[--include]\n"
	    "\t[--ipv4, -4]\n"
	    "\t[--ipv6, -6]\n"
	    "\t[--links, -l]\n"
	    "\t[--max-size=size]\n"
	    "\t[--min-size=size]\n"
	    "\t[--no-devices]\n"
	    "\t[--no-group]\n"
	    "\t[--no-links]\n"
	    "\t[--no-motd]\n"
	    "\t[--no-omit-dir-times]\n"
	    "\t[--no-omit-link-times]\n"
	    "\t[--no-owner]\n"
	    "\t[--no-perms]\n"
	    "\t[--no-recursive]\n"
	    "\t[--no-specials]\n"
	    "\t[--no-times]\n"
	    "\t[--numeric-ids]\n"
	    "\t[--omit-dir-times, -O]\n"
	    "\t[--omit-link-times, -J]\n"
	    "\t[--one-file-system, -x]\n"
	    "\t[--owner, -o]\n"
	    "\t[--perms, -p]\n"
	    "\t[--port=portnumber]\n"
	    "\t[--protocol]\n"
	    "\t[--recursive, -r]\n"
	    "\t[--rsh=program, -e program]\n"
	    "\t[--rsync-path=program]\n"
	    "\t[--size-only]\n"
	    "\t[--specials]\n"
	    "\t[--timeout=seconds]\n"
	    "\t[--times, -t]\n"
	    "\t[--verbose, -v]\n"
	    "\t[--version, -V]\n"
	    "\tsource ... directory\n",
	    getprogname());
}

/*
 * Add a basedir to the list.
 */
static size_t
rsync_getopt_xxxdest(char *optarg, const char *name, size_t count)
{
	if (count >= MAX_BASEDIR)
		errx(ERR_SYNTAX, "--%s: too many directories", name);
	opts.basedir[count++] = optarg;
	return count;
}

/*
 * Parse options out of argv.
 *
 * Returns NULL on error or the client options struct on success.  If
 * returning NULL, the caller should call exit() after any cleanup,
 * using the passed-in exitcode as its exit value.
 */
static struct opts *
rsync_getopt(int argc, char *argv[], rsync_option_filter *filter,
    struct sess *sess, int *exitcode, int *whole_file)
{
	const char	*errstr; /* temporary error string */
	const char	*new_rule; /* filter rule */
	long long	 tmpint; /* temporary */
	size_t		 basedir_cnt = 0, /* number of base directories */
			 opts_F = 0, /* -F calls */
			 opts_no_dirs = 0; /* transitional */
	int		 c, /* getopt return */
			 rc, /* temporary */
			 lidx; /* getopt long index */
	bool		 cvs_excl = false; /* exclude CVS */

	(void)filter; /* TODO: currently unused */

	*exitcode = 0;

	while ((c = getopt_long(argc, argv, rsync_shopts, lopts, &lidx)) != -1) {
		switch (c) {
		case OP_SET_BOOL_TRUE:
			if (strcmp(lopts[lidx].name, "specials") == 0)
				opts.specials = true;
			else if (strcmp(lopts[lidx].name, "devices") == 0)
				opts.devices = true;
			else if (strcmp(lopts[lidx].name, "delete") == 0)
				opts.del = DMODE_BEFORE;
			else if (strcmp(lopts[lidx].name, "del") == 0)
				opts.del = DMODE_BEFORE;
			else if (strcmp(lopts[lidx].name, "size-only") == 0)
				opts.size_only = true;
			else if (strcmp(lopts[lidx].name, "numeric-ids") == 0)
				opts.numeric_ids = NIDS_FULL;
			else if (strcmp(lopts[lidx].name, "perms") == 0)
				opts.preserve_perms = true;
			else if (strcmp(lopts[lidx].name, "owner") == 0)
				opts.preserve_uids = true;
			else if (strcmp(lopts[lidx].name, "group") == 0)
				opts.preserve_gids = true;
			else if (strcmp(lopts[lidx].name, "links") == 0)
				opts.preserve_links = true;
			else if (strcmp(lopts[lidx].name, "times") == 0)
				opts.preserve_times = true;
			else if (strcmp(lopts[lidx].name, "sender") == 0)
				opts.sender = true;
			else if (strcmp(lopts[lidx].name, "server") == 0)
				opts.server = true;
			break;
		case OP_SET_BOOL_FALSE:
			if (strcmp(lopts[lidx].name, "no-O") == 0)
				opts.omit_dir_times = false;
			else if (strcmp(lopts[lidx].name, "no-omit-dir-times") == 0)
				opts.omit_dir_times = false;
			else if (strcmp(lopts[lidx].name, "no-J") == 0)
				opts.omit_link_times = false;
			else if (strcmp(lopts[lidx].name, "no-omit-link-times") == 0)
				opts.omit_link_times = false;
			else if (strcmp(lopts[lidx].name, "specials") == 0)
				opts.specials = false;
			else if (strcmp(lopts[lidx].name, "devices") == 0)
				opts.devices = false;
			else if (strcmp(lopts[lidx].name, "no-motd") == 0)
				opts.no_motd = false;
			else if (strcmp(lopts[lidx].name, "no-perms") == 0)
				opts.preserve_perms = false;
			else if (strcmp(lopts[lidx].name, "no-owner") == 0)
				opts.preserve_uids = false;
			else if (strcmp(lopts[lidx].name, "no-group") == 0)
				opts.preserve_gids = false;
			else if (strcmp(lopts[lidx].name, "no-links") == 0)
				opts.preserve_links = false;
			else if (strcmp(lopts[lidx].name, "no-times") == 0)
				opts.preserve_times = false;
			else if (strcmp(lopts[lidx].name, "no-recursive") == 0)
				opts.recursive = false;
			else if (strcmp(lopts[lidx].name, "no-whole-file") == 0)
				*whole_file = 0;
			else if (strcmp(lopts[lidx].name, "no-W") == 0)
				*whole_file = 0;
			break;
		case '4':
			opts.ipf = 4;           
			break;
		case '6':
			opts.ipf = 6;
			break;
		case '8':
			opts.bit8 = true;
			break;
                case 'B':
			/*
			 * The largest possible block size is fixed at 512 MB
			 * and must be >0.
			 */
			if (scan_scaled(optarg, &tmpint) == -1 ||
			    tmpint < 0 || tmpint > (512 << 20))
				errx(ERR_SYNTAX, "--block-size=%s: "
				    "invalid numeric value", optarg);
			opts.block_size = tmpint; 
			break;  
		case 'C':
			cvs_excl = true;
			break;
		case 'D':
			opts.devices = true;
			opts.specials = true;
			break;
		case 'F':
			new_rule = NULL;
			/*
			 * If -F is specified once, the filter added is
			 * a dir-merge; if twice, it's an exclusion.
			 * (More than that, the -F ignored.)
			 */
			switch (++opts_F) {
			case 1:
				new_rule = ": /.rsync-filter";
				break;  
			case 2:
				new_rule = "- .rsync-filter";
				break;
			default:
				break;  
			}
			if (new_rule == NULL)
				break;
			rc = parse_rule(new_rule, RULE_NONE, '\n');
			assert(rc == 0);
			break;
		case 'a':
			opts.recursive = true;
			opts.preserve_links = true;
			opts.preserve_perms = true;
			opts.preserve_times = true;
			opts.preserve_gids = true;
			opts.preserve_uids = true;
			opts.devices = true;
			opts.specials = true;
			break;
		case 'd':
			opts.dirs = DIRMODE_REQUESTED;
			break;
		case 'e':
			opts.ssh_prog = optarg;
			break;
		case 'f':
			if (parse_rule(optarg, RULE_NONE, '\n') == -1)
				errx(ERR_SYNTAX, "--filter=%s: syntax "
				    "error", optarg);
			break;
		case 'g':
			opts.preserve_gids = true;
			break;
		case 'I':
			opts.ignore_times = true;
			break;
		case 'J':
			opts.omit_link_times = true;
			break;
		case 'l':
			opts.preserve_links = true;
			break;
		case 'n':
			if (opts.dry_run == DRY_DISABLED)
				opts.dry_run = DRY_XFER;
			else if (opts.dry_run == DRY_XFER)
				opts.dry_run = DRY_FULL;
			break;
		case 'O':
			opts.omit_dir_times = true;
			break;
		case 'o':
			opts.preserve_uids = true;
			break;
		case 'p':
			opts.preserve_perms = true;
			break;
		case 'r':
			opts.recursive = true;
			break;
		case 't':
			opts.preserve_times = true;
			break;
		case 'v':
			verbose++;
			break;
		case 'V':
			fprintf(stderr, "openrsync: protocol version %u\n",
			    RSYNC_PROTOCOL);
			exit(0);
		case 'W':
			*whole_file = 1;
			break;
		case 'x':
			opts.one_file_system++;
			break;
		case 'z':
			opts.compress = true;
			break;
		case 0:
			/* Non-NULL flag values (e.g., --sender). */
			break;
#if 0
		case 6:
			opts.syncfile = optarg;
			break;
#endif
		case OP_ADDRESS:
			opts.address = optarg;
			break;
		case OP_CONTIMEOUT:
			poll_contimeout = strtonum(optarg, 0, 60 * 60,
			    &errstr);
			if (errstr != NULL)
				errx(ERR_SYNTAX, "--contimeout=%s: %s",
				    optarg, errstr);
			break;
		case OP_PORT:
			opts.port = optarg;
			break;
		case OP_RSYNCPATH:
			opts.rsync_path = optarg;
			break;
		case OP_PROTOCOL:
			if (strcmp(optarg, "27") != 0)
				errx(ERR_SYNTAX, "--protocol=%s: only "
				   "27 is currently supported", optarg);
			break;
		case OP_TIMEOUT:
			poll_timeout = strtonum(optarg, 0, 60 * 60,
			    &errstr);
			if (errstr != NULL)
				errx(ERR_SYNTAX, "--timeout=%s: %s",
				    optarg, errstr);
			break;
		case OP_EXCLUDE:
			if (parse_rule(optarg, RULE_EXCLUDE, '\0') == -1)
				errx(ERR_SYNTAX, "--exclude=%s: syntax "
				    "error", optarg);
			break;
		case OP_INCLUDE:
			if (parse_rule(optarg, RULE_INCLUDE, '\0') == -1)
				errx(ERR_SYNTAX, "--include=%s: syntax "
				    "error in include", optarg);
			break;
		case OP_EXCLUDE_FROM:
			parse_file_rule(optarg, RULE_EXCLUDE, '\n');
			break;
		case OP_INCLUDE_FROM:
			parse_file_rule(optarg, RULE_INCLUDE, '\n');
			break;
		case OP_COMP_DEST:
			if (opts.alt_base_mode != BASE_MODE_OFF &&
			    opts.alt_base_mode != BASE_MODE_COMPARE) {
				errx(ERR_SYNTAX, "--%s: conflicts "
				    "with %s", lopts[lidx].name,
				    alt_base_mode(opts.alt_base_mode));
			}
			opts.alt_base_mode = BASE_MODE_COMPARE;
			basedir_cnt = rsync_getopt_xxxdest(optarg,
			    lopts[lidx].name, basedir_cnt);
			break;
		case OP_COPY_DEST:
			if (opts.alt_base_mode != BASE_MODE_OFF &&
			    opts.alt_base_mode != BASE_MODE_COPY) {
				errx(ERR_SYNTAX, "option --%s conflicts with %s",
				    lopts[lidx].name,
				    alt_base_mode(opts.alt_base_mode));
			}
			opts.alt_base_mode = BASE_MODE_COPY;
			basedir_cnt = rsync_getopt_xxxdest(optarg,
			    lopts[lidx].name, basedir_cnt);
			break;
		case OP_LINK_DEST:
			if (opts.alt_base_mode !=0 &&
			    opts.alt_base_mode != BASE_MODE_LINK) {
				errx(ERR_SYNTAX, "option --%s conflicts with %s",
				    lopts[lidx].name,
				    alt_base_mode(opts.alt_base_mode));
			}
			opts.alt_base_mode = BASE_MODE_LINK;
			basedir_cnt = rsync_getopt_xxxdest(optarg,
			    lopts[lidx].name, basedir_cnt);
			break;
		case OP_MAX_SIZE:
			if (scan_scaled(optarg, &tmpint) == -1)
				errx(ERR_SYNTAX, "--max-size=%s: "
				    "invalid numeric value", optarg);
			opts.max_size = tmpint;
			break;
		case OP_MIN_SIZE:
			if (scan_scaled(optarg, &tmpint) == -1)
				errx(ERR_SYNTAX, "--min-size=%s: "
				    "invalid numeric value", optarg);
			opts.min_size = tmpint;
			break;
		case 'h':
			usage();
			return NULL;
		default:
			*exitcode = ERR_SYNTAX;
			usage();
			return NULL;
		}
	}

	if (opts.del > DMODE_NONE &&
	    !(opts.recursive || opts.dirs != DIRMODE_OFF))
		errx(ERR_SYNTAX, "--delete does not work without "
		    "--recursive or --dirs");

	if (opts.dirs && opts_no_dirs)
		ERRX1("Cannot use --dirs and --no-dirs at the same time");

	if (opts.recursive && opts.dirs == DIRMODE_OFF && !opts_no_dirs)
		opts.dirs = DIRMODE_IMPLIED;

        assert(opts.ipf == 0 || opts.ipf == 4 || opts.ipf == 6);

	if (opts.port == NULL)
		opts.port = (char *)"rsync";

	/* by default and for --contimeout=0 disable poll_contimeout */
	if (poll_contimeout == 0)
		poll_contimeout = -1;
	else
		poll_contimeout *= 1000;

	/* by default and for --timeout=0 disable poll_timeout */
	if (poll_timeout == 0)
		poll_timeout = -1;
	else
		poll_timeout *= 1000;

	if (!opts.server && cvs_excl) {
		rc = parse_rule("-C", RULE_NONE, '\n');
		assert(rc == 0);
		rc = parse_rule(":C", RULE_NONE, '\n');
		assert(rc == 0);

		/* Silence NDEBUG warnings. */
		(void)rc;
	}

	return &opts;
}

int
main(int argc, char *argv[])
{
	char 		 *msg, *ptr = NULL; /* temporary */
	pid_t		  child; /* return value of fork() */
	int		  fds[2], /* 0 is for parent, 1 for child */
			  sd = -1, /* socket for daemon */
			  c, /* temporary */
			  i, /* temporary */
			  rc, /* rsync_client/server() return */
			  rc2, /* child process return */
			  st, /* child process status */
			  whole_file = -1; /* whole_file status */
	struct sess	  sess;
	struct fargs	 *fargs;
	char		**args;

	/* 
	 * We cannot safely log to stdout until we are certain that
	 * we're the client (i.e., the server must enable multiplexing
	 * before logging to stdout).
	 */
	rsync_set_logfile(isatty(STDOUT_FILENO) ? stdout : stderr, NULL);

	/* Global pledge. */

	if (pledge("stdio unix rpath wpath cpath dpath inet fattr chown dns getpw proc exec unveil",
	    NULL) == -1)
		err(ERR_IPC, "pledge");

	opts.max_size = opts.min_size = -1;

	if (rsync_getopt(argc, argv, NULL, NULL, &c, &whole_file) == NULL)
		exit(c);

	argc -= optind;
	argv += optind;

	if (argc < 2) {
		usage();
		exit(ERR_SYNTAX);
	}

	/* Set whole-file only if explicitly specified. */

	opts.whole_file = whole_file > 0;

	/*
	 * This is what happens when we're started with the "hidden"
	 * --server option, which is invoked for the rsync on the remote
	 * host by the parent.
	 */

	if (opts.server)
		exit(rsync_server(&opts, (size_t)argc, argv));

	rsync_set_logfile(stdout, NULL);

	/*
	 * Now we know that we're the client on the local machine
	 * invoking rsync(1).
	 * At this point, we need to start the client and server
	 * initiation logic.
	 * The client is what we continue running on this host; the
	 * server is what we'll use to connect to the remote and
	 * invoke rsync with the --server option.
	 */

	fargs = fargs_parse(argc, argv, &opts);
	assert(fargs != NULL);

	/*
	 * For local transfers, enable whole_file by default if the user
	 * did not specifically ask for --no-whole-file.
	 */

	if (fargs->host == NULL && !fargs->remote && whole_file < 0)
		opts.whole_file = true;

	/*
	 * For implied --list-only mode, we set --dirs up early so that
	 * it can be inherited by the other paths.  We won't touch
	 * opts.list_only yet because we don't want to send a spurious
	 * --list-only to the reference rsync.
	 */

	if (fargs->sink == NULL) {
		assert(fargs->mode == FARGS_RECEIVER);
		opts.dirs = DIRMODE_REQUESTED;
	}

	/*
	 * If we're contacting an rsync:// daemon, then we don't need to
	 * fork, because we won't start a server ourselves.
	 * Route directly into the socket code, unless a remote shell
	 * has explicitly been specified.
	 */

	if (fargs->remote && opts.ssh_prog == NULL) {
		assert(fargs->mode == FARGS_RECEIVER);
		if ((c = rsync_connect(&opts, &sd, fargs)) == 0) {
			c = rsync_socket(&opts, sd, fargs);
			close(sd);
		}
		exit(c);
	}

	/* Drop the dns/inet possibility. */

	if (pledge("stdio unix rpath wpath cpath dpath fattr chown getpw proc exec unveil",
	    NULL) == -1)
		err(ERR_IPC, "pledge");

	/* Create a bidirectional socket and start our child. */

#if HAVE_SOCK_NONBLOCK
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, fds) == -1)
		err(ERR_IPC, "socketpair");
#else
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == -1)
		err(ERR_IPC, "socketpair");
	if (fcntl(fds[0], F_SETFL, fcntl(fds[0], F_GETFL, 0) | O_NONBLOCK) == -1)
		err(ERR_IPC, "fcntl");
	if (fcntl(fds[1], F_SETFL, fcntl(fds[1], F_GETFL, 0) | O_NONBLOCK) == -1)
		err(ERR_IPC, "fcntl");
#endif

	switch ((child = fork())) {
	case -1:
		err(ERR_IPC, "fork");
	case 0:
		close(fds[0]);
		if (pledge("stdio exec", NULL) == -1)
			err(ERR_IPC, "pledge");

		memset(&sess, 0, sizeof(struct sess));
		sess.opts = &opts;

		args = fargs_cmdline(&sess, fargs, NULL);

		if (verbose > 1) {
			msg = strdup("opening connection using:");
			for (i = 0; args[i] != NULL && msg != NULL; i++) {
				if (asprintf(&ptr, "%s %s", msg, args[i]) < 0)
					break;
				free(msg);
				msg = ptr;
			}
			LOG0("%s%s (%d args)", msg != NULL ? msg :
			    args[0], ptr ? "" : " ...", i);
			free(msg);
		}

		fflush(stdout);

		/* Make sure the child's stdin is from the sender. */

		if (dup2(fds[1], STDIN_FILENO) == -1)
			err(ERR_IPC, "dup2");
		if (dup2(fds[1], STDOUT_FILENO) == -1)
			err(ERR_IPC, "dup2");
		execvp(args[0], args);
		ERR("exec on '%s'", args[0]);
		_exit(ERR_IPC);
		/* NOTREACHED */
	default:
		if (fargs->sink == NULL) {
			assert(fargs->mode == FARGS_RECEIVER);
			fargs->sink = strdup(".");
			if (fargs->sink == NULL)
				errx(ERR_NOMEM, NULL);
		}

		close(fds[1]);
		if (!fargs->remote)
			rc = rsync_client(&opts, fds[0], fargs);
		else
			rc = rsync_socket(&opts, fds[0], fargs);
		break;
	}

	/* Reached only in parent process. */

	assert(child > 0);
	close(fds[0]);

	if (waitpid(child, &st, 0) == -1)
		err(ERR_WAITPID, "waitpid");

	/*
	 * If the child exited abnormally then use its exit status as our exit
	 * code.  Otherwise, use the return code from the fork parent operation.
	 */

	if (WIFEXITED(st) && WEXITSTATUS(st) != 0)
		WARNX1("child %d exited with status %d", child, WEXITSTATUS(st));
	else if (WIFSIGNALED(st))
		WARNX1("child %d terminated due to signal %d", child, WTERMSIG(st));

	if (WIFEXITED(st))
		rc2 = WEXITSTATUS(st);
	else if (WIFSIGNALED(st))
		rc2 = WTERMSIG(st) != SIGUSR2 ? ERR_TERMIMATED : 0;
	else
		rc2 = ERR_WAITPID;

	return MAX(rc, rc2);
}

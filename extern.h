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
#ifndef EXTERN_H
#define EXTERN_H

/*
 * This is the rsync protocol version that we support.
 * This is the oldest currently supported, but also the simplest.
 * One caveat is that we use an updated MD5 algorithm instead of the
 * stipulated MD4, but that can be overridden when talking with GNU
 * rsync clients and servers.
 * (This was changed in version 27, which is probably the next target
 * for protocol compatibility.)
 */
#define	RSYNC_PROTOCOL	(20)

/*
 * Maximum amount of data sent over the wire at once.
 */
#define MAX_CHUNK	(32 * 1024)

/*
 * The sender and receiver use a two-phase synchronisation process.
 * The first uses two-byte hashes; the second, 16-byte.
 * (The second must hold a full MD5 digest.)
 */
#define	CSUM_LENGTH_PHASE1 (2)
#define	CSUM_LENGTH_PHASE2 (16)

/*
 * Operating mode for a client or a server.
 * Sender means we synchronise local files with those from remote.
 * Receiver is the opposite.
 * This is relative to which host we're running on.
 */
enum	fmode {
	FARGS_LOCAL, /* FIXME: necessary? */
	FARGS_SENDER, 
	FARGS_RECEIVER
};

/*
 * File arguments given on the command line.
 * See struct opts.
 */
struct	fargs {
	char	  *host; /* hostname or NULL if FARGS_LOCAL */
	char	 **sources; /* transfer source */
	size_t	   sourcesz; /* number of sources */
	char	  *sink; /* transfer endpoint */
	enum fmode mode; /* mode of operation */
};

/*
 * The subset of stat(2) information that we need.
 * (There are some parts we don't use yet.)
 */
struct	flstat {
	mode_t		 mode; /* mode */
	uid_t		 uid; /* user */
	gid_t		 gid; /* group */
	off_t		 size; /* size */
	time_t		 mtime; /* modification */
};

/*
 * A list of files with their statistics.
 */
struct	flist {
	char		*path; /* full path relative to root */
	size_t		 pathlen; /* length of path */
	const char	*filename; /* just filename of path */
	size_t		 filenamelen; /* length of filename */
	struct flstat	 st; /* file information */
};

/*
 * Options passed into the command line.
 * See struct fargs.
 */
struct	opts {
	int	 sender; /* --sender */
	int	 server; /* --server */
	int	 recursive; /* -r */
	int	 verbose; /* -v */
	int	 dry_run; /* -n */
};

/*
 * An individual block description for a file.
 * See struct blkset.
 */
struct	blk {
	off_t		 offs; /* offset in file */
	size_t		 idx; /* block index */
	size_t		 len; /* bytes in block */
	uint32_t	 chksum_short; /* fast checksum */
	unsigned char	 chksum_long[CSUM_LENGTH_PHASE2]; /* slow checksum */
};

/*
 * When transferring file contents, we break the file down into blocks
 * and work with those.
 */
struct	blkset {
	off_t		 size; /* file size */
	size_t		 rem; /* terminal block length if non-zero */
	size_t		 len; /* block length */
	struct blk	*blks; /* all blocks */
	size_t		 blksz; /* number of blks */
};

/*
 * Values exchanged in an rsync session between client and server.
 */
struct	sess {
	int32_t		 seed; /* checksum seed */
	int32_t		 lver; /* local version */
	int32_t		 rver; /* remote version */
};

#define LOG1(_opts, _fmt, ...) \
	rsync_log((_opts), __FILE__, __LINE__, 0, (_fmt), ##__VA_ARGS__)
#define LOG2(_opts, _fmt, ...) \
	rsync_log((_opts), __FILE__, __LINE__, 1, (_fmt), ##__VA_ARGS__)
#define LOG3(_opts, _fmt, ...) \
	rsync_log((_opts), __FILE__, __LINE__, 2, (_fmt), ##__VA_ARGS__)
#define LOG4(_opts, _fmt, ...) \
	rsync_log((_opts), __FILE__, __LINE__, 3, (_fmt), ##__VA_ARGS__)
#define ERRX1(_opts, _fmt, ...) \
	rsync_errx1((_opts), __FILE__, __LINE__, (_fmt), ##__VA_ARGS__)
#define WARNX(_opts, _fmt, ...) \
	rsync_warnx((_opts), __FILE__, __LINE__, (_fmt), ##__VA_ARGS__)
#define WARN(_opts, _fmt, ...) \
	rsync_warn((_opts), 0, __FILE__, __LINE__, (_fmt), ##__VA_ARGS__)
#define WARN1(_opts, _fmt, ...) \
	rsync_warn((_opts), 1, __FILE__, __LINE__, (_fmt), ##__VA_ARGS__)
#define WARN2(_opts, _fmt, ...) \
	rsync_warn((_opts), 2, __FILE__, __LINE__, (_fmt), ##__VA_ARGS__)
#define ERR(_opts, _fmt, ...) \
	rsync_err((_opts), __FILE__, __LINE__, (_fmt), ##__VA_ARGS__)
#define ERRX(_opts, _fmt, ...) \
	rsync_errx((_opts), __FILE__, __LINE__, (_fmt), ##__VA_ARGS__)

__BEGIN_DECLS

void		  rsync_log(const struct opts *, 
			const char *, size_t, int, 
			const char *, ...)
			__attribute__((format(printf, 5, 6)));
void		  rsync_warnx1(const struct opts *, 
			const char *, size_t, const char *, ...)
			__attribute__((format(printf, 4, 5)));
void		  rsync_warn(const struct opts *, int,
			const char *, size_t, const char *, ...)
			__attribute__((format(printf, 5, 6)));
void		  rsync_warnx(const struct opts *, 
			const char *, size_t, const char *, ...)
			__attribute__((format(printf, 4, 5)));
void		  rsync_err(const struct opts *, 
			const char *, size_t, const char *, ...)
			__attribute__((format(printf, 4, 5)));
void		  rsync_errx(const struct opts *, 
			const char *, size_t, const char *, ...)
			__attribute__((format(printf, 4, 5)));
void		  rsync_errx1(const struct opts *, 
			const char *, size_t, const char *, ...)
			__attribute__((format(printf, 4, 5)));

void		  fargs_free(struct fargs *);
struct fargs	 *fargs_parse(const struct opts *, size_t, char *[]);

struct flist	 *flist_gen(const struct opts *, size_t, char **, size_t *);
void		  flist_free(struct flist *, size_t);
struct flist	 *flist_recv(const struct opts *, int, size_t *);
int		  flist_send(const struct opts *, 
			int, const struct flist *, size_t);

int		  io_read_buf(const struct opts *, int, void *, size_t);
int		  io_read_byte(const struct opts *, int, uint8_t *);
int		  io_read_int(const struct opts *, int, int32_t *);
int		  io_read_size(const struct opts *, int, size_t *);
int		  io_read_long(const struct opts *, int, int64_t *);
int		  io_write_buf(const struct opts *, 
			int, const void *, size_t);
int		  io_write_byte(const struct opts *, int, uint8_t);
int		  io_write_int(const struct opts *, int, int32_t);
int		  io_write_long(const struct opts *, int, int64_t);

void		  rsync_child(const struct opts *, int, size_t, char *[])
			__attribute__((noreturn));
int		  rsync_receiver(const struct opts *, 
			const struct sess *, int, int, const char *);
int		  rsync_sender(const struct opts *, const struct sess *, 
			int, int, size_t, char **);
int		  rsync_client(const struct opts *, int, size_t, char *[]);
int		  rsync_server(const struct opts *, size_t, char *[]);

struct blkset	 *blk_recv(const struct opts *, int, size_t, const char *);
int		  blk_recv_ack(const struct opts *, 
			int , const struct blkset *, int32_t);
int		  blk_match(const struct opts *, const struct sess *,
			int, const struct blkset *, const char *, size_t);
int		  blk_send(const struct opts *, int, size_t,
			const struct blkset *, const char *);
int		  blk_send_ack(const struct opts *, int, 
			const struct blkset *, size_t);
int		  blk_merge(const struct opts *, int, int, 
			const struct blkset *, int, const char *, 
			const void *, size_t);
void		  blkset_free(struct blkset *);

uint32_t	  hash_fast(const void *, size_t);
void		  hash_slow(const void *, size_t, 
			unsigned char *, const struct sess *);
void		  hash_file(const void *, off_t, unsigned char *);

int		  mkpath(const struct opts *, char *);

__END_DECLS

#endif /*!EXTERN_H*/

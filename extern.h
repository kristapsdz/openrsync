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
#ifndef EXTERN_H
#define EXTERN_H

#include "md4.h"
#include <fts.h> /* FTSENT */
#include <stdbool.h>
#include <stdio.h> /* FILE */
#include <time.h> /* struct timespec */

#if !HAVE_PLEDGE
# define pledge(x, y) (1)
#endif
#if !HAVE_UNVEIL
# define unveil(x, y) (1)
#endif

#if __APPLE__
# define st_atim st_atimespec
# define st_ctim st_ctimespec
# define st_mtim st_mtimespec
#endif

/*
 * Mirror the reference rsync here; they don't really entertain path
 * limitations lower than 4096.
 */

#if PATH_MAX <= 4096
# define BIGPATH_MAX	(4096 + 1024)
#else
# define BIGPATH_MAX	(PATH_MAX + 1024)
#endif

/*
 * Chunk large fmaps into 4MB pieces, arbitrarily
 */
#define	HASH_LARGE_CHUNK_SIZE (4 * 1024 * 1024)

/*
 * This is the rsync protocol version that we support.
 */
#define	RSYNC_PROTOCOL	(27)

/*
 * Itemise-changes flags.
 */
#define	IFLAG_ATIME		(1U << 0)
#define	IFLAG_CHECKSUM		(1U << 1)
#define	IFLAG_SIZE		(1U << 2)
#define	IFLAG_TIME		(1U << 3)
#define	IFLAG_PERMS		(1U << 4)
#define	IFLAG_OWNER		(1U << 5)
#define	IFLAG_GROUP		(1U << 6)
#define	IFLAG_ACL		(1U << 7)
#define	IFLAG_XATTR		(1U << 8)
#define	IFLAG_BASIS_FOLLOWS	(1U << 11)
#define	IFLAG_HLINK_FOLLOWS	(1U << 12)
#define	IFLAG_NEW		(1U << 13)
#define	IFLAG_LOCAL_CHANGE	(1U << 14)
#define	IFLAG_TRANSFER		(1U << 15)
/*
 * (Not for transmission...)
 */
#define	IFLAG_MISSING_DATA	(1U << 16)
#define	IFLAG_DELETED		(1U << 17) /* used by log_format() */
#define	IFLAG_HAD_BASIS		(1U << 18) /* had basis, used by sender_get_iflags() */

#define	SIGNIFICANT_IFLAGS	\
	(~(IFLAG_BASIS_FOLLOWS | IFLAG_HLINK_FOLLOWS | IFLAG_LOCAL_CHANGE))

/*
 * Maximum amount of file data sent over the wire at once.
 */
#define MAX_CHUNK	(32 * 1024)

/*
 * Maximum size of a compression chunk.  Saves 2 bytes to fit a 14 bit
 * count and compression flags.
 */
#define MAX_COMP_CHUNK  16383

/*
 * Decompression buffer size: zlib needs a bit of extra space in the
 * buffer.
 */
#define MAX_CHUNK_BUF   ((MAX_CHUNK)*1001/1000+16)

/*
 * This is the minimum size for a block of data not including those in
 * the remainder block.
 */
#define	BLOCK_SIZE_MIN  (700)

/*
 * Maximum number of base directories that can be used.
 */
#define MAX_BASEDIR	20

enum dirmode {
	DIRMODE_OFF = 0,	/* No --dirs */
	DIRMODE_IMPLIED,	/* Implied --dirs */
	DIRMODE_REQUESTED,	/* --dirs */
};

enum dryrun {
	DRY_DISABLED = 0,	/* full run */
	DRY_XFER,		/* xfer only */
	DRY_FULL,		/* full dry-run */
};

/*
 * The sender and receiver use a two-phase synchronisation process.
 * The first uses two-byte hashes; the second, 16-byte.
 * (The second must hold a full MD4 digest.)
 */
#define	CSUM_LENGTH_PHASE1 (2)
#define	CSUM_LENGTH_PHASE2 (16)

/*
 * Rsync error codes.
 */
#define ERR_SYNTAX	1
#define ERR_PROTOCOL	2
#define ERR_FILEGEN	3
#define ERR_SOCK_IO	10
#define ERR_FILE_IO	11
#define ERR_WIREPROTO	12
#define ERR_IPC		14	/* catchall for any kind of syscall error */
#define ERR_TERMIMATED	16
#define ERR_WAITPID	21
#define ERR_NOMEM	22

/*
 * Use this for --timeout.
 * All poll events will use it and catch time-outs.
 */
extern int poll_timeout;

/*
 * Use this for --contimeout.
 */
extern int poll_contimeout;

/*
 * Operating mode for a client or a server.
 * Sender means we synchronise local files with those from remote.
 * Receiver is the opposite.
 * This is relative to which host we're running on.
 */
enum	fmode {
	FARGS_SENDER,
	FARGS_RECEIVER
};

/*
 * FIXME: document
 */
#define	IOTAG_OFFSET	7

/*
 * A resizable buffer used for storing data.
 */
struct	iobuf {
	uint8_t	*buffer; /* the data buffer */
	size_t	 offset; /* position in buffer */
	size_t	 resid; /* amount read into buffer */
	size_t	 size; /* allocated size */
	bool	 eof; /* whether EOF has been seen */
};

/*
 * Codes used during multiplexing.
 */
enum	iotag {
	IT_DATA = 0,
	IT_ERROR_XFER,
	IT_INFO,
	IT_ERROR, // protocol 30+
	IT_WARNING, // protocol 30+
	IT_SUCCESS = 100,
	IT_DELETED,
	IT_NO_SEND,
};

/*
 * A buffer of fixed size, but filled with multiple attempts.  The
 * vstring is "complete" when the offset equals the size.
 */
struct	vstring {
	char		*vstring_buffer; /* binary contents */
	size_t		 vstring_offset; /* current size */
	size_t		 vstring_size; /* expected size */
};

/*
 * File arguments given on the command line.
 * See struct opts.
 */
struct	fargs {
	char		  *user; /* username or NULL if unspecified or local */
	char		  *host; /* hostname or NULL if local */
	char		 **sources; /* transfer source */
	size_t		   sourcesz; /* number of sources */
	char		  *sink; /* transfer endpoint */
	enum fmode	   mode; /* mode of operation */
	bool		   remote; /* uses rsync:// or :: for remote */
	const char	  *module; /* if rsync://, the module */
};

/*
 * The subset of stat(2) information that we need.
 * (There are some parts we don't use yet.)
 */
struct	flstat {
	unsigned int	 flags; /* see FLSTAT_xxx */
	mode_t		 mode;	/* mode */
	uid_t		 uid;	/* user */
	gid_t		 gid;	/* group */
	dev_t		 rdev;	/* device type */
	off_t		 size;	/* size */
	time_t		 mtime;	/* modification */
	int64_t		 device; /* device number, for hardlink detection */
	int64_t		 inode;  /* inode number, for hardlink detection */
	uint64_t	 nlink;  /* number of links, for hardlink detection */
#define	FLSTAT_TOP_DIR	 0x01	/* a top-level directory */
};

/*
 * Subset of stat(2) information from the original destination file that
 * we need to apply to backup files.
 */
struct	fldstat {
	mode_t		 mode;	 /* mode */
	struct timespec	 atime;	 /* access */
	struct timespec	 mtime;	 /* modification */
	uid_t		 uid;	 /* user */
	gid_t		 gid;	 /* group */
};

/*
 * Used for logging messages.
 */
enum log_type {
	LT_CLIENT,
	LT_INFO,
	LT_LOG,
	LT_WARNING,
	LT_ERROR,
};

/*
 * Delete modes.  Currently only supports DMODE_BEFORE or no deletion.
 */
enum	delmode {
	DMODE_NONE = 0,
	DMODE_BEFORE,
	DMODE_DURING, /* FIXME: NOT SUPPORTED */
	DMODE_DELAY, /* FIXME: NOT SUPPORTED */
};

/* --numeric-ids mode */
enum	nidsmode {
	NIDS_OFF = 0,	/* no numeric IDs */
	NIDS_STEALTH,	/* numeric IDs, client side is unaware */
	NIDS_FULL,	/* numeric IDs, both sides know */
};

enum 	altbasemode {
	BASE_MODE_OFF = 0,
	BASE_MODE_COMPARE = 1,
	BASE_MODE_COPY = 2,
	BASE_MODE_LINK = 3,
};

/*
 * XXX: meaning?
 */
enum name_basis {
	BASIS_DIR_LOW = 0,
	BASIS_DIR_HIGH = 0x7F,
	BASIS_NORMAL,
	BASIS_PARTIAL_DIR,
	BASIS_BACKUP,
	BASIS_FUZZY,
};

/*
 * The root of a file list.
 */
struct	froot {
	char	*rootpath; /* path */
	size_t	 refcount; /* references */
	int	 rootfd; /* root dirfd */
};

struct froot *froot_acquire(struct froot *);
void froot_release(struct froot *);

/*
 * A list of files with their statistics.
 */
struct	flist {
	char		*path; /* path relative to root */
	const char	*wpath; /* "working" path for receiver */
	struct flstat	 st; /* file information */
	char		*link; /* symlink target or NULL */
	unsigned char    md[MD4_DIGEST_LENGTH]; /* MD4 hash for --checksum */
	int32_t		 iflags; /* itemise flags */
	enum name_basis	 basis; /* name basis */
	enum fmode	 fmode; /* sender/receiver */
	union {
		struct {
			struct froot *froot;
		};
		struct {
			struct fldstat dstat; /* orig dest file info */
			int flstate; /* flagged for redo or complete? */
			int sendidx; /* sender index */
		};
	};
};

/*
 * Flags for "flstate" of struct flist.
 */
#define	FLIST_COMPLETE		0x01	/* finished */
#define	FLIST_REDO		0x02	/* finished, but go again */
#define	FLIST_SUCCESS		0x04	/* finished and in place */
#define	FLIST_FAILED		0x08	/* failed */
#define	FLIST_SUCCESS_ACKED	0x10	/* sent success message */
#define	FLIST_NEED_HLINK	0x20	/* needs to be hardlinked */
#define	FLIST_SKIPPED		0x40	/* file should be skipped */
#define	FLIST_SKIP_METADATA	0x80	/* file metadata should be skipped */
#define	FLIST_DONE_MASK		(FLIST_SUCCESS | FLIST_REDO | FLIST_FAILED)

/*
 * Holds many struct flist and takes care of memory management.
 */
struct fl {
	struct flist	*flp; /* list of flists */
	size_t		 sz;   /* actual entries */
	size_t		 max;  /* allocated size */
	struct sess	*sess;	/* associated session */
};

void		 fl_init(struct sess *, struct fl *);
void		 fl_pop(struct fl *);
struct flist	*fl_new(struct fl *);

/*
 * Options passed into the command line.
 * See struct fargs.
 */
struct	opts {
	off_t		 max_size;		/* --max-size */
	off_t		 min_size;		/* --min-size */
	char		*backup_suffix;		/* --suffix */
	char		*address;		/* --address */
	char		*basedir[MAX_BASEDIR];	/* --compare/copy/link-dest */
	char		*port;			/* --port */
	char		*rsync_path;		/* --rsync-path */
	char		*ssh_prog;		/* --rsh or -e */
	enum altbasemode alt_base_mode;		/* --compare/copy/link-dest */
	enum delmode	 del;			/* --delete */
	enum dirmode	 dirs;			/* -d --dirs */
	enum dryrun	 dry_run;		/* -n */
	enum nidsmode	 numeric_ids;		/* --numeric-ids */
	int		 compression_level;	/* --compress-level */
	long		 block_size;		/* -B */
	size_t		 one_file_system;	/* -x */
	char		 ipf;			/* 0 (unspec), 4 (IPV4), 6 (IPV6) */
	bool		 backup;		/* -b */
	bool		 bit8;			/* -8 */
	bool		 checksum;		/* -c */
	bool		 compress;		/* -z */
	bool		 del_excl;		/* --delete-excluded */
	bool		 devices;		/* --devices */
	bool		 ignore_times;		/* -I */
	bool		 no_motd;		/* --no-motd */
	bool		 omit_dir_times;	/* -O */
	bool		 omit_link_times;	/* -J */
	bool		 partial;		/* --partial */
	bool		 preserve_gids;		/* -g */
	bool		 preserve_links;	/* -l */
	bool		 preserve_perms;	/* -p */
	bool		 preserve_times;	/* -t */
	bool		 preserve_uids;		/* -u */
	bool		 recursive;		/* -r */
	bool		 sender;		/* --sender */
	bool		 server;		/* --server */
	bool		 size_only;		/* --size-only */
	bool		 specials;		/* --specials */
	bool		 update;		/* -u */
	bool		 whole_file;		/* --whole-file */
#if 0
	char		*syncfile;		/* --sync-file */
#endif
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

enum	blkstatst {
	BLKSTAT_NONE = 0,
	BLKSTAT_NEXT,
	BLKSTAT_DATA,
	BLKSTAT_TOK,
	BLKSTAT_HASH,
	BLKSTAT_DONE,
	BLKSTAT_PHASE,
	BLKSTAT_FLUSH,
};

/*
 * Information for the sender updating receiver blocks reentrantly.
 */
struct	blkstat {
	off_t		 offs; /* position in sender file */
	off_t		 total; /* total amount processed */
	off_t		 dirty; /* total amount sent */
	size_t		 hint; /* optimisation: next probable match */
	struct fmap	*map; /* mapped file or NULL otherwise */
	size_t		 mapsz; /* TODO: remove (fmap_size()) */
	int		 fd; /* descriptor girding the map */
	enum blkstatst	 curst; /* FSM for sending file blocks */
	off_t		 curpos; /* sending: position in file to send */
	off_t		 curlen; /* sending: length of send */
	int32_t		 curtok; /* sending: next matching token or zero */
	struct blktab	*blktab; /* hashtable of blocks */
	uint32_t	 s1; /* partial sum for computing fast hash */
	uint32_t	 s2; /* partial sum for computing fast hash */
	MD4_CTX		 ctx; /* context for hash_file */
	bool		 error; /* is there an error on the send? */
};

/*
 * When transferring file contents, we break the file down into blocks
 * and work with those.
 */
struct	blkset {
	off_t		 size; /* file size */
	size_t		 rem; /* terminal block length if non-zero */
	size_t		 len; /* block length */
	size_t		 csum; /* checksum length */
	struct blk	*blks; /* all blocks */
	size_t		 blksz; /* number of blks */
};

/* TODO */
enum	send_dl_state {
	SDL_META = 0,
	SDL_IFLAGS,
	SDL_BLOCKS,
	SDL_DONE,
};

/*
 * Context for the role (sender/receiver).  The role may embed this into
 * their own context struct.
 */
struct	role {
	bool		 append; /* append mode active (TODO) */
	int		 client; /* socket for the client */

	/*
	 * We basically track two different forms of phase: the metadata
	 * phase, and the transfer phase.  The metadata phase may be
	 * advanced from the transfer phase, as we'll immediately move
	 * on to checking for or processing redo entries when the first
	 * phase's file requests are done.
	 *
	 * Each role has its own way of tracking these, so we just have
	 * them drop a pointer here to avoid having to keep things in
	 * sync.  `append` above will be reset as the transfer phase
	 * progresses, so parts dealing with block metadata should check
	 * `phase` *and* `append` to determine if they need to
	 * send/receive block checksums, and anything part of the data
	 * transfer process should just be checking `append`.
	 */
	const size_t	*phase; /* metadata phase */
};

/*
 * Values required during a communication session.
 */
struct	sess {
	const struct opts *opts; /* system options */
	size_t		   sender_flsz; /* sender's flist size */
	enum fmode	   mode; /* sender or receiver */
	int32_t		   seed; /* checksum seed */
	int32_t		   lver; /* local version */
	bool		   lreceiver; /* Receiver is local */
	int32_t		   protocol; /* negotiated protocol version */
	int32_t		   rver; /* remote version */
	uint64_t	   total_read; /* non-logging wire/reads */
	uint64_t	   total_size; /* total file size */
	uint64_t	   total_write; /* non-logging wire/writes */
	int		   mplex_reads; /* multiplexing reads? */
	size_t		   mplex_read_remain; /* remaining bytes */
	int		   mplex_writes; /* multiplexing writes? */
	struct role	  *role; /* role context */
	char		  *token_buf; /* used for protocol token processing */
	size_t		   token_bufsz; /* used for protocol token processing */
	char		  *token_dbuf; /* decompression buffer */
	size_t		   token_dbufsz; /* size of token_dbuf */
	char		  *token_cbuf; /* decompression buffer */
	size_t		   token_cbufsz; /* size of token_dbuf */
	void		 **wbufp; /* senders's output buffer ptr */
	size_t		  *wbufszp; /* senders's output buffer length */
	size_t		  *wbufmaxp; /* senders's output buffer size */
};

#define TOKEN_END               0x00    /* end of sequence */
#define TOKEN_LONG              0x20    /* Token is 32-bits */
#define TOKEN_LONG_RUN          0x21    /* Token is 32-bits and has 16 bit run count */
#define TOKEN_DEFLATED          0x40    /* Data is deflated */
#define TOKEN_RELATIVE          0x80    /* Token number is relative */
#define TOKEN_RUN_RELATIVE      0xc0    /* Run count is 16-bit */
        
#define TOKEN_MAX_DATA          MAX_COMP_CHUNK  /* reserve 2 bytes for flags */
#define TOKEN_MAX_BUF           (TOKEN_MAX_DATA + 2)

enum    zlib_state {
	COMPRESS_INIT = 0,
	COMPRESS_READY,
	COMPRESS_SEQUENCE,
	COMPRESS_RUN,
	COMPRESS_DONE,
};

/*
 * Combination of name and numeric id for groups and users.
 */
struct	ident {
	int32_t	 id; /* the gid_t or uid_t */
	int32_t	 mapped; /* if receiving, the mapped gid */
	char	*name; /* resolved name */
};

typedef struct arglist arglist;
struct arglist {
	char	**list;
	u_int	num;
	u_int	nalloc;
};

void		 addargs(arglist *, const char *, ...)
		   __attribute__((format(printf, 2, 3)));
const char	*getarg(const arglist *, size_t);
void		 freeargs(arglist *);

struct	download;
struct	upload;

extern int verbose;

#define TMPDIR_FD       (p->rootfd)
#define IS_TMPDIR       (false)

#define MINIMUM(a, b) (((a) < (b)) ? (a) : (b))

#define LOG0(_fmt, ...) \
	rsync_log( -1, (_fmt), ##__VA_ARGS__)
#define LOG1(_fmt, ...) \
	rsync_log( 0, (_fmt), ##__VA_ARGS__)
#define LOG2(_fmt, ...) \
	rsync_log( 1, (_fmt), ##__VA_ARGS__)
#define LOG3(_fmt, ...) \
	rsync_log( 2, (_fmt), ##__VA_ARGS__)
#define LOG4(_fmt, ...) \
	rsync_log( 3, (_fmt), ##__VA_ARGS__)
#define ERRX1(_fmt, ...) \
	rsync_errx1( (_fmt), ##__VA_ARGS__)
#define WARNX(_fmt, ...) \
	rsync_warnx( (_fmt), ##__VA_ARGS__)
#define WARNX1(_fmt, ...) \
	rsync_warnx1( (_fmt), ##__VA_ARGS__)
#define WARN(_fmt, ...) \
	rsync_warn(0,  (_fmt), ##__VA_ARGS__)
#define WARN1(_fmt, ...) \
	rsync_warn(1,  (_fmt), ##__VA_ARGS__)
#define WARN2(_fmt, ...) \
	rsync_warn(2,  (_fmt), ##__VA_ARGS__)

#if defined(__sun) && defined(ERR)
# undef ERR
#endif
#define ERR(_fmt, ...) \
	rsync_err( (_fmt), ##__VA_ARGS__)
#define ERRX(_fmt, ...) \
	rsync_errx( (_fmt), ##__VA_ARGS__)

void	rsync_log(int, const char *, ...)
			__attribute__((format(printf, 2, 3)));
void	rsync_warn(int, const char *, ...)
			__attribute__((format(printf, 2, 3)));
void	rsync_warnx(const char *, ...)
			__attribute__((format(printf, 1, 2)));
void	rsync_warnx1(const char *, ...)
			__attribute__((format(printf, 1, 2)));
void	rsync_err(const char *, ...)
			__attribute__((format(printf, 1, 2)));
void	rsync_errx(const char *, ...)
			__attribute__((format(printf, 1, 2)));
void	rsync_errx1(const char *, ...)
			__attribute__((format(printf, 1, 2)));

bool	flist_add_del(struct sess *, const char *, size_t, struct flist **,
	    size_t *, size_t *, const struct stat *);
void	flist_del(const struct sess *, int, const struct flist *, size_t);
int	flist_dir_cmp(const void *, const void *);
bool	flist_gen(struct sess *, size_t, char **, struct fl *);
void	flist_free(struct flist *, size_t);
bool	flist_recv(struct sess *, int, int, struct flist **, size_t *);
bool	flist_send(struct sess *, int, int, const struct flist *, size_t);
bool	flist_gen_dels(struct sess *, const char *, struct flist **, size_t *,
	    const struct flist *, size_t);
bool	flist_fts_check(struct sess *, FTSENT *, enum fmode);

struct fmap	*fmap_open(const char *, int, size_t);
bool		 fmap_access_valid(const struct fmap *, off_t, size_t);
const void	*fmap_data(const struct fmap *, off_t, size_t);
size_t		 fmap_size(const struct fmap *);
void		 fmap_close(struct fmap *);
bool		 fmap_trap(const struct fmap *);
void		 fmap_untrap(const struct fmap *);

const char	 *alt_base_mode(enum altbasemode);
char		**fargs_cmdline(struct sess *, const struct fargs *, size_t *);

bool	io_read_buf(struct sess *, int, void *, size_t);
bool	io_read_byte(struct sess *, int, uint8_t *);
int	io_read_check(const struct sess *, int);
bool	io_read_close(struct sess *, int);
bool	io_read_flush(struct sess *, int);
bool	io_read_int(struct sess *, int, int32_t *);
bool	io_read_uint(struct sess *, int, uint32_t *);
bool	io_read_long(struct sess *, int, int64_t *);
bool	io_read_size(struct sess *, int, size_t *);
bool	io_read_ulong(struct sess *, int, uint64_t *);
bool	io_read_vstring(struct sess *, int, char **);
bool	io_write_blocking(int, const void *, size_t);
bool	io_write_buf(struct sess *, int, const void *, size_t);
bool	io_write_buf_tagged_safe(struct sess *, int, const void *, size_t, enum iotag);
bool	io_write_byte(struct sess *, int, uint8_t);
bool	io_write_int(struct sess *, int, int32_t);
bool	io_write_uint(struct sess *, int, uint32_t);
bool	io_write_int_tagged(struct sess *, int, int32_t, enum iotag);
bool	io_write_line(struct sess *, int, const char *);
bool	io_write_long(struct sess *, int, int64_t);
bool	io_write_ulong(struct sess *, int, uint64_t);

bool	io_lowbuffer_alloc(struct sess *, void **, size_t *, size_t *, size_t);
bool	io_lowbuffer_alloc_safe(struct sess *, void **, size_t *, size_t *, size_t);
void	io_lowbuffer_int(struct sess *, void *, size_t *, size_t, int32_t);
void	io_lowbuffer_byte(struct sess *, void *, size_t *, size_t, int8_t);
void	io_lowbuffer_buf(struct sess *, void *, size_t *, size_t, const void *,
	    size_t);

void	io_buffer_int(void *, size_t *, size_t, int32_t);
void	io_buffer_buf(void *, size_t *, size_t, const void *, size_t);

void	io_unbuffer_int(const void *, size_t *, size_t, int32_t *);
bool	io_unbuffer_size(const void *, size_t *, size_t, size_t *);
void	io_unbuffer_buf(const void *, size_t *, size_t, void *, size_t);

bool	iobuf_alloc(const struct sess *, struct iobuf *, size_t);
size_t	iobuf_get_readsz(const struct iobuf *);
bool	iobuf_seen_eof(const struct iobuf *);
void	iobuf_eof(struct iobuf *);
bool	iobuf_fill(struct sess *, struct iobuf *, int);
int32_t	iobuf_peek_int(const struct iobuf *);
void	iobuf_read_buf(struct iobuf *, void *, size_t);
void	iobuf_read_int(struct iobuf *, int32_t *);
bool	iobuf_read_size(struct iobuf *, size_t *);
void	iobuf_read_byte(struct iobuf *, uint8_t *);
int	iobuf_read_vstring(struct iobuf *, struct vstring *);

bool	rsync_receiver(struct sess *, int, int, const char *);
bool	rsync_sender(struct sess *, int, int, size_t, char **);
int	rsync_client(const struct opts *, int, const struct fargs *);
int	rsync_connect(const struct opts *, int *, const struct fargs *);
int	rsync_socket(const struct opts *, int, const struct fargs *);
int	rsync_server(const struct opts *, size_t, char *[]);
int	rsync_downloader(struct download *, struct sess *, int *);
bool	rsync_set_metadata_at(const struct sess *, bool, int,
	    const struct flist *, const char *);
void	rsync_uploader_next_phase(struct upload *, struct sess *, int);
void	rsync_uploader_ack_complete(struct upload *, struct sess *, int);
int	rsync_uploader(struct upload *, struct sess *, int, int *, int *);
bool	rsync_uploader_tail(struct upload *, struct sess *);

bool		 download_needs_redo(const struct download *);
const char	*download_partial_filepath(const struct flist *);
struct download	*download_alloc(struct sess *, int, struct flist *,
		    size_t, int);
void		 download_free(struct sess *, struct download *);
struct upload	*upload_alloc(const char *, int, int, size_t,
		    struct flist *, size_t, size_t, mode_t);
void		upload_free(struct upload *);

struct blktab	*blkhash_alloc(void);
bool		 blkhash_set(struct blktab *, const struct blkset *);
void		 blkhash_free(struct blktab *);

struct blkset	*blk_recv(struct sess *, int, struct iobuf *, const char *,
		    struct blkset *, size_t *, enum send_dl_state *);
void		 blk_recv_ack(char [16], const struct blkset *, int32_t);
bool		 blk_match(struct sess *, const struct blkset *,
		    const char *, struct blkstat *);
bool		 blk_send_ack(struct sess *, int, struct blkset *);

uint32_t	 hash_fast(const void *, size_t);
void		 hash_slow(const void *, size_t, unsigned char *,
		    const struct sess *);
bool		 hash_file_by_path(int, const char *, size_t, unsigned char *);

void		 hash_file_start(MD4_CTX *, const struct sess *);
void		 hash_file_buf(MD4_CTX *, const void *, size_t);
void		 hash_file_final(MD4_CTX *, unsigned char *);
bool		 hash_fmap(const char *, const struct fmap *, size_t,
		    unsigned char *, const struct sess *);

void		 copy_file(int, const char *, const struct flist *);
bool   	 	 move_file(int, const char *, int, const char *, bool, bool);
bool		 backup_file(int, const char *, int, const char *, bool,
		    const struct fldstat *);

int		 mkpath(char *, mode_t);
int		 mkpathat(int fd, char *, mode_t);

int		 mkstempat(int, char *);
char		*mkstemplinkat(char*, int, char *);
char		*mkstempfifoat(int, char *);
char		*mkstempnodat(int, char *, mode_t, dev_t);
char		*mkstempsock(const char *, char *);
int		 mktemplate(char **, const char *, bool, bool);

int		 rmatch(const char *, const char *, int);

char		*symlink_read(const char *, size_t);
char		*symlinkat_read(int, const char *, size_t);

bool		 sess_stats_send(struct sess *, int);
bool		 sess_stats_recv(struct sess *, int);
void		 sess_cleanup(struct sess *);

bool		 idents_add(int, struct ident **, size_t *, int32_t);
void		 idents_assign_gid(struct sess *, struct flist *, size_t,
		    const struct ident *, size_t);
void		 idents_assign_uid(struct sess *, struct flist *, size_t,
		    const struct ident *, size_t);
void		 idents_free(struct ident *, size_t);
bool		 idents_recv(struct sess *, int, struct ident **, size_t *);
void		 idents_remap(struct sess *, int, struct ident *, size_t);
bool		 idents_send(struct sess *, int, const struct ident *, size_t);

struct sbuf;

void		 our_strmode(mode_t, char *);
void		 rsync_set_logfile(FILE *, struct sess *);
bool		 log_item_impl(enum log_type, const struct sess *, const struct flist *);
bool		 log_item(const struct sess *, const struct flist *);
bool		 print_7_or_8_bit(const struct sess *, const char *,
		    const char *, struct sbuf *)
		    __attribute__((format(printf, 2, 0)));

#endif /*!EXTERN_H*/

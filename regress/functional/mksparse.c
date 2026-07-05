/*
 * Copyright (C) 2025 Klara, Inc.
 * Copyright (c) Kristaps Dzonsons <kristaps@bsd.lv>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#if !defined(__OpenBSD__) && !defined(__NetBSD__)

#ifdef __linux__
#define _GNU_SOURCE
#endif
#include <sys/mman.h>
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * On Linux, force 64-bit off_t.
 */
#ifdef __linux__
# define	off_t	loff_t
# undef OFF_MAX
# define	OFF_MAX	LLONG_MAX
#endif

/*
 * If OFF_MAX is not defined (e.g., OpenBSD) assume it's 64 bit.
 */
#ifndef OFF_MAX
# define	OFF_MAX	LLONG_MAX
#endif

#ifndef __printflike
/* FreeBSD's sys/cdefs.h */
#define	__printflike(fmtarg, firstvararg) \
	__attribute__((__format__ (__printf__, fmtarg, firstvararg)))
#endif

struct cblk {
	struct cblk	*next;
	size_t		 nblks;
	bool		 datablk;
};

static struct cblk *head, *last;
static size_t totalblks;

static void __printflike(1, 2)
warnx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");
}

static void __printflike(1, 2)
error(const char *fmt, ...)
{
	va_list ap;
	int serrno = errno;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, ": %s\n", strerror(serrno));
	exit(1);
}

static void __printflike(1, 2)
errorx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");
	exit(1);
}

static void
usage(const char *prog)
{

	/*
	 * In the first form, we sparsify an existing file if -r is not
	 * specified, or we report on its holes if -r is specified.
	 *
	 * In the second form, we create a new file with a layout created by
	 * a series of -d and -h flags.  Both flags may be specified multiple
	 * times, and the file will be constructed in the order specified.
	 * e.g., -d 4 -h 4 -d 8 will create a file with four data blocks, then
	 * 4 hole blocks, finally followed by another eight data blocks.  This
	 * functionality does depend on the filesystem reporting a proper
	 * minimum hole size.  The -n flag tells us to avoid actually creating
	 * holes; write zeroes instead.
	 */
	fprintf(stderr,
	    "usage: %s [-r] <file>\n"
	    "       %s -c [-d datablks] [-h holeblks] [-n] <file>\n",
	    prog, prog);
	exit(1);
}

static void
punch_hole(int fd, off_t offset, size_t holesz, size_t nholes)
{
	size_t maxholes;

	/* Loop in case the multiplication would overflow. */
	maxholes = OFF_MAX / holesz;
	while (nholes != 0) {
		size_t curholes;
		off_t rangesz = 0;

		if ((curholes = nholes) > maxholes)
			curholes = maxholes;
		rangesz = curholes * holesz;
		nholes -= curholes;
		warnx("Punching %zu holes at %zu -> %zu",
		    curholes, (size_t)offset, (size_t)(offset + rangesz));

#ifdef __FreeBSD__
		struct spacectl_range range;

		range.r_offset = offset;
		range.r_len = rangesz;
		if (fspacectl(fd, SPACECTL_DEALLOC, &range, 0, NULL) == -1)
			error("fspacectl");
#elif defined(__linux__)
		if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, offset, rangesz) == -1)
			error("fallocate");
#elif defined(__APPLE__)
		struct fpunchhole fph = { 0 };

		fph.fp_offset = offset;
		fph.fp_length = rangesz;
		if (fcntl(fd, F_PUNCHHOLE, &fph) == -1)
			error("fcntl");
#else
	/*
	 * Perhaps we should consider creating a temp file that we lseek() past
	 * holes in for systems that we can't punch holes on; that kind of
	 * changes our operating mode significantly.
	 */
#error Do not know how to punch holes on this system.
#endif

		offset += rangesz;
	}
}

static void
report_hole(off_t start, off_t end)
{

	printf("[%zu,%zu]\n", (size_t)start, (size_t)end - 1);
}

static int
lssparse(int fd, off_t filesz)
{
	off_t doff = 0, hoff;

	while ((hoff = lseek(fd, doff, SEEK_HOLE)) != filesz) {
		if (hoff == -1) {
			/*
			 * If we didn't even get off the ground, I guess it may
			 * be a special case of the filesystem not supporting
			 * holes.
			 */
			if (doff == 0)
				break;
			error("lseek");
		}
		doff = lseek(fd, hoff, SEEK_DATA);
		if (doff == -1) {
			/* Hole to EOF */
			report_hole(hoff, filesz);
			break;
		}

		report_hole(hoff, doff);
	}

	return (0);
}

static int
sparsify(int fd, off_t filesz, size_t holesz)
{
	char *fmap, *zerobuf;
	off_t holestart = 0;
	size_t nholes = 0;

	zerobuf = malloc(holesz);
	if (zerobuf == NULL)
		error("malloc");

	fmap = mmap(NULL, filesz, PROT_READ, MAP_SHARED, fd, 0);
	if (fmap == MAP_FAILED)
		error("mmap");

	/*
	 * In our most primitive operation, we just punch holes that we can find
	 * in a file that was created without them.
	 */
	memset(zerobuf, 0, holesz);
	for (off_t off = 0; off < filesz; off += holesz) {
		if (filesz - off < holesz)
			break;	/* Can't be a hole with less than holesz left. */
		if (memcmp(&fmap[off], zerobuf, holesz) != 0) {
			if (nholes != 0) {
				punch_hole(fd, holestart, holesz, nholes);
				holestart = 0;
				nholes = 0;
			}

			continue;
		}

		if (nholes == 0)
			holestart = off;
		nholes++;
	}

	if (nholes != 0) {
		punch_hole(fd, holestart, holesz, nholes);
		nholes = 0;
	}

	munmap(fmap, filesz);
	free(zerobuf);

	if (fsync(fd) == -1)
		error("fsync");

	close(fd);

	return (0);
}

static void
add_blocks(bool datablk, const char *strblks)
{
	struct cblk *cblk;
	unsigned long nblks;
	char *endp;

	errno = 0;
	nblks = strtoul(strblks, &endp, 10);
	if (errno != 0)
		error("strtoul: %s", strblks);
	else if (*endp != '\0')
		errorx("strtoul: %s: malformed number", strblks);

	cblk = calloc(1, sizeof(*cblk));
	if (cblk == NULL)
		error("malloc");

	cblk->datablk = datablk;
	cblk->nblks = nblks;
	if (head == NULL) {
		head = last = cblk;
	} else {
		last->next = cblk;
		last = cblk;
	}

	totalblks += nblks;
}

static void
dowrite(int fd, char *buf, size_t holesz)
{
	ssize_t writesz;

	while (holesz > 0) {
		writesz = write(fd, buf, holesz);
		if (writesz == -1) {
			if (errno == EINTR)
				continue;
			error("write");
		}

		holesz -= writesz;
		buf += writesz;
	}
}

static int
newsparse(int fd, size_t holesz, bool seekholes)
{
	struct cblk *cblk = head;
	char *buf;

	/* Pre-size the file */
	if (ftruncate(fd, totalblks * holesz) == -1)
		error("ftruncate");

	buf = calloc(1, holesz);
	if (buf == NULL)
		error("calloc");

	assert(cblk != NULL);
	while (cblk != NULL) {
		/*
		 * Flip our buffer as appropriate.  If we're not writing out
		 * holes as zeroes, we'll effectively only fill it once with
		 * a series of 'A's because the zero-buffer won't be needed.
		 */
		if (cblk->datablk && buf[0] != 'A')
			memset(buf, 'A', holesz);
		else if (!cblk->datablk && !seekholes && buf[0] != '\0')
			memset(buf, 0, holesz);

		if (!cblk->datablk && seekholes) {
			/*
			 * We won't worry about this multiplication overflowing,
			 * we shouldn't be creating *that* large of files for
			 * any of our tests.
			 */
			if (lseek(fd, cblk->nblks * holesz, SEEK_CUR) == -1)
				error("lseek");
		} else {
			/*
			 * buf is accurate for the type of block we're writing,
			 * just write it out.
			 */
			while (cblk->nblks != 0) {
				dowrite(fd, buf, holesz);
				cblk->nblks--;
			}
		}

		cblk = cblk->next;
	}

	free(buf);
	return (0);
}

static size_t
holesz_env(void)
{
	const char *envp;
	char *endp;
	unsigned long holesz;

	envp = getenv("HOLESIZE");
	if (envp == NULL || *envp == '\0')
		return (0);

	errno = 0;
	holesz = strtoul(envp, &endp, 10);
	if (errno != 0)
		error("strtoul: %s", envp);
	else if (*endp != '\0')
		errorx("strtoul: %s: malformed", envp);

	return (holesz);
}

int
main(int argc, char *argv[])
{
	struct stat sb;
	const char *prog = argv[0];
	const char *file;
	size_t holesz = 0;
	int ch, fd, oflags;
	enum { MODE_MKSPARSE, MODE_CREAT, MODE_REPORT } reqmode = MODE_MKSPARSE;
	bool seekholes = true;

	while ((ch = getopt(argc, argv, "cd:h:nr")) != -1) {
		switch (ch) {
		case 'c':
			reqmode = MODE_CREAT;
			break;
		case 'd':
		case 'h':
			add_blocks(ch == 'd', optarg);
			break;
		case 'n':
			seekholes = false;
			break;
		case 'r':
			reqmode = MODE_REPORT;
			break;
		default:
			usage(prog);
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		usage(prog);
	} else if (reqmode != MODE_CREAT && head != NULL) {
		warnx("error: -d/-h not valid except in -c mode");
		usage(prog);
	} else if (reqmode == MODE_CREAT && totalblks == 0) {
		warnx("error: must have at least one -d or -h spec for -c mode");
		usage(prog);
	}

	if (reqmode == MODE_REPORT)
		oflags = O_RDONLY;
	else
		oflags = O_RDWR;
	if (reqmode == MODE_CREAT)
		oflags |= O_CREAT | O_TRUNC;

	file = argv[0];
	fd = open(file, oflags, 0644);
	if (fd == -1)
		error("open");

	if (fstat(fd, &sb) == -1)
		error("fstat");

	/*
	 * Some filesystems may provide the wrong _PC_MIN_HOLE_SIZE, so we
	 * provide an escape hatch via a HOLESIZE env var in case the caller
	 * knows this to be the case.
	 */
	holesz = holesz_env();
	if (holesz != 0)
		goto perform;
#ifdef _PC_MIN_HOLE_SIZE
	/*
	 * Not all systems have _PC_MIN_HOLE_SIZE, so we'll start there.  If
	 * that fails, we'll try to guess based on the reported block size.
	 *
	 * Some filesystems may also report a smaller minimum hole size because
	 * it's complicated.  Files on ZFS, for instance, can have holes in the
	 * neighborhood of the _PC_MIN_HOLE_SIZE that will later disappear if
	 * non-zero data shows up within the same blksize segment of the file.
	 * Additionally, it won't *complain* if you try to punch a hole that's
	 * smaller than the block size, but it may not actually be able to punch
	 * that hole if the block contains other data.  We'll use the larger of
	 * the minimum hole size and the block size to be safe.
	 */
	holesz = fpathconf(fd, _PC_MIN_HOLE_SIZE);
	if (holesz == -1)
		error("fpathconf");
	else if (holesz == 0)
		errorx("filesystem does not report hole support");
#endif
	if (sb.st_blksize > holesz)
		holesz = sb.st_blksize;

perform:
	warnx("Hole size %zu will be used", holesz);
	assert(holesz != 0);
	switch (reqmode) {
	case MODE_CREAT:
		return (newsparse(fd, holesz, seekholes));
	case MODE_REPORT:
		return (lssparse(fd, sb.st_size));
	case MODE_MKSPARSE:
	default:
		return (sparsify(fd, sb.st_size, holesz));
	}
}

#else

int
main(void)
{
	return 1;
}

#endif

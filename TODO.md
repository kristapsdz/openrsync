This is a list of possible work projects within openrsync, rated by difficulty.

First, let's get porting out of the way.
As noted many times before, porting-to-compile is trivially easy, and
also insufficient: any port **must** have system-specific security
features in place.
Remember that rsync has specific modes to be run as root, and
effectively dumps arbitrary network data into your file system.
On [OpenBSD](https://www.openbsd.org),
[unveil(2)](https://man.openbsd.org/unveil.2) and
[pledge(2)](https://man.openbsd.org/pledge.2) take care of these
security concerns.
All operating systems have similar facilities, but these require
delicate programming.
See
[Porting](https://github.com/kristapsdz/openrsync/blob/master/README.md#porting)
for more information.

This list does not include adding support for features (e.g., **-u** and
so on).

- Easy: add a hashtable to `blk_find()` in 
  [blocks.c](https://github.com/kristapsdz/openrsync/blob/master/blocks.c)
  for quickly looking up fast-hash matches.

- Easy: add a hashtable to `flist_del()` in 
  [flist.c](https://github.com/kristapsdz/openrsync/blob/master/flist.c)
  for quick removal of existing files.
  Alternatively, hash the entire file list and do it in-band during the
  file search in `flist_gen_local()`.

- Easy: keep track of rsync-mandated upload/download statistics in
  `struct sess` and properly report those in `sess_stats_send()`,
  [session.c](https://github.com/kristapsdz/openrsync/blob/master/session.c).

- Easy: print more statistics, such as transfer times and rates.

- Medium: have the log messages when multiplex writing (server mode) is
  enabled by flushed out through the multiplex channel.
  Right now, they're emitted on `stderr` just like with the client.

- Medium: porting the security precautions
  ([unveil(2)](https://man.openbsd.org/unveil.2),
  [pledge(2)](https://man.openbsd.org/pledge.2)) to
  [FreeBSD](https://www.freebsd.org)'s
  [Capsicum](https://wiki.freebsd.org/Capsicum).
  Without this in place, you're exposing your file-system to whatever is
  coming down over the wire.

- Hard: the same, but for Linux.

Above all, `grep FIXME *.c *.h` and start from there.

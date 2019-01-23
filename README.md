This is a clean-room implementation of [rsync](https://rsync.samba.org/)
with a BSD (ISC) license.  It is designed to be compatible with a modern
rsync (3.1.3 is used for testing).  It currently compiles and runs only
on [OpenBSD](https://www.openbsd.org).

*This project is still very new and very fast-moving.*

It's not ready for wide-spread testing.  Or even narrow-spread beyond
getting all of the bits to work.  It's not ready for strong attention.
Or really any attention but by careful programming.

Many have asked about portability.  The system is moving a bit too fast
for porting right now, but I was able to copy over
[oconfigure](https://github.com/kristapsdz/oconfigure), add `config.h`
as requirement, and mask the OpenBSD-specific functions on both Linux
and FreeBSD without any problems.

The acutal problem, however, is security in matching OpenBSD's
[pledge](https://man.openbsd.org/pledge.2) and
[unveil](https://man.openbsd.org/unveil.2).  This is partly possible
with FreeBSD's capsicum, but Linux is a mess.

See
[rsync.5](https://github.com/kristapsdz/openrsync/blob/master/rsync.5)
and
[rsyncd.5](https://github.com/kristapsdz/openrsync/blob/master/rsyncd.5)
for protocol details or utility documentation in
[openrsync.1](https://github.com/kristapsdz/openrsync/blob/master/openrsync.1).

This repository is a read-only mirror of a private CVS repository.  I
use it for issues and pull requests.  **Please do not make feature
requests**: I will simply close out the issue.

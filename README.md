# introduction

This is a clean-room implementation of [rsync](https://rsync.samba.org/)
with a BSD (ISC) license.  It is compatible with a modern rsync (3.1.3
is used for testing), but accepts only a subset of rsync's command-line
arguments.

*This project is still very new and very fast-moving.*

The canonical documentation for openrsync is its manual pages.
See
[rsync.5](https://github.com/kristapsdz/openrsync/blob/master/rsync.5)
and
[rsyncd.5](https://github.com/kristapsdz/openrsync/blob/master/rsyncd.5)
for protocol details or utility documentation in
[openrsync.1](https://github.com/kristapsdz/openrsync/blob/master/openrsync.1).

This repository is a read-only mirror of a private CVS repository.  I
use it for issues and pull requests.  **Please do not make feature
requests**: I will simply close out the issue.

# architecture

Each openrsync session is divided into a *server* and *client* run-time.

The client openrsync is executed by the user.
The server openrsync is executed on behalf of the client on a remote
host.
The latter may be invoked on-demand over
[ssh(1)](https://man.openbsd.org/ssh.1) or as a standalone network
daemon.
If executed over [ssh(1)](https://man.openbsd.org/ssh.1), the server is
distinguished from the client with the `--server` flag.

Once the client or server openrsync starts, it examines the command-line
arguments to determine whether it's in *receiver* or *sender* mode.
The receiver is the destination for files; the sender is the origin.
There is always one receiver and one sender.

The server is explicitly instructed that it is a sender, otherwise it is
a receiver.
The client implicitly determines its status by looking at the files
passed on the command line for whether they are local or remote.

```
openrsync path/to/source host:destination
openrsync host:source path/to/destination
```

In the first example, the client is the sender: it *sends* data from
itself to the server.
In the second, the opposite is true in that it *receives* data.

The client's command-line files may have any of the following host
specifications that determine locality.

- local: *../path/to/source ../another*
- remote server: *host:path/to/source :path/to/another*
- remote daemon: *rsync://host/module/path ::another*

Host specifications must be consistent: sources must all be local or all
be remote on the same host.  Both may not be remote.  (**Aside**: it's
technically possible to do this.  I'm not sure why the GPL rsync is
limited to one or the other.)

If the source or destination is on a remote server, the client then
[fork(2)](https://man.openbsd.org/fork.2)s and starts the server
openrsync on the remote host over
[ssh(1)](https://man.openbsd.org/ssh.1).
The client and the server subsequently communicate over
[socketpair(2)](https://man.openbsd.org/socketpair.2) pipes.
If on a remote daemon, the client does *not* fork, but instead connects
to the standalone server with a network
[socket(2)](https://man.openbsd.org/socket.2).

Once the client and server begin, they start to negotiate the transfer
of files over the connected socket.
The protocol used is specified in
[rsync.5](https://github.com/kristapsdz/openrsync/blob/master/rsync.5).
For daemon connections, the
[rsyncd.5](https://github.com/kristapsdz/openrsync/blob/master/rsyncd.5)
protocol is also used for handshaking.

# portability

Many have asked about portability.  The system is moving a bit too fast
for porting right now, but I was able to copy over
[oconfigure](https://github.com/kristapsdz/oconfigure), add `config.h`
as requirement, and mask the OpenBSD-specific functions on both Linux
and FreeBSD without any problems.

The actual problem, however, is security in matching OpenBSD's
[pledge](https://man.openbsd.org/pledge.2) and
[unveil](https://man.openbsd.org/unveil.2).  This is partly possible
with FreeBSD's capsicum, but Linux is a mess.

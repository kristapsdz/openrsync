# Introduction

This is a clean-room implementation of [rsync](https://rsync.samba.org/)
with a BSD (ISC) license.  It is compatible with a modern rsync (3.1.3
is used for testing), but accepts only a subset of rsync's command-line
arguments.

*This project is still very new and very fast-moving.*

At this time, openrsync runs only on [OpenBSD](https://www.openbsd.org).
See the [Portability](#Portability) section for details.

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

# Architecture

Each openrsync session is divided into a *server* and *client* service.

The client openrsync is executed by the user.
The server openrsync is executed on a remote host.
The latter may be invoked on-demand over
[ssh(1)](https://man.openbsd.org/ssh.1) or as a persistent network
daemon.
If executed over [ssh(1)](https://man.openbsd.org/ssh.1), the server
openrsync is distinguished from a client with the **--server** flag.

Once the client or server openrsync starts, it examines the command-line
arguments to determine whether it's in *receiver* or *sender* mode.
(The daemon is sent the command-line arguments in a protocol-specific
way.)
The receiver is the destination for files; the sender is the origin.
There is always one receiver and one sender.

The server is explicitly instructed that it is a sender with the
**--sender** command-line flag, otherwise it is a receiver.
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

Locality detection and routing to client and server run-times are
handled in
[main.c](https://github.com/kristapsdz/openrsync/blob/master/main.c).
The client for a server is implemented in
[client.c](https://github.com/kristapsdz/openrsync/blob/master/client.c)
and the server in
[server.c](https://github.com/kristapsdz/openrsync/blob/master/server.c).
The client for a network daemon is in
[socket.c](https://github.com/kristapsdz/openrsync/blob/master/socket.c).
Invocation of the remote server openrsync is managed in
[child.c](https://github.com/kristapsdz/openrsync/blob/master/child.c).

Once the client and server begin, they start to negotiate the transfer
of files over the connected socket.
The protocol used is specified in
[rsync.5](https://github.com/kristapsdz/openrsync/blob/master/rsync.5).
For daemon connections, the
[rsyncd.5](https://github.com/kristapsdz/openrsync/blob/master/rsyncd.5)
protocol is also used for handshaking.

The receiver side is managed in
[receiver.c](https://github.com/kristapsdz/openrsync/blob/master/receiver.c)
and the sender in
[sender.c](https://github.com/kristapsdz/openrsync/blob/master/sender.c).

# Security

Besides the usual defensive programming, openrsync makes significant use
of OpenBSD's native security features.

The system operations available to executing code are limited by
[pledge(2)](https://man.openbsd.org/pledge.2).
The pledges given depend upon the operating mode.
For example, the receiver needs write access to the disc---but only when
not in dry-run mode (**-n**).
The daemon client needs DNS and network access, but only to a point.
[pledge(2)](https://man.openbsd.org/pledge.2) allows available resources
to be limited over the course of operation.

The second tool is [unveil(2)](https://man.openbsd.org/unveil.2), which
limits access to the file-system.
At this time, the receiver has its file-system limited to only the
receiving directory.
This protects against rogue attempts to "break out" of the destination.
It's an attractive alternative to
[chroot(2)](https://man.openbsd.org/chroot.2) because it doesn't require
root permissions to execute.

# Portability

Many have asked about portability.
The system is moving a bit too fast for porting right now, but I was
able to copy over
[oconfigure](https://github.com/kristapsdz/oconfigure), add `config.h`
as requirement, and mask the OpenBSD-specific functions on both Linux
and FreeBSD without any problems.

The actual work of porting, however, is matching the security features
provided by OpenBSD's [pledge](https://man.openbsd.org/pledge.2) and
[unveil](https://man.openbsd.org/unveil.2).
These are **critical** elements to the functionality of the system.
Without them, your system accepts arbitrary data from the public
network.

This is possible (I think?) with FreeBSD's
[Capsicum](https://man.freebsd.org/capsicum(4), but Linux's security
facilities are a mess, and will take an expert hand to properly secure.

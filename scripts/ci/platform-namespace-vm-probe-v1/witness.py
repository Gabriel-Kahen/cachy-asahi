# SPDX-License-Identifier: MIT
"""One guest-local packet; credentials are supplied by the kernel to the outer observer."""
import os
import socket
import struct
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C

PACKET_BYTES = 12288
CREDENTIAL_BYTES = struct.calcsize('iII')


def channel():
    sender, receiver = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        C.need(sender.fileno() == 3, 'fresh guest credential socket must own FD3; never replace an unknown FD')
        receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        receiver.setblocking(False)
        return sender, receiver
    except BaseException:
        sender.close()
        receiver.close()
        raise


def send(context, nonce, release):
    raw = C.encoded(dict(schema=1, nonce=nonce, release=release, context=context))
    C.need(len(raw) <= PACKET_BYTES, 'finite raw inner context packet')
    with socket.socket(fileno=3) as endpoint:
        C.need(endpoint.family == socket.AF_UNIX and endpoint.type == socket.SOCK_SEQPACKET,
               'only intentional inherited guest-local credential FD')
        # No explicit ancillary credentials: SO_PASSCRED attaches actual sending-task credentials.
        C.need(endpoint.send(raw, socket.MSG_DONTWAIT) == len(raw), 'whole single inner context packet')


def close_rights(ancillary):
    for level, kind, raw in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            for (fd,) in struct.iter_unpack('i', raw[:len(raw) // 4 * 4]):
                os.close(fd)


def receive(receiver):
    raw, ancillary, flags, _ = receiver.recvmsg(PACKET_BYTES + 1, socket.CMSG_SPACE(CREDENTIAL_BYTES))
    close_rights(ancillary)  # Reject and retire any unexpected transferred descriptors before any guard raises.
    C.need(raw and len(raw) <= PACKET_BYTES and flags & ~socket.MSG_EOR == 0,
           'one complete bounded credential packet without data/control truncation')
    C.need(len(ancillary) == 1 and ancillary[0][:2] == (socket.SOL_SOCKET, socket.SCM_CREDENTIALS) and
           len(ancillary[0][2]) == CREDENTIAL_BYTES, 'exactly one kernel SCM_CREDENTIALS record')
    pid, uid, gid = struct.unpack('iII', ancillary[0][2])
    payload = C.decode(raw)
    C.need(type(payload) is dict and C.encoded(payload) == raw, 'canonical raw inner context envelope')
    try:
        extra, control, _, _ = receiver.recvmsg(PACKET_BYTES + 1, socket.CMSG_SPACE(CREDENTIAL_BYTES))
        close_rights(control)
        C.need(not extra and not control, 'extra inner context packet refused')
    except BlockingIOError:
        pass
    return dict(schema=1, transport='AF_UNIX_SEQPACKET_SCM_CREDENTIALS', payload=payload, packet=C.pin(raw),
                credentials=dict(pid=pid, uid=uid, gid=gid), records=1, flags=flags,
                observer=dict(uid=os.getuid(), euid=os.geteuid(), gid=os.getgid(), egid=os.getegid(),
                              user_namespace=os.readlink('/proc/self/ns/user'),
                              pid_namespace=os.readlink('/proc/self/ns/pid')))

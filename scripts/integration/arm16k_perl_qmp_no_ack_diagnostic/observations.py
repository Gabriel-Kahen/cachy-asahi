# SPDX-License-Identifier: MIT
"""Read-only, bounded public observations; never acceptance or transport progress."""
import fcntl
import select
import socket
import struct


def transport_observation(peer):
    """No receive, send, SO_ERROR read, serial drain, wait or process probe."""
    result = dict(status='UNAVAILABLE', VM_acceptance=None, Root_acceptance=None)
    try:
        stream = peer.stream
        if stream.fileno() != peer.fd:
            return result
        readable, writable, exceptional = select.select([stream], [stream], [stream], 0)
        result.update(status='SAME_FD_SOCKET_QUEUES_ONLY', readable=bool(readable),
                      writable=bool(writable), exceptional=bool(exceptional),
                      input_queued_bytes=struct.unpack('i', fcntl.ioctl(stream, 0x541B, struct.pack('i', 0)))[0],
                      output_kernel_accounted_bytes=struct.unpack('i', fcntl.ioctl(stream, 0x5411, struct.pack('i', 0)))[0],
                      receive_buffer_bytes=stream.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF),
                      send_buffer_bytes=stream.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))
        # AF_UNIX output accounting can include skb overhead. It is not an exact
        # application-byte delivery count and cannot prove QEMU parsed anything.
        if not all(type(result[n]) is int and 0 <= result[n] <= 2**31 - 1 for n in
                   ('input_queued_bytes', 'output_kernel_accounted_bytes', 'receive_buffer_bytes', 'send_buffer_bytes')):
            return dict(status='UNAVAILABLE', VM_acceptance=None, Root_acceptance=None)
    except (OSError, ValueError, TypeError, OverflowError):
        return dict(status='UNAVAILABLE', VM_acceptance=None, Root_acceptance=None)
    return result


def retirement_journal(K, out, retired_name, phase, report, observe):
    """Preserve before/after failure observations; absence never becomes receipt."""
    if phase not in ('BEFORE_FORCED_FALLBACK', 'AFTER_OWNED_CLEANUP'):
        return
    try:
        rows = report.setdefault('retirement_observation_journal', [])
        if type(rows) is not list or len(rows) >= 2 or any(row.get('phase') == phase for row in rows):
            return
        rows.append(dict(phase=phase, observation=observe(K, out, retired_name),
                         VM_acceptance=None, Root_acceptance=None))
    except Exception:
        # Observation failure cannot mask or waive the existing HOLD/fallback.
        return

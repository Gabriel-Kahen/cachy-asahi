# SPDX-License-Identifier: MIT
"""Stable PID ownership and bounded retirement of Welcome's non-child terminal."""
import os
from pathlib import Path
import select
import signal
import time


def identity(pid,proc=Path('/proc')):
    root=proc/str(pid);status=dict(line.split(':',1) for line in (root/'status').read_text().splitlines() if ':' in line)
    values=(root/'stat').read_text().rsplit(')',1)[1].split()
    return dict(pid=pid,uid=[int(v) for v in status['Uid'].split()],starttime=int(values[19]),
                executable=os.readlink(root/'exe'))


class ObservedTerminal:
    def __init__(self,pid):
        self.fd=None
        try:
            before=identity(pid)
            if before['uid']!=[23001]*4 or before['executable']!='/usr/bin/alacritty':raise ValueError('Welcome-launched terminal identity differs')
            self.fd=os.pidfd_open(pid)
            if identity(pid)!=before:raise ValueError('terminal PID changed during pidfd acquisition')
            self.proof=before;self.poller=select.poll();self.poller.register(self.fd,select.POLLIN)
        except BaseException:
            if self.fd is not None:os.close(self.fd);self.fd=None
            raise

    def exited(self):return bool(self.poller.poll(0))
    def healthy(self):
        if self.exited() or identity(self.proof['pid'])!=self.proof:raise ValueError('Welcome-launched terminal exited/changed')

    def wait(self,seconds):
        until=time.monotonic()+seconds
        while not self.exited():
            if time.monotonic()>=until:raise ValueError('Welcome-launched terminal retirement deadline')
            time.sleep(.1)

    def close(self):
        if self.fd is None:return
        try:
            if not self.exited():
                signal.pidfd_send_signal(self.fd,signal.SIGTERM);self.wait(3)
        except BaseException:
            if not self.exited():signal.pidfd_send_signal(self.fd,signal.SIGKILL);self.wait(3)
            raise
        finally:os.close(self.fd);self.fd=None

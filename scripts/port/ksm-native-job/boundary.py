# SPDX-License-Identifier: MIT
"""Extend the held KSM Docker identity boundary with the finite job supervisor."""
import os
from pathlib import Path
import re
import stat
import subprocess


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def cli_capture():
    path = Path('/usr/bin/docker')
    need(path == path.resolve(), 'canonical-docker-cli-required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == 0 and
             not before.st_mode & 0o022 and before.st_mode & 0o111 and
             0 < before.st_size <= 128 * 1024**2, 'root-owned-docker-cli-required')
        data = bytearray()
        while chunk := os.read(fd, min(65536, before.st_size - len(data) + 1)):
            data.extend(chunk)
            need(len(data) <= before.st_size, 'docker-cli-byte-bound')
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(len(data) == before.st_size and data[:4] == b'\x7fELF' and
             all(getattr(before, field) == getattr(after, field) for field in fields), 'docker-cli-capture-drift')
        return bytes(data)
    finally:
        os.close(fd)


def create(stage, runtime, runner, cli_sha256, *, daemon=None):
    """Keep held file/UID/socket/daemon checks; supervise exact sealed bytes."""
    endpoint = 'unix:///run/docker.sock'
    socket = Path('/run/docker.sock')
    need(socket == socket.resolve(), 'canonical-docker-socket-required')
    info = socket.lstat()
    need(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o002,
         'rootful-docker-socket-required')
    serial = [0]
    class Bound(stage.Docker):
        cleanup_mode = False

        def reconcile(self):
            if stage.base.CANCELLED:
                runtime.mark_cancelled()
            if not self.cleanup_mode:
                runtime.check_cancelled()

        def raw(self, argv, **options):
            need(argv[:2] == stage.base.docker_command(self.endpoint), 'unbound-docker-command')
            need(set(options) <= {'timeout', 'limit'}, 'unapproved-docker-runtime-options')
            self.check_files()
            self.reconcile()
            serial[0] += 1
            try:
                result = runner.run([self.executable, *argv[1:]], timeout=options.get('timeout', 30),
                                    limit=options.get('limit', 8 * 1024**2),
                                    log=None if self.cleanup_mode else 'docker-' + str(serial[0]) + '.log',
                                    pass_fds=(self.exec_fd,), cleanup=self.cleanup_mode)
                return result.returncode, result.stdout
            finally:
                with runtime.defer_signals():
                    self.check_files()
                self.reconcile()

        def bounded(self, argv, **options):
            # Keep the held per-operation identity checks without its independent
            # signal handler state, which could hide cancellation from this job.
            self.reconcile(); self.identity()
            try:
                return self.raw(argv, **options)
            finally:
                with runtime.defer_signals(): self.identity()
                self.reconcile()

        def call(self, argv, timeout=30):
            code, data = self.bounded(argv, timeout=timeout, limit=131072 if self.cleanup_mode else 8 * 1024**2)
            return subprocess.CompletedProcess(argv, code, data, b'')

    bound = Bound(endpoint, daemon or 'bootstrap-identity', cli_sha256, info.st_dev, info.st_ino)
    if daemon is None:
        code, data = bound.raw(stage.base.docker_command(endpoint, 'info', '--format', '{{.ID}}'),
                               timeout=30, limit=131072)
        need(code == 0, 'daemon-identity-query-failed')
        daemon = data.decode('ascii').strip()
        need(re.fullmatch(r'[A-Za-z0-9:-]{8,128}', daemon), 'daemon-identity-schema')
        bound.expected = daemon
    bound.identity()
    bound.runner = runner
    return bound

# SPDX-License-Identifier: MIT
"""Model the portable host binding under a process and socket fence."""

import hashlib
import os
from pathlib import Path
from runpy import run_path
import stat
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
S = run_path(str(HERE / "site.py"))
C = S["C"]
sys.addaudithook(S["fence"])


class DockerBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory(prefix="qtcore-docker-")
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name).resolve()
        self.client = root / "reviewed-client"
        self.socket = root / "custom-rootless.sock"
        raw = b"synthetic client bytes, never executed\n"
        self.client.write_bytes(raw)
        self.client.chmod(0o700)
        os.mknod(self.socket, stat.S_IFSOCK | 0o600)
        self.size = len(raw)
        self.sha = hashlib.sha256(raw).hexdigest()

    def seal(self):
        return C.seal_docker(self.client, self.socket, self.size, self.sha)

    def test_configured_paths_are_used_without_invoking_docker(self):
        binding = self.seal()
        self.assertEqual(binding["uid"], os.getuid())
        self.assertEqual(binding["socket"]["identity"], C.docker_identity(self.socket.lstat()))
        host = S["Client"]({"docker": binding})
        self.assertEqual(host.argv(("info",)), [str(self.client), "--host", "unix://" + str(self.socket), "info"])
        changed = binding | {"uid": 8341}
        changed["client"] = binding["client"] | {"identity": binding["client"]["identity"] | {"uid": 0}}
        changed["socket"] = binding["socket"] | {"identity": binding["socket"]["identity"] | {"uid": 8341}}
        self.assertEqual(C.validate_docker(changed), changed)
        with self.assertRaisesRegex(ValueError, "ordinary rootless host user"):
            C.check_docker(changed)

    def test_nonlocal_or_aliased_endpoint_refuses(self):
        binding = self.seal()
        for endpoint in ("tcp://localhost:2375", "unix:///var/run/docker.sock"):
            stale = binding | {"socket": binding["socket"] | {"endpoint": endpoint}}
            with self.assertRaisesRegex(ValueError, "owned rootless Unix endpoint"):
                C.validate_docker(stale)
        alias = self.socket.with_suffix(".alias")
        alias.symlink_to(self.socket)
        with self.assertRaisesRegex(ValueError, "Canonical ordinary absolute path"):
            C.seal_docker(self.client, alias, self.size, self.sha)

    def test_client_changed_or_not_executable_refuses(self):
        self.client.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "Pinned executable"):
            self.seal()
        self.client.chmod(0o700)
        with self.assertRaisesRegex(ValueError, "Changed pinned bytes"):
            C.seal_docker(self.client, self.socket, self.size, "0" * 64)
        binding = self.seal()
        host = S["Client"]({"docker": binding})
        self.client.write_bytes(b"!" * self.size)
        with self.assertRaisesRegex(ValueError, "Docker CLI changed"):
            host.argv(("info",))

    def test_socket_replacement_fails_even_when_path_mode_and_uid_match(self):
        binding = self.seal()
        host = S["Client"]({"docker": binding})
        self.socket.rename(self.socket.with_suffix(".old"))
        os.mknod(self.socket, stat.S_IFSOCK | 0o600)
        with self.assertRaisesRegex(ValueError, "Docker executable or socket identity changed"):
            host.argv(("info",))

    def test_handoff_checks_importer_pins_without_opening_the_host_endpoint(self):
        binding = self.seal()
        source = {name: dict(bytes=1, sha256=C.PORTABLE_HASHES.get(name, "1" * 64), mode=0o444)
                  for name in sorted(C.SOURCE_FILES)}
        handoff = dict(kind=C.HANDOFF_KIND, authority=None, scope=C.SCOPE, actor_image=C.IMAGE,
                       plan=dict(bytes=1, sha256="1" * 64), source=source,
                       source_tree_sha256=C.P.sha(C.T.encoded(source)), prior_closures={"q3": None, "r4": None},
                       docker=binding, portable_commit=C.PORTABLE_COMMIT)
        path = self.client.parent / C.HANDOFF_LEAF
        raw = C.T.encoded(handoff)
        path.write_bytes(raw)
        with patch.object(C, "check_docker", side_effect=AssertionError("Actor reader touched host endpoint")):
            self.assertEqual(C.load_handoff(path, C.P.sha(raw)), handoff)
        source[next(iter(C.PORTABLE_HASHES))]["sha256"] = "0" * 64
        handoff["source_tree_sha256"] = C.P.sha(C.T.encoded(source))
        raw = C.T.encoded(handoff)
        path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "Exact unissued local QtCore handoff"):
            C.load_handoff(path, C.P.sha(raw))


if __name__ == "__main__":
    unittest.main(verbosity=2)

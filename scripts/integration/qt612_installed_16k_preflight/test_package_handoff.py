# SPDX-License-Identifier: MIT
"""Exercise the installed handoff with inert archive and package receipts."""

from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

H = SimpleNamespace(**run_path(str(Path(__file__).with_name("package_handoff.py"))))
C = H.C


class Handoff(unittest.TestCase):
    def test_requires_one_original_attempt_and_its_archive_and_fsck(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            archive = root / H.ARCHIVE_NAME
            archive.write_bytes(b"inert archive")
            archive_pin = C.pin(archive.read_bytes())
            nonce, plan, authority, media = "1" * 32, "2" * 64, "3" * 64, "4" * 64
            result, serial = C.pin(b"result"), C.pin(b"serial")
            fsck = dict(argv=["/usr/bin/e2fsck", "-fn", "/out/result.raw"], exit=0,
                        ownership="REAPED", group_census="EMPTY_TWICE", passed=True, reaped=True,
                        output_complete=True, timeout=False, command_timed_out=False, original_budget_overrun=False,
                        emergency_retirement=False, emergency_retirement_cap_seconds=None, signals=[],
                        command_cancelled=[], error=None, operation_seconds=1, operation_cap_seconds=60,
                        child_file_size_cap=None)

            def save(name, value):
                body = C.wire(value)
                (root / name).write_bytes(body)
                return C.pin(body)

            fsck_pin = save("fsck-result.json", fsck)
            for suffix, data in (("stdout", b"clean result"), ("stderr", b""), ("log", b"clean result")):
                (root / ("fsck-result." + suffix)).write_bytes(data)
            actor = dict(kind="QTBASE16K_PACKAGE_ACTOR_RESULT_V1", scope=H.PACKAGE_SCOPE, nonce=nonce,
                         status=H.PACKAGE_PASS, phase="complete", signing="NOT_RUN", plan_sha256=plan,
                         selection_sha256=authority, media_sha256=media, result_disk=result, serial=serial,
                         fsck_result=fsck_pin)
            actor_pin = save("actor-result.json", actor)
            post = dict(kind="QTBASE16K_PACKAGE_POST_SCOPE_V1", scope=H.PACKAGE_SCOPE, nonce=nonce,
                        authority=None, exit_code=0, observations=[dict(scope_absent=True, container_absent=True)] * 2,
                        plan_sha256=plan, authority_sha256=authority, handoff_sha256=media, actor_result=actor_pin)
            worker = dict(kind="QTBASE16K_PACKAGING_RESULT_V1", scope=H.PACKAGE_SCOPE, nonce=nonce,
                          status=H.PACKAGE_PASS, phase="complete", signing="NOT_RUN", plan_sha256=plan,
                          selection_sha256=authority, archive=archive_pin)
            readback = dict(kind="QTBASE16K_PACKAGE_OFFLINE_READBACK_V1", status="PASS", phase="complete",
                            signing="NOT_RUN", nonce=nonce, plan={"sha256": plan}, selection={"sha256": authority},
                            worker=worker, result=result, serial=serial, evidence={archive.name: archive_pin})

            def verify(post=post, readback=readback):
                return H.bind(archive, root / "post.json", save("post.json", post)["sha256"],
                              root / "actor-result.json", root / "readback.json",
                              save("readback.json", readback)["sha256"])

            handoff = verify()
            self.assertEqual(handoff["archive"], archive_pin)
            self.assertEqual(handoff["packaging_receipt"], C.pin(C.wire(readback)))
            self.assertIsNone(handoff["authority"])
            with self.assertRaisesRegex(ValueError, "retirement required"):
                verify(post=post | {"observations": post["observations"][:1]})
            with self.assertRaisesRegex(ValueError, "same original attempt"):
                verify(readback=readback | {"result": C.pin(b"different result")})
            archive.write_bytes(b"changed bytes")
            with self.assertRaises(ValueError):
                verify()
            archive.write_bytes(b"inert archive")
            (root / "fsck-result.log").write_bytes(b"changed fsck stream")
            with self.assertRaises(ValueError):
                verify()


if __name__ == "__main__":
    unittest.main()

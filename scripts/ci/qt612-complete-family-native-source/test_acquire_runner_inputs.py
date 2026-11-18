#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check pinned response, custody and original-log handling without network."""
import argparse
import base64
from email.message import Message
import importlib.util
import io
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

here = Path(__file__).with_name("acquire_runner_inputs.py")
spec = importlib.util.spec_from_file_location("qt_acquire_inputs", here)
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)


class Response(io.BytesIO):
    def __init__(self, url, content, length=None, encoding=None, status=200):
        super().__init__(content)
        self.url, self.status, self.headers = url, status, Message()
        if length is not None:
            self.headers["Content-Length"] = str(length)
        if encoding is not None:
            self.headers["Content-Encoding"] = encoding

    def geturl(self):
        return self.url


class AcquisitionTests(unittest.TestCase):
    url = "https://raw.githubusercontent.com/example/fixture/aaaaaaaaaaaa/file"

    def response(self, content, **options):
        return lambda *_args, **_kwargs: Response(self.url, content, **options)

    def test_accepts_exact_stream_and_empty_revocations(self):
        body = b"exact data"
        for value in (body, b"", body * 100_000):
            with self.subTest(bytes=len(value)):
                target = io.BytesIO()
                A.receive(self.response(value, length=len(value)), self.url, A.C.pin(value), target)
                self.assertEqual(target.getvalue(), value)

    def test_refuses_short_wrong_digest_oversized_and_bad_content_length(self):
        for wrong, message in ((b"x", "WHOLE_INPUT_PIN"), (b"bytf", "WHOLE_INPUT_PIN"),
                               (b"bytes", "BODY_OVER_LIMIT")):
            with self.subTest(wrong=wrong), self.assertRaisesRegex(ValueError, message):
                A.receive(self.response(wrong), self.url, A.C.pin(b"byte"), io.BytesIO())
        with self.assertRaisesRegex(ValueError, "CONTENT_LENGTH"):
            A.receive(self.response(b"byte", length=5), self.url, A.C.pin(b"byte"), io.BytesIO())

    def test_refuses_redirect_non_success_or_transformed_bytes(self):
        cases = [lambda *_a, **_k: Response(self.url + "/redirect", b"read"),
                 self.response(b"read", status=206), self.response(b"read", encoding="gzip")]
        for opener in cases:
            with self.assertRaisesRegex(ValueError, "EXACT_HTTP_BODY"):
                A.receive(opener, self.url, A.C.pin(b"read"), io.BytesIO())
        with self.assertRaisesRegex(ValueError, "EXACT_PUBLIC_HTTPS_ROUTE"):
            A.receive(self.response(b"read"), "http://raw.githubusercontent.com/insecure", A.C.pin(b"read"), io.BytesIO())

    def test_public_git_coordinate_and_arch_epoch_escaping(self):
        self.assertTrue(A.git_url("e" * 40, "packages/pkg-2:3.tar.xz").endswith("pkg-2%3A3.tar.xz"))
        for name in ("../../x", "/root", "a//b", "a/../b", "alt?url=other", "a%2fb"):
            with self.assertRaisesRegex(ValueError, "RELATIVE_PUBLIC"):
                A.git_url("e" * 40, name)

    def test_acquisition_publishes_only_verified_set(self):
        with tempfile.TemporaryDirectory(prefix="qt-acquisition-test-") as directory:
            root = Path(directory)
            portable, md4c = root / "portable", root / "md4c"
            portable.mkdir()
            md4c.mkdir()
            source = md4c / A.ARCHIVE
            source.write_bytes(b"archive")
            (md4c / (A.ARCHIVE + ".sig")).write_bytes(b"signature")
            (md4c / A.CERT).write_bytes(b"certificate")
            pins = dict(filename=A.ARCHIVE, archive=A.C.pin(b"archive"), signature=A.C.pin(b"signature"))
            selection = A.C.encoded(dict(dependencies=dict(md4c=pins)))
            (portable / A.R.SELECTION).write_bytes(selection)
            route = root / "routes.json"
            route.write_bytes(b"{}")
            output = root / "closed"
            args = argparse.Namespace(portable=portable, route_plan=route, md4c_input=md4c, output=output,
               selection_sha256=A.C.pin(selection)["sha256"], route_plan_sha256=A.C.pin(b"{}")["sha256"],
               md4c_cert_bytes=11, md4c_cert_sha256=A.C.pin(b"certificate")["sha256"], r128_job_log=None)
            path = "operands/base-materials/pkg-1:2.tar.xz"
            targets = {path: dict(pin=A.C.pin(b"bytes"), url=self.url)}
            def publish_fixture(staging, parent_fd, final, inode):
                self.assertFalse(final.exists())
                self.assertEqual((staging.stat().st_dev, staging.stat().st_ino), inode)
                self.assertEqual(os.fstat(parent_fd).st_ino, final.parent.stat().st_ino)
                staging.rename(final)

            # The other offline controls permanently fence ctypes in shared discovery.
            with (patch.object(A, "public_targets", return_value=targets),
                  patch.object(A.K, "publish", side_effect=publish_fixture) as commit):
                with self.assertRaisesRegex(A.AcquisitionError, "HTTP_WHOLE_INPUT_PIN_MISMATCH"):
                    A.acquire(args, root, self.response(b"wrong"))
                self.assertFalse(output.exists())
                commit.assert_not_called()
                self.assertFalse(list(root.glob(".qt-acquisition-*")))
                result = A.acquire(args, root, self.response(b"bytes"))
                self.assertEqual(result["GPG"], "NOT_RUN")
                commit.assert_called_once()
                self.assertEqual((output / path).read_bytes(), b"bytes")
                self.assertEqual((output / "trust" / A.CERT).read_bytes(), b"certificate")

    def test_bounded_job_log_replay_selects_one_child_only(self):
        payload = b"synthetic archive body"
        tar_data = io.BytesIO()
        with tarfile.open(fileobj=tar_data, mode="w:gz") as archive:
            row = tarfile.TarInfo(A.R128_MEMBER)
            row.size = len(payload)
            archive.addfile(row, io.BytesIO(payload))
        compressed = tar_data.getvalue()
        tar_pin = A.C.pin(compressed)
        beginning = (f"CACHY_ASAHI_EVIDENCE_BEGIN {A.R128_EXPORT} sha256={tar_pin['sha256']} "
                     f"bytes={tar_pin['bytes']}\n").encode()
        end = f"\nCACHY_ASAHI_EVIDENCE_END {A.R128_EXPORT}\n".encode()
        log = beginning + base64.b64encode(compressed) + end
        with patch.multiple(A, R128_ORIGINAL=A.C.pin(log), R128_TAR=tar_pin, R128_PACKAGE=A.C.pin(payload)):
            self.assertEqual(A.r128_package(log, A.C.pin(payload)), payload)
            with self.assertRaisesRegex(ValueError, "ORIGINAL_AND_PACKAGE_PIN"):
                A.r128_package(log + end, A.C.pin(payload))
            with self.assertRaisesRegex(ValueError, "ORIGINAL_AND_PACKAGE_PIN"):
                A.r128_package(log, A.C.pin(b"substitute"))


if __name__ == "__main__":
    unittest.main()

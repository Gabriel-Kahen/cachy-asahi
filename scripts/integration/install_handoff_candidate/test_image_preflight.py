#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline controls for the exact-image install-handoff controller admission."""

import gzip
import io
from pathlib import Path
import runpy
import tarfile
import tempfile
import unittest
from unittest.mock import patch

G = runpy.run_path(str(Path(__file__).with_name("image_preflight.py")))
DB = G["DB_DIR"]
DIFF = "sha256:" + "3" * 64


class ImagePreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.blobs = Path(self.temp.name)

    def write(self, name, value):
        path = self.blobs / name
        path.write_bytes(G["encode"](value))
        return path

    def layer(self, members):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as archive:
            for name, body in members:
                member = tarfile.TarInfo(name)
                if body is None:
                    member.type = tarfile.DIRTYPE
                    archive.addfile(member)
                else:
                    member.size = len(body)
                    archive.addfile(member, io.BytesIO(body))
        raw = stream.getvalue()
        compressed = gzip.compress(raw, mtime=0)
        pin = G["digest"](compressed)
        (self.blobs / pin).write_bytes(compressed)
        return dict(mediaType=G["LAYER"], digest="sha256:" + pin, size=len(compressed)), "sha256:" + G["digest"](raw)

    def test_layer_inventory_binds_compressed_and_uncompressed_identity(self):
        members = [(f"{DB}/python-3.14.9-1", None),
                   (f"{DB}/python-3.14.9-1/desc", b"%NAME%\npython\n\n%VERSION%\n3.14.9-1\n"),
                   (G["VERSIONS"], b"python 3.14.9-1\n")]
        layer, diff = self.layer(members)
        want = {"python": "3.14.9-1"}
        self.assertEqual(G["layer_inventory"](self.blobs, layer, diff), (want, want))
        with self.assertRaisesRegex(ValueError, "Whole compressed and uncompressed layer digest"):
            G["layer_inventory"](self.blobs, layer, DIFF)
        with self.assertRaisesRegex(ValueError, "Layer extent"):
            G["layer_inventory"](self.blobs, dict(layer, size=layer["size"] + 1), diff)

    def test_inventory_shadowing_and_whiteouts_refuse(self):
        for name in (".wh.var", "var/lib/.wh.pacman", f"{DB}/.wh.python-3.14.9-1",
                     "opt/.wh.composition-runtime-packages.txt", "var/.wh..wh..opq",
                     f"{DB}/../local/python-3.14.9-1/desc", "var/lib/pacman", f"{DB}/python-3.14.9-1"):
            with self.subTest(name=name):
                layer, diff = self.layer([(name, b"not a directory")])
                with self.assertRaises(ValueError):
                    G["layer_inventory"](self.blobs, layer, diff)

    def test_layers_refuse_replaced_package_identity(self):
        data = b"%NAME%\npython\n\n%VERSION%\n3.14.9-1\n"
        a, da = self.layer([(f"{DB}/python-3.14.9-1/desc", data)])
        b, db = self.layer([(f"{DB}/python-3.14.9-1/desc", data + b"\n")])
        with self.assertRaisesRegex(ValueError, "may only add"):
            G["inventory"](self.blobs, (a, b), (da, db))

    def test_local_rootless_context_and_pinned_inspection_required(self):
        context = {"Name": "selected", "Endpoints": {"docker": {"Host": "unix:///run/docker.sock"}}}
        daemon = {"ClientInfo": {"Context": "selected"}, "Architecture": "x86_64", "OSType": "linux",
                  "SecurityOptions": ["name=rootless"]}
        self.assertEqual(G["selected_context"](self.write("context", [context]), self.write("daemon", daemon))["context"],
                         "selected")
        with self.assertRaisesRegex(ValueError, "same selected rootless"):
            G["selected_context"](self.blobs / "context", self.write("daemon", dict(daemon, SecurityOptions=[])))
        context["Endpoints"]["docker"]["Host"] = "tcp://example.invalid:2375"
        with self.assertRaisesRegex(ValueError, "local Unix Docker context"):
            G["selected_context"](self.write("context", [context]), self.blobs / "daemon")
        image = {"Id": DIFF, "Os": "linux", "Architecture": "amd64",
                 "RootFS": {"Type": "layers", "Layers": [DIFF]}, "Config": {}}
        self.assertEqual(G["observe_image"](self.write("image", [image]), DIFF, [DIFF]), G["digest"](G["encode"]([image])))
        for changed in (dict(image, Id="wrong"), dict(image, Config={"Volumes": {"/extra": {}}})):
            with self.assertRaisesRegex(ValueError, "Image inspection must match"):
                G["observe_image"](self.write("image", [changed]), DIFF, [DIFF])

    def test_ambiguous_index_refused_before_layer_access(self):
        item = {"mediaType": G["MANIFEST"], "platform": G["PLATFORM"], "digest": DIFF, "size": 42}
        raw = G["encode"]({"schemaVersion": 2, "mediaType": G["INDEX"], "manifests": [item, item]})
        pin = G["digest"](raw)
        (self.blobs / pin).write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "One Linux amd64 execution manifest"):
            G["image_objects"](self.blobs, "sha256:" + pin)

    def test_image_refuses_exact_count_with_changed_version(self):
        rows = {f"model-{i}": "1-1" for i in range(139)}
        base, selected = [dict(digest=DIFF)], [dict(digest=DIFF), dict(digest="sha256:" + "4" * 64)]
        observed = [("manifest", "config", selected, [DIFF, DIFF]), ("base", "config", base, [DIFF])]
        with patch.dict(G["image_check"].__globals__, {
            "image_objects": lambda *_: observed.pop(0),
            "observe_image": lambda *_: "metadata",
            "inventory": lambda *_: (rows, rows),
        }):
            with self.assertRaisesRegex(ValueError, "exact accepted ALPM and 139-package"):
                G["image_check"](self.blobs, DIFF, self.blobs / "unused", {})


if __name__ == "__main__":
    unittest.main()

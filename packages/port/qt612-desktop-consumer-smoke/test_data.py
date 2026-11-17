# SPDX-License-Identifier: MIT
"""Passive source/fixture checks. No Qt actor is run or simulated."""
import sys


def fence(event, args):
    if event.startswith(("subprocess.", "socket.", "ctypes.")) or event in {
        "os.system", "os.fork", "os.forkpty", "os.exec", "os.posix_spawn",
        "os.kill", "os.killpg", "fcntl.flock", "resource.setrlimit",
    }:
        raise RuntimeError("source/data control cannot launch or mutate actors")


sys.addaudithook(fence)
import hashlib
import json
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent


class SourceData(unittest.TestCase):
    def test_closed_source_map(self):
        records = json.loads((ROOT / "source-files.lock.json").read_text())["files"]
        actual = {p.relative_to(ROOT).as_posix() for p in ROOT.rglob("*") if p.is_file()}
        self.assertEqual(actual, set(records) | {"source-files.lock.json"})
        for name, record in records.items():
            path = ROOT / name
            self.assertFalse(path.is_symlink())
            data = path.read_bytes()
            self.assertEqual(len(data), record["bytes"], name)
            self.assertEqual(hashlib.sha256(data).hexdigest(), record["sha256"], name)

    def test_interface_retains_unexecuted_state(self):
        data = json.loads((ROOT / "INTERFACE.DATA.json").read_text())
        self.assertEqual(data["qt_version"], "6.12.0")
        self.assertEqual(data["installed_prefix"], "/usr")
        self.assertEqual(len(data["provider_sources"]), 5)
        for revision in data["provider_sources"].values():
            self.assertRegex(revision, r"^[0-9a-f]{40}$")
        self.assertEqual(set(data["checks"]), {
            "qt612-desktop-render", "qt612-desktop-shader", "qt612-desktop-protocol"})
        self.assertEqual(set(data["success_markers"]), set(data["checks"]))
        for name, marker in data["success_markers"].items():
            source = (ROOT / (name.removeprefix("qt612-desktop-") + ".cpp")).read_text()
            self.assertEqual(source.count(f'std::puts("{marker}");'), 1)
        self.assertTrue(data["required_all_checks"])
        for field in ("configure", "build", "render", "shader_reflection", "protocol_exchange",
                      "native", "asahi_m2", "root_acceptance"):
            self.assertIsNone(data[field], field)

    def test_svg_interior_expectations(self):
        svg = ET.fromstring((ROOT / "colors.svg").read_bytes())
        self.assertEqual(svg.attrib, {"width": "16", "height": "16", "viewBox": "0 0 16 16"})
        rectangles = list(svg)
        self.assertEqual(len(rectangles), 2)
        # Evaluate this tiny axis-aligned fixture independently of any Qt API.
        def color(x, y):
            result = None
            for rect in rectangles:
                self.assertEqual(rect.tag, "{http://www.w3.org/2000/svg}rect")
                left, top = int(rect.get("x", "0")), int(rect.get("y", "0"))
                if left <= x < left + int(rect.get("width")) and top <= y < top + int(rect.get("height")):
                    result = rect.get("fill")
            return result
        self.assertEqual(color(4, 8), "#e02030")
        self.assertEqual(color(12, 8), "#2040d0")
        for x, y in ((2, 2), (6, 12)):
            self.assertEqual(color(x, y), "#e02030")
        for x, y in ((10, 2), (14, 12)):
            self.assertEqual(color(x, y), "#2040d0")

    def test_protocol_is_finite_echo_fixture(self):
        protocol = ET.fromstring((ROOT / "desktop-probe.xml").read_bytes())
        interfaces = protocol.findall("interface")
        self.assertEqual(len(interfaces), 1)
        interface = interfaces[0]
        self.assertEqual(interface.get("name"), "qt612_desktop_probe_v1")
        self.assertEqual(interface.get("version"), "1")
        request = interface.find("request[@name='echo']")
        event = interface.find("event[@name='echoed']")
        self.assertIsNotNone(request)
        self.assertIsNotNone(event)
        self.assertEqual([a.get("type") for a in request.findall("arg")], ["uint", "string"])
        self.assertEqual([a.attrib for a in request.findall("arg")],
                         [a.attrib for a in event.findall("arg")])
        self.assertFalse(interface.findall(".//arg[@type='fd']"))

    def test_glsl_fixture_has_std140_layout_inputs(self):
        shader = (ROOT / "probe.vert").read_text()
        self.assertIn("#version 440", shader)
        declarations = re.findall(r"layout\(location = (\d)\) (in|out) (vec\d) (\w+);", shader)
        self.assertEqual(declarations, [("0", "in", "vec3", "position"),
                                        ("1", "in", "vec4", "color"),
                                        ("0", "out", "vec4", "vertexColor")])
        self.assertRegex(shader, r"layout\(std140, binding = 0\) uniform Params\s*\{\s*mat4 transform;\s*vec4 tint;\s*\} params;")


if __name__ == "__main__":
    unittest.main(verbosity=2)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the independent successor reader's event and graph checks."""

from pathlib import Path
from runpy import run_path
import unittest


R = run_path(str(Path(__file__).with_name("arm16k_readback.py")))
NONCE = "12345678" * 4


class ReadbackTests(unittest.TestCase):
    def test_checkpoint_and_terminal_are_ordered_and_nonce_bound(self):
        state = R["serial_state"]
        setup = f"QTBASE_SUCCESSOR16K_SETUP {NONCE}\r\n"
        configured = f"QTBASE_SUCCESSOR16K_CONFIGURED {NONCE}\r\n"
        complete = f"QTBASE_SUCCESSOR16K_TERMINAL {NONCE} PASS complete\r\n"
        failed = f"QTBASE_SUCCESSOR16K_TERMINAL {NONCE} HOLD build\r\n"
        self.assertEqual(state((setup + configured + complete).encode(), NONCE), (("PASS", "complete"), True, True))
        self.assertEqual(state((setup + failed).encode(), NONCE), (("HOLD", "build"), True, False))
        for invalid in (configured, setup + setup, setup + complete + configured,
                        setup + failed.replace(NONCE, "f" * 32), setup + "QTBASE_SUCCESSOR16K_TERMINAL\n"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                state(invalid.encode(), NONCE)

    def test_hashed_graph_still_has_to_enable_the_actual_features(self):
        profile = b'set(FEATURE_vulkan ON CACHE BOOL "" FORCE)\n'
        settings = R["FEATURES"] | {"QT612_SERVER_API_LINKS": "1"}
        rows = [f"{name}:INTERNAL={value}\n".encode() for name, value in settings.items()]
        files = {
            "CMakeCache.txt": b"".join(rows),
            "build.ninja": b"include CMakeFiles/rules.ninja\nbuild all: phony lib/something\n",
            "rules.ninja": b"# CMAKE generated file: DO NOT EDIT!\n",
            "features.txt": b"".join(rows),
            "profile.json": b'{"status":"PASS_CONFIGURED_PROFILE_ONLY","settings":1,"native":"NOT_ESTABLISHED"}',
        }

        def refresh():
            pins = {name: R["C"].pin(files[name]) for name in R["GRAPH"]}
            files["graph.sha256"] = "".join(f"{pin['sha256']}  {name}\n" for name, pin in pins.items()).encode()
            return pins

        self.assertEqual(R["graph_checks"](refresh(), files, profile)["QT_FEATURE_vulkan"], "ON")
        files["CMakeCache.txt"] = files["CMakeCache.txt"].replace(b"QT_FEATURE_vulkan:INTERNAL=ON",
                                                                b"QT_FEATURE_vulkan:INTERNAL=OFF")
        with self.assertRaisesRegex(ValueError, "fresh CMake cache differs"):
            R["graph_checks"](refresh(), files, profile)


if __name__ == "__main__":
    unittest.main()

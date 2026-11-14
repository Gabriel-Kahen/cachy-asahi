#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Configuration semantics and parser checks only; never launch a session."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
OLD_LOCK = 'hl.bind("SUPER + L", hl.dsp.exec_cmd("swaylock --color 000000"))'
NEW_LOCK = 'hl.bind("SUPER + L", hl.dsp.exec_cmd("cachy-asahi-session-lock lock"))'
SUSPEND = 'hl.bind("SUPER + SHIFT + L", hl.dsp.exec_cmd("cachy-asahi-session-lock suspend"))'
LUA_STUB = r'''
local bindings = {}
local function describe(value)
    if type(value) ~= "table" then return tostring(value) end
    local keys, parts = {}, {}
    for key, _ in pairs(value) do table.insert(keys, key) end
    table.sort(keys)
    for _, key in ipairs(keys) do table.insert(parts, key .. "=" .. describe(value[key])) end
    return "{" .. table.concat(parts, ",") .. "}"
end
local function dispatcher(kind)
    return function(value) return { kind=kind, value=value } end
end
hl = {
    monitor = function(_) end,
    config = function(_) end,
    bind = function(key, value, options)
        table.insert(bindings, key .. "\t" .. describe(value) .. "\t" .. describe(options))
    end,
    dsp = {
        exec_cmd=dispatcher("exec"), focus=dispatcher("focus"),
        window = { close=dispatcher("close"), float=dispatcher("float"),
                   move=dispatcher("move"), drag=dispatcher("drag"), resize=dispatcher("resize") },
    },
}
dofile(arg[1])
for _, value in ipairs(bindings) do io.write(value .. "\n") end
'''


def prior_config(text):
    if text.count(NEW_LOCK) != 1 or text.count(SUSPEND) != 1:
        raise ValueError("expected exactly one lock and one suspend binding")
    return text.replace(NEW_LOCK, OLD_LOCK).replace(SUSPEND + "\n", "")


def enable_optional(text):
    lines = []
    for line in text.splitlines():
        if line.startswith("-- hl.bind(") or line.startswith("-- hl.on(") or line.startswith("--     hl.exec_cmd(") or line == "-- end)":
            line = line[3:]
        lines.append(line)
    return "\n".join(lines) + "\n"


class Settings(unittest.TestCase):
    def setUp(self):
        self.text = (HERE / "hyprland.lua").read_text()
        self.provenance = json.loads((HERE / "source-provenance.json").read_text())

    def semantic_bindings(self, config):
        result = subprocess.run(["/usr/bin/lua", "-", str(config)], input=LUA_STUB.encode(),
                                capture_output=True, env={"PATH": "/usr/bin", "LC_ALL": "C"}, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        lines = result.stdout.decode().splitlines()
        keys = [line.split("\t", 1)[0] for line in lines]
        self.assertEqual(len(keys), len(set(keys)), "duplicate executed keyboard/mouse binding")
        return dict(line.split("\t", 1) for line in lines)

    def test_only_two_lock_binding_changes_against_pinned_baseline(self):
        restored = prior_config(self.text)
        self.assertEqual(hashlib.sha256(restored.encode()).hexdigest(), self.provenance["baseline_hyprland_sha256"])
        self.assertEqual(self.provenance["baseline_version"], "0.1.0-3")
        self.assertEqual(self.provenance["version"], "0.1.1-1")
        self.assertFalse(self.provenance["selected_for_release"])
        self.assertFalse(self.provenance["selected_for_development"])

    def test_executed_bindings_are_unique_and_keep_all_prior_semantics(self):
        with tempfile.TemporaryDirectory(prefix="settings011-lua-") as temporary:
            baseline = Path(temporary) / "baseline.lua"
            baseline.write_text(prior_config(self.text))
            old = self.semantic_bindings(baseline)
            current = self.semantic_bindings(HERE / "hyprland.lua")
        self.assertEqual(len(old), 36)
        self.assertEqual(len(current), 37)
        self.assertEqual(current.pop("SUPER + SHIFT + L"), "{kind=exec,value=cachy-asahi-session-lock suspend}\tnil")
        self.assertEqual(current["SUPER + L"], "{kind=exec,value=cachy-asahi-session-lock lock}\tnil")
        current["SUPER + L"] = "{kind=exec,value=swaylock --color 000000}\tnil"
        self.assertEqual(current, old)

    def test_all_auxiliary_sources_remain_identical_to_prior_candidate(self):
        expected = {"waybar.json", "waybar.css", "mako.conf", "cachy-asahi-screenshot", "LICENSE", "NOTICE"}
        self.assertEqual(set(self.provenance["unchanged_sources"]), expected)
        for name, checksum in self.provenance["unchanged_sources"].items():
            with self.subTest(source=name):
                self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), checksum)

    def test_optional_capture_and_startup_commands_still_reference_shipped_paths(self):
        for mode, key in (("full", "SUPER + CTRL + SHIFT + S"), ("region", "SUPER + SHIFT + S")):
            self.assertIn(f'-- hl.bind("{key}", hl.dsp.exec_cmd("cachy-asahi-screenshot {mode}"))', self.text)
        self.assertIn('--     hl.exec_cmd("waybar --config /usr/share/cachy-asahi/hyprland/waybar.json --style /usr/share/cachy-asahi/hyprland/waybar.css")', self.text)
        self.assertIn('--     hl.exec_cmd("mako --config /usr/share/cachy-asahi/hyprland/mako.conf")', self.text)
        result = subprocess.run(["/usr/bin/python3", "-I", "-B", str(HERE / "cachy-asahi-screenshot"), "--help"],
                                env={"PATH": "/usr/bin"}, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"full", result.stdout)
        self.assertIn(b"region", result.stdout)
        self.assertIsInstance(json.loads((HERE / "waybar.json").read_text()), dict)

    def test_real_lua_syntax_and_hyprland_parser_for_default_and_optional_config(self):
        with tempfile.TemporaryDirectory(prefix="settings011-verify-") as temporary:
            work = Path(temporary)
            for name in ("home", "config", "cache", "runtime"):
                (work / name).mkdir(mode=0o700)
            env = {"PATH": "/usr/bin", "LC_ALL": "C.UTF-8", "HOME": str(work / "home"),
                   "XDG_CONFIG_HOME": str(work / "config"), "XDG_CACHE_HOME": str(work / "cache"),
                   "XDG_RUNTIME_DIR": str(work / "runtime")}
            optional = work / "optional.lua"
            optional.write_text(enable_optional(self.text))
            for config in (HERE / "hyprland.lua", optional):
                with self.subTest(config=config.name):
                    syntax = subprocess.run(["/usr/bin/luac", "-p", str(config)], cwd=work, env=env,
                                            capture_output=True, timeout=10)
                    self.assertEqual(syntax.returncode, 0, syntax.stderr)
                    parsed = subprocess.run(["/usr/bin/Hyprland", "--verify-config", "--config", str(config)],
                                            cwd=work, env=env, capture_output=True, timeout=15)
                    self.assertEqual(parsed.returncode, 0, parsed.stdout + parsed.stderr)
                    self.assertIn(b"config ok", parsed.stdout + parsed.stderr)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors.
"""Exercise development fixture generation using copied frozen inputs only."""
import sys
sys.dont_write_bytecode = True

import copy
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
# Fixture generation stays on its complete retained v1 source/lock snapshot.
FROZEN = ROOT / "scripts/ci/maintained-native/native"
PATHS = (
    "packages/desktop/cachy-asahi-hyprland-settings",
    "packages/settings/cachy-asahi-setup",
    "packages/shells/cachy-asahi-fish-config",
    "packages/shells/cachy-asahi-zsh-config",
)
EPOCH = 1791748800
SOURCE_COMMIT = "1" * 40


def sha(data):
    return hashlib.sha256(data).hexdigest()


def snapshot(root):
    result = {}
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        result[str(path.relative_to(root))] = (
            info.st_mode, info.st_mtime_ns,
            os.readlink(path) if path.is_symlink() else sha(path.read_bytes()) if path.is_file() else None,
        )
    return result


def srcinfo(recipe):
    fields = {}
    for line in (recipe / ".SRCINFO").read_text().splitlines():
        if " = " in line:
            key, value = line.strip().split(" = ", 1)
            fields.setdefault(key, []).append(value)
    return fields


def body(recipe):
    text = (recipe / "PKGBUILD").read_text()
    match = re.search(r"^(?:prepare|check|package)\(\)\s*\{", text, re.M)
    return text[match.start():] if match else ""


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = ROOT / "scripts/integration/fixtures.py"
        spec = importlib.util.spec_from_file_location("cachy_asahi_fixture_generator", path)
        cls.generator = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = cls.generator
        spec.loader.exec_module(cls.generator)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cachy-asahi-upgrade-tests-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.repo = self.work / "source"
        self.repo.mkdir()
        self.lock = self.repo / "scripts/ci/recipes.lock.json"
        self.lock.parent.mkdir(parents=True)
        self.record = json.loads((FROZEN / "scripts/ci/recipes.lock.json").read_bytes())
        self.assertEqual(set(self.record), set(PATHS))
        for directory, files in self.record.items():
            for name, digest in files.items():
                data = (FROZEN / directory / name).read_bytes()
                self.assertEqual(sha(data), digest, f"retained frozen input drift: {directory}/{name}")
                destination = self.repo / directory / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
        (self.repo / "LICENSE").write_bytes((FROZEN / "LICENSE").read_bytes())
        canonical = self.repo / "scripts/setup/setup.py"
        canonical.parent.mkdir(parents=True)
        canonical.write_bytes((FROZEN / "scripts/setup/setup.py").read_bytes())
        self.save_lock()
        self.output = self.work / "output"

    def save_lock(self):
        self.lock.write_text(json.dumps(self.record, sort_keys=True, indent=2) + "\n")
        self.lock_hash = sha(self.lock.read_bytes())

    def generate(self, output=None, version=None, lock_hash=None):
        return self.generator.generate(self.repo, self.lock, output or self.output,
                                       lock_hash or self.lock_hash, SOURCE_COMMIT, version=version, epoch=EPOCH)

    def refuse(self, **kwargs):
        output = kwargs.get("output", self.output)
        existed = output.exists() or output.is_symlink()
        with self.assertRaises((ValueError, OSError)):
            self.generate(**kwargs)
        if not existed:
            self.assertFalse(output.exists(), "invalid inputs created an output directory")

    def refresh_recipe(self, directory):
        recipe = self.repo / directory
        fields = srcinfo(recipe)
        hashes = [sha((recipe / name).read_bytes()) for name in fields["source"]]
        text = (recipe / "PKGBUILD").read_text()
        text = re.sub(r"sha256sums=\(.*?\)", "sha256sums=(" + " ".join(repr(h) for h in hashes) + ")", text, flags=re.S)
        (recipe / "PKGBUILD").write_text(text)
        replacements = iter(hashes)
        text = (recipe / ".SRCINFO").read_text()
        (recipe / ".SRCINFO").write_text(re.sub(r"(?m)^(\s*sha256sums = ).*$", lambda m: m[1] + next(replacements), text))
        for name in self.record[directory]:
            self.record[directory][name] = sha((recipe / name).read_bytes())
        self.save_lock()

    def test_deterministic_output_and_unchanged_inputs(self):
        before = snapshot(self.repo)
        first = self.generate()
        self.assertIsInstance(first, dict)
        other = self.work / "other-output"
        self.generate(other)
        self.assertEqual(snapshot(self.repo), before)
        first_tree, second_tree = snapshot(self.output), snapshot(other)
        self.assertEqual(set(first_tree), set(second_tree))
        for name in first_tree:
            self.assertEqual(first_tree[name], second_tree[name], name)
        for path in self.output.rglob("*"):
            if path.is_file():
                self.assertEqual(int(path.stat().st_mtime), EPOCH, str(path))
        manifest = json.loads((self.output / "fixture-manifest.json").read_bytes())
        self.assertTrue(manifest["development_only"])
        self.assertEqual(manifest["source_commit"], SOURCE_COMMIT)
        self.assertEqual(manifest["frozen_lock_sha256"], self.lock_hash)
        for stage in ("baseline", "upgrade"):
            self.assertEqual((self.output / stage / "LICENSE").read_bytes(), (self.repo / "LICENSE").read_bytes())
            generated = json.loads((self.output / f"{stage}-recipes.lock.json").read_bytes())
            self.assertEqual(set(generated), set(PATHS))
            for directory, files in generated.items():
                for name, digest in files.items():
                    self.assertEqual(sha((self.output / stage / directory / name).read_bytes()), digest)
                name = srcinfo(self.output / stage / directory)["pkgname"][0]
                reviewed = json.loads((self.output / "reviewed-inputs" / stage / f"{name}.json").read_bytes())
                self.assertEqual(reviewed, files)

    def test_versions_metadata_bodies_payloads_and_provenance(self):
        self.generate()
        version = max(tuple(map(int, srcinfo(self.repo / directory)["pkgver"][0].split("."))) for directory in PATHS)
        expected_version = f"{version[0]}.{version[1]}.{version[2] + 1}"
        preserved = ("pkgname", "arch", "license", "depends", "makedepends", "optdepends",
                     "provides", "conflicts", "replaces", "install", "backup")
        for directory in PATHS:
            original = self.repo / directory
            baseline = self.output / "baseline" / directory
            upgrade = self.output / "upgrade" / directory
            old, base, new = srcinfo(original), srcinfo(baseline), srcinfo(upgrade)
            self.assertEqual(base["pkgver"], old["pkgver"])
            self.assertEqual(new["pkgver"], [expected_version])
            self.assertEqual(new["pkgrel"], ["1"])
            for key in preserved:
                self.assertEqual(base.get(key), old.get(key), (directory, key, "baseline"))
                self.assertEqual(new.get(key), old.get(key), (directory, key, "upgrade"))
            self.assertEqual(body(baseline), body(original))
            self.assertEqual(body(upgrade), body(original))
            for fields in (base, new):
                if directory == PATHS[1]:
                    self.assertTrue(set(old["source"]) <= set(fields["source"]))
                    self.assertTrue(set(fields["source"]) - set(old["source"]) <= {"base-setup.py"})
                else:
                    self.assertEqual(fields["source"], old["source"])
            for recipe, fields in ((baseline, base), (upgrade, new)):
                self.assertEqual(fields["sha256sums"], [sha((recipe / n).read_bytes()) for n in fields["source"]])
                self.assertEqual((recipe / "LICENSE").read_bytes(), (self.repo / "LICENSE").read_bytes())
            for name, digest in self.record[directory].items():
                self.assertEqual(sha((baseline / name).read_bytes()), digest, f"baseline differs from frozen input: {directory}/{name}")
            for name in ("PKGBUILD", "NOTICE", "README.md"):
                self.assertRegex((upgrade / name).read_text(), r"(?i)TEST[ -]?ONLY|DEVELOPMENT-FIXTURE")
        for directory, template, prefix in ((PATHS[0], "hyprland.lua", "--"),
                                             (PATHS[2], "config.fish", "#"), (PATHS[3], "config.zsh", "#")):
            old = (self.output / "baseline" / directory / template).read_text()
            new = (self.output / "upgrade" / directory / template).read_text()
            self.assertNotEqual(old, new)
            for line in difflib.ndiff(old.splitlines(), new.splitlines()):
                if line.startswith(("+ ", "- ")) and line[2:].strip():
                    self.assertTrue(line[2:].lstrip().startswith(prefix), line)
        for stage in ("baseline", "upgrade"):
            root = self.output / stage
            self.assertEqual({str(path.parent.relative_to(root)) for path in root.rglob("PKGBUILD")}, set(PATHS))
            package = root / PATHS[1]
            helper = (package / "cachy-asahi-setup").read_bytes()
            provenance = json.loads((package / "source-provenance.json").read_bytes())
            self.assertEqual(helper, (root / "scripts/setup/setup.py").read_bytes())
            self.assertEqual(provenance["sha256"], sha(helper))
            self.assertEqual(provenance["license_sha256"], sha((root / "LICENSE").read_bytes()))
            if (package / "base-setup.py").exists():
                self.assertEqual((package / "base-setup.py").read_bytes(), (self.repo / PATHS[1] / "cachy-asahi-setup").read_bytes())

    def test_explicit_version_and_readonly_cli(self):
        self.generate(version="9.9.9")
        for directory in PATHS:
            self.assertEqual(srcinfo(self.output / "upgrade" / directory)["pkgver"], ["9.9.9"])
        helper = self.output / "upgrade" / PATHS[1] / "cachy-asahi-setup"
        home = self.work / "isolated-home"
        home.mkdir(mode=0o700)
        before = snapshot(self.work)
        env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / "config"),
                   XDG_DATA_HOME=str(home / "data"), XDG_STATE_HOME=str(home / "state"),
                   XDG_CACHE_HOME=str(home / "cache"), ZDOTDIR=str(home), PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run([sys.executable, "-B", str(helper), "--integration-fixture-version"], cwd=home,
                                env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("DEVELOPMENT-FIXTURE", result.stdout)
        self.assertIn("9.9.9", result.stdout)
        self.assertEqual(snapshot(self.work), before)

    def test_stale_missing_extra_inputs_and_wrong_lock_digest(self):
        recipe = self.repo / PATHS[2]
        target = recipe / "config.fish"
        original = target.read_bytes()
        target.write_bytes(original + b"# drift\n")
        self.refuse()
        target.write_bytes(original)
        target.unlink()
        self.refuse()
        target.write_bytes(original)
        extra = recipe / "unreviewed-input"
        extra.write_text("unexpected\n")
        self.refuse()
        extra.unlink()
        self.refuse(lock_hash="0" * 64)

    def test_duplicate_malformed_lock_entries(self):
        original = copy.deepcopy(self.record)
        for key, value in (("PKGBUILD", "bad"), ("PKGBUILD", "A" * 64), ("../escape", "0" * 64),
                           ("/absolute", "0" * 64)):
            self.record = copy.deepcopy(original)
            self.record[PATHS[0]][key] = value
            self.save_lock()
            self.refuse()
        for name in ("../escape", "/absolute", "packages/desktop/../escape"):
            self.record = copy.deepcopy(original)
            self.record[name] = {"PKGBUILD": "0" * 64}
            self.save_lock()
            self.refuse()
        self.record = original
        entry = json.dumps(original[PATHS[0]])
        raw = json.dumps(original)[:-1] + "," + json.dumps(PATHS[0]) + ":" + entry + "}"
        self.lock.write_text(raw)
        self.lock_hash = sha(self.lock.read_bytes())
        self.refuse()
        entries = []
        for directory, files in original.items():
            text = json.dumps(files)
            if directory == PATHS[0]:
                text = text[:-1] + ',"PKGBUILD":' + json.dumps(files["PKGBUILD"]) + "}"
            entries.append(json.dumps(directory) + ":" + text)
        self.lock.write_text("{" + ",".join(entries) + "}")
        self.lock_hash = sha(self.lock.read_bytes())
        self.refuse()

    def test_symlink_inputs_and_roots(self):
        target = self.repo / PATHS[2] / "config.fish"
        outside = self.work / "outside"
        outside.write_bytes(target.read_bytes())
        target.unlink()
        target.symlink_to(outside)
        self.refuse()
        target.unlink()
        target.write_bytes(outside.read_bytes())
        canonical = self.repo / "scripts/setup/setup.py"
        copy_path = self.work / "canonical-copy.py"
        copy_path.write_bytes(canonical.read_bytes())
        canonical.unlink()
        canonical.symlink_to(copy_path)
        self.refuse()
        canonical.unlink()
        canonical.write_bytes(copy_path.read_bytes())
        original_lock = self.lock.read_bytes()
        lock_copy = self.work / "lock-copy.json"
        lock_copy.write_bytes(original_lock)
        self.lock.unlink()
        self.lock.symlink_to(lock_copy)
        self.refuse()
        self.lock.unlink()
        self.lock.write_bytes(original_lock)
        link = self.work / "source-link"
        link.symlink_to(self.repo, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.generator.generate(link, self.lock, self.output, self.lock_hash, SOURCE_COMMIT, epoch=EPOCH)

    def test_unsafe_output_and_versions(self):
        self.output.mkdir()
        self.refuse()
        self.output.rmdir()
        self.refuse(output=self.repo / "inside-output")
        outside = self.work / "external-output"
        outside.mkdir()
        self.output.symlink_to(outside, target_is_directory=True)
        self.refuse()
        self.output.unlink()
        parent_link = self.work / "output-parent-link"
        parent_link.symlink_to(outside, target_is_directory=True)
        self.refuse(output=parent_link / "child")
        self.refuse(output=self.work / "missing-parent" / "child")
        old = srcinfo(self.repo / PATHS[0])["pkgver"][0]
        for version in ("1.2", "1.2.3.4", "1.2.x", "-1.2.3", old, "0.0.0"):
            self.refuse(version=version)

    def test_coherent_lock_does_not_hide_source_pin_mismatch(self):
        recipe = self.repo / PATHS[2]
        path = recipe / "config.fish"
        path.write_bytes(path.read_bytes() + b"# source changed without recipe pin\n")
        self.record[PATHS[2]]["config.fish"] = sha(path.read_bytes())
        self.save_lock()
        self.refuse()

    def test_setup_provenance_and_canonical_mismatch(self):
        canonical = self.repo / "scripts/setup/setup.py"
        original = canonical.read_bytes()
        canonical.write_bytes(original + b"# canonical drift\n")
        self.refuse()
        canonical.write_bytes(original)
        recipe = self.repo / PATHS[1]
        provenance = json.loads((recipe / "source-provenance.json").read_bytes())
        provenance["sha256"] = "0" * 64
        (recipe / "source-provenance.json").write_text(json.dumps(provenance))
        self.refresh_recipe(PATHS[1])
        self.refuse()

    def test_coherent_packaged_cli_mismatch(self):
        helper = self.repo / PATHS[1] / "cachy-asahi-setup"
        helper.write_bytes(helper.read_bytes() + b"# packaged CLI drift\n")
        self.refresh_recipe(PATHS[1])
        self.refuse()

    def test_root_license_mismatch_and_invalid_source_commit(self):
        license_path = self.repo / "LICENSE"
        original = license_path.read_bytes()
        license_path.write_bytes(original + b"changed grant\n")
        self.refuse()
        license_path.write_bytes(original)
        for commit in ("bad", "x" * 40, "0" * 39):
            with self.assertRaises((ValueError, OSError)):
                self.generator.generate(self.repo, self.lock, self.output, self.lock_hash, commit, epoch=EPOCH)
            self.assertFalse(self.output.exists())

    def test_recipe_is_never_sourced(self):
        recipe = self.repo / PATHS[2] / "PKGBUILD"
        marker = self.work / "forbidden-shell-execution"
        text = re.sub(r"(?m)^pkgver=.*$", f"pkgver=$(touch '{marker}')", recipe.read_text())
        recipe.write_text(text)
        self.record[PATHS[2]]["PKGBUILD"] = sha(recipe.read_bytes())
        self.save_lock()
        self.refuse()
        self.assertFalse(marker.exists())

    def test_literal_metadata_parser_rejects_unquoted_shell_syntax(self):
        malformed = (
            "pkgdesc=fixture;true", "pkgdesc=fixture|true", "pkgdesc=fixture&true",
            "pkgdesc=fixture>file", "pkgdesc=fixture<file", "pkgdesc=~",
            "pkgdesc=fixture(word)", "pkgdesc=fixture#embedded",
            "depends=(fish*)", "depends=(fish?)", "depends=(fish[12])",
            "depends=({fish,zsh})", "depends=(~)", "depends=(fish#embedded)",
        )
        for text in malformed:
            with self.subTest(metadata=text):
                with self.assertRaises(ValueError):
                    self.generator.assignments(text + "\n")
        parsed, _ = self.generator.assignments(
            "pkgdesc='fixture;~|&<>()#literal' # real trailing comment\n"
            "depends=('fish*' 'fish?' '[literal]' '{fish,zsh}' '~' 'fish;true' 'fish#literal')\n"
        )
        self.assertEqual(parsed["pkgdesc"], ["fixture;~|&<>()#literal"])
        self.assertEqual(parsed["depends"], ["fish*", "fish?", "[literal]", "{fish,zsh}", "~", "fish;true", "fish#literal"])

    def test_coherently_pinned_operator_metadata_is_refused_before_output(self):
        directory = PATHS[2]
        recipe = self.repo / directory
        original_recipe = (recipe / "PKGBUILD").read_text()
        original_metadata = (recipe / ".SRCINFO").read_text()

        def set_description(expression, value):
            (recipe / "PKGBUILD").write_text(re.sub(r"(?m)^pkgdesc=.*$", "pkgdesc=" + expression, original_recipe))
            (recipe / ".SRCINFO").write_text(re.sub(r"(?m)^(\s*pkgdesc = ).*$", lambda m: m[1] + value, original_metadata))
            for name in ("PKGBUILD", ".SRCINFO"):
                self.record[directory][name] = sha((recipe / name).read_bytes())
            self.save_lock()

        for value in ("fixture;true", "~", "fixture|true", "fixture>file"):
            with self.subTest(description=value):
                set_description(value, value)
                self.refuse()
        set_description("'fixture;~'", "fixture;~")
        self.generate()
        upgraded = srcinfo(self.output / "upgrade" / directory)
        self.assertEqual(upgraded["pkgdesc"], ["DEVELOPMENT TEST ONLY: fixture;~"])

    def test_derived_setup_sync_guard_checks_origin_and_canonical(self):
        self.generate()
        phase = self.output / "upgrade"
        package = phase / PATHS[1]
        checker = package / "check-sync.py"
        home = self.work / "checker-home"
        home.mkdir(mode=0o700)
        env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / "config"),
                   XDG_DATA_HOME=str(home / "data"), XDG_STATE_HOME=str(home / "state"),
                   XDG_CACHE_HOME=str(home / "cache"), PYTHONDONTWRITEBYTECODE="1")

        def run(expected):
            before = snapshot(self.work)
            result = subprocess.run([sys.executable, "-B", str(checker)], cwd=home,
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
            self.assertEqual(snapshot(self.work), before)

        run(0)
        for path in (package / "base-setup.py", phase / "scripts/setup/setup.py", phase / "LICENSE"):
            original = path.read_bytes()
            path.write_bytes(original + b"# drift\n")
            run(1)
            path.write_bytes(original)
        run(0)


if __name__ == "__main__":
    unittest.main()

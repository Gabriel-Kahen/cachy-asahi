# SPDX-License-Identifier: MIT
"""Private package() staging and moved --help only; no package manager."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--recipe-root', type=Path, default=Path(__file__).resolve().parent)
args, remaining = parser.parse_known_args()
RECIPE = args.recipe_root.resolve()
SOURCE = Path(__file__).resolve().parent
NAME = 'cachy-asahi-screenshot-copy'
FILES = {f'bin/{NAME}': (NAME, 0o755),
         f'share/doc/{NAME}/README.md': ('README.md', 0o644),
         f'share/doc/{NAME}/source-provenance.json': ('source-provenance.json', 0o644),
         f'share/licenses/{NAME}/NOTICE': ('NOTICE', 0o644),
         f'share/licenses/{NAME}/LICENSE': ('LICENSE', 0o644)}


class Package(unittest.TestCase):
    def test_recipe_pins_every_source_and_declares_explicit_dependencies(self):
        script = 'set -eu; source "$1"; for i in "${!source[@]}"; do printf "%s %s\\n" "${source[$i]}" "${sha256sums[$i]}"; done'
        result = subprocess.run(['bash', '-c', script, 'check', str(RECIPE/'PKGBUILD')],
                                text=True, capture_output=True, check=True, timeout=10)
        rows = [line.split() for line in result.stdout.splitlines()]
        self.assertEqual(len(rows), 7)
        for name, digest in rows:
            self.assertRegex(digest, r'^[0-9a-f]{64}$')
            self.assertEqual(hashlib.sha256((SOURCE/name).read_bytes()).hexdigest(), digest)
        recipe = (RECIPE/'PKGBUILD').read_text()
        self.assertIn("'wl-clipboard>=2.2.1'", recipe)
        self.assertIn("'cachy-asahi-hyprland-settings>=0.1.0'", recipe)
        self.assertNotRegex(recipe, r'(?m)^install=')

    def test_private_staging_exact_files_modes_and_moved_help(self):
        with tempfile.TemporaryDirectory(prefix='screenshot-copy-package-') as directory:
            root = Path(directory); stage = root/'stage'
            env = dict(os.environ, srcdir=str(SOURCE), pkgdir=str(stage))
            subprocess.run(['bash', '-eu', '-c', 'source "$1"; package', 'stage', str(RECIPE/'PKGBUILD')],
                           env=env, check=True, capture_output=True, timeout=10)
            prefix = stage/'usr'
            actual = {str(path.relative_to(prefix)): path for path in prefix.rglob('*') if path.is_file()}
            self.assertEqual(set(actual), set(FILES))
            for name, path in actual.items():
                source, mode = FILES[name]
                self.assertFalse(path.is_symlink())
                self.assertEqual(path.read_bytes(), (SOURCE/source).read_bytes())
                self.assertEqual(path.stat().st_mode & 0o777, mode)
            moved = root/'moved'; prefix.rename(moved)
            result = subprocess.run([str(moved/'bin'/NAME), '--help'], cwd=root,
                                    env={'PATH':'/usr/bin:/bin','HOME':str(root)},
                                    check=True, text=True, capture_output=True, timeout=10)
            self.assertIn('{full,region}', result.stdout)
            keep = moved/'user-file'; keep.write_text('keep me')
            for name in FILES: (moved/name).unlink()
            self.assertEqual(keep.read_text(), 'keep me')

    def test_provenance_binds_command_and_external_helper_without_bundling_it(self):
        provenance = json.loads((SOURCE/'source-provenance.json').read_bytes())
        self.assertEqual(provenance['license'], 'MIT')
        self.assertEqual(provenance['command_sha256'], hashlib.sha256((SOURCE/NAME).read_bytes()).hexdigest())
        self.assertEqual(provenance['external_capture']['bundled'], False)
        self.assertRegex(provenance['external_capture']['observed_source_revision'], r'^[0-9a-f]{40}$')
        self.assertEqual(provenance['native_ARM'], 'NOT RUN')


if __name__ == '__main__':
    unittest.main(argv=[__file__, *remaining])

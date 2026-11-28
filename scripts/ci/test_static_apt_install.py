"""Exercise the composite's cache and install steps with inert external actors."""
import collections
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / '.github/actions/static-prerequisites/action.yml'
INSTALLER = ROOT / 'scripts/ci/static_apt_install.sh'
NAME = 'fixture_1_amd64.deb'

ACTOR = """
import json, os, runpy, sys
from pathlib import Path
sys.dont_write_bytecode = True
actor = Path(sys.argv[0]).name
args = sys.argv[1:]

def note(*entry):
    with open(os.environ['ACTOR_LOG'], 'a') as stream:
        stream.write(json.dumps(entry) + '\\n')

if actor == 'sudo':
    assert args[0] == 'apt-get' and 'install' in args
    note('install')
    option = next(value for value in args if value.startswith('Dir::Cache::archives='))
    target = Path(option.split('=', 1)[1])
    for archive in Path(os.environ['FAKE_DOWNLOADS']).glob('*.deb'):
        staged = target / archive.name
        if not staged.exists():
            staged.write_bytes(archive.read_bytes())
            note('download', archive.name)
    raise SystemExit(0)
if actor != 'python3':
    raise SystemExit(0)

class Counted:
    def __init__(self, stream, directory):
        self.stream, self.directory = stream, directory
    def __enter__(self):
        self.stream.__enter__()
        return self
    def __exit__(self, *exc):
        return self.stream.__exit__(*exc)
    def __getattr__(self, name):
        return getattr(self.stream, name)
    def read(self, size):
        data = self.stream.read(size)
        note('read', self.directory, len(data))
        return data
    def write(self, data):
        size = self.stream.write(data)
        note('write', self.directory, size)
        return size

fdopen = os.fdopen
def measured(fd, *args, **kwargs):
    path = Path(os.readlink('/proc/self/fd/' + str(fd)))
    stream = fdopen(fd, *args, **kwargs)
    if path.suffix == '.deb' or path.name.startswith('.archive-'):
        return Counted(stream, path.parent.name)
    return stream

os.fdopen = measured
assert args[:2] == ['-I', '-B']
sys.argv = args[2:]
if sys.argv[0] == '-':
    exec(compile(sys.stdin.read(), '<install-stdin>', 'exec'), {'__name__': '__main__'})
else:
    runpy.run_path(sys.argv[0], run_name='__main__')
"""


def composite_step(name):
    content = ACTION.read_text().split(f'    - name: {name}\n', 1)[1].split('    - name: ', 1)[0]
    body = content.split('      run: ', 1)[1]
    script = textwrap.dedent(body[2:]) if body.startswith('|\n') else body
    return script, 'CAA_CACHE_HIT: ${{ steps.archives.outputs.cache-hit }}' in content


class InstallControls(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.cache = self.root / 'static-apt-cache'
        self.staged = self.root / 'static-apt-verified'
        self.downloads = self.root / 'downloads'
        self.downloads.mkdir()
        self.log = self.root / 'actors.jsonl'
        self.state = self.root / 'static-apt-trial-state.json'
        self.plan = self.root / 'static-apt-uris'
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        actor = self.bin / 'actor'
        actor.write_text(f'#!{sys.executable}\n' + ACTOR)
        actor.chmod(0o755)
        tools = next(line for line in INSTALLER.read_text().splitlines() if line.startswith('for tool in '))
        names = shlex.split(tools.removeprefix('for tool in ').split(';', 1)[0])
        for name in {*names, 'sudo', 'python3', 'dpkg-query'} - {'bash'}:
            (self.bin / name).symlink_to(actor.name)
        self.expected = {NAME: b'authenticated bytes'}

    def setup_case(self, phase='normal', hit='', cached=None):
        rows = {name: {'size': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                for name, raw in self.expected.items()}
        self.plan.write_text(''.join(f"'https://mirror/{name}' {name} {row['size']} SHA256:{row['sha256']}\n"
                                     for name, row in rows.items()))
        digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        helper = ROOT / 'scripts/ci/static_apt_cache.py'
        self.state.write_text(json.dumps(dict(phase=phase, plan_digest=digest,
                                              helper_digest=hashlib.sha256(helper.read_bytes()).hexdigest())))
        if cached is not None:
            self.cache.mkdir()
            for name, raw in cached.items():
                (self.cache / name).write_bytes(raw)
        for name, raw in self.expected.items():
            (self.downloads / name).write_bytes(raw)
        self.env = dict(PATH=f'{self.bin}:/usr/bin:/bin', RUNNER_TEMP=str(self.root), CAA_CACHE_HIT=hit,
                        ACTOR_LOG=str(self.log), FAKE_DOWNLOADS=str(self.downloads))

    def install_case(self):
        for step in ('Record restore timing and check cache misses',
                     'Install test prerequisites on disposable runner'):
            script, uses_hit = composite_step(step)
            env = dict(self.env)
            if not uses_hit:
                env.pop('CAA_CACHE_HIT')
            result = subprocess.run(['/bin/bash', '-euo', 'pipefail', '-c', script],
                                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=20)
            if result.returncode:
                break
        return result

    def events(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def receipt(self):
        return json.loads(self.state.read_text())

    def success(self):
        result = self.install_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(['install'], self.events())

    def refused(self, reason):
        result = self.install_case()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(reason, result.stderr)
        self.assertNotIn(['install'], self.events())

    def test_exact_hit_reads_and_copies_each_archive_once(self):
        self.expected = {NAME: b'A' * (4 * 1024**2), 'second_1_amd64.deb': b'B' * (2 * 1024**2)}
        self.setup_case(hit='true', cached=self.expected)
        self.success()
        totals = collections.Counter()
        for event in self.events():
            if event[0] in ('read', 'write'):
                kind, directory, count = event
                totals[kind, directory] += count
        size = 6 * 1024**2
        self.assertEqual(totals, {('read', self.cache.name): size, ('write', self.staged.name): size})
        for name, raw in self.expected.items():
            self.assertEqual((self.staged / name).read_bytes(), raw)

    def test_exact_hit_reports_staged_count_without_replacing_cache(self):
        self.setup_case(hit='true', cached=self.expected)
        before = (self.cache / NAME).stat()
        self.success()
        after = (self.cache / NAME).stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))
        self.assertEqual(self.receipt()['verified_before_install'], 1)

    def test_warm_exact_hit_requires_and_records_complete_stage(self):
        self.setup_case(phase='warm', hit='true', cached=self.expected)
        self.success()
        self.assertEqual((self.receipt()['cache_hit'], self.receipt()['archive_count'],
                          self.receipt()['verified_before_install']), ('true', 1, 1))

    def test_missing_warm_archive_refuses_before_install(self):
        self.setup_case(phase='warm', hit='true', cached={})
        self.refused('warm cache lacks complete verified archive set')

    def test_warm_miss_refuses_before_install(self):
        self.setup_case(phase='warm', hit='false', cached=self.expected)
        self.refused('warm sample requires an exact cache hit')

    def test_exact_hit_with_corruption_downloads_only_in_normal_mode(self):
        bad = b'X' * len(self.expected[NAME])
        self.setup_case(hit='true', cached={NAME: bad})
        self.success()
        self.assertIn(['download', NAME], self.events())
        self.assertEqual((self.cache / NAME).read_bytes(), bad)
        self.assertEqual(self.receipt()['verified_before_install'], 0)

    def test_cold_exact_hit_refuses_before_install(self):
        self.setup_case(phase='cold', hit='true', cached=self.expected)
        self.refused('cold sample restored archives')

    def test_cold_miss_exports_newly_downloaded_archives(self):
        self.setup_case(phase='cold')
        self.success()
        self.assertEqual((self.cache / NAME).read_bytes(), self.expected[NAME])
        self.assertEqual(self.receipt()['verified_before_install'], 0)
        self.assertIn(['download', NAME], self.events())

    def test_normal_exact_hit_permits_empty_plan(self):
        self.expected = {}
        self.setup_case(hit='true', cached={})
        self.success()
        self.assertEqual(self.receipt()['archive_count'], 0)
        self.assertEqual(list(self.staged.iterdir()), [])

    def test_plan_or_helper_drift_after_key_binding_refuses_exact_hit(self):
        self.setup_case(hit='true', cached=self.expected)
        state = self.receipt()
        for field, reason in (('plan_digest', 'archive plan changed'),
                              ('helper_digest', 'archive helper changed')):
            with self.subTest(field=field):
                self.state.write_text(json.dumps(dict(state, **{field: '0' * 64})))
                self.refused(reason + ' after cache key binding')


if __name__ == '__main__':
    unittest.main()

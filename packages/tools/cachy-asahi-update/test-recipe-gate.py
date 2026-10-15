#!/usr/bin/env python3
"""Execute only extracted gate function with mocked Python in private Bash."""
from pathlib import Path
import json
import os
import subprocess
import tempfile
import unittest


class GatePropagation(unittest.TestCase):
    def test_native_gate_failure_stops_before_source_verifier(self):
        text = Path(__file__).with_name('PKGBUILD').read_text()
        body = text.split('\n_review_gate() {\n', 1)[1].split('\n}\n', 1)[0]
        with tempfile.TemporaryDirectory(prefix='cachy-update-gate-fixture-') as tmp:
            root = Path(tmp)
            harness = r'''_review_python() {
  printf '%s\0' "$@" >> "$fixture_prefix"
  python "$@"
}
python() {
  printf '%s\n' "$1" >> "$fixture_log"
  case "$1" in */build-gate.py) return 23 ;; *) return 0 ;; esac
}
_review_gate() {
''' + body + '\n}\n_review_gate\n'
            result = subprocess.run(['/usr/bin/bash', '--noprofile', '--norc', '-c', harness],
                cwd=root, env={'PATH':'/usr/bin:/bin','srcdir':str(root),
                               'CACHY_ASAHI_CONTROLLER_SHA256':'fixture-not-native',
                               'fixture_log':str(root/'calls'), 'fixture_prefix':str(root/'prefix')}, capture_output=True)
            self.assertEqual(result.returncode, 23, result.stderr.decode())
            prefix = (root/'prefix').read_bytes().decode().split('\0')
            self.assertEqual(prefix[0], '/inputs/recipe/build-gate.py')
            self.assertEqual((root/'calls').read_text().splitlines(), ['/inputs/recipe/build-gate.py'])


def recipe_functions(text, names):
    """Extract top-level definitions only; never source the full PKGBUILD."""
    return '\n'.join(name + '() {\n' + text.split('\n' + name + '() {\n', 1)[1].split('\n}\n', 1)[0] + '\n}\n'
                     for name in names)


class MakepkgPhaseShell(unittest.TestCase):
    """Exact extracted functions; all external commands are harmless Bash stubs."""
    phases = ('prepare', 'build', 'check', 'package')
    contexts = ('ordinary', 'conditional', 'errexit')

    def expected_calls(self, root, phase):
        src, pkg = str(root / 'source'), str(root / 'package')
        tree = src + '/cachy-update-e2b1b7144be71cf392809f48d1440f8da1d9c81a'
        gate = [
            ['_review_python', '/inputs/recipe/build-gate.py', '--metadata', '/out/target-metadata/cargo-metadata.stdout',
             '--worker', '/out/target-metadata/worker.json', '--cfg', '/out/target-metadata/target-cfg.stdout',
             '--manifest', tree + '/src/tray/Cargo.toml', '--lock', tree + '/src/tray/Cargo.lock',
             '--cargo-audit', '/inputs/recipe/cargo-audit.json', '--vendor', src + '/vendor',
             '--build-script-review', '/inputs/recipe/build-script-review.json',
             '--additional-licenses', '/inputs/recipe/additional-cargo-licenses.json',
             '--controller-input', '/inputs/controller-input.json', '--controller-input-sha256', 'fixture-not-native'],
            ['python', '/inputs/recipe/verify-updater.py', '--source', tree]]
        if phase == 'prepare':
            return [['cp', '-a', tree, src + '/unpatched-source'],
                    ['patch', '--batch', '--forward', '--fuzz=0', '-d', tree, '-p1'],
                    ['patch', '--batch', '--forward', '--fuzz=0', '-d', tree, '-p1'],
                    ['install', '-dm700', src + '/cargo-home']]
        if phase == 'build':
            return [['python', '/inputs/recipe/worker-build.py', '--manifest', tree + '/src/tray/Cargo.toml',
                     '--vendor', src + '/vendor', '--cargo-audit', '/inputs/recipe/cargo-audit.json'],
                    gate[1], ['cd', tree], ['make', 'WITH_TRAY=false']]
        if phase == 'check':
            return gate + [
                ['python', '/inputs/recipe/test-patches.py', '--source', src + '/unpatched-source', '-v'],
                ['python', '/inputs/recipe/test-asahi-policy.py', '--source', src + '/unpatched-source', '-v'],
                ['install', '-dm700', src + '/check-home', src + '/check-runtime', src + '/check-config/arch-update',
                 src + '/check-data', src + '/check-state'], ['cd', tree], ['make', 'test'],
                ['python', '/inputs/recipe/build-gate.py', '--elf', 'src/tray/target/release/arch-update-tray']]
        return gate + [
            ['cd', tree], ['python', '/inputs/recipe/build-gate.py', '--elf', 'src/tray/target/release/arch-update-tray'],
            ['make', 'PREFIX=/usr', 'DESTDIR=' + pkg, 'WITH_TRAY=true', 'install'],
            ['ln', '-s', 'arch-update', pkg + '/usr/bin/cachy-asahi-update'],
            ['install', '-Dm755', '/inputs/recipe/asahi-policy.py', pkg + '/usr/lib/cachy-asahi-update/asahi-policy'],
            ['chmod', '644', pkg + '/usr/share/icons/hicolor/scalable/apps/cachy-update*.svg'],
            ['install', '-Dm644', 'LICENSE', pkg + '/usr/share/licenses/cachy-asahi-update/LICENSE'],
            *[['install', '-Dm644', '/inputs/recipe/ICON-LICENSE', pkg + '/usr/share/licenses/cachy-asahi-update/' + name]
              for name in ('ICON-LICENSE', 'PROJECT-MIT')],
            ['install', '-Dm644', '/inputs/recipe/NOTICE', pkg + '/usr/share/licenses/cachy-asahi-update/NOTICE'],
            ['python', '/inputs/recipe/verify-updater.py', '--materialize-notices', src + '/verified-LICENSES'],
            ['cp', '-r', src + '/verified-LICENSES', pkg + '/usr/share/licenses/cachy-asahi-update/cargo'],
            ['install', '-Dm644', '/inputs/recipe/README.md', pkg + '/usr/share/doc/cachy-asahi-update/README.md'],
            *[['install', '-Dm644', '/inputs/recipe/' + name, pkg + '/usr/share/doc/cachy-asahi-update/' + name]
              for name in ('source-audit.json', 'cargo-audit.json', 'additional-cargo-licenses.json', 'build-policy.json')]]

    def run_shell(self, root, phase, context='ordinary', fail_at=0, status=23,
                  report_status=0, guard='1', blocked_redirect=False, text=None, recipe_load=False):
        src = root / 'source'
        for relative in ('cargo-home', 'check-config/arch-update', 'check-home', 'check-runtime',
                         'check-data', 'check-state'):
            (src / relative).mkdir(parents=True, exist_ok=True)
        for name in ('behavior.patch', 'apple-policy.patch'):
            (src / name).write_text('')
        if blocked_redirect:
            destination = src / ('cargo-home/config.toml' if phase == 'prepare'
                                 else 'check-config/arch-update/arch-update.conf')
            destination.mkdir()
        text = text if text is not None else Path(__file__).with_name('PKGBUILD').read_text()
        if recipe_load:
            # This suffix contains definitions and the two markers, no package metadata/source arrays.
            definitions = '_makepkg_phase() {\n' + text.split('\n_makepkg_phase() {\n', 1)[1]
        else:
            names = (['_makepkg_phase', '_makepkg_exit'] if '\n_makepkg_phase() {\n' in text else [])
            definitions = recipe_functions(text, names + ['_review_gate', *self.phases])
        prelude = r'''_fixture_count=0
_fixture_record() {
    local target=$1 name=$2; shift 2
    printf '%s\0' "$name" "$#" "$@" >> "$target"
}
_fixture_command() {
    _fixture_count=$((_fixture_count + 1))
    _fixture_record "$fixture_calls" "$@"
    if [[ $_fixture_count == "$fixture_fail_at" ]]; then return "$fixture_status"; fi
    return 0
}
python() { _fixture_command python "$@"; }
_review_python() { _fixture_command _review_python "$@"; }
cp() { _fixture_command cp "$@"; }
patch() { _fixture_command patch "$@"; }
install() { _fixture_command install "$@"; }
make() { _fixture_command make "$@"; }
ln() { _fixture_command ln "$@"; }
chmod() { _fixture_command chmod "$@"; }
cd() { _fixture_command cd "$@"; }
/usr/bin/python() {
    _fixture_record "$fixture_markers" diagnostic-python "$@"
    printf 'FIXTURE_DIAGNOSTIC_PRIVATE_STDOUT'
    printf 'FIXTURE_DIAGNOSTIC_PRIVATE_STDERR' >&2
    return "$fixture_report_status"
}
'''
        invocation = ':' if recipe_load else phase
        if context == 'conditional':
            tail = 'if ' + invocation + '; then result=0; else result=$?; fi\nexit "$result"\n'
        else:
            tail = invocation + '\nresult=$?\nexit "$result"\n'
        script = ('set -e\n' if context == 'errexit' else '') + prelude + definitions + tail
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'srcdir': str(src),
               'pkgdir': str(root / 'package'), 'pkgname': 'cachy-asahi-update',
               'CACHY_ASAHI_CONTROLLER_SHA256': 'fixture-not-native',
               'fixture_calls': str(root / 'calls'), 'fixture_markers': str(root / 'markers'),
               'fixture_fail_at': str(fail_at), 'fixture_status': str(status),
               'fixture_report_status': str(report_status)}
        if guard is not None:
            env['CACHY_ASAHI_MAKEPKG_DIAGNOSTIC'] = guard
        result = subprocess.run(['/usr/bin/bash', '--noprofile', '--norc', '-c', script],
                                cwd=root, env=env, capture_output=True, timeout=10)
        def records(path):
            if not path.exists():
                return []
            fields = path.read_bytes().decode().split('\0')
            self.assertEqual(fields.pop(), '')
            rows = []
            while fields:
                name, count, *fields = fields
                count = int(count)
                rows.append([name, *fields[:count]])
                fields = fields[count:]
            return rows
        for channel in (result.stdout, result.stderr):
            self.assertNotIn(b'FIXTURE_DIAGNOSTIC_PRIVATE', channel)
        return result, records(root / 'calls'), records(root / 'markers')

    def markers(self, phase, code):
        return [['diagnostic-python', '/inputs/recipe/worker-diagnostic.py', '--makepkg-phase', phase, 'enter', 'null'],
                ['diagnostic-python', '/inputs/recipe/worker-diagnostic.py', '--makepkg-phase', phase, 'return', str(code)]]

    def test_success_preserves_exact_command_arguments_and_config_writes(self):
        for phase in self.phases:
            for context in self.contexts:
                with self.subTest(phase=phase, context=context), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    result, calls, markers = self.run_shell(root, phase, context)
                    self.assertEqual(result.returncode, 0, result.stderr.decode())
                    self.assertEqual(calls, self.expected_calls(root, phase))
                    self.assertEqual(markers, self.markers(phase, 0))
                    self.assertEqual(result.stdout, b'')
                    self.assertEqual(result.stderr, b'')
                    if phase == 'prepare':
                        self.assertEqual((root / 'source/cargo-home/config.toml').read_text(),
                            '[source.crates-io]\nreplace-with = "vendored-sources"\n[source.vendored-sources]\ndirectory = "' + str(root / 'source/vendor') + '"\n')
                    if phase == 'check':
                        self.assertEqual((root / 'source/check-config/arch-update/arch-update.conf').read_text(),
                                         'NoAUR\nNoFlatpak\nNoALHPCheck\nNoNotification\n')

    def test_each_external_failure_preserves_status_and_stops_later_commands(self):
        # 130/143 are returned statuses only: no claim to exercise signal delivery or cancellation.
        for phase in self.phases:
            count = len(self.expected_calls(Path('/fixture'), phase))
            for fail_at in range(1, count + 1):
                status = (4, 23, 127, 130, 143)[(fail_at - 1) % 5]
                for context in self.contexts:
                    with self.subTest(phase=phase, fail_at=fail_at, status=status, context=context), tempfile.TemporaryDirectory() as tmp:
                        root = Path(tmp)
                        result, calls, markers = self.run_shell(root, phase, context, fail_at, status)
                        self.assertEqual(result.returncode, status, result.stderr.decode())
                        self.assertEqual(calls, self.expected_calls(root, phase)[:fail_at])
                        self.assertEqual(markers, self.markers(phase, status))

    def test_reporting_failure_does_not_change_success_or_first_command_failure(self):
        for phase in self.phases:
            for report_status in (4, 127, 130, 143):
                for fail_at, status in ((0, 0), (1, 23)):
                    with self.subTest(phase=phase, reporter=report_status, fail_at=fail_at), tempfile.TemporaryDirectory() as tmp:
                        root = Path(tmp)
                        result, calls, markers = self.run_shell(root, phase, 'errexit', fail_at, status, report_status)
                        self.assertEqual(result.returncode, status, result.stderr.decode())
                        expected = self.expected_calls(root, phase)
                        self.assertEqual(calls, expected if not fail_at else expected[:fail_at])
                        self.assertEqual(markers, self.markers(phase, status))

    def test_unset_or_nonexact_enable_flag_makes_no_helper_calls(self):
        for guard in (None, '0', '01', 'true', ' 1'):
            for phase in self.phases:
                for position in ('success', 'first', 'last'):
                    with self.subTest(phase=phase, guard=guard, position=position), tempfile.TemporaryDirectory() as tmp:
                        root = Path(tmp)
                        expected = self.expected_calls(root, phase)
                        fail_at = {'success': 0, 'first': 1, 'last': len(expected)}[position]
                        result, calls, markers = self.run_shell(root, phase, 'errexit', fail_at, 23, guard=guard)
                        self.assertEqual(result.returncode, 23 if fail_at else 0, result.stderr.decode())
                        self.assertEqual(calls, expected[:fail_at] if fail_at else expected)
                        self.assertEqual(markers, [])

    def test_redirect_failure_reports_original_status_without_later_commands(self):
        for phase, count in (('prepare', 4), ('check', 5)):
            for context in self.contexts:
                with self.subTest(phase=phase, context=context), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    result, calls, markers = self.run_shell(root, phase, context, blocked_redirect=True)
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(calls, self.expected_calls(root, phase)[:count])
                    self.assertEqual(markers, self.markers(phase, 1))

    def test_recipe_load_markers_are_best_effort_without_running_recipe_functions(self):
        for guard, report in (('1', 0), ('1', 127), (None, 0)):
            with self.subTest(guard=guard, reporter=report), tempfile.TemporaryDirectory() as tmp:
                result, calls, markers = self.run_shell(Path(tmp), 'recipe-load', 'errexit',
                                                       report_status=report, guard=guard, recipe_load=True)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(calls, [])
                self.assertEqual(markers, self.markers('recipe-load', 0) if guard == '1' else [])






class ScopedLoaderEnvironment(unittest.TestCase):
    """Exact child helper, owned inert probes only; never launch a product gate."""
    def definition(self):
        text=Path(__file__).with_name('PKGBUILD').read_text()
        body=text.split('\n_review_python() (\n',1)[1].split('\n)\n',1)[0]
        self.assertEqual(body.strip(), 'unset "${!LD_@}" FAKEROOTKEY || return\n    exec /usr/bin/python -I -B "$@"')
        return '_review_python() (\n'+body+'\n)\n'

    def run_probe(self, root, setup='', readonly=False):
        probe=root/'inert-probe.py'; poison=root/'poison'; poison.mkdir()
        (poison/'sitecustomize.py').write_text('raise RuntimeError("OWNED_POISON_SITE")\n')
        (poison/'json.py').write_text('raise RuntimeError("OWNED_POISON_JSON")\n')
        (poison/'cachy_owned_loader_poison.py').write_text('raise RuntimeError("OWNED_POISON_MODULE")\n')
        cache=root/'cache'; cache.mkdir()
        probe.write_text('import importlib.util,json,os,sys\n'
            'keys=["CACHY_ASAHI_CONTROLLER_SHA256","CACHY_ASAHI_IMAGE_ID","CACHY_ASAHI_UPDATE_BUILD_NONCE","UNRELATED","HOME","TMPDIR"]\n'
            'value=dict(loader={k:v for k,v in os.environ.items() if k.startswith("LD_") or k=="FAKEROOTKEY"},'
            'bindings={k:os.environ.get(k) for k in keys},args=sys.argv[1:],isolated=sys.flags.isolated,'
            'dontwrite=sys.flags.dont_write_bytecode,pycache_prefix=sys.pycache_prefix,'
            'poison_found=importlib.util.find_spec("cachy_owned_loader_poison") is not None)\n'
            'print(json.dumps(value,sort_keys=True))\n')
        env=dict(PATH='/usr/bin:/bin',HOME=str(root),TMPDIR=str(root),
                 CACHY_ASAHI_CONTROLLER_SHA256='a'*64,CACHY_ASAHI_IMAGE_ID='sha256:'+'b'*64,
                 CACHY_ASAHI_UPDATE_BUILD_NONCE='c'*32,UNRELATED='preserved',
                 OWNED_POISON=str(poison),OWNED_CACHE=str(cache),OWNED_PROBE=str(probe))
        # The process starts clean. Poison is assigned using Bash builtins only
        # after startup, and removed in the helper before the next executable.
        parent=dict(os.environ)
        script=self.definition()+setup+'\n'
        script+='before=$(export -p)\n'
        script+='if _review_python "$OWNED_PROBE" --fixture "literal value" --end; then status=0; else status=$?; fi\n'
        script+='[[ "$(export -p)" == "$before" ]] || exit 91\nexit "$status"\n'
        result=subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c',script],cwd=root,env=env,capture_output=True,timeout=10)
        self.assertEqual(dict(os.environ),parent)
        self.assertEqual(list(root.rglob('__pycache__')),[])
        self.assertEqual(list(cache.iterdir()),[])
        if readonly:
            self.assertNotEqual(result.returncode,0)
            self.assertEqual(result.stdout,b'')
            self.assertIn(b'readonly',result.stderr)
            return
        self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(result.stderr,b'')
        value=json.loads(result.stdout);self.assertEqual(value['loader'],{})
        self.assertEqual(value['isolated'],1);self.assertEqual(value['dontwrite'],1)
        self.assertIsNone(value['pycache_prefix']);self.assertFalse(value['poison_found'])
        self.assertEqual(value['args'],['--fixture','literal value','--end'])
        self.assertEqual(value['bindings'],{k:env[k] for k in value['bindings']})

    def test_complete_loader_namespace_removed_and_python_poison_ignored_before_probe(self):
        setup=r'''
export LD_PRELOAD=OWNED_NOT_A_LIBRARY LD_LIBRARY_PATH="$OWNED_POISON"
export LD_AUDIT=OWNED_NOT_AN_AUDITOR LD_DEBUG=OWNED_NOT_DEBUG LD_ORIGIN_PATH="$OWNED_POISON"
export LD_BIND_NOW=1 LD_FUTURE_SENTINEL=OWNED_POISON FAKEROOTKEY=OWNED_INERT_KEY
export PYTHONPATH="$OWNED_POISON" PYTHONHOME="$OWNED_POISON" PYTHONUSERBASE="$OWNED_POISON"
export PYTHONPYCACHEPREFIX="$OWNED_CACHE" PYTHONINSPECT=1 PYTHONSTARTUP="$OWNED_POISON/sitecustomize.py"
'''
        with tempfile.TemporaryDirectory(prefix='gate-loader-owned-') as tmp:self.run_probe(Path(tmp),setup)

    def test_readonly_loader_variable_refuses_before_python_probe(self):
        setup='export LD_PRELOAD=OWNED_MUST_NOT_LOAD\nreadonly LD_PRELOAD\n'
        with tempfile.TemporaryDirectory(prefix='gate-loader-readonly-') as tmp:self.run_probe(Path(tmp),setup,readonly=True)

    def test_no_loader_variables_is_accepted_without_changing_parent_bindings(self):
        with tempfile.TemporaryDirectory(prefix='gate-loader-clean-') as tmp:self.run_probe(Path(tmp))


if __name__ == '__main__':
    unittest.main()

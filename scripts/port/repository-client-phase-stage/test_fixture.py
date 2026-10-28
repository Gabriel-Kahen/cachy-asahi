#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""MODELED native observations combined with actual ephemeral TEST cryptography.

No Docker/native/pacman installation or hardware observation occurs here. Only
local GPG/repo-add execution is real. Test source-string transforms adapt version
labels and probe layout; they never change production collector/gate sources.
"""
from contextlib import contextmanager
import copy
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import types

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).parent
OLD_TEST_SHA = '1a853e04081694554b63475d85237754f2b6ea638f9b4266a47f9cc66db16c51'
CRYPTO_TEST_SHA = '78da74747e44956dd1c41bc781ac8ff897bb46c2150efaf7d1de8ab78affc505'


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


@contextmanager
def aliases(modules):
    previous = {name: sys.modules.get(name) for name in modules}
    sys.modules.update(modules)
    try:
        yield
    finally:
        for name, old in previous.items():
            if old is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old


def compile_module(name, path, raw=None):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(path.read_bytes() if raw is None else raw, str(path), 'exec'), module.__dict__)
    return module


def modules():
    """Verify frozen dependencies before test helpers import collector namespaces."""
    dependencies = compile_module('phase_fixture_dependencies', HERE / 'dependencies.py')
    collector = dependencies.load_collector(ROOT)
    old_path = ROOT / 'scripts/port/repository-client-stage/gate.py'
    old_gate = compile_module('controlled_frozen_v1_gate', old_path, dependencies.predecessor(ROOT, str(old_path.relative_to(ROOT))))
    old_test_path = old_path.with_name('test_gate.py')
    old_raw = old_test_path.read_bytes()
    assert digest(old_raw) == OLD_TEST_SHA, 'frozen old fixture source drift'
    with aliases({'gate': old_gate}):
        old_tests = compile_module('controlled_frozen_v1_tests', old_test_path, old_raw)
    with aliases({'dependencies': dependencies}):
        phases = compile_module('phase_fixture_phases', HERE / 'phases.py')
    with aliases({'dependencies': dependencies, 'phases': phases}):
        gate = compile_module('phase_fixture_gate', HERE / 'gate.py')
    return dependencies, collector, old_gate, old_tests, phases, gate


def real_template(root, collector):
    path = ROOT / 'scripts/port/repository-client-native/test_crypto.py'
    raw = path.read_bytes()
    assert digest(raw) == CRYPTO_TEST_SHA, 'reviewed crypto fixture source drift'
    source = raw.decode()
    anchor = '            for name in sorted(crypto.ORIGINALS | {crypto.PROBE}):\n'
    assert source.count(anchor) == 1
    source = source.replace(anchor, anchor + "                package_version = version if name == crypto.PROBE else ('0.1.0-1' if version == '1-1' else '0.1.1-1')\n")
    assert source.count('pkgver = {version}') == 1
    source = source.replace('pkgver = {version}', 'pkgver = {package_version}')
    anchor = "filename = name + '-' + version + '-any.pkg.tar.xz'"
    assert source.count(anchor) == 1
    source = source.replace(anchor, "filename = name + '-' + package_version + '-any.pkg.tar.xz'")
    anchor = "'usr/share/' + name + '/fixture.txt': value"
    assert source.count(anchor) == 1
    source = source.replace(anchor, "('usr/share/cachy-asahi-repository-TEST/fixture.txt' if name == crypto.PROBE else 'usr/share/' + name + '/fixture.txt'): value")
    with aliases({'crypto': collector['crypto'], 'common': collector['common']}):
        helper = compile_module('controlled_real_crypto_fixture', path, source.encode())
    class CapturedFixture(helper.RealFixture):
        def __init__(self, root):
            self.actual_cli_observations = []
            super().__init__(root)
        def run(self, argv, *args, **kwargs):
            result = super().run(argv, *args, **kwargs)
            if '--status-fd' in argv and '--verify' in argv:
                self.actual_cli_observations.append({'argv': list(argv), 'stdout': result[0], 'stderr': result[1], 'exit_code': result[2]})
            return result
    return CapturedFixture(root)


class PhaseFixture:
    """All native receipts/argv are explicitly MODELED; signature bytes are real."""
    def __init__(self, root, template=None):
        self.root = Path(root)
        self.dependencies, self.collector, self.old_gate, self.old_tests, self.phases, self.gate = modules()
        self.temporary = None
        if template is None:
            self.temporary = tempfile.TemporaryDirectory(prefix='MODELED-native-real-TEST-crypto-')
            template = real_template(Path(self.temporary.name), self.collector)
        self.template = template
        self.old = self.old_tests.Fixture(self.root)
        self.data, self.refs, self.authority = self.old.data, self.old.refs, self.old.authority
        self.commit, self.recipe_commit = self.old.commit, self.old.recipe_commit
        self.base, self.rows, self.payloads = self.old.base, self.old.rows, self.old.payloads
        self.nonce, self.image = self.old.nonce, self.old.image
        try:
            self._combine()
            self._attest()
        except BaseException:
            self.close()
            raise

    def __getattr__(self, name):
        return getattr(self.old, name)

    @property
    def repository(self):
        return json.loads(self.data[self.refs['repository']])

    @property
    def files(self):
        return self.authority['files']

    def get(self, name):
        return self.data[name]

    def clone(self, root):
        """Copy public fixture bytes; never copy the ephemeral private key homes."""
        fixture = object.__new__(type(self))
        for name in ('dependencies', 'collector', 'old_gate', 'old_tests', 'phases', 'gate', 'template'):
            setattr(fixture, name, getattr(self, name))
        fixture.root, fixture.temporary = Path(root), None
        fixture.old = object.__new__(type(self.old))
        fixture.old.__dict__.update(copy.deepcopy(self.old.__dict__))
        fixture.old.root = fixture.root
        for name in ('data', 'refs', 'authority', 'base', 'rows', 'payloads', 'commit', 'recipe_commit', 'nonce', 'image'):
            setattr(fixture, name, getattr(fixture.old, name))
        fixture.request, fixture.receipt = copy.deepcopy(self.request), copy.deepcopy(self.receipt)
        fixture.root.mkdir(parents=True, exist_ok=True)
        for name, raw in fixture.data.items():
            path = fixture.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        return fixture

    def rebind_phase(self, role, mutate):
        """Coherent test-only reference rebinding, without promoting fake crypto."""
        reference = self.authority['crypto'][role]
        value = json.loads(self.data[reference['path']])
        mutate(value)
        raw = encoded(value)
        self.put(reference['path'], raw)
        reference.update(sha256=digest(raw), bytes=len(raw))
        setattr(self, role, value)
        self.refresh()

    def close(self):
        if self.temporary is not None:
            try:
                self.template.close()
            finally:
                self.temporary.cleanup()
                self.temporary = None

    def put(self, name, raw):
        self.old.put(name, raw)

    def refresh(self):
        self.old.refresh()

    def change(self, role, change):
        self.old.change(role, change)

    def _combine(self):
        # Replace every old synthetic public archive/certificate with actual bytes.
        for name in list(self.data):
            if name.startswith('public/') and name != self.refs['public_manifest']:
                del self.data[name]
                (self.root / name).unlink()
        for path in self.template.inputs.rglob('*'):
            if path.is_file() and not path.relative_to(self.template.inputs).as_posix().startswith('native/'):
                self.put('public/' + path.relative_to(self.template.inputs).as_posix(), path.read_bytes())
        public = {name[7:]: {'sha256': digest(raw), 'bytes': len(raw)} for name, raw in self.data.items()
                  if name.startswith('public/') and name != self.refs['public_manifest']}
        for phase, label in (('baseline', 'baseline-A'), ('upgrade', 'updated-B')):
            self.payloads[phase].clear()
            for row in self.rows[phase]:
                name = 'public/TEST-repositories/' + label + '/' + Path(row['archive']).name
                raw = self.data[name]
                with tarfile.open(fileobj=io.BytesIO(raw), mode='r:xz') as archive:
                    payloads = {member.name: digest(archive.extractfile(member).read()) for member in archive.getmembers()
                                if member.isfile() and not member.name.startswith('.')}
                row.update(sha256=digest(raw), payload_sha256=payloads)
                self.payloads[phase].update(payloads)
        contract = json.loads(self.data[self.refs['repository_contract']])
        contract.update(self.rows)
        self.put(self.refs['repository_contract'], encoded(contract))
        repository = json.loads(self.data[self.refs['repository']])
        repository['original_inputs'] = {phase: {row['name']: {key: row[key] for key in ('sha256', 'version')} for row in rows}
                                         for phase, rows in self.rows.items()}
        repository['public_TEST_identities'] = {role: {'fingerprint': value['fingerprint'],
            'public_sha256': public[value['certificate']]['sha256']} for role, value in self.template.keys.items()}
        repository['final_sync_cache'] = {name: public['TEST-repositories/updated-B/' + target]['sha256'] for name, target in
            (('integration.db', 'integration.db.tar.gz'), ('integration.db.sig', 'integration.db.tar.gz.sig'))}
        # Native install snapshots remain MODELED, now bound to actual payload bytes.
        state, previous = None, {'inventory': self.old.inventory(None), 'files': {name: {'type': 'missing'} for name in self.old.owned()}}
        for case, negative in self.old_gate.CASES:
            if not negative:
                state = 'baseline' if case in ('trusted-baseline-full-install', 'full-rollback-to-retained-A') else 'upgrade'
            hashes = {} if state is None else self.payloads[state] | {self.old.probe_path(): digest(
                f'SYNTHETIC TEST fixture version {1 if state == "baseline" else 2}\n'.encode())}
            after = {'inventory': self.old.inventory(state), 'files': {name: {'type': 'regular', 'sha256': hashes[name],
                'uid': 0, 'gid': 0, 'mode': 0o644} if name in hashes else {'type': 'missing'} for name in self.old.owned()}}
            self.put('raw/' + case + '-before-snapshot.json', encoded(previous))
            self.put('raw/' + case + '-after-snapshot.json', encoded(after))
            previous = after
        snapshot = self.data['raw/revoked-A-repository-rejected-after-snapshot.json']
        for suffix in ('before', 'after'):
            self.put('raw/revoked-A-sync-cache-reset-' + suffix + '-snapshot.json', snapshot)
        for command in repository['commands']:
            if command['label'].startswith('inventory-revoked-A-sync-cache-reset-'):
                self.put('raw/' + command['log'], self.old.inventory('baseline').encode())
                command['sha256'] = digest(self.data['raw/' + command['log']])
        # Preserve genuine local GPG status facts, with explicitly MODELED native
        # /test-home and /scratch argv so the exact producer contract is exercised.
        native = []
        prefix = []
        captured = {row['argv'][-1]: row for row in self.template.actual_cli_observations}
        def append_command(commands, label, argv, stdout, stderr=b'', exit_code=0, expected=0):
            index = len(commands)
            log, error = f'{index:03d}-{label}.txt', f'{index:03d}-{label}-stderr.txt'
            self.put('raw/' + log, stdout)
            self.put('raw/' + error, stderr)
            commands.append({'label': label, 'argv': argv, 'log': log, 'sha256': digest(stdout), 'stderr_log': error,
                             'stderr_sha256': digest(stderr), 'exit_code': exit_code, 'expected': expected})
            return index, 'raw/' + log
        for obj in self.template.objects:
            if obj['path'] == 'TEST-repository-aliases.json':
                continue
            role, path = obj['signer'], 'public/' + obj['path']
            target, label = self.phases.native_target(path, 'public/', role)
            local = str(self.template.inputs / obj['path'])
            # Baseline DB verification also has a later revoked observation; use
            # the retained positive log, never the last matching command output.
            original = next(row for row in self.template.observations if row['path'] == obj['path'])
            status = (self.template.inputs / original['status_log']).read_bytes()
            actual = next(row for row in self.template.actual_cli_observations if row['argv'][-1] == local and row['stdout'] == status)
            index, log = append_command(prefix, label, self.phases.native_argv(role, target), status, actual['stderr'])
            native.append({'path': path, 'status_log': log, 'exit_code': 0, 'command_index': index,
                           'native_phase': original['native_phase']})
        old_commands = repository['commands']
        commands = prefix
        for old in old_commands:
            label = old['label']
            argv = list(old['argv'])
            stdout, stderr = self.data['raw/' + old['log']], self.data.get('raw/' + old.get('stderr_log', ''), b'')
            if label in ('revoke-A-signing-home', 'revoke-A-verification-home'):
                role = 'signer-A' if label == 'revoke-A-signing-home' else 'verifier'
                argv = self.phases.native_argv(role, 'unused')[:9] + ['--import', '/test-home/TEST-revocation.asc']
            if label == 'gpg-revoked-A-status':
                stdout = (self.template.inputs / self.template.revocation['status_log']).read_bytes()
                argv = self.phases.native_argv('verifier', '/scratch/repos/baseline-A/integration.db.tar.gz')
            old_log = old['log']
            index, log = append_command(commands, label, argv, stdout, stderr, old['exit_code'], old['expected'])
            for key in ('positive_diagnostics', 'signature_rejection_kind'):
                if key in old:
                    commands[-1][key] = old[key]
            # Remove stale raw numbered logs; projected aliases are rebuilt below.
            if 'raw/' + old_log != log:
                self.data.pop('raw/' + old_log, None)
                (self.root / 'raw' / old_log).unlink(missing_ok=True)
            if old.get('stderr_log') and old['stderr_log'] != commands[-1]['stderr_log']:
                self.data.pop('raw/' + old['stderr_log'], None)
                (self.root / 'raw' / old['stderr_log']).unlink(missing_ok=True)
            if label == 'gpg-revoked-A-status':
                revoked = {'status_log': log, 'exit_code': old['exit_code'], 'command_index': index}
        obj = next(row for row in self.template.objects if row['path'] == 'TEST-repository-aliases.json')
        observed = next(row for row in self.template.observations if row['path'] == obj['path'])
        status = (self.template.inputs / observed['status_log']).read_bytes()
        actual = captured[str(self.template.inputs / obj['path'])]
        target, label = self.phases.native_target('public/' + obj['path'], 'public/', obj['signer'])
        index, log = append_command(commands, label, self.phases.native_argv(obj['signer'], target), status, actual['stderr'])
        native.append({'path': 'public/' + obj['path'], 'status_log': log, 'exit_code': 0, 'command_index': index,
                       'native_phase': observed['native_phase']})
        repository['commands'] = commands
        reset = json.loads(self.data[self.refs['reset']])
        reset['removed'] = {name: public['TEST-repositories/baseline-A/' + target]['sha256'] for name, target in
            (('integration.db', 'integration.db.tar.gz'), ('integration.db.sig', 'integration.db.tar.gz.sig'))}
        reset['revocation_status_log_sha256'] = digest(self.data[revoked['status_log']])
        reset['prior_rejection_log_sha256'] = next(row['sha256'] for row in commands if row['label'] == 'revoked-A-repository-rejected')
        self.put(self.refs['reset'], encoded(reset))
        repository['sync_cache_reset']['sha256'] = digest(self.data[self.refs['reset']])
        self.put('raw/TEST-repository-aliases.json', self.data['public/TEST-repository-aliases.json'])
        self.put(self.refs['repository'], encoded(repository))
        # Old projected logs are no longer inputs once command indices change.
        folder = Path(self.refs['projected_repository']).parent
        projected = json.loads(self.data[self.refs['projected_repository']])
        stale = {row[field] for row in projected['commands'] for field in ('public_log', 'public_stderr_log') if field in row}
        stale |= {projected['sync_cache_reset']['public_receipt'], projected['public_operation_index']}
        for alias in stale:
            name = (folder / alias).as_posix()
            self.data.pop(name, None)
            (self.root / name).unlink(missing_ok=True)
        self.old.bind_native()
        self.old.project()
        manifest = json.loads(self.data[self.refs['public_manifest']])
        manifest['files'] = public
        self.put(self.refs['public_manifest'], encoded(manifest))
        self.change('public_acceptance', lambda value: value.update(manifest_sha256=digest(self.data[self.refs['public_manifest']])))
        self.authority['archives'] = [{'name': row['name'], 'path': 'public/TEST-repositories/updated-B/' + Path(row['archive']).name,
            'version': row['version'], 'sha256': row['sha256'], 'bytes': len(self.data['public/TEST-repositories/updated-B/' + Path(row['archive']).name])}
            for row in self.rows['upgrade']]
        self.request = copy.deepcopy(self.template.request)
        self.request.update(source_commit=self.commit, run_id='123', nonce=self.nonce, image_id=self.image, public_prefix='public')
        self.request['signers'] = {role: {key: ('public/' + value if key.endswith('certificate') else value)
            for key, value in row.items()} for role, row in self.template.keys.items()}
        self.request['signed_objects'] = sorted([{**obj, 'path': 'public/' + obj['path'], 'signature': 'public/' + obj['signature']}
                                               for obj in self.template.objects], key=lambda row: row['path'])
        self.request['native_verifications'], self.request['native_revocation'] = native, revoked
        mapped = {row['status_log'] for row in native} | {revoked['status_log']} | {'public/' + name for name in public}
        self.request['files'] = {name: {'sha256': digest(self.data[name]), 'bytes': len(self.data[name])} for name in sorted(mapped)}
        self.refresh()

    def _attest(self):
        request_name, receipt_name = 'control/phase-request.json', 'control/phase-receipt.json'
        self.put(request_name, encoded(self.request))
        temporary = tempfile.TemporaryDirectory(prefix='MODELED-input-real-GPG-attestation-')
        try:
            root = Path(temporary.name)
            inputs = root / 'inputs'; inputs.mkdir()
            for name in self.request['files']:
                path = inputs / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(self.data[name])
            self.receipt = self.collector['crypto'].attest(inputs, self.data[request_name], digest(self.data[request_name]), root / 'output')
            assert self.receipt['status'] == 'PASS', self.receipt
            self.put(receipt_name, encoded(self.receipt))
        finally:
            temporary.cleanup()
        self.authority.update(schema_version=2, purpose='accepted-repository-client-inputs', crypto={
            'schema_version': 2, 'purpose': 'external-repository-cryptographic-phase-acceptance', 'status': 'PASS',
            'request': {'path': request_name, 'sha256': digest(self.data[request_name]), 'bytes': len(self.data[request_name])},
            'receipt': {'path': receipt_name, 'sha256': digest(self.data[receipt_name]), 'bytes': len(self.data[receipt_name])}})
        self.refresh()

    def accept(self):
        raw = encoded(self.authority)
        with aliases({'dependencies': self.dependencies}):
            return self.gate.accept(self.root, raw, digest(raw), repo_root=ROOT)

    def metadata(self):
        """Complete but FABRICATED generic metadata, never collected/native proof."""
        snapshot = 'SYNTHETIC-complete-phase-generic-base'
        license_text = 'SYNTHETIC test license only; no distribution acceptance.\n'
        protected = next(iter(sorted(self.base)))
        return {'schema_version': 1, 'purpose': 'reviewed-generic-restage-metadata', 'development_only': True,
            'platform_scope': 'generic-builder-only', 'acceptance_sha256': digest(encoded(self.authority)),
            'source_commit': self.recipe_commit, 'base': {'schema_version': 1, 'snapshot_id': snapshot,
            'target_arch': 'aarch64', 'kind': 'complete-target-transaction', 'fixture_scope': 'FABRICATED-METADATA-NOT-NATIVE',
            'packages': [{'name': name, 'version': version, 'arch': 'aarch64', 'depend': [], 'provides': [], 'conflict': [],
                          'files': ['SYNTHETIC/base/' + name]} for name, version in sorted(self.base.items())]},
            'policy': {'selected_packages': sorted(self.old_gate.ORIGINALS), 'supported_models': [],
                'protected_packages': [protected], 'coordinated_sets': [{'name': 'SYNTHETIC-base', 'versions': {protected: self.base[protected]}}]},
            'project_license': {'spdx': 'MIT', 'text': license_text, 'sha256': digest(license_text.encode())},
            'provenance': {row['name']: {'schema_version': 1, 'artifact_sha256': row['sha256'], 'source_commit': self.recipe_commit,
                'recipe_sha256': 'b' * 64, 'package': {'name': row['name'], 'version': row['version'], 'arch': 'any'},
                'licenses': ['MIT'], 'sources': [{'url': 'fixture://SYNTHETIC-not-retrievable/' + row['name'], 'sha256': 'c' * 64}],
                'build': {'execution': 'synthetic', 'architecture': 'aarch64', 'environment': 'SYNTHETIC-not-native', 'snapshot_id': snapshot}}
                for row in self.authority['archives']}}

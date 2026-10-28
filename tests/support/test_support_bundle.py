#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Original offline fixtures and CLI controls; no hardware acceptance."""
from collections import Counter
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve()
ROOT = next(p for p in HERE.parents if (p / 'scripts/hardware/session_probe.py').is_file())
PROPOSED = next((p for p in HERE.parents if (p / 'scripts/support/support_bundle.py').is_file()), ROOT)
SCRIPT = PROPOSED / 'scripts/support/support_bundle.py'
SPEC = importlib.util.spec_from_file_location('support_bundle', SCRIPT)
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)
D, _ = B.load_current('packages/tools/cachy-asahi-doctor2/cachy-asahi-doctor', 'fixture_doctor')
S, _ = B.load_current('scripts/hardware/session_probe.py', 'fixture_session')
IDENTITY = dict(release_id='synthetic-support-demo', release_sha256='a' * 64, source_commit='b' * 40)
STAMP = '2026-10-27T12:00:00+00:00'
PRIVATE = '/home/PRIVATE-USER/SSID-SECRET 192.0.2.19 --token=SECRET'

def coverage(report):
    report['coverage'] = dict(Counter(row['state'] for row in report['checks']))
    if 'tool' in report:
        report['coverage'] = {state: report['coverage'].get(state, 0) for state in B.STATES}
    return report

def doctor_fixture():
    rows = [D.item('platform', 'checked', dict(architecture='aarch64', kernel='PRIVATE-USER', page_size_bytes=16384), PRIVATE),
            D.item('apple-model', 'checked', dict(identifier='apple,j413', observed_board='apple,j413', model=D.MODELS['apple,j413'], model_property_available=True), PRIVATE),
            D.item('session', 'unknown', dict(type='unknown', wayland_environment=False, hyprland_environment=False), PRIVATE),
            D.item('tools', 'checked', dict.fromkeys(D.TOOLS, False), PRIVATE)]
    for group, names in D.PACKAGES.items():
        rows.extend(D.item('package/' + name, 'checked', dict(group=group, presence='present', version='PRIVATE-USER'), PRIVATE) for name in names)
    for scope, units in D.UNITS.items():
        rows.extend(D.item(scope + '/' + unit, 'checked', dict(LoadState='loaded', ActiveState='failed', SubState='private-user'), PRIVATE) for unit in units)
    rows.append(D.item('audio/default-output', 'unavailable', None, PRIVATE))
    return coverage(dict(schema_version=1, tool='cachy-asahi-doctor', version='0.2.0', collected_utc=STAMP, checks=rows,
        coverage={}, limits=D.LIMITS, scope='local observations only', limitations=[PRIVATE]))

def session_fixture():
    with patch.object(S.platform, 'machine', return_value='aarch64'), patch.object(S.platform, 'release', return_value=PRIVATE), patch.object(S.os, 'sysconf', return_value=16384), patch.object(S.os, 'access', return_value=False):
        value = S.collect(dict(declared_model_id='apple,j413', source_revision=IDENTITY['source_commit'], baseline_sha256='c' * 64, execution_context='unknown'),
            read=lambda p: b'apple,j413\0' if p.endswith('compatible') else None,
            run=lambda *a: (_ for _ in ()).throw(AssertionError('no runner allowed')), environ={}, context={})
    value['collected_at'] = STAMP
    for row in value['checks']:
        row['note'] = PRIVATE
        if 'argv' in row: row['argv'] = [PRIVATE]
    row = next(r for r in value['checks'] if r['check'] == 'user/pipewire.service')
    row.update(state='checked', reason='observed', value=dict(LoadState='loaded', ActiveState='failed', SubState='private-user'))
    value['limitations'] = [PRIVATE]
    return coverage(value)

def health_fixture():
    return dict(schema_version=1, status='OFFLINE_HEALTH_REVIEW_REQUIRED', as_of=STAMP, max_age_hours=24,
        binding=dict(IDENTITY, snapshot_id=PRIVATE, synthetic=True, package_inventory_sha256='d' * 64, project_sources_sha256='e' * 64),
        checks={kind: dict(status='UNAVAILABLE') for kind in B.KINDS},
        findings=[dict(kind=kind, code='EVIDENCE_UNAVAILABLE', action=PRIVATE, path=PRIVATE) for kind in B.KINDS], summary=dict(EVIDENCE_UNAVAILABLE=5),
        release_authenticated_to_supplied_fingerprint=True, observations_authenticated=False,
        release_verification_time='CURRENT_GPG_TIME_NOT_HISTORICAL_AS_OF', arm_security_status='UNKNOWN', maintenance_acceptance='NOT_ESTABLISHED',
        publication_selection_or_withdrawal='NOT_CHECKED', native_build='NOT_RUN', installed_lifecycle='NOT_RUN', physical_m2='NOT_RUN',
        limitations=[PRIVATE], implementation_dependencies={'scripts/maintenance/health.py': dict(sha256='f' * 64, bytes=10)})

def fixtures():
    before = doctor_fixture()
    after = copy.deepcopy(before)
    next(r for r in after['checks'] if r['check'] == 'package/m1n1')['value'].update(presence='absent', version=None)
    comparison = D.compare_reports(D.validate_report(before), D.validate_report(after))
    return dict(session=session_fixture(), doctor=before, **{'doctor-before': before, 'doctor-after': after, 'doctor-comparison': comparison}, health=health_fixture())

class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='support-bundle-tests-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inputs = {}
        for name, value in fixtures().items():
            path = self.root / (name + '.json')
            path.write_bytes(B.encoded(value))
            self.inputs[name] = path

    def arguments(self, output='bundle'):
        args = ['create', '--release-id', IDENTITY['release_id'], '--release-sha256', IDENTITY['release_sha256'], '--source-commit', IDENTITY['source_commit'], '--output-dir', str(self.root / output)]
        for name, path in self.inputs.items(): args += ['--reviewed-' + name, str(path), B.digest(path.read_bytes())]
        return args

    def call(self, args):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err: code = B.main(args)
        return code, out.getvalue(), err.getvalue()

    def created(self, output='bundle'):
        code, out, err = self.call(self.arguments(output))
        self.assertEqual((code, err), (0, ''))
        return self.root / output / 'support-bundle.tar', json.loads(out)['sha256']

    def members(self, path):
        with tarfile.open(path) as archive: return {r.name: archive.extractfile(r).read() for r in archive}

    def test_private_deterministic_exact_inventory_unchanged_inputs(self):
        before = {p: p.read_bytes() for p in self.inputs.values()}
        path, checksum = self.created()
        other, second = self.created('repeat')
        self.assertEqual(path.read_bytes(), other.read_bytes())
        self.assertEqual(checksum, second)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        members = self.members(path)
        index = B.decode(members['inventory.json'])
        self.assertEqual(index['members'], {k: B.pin(v) for k, v in members.items() if k != 'inventory.json'})
        self.assertEqual(index['inputs'], {k: B.pin(v.read_bytes()) for k, v in self.inputs.items()})
        self.assertEqual(before, {p: p.read_bytes() for p in self.inputs.values()})

    def test_privacy_failed_unknown_and_comparison_preserved(self):
        path, _ = self.created()
        members = self.members(path)
        raw = b'\n'.join(members.values())
        for secret in ('PRIVATE', 'SSID-SECRET', '192.0.2.19', '--token=', '/home/', 'private-user'): self.assertNotIn(secret.encode(), raw)
        session = B.decode(members['reports/session.json'])
        self.assertEqual(session['checks']['user/pipewire.service']['value']['ActiveState'], 'failed')
        self.assertEqual(session['checks']['audio/graph']['state'], 'unavailable')
        self.assertEqual(set(session['physical_checks'].values()), {'NOT RUN'})
        health = B.decode(members['reports/health.json'])
        self.assertEqual((health['arm_security_status'], health['finding_count']), ('UNKNOWN', 5))
        self.assertEqual(B.decode(members['reports/doctor-comparison.json'])['changes'], [dict(check='package/m1n1', kind='value')])

    def test_no_process_network_or_live_collection(self):
        with patch.object(B, 'load_current', wraps=B.load_current) as loads, patch.object(subprocess, 'Popen', side_effect=AssertionError('process forbidden')), patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')):
            self.created()
            self.assertEqual(loads.call_count, 2)

    def test_relocation_standalone_verify_extract(self):
        path, checksum = self.created()
        moved = self.root / 'moved'
        moved.mkdir()
        shutil.copyfile(path, moved / 'support-bundle.tar')
        shutil.copyfile(SCRIPT, moved / 'support_bundle.py')
        extracted = moved / 'extracted'
        result = subprocess.run([sys.executable, '-B', str(moved / 'support_bundle.py'), 'verify', '--archive', str(moved / 'support-bundle.tar'), '--sha256', checksum, '--extract-to', str(extracted)], cwd=moved, env={'PATH': '/usr/bin:/bin'}, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({str(p.relative_to(extracted)): p.read_bytes() for p in extracted.rglob('*') if p.is_file()}, self.members(path))
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == (0o700 if p.is_dir() else 0o600) for p in [extracted, *extracted.rglob('*')]))

    def test_tampered_archive_and_member_refused_before_extraction(self):
        path, checksum = self.created()
        members = self.members(path)
        members['summary.txt'] += b'tampered\n'
        path.write_bytes(B.archive_bytes(members))
        for expected in (checksum, B.digest(path.read_bytes())):
            code, out, _ = self.call(['verify', '--archive', str(path), '--sha256', expected, '--extract-to', str(self.root / 'extracted')])
            self.assertEqual((code, out), (2, ''))
            self.assertFalse((self.root / 'extracted').exists())

    def test_tar_traversal_duplicate_link_metadata_refused(self):
        path, _ = self.created()
        original = self.members(path)
        for kind in ('traversal', 'duplicate', 'link', 'metadata'):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for name, raw in original.items():
                    info = tarfile.TarInfo(name)
                    info.size, info.mode = len(raw), 0o600
                    if kind == 'metadata': info.mtime = 123
                    archive.addfile(info, io.BytesIO(raw))
                info = tarfile.TarInfo('../outside' if kind == 'traversal' else 'summary.txt')
                info.mode = 0o600
                if kind == 'link': info.type, info.linkname = tarfile.SYMTYPE, '/outside'
                archive.addfile(info)
            path.write_bytes(stream.getvalue())
            self.assertEqual(self.call(['verify', '--archive', str(path), '--sha256', B.digest(path.read_bytes())])[0], 2, kind)

    def test_binding_pin_and_comparison_refusal_without_output(self):
        cases = [('session', lambda v: v['identity'].update(source_revision='f' * 40)),
                 ('health', lambda v: v['binding'].update(release_sha256='f' * 64)),
                 ('doctor-comparison', lambda v: v.update(change_count=9))]
        for name, change in cases:
            original = self.inputs[name].read_bytes()
            value = B.decode(original)
            change(value)
            self.inputs[name].write_bytes(B.encoded(value))
            code, out, err = self.call(self.arguments())
            self.assertEqual((code, out), (2, ''))
            self.assertNotIn('PRIVATE', err)
            self.assertFalse((self.root / 'bundle').exists())
            self.inputs[name].write_bytes(original)
        args = self.arguments()
        args[-1] = '0' * 64
        self.assertEqual(self.call(args)[0], 2)

    def test_malformed_schema_states_coverage_limits_and_health_refused(self):
        cases = [('session', lambda v: v.update(schema_version=True)),
                 ('session', lambda v: v['coverage'].update(checked=999)),
                 ('session', lambda v: v['coverage'].update(unknown=True)),
                 ('session', lambda v: v['limits'].update(command_seconds=2.0)),
                 ('session', lambda v: v['limits'].update(cleanup_seconds_per_command=True)),
                 ('session', lambda v: v['checks'][0].update(state='checked', reason='observed', value=None)),
                 ('session', lambda v: v['physical_checks'].update(lock_unlock='PASS')),
                 ('doctor', lambda v: v['checks'].pop()),
                 ('health', lambda v: v.update(summary={'EVIDENCE_UNAVAILABLE': 99})),
                 ('health', lambda v: v.update(status='PASS')),
                 ('health', lambda v: v.update(status='FINITE_OBSERVATIONS_REPLAYED', findings=[], summary={}))]
        for name, change in cases:
            raw = self.inputs[name].read_bytes()
            value = B.decode(raw)
            change(value)
            self.inputs[name].write_bytes(B.encoded(value))
            self.assertEqual(self.call(self.arguments())[0], 2, name)
            self.assertFalse((self.root / 'bundle').exists())
            self.inputs[name].write_bytes(raw)
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}', b'{', b'[]'):
            self.inputs['health'].write_bytes(raw)
            self.assertEqual(self.call(self.arguments())[0], 2)

    def test_alias_fifo_hardlink_and_size_refusals(self):
        path = self.inputs['session']
        original = path.read_bytes()
        path.unlink()
        for kind in ('symlink', 'fifo', 'hardlink', 'oversize'):
            target = self.root / 'target.json'
            target.write_bytes(original)
            if kind == 'symlink': path.symlink_to(target)
            elif kind == 'fifo': os.mkfifo(path)
            elif kind == 'hardlink': os.link(target, path)
            else: path.write_bytes(b'x' * (B.MAX_INPUT + 1))
            with self.assertRaises((ValueError, OSError)): B.read_file(path)
            path.unlink()
            target.unlink()
        path.write_bytes(original)
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError): B.read_file(alias / path.name)

    def test_existing_output_and_symlink_parent_preserved(self):
        path, _ = self.created()
        raw = path.read_bytes()
        self.assertEqual(self.call(self.arguments())[0], 2)
        self.assertEqual(path.read_bytes(), raw)
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        self.assertEqual(self.call(self.arguments('alias/new'))[0], 2)
        self.assertFalse((self.root / 'new').exists())

    def test_optional_inputs_and_argument_dependencies(self):
        original = self.inputs
        for name in ('session', 'doctor', 'health'):
            self.inputs = {name: original[name]}
            self.created(name + '-only')
        for name in ('doctor-after', 'doctor-comparison'):
            self.inputs = {name: original[name]}
            self.assertEqual(self.call(self.arguments())[0], 2)
        self.inputs = {}
        self.assertEqual(self.call(self.arguments())[0], 2)

    def test_change_during_review_refused(self):
        original = B.read_file
        calls = Counter()
        def read(path, *args):
            raw = original(path, *args)
            calls[str(path)] += 1
            return raw + b' ' if str(path) == str(self.inputs['session']) and calls[str(path)] == 2 else raw
        with patch.object(B, 'read_file', side_effect=read): self.assertEqual(self.call(self.arguments())[0], 2)
        self.assertFalse((self.root / 'bundle').exists())

    def test_directory_open_failure_cleans_new_directory(self):
        original = B.os.open
        def opened(path, *args, **kwargs):
            if path == 'bundle': raise OSError('fixture failure after mkdir')
            return original(path, *args, **kwargs)
        with patch.object(B.os, 'open', side_effect=opened): self.assertEqual(self.call(self.arguments())[0], 2)
        self.assertFalse((self.root / 'bundle').exists())

    def test_complete_current_session_producer_formats(self):
        def run(argv, *args):
            name = Path(argv[0]).name
            if name == 'hyprctl':
                value = dict(version=PRIVATE, commit='a' * 40) if argv[-1] == 'version' else [dict(width=2560, height=1600, refreshRate=60, scale=2, transform=0, serial=PRIVATE)]
                raw = B.encoded(value)
            elif name == 'eglinfo':
                raw = ('OpenGL ES profile vendor: PRIVATE\nOpenGL ES profile renderer: llvmpipe PRIVATE\nOpenGL ES profile version: PRIVATE\n').encode()
            elif name == 'systemctl': raw = b'LoadState=loaded\nActiveState=failed\nSubState=dead\n'
            elif name == 'loginctl': raw = b'Type=wayland\nClass=user\nState=active\nActive=yes\nRemote=no\nLockedHint=no\n'
            elif name == 'pw-dump': raw = B.encoded([dict(type='PipeWire:Interface:Node', info=dict(state='error', props={'media.class': 'Audio/Sink', 'node.name': PRIVATE}))])
            else: raw = b's "challenge"\n'
            return 'observed', 0, raw, b''
        value = S.collect(dict(declared_model_id=None, source_revision=IDENTITY['source_commit'], baseline_sha256=None, execution_context='unknown'),
            read=lambda p: b'freeze mem' if p.endswith('/state') else b'[s2idle] deep' if p.endswith('mem_sleep') else None,
            run=run, environ={}, context={scope: ({}, ()) for scope in ('local', 'hypr', 'wayland', 'user', 'system', 'audio')})
        projection = B.session_projection(value, S, IDENTITY)
        self.assertEqual(projection['coverage'], {'checked': 14, 'unknown': 1})
        self.assertTrue(projection['checks']['renderer/wayland-gles-client']['value']['software_renderer_hint'])
        self.assertEqual(projection['checks']['audio/graph']['value']['node_state_counts'], {'error': 1})
        self.assertNotIn('PRIVATE', json.dumps(projection))

    def test_health_nested_unknown_fields_refused(self):
        value = health_fixture()
        value['checks']['operations']['unrecognized'] = PRIVATE
        with self.assertRaises(ValueError): B.health_projection(value, IDENTITY)

    def test_all_collector_failure_reasons_remain_explicit(self):
        for reason in B.REASONS:
            if reason == 'observed': continue
            value = session_fixture()
            row = next(r for r in value['checks'] if r['check'] == 'user/pipewire.service')
            row.update(state='unknown', reason=reason, value=None)
            projection = B.session_projection(coverage(value), S, IDENTITY)
            self.assertEqual(projection['checks'][row['check']], dict(state='unknown', reason=reason, value=None))

if __name__ == '__main__':
    unittest.main()

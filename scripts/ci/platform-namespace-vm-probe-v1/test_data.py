# SPDX-License-Identifier: MIT
"""Actor-denied modeled DATA controls; no actual guest or VM evidence."""
import argparse
import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C
import controller as H
import guest as G

ROOT = Path(__file__).resolve().parents[3]
NONCE = 'a' * 32
RELEASE = 'MODELED-generic16k-NOT-OBSERVED'


def model_context(pid=20):
    return dict(machine='aarch64', kernel=RELEASE, page_size=16384, uid=23001, euid=23001,
                gid=23001, egid=23001, groups=[], NoNewPrivs=1, pid=pid, pgid=pid, sid=pid,
                capabilities={k: 0 for k in C.CAPS}, namespaces={k: k + ':[100]' for k in C.NAMESPACES},
                uid_map=[[23001, 23001, 1]], gid_map=[[23001, 23001, 1]])


def model_report():
    before = model_context()
    child = model_context(30)
    binary = C.pin(b'MODELED_BWRAP_NOT_EXECUTED')
    child['bwrap'] = dict(binary, mode=0o755, uid=0, gid=0)
    inside = model_context(31)
    inside['namespaces'].update({k: k + ':[200]' for k in ('user', 'mnt', 'net')})
    row = dict(argv=C.WRAPPER + [NONCE, RELEASE], time_limit=20, output_limit=65536,
               exit_code=0, group_absence_verified=True, stderr_bytes=0, stderr_sha256=C.pin(b'')['sha256'])
    return dict(schema=1, operation=C.OPERATION, nonce=NONCE, before=before, after=copy.deepcopy(before),
                exec_context=child, inside=inside, command=row, bwrap_argv=C.BWRAP + [NONCE, RELEASE],
                bwrap=binary, stderr=C.pin(b''), stderr_preview=C.stderr_preview(b''),
                status='OBSERVED_UNPRIVILEGED_BWRAP_SUCCESS', command_error=None,
                cleanup=dict(group_absence_verified=True, work_removed=True), generic_emulated_16K_only=True,
                hardware='NOT_RUN', numeric_unshare_errno=None)


def wire(report=None, nonce=NONCE):
    value = model_report() if report is None else report
    return b'kernel boot DATA\nNSVM_REPORT_V1 ' + nonce.encode() + b' ' + base64.b64encode(C.encoded(value)) + \
        b'\nNSVM_END_V1 ' + nonce.encode() + b' 0\n'


def tar_data(names=None):
    names = names or ['busybox', 'usr/bin/python3', 'usr/bin/bwrap']
    stream = io.BytesIO()
    rows = {}
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name in names:
            body = ('MODELED_NOT_ELF_OR_EXECUTED:' + name).encode()
            entry = tarfile.TarInfo(name)
            entry.mode, entry.size = 0o755, len(body)
            archive.addfile(entry, io.BytesIO(body))
            rows[name] = dict(C.pin(body), mode=0o755)
    return stream.getvalue(), dict(schema=1, status='CLOSED_GENERIC16K_NAMESPACE_ROOTFS_DATA', files=rows)


class DataControls(unittest.TestCase):
    def setUp(self):
        # Scoped restoration includes exceptions in setUp; unrelated shared suites retain actors.
        for name in ('subprocess.Popen', 'subprocess.run', 'os.execve', 'socket.socket', 'ctypes.CDLL'):
            self.enterContext(patch(name, side_effect=AssertionError('ACTOR_DENIED_DATA_CONTROL:' + name)))

    def test_defaults_and_input_template_are_null(self):
        value = C.decode(C.read(H.HERE / 'input-policy.json'))
        self.assertEqual(value, C.defaults())
        for key in ('kernel', 'rootfs', 'QEMU', 'actual_source', 'actual_ref', 'actual_run'):
            self.assertIsNone(value[key])
        self.assertFalse(value['native_permission'])

    def test_unbound_execution_refuses_before_helpers_or_outputs(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'selection.json'
            raw = C.encoded(C.defaults())
            path.write_bytes(raw)
            args = types.SimpleNamespace(execute=True, selection=path, selection_sha256=C.pin(raw)['sha256'])
            with self.assertRaisesRegex(ValueError, 'UNBOUND'):
                H.trial(args)
            self.assertEqual(list(Path(temp).iterdir()), [path])

    def test_explicit_execute_false_refuses_before_selection(self):
        with self.assertRaisesRegex(ValueError, 'explicit future Root'):
            H.trial(types.SimpleNamespace(execute=False))

    def test_source_only_cli_is_actor_denied_and_inputs_stay_unbound(self):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['controller.py', '--source-root', str(ROOT)]), contextlib.redirect_stdout(output):
            self.assertEqual(H.main(), 0)
        value = C.decode(output.getvalue())
        self.assertEqual(value['status'], 'SOURCE_DATA_ONLY_NO_ACTORS')
        self.assertIsNone(value['kernel'])

    def test_helper_bytes_are_pinned_without_importing_collected_code(self):
        value = H.source(ROOT)
        self.assertEqual(set(value['files']), {H.FIXTURE, H.SUPERVISOR, H.KERNEL_CHECK})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for n in value['files']:
                path = root / n
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'MODELED_UNTRUSTED_HELPER')
            with self.assertRaisesRegex(ValueError, 'pinned input differs'):
                H.source(root)

    def test_guest_guard_refuses_host_before_any_privilege_or_probe_actor(self):
        with patch.object(G.os, 'uname', return_value=types.SimpleNamespace(machine='x86_64', release=RELEASE)):
            with self.assertRaisesRegex(ValueError, 'marked actual generic16K'):
                G.guard(NONCE, RELEASE, root=True)

    def test_whole_rootfs_member_bijection_and_mode(self):
        archive, manifest = tar_data()
        files = H.payload(archive, manifest)
        self.assertEqual(set(files), H.REQUIRED)
        self.assertTrue(all(stat.S_IMODE(row[0]) == 0o755 for row in files.values()))
        missing = copy.deepcopy(manifest)
        missing['files']['usr/lib/missing'] = dict(C.pin(b'MODELED'), mode=0o644)
        with self.assertRaisesRegex(ValueError, 'bijection'):
            H.payload(archive, missing)

    def test_rootfs_duplicate_traversal_and_reserved_paths_refuse(self):
        for names in [['busybox', 'usr/bin/python3', 'usr/bin/bwrap', 'busybox'],
                      ['busybox', 'usr/bin/python3', 'usr/bin/bwrap', '../escape'],
                      ['busybox', 'usr/bin/python3', 'usr/bin/bwrap', 'probe/guest.py']]:
            with self.subTest(names=names), self.assertRaises(ValueError):
                archive, manifest = tar_data(names)
                H.payload(archive, manifest)

    def test_rootfs_link_and_special_members_refuse(self):
        _, manifest = tar_data()
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.DIRTYPE):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w') as archive:
                row = tarfile.TarInfo('busybox')
                row.mode, row.type, row.linkname = 0o755, kind, 'usr/bin/bwrap'
                archive.addfile(row)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                H.payload(buffer.getvalue(), manifest)

    def test_rootfs_hash_setuid_and_boolean_mode_refuse(self):
        archive, manifest = tar_data()
        for mutation in [('sha256', '0' * 64), ('mode', 0o4755), ('mode', True)]:
            bad = copy.deepcopy(manifest)
            bad['files']['usr/bin/bwrap'][mutation[0]] = mutation[1]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                H.payload(archive, bad)

    def test_elf_alignment_and_interpreter_closure_are_required(self):
        files = {n: (stat.S_IFREG | 0o755, b'\x7fELF_MODELED_NOT_REAL') for n in H.REQUIRED}
        good = types.SimpleNamespace(elf=lambda b: (None, [], [(0, 0, 1, 16384)]))
        self.assertEqual(set(H.elf_closure(files, good)), H.REQUIRED)
        for fake in [types.SimpleNamespace(elf=lambda b: (None, [], [(0, 0, 1, 4096)])),
                     types.SimpleNamespace(elf=lambda b: ('/missing/loader', [], [(0, 0, 1, 16384)])),
                     types.SimpleNamespace(elf=lambda b: (None, ['missing.so'], [(0, 0, 1, 16384)]))]:
            with self.assertRaises(ValueError):
                H.elf_closure(files, fake)

    def test_memory_only_cpio_uses_exact_helpers_and_guest_entry(self):
        dependencies = H.source(ROOT)
        generic = H.load(ROOT, H.FIXTURE, 'namespace_vm_DATA_cpio_only', dependencies)
        archive, manifest = tar_data()
        payload = H.payload(archive, manifest)
        before = copy.deepcopy(payload)
        raw = H.assemble(payload, dict(dependencies, source_root=str(ROOT)), NONCE, RELEASE, generic)
        self.assertTrue(raw.startswith(b'070701'))
        for name in (b'probe/guest.py\0', b'probe/boot.py\0', b'probe/runner.py\0', b'probe/selection.json\0', b'init\0'):
            self.assertIn(name, raw)
        self.assertEqual(before, payload)

    def test_qemu_plan_is_finite_tcg_no_network_no_shared_host_filesystem(self):
        args = H.qemu_argv(Path('/MODELED/qemu'), Path('/MODELED/private'), NONCE)
        self.assertEqual(args[args.index('-accel') + 1], 'tcg')
        self.assertEqual(args[args.index('-nic') + 1], 'none')
        self.assertEqual(args[args.index('-smp') + 1], '1')
        self.assertEqual(args[args.index('-m') + 1], '1024')
        self.assertNotIn('-drive', args)
        self.assertNotIn('-virtfs', args)
        self.assertIn('namespace_vm_probe_v1=' + NONCE, args[args.index('-append') + 1])

    def test_init_has_guest_mounts_one_probe_and_explicit_poweroff(self):
        init = H.init(NONCE, RELEASE)
        self.assertTrue(init.startswith(b'#!/busybox sh\n'))
        self.assertEqual(init.count(b'/usr/bin/python3 -I -B /probe/guest.py'), 1)
        self.assertIn(b'exec /busybox poweroff -f', init)
        self.assertEqual(init.count(b'/usr/bin/python3 -I -B /probe/boot.py'), 1)
        self.assertNotIn(b'/busybox mount', init)
        self.assertNotIn(b'/busybox mkdir', init)
        self.assertNotIn(b'sysctl', init)
        self.assertNotIn(b'docker', init)

    def test_modeled_report_success_has_exact_identity_and_namespace_change(self):
        self.assertEqual(C.validate_report(model_report(), NONCE, RELEASE)['status'],
                         'OBSERVED_UNPRIVILEGED_BWRAP_SUCCESS')

    def test_modeled_identity_and_namespace_counterexamples_refuse(self):
        for key, value in [('uid', 0), ('groups', [0]), ('page_size', 4096), ('NoNewPrivs', False)]:
            report = model_report()
            report['before'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                C.validate_report(report, NONCE, RELEASE)
        report = model_report()
        report['inside']['namespaces']['user'] = report['before']['namespaces']['user']
        with self.assertRaisesRegex(ValueError, 'actual created'):
            C.validate_report(report, NONCE, RELEASE)

    def test_same_process_exec_session_and_nonsetuid_binary_join(self):
        for mutate in (lambda r: r['exec_context'].update(pgid=99),
                       lambda r: r['exec_context']['bwrap'].update(mode=0o4755),
                       lambda r: r['exec_context']['bwrap'].update(sha256='0' * 64)):
            report = model_report()
            mutate(report)
            with self.assertRaises(ValueError):
                C.validate_report(report, NONCE, RELEASE)

    def test_capabilities_inside_new_user_namespace_are_observed_not_outer_privilege(self):
        report = model_report()
        report['inside']['capabilities']['CapBnd'] = 15
        self.assertEqual(C.validate_report(report, NONCE, RELEASE)['inside']['capabilities']['CapBnd'], 15)
        report['exec_context']['capabilities']['CapBnd'] = 15
        with self.assertRaisesRegex(ValueError, 'zero-capability outer'):
            C.validate_report(report, NONCE, RELEASE)

    def test_inner_identity_is_joined_through_actual_user_and_group_maps(self):
        report = model_report()
        report['inside'].update(uid=0, euid=0, gid=0, egid=0, uid_map=[[0, 23001, 1]], gid_map=[[0, 23001, 1]])
        C.validate_report(report, NONCE, RELEASE)
        report['inside']['uid_map'] = [[0, 0, 1]]
        with self.assertRaisesRegex(ValueError, 'maps exactly'):
            C.validate_report(report, NONCE, RELEASE)

    def test_nonzero_is_not_numeric_errno_or_policy_cause(self):
        report = model_report()
        report.update(status='OBSERVED_BWRAP_NONZERO', inside=None)
        report['command']['exit_code'] = 1
        C.validate_report(report, NONCE, RELEASE)
        report['numeric_unshare_errno'] = 1
        with self.assertRaisesRegex(ValueError, 'errno unknown'):
            C.validate_report(report, NONCE, RELEASE)

    def test_observed_join_requires_natural_qemu_and_complete_frames(self):
        actor = dict(exit_code=0, group_absence_verified=True)
        self.assertEqual(H.observed(wire(), actor, None, NONCE, RELEASE)['nonce'], NONCE)
        for raw in (wire() + wire(), wire(nonce='b' * 32), wire().split(b'NSVM_END_V1')[0],
                    wire() + b'X' * C.BOUNDS['UART_bytes']):
            with self.assertRaises(ValueError):
                H.observed(raw, actor, None, NONCE, RELEASE)
        with self.assertRaises(ValueError):
            H.observed(wire(), dict(actor, group_absence_verified=False), None, NONCE, RELEASE)

    def test_unknown_actor_retirement_retains_all_private_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary) / 'owned'
            work.mkdir()
            (work / 'Image').write_bytes(b'MODELED_KERNEL')
            (work / 'initramfs.cpio').write_bytes(b'MODELED_CPIO')
            for actor in (None, dict(group_absence_verified=False)):
                self.assertEqual(H.cleanup(work, True, actor), 'UNKNOWN_VM_RETIREMENT_RETAIN_PRIVATE_FILES')
                self.assertEqual(len(list(work.iterdir())), 2)

    def test_known_actor_retirement_cleans_only_exact_owned_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            outside = parent / 'unrelated'
            outside.write_bytes(b'HELD')
            work = parent / 'owned'
            work.mkdir()
            (work / 'Image').write_bytes(b'MODELED_KERNEL')
            (work / 'initramfs.cpio').write_bytes(b'MODELED_CPIO')
            self.assertEqual(H.cleanup(work, True, dict(group_absence_verified=True)),
                             'VERIFIED_VM_GROUP_AND_SCOPED_PRIVATE_FILES_RETIRED')
            self.assertFalse(work.exists())
            self.assertEqual(outside.read_bytes(), b'HELD')

    def test_prestart_is_not_vm_retirement_and_unknown_files_are_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary) / 'owned'
            work.mkdir()
            self.assertEqual(H.cleanup(work, False, None), 'SCOPED_PRESTART_FILES_RETIRED_VM_NOT_STARTED')
            work.mkdir()
            (work / 'unowned').write_bytes(b'HELD')
            with self.assertRaisesRegex(ValueError, 'retain workspace'):
                H.cleanup(work, True, dict(group_absence_verified=True))
            self.assertEqual((work / 'unowned').read_bytes(), b'HELD')

    def test_json_duplicates_and_bounds_bool_are_not_bound(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            C.decode(b'{"schema":1,"schema":1}')
        bad = C.defaults()
        bad['bounds']['CPUs'] = True
        with self.assertRaisesRegex(ValueError, 'integer bounds'):
            C.bound(bad)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=ROOT)
    args, remaining = parser.parse_known_args()
    ROOT = args.root.resolve()
    unittest.main(argv=[sys.argv[0], *remaining])

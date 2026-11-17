# SPDX-License-Identifier: MIT
"""Adversarial DATA controls; synthetic operands never qualify the773 join."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('adoption_controls', HERE/'adopt.py')
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root/'archive'
        self.raw = b'whole public archive DATA\n'
        self.path.write_bytes(self.raw)
        self.path.chmod(0o600)
        self.ref = dict(path=str(self.path), **A.pin(self.raw))

    def tearDown(self):
        self.temp.cleanup()

    def test_whole_copy_preserves_bytes_and_private_modes(self):
        sink = A.CopyDomain(self.root/'recipient')
        try:
            dest = sink.root/'archive'
            A.stream(self.ref, {}, target=dest, sink=sink)
            self.assertEqual(dest.read_bytes(), self.raw)
            self.assertEqual(dest.stat().st_mode & 0o777, 0o600)
            self.assertEqual(sink.root.stat().st_mode & 0o777, 0o700)
            sink.check()
        finally:
            sink.close()

    def test_changed_body_same_length_refused(self):
        self.path.write_bytes(b'x'*len(self.raw))
        with self.assertRaisesRegex(ValueError, 'STABLE_WHOLE_REQUIRED_PIN'):
            A.stream(self.ref, {})

    def test_wrong_size_refused(self):
        self.path.write_bytes(self.raw+b'x')
        with self.assertRaisesRegex(ValueError, 'EXACT_SIZE'):
            A.stream(self.ref, {})

    def test_symlink_refused(self):
        link = self.root/'link'
        link.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError, 'UNALIASED'):
            A.stream(dict(self.ref, path=str(link)), {})

    def test_hardlink_refused(self):
        os.link(self.path, self.root/'link')
        with self.assertRaisesRegex(ValueError, 'SINGLE_LINK'):
            A.stream(self.ref, {})

    def test_writable_input_refused(self):
        self.path.chmod(0o666)
        with self.assertRaisesRegex(ValueError, 'SINGLE_LINK'):
            A.stream(self.ref, {})

    def test_fifo_refused_without_blocking(self):
        fifo = self.root/'fifo'
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(ValueError, 'SINGLE_LINK'):
            A.stream(dict(path=str(fifo), **A.pin(b'')), {})

    def test_private_ancestry_refused(self):
        with self.assertRaisesRegex(ValueError, 'PUBLIC_UNALIASED'):
            A.ordinary(str(self.root/'.gnupg'/'pubring'))

    def test_private_key_marker_refused_across_stream_boundary(self):
        raw = b'x'*(1024**2-12)+b'-----BEGIN RSA PRIVATE KEY-----'
        self.path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'PRIVATE_KEY_REFUSED'):
            A.stream(dict(path=str(self.path), **A.pin(raw)), {})

    def test_missing_roles_exact_counts_and_bytes(self):
        missing = A.missing_roles({'candidate_materials':{'present':self.ref,
            'absent':dict(self.ref, path=str(self.root/'absent'), bytes=123)}})
        self.assertEqual([(r['group'],r['name'],r['bytes']) for r in missing],
                         [('candidate_materials','absent',123)])

    def test_duplicate_operand_inode_refused(self):
        with self.assertRaisesRegex(ValueError, 'INODE_ALIAS'):
            A.missing_roles({'one':{'a':self.ref},'two':{'b':self.ref}})

    def test_output_namespace_injection_refused(self):
        sink = A.CopyDomain(self.root/'recipient')
        try:
            (sink.root/'foreign').write_bytes(b'foreign')
            with self.assertRaisesRegex(ValueError, 'NAMESPACE'):
                A.write(sink.root/'receipt', {}, sink)
        finally:
            sink.close()

    def test_replaced_output_ancestor_refused(self):
        sink = A.CopyDomain(self.root/'recipient')
        try:
            sink.root.rename(self.root/'old')
            sink.root.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, 'OUTPUT_DIRECTORY'):
                A.write(sink.root/'receipt', {}, sink)
            self.assertEqual(list(sink.root.iterdir()), [])
        finally:
            sink.close()

    def test_output_leaf_change_refused(self):
        sink = A.CopyDomain(self.root/'recipient')
        try:
            target = sink.root/'receipt'
            A.write(target, {'authority':None}, sink)
            target.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'OUTPUT_CHANGED'):
                sink.check()
        finally:
            sink.close()

    def test_existing_output_refused(self):
        self.path.unlink()
        self.path.mkdir()
        with self.assertRaises(FileExistsError):
            A.CopyDomain(self.path)

    def test_repeated_directory_checks_after_new_children(self):
        sink = A.CopyDomain(self.root/'recipient')
        try:
            for name in ('base','candidate','metadata'):
                directory = sink.root/name
                sink.mkdir(directory)
                A.stream(self.ref, {}, target=directory/'archive', sink=sink)
                sink.check()
        finally:
            sink.close()

    def test_flush_failure_closes_both_stream_descriptors(self):
        sink = A.CopyDomain(self.root/'recipient')
        opened, original_open, original_fdopen = [], A.os.open, A.os.fdopen
        class FailedFlush:
            def __init__(self, stream):
                self.stream = stream
            def write(self, raw):
                return self.stream.write(raw)
            def flush(self):
                raise OSError('simulated full output')
            def close(self):
                self.stream.close()
        def capture(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            opened.append(fd)
            return fd
        try:
            with patch.object(A.os, 'open', side_effect=capture), patch.object(
                    A.os, 'fdopen', side_effect=lambda *a,**k:FailedFlush(original_fdopen(*a,**k))):
                with self.assertRaisesRegex(OSError, 'simulated full output'):
                    A.stream(self.ref, {}, target=sink.root/'archive', sink=sink)
            for fd in opened:
                with self.assertRaises(OSError):
                    os.fstat(fd)
        finally:
            sink.close()

    def test_constructor_check_failure_closes_domain(self):
        closed, original_close = [], A.os.close
        def capture(fd):
            closed.append(fd)
            return original_close(fd)
        with patch.object(A.CopyDomain, 'check', side_effect=ValueError('changed domain')), patch.object(
                A.os, 'close', side_effect=capture):
            with self.assertRaisesRegex(ValueError, 'changed domain'):
                A.CopyDomain(self.root/'recipient')
        self.assertEqual(len(closed), 2)

    def test_boolean_byte_count_refused(self):
        with self.assertRaisesRegex(ValueError, 'REQUIRED_PIN'):
            A.descriptor(dict(self.ref, bytes=True))

    def test_duplicate_json_key_refused(self):
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_JSON_KEY'):
            A.decode(b'{"approved":null,"approved":true}')

    def test_required_lock_and_unissued_source79_templates(self):
        observed = {}
        lock = A.decode(A.read(HERE/'inputs.lock.json', A.LOCK_PIN, observed))
        self.assertEqual(lock['required_materials'], 773)
        sink = A.CopyDomain(self.root/'proposal')
        try:
            result = A.request_handoff(sink.root, lock, observed, sink)
            request = A.decode(Path(result['request']['path']).read_bytes())
            delegation = A.decode(request['delegation_json'].encode())
            self.assertEqual(delegation['binding']['source'], '429f82ea1e63cdf69b4be4be518257142f925e91')
            self.assertEqual(len(delegation['materials']), 77)
            for value in (request,delegation):
                self.assertIsNone(value['issuer'])
                self.assertIsNone(value['approved'])
            self.assertIsNone(request['staged_inputs'])
            self.assertIsNone(delegation['inputs_pin'])
            self.assertFalse(result['dispatch_ready'])
            self.assertEqual(A.pin(request['delegation_json'].encode()), request['delegation_pin'])
        finally:
            sink.close()

    def test_actor_audit_refuses_acquisition_and_processes(self):
        for event in ('socket.connect','subprocess.Popen','ctypes.dlopen','os.system','fcntl.flock'):
            with self.assertRaisesRegex(ValueError, 'ACTOR_FREE'):
                A.no_actors(event, ())

    def role_model(self):
        # Finite selection MODEL only; no files, Source or real773 acceptance.
        groups, wanted = {}, {}
        for group,count in A.GROUPS.items():
            if group == 'candidate_materials':
                continue
            refs = {group+str(i):dict(path=str(self.root/(group+str(i))), **A.pin(b'')) for i in range(count)}
            groups[group] = refs
            wanted[group] = {n:{k:r[k] for k in ('bytes','sha256')} for n,r in refs.items()}
        selected = {'pkg'+str(i):dict(filename='pkg'+str(i), archive=A.pin(b''), signature=A.pin(b'')) for i in range(128)}
        candidates = {r['filename']+suffix:dict(path=str(self.root/(r['filename']+suffix)), **r['archive'])
                      for r in selected.values() for suffix in ('','.sig')}
        base = dict(groups, base_lock=None, bootstrap_profile=None, baseline_inventory=None)
        return base,candidates,dict(groups=wanted,packages={}),selected

    def test_unselected_role_replacement_refused(self):
        base,candidates,plan,selected = self.role_model()
        candidates['unselected'] = candidates.pop(next(iter(candidates)))
        with self.assertRaisesRegex(ValueError, 'ROLE_SET'):
            A.select_groups(base,candidates,plan,selected)

    def test_role_archive_pin_substitution_refused(self):
        base,candidates,plan,selected = self.role_model()
        candidates[next(iter(candidates))]['sha256'] = 'f'*64
        with self.assertRaisesRegex(ValueError, 'ARCHIVE_PIN'):
            A.select_groups(base,candidates,plan,selected)

    def test_cross_group_path_alias_refused(self):
        base,candidates,plan,selected = self.role_model()
        candidates[next(iter(candidates))]['path'] = next(iter(base['base_materials'].values()))['path']
        with self.assertRaisesRegex(ValueError, 'DISTINCT773'):
            A.select_groups(base,candidates,plan,selected)

    def test_manifest_byte_drift_refused(self):
        expected = A.pin(self.raw)
        self.path.write_bytes(b'x'*len(self.raw))
        with self.assertRaisesRegex(ValueError, 'STABLE_WHOLE_REQUIRED_PIN'):
            A.read(self.path, expected, {})


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""MODELED producer/protocol only. No Docker, GPG or actual native actor runs."""
import base64
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('owned_handoff_producer', Path(__file__).with_name('producer.py'))
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)
ROOT = Path(__file__).resolve().parents[3]
NONCE = 'a' * 32


class ModeledProtocol:
    """Acknowledgments are test controls, never actual host durability evidence."""
    def __init__(self):
        self.frames, self.previous, self.trace = [], '0' * 64, []
    def exchange(self, wire, *, deadline):
        parsed = producer.parse_frame(wire, nonce=NONCE, sequence=len(self.frames) + 1, previous_frame_sha256=self.previous)
        self.frames.append(parsed)
        self.previous = parsed['frame_sha256']
        self.trace.append('ack-' + str(len(self.frames)))
        return producer.encode_ack(parsed)


class WireTests(unittest.TestCase):
    def test_exact_two_frame_chain_and_digest_excludes_markers(self):
        protocol = ModeledProtocol()
        checkpoints = producer.Checkpoints(protocol, NONCE, time.monotonic() + 10)
        checkpoints.emit({'fixture_scope': 'MODELED', 'part': 1})
        checkpoints.emit({'fixture_scope': 'MODELED', 'part': 2})
        self.assertEqual(checkpoints.sequence, 2)
        self.assertEqual(protocol.frames[1]['frame']['previous_frame_sha256'], protocol.frames[0]['frame_sha256'])
        wire = producer.encode_frame({'fixture_scope': 'MODELED'}, NONCE, 1)
        self.assertEqual(producer.frame_digest(wire), producer.digest(wire[len(producer.FRAME_MARKER):-1]))
        self.assertNotEqual(producer.frame_digest(wire), producer.digest(wire))
        with self.assertRaises(producer.Refused): checkpoints.emit({})

    def test_fail_closed_frame_parser_and_canonical_schema(self):
        wire = producer.encode_frame({'fixture_scope': 'MODELED'}, NONCE, 1)
        frame = json.loads(wire[len(producer.FRAME_MARKER):-1])
        candidates = [wire + b'\n', b'wrong' + wire, wire[:-1], producer.FRAME_MARKER + b'{"nonce":"x","nonce":"y"}\n']
        for mutate in (lambda value: value.update(sequence=True), lambda value: value.update(phase='post-public-export'),
                       lambda value: value.update(nonce='b' * 32), lambda value: value.update(extra='refused'),
                       lambda value: value.update(payload_sha256='0' * 64), lambda value: value.update(payload='!invalid'),
                       lambda value: value.update(previous_frame_sha256='f' * 64)):
            value = copy.deepcopy(frame); mutate(value)
            candidates.append(producer.FRAME_MARKER + producer.canonical(value) + b'\n')
        candidates.append(producer.FRAME_MARKER + json.dumps(frame, sort_keys=True).encode() + b'\n')
        for candidate in candidates:
            with self.subTest(candidate=candidate[:80]), self.assertRaises(producer.Refused):
                producer.parse_frame(candidate, nonce=NONCE, sequence=1, previous_frame_sha256='0' * 64)

    def test_ack_requires_every_durable_binding(self):
        wire = producer.encode_frame({'fixture_scope': 'MODELED'}, NONCE, 1)
        parsed = producer.parse_frame(wire, nonce=NONCE, sequence=1, previous_frame_sha256='0' * 64)
        ack = producer.encode_ack(parsed)
        value = json.loads(ack[len(producer.ACK_MARKER):-1])
        for field, item in (('durable_host_digest', False), ('sequence', True), ('frame_sha256', '0' * 64),
                            ('nonce', 'f' * 32), ('phase', 'post-public-export'), ('extra', True)):
            changed = {**value, field: item}
            with self.subTest(field=field), self.assertRaises(producer.Refused):
                producer.validate_ack(producer.ACK_MARKER + producer.canonical(changed) + b'\n', parsed)

    def test_decoded_bound_private_marker_and_noninteger_json(self):
        for payload in ({'x': 'x' * producer.DECODED_LIMIT}, {'x': '-----BEGIN PGP PRIVATE KEY BLOCK-----'}):
            with self.assertRaises(producer.Refused): producer.encode_frame(payload, NONCE, 1)
        with self.assertRaises(producer.Refused): producer.decode(b'{"a":1.5}')
        with self.assertRaises(producer.Refused): producer.decode(b'{"a":NaN}')

    def test_ack_deadline_is_independent_of_injected_protocol(self):
        class Silent:
            def exchange(self, *args, **kwargs):
                time.sleep(60)
        checkpoint = producer.Checkpoints(Silent(), NONCE, time.monotonic() + 10, phase_seconds=0.05)
        started = time.monotonic()
        with self.assertRaisesRegex(producer.Refused, 'ack-timeout'): checkpoint.emit({'fixture_scope': 'MODELED'})
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual(checkpoint.sequence, 0)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_external_expected_identity_and_ack_constructor_are_typed(self):
        wire = producer.encode_frame({'fixture_scope': 'MODELED'}, NONCE, 1)
        with self.assertRaises(producer.Refused):
            producer.parse_frame(wire, nonce=NONCE, sequence=True, previous_frame_sha256='0'*64)
        for value in (None, {'frame': None}, {'nonce':NONCE,'sequence':True,'phase':producer.PHASES[1],
                                           'frame_sha256':'a'*64}):
            with self.subTest(value=value), self.assertRaises(producer.Refused):producer.encode_ack(value)

    def test_alarm_setter_failure_restores_original_handler_and_mask(self):
        original, mask, actual, fired = signal.getsignal(signal.SIGALRM), signal.pthread_sigmask(signal.SIG_BLOCK, set()), signal.signal, []
        def setter(number, handler):
            result = actual(number, handler)
            if number == signal.SIGALRM and getattr(handler, '__name__', '') == 'expired' and not fired:
                fired.append(True)
                raise RuntimeError('MODELED setter failure after real installation')
            return result
        with mock.patch.object(signal, 'signal', side_effect=setter), self.assertRaises(RuntimeError):
            with producer.acknowledgement_deadline(time.monotonic()+2):self.fail('must not enter')
        self.assertEqual(fired, [True]);self.assertEqual(signal.getsignal(signal.SIGALRM), original)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), mask)

    def test_real_alarm_during_restoration_cannot_deliver_default_disposition(self):
        original, actual, fired = signal.getsignal(signal.SIGALRM), signal.signal, []
        def setter(number, handler):
            result = actual(number, handler)
            if number == signal.SIGALRM and handler == original and not fired:
                fired.append(True);os.kill(os.getpid(), signal.SIGALRM)
            return result
        with mock.patch.object(signal, 'signal', side_effect=setter), self.assertRaisesRegex(producer.Refused,'ack-timeout'):
            with producer.acknowledgement_deadline(time.monotonic()+2):pass
        self.assertEqual(fired,[True]);self.assertEqual(signal.getsignal(signal.SIGALRM),original)
        self.assertNotIn(signal.SIGALRM,signal.sigpending())


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='MODELED-handoff-producer-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        source = (ROOT / 'scripts/integration/repository.py').read_bytes()
        self.assertEqual(producer.digest(source), producer.SOURCE_SHA256)
        self.original = types.ModuleType('frozen_repository_functions_only')
        self.original.__file__ = str(ROOT / 'scripts/integration/repository.py')
        exec(compile(source, self.original.__file__, 'exec'), self.original.__dict__)
        self.protocol = ModeledProtocol()
        self.checkpoints = producer.Checkpoints(self.protocol, NONCE, time.monotonic() + 30)
        self.trace = self.protocol.trace
        parent = self
        class ModelIntegration:
            def __init__(self, spec, observed=None):
                self.spec, self.receipts, self.keys = spec, [], {}
                self.scratch, self.home, self.out = parent.root / 'scratch', parent.root / 'private-home', parent.root / 'out'
                for path in (self.scratch, self.home, self.out):path.mkdir()
                self.result = {'status': 'RUNNING', 'commands': self.receipts, 'fixture_scope': 'MODELED-NOT-NATIVE'}
            def gpg(self, home):
                return ['gpg', '--batch', '--no-options', '--homedir', home, '--no-default-keyring', '--keyring',
                        home / 'pubring.gpg', '--no-auto-key-retrieve']
            def command(self, label, argv, **kwargs):
                parent.trace.append('delegate-' + label)
                return 'MODELED delegated operation'
            def export_public_repositories(self):
                parent.trace.append('delegate-export')
                path = self.out / 'TEST-repository-aliases.json'
                path.write_bytes(b'{"MODELED":"public aliases"}\n')
                Path(str(path) + '.sig').write_bytes(b'MODELED-alias-signature')
                parent.record(self, path, 'signer-B', 'verify-signer-B')
            def cleanup(self):
                parent.trace.append('cleanup-start')
                signal.raise_signal(signal.SIGTERM) if parent.cancel_cleanup else None
                parent.trace.append('cleanup-end')
        self.cancel_cleanup = False
        self.module = types.SimpleNamespace(Integration=ModelIntegration, ORIGINALS=self.original.ORIGINALS,
                    FIXTURE=self.original.FIXTURE, signature_status=self.original.signature_status)
        cls = producer.observer_class(self.module, self.checkpoints)
        self.integration = cls({'nonce': NONCE, 'script_sha256': producer.SOURCE_SHA256, 'source_commit': 'b' * 40,
                            'image_id': 'sha256:' + 'c' * 64, 'baseline': [], 'upgrade': []})
        for role, fingerprint in [('signer-A', 'A' * 40), ('signer-B', 'B' * 40), ('verifier', 'C' * 40)]:
            raw = ('-----BEGIN PGP PUBLIC KEY BLOCK-----\nMODELED-' + role + '\n').encode()
            (self.integration.out / ('TEST-' + role + '-public.asc')).write_bytes(raw)
            self.integration.keys[role] = {'home': self.integration.home / role, 'fingerprint': fingerprint,
                                           'public_sha256': producer.digest(raw)}
        for field, label, role, version, probe in [('baseline', 'baseline-A', 'signer-A', '0.1.0-1', '1-1'),
                                                 ('upgrade', 'updated-B', 'signer-B', '0.1.1-1', '2-1')]:
            folder = self.integration.scratch / 'repos' / label; folder.mkdir(parents=True)
            names = []
            for name in sorted(self.original.ORIGINALS):
                filename = name + '-' + version + '-any.pkg.tar.xz'
                self.integration.spec[field].append({'name': name, 'archive': field + '/' + filename})
                names.append(filename)
            names += [self.original.FIXTURE + '-' + probe + '-any.pkg.tar.xz', 'integration.db.tar.gz', 'integration.files.tar.gz']
            for filename in names:
                path = folder / filename; path.write_bytes(b'MODELED-archive-or-database')
                Path(str(path) + '.sig').write_bytes(b'MODELED-public-signature')
                self.record(self.integration, path, role, 'verify-database-' + label if filename.startswith('integration.') else 'verify-' + role)
        (self.integration.out / 'MODELED-before-snapshot.json').write_bytes(b'{"inventory":"MODELED"}\n')

    def record(self, integration, path, role, label):
        fingerprint = integration.keys[role]['fingerprint']
        # Fabricated signature status, explicitly a control fixture only.
        status = ('gpg: MODELED merged stderr human diagnostics\n[GNUPG:] GOODSIG ' + fingerprint[-16:] +
                  ' TEST\n[GNUPG:] VALIDSIG ' + fingerprint + ' 2026-10-12 1791748800 0 4 0 22 8 00 ' + fingerprint + '\n').encode()
        index = len(integration.receipts); log = f'{index:03d}-{label}.txt'
        (integration.out / log).write_bytes(status)
        integration.receipts.append({'label': label, 'argv': [str(x) for x in integration.gpg(integration.keys[role]['home']) +
            ['--status-fd', '1', '--verify', str(path) + '.sig', path]], 'log': log, 'sha256': producer.digest(status),
            'expected': 0, 'exit_code': 0})

    def revoke(self):
        return self.integration.command('revoke-A-signing-home', self.integration.gpg(self.integration.keys['signer-A']['home']) +
                        ['--import', self.integration.home / 'TEST-revocation.asc'])

    def test_two_checkpoint_acks_precede_delegated_revocation_and_cleanup(self):
        self.revoke()
        self.integration.export_public_repositories()
        self.integration.cleanup()
        self.assertEqual(self.trace, ['ack-1', 'delegate-revoke-A-signing-home', 'delegate-export', 'ack-2', 'cleanup-start', 'cleanup-end'])
        first, second = [parsed['payload'] for parsed in self.protocol.frames]
        self.assertEqual(len(first['objects']), 14)
        self.assertEqual(set(first['public_certificates']), {'signer-A', 'signer-B', 'verifier'})
        self.assertTrue(all(row['stream_layout'] == 'merged-stdout-stderr' for row in first['objects']))
        self.assertTrue(all('gpg: MODELED merged stderr' in base64.b64decode(row['original_stdout']['base64']).decode()
                            for row in first['objects']))
        self.assertEqual(first['snapshot_sha256']['MODELED-before-snapshot.json']['bytes'], 24)
        self.assertEqual(second['original_precleanup_receipt']['status'], 'RUNNING')
        self.assertEqual(second['private_cleanup'], 'NOT YET OBSERVED')
        self.assertEqual(second['alias']['data_sha256'], second['alias']['data']['sha256'])
        self.assertNotIn('data', first['objects'][0])  # Archive custody is not exported by checkpoints.

    def test_bad_ack_cannot_delegate_revocation(self):
        with mock.patch.object(self.protocol, 'exchange', return_value=b'refused\n'):
            with self.assertRaises(producer.Refused):self.revoke()
        self.assertEqual(self.trace, [])
        self.assertEqual(self.checkpoints.sequence, 0)

    def test_duplicate_first_command_and_wrong_revocation_args_refused(self):
        wrong = self.integration.gpg(self.integration.keys['signer-A']['home']) + ['--import', '/unexpected/revocation.asc']
        with self.assertRaises(producer.Refused):self.integration.command('revoke-A-signing-home', wrong)
        self.revoke()
        with self.assertRaises(producer.Refused):self.revoke()
        self.assertEqual(len(self.protocol.frames), 1)

    def test_original_status_or_subject_drift_refused(self):
        row = self.integration.receipts[0]
        row['argv'][-1] += '.wrong'
        with self.assertRaises(producer.Refused):self.revoke()
        self.assertEqual(self.checkpoints.sequence, 0)

    def test_no_key_home_revocation_certificate_or_agent_reads(self):
        actual, paths = producer.read, []
        def read(path, *args):
            paths.append(Path(path));self.assertFalse(Path(path).is_relative_to(self.integration.home))
            return actual(path, *args)
        with mock.patch.object(producer, 'read', side_effect=read):
            self.revoke();self.integration.export_public_repositories()
        self.assertTrue(paths)
        self.assertFalse(any('openpgp-revocs.d' in p.parts or p.name == 'TEST-revocation.asc' for p in paths))

    def test_real_cleanup_term_delivered_after_delegate_finishes(self):
        self.cancel_cleanup = True
        with producer.cancellation_handlers(), self.assertRaises(producer.Cancelled):self.integration.cleanup()
        self.assertEqual(self.trace, ['cleanup-start', 'cleanup-end'])
        self.assertEqual(producer.PENDING, [])

    def test_real_term_during_first_remember_installation_cannot_bypass_cleanup(self):
        actual, fired = signal.signal, []
        def setter(number, handler):
            result = actual(number, handler)
            if not fired and getattr(handler, '__name__', '') == 'remember':
                fired.append(True);os.kill(os.getpid(), signal.SIGTERM)
            return result
        with producer.cancellation_handlers(), mock.patch.object(signal, 'signal', side_effect=setter):
            with self.assertRaises(producer.Cancelled):self.integration.cleanup()
        self.assertEqual(fired, [True]);self.assertEqual(self.trace, ['cleanup-start', 'cleanup-end'])
        self.assertEqual(producer.PENDING, [])


class ModeledStdioTests(unittest.TestCase):
    def setUp(self):
        self.input_read, self.input_write = os.pipe()
        self.output_read, self.output_write = os.pipe()
        self.addCleanup(self.close_pipes)

    def close_pipes(self):
        for fd in (self.input_read, self.input_write, self.output_read, self.output_write):
            try: os.close(fd)
            except OSError: pass

    def test_real_pipe_roundtrip_is_modeled_host_ack_only(self):
        wire = producer.encode_frame({'fixture_scope': 'MODELED-stream-not-native'}, NONCE, 1)
        parsed = producer.parse_frame(wire, nonce=NONCE, sequence=1, previous_frame_sha256='0'*64)
        received = []
        def host():
            raw = bytearray()
            while not raw.endswith(b'\n'):
                raw.extend(os.read(self.output_read, 4096))
            received.append(bytes(raw))
            os.write(self.input_write, producer.encode_ack(parsed))
        thread = threading.Thread(target=host);thread.start()
        transport = producer.StdioProtocol(self.input_read, self.output_write)
        result = transport.exchange(wire, deadline=time.monotonic()+2)
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(received, [wire])
        self.assertEqual(producer.validate_ack(result, parsed)['durable_host_digest'], True)
        self.assertTrue(os.get_blocking(self.input_read) and os.get_blocking(self.output_write))

    def test_stdio_eof_and_absolute_deadline_refuse_restore_flags(self):
        wire = producer.encode_frame({'fixture_scope': 'MODELED'}, NONCE, 1)
        os.close(self.input_write)
        transport = producer.StdioProtocol(self.input_read, self.output_write)
        with self.assertRaisesRegex(producer.Refused, 'stdio-eof'):
            transport.exchange(wire, deadline=time.monotonic()+1)
        self.assertTrue(os.get_blocking(self.input_read) and os.get_blocking(self.output_write))
        with self.assertRaises(producer.Refused):transport.exchange(wire, deadline=time.monotonic()-1)

    def test_cli_strips_only_explicit_wrapper_options_preserves_original(self):
        args = ['--handoff-deadline', repr(time.monotonic()+2), '--inputs', '/inputs/manifest.json',
                '--inputs-sha256', 'd'*64, '--allow-disposable-repository-test']
        protocol = ModeledProtocol()
        with mock.patch.dict(os.environ, {'CACHY_ASAHI_DISPOSABLE_REPOSITORY':NONCE}), \
             mock.patch.object(producer, 'observe', return_value={'fixture_scope':'MODELED'}) as observe:
            producer.main(args, protocol=protocol)
        kwargs = observe.call_args.kwargs
        self.assertEqual(kwargs['argv'], args[2:])
        self.assertEqual(kwargs['nonce'], NONCE)
        self.assertEqual(observe.call_args.args[:2], (Path('/runner/repository.py'), protocol))

    def test_real_term_during_fd_flag_restoration_restores_both(self):
        wire = producer.encode_frame({'fixture_scope':'MODELED'}, NONCE, 1)
        os.close(self.input_write)
        actual, fired = os.set_blocking, []
        def setter(fd, blocking):
            result = actual(fd, blocking)
            if blocking and not fired:
                fired.append(True);os.kill(os.getpid(), signal.SIGTERM)
            return result
        with producer.cancellation_handlers(), mock.patch.object(os, 'set_blocking', side_effect=setter):
            with self.assertRaises(producer.Cancelled):
                producer.StdioProtocol(self.input_read, self.output_write).exchange(wire, deadline=time.monotonic()+1)
        self.assertEqual(fired,[True]);self.assertTrue(os.get_blocking(self.input_read) and os.get_blocking(self.output_write))
        self.assertEqual(producer.PENDING, [])



class GuardAndReadTests(unittest.TestCase):
    def test_modeled_terminal_write_before_or_after_term_cannot_return_pass(self):
        # Replaces only the compiled module's main with an explicit model. No
        # guard-positive frozen worker, GPG, Docker or native actor is executed.
        original_argv = sys.argv
        for after_write in (False, True):
            with self.subTest(after_write=after_write), tempfile.TemporaryDirectory() as directory:
                terminal = Path(directory)/'MODELED-private-original-result.json'
                def install_modeled_main(module, checkpoints):
                    def modeled_main():
                        checkpoints.emit({'fixture_scope':'MODELED','part':1})
                        checkpoints.emit({'fixture_scope':'MODELED','part':2})
                        if after_write:terminal.write_bytes(b'{"status":"PASS","scope":"MODELED"}')
                        os.kill(os.getpid(), signal.SIGTERM)
                        if not after_write:terminal.write_bytes(b'{"status":"PASS","scope":"MODELED"}')
                    module.main = modeled_main
                    return module.Integration
                with mock.patch.object(producer, 'observer_class', side_effect=install_modeled_main):
                    with self.assertRaises(producer.Cancelled):
                        producer.observe(ROOT/'scripts/integration/repository.py', ModeledProtocol(), nonce=NONCE,
                                         deadline=time.monotonic()+2, argv=['MODELED-only'])
                self.assertIs(sys.argv, original_argv)
                self.assertEqual(terminal.exists(), after_write)

    def test_real_frozen_main_guard_refuses_before_mutating_worker(self):
        original_argv = sys.argv
        protocol = ModeledProtocol()
        with mock.patch('subprocess.run', side_effect=AssertionError('no actual actor commands')):
            with self.assertRaises(Exception):
                producer.observe(ROOT / 'scripts/integration/repository.py', protocol, nonce=NONCE,
                    deadline=time.monotonic() + 10, argv=['--inputs', '/not-present-contract', '--inputs-sha256', 'f' * 64])
        self.assertIs(sys.argv, original_argv);self.assertEqual(protocol.frames, [])

    def test_source_pin_refused_before_compile_and_signal_handlers(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'repository.py';path.write_bytes(b'raise AssertionError("must not run")\n')
            with mock.patch.object(producer, 'cancellation_handlers', side_effect=AssertionError('must not install')):
                with self.assertRaisesRegex(producer.Refused, 'source-pin'):
                    producer.observe(path, ModeledProtocol(), nonce=NONCE, deadline=time.monotonic()+10)

    def test_regular_single_link_stable_nofollow_reads(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name);path = root/'file';path.write_bytes(b'actual regular bytes')
            self.assertEqual(producer.read(path), b'actual regular bytes')
            alias=root/'alias';alias.symlink_to(path)
            with self.assertRaises(OSError):producer.read(alias)
            os.link(path,root/'hardlink')
            with self.assertRaises(producer.Refused):producer.read(path)
            with self.assertRaises(producer.Refused):producer.read(path,1)

    def test_real_int_and_term_handlers_restore_original_pair(self):
        originals = {number: signal.getsignal(number) for number in producer.SIGNALS}
        for number in producer.SIGNALS:
            with producer.cancellation_handlers(), self.assertRaises(producer.Cancelled):signal.raise_signal(number)
            self.assertEqual({n:signal.getsignal(n) for n in producer.SIGNALS}, originals)
        self.assertEqual(producer.PENDING, [])


if __name__ == '__main__':
    unittest.main()

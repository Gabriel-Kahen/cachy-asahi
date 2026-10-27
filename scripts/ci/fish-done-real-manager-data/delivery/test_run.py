# SPDX-License-Identifier: MIT
"""Focused inert constructor, ownership and real-message refusal controls."""
import copy
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import run as R
import observation as O


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_exact_retained_validators_and_runtime_pins(self):
        self.assertEqual(hashlib.sha256((HERE/'native_inputs.py').read_bytes()).hexdigest(), R.BASE_SHA256)
        pins = json.loads((HERE/'source-pins.json').read_bytes())
        for name, digest in pins.items():
            self.assertEqual(hashlib.sha256((HERE/name).read_bytes()).hexdigest(), digest, name)

    def test_wrong_input_hash_refuses_before_actors_or_work(self):
        p = self.root/'inputs.json'; p.write_text('{}')
        with patch.object(R.subprocess, 'Popen', side_effect=AssertionError('actor before input validation')):
            with self.assertRaisesRegex(ValueError, 'hash/drift'):
                R.preflight(str(p), '0'*64, str(self.root/'fresh'), 'archive-staged')
        self.assertFalse((self.root/'fresh').exists())

    def test_isolation_argv_has_no_live_bus_display_device_or_home(self):
        plan = dict(work=self.root/'fresh', context='archive-staged', tools={'bwrap': (Path('/usr/bin/bwrap'), b'')})
        argv = R.argv(plan)
        self.assertIn('--unshare-all', argv); self.assertIn('--clearenv', argv)
        self.assertNotIn('--dev-bind', argv); self.assertNotIn('/dev/dri', argv)
        self.assertNotIn('/run/user', argv); self.assertNotIn(os.environ.get('HOME'), argv)
        self.assertNotIn('DBUS_SESSION_BUS_ADDRESS', argv); self.assertNotIn('WAYLAND_DISPLAY', argv)
        self.assertNotIn('/var/lib/pacman', argv)
        plan['context'] = 'alpm-installed'
        self.assertIn('/var/lib/pacman', R.argv(plan))

    def test_namespace_root_mapping_preserves_host_root_requirement(self):
        self.assertEqual(R.mapped_root('uid', '1000 1000 1\n', 65534), 65534)
        self.assertEqual(R.mapped_root('gid', '1000 1000 1\n', 65534), 65534)
        self.assertEqual(R.mapped_root('uid', '0 0 4294967295\n', 65534), 0)
        self.assertEqual(R.mapped_root('uid', '100 0 10\n', 65534), 100)
        for bad in ('', '0 0 0', '0 -1 1'):
            with self.assertRaises(ValueError): R.mapped_root('uid', bad, 65534)

    def installed_fixture(self):
        p = self.root/'usr/share/done.fish'; p.parent.mkdir(parents=True); p.write_bytes(b'held product')
        p.chmod(0o644)
        lock = dict(name='cachy-asahi-fish-done', version='0.1.0-2', payload={
            'usr/share/done.fish': dict(mode=0o644, size=12, sha256=hashlib.sha256(b'held product').hexdigest())})
        def query(argv):
            return 'cachy-asahi-fish-done '+('0.1.0-2\n' if argv[1] == '-Q' else '/usr/share/done.fish\n')
        return p, lock, query

    def test_installed_refuses_unregistered_or_foreign_file_lists(self):
        _, lock, _ = self.installed_fixture()
        with self.assertRaisesRegex(ValueError, 'installed version'):
            R.installed(lambda argv: 'cachy-asahi-fish-done 0.1.0-1', lock, self.root)
        def foreign(argv):
            return 'cachy-asahi-fish-done 0.1.0-2' if argv[1] == '-Q' else 'foreign /usr/share/done.fish'
        with self.assertRaisesRegex(ValueError, 'foreign ALPM'):
            R.installed(foreign, lock, self.root)

    def test_installed_exact_bytes_mode_and_namespace_owner(self):
        p, lock, query = self.installed_fixture()
        owners = (os.getuid(), os.getgid())
        self.assertEqual(R.installed(query, lock, self.root, owners)['status'], 'VERIFIED_ALPM_INSTALLED_PAYLOAD')
        with self.assertRaisesRegex(ValueError, 'installed payload drift'):
            R.installed(query, lock, self.root, (65533, 65533))
        p.write_bytes(b'held changed')
        with self.assertRaisesRegex(ValueError, 'installed payload drift'):
            R.installed(query, lock, self.root, owners)

    def test_installed_refuses_symlink_even_to_matching_bytes(self):
        p, lock, query = self.installed_fixture()
        target = self.root/'original'; target.write_bytes(p.read_bytes()); p.unlink(); p.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'installed payload drift'):
            R.installed(query, lock, self.root, (os.getuid(), os.getgid()))

    def test_product_no_lowered_threshold_or_replaced_runtime(self):
        source = (HERE/'controller.py').read_text()
        self.assertNotIn('caa_done_min_duration 80', source)
        self.assertNotIn('function __done_notify', source)
        self.assertIn("WLR_RENDERER='pixman'", source)
        self.assertIn('command sleep 5.25', source)
        self.assertIn("'pacman': '/usr/bin/pacman'", (HERE/'run.py').read_text())

    def real_rows(self):
        value = json.loads((HERE/'fixtures/real-foreground-success.json').read_bytes())
        raw = base64.b64decode(value['case']['monitor']['raw_base64'], validate=True)
        return value, O.messages(raw)

    def test_original_real_mako_call_reply_content_listing_and_expiry(self):
        value, rows = self.real_rows()
        wire = O.notify(rows, value['daemon']['owner'], 0)
        self.assertEqual(wire, value['case']['wire'])
        self.assertEqual(O.listing([value['case']['daemon_listing']], wire), value['case']['daemon_listing'])
        close = O.closure_facts(base64.b64decode(value['case']['monitor']['raw_base64']), wire)
        self.assertEqual(close['matching_closed_signals'][0]['signal']['payload']['data'], [wire['id'], 1])

    def test_real_wire_mutated_body_expiry_urgency_and_privacy_refused(self):
        value, original = self.real_rows()
        for field, changed in ((4, 'Foreground command: secret'), (7, 6000), (0, 'fake-fish')):
            rows = copy.deepcopy(original)
            call = next(r for r in rows if r.get('member') == 'Notify')
            call['payload']['data'][field] = changed
            with self.assertRaises(ValueError): O.notify(rows, value['daemon']['owner'], 0)
        rows = copy.deepcopy(original)
        call = next(r for r in rows if r.get('member') == 'Notify')
        call['payload']['data'][6]['urgency']['data'] = 2
        with self.assertRaises(ValueError): O.notify(rows, value['daemon']['owner'], 0)

    def test_real_wire_foreign_reply_duplicate_and_missing_reply_refused(self):
        value, original = self.real_rows()
        call = next(r for r in original if r.get('member') == 'Notify')
        def is_reply(row):
            return row.get('type') == 'method_return' and row.get('destination') == call['sender'] and \
                   row.get('reply_cookie', row.get('reply-cookie')) == call['cookie']
        rows = copy.deepcopy(original)
        next(r for r in rows if is_reply(r))['sender'] = ':9.999'
        with self.assertRaisesRegex(ValueError, 'foreign recipient'): O.notify(rows, value['daemon']['owner'], 0)
        with self.assertRaisesRegex(ValueError, 'duplicate notification'):
            O.notify(original+[call], value['daemon']['owner'], 0)
        self.assertIsNone(O.notify([r for r in original if not is_reply(r)], value['daemon']['owner'], 0))

    def test_actual_daemon_list_cannot_substitute_other_notification(self):
        value, rows = self.real_rows()
        wire = O.notify(rows, value['daemon']['owner'], 0)
        listing = copy.deepcopy(value['case']['daemon_listing'])
        listing['id'] += 1
        self.assertIsNone(O.listing([listing], wire))
        listing['id'] = wire['id']; listing['body'] = 'unrelated notice'
        with self.assertRaisesRegex(ValueError, 'listing/wire'): O.listing([listing], wire)


if __name__ == '__main__':
    unittest.main()

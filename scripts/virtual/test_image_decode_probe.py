# SPDX-License-Identifier: MIT
"""Strict observation parser and fixtures; future binding API, no adapter adoption."""
import copy
import hashlib
import json
from pathlib import Path
import re
import unittest
import base64
import struct
import tempfile
from unittest import mock
import image_decode_report as report

from image_decode_report import (MAX_REPORT, ASSET_PATH, CACHE_PATH, CONTEXT_HASHES, CONTEXT_KEYS,
    need, decode, parse_report, parse_bound_report)


def fixture():
    return {'schema_version': 1, 'scope': 'fixed-adwaita-svg-observation', 'observation_only': True,
        'asset': {'status': 'ok', 'size': 123, 'sha256': 'a' * 64, 'errno': 0},
        'cache': {'status': 'ok', 'size': 456, 'sha256': 'b' * 64, 'errno': 0},
        'content_type': {'status': 'observed', 'value': 'image/svg+xml', 'uncertain': False, 'is_svg': True},
        'formats': {'status': 'observed', 'entries': [{'name': 'png', 'disabled': False}, {'name': 'svg', 'disabled': True}]},
        'decode': {'status': 'error', 'width': None, 'height': None, 'error_domain': 1, 'error_code': 0}}


def encoded(row): return json.dumps(row, separators=(',', ':'), allow_nan=False).encode()


class ReportTests(unittest.TestCase):
    def rejected(self, changes):
        for change in changes:
            row = fixture(); change(row)
            with self.subTest(row=row), self.assertRaises(ValueError): parse_report(encoded(row))

    def test_error_and_success_are_observations(self):
        row = fixture(); self.assertEqual(parse_report(encoded(row)), row)
        row['decode'].update(status='success', width=16, height=16, error_domain=None, error_code=None)
        self.assertEqual(parse_report(encoded(row)), row)
        self.assertNotIn('status', row); self.assertNotIn('accepted', row)

    def test_missing_cache_does_not_disable_mime_or_memory_decode(self):
        row = fixture(); row['cache'].update(status='missing', size=None, sha256=None, errno=2)
        self.assertEqual(parse_report(encoded(row)), row)
        row['content_type']['is_svg'] = False; row['content_type']['value'] = 'application/octet-stream'
        self.assertEqual(parse_report(encoded(row)), row)

    def test_unavailable_asset_disables_content_and_decode(self):
        row = fixture(); row['asset'].update(status='missing', size=None, sha256=None, errno=2)
        row['content_type'].update(status='not-attempted', value=None, uncertain=None, is_svg=None)
        row['decode'].update(status='not-attempted', error_domain=None, error_code=None)
        self.assertEqual(parse_report(encoded(row)), row)
        row = fixture(); row['content_type'].update(status='not-attempted', value=None, uncertain=None, is_svg=None)
        with self.assertRaises(ValueError): parse_report(encoded(row))

    def test_closed_shapes_and_no_producer_acceptance(self):
        self.rejected([lambda r: r.update(status='PASS'), lambda r: r.update(context={}),
            lambda r: r.update(accepted=True), lambda r: r.pop('cache'), lambda r: r.update(schema_version=True),
            lambda r: r.update(observation_only=1), lambda r: r['decode'].update(error_message='private text'),
            lambda r: r['asset'].update(path='/tmp/arbitrary')])

    def test_file_identity_and_errno_relations(self):
        self.rejected([lambda r: r['asset'].update(size=True), lambda r: r['cache'].update(size=16 * 1024**2 + 1),
            lambda r: r['asset'].update(size=262145), lambda r: r['asset'].update(sha256='A' * 64),
            lambda r: r['asset'].update(sha256=None),
            lambda r: r['asset'].update(errno=1), lambda r: r['asset'].update(status='missing'),
            lambda r: r['cache'].update(status='io-error', size=None, sha256=None, errno=0),
            lambda r: r['cache'].update(status='missing', size=None, sha256=None, errno=0)])

    def test_mime_and_boolean_fields_are_closed(self):
        self.rejected([lambda r: r['content_type'].update(value='image/svg+xml\nSECRET'),
            lambda r: r['content_type'].update(value='é/svg'), lambda r: r['content_type'].update(value='x/' + 'a' * 128),
            lambda r: r['content_type'].update(uncertain=0), lambda r: r['content_type'].update(is_svg=1),
            lambda r: r['content_type'].update(status='not-attempted'), lambda r: r['content_type'].update(value=None)])

    def test_format_order_bounds_types_and_refusal(self):
        self.rejected([lambda r: r['formats']['entries'].reverse(),
            lambda r: r['formats']['entries'].append({'name': 'svg', 'disabled': False}),
            lambda r: r['formats'].update(entries=[{'name': 'a' * 65, 'disabled': False}]),
            lambda r: r['formats'].update(entries=[{'name': 'a/b', 'disabled': False}]),
            lambda r: r['formats']['entries'][0].update(disabled=0), lambda r: r['formats'].update(status='limit'),
            lambda r: r['formats'].update(entries=[{'name': f'f{i:02}', 'disabled': False} for i in range(65)])])
        row = fixture(); row['formats'].update(status='name-refused', entries=[])
        self.assertEqual(parse_report(encoded(row)), row)

    def test_descriptive_names_and_duplicate_descriptors_preserve_svg(self):
        row = fixture()
        descriptors = [('Digital camera RAW', False), ('bmp', False), ('bmp', True),
                       ('png', False), ('svg', False), ('svg', True), ('svg', True)]
        row['formats']['entries'] = [{'name': name, 'disabled': disabled} for name, disabled in descriptors]
        observed = parse_report(encoded(row))['formats']['entries']
        self.assertEqual(observed, row['formats']['entries'])
        self.assertEqual(sum(entry['name'] == 'svg' for entry in observed), 3)

    def test_decode_semantics_and_numeric_limits(self):
        self.rejected([lambda r: r['decode'].update(error_domain=True), lambda r: r['decode'].update(error_code=2**31),
            lambda r: r['decode'].update(error_domain=2**32), lambda r: r['decode'].update(width=1),
            lambda r: r['decode'].update(status='not-attempted', error_domain=None, error_code=None),
            lambda r: r['decode'].update(status='success', width=0, height=1, error_domain=None, error_code=None),
            lambda r: r['decode'].update(status='success', width=1, height=32769, error_domain=None, error_code=None)])

    def test_exact_boundaries_and_all_unavailable_states(self):
        row = fixture(); row['asset']['size'] = 262144; row['cache']['size'] = 16777216
        row['decode'].update(error_domain=2**32 - 1, error_code=-(2**31))
        row['formats']['entries'] = [{'name': f'f{i:02}', 'disabled': False} for i in range(64)]
        self.assertEqual(parse_report(encoded(row)), row)
        for status, errno in (('refused', 0), ('changed', 0), ('io-error', 13)):
            row['cache'].update(status=status, size=None, sha256=None, errno=errno)
            self.assertEqual(parse_report(encoded(row)), row)

    def test_json_duplicates_nonfinite_depth_bytes_and_utf8(self):
        raw = encoded(fixture())
        for bad in (raw.replace(b'"errno":0', b'"errno":0,"errno":0', 1), b'{"x":NaN}', b'{"x":1.0}',
                    b'[' * 9 + b'0' + b']' * 9, b' ' * (MAX_REPORT + 1), b'\xff', b'', b'{', b'[]'):
            with self.subTest(raw=bad[:80]), self.assertRaises(ValueError): parse_report(bad)
        with self.assertRaises(ValueError): parse_report(raw.decode())
        with self.assertRaises(ValueError): decode(b'{"nodes":[' + b'0,' * 512 + b'0]}')


class BindingTests(unittest.TestCase):
    def setUp(self):
        self.raw = encoded(fixture()); self.pin = hashlib.sha256(self.raw).hexdigest()
        self.context = {key: 'c' * 64 for key in CONTEXT_HASHES}
        self.context.update(asset_sha256='a' * 64, run_id='38274341668', run_attempt='1')
        self.binding = {'schema_version': 1, 'scope': 'supervisor-bound-image-decode-observation',
                        'observation_only': True, 'context': copy.deepcopy(self.context), 'report_sha256': self.pin}

    def parse(self, **options):
        return parse_bound_report(options.get('raw', self.raw), options.get('binding', self.binding),
            options.get('context', self.context), expected_report_sha256=options.get('pin', self.pin))

    def test_external_binding_keeps_observations_separate(self):
        result = self.parse(); self.assertEqual(set(result), {'binding', 'observation'})
        self.binding['context']['run_attempt'] = '9'
        self.assertEqual(result['binding']['context']['run_attempt'], '1')

    def test_each_forged_or_missing_context_field_refused(self):
        for key in CONTEXT_KEYS:
            for missing in (False, True):
                binding = copy.deepcopy(self.binding)
                if missing: binding['context'].pop(key)
                else: binding['context'][key] = '2' if key.startswith('run_') else 'd' * 64
                with self.subTest(key=key, missing=missing), self.assertRaises(ValueError): self.parse(binding=binding)
        context = dict(self.context, unexpected='producer-data')
        with self.assertRaises(ValueError): self.parse(context=context)

    def test_missing_external_hash_and_rehashed_producer_cannot_bind(self):
        for pin in (None, True, 'A' * 64, 'd' * 64):
            with self.subTest(pin=pin), self.assertRaises(ValueError): self.parse(pin=pin)
        raw = self.raw + b' '; binding = dict(self.binding, report_sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(ValueError): self.parse(raw=raw, binding=binding)
        binding = dict(self.binding); binding.pop('report_sha256')
        with self.assertRaises(ValueError): self.parse(binding=binding)

    def test_binding_types_and_producer_success_claim_refused(self):
        for field, value in (('schema_version', True), ('observation_only', 1), ('status', 'PASS'), ('accepted', True)):
            with self.subTest(field=field), self.assertRaises(ValueError): self.parse(binding=dict(self.binding, **{field: value}))
        binding = copy.deepcopy(self.binding); binding['context']['run_attempt'] = True
        with self.assertRaises(ValueError): self.parse(binding=binding)

    def test_asset_pin_is_external_and_missing_asset_is_diagnostic(self):
        context = dict(self.context, asset_sha256='d' * 64); binding = dict(self.binding, context=context)
        with self.assertRaises(ValueError): self.parse(binding=binding, context=context)
        row = fixture(); row['asset'].update(status='missing', size=None, sha256=None, errno=2)
        row['content_type'].update(status='not-attempted', value=None, uncertain=None, is_svg=None)
        row['decode'].update(status='not-attempted', error_domain=None, error_code=None)
        raw = encoded(row); pin = hashlib.sha256(raw).hexdigest(); binding = dict(binding, report_sha256=pin)
        self.assertEqual(self.parse(raw=raw, pin=pin, binding=binding, context=context)['observation'], row)


def source_controls(raw):
    """Narrow source text checks; neither compilation nor a runtime proof."""
    need(type(raw) is bytes and len(raw) <= 128 * 1024, 'bounded source bytes')
    text = raw.decode('ascii')
    need(re.findall(r'#define (ASSET|CACHE) "([^"\n]+)"', text) ==
         [('ASSET', ASSET_PATH), ('CACHE', CACHE_PATH)], 'fixed input constants')
    need('(void)argv;' in text and 'if (argc != 1) return 64;' in text and
         not re.search(r'argv\s*\[', text), 'no caller path arguments')
    compact = re.sub(r'\s+', '', text)
    need('snapshot(ASSET,256*1024)' in compact and 'snapshot(CACHE,16*1024*1024)' in compact and
         '#defineMAX_FORMATS64' in compact and 'out->len<=16384' in compact, 'fixed source bounds')
    need('g_memory_input_stream_new_from_data(asset.bytes,(gssize)asset.size,NULL)' in compact and
         compact.count('gdk_pixbuf_new_from_stream(stream,NULL,&error)') == 1 and
         not re.search(r'gdk_pixbuf_new_from_file\w*\s*\(', text), 'once-captured memory decode')


class SourceControls(unittest.TestCase):
    def test_held_fixed_path_argc_bounds_and_memory_decode(self):
        raw = Path(__file__).with_name('image_decode_probe.c').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
            'e5857f60f664ccfeb8a2275396c4a4f8ed6412f14bb5237e71bd34582479ba3a')
        source_controls(raw)

    def test_source_controls_refuse_scope_and_decode_substitution(self):
        raw = Path(__file__).with_name('image_decode_probe.c').read_bytes()
        bad = (raw.replace(ASSET_PATH.encode(), b'/tmp/arbitrary.svg'),
               raw.replace(b'argc != 1', b'argc != 2'), raw.replace(b'256 * 1024', b'1024 * 1024'),
               raw.replace(b'gdk_pixbuf_new_from_stream(stream, NULL, &error)',
                           b'gdk_pixbuf_new_from_file(ASSET, &error)'))
        for data in bad:
            self.assertNotEqual(data, raw)
            with self.assertRaises(ValueError): source_controls(data)



def guest_fixture():
    row = {key: 'c' * 64 for key in report.GUEST_HASHES}
    row.update(schema_version=1, scope='fixed-adwaita-svg-guest-contract', nonce='d' * 32,
               attempt=1, asset_sha256=report.ASSET_SHA256, source_sha256=report.C_SHA256)
    return row


def identity_fixture(path):
    return {'path': path, 'resolved_path': path, 'sha256': 'c' * 64, 'bytes': 1, 'mode': 0o644}


def build_fixture():
    c = {'nonce': 'd' * 32, 'source_commit': 'a' * 40, 'image_id': 'sha256:' + 'c' * 64,
         'baseline_image_id': 'sha256:' + 'b' * 64, 'tooling_lock_sha256': 'a' * 64,
         'tooling_audit_sha256': 'b' * 64, 'run_id': '38307993177', 'run_attempt': '1',
         'runner_sha256': {key: 'c' * 64 for key in report.CORE_FILES}}
    c['runner_sha256']['image_decode_probe.c'] = report.C_SHA256
    packages = {'glib2': '2.90.1-1', 'gdk-pixbuf2': '2.44.8-1'}
    guest = guest_fixture(); guest.update(core_sha256=report.core_sha256(c['runner_sha256']),
                                        package_inventory_sha256=report.inventory_sha256(packages))
    header_paths = ['/usr/include/gdk-pixbuf-2.0/gdk-pixbuf/gdk-pixbuf.h',
        '/usr/include/glib-2.0/gio/gio.h', '/usr/include/glib-2.0/glib.h', '/usr/include/glib-2.0/glib/gtypes.h',
        '/usr/include/glib-2.0/gobject/gobject.h', '/usr/lib/glib-2.0/include/glibconfig.h']
    build = {'status': 'BUILT', 'guest_contract': guest,
        'guest_contract_sha256': report.canonical_sha256(guest), 'source_commit': c['source_commit'],
        'proof_contract_sha256': 'e' * 64, 'run_id': c['run_id'], 'run_attempt': c['run_attempt'],
        'helper': {'bytes': 256, 'sha256': 'c' * 64, 'mode': 0o755},
        'elf': {'class': 64, 'encoding': 'little-endian', 'machine': 183, 'type': 'DYN', 'entry': 0,
                'load_segments': [{'offset': 0, 'virtual_address': 0, 'file_size': 256,
                                   'memory_size': 256, 'alignment': 16384}], 'compatible_16k': True},
        'provenance': {'baseline_image_id': c['baseline_image_id'], 'tooling_lock_sha256': c['tooling_lock_sha256'],
            'tooling_audit_sha256': c['tooling_audit_sha256'], 'compiler': identity_fixture('/usr/bin/cc'),
            'pkg_config': identity_fixture('/usr/bin/pkg-config'),
            'headers': [identity_fixture(path) for path in sorted(header_paths)],
            'pc_files': [identity_fixture('/usr/lib/pkgconfig/' + name + '.pc') for name in report.PC_NAMES],
            'pkg_config_argv': list(report.PKG_ARGV), 'pkg_config_stdout_sha256': 'e' * 64,
            'flags': ['-I/usr/include/glib-2.0', '-lgio-2.0'],
            'compile_argv': list(report.COMPILE_PREFIX) + ['-I/usr/include/glib-2.0', '-lgio-2.0'],
            'compile_log_sha256': 'f' * 64}}
    return build, c, packages


class GuestContractTests(unittest.TestCase):
    def test_closed_guest_contract_all_pins_and_fixed_inputs(self):
        self.assertEqual(report.validate_guest_contract(guest_fixture()), guest_fixture())
        for key in report.GUEST_KEYS:
            row = guest_fixture(); row.pop(key)
            with self.subTest(key=key), self.assertRaises(ValueError): report.validate_guest_contract(row)
        for key, value in (('attempt', True), ('schema_version', True), ('source_sha256', 'c' * 64),
                           ('asset_sha256', 'c' * 64), ('nonce', 'd' * 31), ('image_sha256', 'c' * 64)):
            row = guest_fixture(); row[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): report.validate_guest_contract(row)

    def test_inventory_and_core_reproducible_without_self_image_hash(self):
        packages = {'b': '2', 'a': '1'}
        self.assertEqual(report.inventory_sha256(packages), hashlib.sha256(b'a 1\nb 2\n').hexdigest())
        self.assertEqual(report.inventory_sha256(packages), report.inventory_sha256({'a': '1', 'b': '2'}))
        for bad in ({}, {'a\nb': '1'}, {'a': True}, {'a': '1 2'}):
            with self.subTest(bad=bad), self.assertRaises(ValueError): report.inventory_sha256(bad)
        mapping = {key: 'c' * 64 for key in report.CORE_FILES}
        self.assertEqual(report.core_sha256(mapping), report.canonical_sha256(mapping))
        with self.assertRaises(ValueError): report.core_sha256(dict(mapping, unexpected='c' * 64))
        self.assertNotIn('image_sha256', report.GUEST_KEYS)

    def test_event_decode_error_and_missing_cache_are_observations(self):
        row = fixture(); row['cache'].update(status='missing', size=None, sha256=None, errno=2)
        raw = encoded(row)
        event = {'event': 'image_decode_probe', 'nonce': 'd' * 32, 'stage': 'minimal', 'elapsed_ms': 20000,
                 'returncode': 0, 'error': None, 'report_sha256': hashlib.sha256(raw).hexdigest(),
                 'report_base64': base64.b64encode(raw).decode('ascii')}
        self.assertEqual(report.validate_event(event, 'd' * 32), raw)
        for key, value in (('elapsed_ms', True), ('elapsed_ms', 20001), ('returncode', True),
            ('returncode', 1), ('error', 'private'), ('nonce', 'a' * 32), ('stage', 'overlay'),
            ('report_sha256', 'c' * 64), ('report_base64', event['report_base64'] + '='), ('private', 'text')):
            bad = dict(event); bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): report.validate_event(bad, 'd' * 32)
        for raw in (b'\xff', b'{}', b' ' * 16385):
            bad = dict(event, report_base64=base64.b64encode(raw).decode(), report_sha256=hashlib.sha256(raw).hexdigest())
            with self.subTest(raw=raw[:10]), self.assertRaises(ValueError): report.validate_event(bad, 'd' * 32)

    def test_event_failures_never_publish_report_or_invent_elapsed(self):
        event = {'event': 'image_decode_probe', 'nonce': 'd' * 32, 'stage': 'minimal', 'elapsed_ms': None,
                 'returncode': None, 'error': 'launch', 'report_sha256': None, 'report_base64': None}
        for error in report.ERRORS:
            self.assertIsNone(report.validate_event(dict(event, error=error), 'd' * 32))
        for key, value in (('elapsed_ms', 20000), ('report_sha256', 'a' * 64), ('report_base64', 'e30='),
                           ('returncode', True), ('returncode', -65), ('returncode', 256)):
            bad = dict(event); bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): report.validate_event(bad, 'd' * 32)


class BuildReceiptTests(unittest.TestCase):
    def check(self, build, c, packages):
        return report.validate_build(build, c, 'e' * 64, packages)

    def test_same_image_closed_receipt_binds_external_context(self):
        build, c, packages = build_fixture()
        self.assertEqual(self.check(build, c, packages), build['guest_contract'])
        for key in report.BUILD_KEYS:
            bad = copy.deepcopy(build); bad.pop(key)
            with self.subTest(key=key), self.assertRaises(ValueError): self.check(bad, c, packages)
        for key in report.GUEST_HASHES:
            bad = copy.deepcopy(build); bad['guest_contract'][key] = 'f' * 64
            bad['guest_contract_sha256'] = report.canonical_sha256(bad['guest_contract'])
            with self.subTest(key=key), self.assertRaises(ValueError): self.check(bad, c, packages)

    def test_rehashed_receipt_cannot_substitute_workflow_source_or_tooling(self):
        build, c, packages = build_fixture()
        for key, value in (('run_id', '9'), ('run_attempt', '2'), ('source_commit', 'f' * 40),
                           ('proof_contract_sha256', 'f' * 64), ('status', 'PASS')):
            bad = copy.deepcopy(build); bad[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.check(bad, c, packages)
        for key, value in (('baseline_image_id', 'sha256:' + 'f' * 64), ('tooling_lock_sha256', 'f' * 64),
            ('tooling_audit_sha256', 'f' * 64), ('pkg_config_argv', ['/usr/bin/false']), ('flags', ['-Wl,evil']),
            ('compile_argv', ['/usr/bin/cc']), ('private', 'text')):
            bad = copy.deepcopy(build); bad['provenance'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.check(bad, c, packages)
        with self.assertRaises(ValueError): self.check(build, c, dict(packages, extra='1'))
        bad_c = dict(c, image_id='c' * 64)
        with self.assertRaises(ValueError): self.check(build, bad_c, packages)

    def test_header_pc_binary_and_elf_refusals(self):
        build, c, packages = build_fixture()
        for mutate in (lambda b: b['helper'].update(mode=True), lambda b: b['helper'].update(mode=0o644),
            lambda b: b['helper'].update(sha256='f' * 64), lambda b: b['helper'].update(bytes=0),
            lambda b: b['elf'].update(machine=62), lambda b: b['elf'].update(compatible_16k=False),
            lambda b: b['elf']['load_segments'][0].update(alignment=4096),
            lambda b: b['elf']['load_segments'][0].update(offset=16384),
            lambda b: b['provenance']['pc_files'].pop(),
            lambda b: b['provenance']['headers'].reverse(),
            lambda b: b['provenance'].update(headers=[row for row in b['provenance']['headers']
                                                     if row['path'] != '/usr/include/glib-2.0/glib.h']),
            lambda b: b['provenance']['headers'][0].update(resolved_path='/tmp/old-archive.h'),
            lambda b: b['provenance']['headers'].append(dict(b['provenance']['headers'][0]))):
            bad = copy.deepcopy(build); mutate(bad)
            with self.subTest(bad=bad), self.assertRaises(ValueError): self.check(bad, c, packages)

    def test_actual_elf_parser_on_inert_bytes_and_bad_alignment(self):
        import prepare
        raw = bytearray(256); raw[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHIQQQIHHH', raw, 16, 3, 183, 1, 0, 64, 0, 0, 64, 56, 1)
        struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 0, 0, 256, 256, 16384)
        with tempfile.TemporaryDirectory(prefix='image-decode-elf-') as directory:
            path = Path(directory) / 'inert.elf'; path.write_bytes(raw)
            self.assertTrue(prepare.elf_facts(path)['compatible_16k'])
            for offset, value in ((5, 2), (18, 62), (113, 16)):
                bad = bytearray(raw); bad[offset] = value; path.write_bytes(bad)
                with self.subTest(offset=offset), self.assertRaises(ValueError): prepare.elf_facts(path)
            path.write_bytes(raw[:80])
            with self.assertRaises(ValueError): prepare.elf_facts(path)

    def test_build_refuses_missing_authority_before_new_actors(self):
        import prepare
        _, c, packages = build_fixture()
        for key, value in (('run_id', None), ('run_attempt', True), ('image_id', 'c' * 64),
                           ('baseline_image_id', None)):
            bad = dict(c); bad[key] = value; command = mock.Mock()
            with self.subTest(key=key), self.assertRaises(ValueError):
                prepare.build_image_decode(Path('/out/prepared/root'), bad, packages, 'e' * 64, command, {})
            command.assert_not_called()
        bad = copy.deepcopy(c); bad['runner_sha256']['image_decode_probe.c'] = 'f' * 64; command = mock.Mock()
        with self.assertRaises(ValueError):
            prepare.build_image_decode(Path('/out/prepared/root'), bad, packages, 'e' * 64, command, {})
        command.assert_not_called()

    def test_build_budgets_keep_original_deadline_and_cleanup_reserve(self):
        import prepare
        with mock.patch.object(prepare.time, 'monotonic', return_value=100):
            self.assertEqual(prepare.decode_build_budget(100, 15), 15)
            self.assertEqual(prepare.decode_build_budget(100, 60), 60)
        with mock.patch.object(prepare.time, 'monotonic', return_value=1293):
            self.assertEqual(prepare.decode_build_budget(100, 60), 2)
        for now in (1295, 1300, 1301):
            with mock.patch.object(prepare.time, 'monotonic', return_value=now), self.assertRaises(ValueError):
                prepare.decode_build_budget(100, 15)

    def test_build_uses_same_image_inputs_selected_flags_and_records_inert_elf(self):
        import prepare
        _, c, packages = build_fixture()
        raw = bytearray(256); raw[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHIQQQIHHH', raw, 16, 3, 183, 1, 0, 64, 0, 0, 64, 56, 1)
        struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 0, 0, 256, 256, 16384)
        with tempfile.TemporaryDirectory(prefix='image-decode-build-model-') as directory:
            folder = Path(directory)
            def mapped(path):
                path = str(path)
                return folder / path.lstrip('/') if path.startswith(('/usr/', '/runner/', '/out/')) else Path(path)
            for header in report.CRITICAL_HEADERS | {'/usr/include/glib-2.0/glib/gtypes.h'}:
                path = mapped(header); path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'inert header')
            parser = mapped('/runner/virtual/image_decode_report.py'); parser.parent.mkdir(parents=True)
            parser.write_bytes(b'# inert parser bytes; parent main verifies actual source pins\n')
            root = mapped('/out/prepared/root'); helper = root / 'usr/local/bin/image-decode-probe'
            helper.parent.mkdir(parents=True); asset = root / report.ASSET_PATH.lstrip('/')
            asset.parent.mkdir(parents=True); asset.write_bytes(b'inert labelled asset')
            captured = []; ledger = {'fixture_changes': [], 'commands': []}
            def command(argv, **options):
                captured.append((list(argv), options))
                ledger['commands'].append({'log_sha256': 'f' * 64})
                if argv[0] == '/usr/bin/cc': helper.write_bytes(raw)
                return {'stdout': '-I/usr/include/glib-2.0 -lgio-2.0\n', 'stderr': '', 'returncode': 0, 'error': None}
            actual_digest = prepare.digest
            def fixture_digest(path):
                return report.ASSET_SHA256 if path == asset else actual_digest(path)
            def fixture_identity(path):
                path = str(path)
                if path.startswith(str(folder)): path = '/' + str(Path(path).relative_to(folder))
                return identity_fixture(path)
            with mock.patch.object(prepare, 'Path', side_effect=mapped), \
                 mock.patch.object(prepare, 'file_identity', side_effect=fixture_identity), \
                 mock.patch.object(prepare, 'digest', side_effect=fixture_digest):
                prepare.build_image_decode(root, c, packages, 'e' * 64, command, ledger)
            self.assertEqual(captured[0], (list(report.PKG_ARGV), {'timeout': 15, 'limit': 16384, 'decode_build': True}))
            self.assertEqual(captured[1], (list(report.COMPILE_PREFIX) + ['-I/usr/include/glib-2.0', '-lgio-2.0'],
                                          {'timeout': 60, 'decode_build': True}))
            receipt = ledger['image_decode_build']
            self.assertEqual(report.validate_build(receipt, c, 'e' * 64, packages), receipt['guest_contract'])
            self.assertEqual(receipt['helper']['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertTrue(receipt['elf']['compatible_16k'])
            self.assertNotIn('image_sha256', receipt['guest_contract'])
            contract = root / 'usr/local/share/virtual-proof/image-decode-contract.json'
            self.assertEqual(hashlib.sha256(contract.read_bytes()).hexdigest(), receipt['guest_contract_sha256'])
            self.assertTrue(report.CRITICAL_HEADERS <= {row['path'] for row in receipt['provenance']['headers']})

    def test_same_image_capture_accepts_packaged_hardlinks_and_refuses_drift(self):
        import prepare
        from types import SimpleNamespace
        # Labelled immutable-image path, with real finite hardlink fixture stats; no target image access.
        with tempfile.TemporaryDirectory(prefix='image-decode-provenance-') as directory:
            first = Path(directory) / 'compiler'; second = Path(directory) / 'cc'
            first.write_bytes(b'inert packaged compiler bytes'); second.hardlink_to(first)
            before = first.stat(); self.assertEqual(before.st_nlink, 2)
            selected = mock.MagicMock(); selected.__str__.return_value = '/usr/bin/cc'
            resolved = mock.MagicMock(); resolved.__str__.return_value = '/usr/bin/aarch64-gcc'
            selected.resolve.return_value = resolved; resolved.stat.side_effect = [before, before]
            pin = hashlib.sha256(first.read_bytes()).hexdigest()
            with mock.patch.object(prepare, 'Path', return_value=selected), \
                 mock.patch.object(prepare, 'digest', return_value=pin):
                row = prepare.file_identity('/usr/bin/cc')
            self.assertEqual(row['sha256'], pin); self.assertEqual(row['resolved_path'], '/usr/bin/aarch64-gcc')
            after = SimpleNamespace(**{key: getattr(before, key) for key in
                ('st_mode', 'st_size', 'st_dev', 'st_ino', 'st_mtime_ns', 'st_ctime_ns')})
            after.st_size += 1; resolved.stat.side_effect = [before, after]
            with mock.patch.object(prepare, 'Path', return_value=selected), \
                 mock.patch.object(prepare, 'digest', return_value=pin), self.assertRaises(ValueError):
                prepare.file_identity('/usr/bin/cc')
            resolved.__str__.return_value = '/tmp/older-archive/compiler'
            with mock.patch.object(prepare, 'Path', return_value=selected), self.assertRaises(ValueError):
                prepare.file_identity('/usr/bin/cc')


if __name__ == '__main__':
    unittest.main()

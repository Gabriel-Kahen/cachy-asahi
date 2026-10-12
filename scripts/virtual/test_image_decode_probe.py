# SPDX-License-Identifier: MIT
"""Strict observation parser and fixtures; future binding API, no adapter adoption."""
import copy
import hashlib
import json
from pathlib import Path
import re
import unittest

MAX_REPORT = 16384
ASSET_PATH = '/usr/share/icons/Adwaita/scalable/status/image-missing.svg'
CACHE_PATH = '/usr/share/mime/mime.cache'
HASH = re.compile(r'[0-9a-f]{64}\Z')
FORMAT_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+ -]{0,63}\Z')
MIME = re.compile(r'[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*\Z')
CONTEXT_HASHES = frozenset(('source_sha256', 'image_sha256', 'tooling_sha256',
    'guest_sha256', 'helper_sha256', 'runtime_sha256', 'package_inventory_sha256', 'asset_sha256'))
CONTEXT_KEYS = CONTEXT_HASHES | {'run_id', 'run_attempt'}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def integer(value, lower, upper):
    return type(value) is int and lower <= value <= upper


def shape(value, keys):
    need(type(value) is dict and set(value) == set(keys), 'closed object required')


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_REPORT, 'bounded report bytes required')
    text = raw.decode('utf-8')
    depth = 0; quoted = escaped = False
    for char in text:
        if quoted:
            if escaped: escaped = False
            elif char == '\\': escaped = True
            elif char == '"': quoted = False
        elif char == '"': quoted = True
        elif char in '[{':
            depth += 1; need(depth <= 8, 'JSON depth bound')
        elif char in ']}': depth -= 1
    def unique(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key'); value[key] = item
        return value
    def no_number(_): raise ValueError('integer JSON numbers required')
    try:
        value = json.loads(text, object_pairs_hook=unique, parse_float=no_number, parse_constant=no_number)
    except (RecursionError, UnicodeError) as error:
        raise ValueError('invalid JSON') from error
    pending = [value]; count = 0
    while pending:
        item = pending.pop(); count += 1; need(count <= 512, 'JSON node bound')
        if type(item) is dict: pending.extend(item.values())
        elif type(item) is list: pending.extend(item)
    return value


def parse_report(raw):
    """Validate helper observations without interpreting them as acceptance."""
    row = decode(raw)
    shape(row, ('schema_version', 'scope', 'observation_only', 'asset', 'cache',
                'content_type', 'formats', 'decode'))
    need(type(row['schema_version']) is int and row['schema_version'] == 1 and type(row['scope']) is str and
         row['scope'] == 'fixed-adwaita-svg-observation' and row['observation_only'] is True,
         'observation schema required')
    for key, maximum in (('asset', 256 * 1024), ('cache', 16 * 1024**2)):
        file = row[key]; shape(file, ('status', 'size', 'sha256', 'errno'))
        need(type(file['status']) is str and file['status'] in
             ('ok', 'missing', 'refused', 'io-error', 'changed') and
             integer(file['errno'], 0, 2**31 - 1), 'file observation fields')
        if file['status'] == 'ok':
            need(integer(file['size'], 0, maximum) and type(file['sha256']) is str and
                 HASH.fullmatch(file['sha256']) and file['errno'] == 0, 'stable file observation')
        else:
            need(file['size'] is file['sha256'] is None, 'unavailable file has no content identity')
            need(file['status'] != 'missing' or file['errno'] == 2, 'missing errno')
            need(file['status'] != 'io-error' or file['errno'] > 0, 'I/O errno')
    content = row['content_type']; shape(content, ('status', 'value', 'uncertain', 'is_svg'))
    need(type(content['status']) is str and content['status'] in ('observed', 'not-attempted'), 'content status')
    need((content['status'] == 'observed') == (row['asset']['status'] == 'ok'), 'content attempt relation')
    if content['status'] == 'observed':
        need(row['asset']['status'] == 'ok' and type(content['value']) is str and
             len(content['value']) <= 128 and MIME.fullmatch(content['value']) and
             type(content['uncertain']) is type(content['is_svg']) is bool, 'content observation')
    else:
        need(all(content[key] is None for key in ('value', 'uncertain', 'is_svg')), 'unobserved content fields')
    formats = row['formats']; shape(formats, ('status', 'entries'))
    need(type(formats['status']) is str and formats['status'] in ('observed', 'limit', 'name-refused') and
         type(formats['entries']) is list and len(formats['entries']) <= 64, 'format bounds')
    descriptors = []
    for entry in formats['entries']:
        shape(entry, ('name', 'disabled'))
        need(type(entry['name']) is str and FORMAT_NAME.fullmatch(entry['name']) and
             type(entry['disabled']) is bool, 'format fields')
        descriptors.append((entry['name'], entry['disabled']))
    need(descriptors == sorted(descriptors), 'sorted format descriptors')
    need(formats['status'] == 'observed' or not descriptors, 'refused formats must be empty')
    result = row['decode']; shape(result, ('status', 'width', 'height', 'error_domain', 'error_code'))
    need(type(result['status']) is str and result['status'] in ('success', 'error', 'not-attempted'), 'decode status')
    need((result['status'] != 'not-attempted') == (row['asset']['status'] == 'ok'), 'decode attempt relation')
    if result['status'] == 'success':
        need(integer(result['width'], 1, 32768) and integer(result['height'], 1, 32768) and
             result['error_domain'] is result['error_code'] is None, 'successful decode fields')
    elif result['status'] == 'error':
        need(result['width'] is result['height'] is None and integer(result['error_domain'], 0, 2**32 - 1) and
             integer(result['error_code'], -(2**31), 2**31 - 1), 'decode error fields')
    else:
        need(all(result[key] is None for key in ('width', 'height', 'error_domain', 'error_code')), 'unattempted decode fields')
    return row


def validate_context(context):
    shape(context, CONTEXT_KEYS)
    need(all(type(context[key]) is str and HASH.fullmatch(context[key]) for key in CONTEXT_HASHES), 'external context pins')
    need(type(context['run_id']) is str and re.fullmatch(r'[0-9]{1,20}', context['run_id']) and
         type(context['run_attempt']) is str and re.fullmatch(r'[0-9]{1,10}', context['run_attempt']), 'external run binding')


def parse_bound_report(raw, binding, expected_context, *, expected_report_sha256):
    """Proposed matching API; expected values must come from a trusted supervisor.

    Matching these values does not authenticate a producer or adopt this probe.
    """
    shape(binding, ('schema_version', 'scope', 'observation_only', 'context', 'report_sha256'))
    need(type(binding['schema_version']) is int and binding['schema_version'] == 1 and type(binding['scope']) is str and
         binding['scope'] == 'supervisor-bound-image-decode-observation' and binding['observation_only'] is True,
         'binding schema')
    validate_context(binding['context']); validate_context(expected_context)
    need(binding['context'] == expected_context, 'external context mismatch')
    need(type(expected_report_sha256) is str and HASH.fullmatch(expected_report_sha256) and
         type(binding['report_sha256']) is str and binding['report_sha256'] == expected_report_sha256,
         'external report pin required')
    observation = parse_report(raw)
    need(hashlib.sha256(raw).hexdigest() == expected_report_sha256, 'report capture mismatch')
    if observation['asset']['status'] == 'ok':
        need(observation['asset']['sha256'] == expected_context['asset_sha256'], 'external asset pin mismatch')
    return {'binding': copy.deepcopy(binding), 'observation': observation}


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


if __name__ == '__main__':
    unittest.main()

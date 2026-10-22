# SPDX-License-Identifier: MIT
"""Closed observation and provenance validation for the fixed SVG guest probe."""
import base64
import binascii
import copy
import hashlib
import json
import re

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


ASSET_SHA256 = 'e66de83d084c5fc73430fe17950c6dad44ecb0ec59d30313ae1d57c9ea6d12c3'
C_SHA256 = 'e5857f60f664ccfeb8a2275396c4a4f8ed6412f14bb5237e71bd34582479ba3a'
CORE_FILES = frozenset(('common.py', 'guest.py', 'prepare.py', 'run.py', 'gbm_probe.c',
                        'image_decode_probe.c', 'image_decode_report.py'))
GUEST_HASHES = frozenset(('source_sha256', 'parser_sha256', 'helper_sha256', 'guest_sha256',
    'runtime_sha256', 'core_sha256', 'tooling_sha256', 'package_inventory_sha256', 'asset_sha256'))
GUEST_KEYS = GUEST_HASHES | {'schema_version', 'scope', 'nonce', 'attempt'}
EVENT_KEYS = frozenset(('event', 'nonce', 'stage', 'elapsed_ms', 'returncode', 'error',
                        'report_sha256', 'report_base64'))
ERRORS = frozenset(('launch', 'timeout', 'output-overflow', 'protocol', 'identity', 'deadline', 'cleanup'))
BUILD_KEYS = frozenset(('status', 'guest_contract', 'guest_contract_sha256', 'source_commit',
    'proof_contract_sha256', 'run_id', 'run_attempt', 'helper', 'elf', 'provenance'))
PC_NAMES = ('gdk-pixbuf-2.0', 'gio-2.0', 'glib-2.0', 'gobject-2.0')
HEADER_ROOTS = ('/usr/include/gdk-pixbuf-2.0', '/usr/include/glib-2.0', '/usr/lib/glib-2.0/include')
CRITICAL_HEADERS = frozenset(('/usr/include/glib-2.0/glib.h', '/usr/include/glib-2.0/gio/gio.h',
    '/usr/include/glib-2.0/gobject/gobject.h', '/usr/lib/glib-2.0/include/glibconfig.h',
    '/usr/include/gdk-pixbuf-2.0/gdk-pixbuf/gdk-pixbuf.h'))
PKG_ARGV = ['/usr/bin/pkg-config', '--cflags', '--libs', 'gio-2.0', 'gdk-pixbuf-2.0']
COMPILE_PREFIX = ['/usr/bin/cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
    '-Wl,-z,max-page-size=16384', '/runner/virtual/image_decode_probe.c', '-o',
    '/out/prepared/root/usr/local/bin/image-decode-probe']


def hash_value(value):
    return type(value) is str and HASH.fullmatch(value) is not None


def canonical_sha256(value):
    return hashlib.sha256((json.dumps(value, sort_keys=True, separators=(',', ':'),
                                      allow_nan=False) + '\n').encode('ascii')).hexdigest()


def core_sha256(mapping):
    shape(mapping, CORE_FILES)
    need(all(hash_value(value) for value in mapping.values()), 'complete CORE pins')
    return canonical_sha256(mapping)


def inventory_sha256(mapping):
    need(type(mapping) is dict and mapping, 'nonempty package inventory')
    token = re.compile(r'[A-Za-z0-9._+:@~-]+\Z')
    need(all(type(k) is str and type(v) is str and token.fullmatch(k) and token.fullmatch(v)
             for k, v in mapping.items()), 'inventory fields')
    return hashlib.sha256(''.join(k + ' ' + v + '\n' for k, v in sorted(mapping.items())).encode('ascii')).hexdigest()


def validate_guest_contract(row):
    shape(row, GUEST_KEYS)
    need(type(row['schema_version']) is int and row['schema_version'] == 1 and
         row['scope'] == 'fixed-adwaita-svg-guest-contract' and type(row['scope']) is str and
         type(row['attempt']) is int and row['attempt'] == 1, 'guest probe contract schema')
    need(type(row['nonce']) is str and re.fullmatch(r'[0-9a-f]{32}', row['nonce']), 'guest nonce')
    need(all(hash_value(row[key]) for key in GUEST_HASHES), 'guest contract pins')
    need(row['asset_sha256'] == ASSET_SHA256 and row['source_sha256'] == C_SHA256,
         'selected fixed asset/source required')
    return row


def validate_event(event, nonce):
    shape(event, EVENT_KEYS)
    need(type(nonce) is str and re.fullmatch(r'[0-9a-f]{32}', nonce) and
         event['nonce'] == nonce and type(event['nonce']) is str and
         event['event'] == 'image_decode_probe' and type(event['event']) is str and
         event['stage'] == 'minimal' and type(event['stage']) is str, 'probe event identity')
    code = event['returncode']; error = event['error']
    need(code is None or integer(code, -64, 255), 'probe returncode')
    if error is not None:
        need(type(error) is str and error in ERRORS and event['elapsed_ms'] is None and
             event['report_sha256'] is event['report_base64'] is None, 'closed failed probe')
        return None
    need(code == 0 and integer(event['elapsed_ms'], 0, 20000) and
         hash_value(event['report_sha256']) and type(event['report_base64']) is str and
         0 < len(event['report_base64']) <= 4 * ((MAX_REPORT + 2) // 3), 'accepted probe fields')
    try:
        raw = base64.b64decode(event['report_base64'], validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError('probe base64') from error
    need(raw.isascii() and 0 < len(raw) <= MAX_REPORT and
         base64.b64encode(raw).decode('ascii') == event['report_base64'], 'canonical bounded ASCII probe')
    parse_report(raw)
    need(hashlib.sha256(raw).hexdigest() == event['report_sha256'], 'probe byte pin')
    return raw


def validate_file_identity(row):
    shape(row, ('path', 'resolved_path', 'sha256', 'bytes', 'mode'))
    for key in ('path', 'resolved_path'):
        need(type(row[key]) is str and row[key].startswith('/usr/') and
             all(part not in ('', '.', '..') for part in row[key].split('/')[1:]) and
             all(32 <= ord(char) < 127 for char in row[key]), 'same-image provenance path')
    need(hash_value(row['sha256']) and integer(row['bytes'], 1, 16 * 1024**2) and
         integer(row['mode'], 0, 0o777), 'provenance file identity')


def validate_elf(row, size):
    shape(row, ('class', 'encoding', 'machine', 'type', 'entry', 'load_segments', 'compatible_16k'))
    need(type(row['class']) is int and row['class'] == 64 and row['encoding'] == 'little-endian' and
         type(row['machine']) is int and row['machine'] == 183 and
         type(row['type']) is str and row['type'] in ('EXEC', 'DYN') and
         integer(row['entry'], 0, 2**64 - 1), 'ARM ELF identity')
    segments = row['load_segments']
    need(type(segments) is list and 1 <= len(segments) <= 128, 'ELF load segments')
    compatible = True
    for segment in segments:
        shape(segment, ('offset', 'virtual_address', 'file_size', 'memory_size', 'alignment'))
        need(all(integer(value, 0, 2**64 - 1) for value in segment.values()) and
             segment['file_size'] <= segment['memory_size'] and
             segment['offset'] + segment['file_size'] <= size, 'ELF segment bounds')
        alignment = segment['alignment']
        need(alignment in (0, 1) or (alignment & (alignment - 1) == 0 and
             segment['offset'] % alignment == segment['virtual_address'] % alignment), 'ELF segment alignment')
        compatible &= alignment >= 16384 and segment['offset'] % 16384 == segment['virtual_address'] % 16384
    need(type(row['compatible_16k']) is bool and row['compatible_16k'] == compatible and compatible,
         'selected 16KiB load alignment')


def validate_build(build, proof_contract, proof_contract_sha256, package_inventory):
    """Cross-bind a retained prepare receipt against external selected authority."""
    shape(build, BUILD_KEYS)
    need(build['status'] == 'BUILT' and type(build['status']) is str, 'actual built receipt required')
    guest = validate_guest_contract(build['guest_contract'])
    need(hash_value(proof_contract_sha256) and build['proof_contract_sha256'] == proof_contract_sha256 and
         build['source_commit'] == proof_contract['source_commit'] and
         type(build['source_commit']) is str and re.fullmatch(r'[0-9a-f]{40}', build['source_commit']),
         'selected proof/source authority')
    need(build['guest_contract_sha256'] == canonical_sha256(guest), 'guest contract byte pin')
    for key, maximum in (('run_id', 20), ('run_attempt', 10)):
        value = build[key]
        need(type(value) is str and re.fullmatch(r'[0-9]{1,' + str(maximum) + '}', value) and
             value == proof_contract[key], 'authenticated workflow identity')
    need(type(proof_contract['image_id']) is str and
         re.fullmatch(r'sha256:[0-9a-f]{64}', proof_contract['image_id']), 'immutable tooling image authority')
    runners = proof_contract['runner_sha256']
    expected = {'nonce': proof_contract['nonce'], 'source_sha256': runners['image_decode_probe.c'],
        'parser_sha256': runners['image_decode_report.py'], 'guest_sha256': runners['guest.py'],
        'runtime_sha256': runners['common.py'], 'core_sha256': core_sha256(runners),
        'tooling_sha256': proof_contract['image_id'].removeprefix('sha256:'),
        'package_inventory_sha256': inventory_sha256(package_inventory), 'asset_sha256': ASSET_SHA256}
    need(all(guest[key] == value for key, value in expected.items()), 'external guest build pins')
    helper = build['helper']; shape(helper, ('bytes', 'sha256', 'mode'))
    need(integer(helper['bytes'], 1, 16 * 1024**2) and helper['mode'] == 0o755 and
         type(helper['mode']) is int and hash_value(helper['sha256']) and
         helper['sha256'] == guest['helper_sha256'], 'built helper identity')
    validate_elf(build['elf'], helper['bytes'])
    provenance = build['provenance']
    shape(provenance, ('baseline_image_id', 'tooling_lock_sha256', 'tooling_audit_sha256',
        'compiler', 'pkg_config', 'headers', 'pc_files', 'pkg_config_argv',
        'pkg_config_stdout_sha256', 'flags', 'compile_argv', 'compile_log_sha256'))
    need(type(provenance['baseline_image_id']) is str and
         re.fullmatch(r'sha256:[0-9a-f]{64}', provenance['baseline_image_id']) and
         provenance['baseline_image_id'] == proof_contract['baseline_image_id'], 'baseline image authority')
    for key in ('tooling_lock_sha256', 'tooling_audit_sha256'):
        need(hash_value(provenance[key]) and provenance[key] == proof_contract[key], 'tooling metadata authority')
    for key, path in (('compiler', '/usr/bin/cc'), ('pkg_config', '/usr/bin/pkg-config')):
        validate_file_identity(provenance[key]); need(provenance[key]['path'] == path, 'fixed build tool')
    headers = provenance['headers']; pcs = provenance['pc_files']
    need(type(headers) is list and 1 <= len(headers) <= 4096 and type(pcs) is list and len(pcs) == len(PC_NAMES),
         'same-image header/pc inventory')
    for rows in (headers, pcs):
        for row in rows: validate_file_identity(row)
        paths = [row['path'] for row in rows]
        need(paths == sorted(set(paths)), 'sorted unique provenance files')
    need(all(any(row['path'].startswith(root + '/') for row in headers) for root in HEADER_ROOTS) and
         all(any(row['path'].startswith('/usr/include/glib-2.0/' + group + '/') for row in headers)
             for group in ('glib', 'gio', 'gobject')) and
         all(any(row['path'].startswith(root + '/') for root in HEADER_ROOTS) and row['path'].endswith('.h')
             for row in headers), 'fixed GLib/GIO/GObject/GdkPixbuf headers')
    need(CRITICAL_HEADERS <= {row['path'] for row in headers}, 'selected critical same-image headers')
    need({row['path'] for row in pcs} == {'/usr/lib/pkgconfig/' + name + '.pc' for name in PC_NAMES},
         'fixed same-image pkg-config inputs')
    need(provenance['pkg_config_argv'] == PKG_ARGV and hash_value(provenance['pkg_config_stdout_sha256']) and
         hash_value(provenance['compile_log_sha256']), 'build command captures')
    flags = provenance['flags']
    need(type(flags) is list and 1 <= len(flags) <= 128 and
         all(type(flag) is str and 0 < len(flag) <= 1024 and flag.isascii() and
             all(32 < ord(char) < 127 for char in flag) and flag.startswith(('-I', '-L', '-l', '-D', '-pthread'))
             for flag in flags), 'finite pkg-config flag vector')
    need(provenance['compile_argv'] == COMPILE_PREFIX + flags, 'selected exact compile argv')
    return guest

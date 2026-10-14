# SPDX-License-Identifier: MIT
"""Finite, data-only projection of the authenticated worker's original calls."""
import hashlib
import json
import math
import re

from runtime import Cancelled

LIMIT = 2048
REPORT_LIMIT = 4 * 1024**2
PHASES = frozenset(('NONE', 'PRECHECK', 'PROFILE', 'INVENTORY', 'TOOLS', 'SOURCE', 'CONFIG',
    'CONFIG_DELTA', 'PAIRED_CONFIG', 'GENERATED_CONFIG', 'KERNEL', 'OUTPUTS', 'FINALIZATION', 'COMPLETE'))
COMMANDS = frozenset(('NONE', 'INVENTORY', 'CONFIG', 'KERNEL', *(f'TOOL_{i}' for i in range(18))))
ERRORS = frozenset(('DATA_REFUSAL', 'IO', 'IMPORT', 'TIMEOUT', 'DEADLINE', 'OUTPUT_BOUND',
    'PROCESS_CLEANUP', 'CANCELLED', 'OTHER'))
BINDING_KEYS = frozenset(('nonce', 'action', 'contract_sha256', 'worker_sha256'))
KEYS = frozenset(('schema_version', 'binding', 'phase', 'command', 'attempt', 'natural_return',
    'first_failure', 'cleanup_failure', 'cancelled', 'write_failed'))
PUBLIC_KEYS = (KEYS - {'binding'}) | {'binding_sha256'}
GROUP_KEYS = frozenset(('availability', 'reason', 'raw_sha256', 'diagnostic'))
CONFIG_STAGES = frozenset(('BEFORE_CONFIG_PARSE', 'AFTER_CONFIG_PARSE', 'DELTA_COMPARE'))
CONFIG_SPECIAL = 'CONFIG_RUSTC_HAS_SUSPICIOUS_RUNTIME_SYMBOL_DEFINITIONS'
COMPILER_OUTPUT_LIMIT = 8 * 1024**2
COMPILER_LINE_LIMIT = 131072
COMPILER_LINE_BYTES = 4096
COMPILER_TEXT_BYTES = 192
COMPILER_PRIVATE_WORDS = ('password', 'passwd', 'secret', 'token', 'authorization',
    'bearer', 'api_key', 'api-key', 'privatekey', 'private_key', 'private-key',
    'private key', 'access_key', 'access-key', 'access key', 'cookie', 'credential')
COMPILER_SOURCE_PREFIX = '/tmp/artifacts/kernel-candidates/trial/source-tree/linux-asahi-7.1.13-3/'
COMPILER_SCAN = frozenset(('COMPLETE', 'LINE_CAP', 'LINE_LENGTH_CAP'))
COMPILER_SOURCE_ROOTS = frozenset(('arch', 'drivers', 'include', 'kernel', 'mm', 'fs',
    'net', 'lib', 'block', 'security', 'crypto', 'sound', 'virt', 'init', 'rust', 'scripts'))
RUST_CODES = {'E0425': 'RUST_UNRESOLVED_NAME', 'E0432': 'RUST_UNRESOLVED_IMPORT',
    'E0433': 'RUST_UNRESOLVED_PATH', 'E0308': 'RUST_TYPE_MISMATCH',
    'E0277': 'RUST_TRAIT_BOUND', 'E0609': 'RUST_UNKNOWN_FIELD',
    'E0599': 'RUST_MISSING_METHOD', 'E0658': 'RUST_UNSTABLE_FEATURE',
    'E0635': 'RUST_UNKNOWN_FEATURE', 'E0463': 'RUST_MISSING_CRATE',
    'E0583': 'RUST_MISSING_MODULE'}
COMPILER_C_CATEGORIES = frozenset(('MISSING_HEADER', 'UNDECLARED_IDENTIFIER',
    'IMPLICIT_DECLARATION', 'INCOMPATIBLE_POINTER', 'TYPE_MISMATCH', 'UNSUPPORTED_OPTION',
    'INTERNAL_COMPILER_ERROR', 'LINK_UNDEFINED_REFERENCE', 'DTC_ERROR',
    'RESOURCE_MARKER', 'MAKE_ERROR', 'OTHER_ERROR'))
COMPILER_CATEGORIES = COMPILER_C_CATEGORIES | frozenset(RUST_CODES.values()) | {'RUST_OTHER_CODE'}


def _need(value):
    if not value: raise ValueError('invalid inner diagnostic')


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def _binding(value):
    _need(type(value) is dict and value.keys() == BINDING_KEYS)
    _need(type(value['nonce']) is str and re.fullmatch('[0-9a-f]{32}', value['nonce']))
    _need(type(value['action']) is str and value['action'] in ('probe', 'baseline', 'candidate'))
    _need(_sha(value['contract_sha256']) and _sha(value['worker_sha256']))


def _config_fact(value):
    keys = {'stage', 'before_parsed_sha256', 'after_parsed_sha256', 'difference_count',
            'unexpected_count', 'difference_keys_sha256', 'first_unexpected', 'rust_capability_mismatch'}
    _need(type(value) is dict and set(value) == keys and type(value['stage']) is str and value['stage'] in CONFIG_STAGES)
    for name in ('before_parsed_sha256', 'after_parsed_sha256', 'difference_keys_sha256'):
        _need(value[name] is None or _sha(value[name]))
    if value['stage'] != 'DELTA_COMPARE':
        _need(value['after_parsed_sha256'] is None and value['difference_keys_sha256'] is None and
              value['difference_count'] is value['unexpected_count'] is value['first_unexpected'] is
              value['rust_capability_mismatch'] is None)
        _need(value['before_parsed_sha256'] is None if value['stage'] == 'BEFORE_CONFIG_PARSE'
              else _sha(value['before_parsed_sha256']))
        return value
    _need(_sha(value['before_parsed_sha256']) and _sha(value['after_parsed_sha256']) and
          _sha(value['difference_keys_sha256']) and type(value['difference_count']) is int and
          type(value['unexpected_count']) is int and 0 <= value['unexpected_count'] <= value['difference_count'] <= 131072 and
          type(value['rust_capability_mismatch']) is bool)
    first = value['first_unexpected']
    if value['unexpected_count'] == 0:
        _need(first is None)
        return value
    _need(type(first) is dict and set(first) == {'key', 'key_sha256', 'before', 'after',
          'before_present', 'after_present', 'truncated'} and _sha(first['key_sha256']))
    _need(all(type(first[name]) is bool for name in ('before_present', 'after_present', 'truncated')))
    key = first['key']
    _need(key is None and first['truncated'] or type(key) is str and len(key) <= 128 and
          re.fullmatch('CONFIG_[A-Za-z0-9_]+', key) and hashlib.sha256(key.encode()).hexdigest() == first['key_sha256'])
    for name in ('before', 'after'):
        item = first[name]
        _need(item is None or type(item) is str and len(item) <= 96 and all(32 <= ord(c) < 127 for c in item))
        _need(item is None if not first[name + '_present'] else item is not None or first['truncated'])
    return value


def _parsed_config_sha(value):
    _need(type(value) is dict and len(value) <= 65536)
    _need(all(type(key) is str and re.fullmatch('CONFIG_[A-Za-z0-9_]+', key) and
              type(item) is str for key, item in value.items()))
    raw = _encoded(value)
    _need(len(raw) <= 4 * 1024**2)
    return hashlib.sha256(raw).hexdigest()


def config_failure(row, stage, before, after, policy):
    """Only parsed objects already returned by the original worker calls; no IO."""
    _need(stage in CONFIG_STAGES and row['first_failure'] is not None)
    detail = {'stage': stage, 'before_parsed_sha256': None, 'after_parsed_sha256': None,
              'difference_count': None, 'unexpected_count': None, 'difference_keys_sha256': None,
              'first_unexpected': None, 'rust_capability_mismatch': None}
    if stage != 'BEFORE_CONFIG_PARSE': detail['before_parsed_sha256'] = _parsed_config_sha(before)
    if stage == 'DELTA_COMPARE':
        detail['after_parsed_sha256'] = _parsed_config_sha(after)
        changed = sorted(key for key in before.keys() | after.keys() if before.get(key) != after.get(key))
        allowed = set(policy['version_symbols'])
        unexpected = sorted(set(changed) - allowed - {CONFIG_SPECIAL})
        detail.update(difference_count=len(changed), unexpected_count=len(unexpected),
            difference_keys_sha256=hashlib.sha256(_encoded(changed)).hexdigest(),
            rust_capability_mismatch=CONFIG_SPECIAL in changed and
                not (before.get(CONFIG_SPECIAL) in (None, 'n') and after.get(CONFIG_SPECIAL) == 'y'))
        if unexpected:
            key = unexpected[0]; old, new = before.get(key), after.get(key)
            bounded = lambda item: item is None or len(item) <= 96 and all(32 <= ord(c) < 127 for c in item)
            detail['first_unexpected'] = {'key': key if len(key) <= 128 else None,
                'key_sha256': hashlib.sha256(key.encode()).hexdigest(),
                'before': old if bounded(old) else None, 'after': new if bounded(new) else None,
                'before_present': key in before, 'after_present': key in after,
                'truncated': len(key) > 128 or not bounded(old) or not bounded(new)}
    _config_fact(detail)
    candidate = dict(row, schema_version=2, config_failure=detail)
    validate(candidate)  # Atomic update; ordinary diagnostic faults refuse capture.
    row.update(schema_version=2, config_failure=detail)
    return row


def _compiler_location_fact(value):
    _need(type(value) is dict and set(value) == {'path', 'line', 'column'})
    path = value['path']
    _need(type(path) is str and 0 < len(path) <= 128 and
          re.fullmatch('[A-Za-z0-9_./+-]+', path) is not None and
          path.split('/')[0] in COMPILER_SOURCE_ROOTS and len(path.split('/')) >= 2 and
          all(part not in ('', '.', '..') for part in path.split('/')) and
          not any(word in path.lower() for word in COMPILER_PRIVATE_WORDS))
    _need(type(value['line']) is int and 1 <= value['line'] <= 10000000 and
          (value['column'] is None or type(value['column']) is int and 1 <= value['column'] <= 1000000))
    return value


def _compiler_span(value, total):
    _need(type(value) is dict and set(value) == {'category', 'error_code', 'location', 'offset', 'bytes', 'sha256', 'text', 'text_truncated'})
    _need(type(value['category']) is str and value['category'] in COMPILER_CATEGORIES)
    code = value['error_code']
    if code is None:
        _need(value['category'] in COMPILER_C_CATEGORIES)
    else:
        _need(type(code) is str and re.fullmatch('E[0-9]{4}', code) is not None and
              value['category'] == RUST_CODES.get(code, 'RUST_OTHER_CODE'))
    if value['location'] is not None: _compiler_location_fact(value['location'])
    _need(type(value['text_truncated']) is bool)
    text = value['text']
    _need(text is None and not value['text_truncated'] or type(text) is str and
          0 < len(text) <= COMPILER_TEXT_BYTES and all(32 <= ord(c) < 127 for c in text) and
          not any(word in text.lower() for word in COMPILER_PRIVATE_WORDS) and
          '://' not in text and '/home/' not in text.lower() and '/root/' not in text.lower() and
          (not value['text_truncated'] or len(text) == COMPILER_TEXT_BYTES))
    _need(type(value['offset']) is int and 0 <= value['offset'] < total and
          type(value['bytes']) is int and 1 <= value['bytes'] <= COMPILER_LINE_BYTES and
          value['offset'] + value['bytes'] <= total and _sha(value['sha256']))
    return value


def _compiler_fact(value):
    _need(type(value) is dict and set(value) == {'return_code', 'output_bytes', 'output_sha256',
          'log_sha256', 'scan_status', 'matched_lines', 'first', 'last'})
    _need(type(value['return_code']) is int and -64 <= value['return_code'] <= 255 and value['return_code'] != 0)
    _need(type(value['output_bytes']) is int and 0 <= value['output_bytes'] <= COMPILER_OUTPUT_LIMIT and
          _sha(value['output_sha256']) and _sha(value['log_sha256']) and
          value['output_sha256'] == value['log_sha256'])
    _need(type(value['scan_status']) is str and value['scan_status'] in COMPILER_SCAN and
          type(value['matched_lines']) is int and 0 <= value['matched_lines'] <= COMPILER_LINE_LIMIT and
          value['matched_lines'] <= value['output_bytes'])
    if value['matched_lines'] == 0:
        _need(value['first'] is value['last'] is None)
    else:
        first, last = (_compiler_span(value[name], value['output_bytes']) for name in ('first', 'last'))
        _need(first == last if value['matched_lines'] == 1 else
              first['offset'] + first['bytes'] <= last['offset'])
    _need(value['scan_status'] == 'COMPLETE' or value['output_bytes'] > 0)
    return value


def _compiler_private(line):
    """Conservative gate for optional Source locations."""
    lower = line.lower()
    return (any(c >= 127 or c < 32 and c not in (9, 10, 13) for c in line) or
            any(word.encode() in lower for word in COMPILER_PRIVATE_WORDS))


def _compiler_text(line):
    """Bounded recognized-error excerpt; raw span provenance stays separate."""
    # Remove terminal escapes before inspecting words, including split markers.
    clean = re.sub(br'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-_])', b'', line)
    if any(c < 32 and c not in (9, 10, 13) or c == 127 for c in clean):
        return None, False  # Interrupted URLs/paths must not leave a public suffix.
    flattened = bytes(c for c in clean if 32 <= c < 127).decode('ascii').lower()
    clean = bytes(c if 32 <= c < 127 else 32 for c in clean).decode('ascii').strip()
    lower = clean.lower()
    if (any(word in lower or word in flattened for word in COMPILER_PRIVATE_WORDS) or
            '/home/' in lower or '/root/' in lower or
            re.match(r'(?:export\s|env\s|[A-Z_][A-Z0-9_]*=)', clean)):
        return None, False
    clean = re.sub(r'[A-Za-z][A-Za-z0-9+.-]*://[^\s]+', '<url>', clean)
    # Unknown URL fragments also disappear rather than exporting their payload.
    if '://' in clean: return None, False
    clean = clean.replace(COMPILER_SOURCE_PREFIX, '').replace('/tmp/build/', '<build>/')
    return (clean[:COMPILER_TEXT_BYTES], len(clean) > COMPILER_TEXT_BYTES) if clean else (None, False)


def _compiler_location(line, arrow=False):
    if _compiler_private(line): return None
    prefix = br'\s*-->\s+' if arrow else b''
    match = re.match(prefix + br'([A-Za-z0-9_./+-]+):([0-9]{1,8})(?::([0-9]{1,7}))?(?=:|\s|$)', line)
    if match is None: return None
    value = {'path': match[1].decode('ascii'), 'line': int(match[2]),
             'column': int(match[3]) if match[3] is not None else None}
    try: return _compiler_location_fact(value)
    except ValueError: return None


def _compiler_match(line):
    """Closed lexical categories, not proof of tool identity or actual root cause."""
    line = re.sub(br'\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-_])', b'', line)
    codes = re.findall(br'\berror\[(E[0-9]{4})\]:', line)
    if len(codes) == 1:
        code = codes[0].decode('ascii')
        return RUST_CODES.get(code, 'RUST_OTHER_CODE'), code
    if len(codes) > 1: return 'OTHER_ERROR', None
    lower = line.lower()
    error = re.search(br'\b(?:fatal )?error:', lower) is not None
    found = set()
    if error:
        patterns = {
            'MISSING_HEADER': (b'no such file or directory', b'file not found'),
            'UNDECLARED_IDENTIFIER': (b'undeclared',),
            'IMPLICIT_DECLARATION': (b'implicit declaration of function',),
            'INCOMPATIBLE_POINTER': (b'incompatible pointer',),
            'TYPE_MISMATCH': (b'incompatible type', b'conflicting types', b'invalid conversion', b'cannot convert', b'invalid operands'),
            'UNSUPPORTED_OPTION': (b'unrecognized command-line option', b'unrecognized command line option', b'unknown argument', b'unsupported option', b'unknown warning option'),
        }
        found.update(name for name, markers in patterns.items() if any(marker in lower for marker in markers))
    if b'internal compiler error' in lower: found.add('INTERNAL_COMPILER_ERROR')
    if any(marker in lower for marker in (b'undefined reference to', b'undefined symbol', b'unresolved symbol')):
        found.add('LINK_UNDEFINED_REFERENCE')
    if re.search(br'\berror \([a-z0-9_]+\):', lower) or b'unable to parse input tree' in lower:
        found.add('DTC_ERROR')
    if any(marker in lower for marker in (b'out of memory', b'cannot allocate memory', b'killed signal')) or re.search(br'^\s*killed\s*$', lower):
        found.add('RESOURCE_MARKER')
    if re.search(br'^make(?:\[[0-9]{1,3}\])?: \*\*\* ', lower): found.add('MAKE_ERROR')
    if re.search(br'^(?:/bin/sh: [0-9]+: |/bin/(?:ba)?sh: (?:line [0-9]+: )?)[a-z0-9_./+-]+: (?:command )?not found\s*$', lower):
        found.add('OTHER_ERROR')
    if found: return (next(iter(found)) if len(found) == 1 else 'OTHER_ERROR'), None
    if error: return 'OTHER_ERROR', None
    return None


def compiler_failure(row, output, log_sha256):
    """Project original merged stdout and existing log hash; no IO or actors.

    COMPLETE first/last span the whole output; capped results describe only the
    proven prefix. Only bounded sanitized recognized-error excerpts are exported.
    """
    validate(row)
    if row['schema_version'] == 3: return row  # Preserve the first observation.
    _need(row['schema_version'] == 1 and not row['write_failed'] and row['phase'] == 'KERNEL' and
          row['command'] == 'KERNEL' and row['attempt'] == 'ISSUED' and
          row['first_failure'] == {'phase': 'KERNEL', 'command': 'KERNEL', 'error_kind': 'DATA_REFUSAL'} and
          row['natural_return']['kind'] == 'RETURNED' and type(row['natural_return']['code']) is int and
          row['natural_return']['code'] != 0)
    _need(type(output) is bytes and len(output) <= COMPILER_OUTPUT_LIMIT and _sha(log_sha256))
    digest = hashlib.sha256(output).hexdigest()
    _need(digest == log_sha256)
    detail = {'return_code': row['natural_return']['code'], 'output_bytes': len(output),
        'output_sha256': digest, 'log_sha256': log_sha256, 'scan_status': 'COMPLETE',
        'matched_lines': 0, 'first': None, 'last': None}
    offset = lines = 0
    pending = None
    pending_lines = 0
    while offset < len(output):
        if lines == COMPILER_LINE_LIMIT:
            detail['scan_status'] = 'LINE_CAP'; break
        end = output.find(b'\n', offset)
        end = len(output) if end == -1 else end + 1
        if end - offset > COMPILER_LINE_BYTES:
            detail['scan_status'] = 'LINE_LENGTH_CAP'; break
        line = output[offset:end]
        if pending is not None:
            if line.lstrip().startswith(b'-->'):
                pending['location'] = _compiler_location(line, arrow=True)
                pending = None
            else:
                pending_lines -= 1
                if pending_lines == 0: pending = None
        match = _compiler_match(line)
        if match is not None:
            category, code = match
            text, truncated = _compiler_text(line)
            span = {'category': category, 'error_code': code, 'location': _compiler_location(line),
                    'offset': offset, 'bytes': len(line), 'sha256': hashlib.sha256(line).hexdigest(),
                    'text': text, 'text_truncated': truncated}
            if detail['first'] is None: detail['first'] = span
            detail['last'] = span
            detail['matched_lines'] += 1
            pending = span if code is not None and not _compiler_private(line) else None
            pending_lines = 3
        offset, lines = end, lines + 1
    _compiler_fact(detail)
    candidate = dict(row, schema_version=3, compiler_failure=detail)
    validate(candidate)  # Atomic update; diagnostic faults leave the old row intact.
    row.update(schema_version=3, compiler_failure=detail)
    return row


OUTPUT_CHECKS = {'16K ELF load geometry/permissions required; WX refused': 'CHECK_001', 'AArch64 ELF RELA metadata invalid': 'CHECK_002', 'ARM64 Image header required': 'CHECK_003', 'Apple DTB identity differs from pinned J413/J415 DTS': 'CHECK_004', 'Apple/16K config guards differ': 'CHECK_005', 'EFI Image MZ/PE offset required': 'CHECK_006', 'EFI PE signature required': 'CHECK_007', 'EFI section overlap/entry invalid': 'CHECK_008', 'ELF entry must be in file-backed executable load': 'CHECK_009', 'ELF relocation index/offset invalid': 'CHECK_010', 'ELF section file geometry invalid': 'CHECK_011', 'ELF section name/link/alignment invalid': 'CHECK_012', 'ELF section zero invalid': 'CHECK_013', 'ELF section-name string table required': 'CHECK_014', 'ELF segment range invalid': 'CHECK_015', 'ELF short read': 'CHECK_016', 'ELF symbol section/visibility invalid': 'CHECK_017', 'ELF symbol strings invalid': 'CHECK_018', 'ELF writable executable section refused': 'CHECK_019', 'ELF64 little-endian current-version identity required': 'CHECK_020', 'FDT block bounds/alignment/order required': 'CHECK_021', 'FDT final END absent': 'CHECK_022', 'FDT final END/root required': 'CHECK_023', 'FDT node padding invalid': 'CHECK_024', 'FDT property bounds/padding invalid': 'CHECK_025', 'FDT property name/duplicate invalid': 'CHECK_026', 'FDT property placement/truncation': 'CHECK_027', 'FDT reservation terminator absent': 'CHECK_028', 'FDT root/depth invalid': 'CHECK_029', 'FDT strings table must end in NUL': 'CHECK_030', 'FDT token budget exceeded': 'CHECK_031', 'Image ELF inter-section gap must contain only zero bytes': 'CHECK_032', 'Image entry branch required': 'CHECK_033', 'Image header differs from vmlinux bytes': 'CHECK_034', 'Image length differs from complete ELF binary projection': 'CHECK_035', 'Image requires copied allocated ELF sections': 'CHECK_036', 'Image size/entry differ from vmlinux _text/_end': 'CHECK_037', 'Module.symvers requires five tab-separated fields': 'CHECK_038', 'UTS_RELEASE differs from kernel.release': 'CHECK_039', 'actual module code/descriptor required': 'CHECK_040', 'allocated ELF section outside consistent load segment': 'CHECK_041', 'ambiguous module names': 'CHECK_042', 'ambiguous/common defined export': 'CHECK_043', 'bounded ELF program headers required': 'CHECK_044', 'bounded ELF range required': 'CHECK_045', 'bounded ELF section headers required': 'CHECK_046', 'bounded actual ELF symbol table required': 'CHECK_047', 'bounded config bytes required': 'CHECK_048', 'bounded receipt descriptor required': 'CHECK_049', 'bounded source-version kernel.release required': 'CHECK_050', 'bounded terminated string required': 'CHECK_051', 'bounded valid FDT reservation required': 'CHECK_052', 'build inventory entry budget exceeded': 'CHECK_053', 'built-in IKCONFIG and little-endian module-enabled kernel required': 'CHECK_054', 'complete backwards-compatible FDT17 header required': 'CHECK_055', 'complete embedded IKCONFIG differs from generated .config': 'CHECK_056', 'compressed modules unexpected in native build output': 'CHECK_057', 'configured Apple audio modules missing': 'CHECK_058', 'defined symbol outside allocated section': 'CHECK_059', 'duplicate FDT node': 'CHECK_060', 'duplicate config setting': 'CHECK_061', 'duplicate embedded IKCONFIG marker': 'CHECK_062', 'embedded IKCONFIG absent': 'CHECK_063', 'executable ELF stack refused': 'CHECK_064', 'full FDT header required': 'CHECK_065', 'invalid FDT node name/root': 'CHECK_066', 'invalid embedded config gzip': 'CHECK_067', 'invalid/duplicate Module.symvers export': 'CHECK_068', 'lowest copied Image LMA must correspond to vmlinux _text': 'CHECK_069', 'malformed generated config line': 'CHECK_070', 'module dependencies outside actual inventory': 'CHECK_071', 'module inventory storage budget exceeded': 'CHECK_072', 'module inventory symlink directory refused': 'CHECK_073', 'module metadata key/value required': 'CHECK_074', 'module metadata text invalid': 'CHECK_075', 'module vermagic/name/license/dependency metadata invalid': 'CHECK_076', 'modules.order differs from actual .ko inventory': 'CHECK_077', 'non-EFI Image must have source NOP and zero PE offset': 'CHECK_078', 'nonempty bounded unique module order required': 'CHECK_079', 'nonempty terminated Module.symvers required': 'CHECK_080', 'overlapping ELF load memory ranges': 'CHECK_081', 'overlapping ELF section/header file ranges': 'CHECK_082', 'overlapping FDT reservations': 'CHECK_083', 'overlapping copied Image LMA ranges': 'CHECK_084', 'pinned DTS root identity required': 'CHECK_085', 'pinned Kbuild .o module order format required': 'CHECK_086', 'real source root required': 'CHECK_087', 'receipt SHA-256 required': 'CHECK_088', 'receipt byte-snapshot pin differs': 'CHECK_089', 'relocatable module must not have entry/program headers': 'CHECK_090', 'relocation symbol table invalid': 'CHECK_091', 'resolved source link outside verified root': 'CHECK_092', 'source ARM64 EFI COFF header required': 'CHECK_093', 'source EFI PE section geometry/permissions required': 'CHECK_094', 'source EFI PE32+ sizes/alignment/subsystem required': 'CHECK_095', 'source entry budget exceeded': 'CHECK_096', 'source symlink budget exceeded': 'CHECK_097', 'source symlink has cyclic/dangling resolution': 'CHECK_098', 'source-bound little-endian16K Image size/offset/reserved/placement flags required': 'CHECK_099', 'string offset outside table': 'CHECK_100', 'symbol inventory budget exceeded': 'CHECK_101', 'terminated module metadata required': 'CHECK_102', 'terminated modules.order required': 'CHECK_103', 'truncated FDT token': 'CHECK_104', 'unexpected CRC with MODVERSIONS disabled': 'CHECK_105', 'unexpected bytes after final copied Image section': 'CHECK_106', 'unique file-backed Image section load mapping required': 'CHECK_107', 'unknown FDT token': 'CHECK_108', 'unmatched FDT end-node': 'CHECK_109', 'unreviewed RANDSTRUCT vermagic refused': 'CHECK_110', 'unreviewed compressed/excluded allocated Image section': 'CHECK_111', 'valid config-selected AArch64 ELF type/version/header required': 'CHECK_112', 'vmlinux exports absent': 'CHECK_113'}
OUTPUT_PREFIXES = (('ELF file-backed section required: ', 'ELF_FILE_SECTION'), ('export/kernel symbol missing from actual ELF: ', 'ELF_SYMBOL_MISSING'), ('Image body differs from vmlinux allocated section: ', 'IMAGE_SECTION_CONTENT'), ('generated configuration differs: ', 'GENERATED_CONFIG_DIFFERENCE'))
OUTPUT_PREDICATES = frozenset(OUTPUT_CHECKS.values()) | frozenset(code for _, code in OUTPUT_PREFIXES) | {'OTHER'}

def _output_fact(value):
    _need(type(value) is dict and set(value) == {'call_boundary', 'predicate'})
    _need(type(value['call_boundary']) is str and value['call_boundary'] == 'VERIFY_OUTPUTS')
    _need(type(value['predicate']) is str and value['predicate'] in OUTPUT_PREDICATES)
    return value


def output_failure(row, error):
    """Only a closed projection of an existing ValueError; no text or IO exported."""
    predicate = 'OTHER'
    if type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str:
        message = error.args[0]
        predicate = OUTPUT_CHECKS.get(message, 'OTHER')
        if predicate == 'OTHER':
            for prefix, code in OUTPUT_PREFIXES:
                if message.startswith(prefix):
                    predicate = code
                    break
    detail = {'call_boundary': 'VERIFY_OUTPUTS', 'predicate': predicate}
    candidate = dict(row, schema_version=4, output_failure=detail)
    validate(candidate)
    row.update(schema_version=4, output_failure=detail)
    return row


def _keys(row, public=False):
    _need(type(row) is dict and type(row.get('schema_version')) is int and row['schema_version'] in (1, 2, 3, 4))
    extra = {2: {'config_failure'}, 3: {'compiler_failure'}, 4: {'output_failure'}}.get(row['schema_version'], set())
    return (PUBLIC_KEYS if public else KEYS) | extra


def initial(binding):
    _binding(binding)
    return {'schema_version': 1, 'binding': dict(binding), 'phase': 'PRECHECK', 'command': 'NONE',
        'attempt': 'NOT_ISSUED', 'natural_return': {'kind': 'UNOBSERVED', 'code': None},
        'first_failure': None, 'cleanup_failure': None, 'cancelled': False, 'write_failed': False}


def phase(row, name):
    _need(type(name) is str and name in PHASES)
    row['phase'] = name
    return row


def issued(row, command):
    _need(type(command) is str and command in COMMANDS - {'NONE'})
    row.update(command=command, attempt='ISSUED', natural_return={'kind': 'UNOBSERVED', 'code': None})
    return row


def returned(row, code):
    _need(row['attempt'] == 'ISSUED' and type(code) is int and -64 <= code <= 255)
    row['natural_return'] = {'kind': 'RETURNED', 'code': code}
    return row


def _kind(error):
    if isinstance(error, (Cancelled, KeyboardInterrupt, SystemExit)): return 'CANCELLED'
    if isinstance(error, ImportError): return 'IMPORT'
    if isinstance(error, OSError): return 'IO'
    if type(error) is ValueError:
        return {'command-timeout': 'TIMEOUT', 'deadline-exhausted': 'DEADLINE',
            'output-bound': 'OUTPUT_BOUND', 'process-cleanup': 'PROCESS_CLEANUP'}.get(
                error.args[0] if len(error.args) == 1 and type(error.args[0]) is str else '', 'DATA_REFUSAL')
    return 'OTHER'


def failure(row, error, cleanup=False):
    _need(type(cleanup) is bool)
    kind = _kind(error)
    if kind == 'CANCELLED': row['cancelled'] = True
    key = 'cleanup_failure' if cleanup else 'first_failure'
    if row[key] is None: row[key] = {'phase': row['phase'], 'command': row['command'], 'error_kind': kind}
    return row


def invalidate(row):
    row['write_failed'] = True
    return row


def _body(row):
    _need(type(row['schema_version']) is int and row['schema_version'] in (1, 2, 3, 4))
    _need(type(row['phase']) is str and row['phase'] in PHASES)
    _need(type(row['command']) is str and row['command'] in COMMANDS)
    _need(type(row['attempt']) is str and row['attempt'] in ('NOT_ISSUED', 'ISSUED'))
    natural = row['natural_return']
    _need(type(natural) is dict and natural.keys() == {'kind', 'code'})
    _need(type(natural['kind']) is str and natural['kind'] in ('UNOBSERVED', 'RETURNED'))
    _need((natural['kind'] == 'UNOBSERVED' and natural['code'] is None) or
        (natural['kind'] == 'RETURNED' and type(natural['code']) is int and -64 <= natural['code'] <= 255))
    _need((row['attempt'] == 'NOT_ISSUED' and row['command'] == 'NONE' and natural['kind'] == 'UNOBSERVED') or
        (row['attempt'] == 'ISSUED' and row['command'] != 'NONE'))
    for key in ('first_failure', 'cleanup_failure'):
        item = row[key]
        if item is None: continue
        _need(type(item) is dict and item.keys() == {'phase', 'command', 'error_kind'})
        _need(type(item['phase']) is str and item['phase'] in PHASES)
        _need(type(item['command']) is str and item['command'] in COMMANDS)
        _need(type(item['error_kind']) is str and item['error_kind'] in ERRORS)
    _need(type(row['cancelled']) is bool and type(row['write_failed']) is bool)
    _need(not any(row[k] and row[k]['error_kind'] == 'CANCELLED' for k in ('first_failure', 'cleanup_failure')) or row['cancelled'])
    if row['schema_version'] == 2:
        _config_fact(row['config_failure'])
        _need(row['first_failure'] is not None and row['first_failure']['phase'] == 'CONFIG_DELTA' and
              row['first_failure']['command'] == row['command'] == 'CONFIG' and row['attempt'] == 'ISSUED' and
              row['natural_return'] == {'kind': 'RETURNED', 'code': 0})
    if row['schema_version'] == 3:
        _compiler_fact(row['compiler_failure'])
        _need(row['first_failure'] == {'phase': 'KERNEL', 'command': 'KERNEL', 'error_kind': 'DATA_REFUSAL'} and
              row['command'] == 'KERNEL' and row['attempt'] == 'ISSUED' and
              row['natural_return'] == {'kind': 'RETURNED', 'code': row['compiler_failure']['return_code']})
    if row['schema_version'] == 4:
        _output_fact(row['output_failure'])
        _need(row['first_failure'] == {'phase': 'OUTPUTS', 'command': 'KERNEL', 'error_kind': 'DATA_REFUSAL'} and
              row['command'] == 'KERNEL' and row['attempt'] == 'ISSUED' and
              row['natural_return'] == {'kind': 'RETURNED', 'code': 0})
    _need(len(_encoded(row)) <= LIMIT)


def validate(row, expected=None):
    _need(type(row) is dict and row.keys() == _keys(row))
    _binding(row['binding']); _body(row)
    if expected is not None:
        _binding(expected); _need(row['binding'] == expected)
    return row


def _unique(items):
    result = {}
    for key, value in items:
        _need(key not in result); result[key] = value
    return result


def _finite(value):
    number = float(value)
    _need(math.isfinite(number))
    return number


def capture(raw, expected):
    group = {'availability': 'UNAVAILABLE', 'reason': 'MISSING', 'raw_sha256': None, 'diagnostic': None}
    if raw is None: return group
    _need(type(raw) is bytes)
    group.update(availability='REFUSED', reason='INVALID', raw_sha256=hashlib.sha256(raw).hexdigest())
    try:
        _need(len(raw) <= REPORT_LIMIT)
        report = json.loads(raw, object_pairs_hook=_unique, parse_float=_finite,
                            parse_constant=lambda _: _need(False))
        _need(type(report) is dict)
        row = validate(report['inner_diagnostic'], expected)
        _need(report['action'] == expected['action'] and report['nonce'] == expected['nonce'])
        _need(type(report['status']) is str and report['status'] == 'FAIL')
        _need(type(report['cancelled']) is bool and report['cancelled'] == row['cancelled'])
        _need(not row['write_failed'])
        public = {k: v for k, v in row.items() if k != 'binding'}
        public['binding_sha256'] = hashlib.sha256(_encoded(row['binding'])).hexdigest()
        group.update(availability='VERIFIED', reason='OBSERVED', diagnostic=public)
    except (ValueError, KeyError, TypeError, OverflowError, RecursionError, UnicodeError):
        pass
    return group


def validate_group(group):
    _need(type(group) is dict and group.keys() == GROUP_KEYS)
    _need(type(group['availability']) is str and type(group['reason']) is str)
    pair = (group['availability'], group['reason'])
    _need(pair in (('NOT_RUN', 'NOT_RUN'), ('UNAVAILABLE', 'MISSING'), ('REFUSED', 'INVALID'), ('VERIFIED', 'OBSERVED')))
    if pair in (('NOT_RUN', 'NOT_RUN'), ('UNAVAILABLE', 'MISSING')):
        _need(group['raw_sha256'] is None and group['diagnostic'] is None)
    else:
        _need(_sha(group['raw_sha256']) or (pair == ('REFUSED', 'INVALID') and group['raw_sha256'] is None))
        if pair == ('REFUSED', 'INVALID'): _need(group['diagnostic'] is None)
        else:
            row = group['diagnostic']
            _need(type(row) is dict and row.keys() == _keys(row, public=True) and _sha(row['binding_sha256']))
            _body(row); _need(not row['write_failed'])
    return group

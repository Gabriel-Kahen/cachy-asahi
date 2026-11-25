# SPDX-License-Identifier: MIT
"""Pure GUI18 runtime DATA joins. No filesystem, loader, subprocess or issuer.

selection's seven fields are a caller trust boundary: its whole pins must come
from independently authenticated custody. Matching JSON/checksums cannot prove
Root issuance, signed installation, current trust or actual supervision. The
coordinator supplies those separately; every result here retains those limits.

retained is a SHA256 -> bytes mapping. All ELF files in the closure and callback
stdout/stderr/observations must be retained. Snapshot package rows identify the
original archives/signatures/native provenance/database reports; authentication
of their signed transaction is external, never inferred from a name or flag.
"""
import hashlib
import json
import posixpath
import re
import struct

COMMIT = 'b05267833d497ef034576741bf31968019a526c3'
PACKAGE = 'cachy-asahi-qt612-gui-source-reference'
SCOPE = 'PROJECT_TEST_GUI18_DEPENDENCY_COMPONENT'
MODULES = ('Concurrent Core DBus EglFSDeviceIntegration EglFsKmsGbmSupport '
           'EglFsKmsSupport Gui Network OpenGL OpenGLWidgets PrintSupport Sql '
           'Test WaylandClient Widgets WlShellIntegration XcbQpa Xml').split()
LIBRARIES = ['/usr/lib/libQt6' + m + '.so.6.12.0' for m in MODULES]
PRIVATE_MODULES = {'XcbQpa', 'EglFSDeviceIntegration', 'EglFsKmsGbmSupport',
                   'EglFsKmsSupport', 'WlShellIntegration'}
CMAKE_PACKAGES = {m: 'Qt6' + m + ('Private' if m in PRIVATE_MODULES else '') for m in MODULES}
CMAKE_TARGETS = {m: 'Qt6::' + m + ('Private' if m in PRIVATE_MODULES else '') for m in MODULES}
OFFSCREEN_MARKER = 'PASS_QT612_GUI_OFFSCREEN_WIDGETS_OPENGL_API_ONLY'
DEPENDS = ['brotli', 'dbus', 'double-conversion', 'fontconfig', 'freetype2', 'glib2',
    'glibc', 'harfbuzz', 'icu', 'libb2', 'libgcc', 'libgl', 'libice', 'libjpeg-turbo',
    'libpng', 'libsm', 'libstdc++', 'libx11', 'libxcb', 'libxkbcommon', 'libxkbcommon-x11',
    'md4c>=0.5.3', 'md4c<0.6', 'openssl', 'pcre2', 'shared-mime-info', 'sqlite',
    'xcb-util-cursor', 'xcb-util-image', 'xcb-util-keysyms', 'xcb-util-renderutil',
    'xcb-util-wm', 'xdg-utils', 'zlib', 'zstd', 'libdrm', 'libglvnd', 'mesa', 'wayland>=1.15']
MAX_RECORD = 32 * 1024**2
MAX_FILE = 256 * 1024**2
MAX_TOTAL = 2 * 1024**3
FINAL = dict(native_acceptance=False, hardware_acceptance=False, release_acceptance=False,
             Root_acceptance=None, original_official_hold='UNCHANGED', other54='OUTSIDE_COMPONENT_SCOPE')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    need(type(raw) is bytes, 'BYTES_REQUIRED')
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def descriptor(row, cap=MAX_TOTAL):
    need(type(row) is dict and set(row) == {'bytes', 'sha256'}
         and type(row['bytes']) is int and 0 <= row['bytes'] <= cap
         and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'WHOLE_PIN_REQUIRED')
    return row


def decoded(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_RECORD, 'FINITE_JSON_BYTES')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'NONFINITE_JSON'))


def logical(path):
    need(type(path) is str and path.startswith('/') and path != '/'
         and posixpath.normpath(path) == path and not path.startswith('//')
         and all(32 < ord(c) < 127 for c in path) and '\\' not in path, 'CANONICAL_LOGICAL_PATH')
    return path


def retained_map(retained):
    need(type(retained) is dict and 1 <= len(retained) <= 16384, 'BOUNDED_RETAINED_MAP')
    total = 0
    for digest, raw in retained.items():
        need(type(raw) is bytes and len(raw) <= MAX_FILE, 'RETAINED_FILE_BOUND')
        total += len(raw)
        need(total <= MAX_TOTAL and pin(raw)['sha256'] == digest, 'RETAINED_TOTAL_OR_HASH')


def blob(retained, expected, cap=MAX_RECORD):
    descriptor(expected, cap)
    raw = retained.get(expected['sha256'])
    need(type(raw) is bytes and pin(raw) == expected, 'WHOLE_RETAINED_OPERAND_REQUIRED')
    return raw


def selected(raw, expected):
    descriptor(expected, MAX_RECORD)
    need(pin(raw) == expected, 'EXTERNAL_RECORD_PIN_DIFFERS')
    return decoded(raw)


def elf(raw):
    """Bounded actual ELF dynamic/version observation, including loader hazards."""
    need(64 <= len(raw) <= MAX_FILE and raw[:7] == b'\x7fELF\x02\x01\x01', 'ELF64_LE_REQUIRED')
    kind, machine = struct.unpack_from('<HH', raw, 16)
    need(kind in (2, 3) and machine == 183, 'AARCH64_ELF_REQUIRED')
    phoff = struct.unpack_from('<Q', raw, 32)[0]
    size, count = struct.unpack_from('<HH', raw, 54)
    need(size == 56 and 0 < count <= 1024 and 64 <= phoff <= len(raw) - count * size, 'BOUNDED_ELF_HEADERS')
    segments = [struct.unpack_from('<IIQQQQQQ', raw, phoff + i * size) for i in range(count)]
    need(all(s[2] + s[5] <= len(raw) for s in segments), 'ELF_SEGMENT_BOUNDS')
    loads = [s for s in segments if s[0] == 1]
    need(loads and all(s[5] <= s[6] and s[7] > 0 for s in loads), 'ELF_LOAD_REQUIRED')
    for _, _, file_offset, address, _, _, _, alignment in loads:
        need(alignment >= 16384 and alignment & (alignment - 1) == 0
             and file_offset % alignment == address % alignment, 'AARCH64_ELF_16K_LOAD_GEOMETRY')
    def offset(address, length):
        matches = [s[2] + address - s[3] for s in loads if s[3] <= address and address + length <= s[3] + s[5]]
        need(len(matches) == 1 and length >= 0, 'UNIQUE_FILE_BACKED_ELF_ADDRESS')
        return matches[0]
    interps = [s for s in segments if s[0] == 3]
    need(len(interps) <= 1, 'DUPLICATE_INTERPRETER')
    interpreter = None
    if interps:
        s = interps[0]; data = raw[s[2]:s[2] + s[5]]
        need(data.endswith(b'\0') and b'\0' not in data[:-1], 'INTERPRETER_STRING')
        interpreter = data[:-1].decode('ascii')
        need(interpreter == '/lib/ld-linux-aarch64.so.1', 'NORMAL_AARCH64_INTERPRETER_REQUIRED')
    dynamic = [s for s in segments if s[0] == 2]
    need(len(dynamic) == 1 and dynamic[0][5] % 16 == 0, 'ONE_DYNAMIC_SEGMENT_REQUIRED')
    s = dynamic[0]; tags, needed = {}, []; terminated = False
    for start in range(s[2], s[2] + s[5], 16):
        tag, value = struct.unpack_from('<qQ', raw, start)
        if tag == 0:
            terminated = True; break
        if tag == 1:
            needed.append(value)
        else:
            need(tag not in tags, 'DUPLICATE_DYNAMIC_TAG')
            tags[tag] = value
    need(terminated, 'DYNAMIC_TERMINATOR_REQUIRED')
    # Refuse even absolute RPATH/RUNPATH: no implicit override/cache policy waiver.
    need(not set(tags) & {15, 29, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff}, 'LOADER_PATH_OR_AUDIT_HAZARD')
    need(5 in tags and 10 in tags and 0 < tags[10] <= MAX_FILE, 'DYNAMIC_STRING_TABLE_REQUIRED')
    table = offset(tags[5], tags[10])
    def text(index):
        need(0 <= index < tags[10], 'DYNAMIC_STRING_OFFSET')
        end = raw.find(b'\0', table + index, table + tags[10])
        need(end >= table + index, 'DYNAMIC_STRING_TERMINATOR')
        value = raw[table + index:end].decode('ascii')
        need(value and all(32 < ord(c) < 127 for c in value), 'PLAIN_DYNAMIC_STRING')
        return value
    def versions(address_tag, count_tag, definitions):
        need((address_tag in tags) == (count_tag in tags), 'VERSION_TABLE_COUNT_PAIR')
        if address_tag not in tags:
            return None
        count = tags[count_tag]; address = tags[address_tag]; result = []; seen = set(); total = 0
        need(0 < count <= 4096, 'VERSION_COUNT_BOUND')
        for i in range(count):
            need(address not in seen, 'VERSION_CHAIN_CYCLE'); seen.add(address)
            start = offset(address, 20 if definitions else 16)
            if definitions:
                version, flags, index, n, digest, aux, nxt = struct.unpack_from('<HHHHIII', raw, start)
                row = dict(flags=flags, index=index, hash=digest, names=[])
            else:
                version, n, filename, aux, nxt = struct.unpack_from('<HHIII', raw, start)
                row = dict(file=text(filename), versions=[])
            total += n
            need(version == 1 and 0 < n <= 4096 and total <= 65536 and aux > 0, 'VERSION_RECORD_SHAPE')
            a = address + aux; aux_seen = set()
            for j in range(n):
                need(a not in aux_seen, 'VERSION_AUXILIARY_CYCLE'); aux_seen.add(a)
                start = offset(a, 8 if definitions else 16)
                if definitions:
                    name, following = struct.unpack_from('<II', raw, start); row['names'].append(text(name))
                else:
                    digest, flags, other, name, following = struct.unpack_from('<IHHII', raw, start)
                    row['versions'].append(dict(name=text(name), hash=digest, flags=flags, other=other))
                need(bool(following) == (j + 1 < n), 'VERSION_AUXILIARY_COUNT')
                a += following
            need(bool(nxt) == (i + 1 < count), 'VERSION_CHAIN_COUNT')
            result.append(row); address += nxt
        return result
    return dict(type=kind, machine=machine, interpreter=interpreter, soname=text(tags[14]) if 14 in tags else None,
                needed=[text(n) for n in needed], version_needs=versions(0x6ffffffe, 0x6fffffff, False),
                version_definitions=versions(0x6ffffffc, 0x6ffffffd, True))


def resolve(path, snapshot, missing=False):
    logical(path); seen = set()
    for _ in range(64):
        need(path not in seen, 'INSTALLED_ALIAS_CYCLE'); seen.add(path)
        parts = path[1:].split('/'); changed = False
        for i in range(1, len(parts) + 1):
            prefix = '/' + '/'.join(parts[:i]); row = snapshot['symlinks'].get(prefix)
            if row is None:
                continue
            need(row['package'] in snapshot['packages'] and type(row['uid']) is type(row['gid']) is int
                 and row['uid'] == row['gid'] == 0 and row['mode'] == 0o777,
                 'OWNED_ROOT_ALIAS_REQUIRED')
            target = row['target']; need(type(target) is str and target and '\\' not in target, 'ALIAS_TARGET')
            need(pin(target.encode()) == {k:row[k] for k in ('bytes','sha256')}, 'ALIAS_TARGET_WHOLE_PIN')
            target = posixpath.normpath(target if target.startswith('/') else posixpath.join(posixpath.dirname(prefix), target))
            logical(target); need(row['resolved'] == target, 'ALIAS_METADATA_RESOLUTION')
            path = target + ('/' + '/'.join(parts[i:]) if parts[i:] else '')
            logical(path); changed = True; break
        if not changed:
            if path not in snapshot['files'] and missing:
                return None
            need(path in snapshot['files'], 'INSTALLED_CANONICAL_FILE_REQUIRED')
            return path
    raise ValueError('INSTALLED_ALIAS_DEPTH')


def receipt(raw, expected, retained, selection, supervisor, label, argv):
    r = selected(raw, expected)
    need(r.get('kind') == 'GUI18_OWNED_CALLBACK_RECEIPT_V1' and r.get('label') == label
         and r.get('argv') == argv and r.get('supervisor') == supervisor
         and r.get('image') == selection['image'] and r.get('inventory_pin') == selection['inventory_pin'],
         'EXACT_ORIGINAL_CALLBACK_IMAGE_INVENTORY_JOIN')
    need(type(r.get('deadline_seconds')) is int and 0 < r['deadline_seconds'] <= 300
         and type(r.get('elapsed_seconds')) in (int, float) and 0 <= r['elapsed_seconds'] < r['deadline_seconds']
         and type(r.get('exit_code')) is int and r['exit_code'] == 0
         and all(r.get(k) is True for k in ('natural_exit', 'reaped', 'pidfd_retired')),
         'FINITE_SUCCESSFUL_NATURAL_CALLBACK_RETIREMENT_REQUIRED')
    trace = decoded(blob(retained, r['events_pin']))
    need(trace.get('kind') == 'GUI18_ORIGINAL_CALLBACK_EVENTS_V1' and trace.get('supervisor') == supervisor
         and trace.get('label') == label and trace.get('argv') == argv
         and type(trace.get('child_identity')) is list and len(trace['child_identity']) == 3
         and all(type(n) is int and n > 0 for n in trace['child_identity']), 'RETAINED_ORIGINAL_CHILD_EVENTS_REQUIRED')
    events = trace.get('events')
    need(type(events) is list and len(events) == 4
         and [e.get('event') for e in events] == ['start','natural-exit','reaped','pidfd-retired']
         and all(type(e.get('at')) in (int,float) and 0 <= e['at'] < 10**12 for e in events), 'FINITE_ORIGINAL_CALLBACK_EVENT_SEQUENCE')
    times = [e['at'] for e in events]
    need(times == sorted(times) and times[-1] < times[0] + r['deadline_seconds']
         and abs((times[-1] - times[0]) - r['elapsed_seconds']) <= 0.000001
         and events[1].get('exit_code') == 0, 'NATURAL_EXIT_AND_REAP_INSIDE_ORIGINAL_DEADLINE')
    stdout = blob(retained, r['stdout_pin'], 4 * 1024**2)
    blob(retained, r['stderr_pin'], 4 * 1024**2)
    observation = decoded(blob(retained, r['observation_pin'])) if r.get('observation_pin') else None
    return r, stdout, observation


def validate_dependencies(*, stage_raw, stage_pin, snapshot_raw, snapshot_pin,
                          pacman_raw, pacman_pin, retained, selection):
    """Snapshot files: absolute canonical paths -> package/pin/mode/uid/gid/elf.

    symlinks carry package,target,resolved,mode,uid,gid. loader_policy contains
    search_directories,cache and empty ld_library_path/ld_preload/ld_audit/
    ld_so_preload fields. packages contain version/provides plus archive_pin,
    signature_pin,native_provenance_pin,database_pin. provider tuple repeats the
    same complete package rows and original supervisor identity/code/nonce.
    Package rows also carry architecture (aarch64 or any). database_pin names a
    retained INSTALLED_PACKAGE_FILE_METADATA_V1 with matching identity/reference
    fields and entries keyed by absolute paths (type/file pin/mode; symlinks also
    have target/resolved). Original package signature verification is external.
    """
    retained_map(retained)
    need(type(selection) is dict and set(selection) == {'scope', 'recipe_commit', 'image',
         'inventory_pin', 'snapshot_pin', 'provider_tuple_pin', 'stage_pin'}, 'EXACT_EXTERNAL_SELECTION_KEYS')
    need(selection['scope'] == SCOPE and selection['recipe_commit'] == COMMIT
         and re.fullmatch('sha256:[0-9a-f]{64}', selection['image']), 'EXACT_GUI18_COMPONENT_SELECTION')
    need(selection['stage_pin'] == stage_pin and selection['snapshot_pin'] == snapshot_pin,
         'SELECTED_STAGE_AND_SNAPSHOT_REQUIRED')
    stage = selected(stage_raw, stage_pin); snapshot = selected(snapshot_raw, snapshot_pin)
    need(blob(retained, stage_pin) == stage_raw and blob(retained, snapshot_pin) == snapshot_raw
         and blob(retained, pacman_pin) == pacman_raw, 'RETAIN_COMPLETE_INPUT_RECORD_BYTES')
    need(stage.get('status') == 'PASS_QT612_GUI_DESTDIR_CONTRACT_ONLY' and stage.get('architecture') == 'aarch64'
         and stage.get('native_acceptance') is None, 'PINNED_STAGE_BYTES_ONLY_REPORT_REQUIRED')
    need(snapshot.get('kind') == 'GUI18_INSTALLED_RUNTIME_SNAPSHOT_V1'
         and snapshot.get('image') == selection['image'] and snapshot.get('inventory_pin') == selection['inventory_pin']
         and snapshot.get('provider_tuple_pin') == selection['provider_tuple_pin'], 'SELECTED_INSTALLED_PROVIDER_SNAPSHOT')
    tuple_data = decoded(blob(retained, selection['provider_tuple_pin']))
    need(tuple_data.get('kind') == 'GUI18_SIGNED_INSTALLED_PROVIDER_TUPLE_V1'
         and tuple_data.get('image') == selection['image'] and tuple_data.get('inventory_pin') == selection['inventory_pin']
         and tuple_data.get('packages') == snapshot['packages'], 'ORIGINAL_PROVIDER_TUPLE_PACKAGE_JOIN')
    supervisor = tuple_data['supervisor']
    need(type(supervisor) is dict and set(supervisor) == {'code_pin', 'nonce', 'owner_identity'}
         and type(supervisor['nonce']) is str and re.fullmatch('[0-9a-f]{32}', supervisor['nonce'])
         and type(supervisor['owner_identity']) is list and len(supervisor['owner_identity']) == 3
         and all(type(n) is int and n > 0 for n in supervisor['owner_identity']), 'ORIGINAL_SUPERVISOR_IDENTITY_REQUIRED')
    descriptor(supervisor['code_pin'])
    packages = snapshot['packages']; need(type(packages) is dict and 1 <= len(packages) <= 4096, 'BOUNDED_INSTALLED_PACKAGES')
    inventory = blob(retained, selection['inventory_pin'], 2 * 1024**2)
    rows, database = [], {}
    for name, package in sorted(packages.items()):
        need(re.fullmatch('[a-z0-9@+_.-]+', name) and type(package['version']) is str
             and package['version'] and not re.search(r'\s', package['version'])
             and package.get('architecture') in ('aarch64','any')
             and type(package['provides']) is list and len(package['provides']) == len(set(package['provides'])),
             'COMPLETE_INSTALLED_PACKAGE_IDENTITY')
        for key in ('archive_pin', 'signature_pin', 'native_provenance_pin', 'database_pin'):
            need(descriptor(package[key])['bytes'] > 0, 'ORIGINAL_SIGNED_PROVIDER_REFERENCES_REQUIRED')
        meta = decoded(blob(retained, package['database_pin']))
        need(meta.get('kind') == 'INSTALLED_PACKAGE_FILE_METADATA_V1' and meta.get('name') == name
             and all(meta.get(k) == package[k] for k in ('version','architecture','provides','archive_pin','signature_pin','native_provenance_pin'))
             and type(meta.get('entries')) is dict and len(meta['entries']) <= 65536,
             'ORIGINAL_INSTALLED_PACKAGE_FILE_METADATA_JOIN')
        database[name] = meta['entries']
        rows.append(name + ' ' + package['version'] + '\n')
    need(inventory == ''.join(rows).encode(), 'EXACT_SORTED_INSTALLED_INVENTORY')
    need(PACKAGE in packages and packages[PACKAGE]['version'] == '6.12.0-1'
         and packages[PACKAGE]['architecture'] == 'aarch64', 'INSTALLED_GUI_CANDIDATE_IDENTITY')
    pacman, stdout, observation = receipt(pacman_raw, pacman_pin, retained, selection, supervisor,
        'normal-package-dependencies', ['/usr/bin/pacman', '-T'] + DEPENDS)
    need(stdout == b'' and observation == {'kind': 'PACMAN_T_NORMAL_DEPENDENCIES_V1', 'depends': DEPENDS},
         'ORIGINAL_PACMAN_DEPENDENCY_VERSION_PROVIDES_SUCCESS_REQUIRED')
    need(type(snapshot['files']) is dict and len(snapshot['files']) <= 65536
         and type(snapshot['symlinks']) is dict and len(snapshot['symlinks']) <= 65536, 'BOUNDED_INSTALLED_FILE_NAMESPACE')
    for path,row in snapshot['symlinks'].items():
        logical(path)
        need(row.get('package') in database and database[row['package']].get(path) ==
             dict(type='symlink',**{k:row[k] for k in ('bytes','sha256','mode','target','resolved')}),
             'ALIAS_ORIGINAL_PACKAGE_METADATA_DIFFERS')
    policy = snapshot['loader_policy']
    need(set(policy) == {'search_directories', 'cache', 'ld_library_path', 'ld_preload', 'ld_audit', 'ld_so_preload'}
         and policy['search_directories'] == ['/usr/lib', '/lib']
         and all(policy[k] is None for k in ('ld_library_path', 'ld_preload', 'ld_audit', 'ld_so_preload'))
         and type(policy['cache']) is dict, 'NORMAL_OBSERVED_LOADER_POLICY_REQUIRED')
    for name, aliases in policy['cache'].items():
        need(type(name) is str and '/' not in name and type(aliases) is list
             and 0 < len(aliases) <= 32 and len(aliases) == len(set(aliases)), 'BOUNDED_LOADER_CACHE_ALIASES')
        for path in aliases:
            logical(path)
    parsed, closure, joins, version_joins = {}, set(), [], []
    def actual(path):
        if path not in parsed:
            row = snapshot['files'][path]
            need(row['package'] in packages and type(row['uid']) is type(row['gid']) is int
                 and row['uid'] == row['gid'] == 0
                 and type(row['mode']) is int and row['mode'] & 0o7022 == 0
                 and row['mode'] & 0o444 and type(row['archive_member']) is str
                 and '/' + row['archive_member'] == path, 'EXACT_PACKAGE_OWNERSHIP_FILE_MODE')
            need(database[row['package']].get(path) == dict(type='file',**{k:row[k] for k in ('bytes','sha256','mode')}),
                 'ELF_ORIGINAL_PACKAGE_METADATA_DIFFERS')
            body = blob(retained, {k: row[k] for k in ('bytes', 'sha256')}, MAX_FILE)
            parsed[path] = elf(body)
            need(all(row['elf'].get(k) == v for k, v in parsed[path].items()), 'ACTUAL_PROVIDER_ELF_SUMMARY_DIFFERS')
            soname = parsed[path]['soname'] or ''
            need(not soname.startswith('libQt6') or soname in {'libQt6'+m+'.so.6' for m in MODULES},
                 'QT_MODULE_OUTSIDE_GUI18_COMPONENT')
        return parsed[path]
    staged = {'/' + p: row for p, row in stage['elf'].items()}
    need(len(staged) <= 4096 and all(path in staged for path in LIBRARIES), 'ALL18_STAGE_LIBRARIES_REQUIRED')
    for path, summary in staged.items():
        logical(path); file_row = snapshot['files'].get(path)
        need(file_row is not None and file_row['package'] == PACKAGE
             and all(file_row[k] == stage['files'][path[1:]][k] for k in ('bytes', 'sha256', 'mode')),
             'INSTALLED_GUI_FILE_STAGE_JOIN')
        obj = actual(path)
        need(summary.get('geometry_16k') is True and all(summary.get(k) == v for k, v in obj.items()),
             'PINNED_STAGE_ELF16K_SUMMARY_JOIN')
    for name in MODULES:
        path = '/usr/lib/libQt6' + name + '.so.6.12.0'
        need(actual(path)['soname'] == 'libQt6' + name + '.so.6', 'EXACT18_MODULE_SONAME')
        need(resolve('/usr/lib/libQt6' + name + '.so.6', snapshot) == path, 'INSTALLED_MODULE_ALIAS_REQUIRED')
    todo = list(staged)
    while todo:
        path = todo.pop()
        if path in closure:
            continue
        closure.add(path); need(len(closure) <= 4096, 'RUNTIME_CLOSURE_BOUND'); obj = actual(path)
        need(len(obj['needed']) == len(set(obj['needed'])), 'DUPLICATE_NEEDED_AMBIGUITY')
        providers = {}
        for name in obj['needed'] + ([obj['interpreter']] if obj['interpreter'] else []):
            need('$' not in name, 'DYNAMIC_LOADER_TOKEN_HAZARD')
            if '/' in name:
                need(name == '/lib/ld-linux-aarch64.so.1', 'SLASH_NEEDED_HAZARD')
                aliases = [name]
            else:
                aliases = [directory + '/' + name for directory in policy['search_directories']]
                aliases += policy['cache'].get(name, [])
            candidates = {}
            for alias in sorted(set(aliases)):
                if alias not in snapshot['files'] and alias not in snapshot['symlinks']:
                    # A directory alias, notably /lib -> /usr/lib, can resolve this.
                    if not any(alias.startswith(p + '/') for p in snapshot['symlinks']):
                        continue
                provider = resolve(alias, snapshot, missing=True)
                if provider is None:
                    continue
                candidates.setdefault(provider, []).append(alias)
            need(len(candidates) == 1, 'EXACT_ONE_INSTALLED_ELF_PROVIDER_REQUIRED')
            provider = next(iter(candidates)); pobj = actual(provider)
            if '/' not in name:
                need(pobj['soname'] == name, 'PROVIDER_SONAME_DIFFERS')
            providers[name] = provider
            joins.append(dict(consumer=path, needed=name, provider=provider, aliases=candidates[provider],
                              package=snapshot['files'][provider]['package'], file_pin={k:snapshot['files'][provider][k] for k in ('bytes','sha256')}))
            todo.append(provider)
        seen_versions, seen_files = set(), set()
        for requirement in obj['version_needs'] or []:
            name = requirement['file']; need(name in providers, 'GNU_VERSION_FILE_MUST_BE_NEEDED')
            need(name not in seen_files, 'DUPLICATE_GNU_REQUIREMENT_FILE'); seen_files.add(name)
            definitions = actual(providers[name])['version_definitions'] or []
            available, indexes = {}, set()
            for d in definitions:
                need(d['names'] and d['names'][0] not in available and d['index'] not in indexes
                     and 0 < d['index'] < 0x8000 and d['flags'] in (0, 1), 'DUPLICATE_OR_HIDDEN_GNU_DEFINITION')
                available[d['names'][0]] = d; indexes.add(d['index'])
            for v in requirement['versions']:
                key = (name, v['name'])
                need(key not in seen_versions and 1 < v['other'] < 0x8000 and v['flags'] in (0, 2),
                     'DUPLICATE_OR_HIDDEN_GNU_REQUIREMENT')
                seen_versions.add(key)
                need(v['name'] in available and available[v['name']]['hash'] == v['hash'], 'GNU_PROVIDER_VERSION_UNDEFINED')
                version_joins.append(dict(consumer=path, needed=name, provider=providers[name],
                                          requirement=v, definition=available[v['name']]))
    files = {path: {k: snapshot['files'][path][k] for k in ('bytes', 'sha256')} for path in sorted(closure)}
    return dict(schema=1, kind='GUI18_RUNTIME_DEPENDENCY_DATA_V1', status='PASS_RUNTIME_DEPENDENCY_DATA_JOINS_ONLY',
                scope=SCOPE, selection=selection, pacman_pin=pacman_pin, supervisor=supervisor,
                files=files, joins=sorted(joins, key=lambda j:(j['consumer'],j['needed'])),
                version_joins=sorted(version_joins,key=lambda j:(j['consumer'],j['needed'],j['requirement']['name'])),
                modules=LIBRARIES, fixed_baseline_modules=13, source_added_modules=5,
                supervision_truth='EXTERNAL_CUSTODY_REQUIRED_NOT_AUTHENTICATED_BY_JSON', **FINAL)


def validate_smoke(*, dependency_raw, dependency_pin, load_raw, load_pin, offscreen_raw,
                   offscreen_pin, cmake_raw, cmake_pin, retained):
    """Consume finite original-supervisor callback records; execute nothing.

    Callback labels/argv are fixed below. stdout/stderr and observation bytes are
    whole retained operands. An actual executor must implement these labels and
    retain real output; this module supplies no probe binary or default actor.
    """
    retained_map(retained)
    d = selected(dependency_raw, dependency_pin)
    need(d.get('kind') == 'GUI18_RUNTIME_DEPENDENCY_DATA_V1' and d.get('scope') == SCOPE
         and d.get('modules') == LIBRARIES and d.get('status') == 'PASS_RUNTIME_DEPENDENCY_DATA_JOINS_ONLY'
         and all(d.get(k) is v for k,v in FINAL.items() if k not in ('original_official_hold','other54')),
         'BOUND_RUNTIME_DEPENDENCY_COMPONENT_REQUIRED')
    selection, supervisor = d['selection'], d['supervisor']
    rederived = validate_dependencies(stage_raw=blob(retained, selection['stage_pin']),stage_pin=selection['stage_pin'],
        snapshot_raw=blob(retained, selection['snapshot_pin']),snapshot_pin=selection['snapshot_pin'],
        pacman_raw=blob(retained, d['pacman_pin']),pacman_pin=d['pacman_pin'],retained=retained,selection=selection)
    need(encoded(rederived) == dependency_raw, 'RETAINED_RUNTIME_COMPONENT_REDERIVATION_DIFFERS')
    _, _, load = receipt(load_raw, load_pin, retained, selection, supervisor,
        'gui18-rtld-now-local', ['gui18-owned-probe', '--rtld-now-local'] + LIBRARIES)
    need(load == dict(kind='GUI18_RTLD_NOW_LOCAL_OBSERVATION_V1', flags=2,
                     modules=LIBRARIES, loaded_files=d['files'], stage_pin=selection['stage_pin']),
         'ALL18_RTLD_NOW_LOCAL_SAME_PROVIDER_FILES_REQUIRED')
    _, stdout, offscreen = receipt(offscreen_raw, offscreen_pin, retained, selection, supervisor,
        'gui18-offscreen-smoke', ['gui18-owned-probe', '--offscreen-gui'])
    need(stdout == (OFFSCREEN_MARKER + '\n').encode()
         and offscreen == dict(kind='GUI18_OFFSCREEN_OBSERVATION_V1', platform='offscreen',
             marker=OFFSCREEN_MARKER, stage_pin=selection['stage_pin'],
             loaded_files=d['files']), 'OFFSCREEN_GUI_MARKER_AND_BOUND_LOADED_FILES_REQUIRED')
    _, _, cmake = receipt(cmake_raw, cmake_pin, retained, selection, supervisor,
        'gui18-normal-cmake-discovery', ['gui18-owned-probe', '--normal-cmake-discovery'])
    need(cmake == dict(kind='GUI18_NORMAL_CMAKE_OBSERVATION_V1', modules=MODULES,
                      stage_pin=selection['stage_pin'], package_registry=False,
                      target_names=CMAKE_TARGETS, package_names=CMAKE_PACKAGES,
                      target_library_files={m: p for m,p in zip(MODULES,LIBRARIES)}),
         'NORMAL_CMAKE_ALL18_TARGET_DISCOVERY_REQUIRED')
    return dict(schema=1, kind='GUI18_RUNTIME_SMOKE_RECEIPT_DATA_V1',
                status='PASS_SUPERVISED_RUNTIME_RECEIPT_DATA_ONLY', scope=SCOPE,
                dependency_pin=dependency_pin, selection=selection,
                load_pin=load_pin, offscreen_pin=offscreen_pin, cmake_pin=cmake_pin,
                actual_execution_truth='EXTERNAL_SUPERVISOR_CUSTODY_REQUIRED_NOT_ESTABLISHED_BY_JSON', **FINAL)

# SPDX-License-Identifier: MIT
"""Case-specific offline gates. Never prepares, launches, authenticates or accepts a VM."""
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import time

HERE = Path(__file__).resolve().parent
END = None
OP = 'arm16k-llvm23-private-prefix-vm-v1'
PREFIX = '/opt/cachy-asahi/llvm23-source-reference'
PACKAGE = dict(name='cachy-asahi-llvm23-source-reference', version='23.1.1-1', arch='aarch64', prefix=PREFIX,
               depends=['glibc', 'libgcc', 'libstdc++', 'zlib', 'zstd'])
SOURCE = dict(sha='365a763bc515a1b3550cc804536ddbf66353aac8', ref='refs/heads/codex/llvm23-source-reference-native-v2-20261115-r2',
              map_sha256='22f6f8a9d3eabf4de16c853cf67183b67beca4e702e26c5b492066e94194735c', tree='f251f3b7c7e152943ce85bc012f97305934e8fd8')
MATERIALS = ('archive', 'signature', 'public_TEST_certificate', 'signing_receipt')
EVIDENCE = ('baseline_certificate', 'runtime_certificate', 'resource_certificate', 'Root_decision', 'Reader4_report')
TOOLS = ('base64', 'bash', 'cat', 'chmod', 'chown', 'cmp', 'comm', 'cp', 'cut', 'date', 'env', 'find', 'getconf', 'getfattr',
         'gpg', 'gpgconf', 'grep', 'head', 'id', 'install', 'mkdir', 'pacman', 'readlink', 'rm', 'rmdir', 'runuser', 'sed',
         'sha256sum', 'sleep', 'sort', 'stat', 'sync', 'timeout', 'touch', 'tr', 'uname', 'wc', 'xargs')
LIMITS = ('image_scan_passes', 'package_expanded_bytes', 'case_staging_bytes', 'fixture_source_bytes', 'baseline_raw_bytes', 'baseline_allocated_bytes', 'prepared_raw_bytes',
          'guest_filesystem_free_bytes', 'guest_output_cap_bytes', 'clone_allocated_cap_bytes', 'overlay_cap_bytes',
          'readback_allocated_cap_bytes', 'logs_cap_bytes', 'reserve_bytes', 'physical_free_bytes',
          'quota_initial_headroom_bytes', 'quota_live_reserve_bytes', 'guest_memory_bytes', 'owner_memory_bytes',
          'host_reserve_bytes', 'host_MemAvailable_bytes', 'cpus', 'pids', 'prepare_seconds', 'boot_seconds', 'cleanup_seconds', 'boot_overhead_seconds',
          'output_device', 'host_uid', 'gpg_seconds', 'install_seconds', 'probe_wait_seconds', 'remove_seconds',
          'compile_seconds', 'run_seconds', 'sync_seconds', 'log_bytes')


def need(ok, why):
    if END is not None and time.monotonic() >= END:
        raise TimeoutError('original Root phase deadline exhausted')
    if not ok:
        raise ValueError(why)


def keys(value, names, label):
    need(type(value) is dict and set(value) == set(names), label + ' exact fields')


def positive(value):
    return type(value) is int and 0 < value < 2**63


def sha(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def pin_shape(value):
    keys(value, ('bytes', 'sha256'), 'nonnull pin')
    need(positive(value['bytes']) and sha(value['sha256']), 'nonnull bounded byte/SHA256 pin')
    return value


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def json_pin(value):
    raw = canonical(value)
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def ordinary(path):
    p = Path(path)
    need(p.is_absolute() and '..' not in p.parts and not any(q.is_symlink() for q in (p, *p.parents)), 'ordinary absolute DATA path')
    return p


def pin(path, cap=2*1024**3):
    p = ordinary(path)
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), 'rb') as stream:
        a = os.fstat(stream.fileno())
        need(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and 0 <= a.st_size <= cap, 'bounded single-link DATA')
        h = hashlib.sha256()
        total = 0
        while block := stream.read(65536):
            total += len(block); need(total <= cap, 'DATA byte cap'); h.update(block)
        b = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mode, s.st_nlink, s.st_mtime_ns, s.st_ctime_ns)
    need(identity(a) == identity(b) == identity(p.lstat()) and total == a.st_size, 'DATA changed while read')
    return dict(bytes=total, sha256=h.hexdigest())


def load(path, cap=4*1024**2):
    p = ordinary(path); before = pin(p, cap)
    def unique(rows):
        result = {}
        for k, v in rows:
            need(k not in result, 'duplicate JSON field'); result[k] = v
        return result
    def invalid(value):
        raise ValueError('noninteger/nonfinite JSON: ' + value)
    raw = p.read_bytes()
    need(len(raw) <= cap and dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) == before, 'stable bounded JSON read')
    value = json.loads(raw, object_pairs_hook=unique, parse_float=invalid, parse_constant=invalid)
    need(type(value) is dict and raw == canonical(value), 'canonical JSON object required')
    return value


def guest_path(value):
    need(type(value) is str and re.fullmatch('/[A-Za-z0-9._+/@:~-]+', value) is not None and
         all(x not in ('', '.', '..') for x in value.split('/')[1:]), 'literal absolute guest path')
    return value


def root_cert(value, kind):
    need(type(value) is dict and value.get('kind') == kind and value.get('issued_by') == 'Root' and value.get('accepted') is True,
         'actual Root-issued accepted certificate: ' + kind)


def candidate_target(namespace, path):
    seen = set()
    for _ in range(32):
        need(path == PREFIX or path.startswith(PREFIX + '/'), 'candidate alias contained in prefix')
        need(path not in seen, 'candidate alias cycle'); seen.add(path)
        parts = path.split('/')[1:]; changed = False
        for i in range(1, len(parts) + 1):
            prefix = '/' + '/'.join(parts[:i]); row = namespace.get(prefix)
            if row and row['kind'] == 'd': need(row['mode'] & 0o001, 'ordinary guest can traverse candidate directory')
            if row and row['kind'] == 'l':
                target = row['link_target']
                path = posixpath.normpath(posixpath.join(target if target.startswith('/') else posixpath.join(posixpath.dirname(prefix), target), *parts[i:]))
                changed = True; break
        if not changed:
            need(path in namespace and namespace[path]['kind'] in ('f', 'd'), 'candidate alias actual ordinary target')
            need(not namespace[path]['mode'] & 0o6002, 'safe ordinary candidate alias target')
            return path
    raise ValueError('candidate alias resolution bound')


def baseline(value):
    root_cert(value, 'ROOT_ACCEPTED_ARM16K_PAM_BASELINE_V1')
    keys(value, ('kind', 'issued_by', 'accepted', 'architecture', 'page_bytes', 'raw', 'prepared', 'inventory', 'ownership', 'report',
                 'normal_PAM_logout_observed', 'owned_container_absence_verified', 'baseline_count'), 'baseline certificate')
    need(value['architecture'] == 'aarch64' and type(value['page_bytes']) is int and value['page_bytes'] == 16384 and
         value['normal_PAM_logout_observed'] is value['owned_container_absence_verified'] is True, 'actual accepted ARM16K PAM/retirement proof')
    for n in ('raw', 'prepared', 'ownership', 'report'): pin_shape(value[n])
    inv = value['inventory']
    need(type(inv) is dict and inv and all(type(n) is str and re.fullmatch('[a-z0-9@+_.-]+', n) and type(v) is str and
         0 < len(v) <= 128 and not any(c.isspace() for c in v) for n, v in inv.items()), 'actual baseline package versions')
    need(type(value['baseline_count']) is int and value['baseline_count'] == len(inv), 'derived baseline count, no assumed111/155')
    return inv


def runtime(value, case, base):
    root_cert(value, 'ROOT_REVIEWED_LLVM23_VM_RUNTIME_V1')
    keys(value, ('kind', 'issued_by', 'accepted', 'baseline_certificate', 'package', 'namespace_coverage', 'candidate_namespace',
                 'elf_inventory', 'full_payload_elf_coverage', 'elfs', 'files', 'tools', 'crt', 'loader', 'runtime',
                 'gcc_driver_selection', 'dependency_versions'), 'runtime certificate')
    need(value['baseline_certificate'] == case['evidence']['baseline_certificate'] and value['package'] == case['package']['archive'], 'runtime exact baseline/candidate joins')
    pin_shape(value['elf_inventory'])
    need(value['full_payload_elf_coverage'] is True and value['namespace_coverage'] == 'ALL_PACKAGE_OWNED_PATHS', 'full candidate ELF/ownership coverage')
    need(value['dependency_versions'] == {n: base[n] for n in PACKAGE['depends'] if n in base} and
         set(value['dependency_versions']) == set(PACKAGE['depends']), 'five dependencies resolve to actual baseline versions')
    ns = value['candidate_namespace']; need(type(ns) is dict and ns, 'actual candidate namespace required')
    expanded = 0
    for path, row in ns.items():
        guest_path(path); need(type(row) is dict and row.get('kind') in ('f', 'd', 'l'), 'candidate inode kind')
        kind = row['kind']; keys(row, {'kind', 'mode', 'uid', 'gid'} | ({'bytes', 'sha256'} if kind == 'f' else {'link_target'} if kind == 'l' else set()), 'candidate inode')
        need(type(row['mode']) is int and 0 <= row['mode'] <= 0o7777 and not row['mode'] & 0o6000 and (kind == 'l' or not row['mode'] & 0o002) and
             type(row['uid']) is type(row['gid']) is int and row['uid'] == row['gid'] == 0, 'root-owned candidate without SUID/SGID/world-write')
        need(path == PREFIX or path.startswith(PREFIX + '/') or kind == 'd' and path in ('/opt', '/opt/cachy-asahi'), 'private-prefix-only package')
        if kind == 'f':
            need(type(row['bytes']) is int and 0 <= row['bytes'] < 2**63 and sha(row['sha256']), 'actual candidate file pin'); expanded += row['bytes']
        elif kind == 'l':
            target = row['link_target']; need(type(target) is str and target and not any(c in target for c in '\0\n\r\t'), 'literal symlink target')
            resolved = posixpath.normpath(target if target.startswith('/') else posixpath.join(posixpath.dirname(path), target))
            need(resolved == PREFIX or resolved.startswith(PREFIX + '/'), 'symlink stays within private prefix')
    for path, row in ns.items():
        if row['kind'] == 'l': candidate_target(ns, path)
    files = value['files']; need(type(files) is dict and files, 'actual guest file closure')
    owners = dict(base, **{PACKAGE['name']: PACKAGE['version']})
    for path, row in files.items():
        guest_path(path); keys(row, ('bytes', 'sha256', 'mode', 'owner', 'version', 'resolved'), 'guest file')
        guest_path(row['resolved']); need(type(row['bytes']) is int and 0 <= row['bytes'] < 2**63 and sha(row['sha256']) and type(row['mode']) is int and
             0 <= row['mode'] <= 0o7777 and not row['mode'] & 0o6002 and type(row['owner']) is str and owners.get(row['owner']) == row['version'], 'actual file/mode/package owner-version')
        if row['owner'] == PACKAGE['name']:
            target = candidate_target(ns, path); actual = ns[target]
            need(row['resolved'] == target and actual['kind'] == 'f' and all(row[n] == actual[n] for n in ('bytes', 'sha256', 'mode')), 'candidate file resolves to exact package bytes/mode')
    need(type(value['tools']) is list and len(value['tools']) == len(set(value['tools'])) and
         {'/usr/bin/' + n for n in TOOLS} <= set(value['tools']), 'complete explicit baseline tool closure')
    selected = value['gcc_driver_selection']
    keys(selected, ('mode', 'gcc_prefix', 'headers', 'libraries', 'startfiles'), 'actual GCC/development selection')
    need(selected['mode'] in ('EXPLICIT_GCC', 'EXPLICIT_COMPILER_RT') and selected['headers'] and selected['libraries'] and selected['startfiles'], 'actual development inputs, no guessed GCC headers')
    if selected['mode'] == 'EXPLICIT_GCC': guest_path(selected['gcc_prefix'])
    else: need(selected['gcc_prefix'] is None, 'no implicit GCC selection')
    paths = [value['loader']]
    for group in [value['tools'], value['crt'], value['runtime'], selected['headers'], selected['libraries'], selected['startfiles']]:
        need(type(group) is list and group and all(type(p) is str for p in group), 'nonempty explicit file role'); paths += group
    need(all(guest_path(p) in files for p in paths), 'every tool/CRT/loader/runtime/development path certified')
    need(all(files[p]['mode'] & 0o004 for p in paths), 'ordinary guest can read certified runtime/development files')
    need(all(files[p]['mode'] & 0o005 == 0o005 and positive(files[p]['bytes']) for p in value['tools']), 'certified tools ordinary-user executable/nonempty')
    need(all(positive(files[p]['bytes']) for p in [value['loader']] + value['crt'] + value['runtime'] + selected['libraries'] + selected['startfiles']), 'nonempty loader/CRT/runtime/development libraries')
    elfs = value['elfs']; need(type(elfs) is dict and elfs, 'full candidate ELF inventory')
    for n in ('clang', 'clang++', 'ld.lld', 'llvm-config', 'llvm-ar', 'llvm-ranlib'):
        target = candidate_target(ns, PREFIX + '/bin/' + n)
        need(target in elfs and ns[target]['kind'] == 'f' and ns[target]['mode'] & 0o005 == 0o005 and positive(ns[target]['bytes']), 'resolved actual ordinary-user executable LLVM tool ELF')
    for path, elf in elfs.items():
        need(path in ns and ns[path]['kind'] == 'f' and elf.get('sha256') == ns[path]['sha256'], 'ELF member bytes match package namespace')
        keys(elf, ('sha256', 'class', 'byte_order', 'machine', 'interpreter', 'needed', 'version_needs', 'providers', 'static_16k_geometry'), 'ELF facts')
        need(elf['class'] == 64 and elf['byte_order'] == 'little' and elf['machine'] == 183 and elf['static_16k_geometry'] is True, 'actual static ARM16K ELF facts')
        need(elf['interpreter'] is None or elf['interpreter'] == value['loader'], 'exact qualified ELF interpreter')
        needed = elf['needed']; need(type(needed) is list and len(needed) == len(set(needed)) and set(elf['providers']) == set(needed) and set(elf['version_needs']) <= set(needed), 'full DT_NEEDED/GNU-version provider closure')
        for lib, provider in elf['providers'].items():
            keys(provider, ('path', 'version_definitions'), 'ELF provider'); need(provider['path'] in files and type(provider['version_definitions']) is list, 'certified actual provider file')
            required = elf['version_needs'].get(lib, []); need(type(required) is list and all(type(n) is str and n for n in required + provider['version_definitions']) and set(required) <= set(provider['version_definitions']), 'GNU version needs satisfied by actual provider')
    return expanded


def resources(value, case, base, expanded):
    root_cert(value, 'ROOT_REVIEWED_LLVM23_VM_RESOURCES_V1')
    keys(value, {'kind', 'issued_by', 'accepted', 'baseline_certificate', 'package', 'quota_guard'} | set(LIMITS), 'resource certificate')
    need(value['baseline_certificate'] == case['evidence']['baseline_certificate'] and value['package'] == case['package']['archive'], 'resource baseline/candidate joins')
    need(all(positive(value[n]) for n in LIMITS), 'all physical/resource/guest-phase numbers explicit positive integers')
    need(all(value[n] <= 999999999 for n in ('gpg_seconds', 'install_seconds', 'probe_wait_seconds', 'remove_seconds',
         'compile_seconds', 'run_seconds', 'sync_seconds', 'guest_output_cap_bytes')) and 1024 <= value['log_bytes'] <= 16777216,
         'exact guest case.env scalar grammar')
    need(value['baseline_raw_bytes'] == base['raw']['bytes'] and value['package_expanded_bytes'] == expanded and value['prepared_raw_bytes'] >= value['baseline_raw_bytes'], 'actual candidate-expanded/raw geometry')
    need(value['case_staging_bytes'] >= sum(case['package'][n]['bytes'] for n in MATERIALS) + value['fixture_source_bytes'], 'staging includes compressed archive/signature/certificate/receipt and reviewed fixture Source')
    writes = value['baseline_allocated_bytes'] + value['case_staging_bytes'] + expanded + value['guest_output_cap_bytes']
    need(value['clone_allocated_cap_bytes'] >= writes and value['readback_allocated_cap_bytes'] >= writes and
         value['guest_filesystem_free_bytes'] >= value['case_staging_bytes'] + expanded + value['guest_output_cap_bytes'] and value['prepared_raw_bytes'] >= writes, 'clone/readback/raw/guest capacity includes staged and expanded candidate and output')
    peak = sum(value[n] for n in ('clone_allocated_cap_bytes', 'overlay_cap_bytes', 'readback_allocated_cap_bytes', 'logs_cap_bytes', 'reserve_bytes'))
    need(value['physical_free_bytes'] >= peak and value['quota_initial_headroom_bytes'] >= peak and value['quota_live_reserve_bytes'] >= value['reserve_bytes'], 'simultaneous physical/quota clone+overlay+readback+logs+reserve')
    need(value['owner_memory_bytes'] >= value['guest_memory_bytes'] and value['host_MemAvailable_bytes'] >= value['owner_memory_bytes'] + value['host_reserve_bytes'], 'actual host RAM reserve')
    # Probe: two compiles, four version/config calls, two runs, one sync. Root's
    # wait encloses these calls, so the outer envelope counts that wait once.
    probe = 2*value['compile_seconds'] + 6*value['run_seconds'] + value['sync_seconds']
    need(value['probe_wait_seconds'] >= probe, 'probe wait covers two compiles, six runs and sync')
    # Root: five gpg calls plus gpgconf retirement; two database checks and two
    # durable syncs. Root separately supplies nondefault boot/PAM/snapshot overhead.
    phase = (6*value['gpg_seconds'] + value['install_seconds'] + value['probe_wait_seconds'] + value['remove_seconds'] +
             2*value['run_seconds'] + 2*value['sync_seconds'] + value['cleanup_seconds'] + value['boot_overhead_seconds'])
    need(value['boot_seconds'] >= phase and value['prepare_seconds'] > value['cleanup_seconds'] and value['logs_cap_bytes'] >= value['log_bytes'], 'finite guest/cleanup/log envelopes')
    q = value['quota_guard']; keys(q, ('issued_by', 'method', 'whole_actor', 'read_only', 'uid', 'device', 'initial_headroom_bytes', 'live_reserve_bytes', 'on_unknown_or_exhausted'), 'quota guard')
    need(q == dict(issued_by='Root', method='READ_ONLY_Q_GETQUOTA', whole_actor=True, read_only=True, uid=value['host_uid'], device=value['output_device'], initial_headroom_bytes=value['quota_initial_headroom_bytes'], live_reserve_bytes=value['quota_live_reserve_bytes'], on_unknown_or_exhausted='HOLD_AND_OWNED_CLEANUP'), 'actual readonly own-UID whole-actor quota guard')


def validate(case, observed_materials, baseline_certificate, runtime_certificate, resource_certificate, Root_decision, Reader4_report):
    keys(case, ('schema', 'operation', 'source', 'package', 'native', 'evidence', 'trust'), 'case')
    need(type(case['schema']) is int and case['schema'] == 1 and case['operation'] == OP and case['source'] == SOURCE, 'exact published LLVM256 Source/case identity')
    keys(case['package'], set(PACKAGE) | set(MATERIALS), 'package')
    need(all(case['package'][n] == v for n, v in PACKAGE.items()), 'fixed private package identity/dependencies')
    keys(case['native'], ('run', 'job', 'artifact'), 'native tuple')
    need(all(type(n) is str and re.fullmatch('[1-9][0-9]{0,19}', n) for n in case['native'].values()), 'genuine native run/job/artifact required')
    keys(case['evidence'], EVIDENCE, 'case evidence'); keys(observed_materials, MATERIALS + EVIDENCE, 'observed materials')
    certificates = dict(zip(EVIDENCE, (baseline_certificate, runtime_certificate, resource_certificate, Root_decision, Reader4_report)))
    for name in MATERIALS + EVIDENCE:
        expected = case['package'][name] if name in MATERIALS else case['evidence'][name]
        pin_shape(expected); need(pin_shape(observed_materials[name]) == expected, 'actual material pin join: ' + name)
        if name in certificates: need(type(certificates[name]) is dict and json_pin(certificates[name]) == expected, 'canonical actual certificate byte join: ' + name)
    trust = case['trust']; keys(trust, ('fingerprint', 'created_utc', 'expires_utc', 'evaluated_utc', 'public_only', 'signature_valid', 'revoked'), 'trust')
    need(type(trust['fingerprint']) is str and re.fullmatch('[A-F0-9]{40}', trust['fingerprint']) and
         all(type(trust[n]) is int and 100000000 <= trust[n] <= 999999999999 for n in ('created_utc', 'expires_utc', 'evaluated_utc')),
         'actual public TEST signer identity and guest 9-to12-digit epochs')
    now = int(time.time()); need(trust['created_utc'] <= trust['evaluated_utc'] < trust['expires_utc'] and trust['created_utc'] <= now < trust['expires_utc'] and 0 <= now-trust['evaluated_utc'] <= 3600 and trust['public_only'] is trust['signature_valid'] is True and trust['revoked'] is False, 'fresh nonrevoked public-only authenticated TEST signature')
    report = Reader4_report
    need(report.get('status') == 'PASS_INDEPENDENT_ROOT_BOUND_LLVM23_PUBLISHED256_DATA_ONLY' and report.get('source_tree') == SOURCE['tree'] and report.get('source_files') == 256 and report.get('verified_historical_inverse') == [253, 251, 248] and report.get('package') == case['package']['archive'], 'exact completed Reader4 package/Source result')
    actual = report.get('actual', {}); need(actual.get('source') == SOURCE['sha'] and actual.get('ref') == SOURCE['ref'] and all(actual.get(n) == v for n, v in case['native'].items()) and report.get('native_acceptance') is False and report.get('Root_authentication') is False and report.get('Root_acceptance') is None, 'Reader actual tuple, no invented Root acceptance')
    decision = Root_decision; root_cert(decision, 'ROOT_ACCEPTED_LLVM23_NATIVE_INPUT_FOR_VM_V1')
    keys(decision, ('kind', 'issued_by', 'accepted', 'operation', 'accepted_for_vm_input', 'source', 'native', 'package', 'trust', 'evidence', 'package_signature_authenticated'), 'Root decision')
    need(decision['operation'] == OP and decision['accepted_for_vm_input'] is decision['package_signature_authenticated'] is True and decision['source'] == SOURCE and decision['native'] == case['native'] and decision['package'] == case['package'] and decision['trust'] == trust and decision['evidence'] == {n: case['evidence'][n] for n in EVIDENCE if n != 'Root_decision'}, 'explicit Root acceptance and all noncyclic evidence/trust/package joins')
    inventory = baseline(baseline_certificate)
    expanded = runtime(runtime_certificate, case, inventory)
    resources(resource_certificate, case, baseline_certificate, expanded)
    return json.loads(canonical(case))


def helper(name):
    """Only the closed Source's copied reviewed helper closure is importable."""
    need(type(name) is str and re.fullmatch('[A-Za-z0-9_.-]+', name), 'literal copied helper name')
    import importlib.util
    origin = load(HERE/'helper-origin.json')['files']
    key = 'frozen/'+name if 'frozen/'+name in origin else name
    need(key in origin, 'reviewed helper provenance required')
    file = HERE/'frozen'/name
    need(pin(file) == {k:origin[key][k] for k in ('bytes','sha256')}, 'whole copied helper pin')
    spec = importlib.util.spec_from_file_location('llvm_vm_frozen_'+name.replace('.', '_'), file)
    result = importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result


def endpoint(authority):
    daemon=authority['daemon'];host=daemon['host']
    need(daemon['status']=='ROOT_REVIEWED_LOCAL_ROOTLESS_ENDPOINT' and type(host)is str and host.startswith('unix:///') and not any(c in host.removeprefix('unix://') for c in '\n\r,:'),'explicit local rootless endpoint')
    socket=ordinary(host.removeprefix('unix://'));info=socket.lstat()
    need(stat.S_ISSOCK(info.st_mode) and info.st_uid==os.getuid() and {k:getattr(info,'st_'+k) for k in('uid','gid','dev','ino')}==daemon['socket_identity'],'actual selected rootless socket identity')
    return host

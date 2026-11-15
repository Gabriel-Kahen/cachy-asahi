# SPDX-License-Identifier: MIT
"""Independent joins over already retained bytes; no controller imports or I/O."""
import hashlib
import json
import re
import struct

OP = 'arm16k-perl5423-system-runtime-v1'
VERSION = '5.42.3-1.3'
ARCHIVE = dict(bytes=22071176, sha256='647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22')
NATIVE = dict(run='43692477455', job='132745843566', artifact='14153417247')
SOURCE = dict(sha='25dc3e65bdb6137c87a9409067fe9b2cf6e9763f',
              ref='refs/heads/codex/native-arm-perl5423-v2-20261115',
              map_sha256='4b1de3aade5116206318570d1d44ee1063342faeab54935748b1b7c179a99e96')
LOGS = tuple(n + '.log' for n in ('version', 'functional', 'corelist', 'json', 'perldoc', 'podtext', 'podcheck', 'prove', 'sha', 'splain', 'paths'))
FUNCTIONAL = b'PERL5423_FUNCTIONAL_OK\nDB_FILE=ROUNDTRIP\nGDBM=ROUNDTRIP\nZLIB=ROUNDTRIP\nBZIP2=ROUNDTRIP\nTHREADS=JOIN_SHARED\nLIBPERL=SHARED\n'
PROBE = dict(STATUS='PASS', ARCH='aarch64', PAGESIZE='16384', UID='1000', GID='1000', PERL_VERSION='5.42.3', FUNCTIONAL='PASS', COMMANDS='PASS', ELF_GEOMETRY='HOST_CHECK_REQUIRED')
INSTALLED = dict(STATUS='PASS', PACKAGE='perl', VERSION=VERSION)
RESTORED = dict(STATUS='PASS', ARCH='aarch64', PAGESIZE='16384', PACKAGE='perl', VERSION=VERSION,
                BASE_PAYLOAD='RESTORED', BASE_METADATA='RESTORED', BASE_XATTR='RESTORED', LOCAL_DB='RESTORED',
                USERS='RESTORED', UNOWNED_LDCACHE='RESTORED', PERL_BASELINE='RESTORED', PRIVATE_TRUST='REMOVED',
                HOOKS_SCRIPTLETS='UNSUPPRESSED', GUEST_SYNC='PASS', ELF_GEOMETRY='HOST_CHECK_REQUIRED',
                RTC_PRESENT='yes', RTC_DRIVER='pl031', RTC_HCTOSYS='1', RTC_CLOCK_ADVANCED='yes', CLOCK_SETTING='none', DB_POLICY='EXACT')


def need(ok, message):
    if not ok:
        error = ValueError(message)
        error.reader_check = message
        raise error


def inv_bytes(inventory):
    return ''.join(n + ' ' + v + '\n' for n, v in sorted(inventory.items())).encode()


def case_context(packet, files, source_files, lock, nonce, parse, digest):
    need(packet['Source_lock'] == lock and packet['nonce'] == nonce and packet['operation'] == OP
         and packet['status'] == 'PREPARED_CASE_PACKET_NOT_INSTALLED_OR_BOOTED'
         and all(v is None for v in packet['actual'].values()), 'exact unissued Perl packet')
    need(parse(files['source-lock-selection.json']) == lock, 'packet explicit Source lock selection')
    case = parse(files['case-inputs.json'])
    need(digest(files['case-inputs.json']) == packet['case'] and case['operation'] == OP
         and case['source'] == SOURCE and case['native'] == NATIVE, 'Source25/native tuple')
    package = case['package']
    need(package['name'] == 'perl' and package['version'] == VERSION and package['arch'] == 'aarch64'
         and package['archive'] == ARCHIVE, 'exact native1.3 archive')
    cert = {n: parse(files[n + '.json']) for n in case['evidence']}
    for n, pin in case['evidence'].items():
        need(digest(files[n + '.json']) == pin, 'case certificate bytes')
    root = cert['Root_decision']
    need(root['kind'] == 'ROOT_ACCEPTED_PERL5423_INPUT_FOR_VM_V1' and root['issued_by'] == 'Root'
         and root['accepted'] is True and root['accepted_for_vm_input'] is True
         and root['operation'] == OP and root['native'] == NATIVE and root['source'] == SOURCE
         and root['package'] == package and root['package_signature_authenticated'] is True
         and root['trust'] == case['trust'], 'recorded Root native/TEST input admission')
    need(root['evidence'] == {n: pin for n, pin in case['evidence'].items() if n != 'Root_decision'}, 'Root exact evidence joins')
    trust = case['trust']
    need(trust['public_only'] is True and trust['signature_valid'] is True and trust['revoked'] is False
         and trust['created_utc'] <= trust['evaluated_utc'] < trust['expires_utc']
         and re.fullmatch('[0-9A-F]{40}', trust['fingerprint']), 'recorded bounded public TEST authentication')
    base, rt, resource = (cert[n] for n in ('baseline_certificate', 'runtime_certificate', 'resource_certificate'))
    for c in (base, rt, resource):
        need(c['issued_by'] == 'Root' and c['accepted'] is True, 'recorded Root certificate')
    inventory = base['inventory']
    need(base['kind'] == 'ROOT_ACCEPTED_ARM16K_PAM_BASELINE_V1' and base['baseline_count'] == len(inventory) == 111
         and base['architecture'] == 'aarch64' and base['page_bytes'] == 16384
         and base['normal_PAM_logout_observed'] is True and base['owned_container_absence_verified'] is True
         and 'perl' not in inventory and 'db5.3' not in inventory, 'supported exact Perl-absent baseline111')
    need(rt['kind'] == 'ROOT_REVIEWED_PERL5423_VM_EXPECTED_PAYLOAD_INPUTS_V1'
         and rt['baseline_certificate'] == case['evidence']['baseline_certificate']
         and rt['Root_runtime_certificate'] is rt['actual_guest_hashes'] is rt['actual_guest_namespace'] is rt['actual_guest_ALPM_ownership'] is None
         and rt['runtime_acceptance'] is False and rt['reverse_dependencies'] == []
         and rt['rollback']['mode'] == 'REMOVE' and rt['rollback']['local_database_policy'] == 'EXACT', 'expected projection is not actual installed evidence')
    ep = rt['expected_payload']
    need(ep['kind'] == 'EXPECTED_PACKAGE_PAYLOAD_INPUTS_ONLY' and len(ep['rows']) == len(rt['elfs']) == 81
         and ep['actual_guest_hashes'] is ep['actual_guest_ownership'] is ep['Root_runtime_certificate'] is None
         and ep['runtime_acceptance'] is False and rt['full_payload_elf_coverage'] is True, 'complete expected81 projection only')
    need({r['expected_path'] for r in ep['rows']} == set(rt['elfs']), 'one expected projection row per ELF')
    for r in ep['rows']:
        selected = rt['files'][r['expected_path']]
        need(r['expected_member_bytes'] == selected['bytes'] and r['expected_member_sha256'] == selected['sha256']
             and r['expected_package'] == selected['owner'] and r['expected_package_version'] == selected['version'], 'expected member/path/owner/version projection join')
    dependency = rt['dependency_transaction']
    need(dependency['name'] == 'db5.3' and dependency['version'] == '5.3.28-7'
         and dependency['full_ELF_coverage'] is True and set(dependency['elf_paths']) <= set(rt['elfs']), 'only explicitly selected db5.3 transaction')
    installed = dict(inventory, **{'db5.3': dependency['version'], 'perl': VERSION})
    dependencies = {'glibc': 'glibc', 'gdbm>=1.17': 'gdbm', 'db5.3': 'db5.3', 'libxcrypt': 'libxcrypt',
                    'libcrypt.so=2-64': 'libxcrypt', 'bzip2': 'bzip2', 'zlib': 'zlib'}
    need(set(rt['alpm_dependencies']) == set(rt['dependency_resolution']) == set(dependencies), 'exact bounded ALPM dependencies/provides')
    for dep, owner in dependencies.items():
        resolved = rt['dependency_resolution'][dep]
        need(resolved['satisfied'] is True and resolved['owner'] == owner and resolved['version'] == installed[owner]
             and resolved['providers'] and all(p in rt['files'] and rt['files'][p]['owner'] == owner for p in resolved['providers']), 'ALPM dependency version/owner/provider association')
    gdbm = re.match(r'^(\d+)\.(\d+)(?:[.-]|$)', inventory['gdbm'])
    need(gdbm is not None and tuple(map(int, gdbm.groups())) >= (1, 17)
         and any('/libcrypt.so.2' in p for p in rt['dependency_resolution']['libcrypt.so=2-64']['providers']), 'selected gdbm floor and libcrypt ABI2 provide')
    for n, expected in [('expected-base.lock', inventory), ('expected-dependencies.lock', dict(inventory, **{'db5.3': dependency['version']})), ('expected-installed.lock', installed)]:
        need(files[n] == inv_bytes(expected), 'literal complete expected ALPM inventories')
    paths = sorted(p for p in rt['elfs'] if rt['files'][p]['owner'] == 'perl')
    need(len(paths) == 54 and '/usr/bin/perl' in paths and '/usr/lib/perl5/5.42/core_perl/CORE/libperl.so' in paths, 'all54 package ELF paths')
    expected_manifest = ''.join(str(i) + '.elf\t' + p + '\t' + rt['files'][p]['sha256'] + '\n' for i, p in enumerate(paths)).encode()
    need(files['elf-paths.tsv'] == expected_manifest, 'complete numbered ELF selection')
    for name in ('root.sh', 'probe.sh', 'case.sh', 'official-trust.sh', 'runtime.pl', 'smoke.t'):
        need(files[name] == source_files['guest/' + name], 'packet guest body differs from selected Source')
    for name in ('rtc-clock.sh', 'guest-runtime.sh'):
        need(files['frozen/' + name] == source_files['frozen/' + name], 'packet helper differs from selected Source')
    for path, elf in rt['elfs'].items():
        row = rt['files'][path]
        need(row['sha256'] == elf['sha256'] and row['version'] == installed[row['owner']]
             and elf['machine'] == 183 and elf['class'] == 64 and elf['byte_order'] == 'little'
             and elf['static_16k_geometry'] is True and set(elf['providers']) == set(elf['needed']), 'expected ELF hash/owner/version/arch/provider completeness')
        for needed, provider in elf['providers'].items():
            need(provider['path'] in rt['files'] and set(elf['version_needs'].get(needed, [])) <= set(provider['version_definitions']), 'expected GNU version/provider join')
    hooks = rt['effective_hook_policy']
    need(hooks['scriptlets_enabled'] is True and hooks['suppression_added'] is False
         and hooks['transaction_same_effective_policy'] is True, 'normal effective hooks remain enabled')
    decision, reader = cert['installed_component_decision'], cert['installed_Reader']
    need(decision['issuer'] == 'Root' and decision['accepted'] is True and decision['page_bytes'] == 4096
         and decision['archive'] == ARCHIVE and decision['candidate_version'] == VERSION
         and decision['binding']['source'] == '445b37a9475a4e92804954f4f0e3d0ac84cd9511'
         and decision['binding']['run'] == '43734696338' and decision['binding']['job'] == '132874611601'
         and decision['binding'] == reader['binding'] and reader['status'] == 'PASS_INDEPENDENT_RETAINED_OUTPUT_AND_PINNED_LIFECYCLE_DATA_ONLY'
         and reader['retention']['natural_owned_cleanup'] is True, 'separate accepted native installed lifecycle')
    need(resource['baseline_certificate'] == case['evidence']['baseline_certificate']
         and resource['package'] == ARCHIVE and 0 < resource['guest_output_cap_bytes'] <= 256 * 1024**2, 'finite case resource binding')
    return dict(case=case, cert=cert, base=base, runtime=rt, resource=resource, paths=paths)


def cleanup(report, phase, status):
    need(report['operation'] == OP and report['phase'] == phase and report['status'] == status
         and report.get('failure') is None and report.get('budget_failure') is None and report['cleanup_errors'] == []
         and report['cleanup_ownership_verified'] is True and report['owned_container_removed'] is True
         and report['owned_container_absence_verified'] is True and report['Root_acceptance'] is report['VM_acceptance'] is None
         and re.fullmatch('[0-9a-f]{64}', report['container_id']), 'successful owned controller retirement')


def custody(row, phase, status):
    need(row['status'] == 'PASS_OUTER_ONLY_NOT_RUNTIME_ACCEPTANCE' and row['phase'] == phase
         and row['producer_report_status'] == status and row['Root_acceptance'] is None
         and row['initial_same_FD_PIDFD_NB'] is row['final_same_FD_PIDFD_NB'] is True
         and row['owned_children_reaped'] is row['owned_container_absent'] is row['close_only'] is True
         and row['live_HOME_guard_pass'] is True and row['signals'] == [] and row['cleanup_errors'] == [], 'outer custody/cleanup joins')
    a, b = row['initial_lease'], row['final_lease']
    need(a['identity'] == b['identity'] and a['acquiring_pid'] == b['acquiring_pid']
         and a['owner_starttime'] == b['owner_starttime'] and a['proof'] == b['proof'], 'same lease inode/owner lifetime')
    for r in (a, b):
        need(r['same_FD'] is r['original_owner_pidfd_alive'] is r['real_independent_NB_conflict'] is True
             and r['release'] == 'CLOSE_ONLY' and r['identity']['nlink'] == 1
             and r['identity']['bytes'] == 0 and 'FLOCK' in r['fdinfo'] and 'WRITE' in r['fdinfo'], 'retained same-FD/PIDFD/real-NB evidence')
        need(r['proof']['inode'] == r['identity']['inode'] and r['proof']['owner'] == r['acquiring_pid']
             and type(r['acquiring_pid']) is int and r['acquiring_pid'] > 1 and r['owner_starttime'] > 0
             and r['identity']['mode'] == 0o644 and r['identity']['inode'] > 0, 'lease proof identity and live owner binding')
    r = row['producer_retirement']
    need(r['passed'] is r['reaped'] is r['group_absent'] is r['pid_reserved_until_retirement'] is True
         and r['exit'] == 0 and r['forced_retirement'] is r['timeout'] is False and r['error'] is None, 'outer natural producer retirement')


def lineage(ctx, packet, packet_pin, prepared, report, native, observation, outer, digest):
    need(prepared['status'] == 'PREPARED_NOT_BOOTED' and prepared['operation'] == OP
         and prepared['packet'] == packet_pin and prepared['nonce'] == packet['nonce']
         and prepared['baseline'] == ctx['base']['raw'] and prepared['VM'] is prepared['ALPM'] is prepared['Root_acceptance'] is None
         and re.fullmatch('[0-9a-f]{32}', prepared['baseline_nonce']), 'prepare packet/raw lineage')
    need(prepared['raw']['bytes'] == ctx['base']['raw']['bytes'] == ctx['resource']['prepared_raw_bytes']
         and 0 < prepared['raw']['bytes'] <= 3 * 1024**3
         and re.fullmatch('[0-9a-f]{64}', prepared['raw']['sha256']), 'recorded prepared raw geometry/hash; raw is never opened')
    need(native['issuer'] == 'Root' and native['accepted'] is True and native['archive'] == ARCHIVE
         and native['status'] == 'ACCEPTED_EXACT_PERL5423_NATIVE_ARM4K_BUILD_PAIR_ONLY'
         and native['page_bytes'] == 4096 and native['raw_bytes_identical'] is native['payload_identical'] is True
         and native['binding']['source'] == SOURCE['sha'] and native['binding']['run'] == NATIVE['run']
         and native['binding']['job'] == NATIVE['job'] and str(native['authenticated_original_artifact']) == NATIVE['artifact'], 'actual accepted native pair tuple')
    decision = ctx['cert']['installed_component_decision']
    need({k: decision['references']['accepted_native_pair'][k] for k in ('bytes', 'sha256')} == ctx['native_pair_pin'], 'installed decision references selected native pair')
    cleanup(report, 'prepare', 'PREPARED_NOT_BOOTED')
    custody(outer, 'prepare', 'PREPARED_NOT_BOOTED')
    rt, base = ctx['runtime'], ctx['base']
    need(observation['status'] == 'OBSERVED_READONLY_BASELINE_ABI_PROVIDERS_MATCH_EXPECTED_INPUTS_ONLY'
         and observation['baseline_certificate'] == ctx['case']['evidence']['baseline_certificate']
         and observation['raw'] == base['raw'] and observation['runtime_acceptance'] is False
         and observation['Root_runtime_certificate'] is observation['VM'] is observation['crypto_verification'] is None, 'actual readonly provider receipt remains bounded')
    rows = [r for r in rt['expected_payload']['rows'] if r['expected_package'] in base['inventory']]
    need(set(observation['files']) == {r['expected_path'] for r in rows}, 'complete pre-existing provider observations')
    for r in rows:
        actual = observation['files'][r['expected_path']]
        need(actual['bytes'] == r['expected_member_bytes'] and actual['sha256'] == r['expected_member_sha256']
             and actual['owner'] == r['expected_package'] and actual['version'] == base['inventory'][actual['owner']]
             and actual['mode'] == rt['baseline_files'][r['expected_path']]['mode']
             and actual['uid'] == actual['gid'] == 0, 'actual readonly provider byte/mode/owner/version join')
    aliases = {p: r for p, r in rt['expected_payload']['aliases'].items() if r['owner'] in base['inventory']}
    need(observation['aliases'] == aliases, 'actual readonly aliases match explicit projection')


def frame(raw, nonce, kind):
    text = raw.decode('utf-8').replace('\r\n', '\n')
    prefix = 'TCG_LOGIN_' if kind == 'LOGIN' else 'PERL5423_' + kind + '_'
    lines = text.split('\n');start, end = prefix + 'BEGIN ' + nonce, prefix + 'END ' + nonce
    need(lines.count(start) == lines.count(end) == 1, 'unique exact nonce frame')
    first, last = lines.index(start), lines.index(end)
    need(0 < last - first <= 65, 'ordered finite phase frame')
    fields = {}
    for line in lines[first + 1:last]:
        need('=' in line and len(line) <= 321, 'bounded phase scalar')
        k, v = line.split('=', 1)
        need(re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,63}', k) and k not in fields
             and re.fullmatch('[ -~]{1,256}', v), 'unique phase fields')
        fields[k] = v
    return fields


def elf(raw):
    need(len(raw) >= 64 and raw[:7] == b'\x7fELF\x02\x01\x01'
         and struct.unpack_from('<HHI', raw, 16) in ((2, 183, 1), (3, 183, 1)), 'linked little-endian AArch64 ELF64')
    off = struct.unpack_from('<Q', raw, 32)[0];width, count = struct.unpack_from('<HH', raw, 54)
    need(width == 56 and 0 < count <= 1024 and off + width * count <= len(raw), 'bounded program headers')
    ph = [struct.unpack_from('<IIQQQQQQ', raw, off + i * width) for i in range(count)]
    loads = [r for r in ph if r[0] == 1]
    need(loads and all(r[2] + r[5] <= len(raw) and r[5] <= r[6] and r[7] >= 16384
         and r[7] & (r[7] - 1) == 0 and r[2] % r[7] == r[3] % r[7] for r in loads), '16K PT_LOAD geometry')
    def address(a, size):
        candidates = [r[2] + a - r[3] for r in loads if r[3] <= a and a + size <= r[3] + r[5]]
        need(len(candidates) == 1, 'unique file-backed ELF address')
        return candidates[0]
    def cstring(offset, end):
        need(0 <= offset < end <= len(raw), 'bounded ELF string')
        stop = raw.find(b'\0', offset, min(end, offset + 4097))
        need(stop >= 0, 'terminated ELF string')
        return raw[offset:stop].decode('ascii')
    interpreters = [cstring(r[2], r[2] + r[5]) for r in ph if r[0] == 3]
    need(len(interpreters) <= 1, 'unique ELF interpreter')
    ds = [r for r in ph if r[0] == 2];need(len(ds) <= 1, 'unique PT_DYNAMIC')
    tags = {}
    if ds:
        d = ds[0];need(d[5] % 16 == 0 and d[2] + d[5] <= len(raw) and d[5] <= 65536, 'bounded dynamic table')
        terminated = False
        for i in range(d[2], d[2] + d[5], 16):
            tag, value = struct.unpack_from('<qQ', raw, i)
            if tag == 0:terminated = True;break
            tags.setdefault(tag, []).append(value)
        need(terminated, 'terminated dynamic table')
    def one(tag):
        need(len(tags.get(tag, [])) == 1, 'unique required dynamic tag')
        return tags[tag][0]
    needed, versions = [], {}
    if tags:
        length = one(10);strings = address(one(5), length)
        def string(n):
            return cstring(strings + n, strings + length)
        needed = [string(n) for n in tags.get(1, [])]
        need(len(needed) == len(set(needed)) <= 64, 'unique finite DT_NEEDED')
        if 0x6ffffffe in tags:
            n = one(0x6fffffff);need(0 < n <= 64, 'bounded GNU verneed count')
            current = one(0x6ffffffe);seen = set()
            for i in range(n):
                need(current not in seen, 'GNU verneed cycle');seen.add(current)
                version, count, filename, aux, following = struct.unpack_from('<HHIII', raw, address(current, 16))
                name = string(filename);need(version == 1 and 0 < count <= 256 and name not in versions and name in needed, 'GNU verneed library')
                values = [];at = current + aux;auxseen = set()
                for j in range(count):
                    need(at not in auxseen, 'GNU vernaux cycle');auxseen.add(at)
                    _, _, _, vn, nxt = struct.unpack_from('<IHHII', raw, address(at, 16));values.append(string(vn))
                    need((nxt == 0) == (j == count - 1), 'GNU vernaux termination');at += nxt
                need(len(values) == len(set(values)), 'GNU version uniqueness');versions[name] = sorted(values)
                need((following == 0) == (i == n - 1), 'GNU verneed termination');current += following
    return dict(machine=183, LOAD_segments=len(loads), minimum_alignment=min(r[7] for r in loads),
                interpreter=interpreters[0] if interpreters else None, needed=needed, version_needs=versions)


def natural(row):
    need(row['passed'] is row['reaped'] is row['output_complete'] is True and row['ownership'] == 'REAPED'
         and row['exit'] == 0 and row['group_census'] == 'EMPTY_TWICE' and row['signals'] == []
         and row['timeout'] is False and row['error'] is None
         and not any(row.get(n) for n in ('command_cancelled', 'command_timed_out', 'original_budget_overrun', 'emergency_retirement')), 'natural finite command retirement')


BOOT_REQUIRED = {'report.json', 'preservation.json', 'qemu.json', 'qemu-argv.json', 'host-epoch.json', 'serial.redacted.log', 'container.cid', 'retained-data-manifest.json'}


def boot_names(files):
    need(BOOT_REQUIRED <= set(files) and len(files) <= 128, 'complete selected boot metadata')
    for name in files:
        need(name in BOOT_REQUIRED or re.fullmatch(r'owned-docker-[0-9]{6}\.(json|stdout)', name)
             or re.fullmatch(r'results/([0-9]{1,3}\.elf|[a-z-]+\.log|outputs\.sha256|summary\.env|before-alpm-provider-observation\.tsv)', name), 'fixed boot DATA whitelist')


def export_receipt_names(runtime):
    # Independent literal supported-branch transcription of the reviewed
    # Source46 retention whitelist. No import or invocation of that Source.
    required = set('base.lock final.lock installed.lock dependencies.log install.log database-installed.log database-final.log added.paths exclusive.paths before-alpm-provider-observation.tsv pacman-log-before pacman-log-prefix pacman-log-after ownertrust import.log secret.log keys.log ownertrust.log signature.log gpg-stop.log sync.log summary.env remove.log'.split())
    required |= {stage + '.' + suffix for stage in ('before', 'after') for suffix in ('paths', 'meta', 'meta-equality', 'hash', 'db', 'db-normalized', 'xattr', 'dbmeta', 'dbxattr', 'cache')}
    required |= {stage + '.' + suffix for stage in ('user-before', 'user-current') for suffix in ('meta', 'hash', 'xattr')}
    required |= set('dependency-requires.log dependency-install.log dependencies.lock dependency-added.paths dependency-remove.log dependency-exclusive.paths official-public-observation.tsv official-ownertrust'.split())
    required |= {'official-' + n + '.log' for n in ('source-import', 'selected-export', 'import-stop', 'import', 'secret', 'keys', 'ownertrust', 'signature', 'stop')}
    if runtime['restoration_allowances']['pacman_log_before'] is None:
        required.add('pacman-log-before.absent')
    pairs = [{n + '.saved', n + '.absent'} for n in ('_etc_ld.so.cache', '_var_cache_ldconfig_aux-cache')]
    return required, pairs, {'ldconfig-directory.absent'}


def retained_manifest(ctx, packet, data, selection, parse, digest):
    raw = data['retained-data-manifest.json'];need(len(raw) <= 65536, 'retained manifest64KiB cap')
    value = parse(raw)
    need(set(value) == {'schema', 'nonce', 'case_packet', 'Source_lock', 'files'} and type(value['schema']) is int and value['schema'] == 1
         and value['nonce'] == packet['nonce'] and value['case_packet'] == ctx['packet_pin'] and value['Source_lock'] == ctx['source_pin'], 'retained manifest Source/case/nonce identity')
    required, pairs, optional = export_receipt_names(ctx['runtime'])
    result_names = {str(i) + '.elf' for i in range(54)} | set(LOGS) | {'outputs.sha256', 'summary.env', 'before-alpm-provider-observation.tsv'}
    groups = {'results': set(), 'receipts': set()};total = 0
    for name, row in value['files'].items():
        parts = name.split('/');need(len(parts) == 2 and parts[0] in groups and re.fullmatch('[A-Za-z0-9_.-]+', parts[1]), 'flat whitelisted manifest path')
        group, leaf = parts;groups[group].add(leaf)
        need(set(row) == {'bytes', 'sha256', 'mode'} and row['mode'] == 0o600
             and type(row['bytes']) is int and row['bytes'] >= 0 and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'exact retained byte/mode pin')
        cap = 16 * 1024**2
        if leaf == 'pacman-log-after':
            cap = min(24 * 1024**2, (ctx['runtime']['restoration_allowances']['pacman_log_before'] or {'bytes': 0})['bytes'] + ctx['resource']['log_bytes'])
        if leaf.endswith('.log'):cap = min(cap, ctx['resource']['log_bytes'])
        need(row['bytes'] <= cap and (not leaf.endswith('.absent') or row['bytes'] == 0), 'finite exported per-file/log/absence bounds')
        total += row['bytes']
        if group == 'results':
            need(name in data and name in selection and selection[name] == row
                 and digest(data[name]) == {n: row[n] for n in ('bytes', 'sha256')}, 'all retained result members join Source manifest and Root selection')
    need(groups['results'] == result_names and required <= groups['receipts'] <= required | optional | set().union(*pairs)
         and all(len(groups['receipts'] & pair) == 1 for pair in pairs)
         and all(len(names) <= 128 for names in groups.values()), 'complete Source46 export allowlist')
    need(total + 65536 <= min(ctx['resource']['guest_output_cap_bytes'], ctx['resource']['logs_cap_bytes']), 'whole results/receipts/manifest budget')
    reference = parse(data['preservation.json'])['retained_DATA']
    need(set(reference) == {'manifest', 'files', 'bytes', 'VM_acceptance', 'Root_acceptance'}
         and reference['manifest'] == digest(raw) and reference['files'] == len(value['files']) and reference['bytes'] == total
         and reference['VM_acceptance'] is reference['Root_acceptance'] is None, 'preservation binds whole retained manifest and totals')
    ctx['retained_manifest'] = value


def selected_receipts(ctx, rows, data, digest):
    for name, row in rows.items():
        need(ctx['retained_manifest']['files'].get('receipts/' + name) == row
             and digest(data[name]) == {k: row[k] for k in ('bytes', 'sha256')}, 'Root-selected preservation receipt joins complete export manifest')


def boot(ctx, packet, packet_files, prepared, data, outer, parse, digest):
    report = parse(data['report.json']);cleanup(report, 'boot', 'PASS_EMULATED_ARM16K_PERL5423_DATA_ONLY')
    custody(outer, 'boot', report['status'])
    auth = ctx['boot_authority']
    need(auth['kind'] == 'ROOT_PERL5423_VM_ACTOR_AUTHORITY_V1' and auth['issued_by'] == 'Root'
         and auth['accepted'] is True and auth['operation'] == OP and auth['phase'] == 'boot'
         and auth['packet'] == ctx['packet_pin'] and auth['source_lock'] == ctx['source_pin']
         and auth['prepared'] == ctx['prepared_pin'] and auth['output'] == ctx['boot_directory']
         and auth['docker_cli'] == report['docker_cli'], 'actual boot authority Source/packet/prepared/output/CLI joins')
    need(auth['image'] == 'sha256:52958d534193d739aeb6d3c9239ed31b97f8fb357a618e14391293068b28cd2a', 'actual Root-qualified Tool529 image')
    need(data['container.cid'].decode().strip() == report['container_id'] and report['normal_PAM_logout_observed'] is True
         and report['QMP_quit_requested'] is True, 'nonce journey and owned CID')
    serial = data['serial.redacted.log'];nonce = packet['nonce'];session = frame(serial, prepared['baseline_nonce'], 'LOGIN')
    required = dict(ARCH='aarch64', PAGESIZE='16384', UID='1000', USERNAME='builder', PID1='systemd', Name='builder', User='1000', Class='user', Type='tty', Service='login', Remote='no', LOGIND='active', DBUS='active')
    need(all(session.get(k) == v for k, v in required.items()) and session == report['session']
         and re.fullmatch('[A-Za-z0-9_-]{1,64}', session['Id']) and session['XDG_SESSION_ID'] == session['Id']
         and re.fullmatch('[1-9][0-9]{0,9}', session['Leader']) and session['State'] in ('active', 'online'), 'ordinary builder PAM/logind session')
    need(frame(serial, nonce, 'INSTALLED') == report['installed'] == INSTALLED
         and frame(serial, nonce, 'PROBE') == report['probe'] == PROBE, 'serial installed/ordinary functional phase')
    restored = frame(serial, nonce, 'RESTORED')
    need(restored == report['restored'] == frame(data['results/summary.env'], nonce, 'RESTORED')
         and set(restored) == set(RESTORED) | {'BASE_SHA256', 'FINAL_SHA256', 'FUNCTIONAL_SHA256', 'ELF_MANIFEST_SHA256', 'HOST_BOOT_UTC', 'GUEST_BEFORE_CRYPTO_UTC', 'RTC_BEFORE_CRYPTO_UTC'}
         and all(restored[k] == v for k, v in RESTORED.items()), 'exact restored serial/durable receipt')
    need(restored['BASE_SHA256'] == restored['FINAL_SHA256'] == digest(packet_files['expected-base.lock'])['sha256']
         and restored['ELF_MANIFEST_SHA256'] == digest(packet_files['elf-paths.tsv'])['sha256'], 'baseline/ELF manifest restored joins')
    epoch = parse(data['host-epoch.json']);host, guest, rtc = (int(restored[k]) for k in ('HOST_BOOT_UTC', 'GUEST_BEFORE_CRYPTO_UTC', 'RTC_BEFORE_CRYPTO_UTC'))
    need(epoch['nonce'] == nonce and epoch['utc_ns'] // 10**9 == host and host - 5 <= guest <= host + 485
         and abs(guest - rtc) <= 2 and ctx['case']['trust']['created_utc'] <= guest < ctx['case']['trust']['expires_utc'], 'advancing PL031/host/public TEST validity window')
    result_data = {n[8:]: raw for n, raw in data.items() if n.startswith('results/')}
    names = {str(i) + '.elf' for i in range(len(ctx['paths']))}
    need(set(result_data) == names | set(LOGS) | {'summary.env', 'outputs.sha256', 'before-alpm-provider-observation.tsv'}, 'complete flat durable result selection')
    need(result_data['functional.log'] == FUNCTIONAL and digest(FUNCTIONAL)['sha256'] == restored['FUNCTIONAL_SHA256']
         and result_data['version.log'] == b'v5.42.3\n' and result_data['paths.log'] == b'/usr/lib/perl5/5.42/core_perl/CORE/libperl.so\n', 'actual ordinary installed runtime outputs')
    for name, token in [('corelist.log', b'5.42.3'), ('perldoc.log', b'print'), ('podtext.log', b'candidate document'), ('podcheck.log', b'pod syntax OK'), ('prove.log', b'Result: PASS'), ('splain.log', b'undefined value')]:
        need(token in result_data[name], 'complete command-specific positive output')
    need(parse(result_data['json.log']) == {'answer': 42} and result_data['sha.log'] == b'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  digest-input\n', 'JSON and digest actual output')
    geometry = {}
    for i, path in enumerate(ctx['paths']):
        raw = result_data[str(i) + '.elf'];row = ctx['runtime']['files'][path];expected = ctx['runtime']['elfs'][path]
        need(digest(raw) == {n: row[n] for n in ('bytes', 'sha256')}, 'retained actual installed ELF whole bytes')
        observed = elf(raw)
        need(observed['interpreter'] == expected['interpreter'] and observed['needed'] == expected['needed']
             and observed['version_needs'] == {n: sorted(v) for n, v in expected['version_needs'].items()}, 'installed actual ELF DT_NEEDED/interpreter/GNU-version joins')
        geometry[path] = observed
    claimed = report['outputs']
    need(claimed['status'] == 'PASS_DURABLE_PERL5423_DATA_ONLY' and claimed['VM_acceptance'] is claimed['Root_acceptance'] is None
         and claimed['native_acceptance'] is False and claimed['files'] == {n: digest(raw) for n, raw in result_data.items()}
         and claimed['ELF16K'] == {p: {n: r[n] for n in ('machine', 'LOAD_segments', 'minimum_alignment')} for p, r in geometry.items()}, 'producer output claims join independently recomputed bytes/ELF geometry')
    ordered = sorted(names) + sorted(LOGS) + ['before-alpm-provider-observation.tsv']
    need(result_data['outputs.sha256'] == ''.join(digest(result_data[n])['sha256'] + '  ' + n + '\n' for n in ordered).encode(), 'whole durable output manifest')
    expected_pre = []
    for r in ctx['runtime']['expected_payload']['rows']:
        if r['expected_package'] in ctx['base']['inventory']:
            expected_pre.append('\t'.join((r['expected_path'], str(r['expected_member_bytes']), r['expected_member_sha256'], r['expected_package'], r['expected_package_version'])) + '\n')
    for p, r in sorted(ctx['runtime']['expected_payload']['aliases'].items()):
        if r['owner'] in ctx['base']['inventory']:
            expected_pre.append('\t'.join((p, r['target'], r['owner'], r['version'])) + '\n')
    need(result_data['before-alpm-provider-observation.tsv'] == ''.join(expected_pre).encode(), 'durable pre-ALPM actual providers/aliases')
    qemu = parse(data['qemu.json']);natural(qemu);argv = parse(data['qemu-argv.json'])['argv']
    need(qemu['argv'] == argv and argv == qemu_argv(prepared, ctx['resource'], host), 'exact software-only QEMU argv/retirement')
    preservation = parse(data['preservation.json'])
    need(report['preservation'] == preservation and preservation['status'] == 'PASS_COMPLETE_BASELINE_AND_USER_PRESERVATION'
         and preservation['packages'] == 111 and preservation['account_user_residuals'] == [], 'recorded host preservation summary')
    inspections = []
    for n, raw in data.items():
        if re.fullmatch(r'owned-docker-[0-9]{6}\.stdout', n):
            try:
                value = parse(raw)
            except (ValueError, UnicodeError):
                continue
            if type(value) is list and len(value) == 1 and type(value[0]) is dict and 'Id' in value[0]:
                inspections.append(value[0])
    stopped = [r for r in inspections if r['Id'] == report['container_id'] and r['State']['Running'] is False]
    need(stopped, 'retained stopped owned-container inspection')
    for row in stopped:
        h = row['HostConfig'];state = row['State'];labels = row['Config']['Labels']
        need(state['ExitCode'] == 0 and state['OOMKilled'] is False and row['Image'] == 'sha256:52958d534193d739aeb6d3c9239ed31b97f8fb357a618e14391293068b28cd2a'
             and labels['org.cachy-asahi.perl5423-nonce'] == nonce and row['Config']['Entrypoint'] == ['/usr/bin/python3']
             and labels['org.cachy-asahi.perl5423-owner'] == str(auth['uid'])
             and row['Config']['Cmd'] == ['-I', '-B', '/code/actor.py', 'boot']
             and h['ReadonlyRootfs'] is True and h['NetworkMode'] == 'none' and h['CapDrop'] == ['ALL'] and not h.get('CapAdd')
             and not h['Privileged'] and not h['Devices'] and h['Init'] is False and h['SecurityOpt'] == ['no-new-privileges']
             and h['Memory'] == h['MemorySwap'] == ctx['resource']['owner_memory_bytes']
             and h['NanoCpus'] == ctx['resource']['cpus'] * 10**9 and h['PidsLimit'] == ctx['resource']['pids'], 'finite cap0/NNP no-network container inspection')
        mounts = {(m['Destination'], m['Source'], m['RW']) for m in row['Mounts']}
        for target, source, writable in [('/code', ctx['source_directory'], False), ('/packet', ctx['packet_directory'], False),
                                         ('/prepared', ctx['prepared_directory'], False), ('/work', ctx['boot_directory'], True)]:
            need((target, source, writable) in mounts, 'exact readonly code/packet/prepared and owned output mounts')
        need(all(not rw or dst == '/work' for dst, _, rw in mounts)
             and labels['org.cachy-asahi.perl5423-authority'] == ctx['boot_authority_pin']['sha256'], 'only owned output writable and exact authority label')
    commands = []
    for n, raw in data.items():
        if re.fullmatch(r'owned-docker-[0-9]{6}\.stdout', n):
            receipt_name = n[:-6] + 'json'
            need(receipt_name in data, 'owned Docker stdout has command retirement')
            receipt = parse(data[receipt_name]);natural(receipt)
            commands.append((receipt['argv'], raw))
    need(any('container' in argv and 'ls' in argv and raw == b'' for argv, raw in commands), 'actual final empty owned-container listing')
    need(any('container' in argv and 'rm' in argv and report['container_id'] in argv for argv, _ in commands), 'actual owned CID removal command')
    return dict(actual_installed_ELF=geometry, retained_output_files=len(result_data),
                provider_evidence='EXPECTED81_PLUS_RECORDED_BASELINE_AND_PRE_ALPM_OBSERVATIONS; ONLY_PERL54_BINARY_BYTES_RETAINED',
                preservation_scope='HOST_SUMMARY_ONLY_UNTIL_SELECTED_RECEIPTS_JOIN')


def qemu_argv(prepared, resource, epoch):
    return ['/usr/bin/qemu-system-aarch64', '-machine', 'virt', '-accel', 'tcg,thread=multi', '-rtc', 'base=utc,clock=host', '-cpu', 'max',
            '-smp', str(resource['cpus']), '-m', str(resource['guest_memory_bytes'] // 1024**2), '-nodefaults', '-no-user-config', '-display', 'none', '-monitor', 'none', '-nic', 'none', '-no-reboot',
            '-kernel', '/kernel/Image', '-append', 'root=/dev/vda rootfstype=ext4 rw console=ttyAMA0,115200n8 rootwait init=/usr/lib/systemd/systemd systemd.unit=multi-user.target arm16k_systemd_nonce=' + prepared['baseline_nonce'] + ' arm16k_perl5423_vm_nonce=' + prepared['nonce'] + ' arm16k_rtc_host_epoch=' + str(epoch),
            '-drive', 'if=none,id=refdisk,file=/work/overlay.qcow2,format=qcow2', '-device', 'virtio-blk-device,drive=refdisk',
            '-serial', 'unix:/work/serial.sock,server=on,wait=off', '-qmp', 'unix:/work/qmp.sock,server=on,wait=off',
            '-sandbox', 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny']


RECEIPTS = {'base.lock', 'dependencies.lock', 'installed.lock', 'final.lock', 'install.log', 'dependency-install.log', 'remove.log', 'dependency-remove.log', 'pacman-log-before', 'pacman-log-after', 'before.cache', 'after.cache'}
RECEIPTS |= {stage + '.' + suffix for stage in ('before', 'after') for suffix in ('paths', 'meta', 'meta-equality', 'hash', 'db', 'db-normalized', 'xattr', 'dbmeta', 'dbxattr')}
RECEIPTS |= {stage + '.' + suffix for stage in ('user-before', 'user-current') for suffix in ('meta', 'hash', 'xattr')}


def receipt_names(files):
    need(set(files) == RECEIPTS, 'exact bounded selected normal-ALPM preservation receipts')


def metadata_view(raw):
    fields = raw.split(b'\0');need(fields[-1] == b'' and (len(fields) - 1) % 6 == 0, 'complete metadata tuples')
    result = [];seen = set();proc = 0
    for i in range(0, len(fields) - 1, 6):
        name, mode, uid, gid, links, quoted = fields[i:i + 6]
        need(name not in seen and re.fullmatch(b'[0-9a-fA-F]+', mode) and uid.isdigit() and gid.isdigit() and links.isdigit(), 'unique typed metadata tuple');seen.add(name)
        if name == b'/proc/':
            proc += 1;links = b'VOLATILE_LIVE_PROCFS_NLINK'
        result.extend((name, mode, uid, gid, links, quoted))
    need(proc == 1, 'one explicit volatile procfs link count')
    return b'\0'.join(result) + b'\0'


def restoration(ctx, packet, receipts, preservation, digest):
    receipt_names(receipts)
    for actual, expected in [('base.lock', 'expected-base.lock'), ('dependencies.lock', 'expected-dependencies.lock'), ('installed.lock', 'expected-installed.lock'), ('final.lock', 'expected-base.lock')]:
        need(receipts[actual] == packet[expected], 'actual111 to112 to113 to111 ALPM inventories')
    for suffix in ('paths', 'hash', 'db', 'db-normalized', 'xattr', 'dbmeta', 'dbxattr', 'cache'):
        need(receipts['before.' + suffix] == receipts['after.' + suffix], 'complete baseline payload/database/cache receipt equality')
    need(receipts['before.db'] == receipts['before.db-normalized'], 'Perl-absent baseline admits no database normalization')
    for stage in ('before', 'after'):
        need(metadata_view(receipts[stage + '.meta']) == receipts[stage + '.meta-equality'], 'independent narrow procfs link-count normalization')
    need(receipts['before.meta-equality'] == receipts['after.meta-equality'], 'complete owned metadata equality')
    for suffix in ('meta', 'hash', 'xattr'):
        need(receipts['user-before.' + suffix] == receipts['user-current.' + suffix], 'complete private-user receipt equality')
    before, after = receipts['pacman-log-before'], receipts['pacman-log-after']
    pin = ctx['runtime']['restoration_allowances']['pacman_log_before']
    need((not before if pin is None else digest(before) == pin) and after.startswith(before) and len(after) > len(before), 'exact original log prefix plus normal appended transactions')
    added = after[len(before):].decode('utf-8')
    transactions = re.findall(r'\[ALPM\] (installed|removed) (perl|db5\.3) \(([^)]+)\)', added)
    need(transactions == [('installed', 'db5.3', '5.3.28-7'), ('installed', 'perl', VERSION), ('removed', 'perl', VERSION), ('removed', 'db5.3', '5.3.28-7')], 'normal exact dependency/install/remove ALPM transaction order')
    need(len(re.findall(r'\[ALPM\] (?:installed|removed|upgraded|downgraded|reinstalled) ', added)) == 4, 'no silently expanded ALPM package mutations')
    for name, token in [('install.log', b'perl'), ('dependency-install.log', b'db5.3'), ('remove.log', b'perl'), ('dependency-remove.log', b'db5.3')]:
        need(token in receipts[name] and b'error:' not in receipts[name].lower(), 'normal command receipts without suppressed failure')
    need(preservation['normal_install_date'] is None and preservation['pacman_log'] == ('ABSENCE_RESTORED_WITH_RETAINED_NORMAL_TRANSACTION_LOG' if pin is None else 'ORIGINAL_BYTES_PLUS_APPEND_ONLY'), 'only certified normal transaction variance')
    return dict(status='PASS_SELECTED_NORMAL_ALPM_PRESERVATION_RECEIPT_JOINS_ONLY', inventory_counts=[111, 112, 113, 111],
                full_raw_requalification=False, receipt_bodies_disclosed=False, user_account_residuals=[],
                filesystem_observation_boundary='PINNED_PRODUCER_READBACK_AND_ROOT_SELECTED_RECEIPTS; NO_RAW_OR_QCOW_READ')

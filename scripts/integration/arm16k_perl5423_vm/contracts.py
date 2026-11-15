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
OP = 'arm16k-perl5423-system-runtime-v1'
PREFIX = '/usr'
SOURCE = dict(sha='25dc3e65bdb6137c87a9409067fe9b2cf6e9763f',
              ref='refs/heads/codex/native-arm-perl5423-v2-20261115',
              map_sha256='4b1de3aade5116206318570d1d44ee1063342faeab54935748b1b7c179a99e96')
NATIVE_ARCHIVE = dict(bytes=22071176, sha256='647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22')
INSTALLED_SOURCE = '445b37a9475a4e92804954f4f0e3d0ac84cd9511'
PACKAGE = dict(name='perl', version='5.42.3-1.3', arch='aarch64',
               depends=['glibc', 'gdbm>=1.17', 'db5.3', 'libxcrypt', 'libcrypt.so', 'bzip2', 'zlib'])
DB53 = dict(name='db5.3',version='5.3.28-7',archive=dict(bytes=1044852,sha256='0a787f952c0f7dd1493db437ab0dc3ffda6053cb6affa4ebf91caff185e586b4'),signature=dict(bytes=566,sha256='e17a6fdad268459de144b828f33a8b63fd9b7f05a2c1ea2c1dc02b4670b8bdab'))
HARDLINKS = {'/usr/bin/core_perl/perlthanks':'/usr/bin/core_perl/perlbug', '/usr/share/man/man1/perlthanks.1perl.gz':'/usr/share/man/man1/perlbug.1perl.gz'}
ALPM_DEPENDS = ['glibc','gdbm>=1.17','db5.3','libxcrypt','libcrypt.so=2-64','bzip2','zlib']
MATERIALS = ('archive', 'signature', 'public_TEST_certificate', 'signing_receipt')
EVIDENCE = ('baseline_certificate', 'runtime_certificate', 'resource_certificate', 'Root_decision', 'installed_Reader', 'installed_component_decision')
TOOLS = tuple('base64 bash cat chmod chown cmp comm cp cut date env find getconf getfattr gpg gpgconf grep head id install mkdir pacman readlink rm rmdir sed sha256sum sleep sort stat sync timeout touch tr uname wc xargs'.split())
COMMANDS = tuple('corelist json_pp perldoc pod2text podchecker prove shasum splain'.split())
PERL_ELFS = ('/usr/bin/perl', '/usr/lib/perl5/5.42/core_perl/CORE/libperl.so',
 '/usr/lib/perl5/5.42/core_perl/auto/DB_File/DB_File.so',
 '/usr/lib/perl5/5.42/core_perl/auto/GDBM_File/GDBM_File.so',
 '/usr/lib/perl5/5.42/core_perl/auto/Compress/Raw/Zlib/Zlib.so',
 '/usr/lib/perl5/5.42/core_perl/auto/Compress/Raw/Bzip2/Bzip2.so',
 '/usr/lib/perl5/5.42/core_perl/auto/threads/threads.so')
LIMITS = tuple(('package_expanded_bytes case_staging_bytes fixture_source_bytes baseline_raw_bytes baseline_allocated_bytes prepared_raw_bytes '
 'guest_filesystem_free_bytes guest_output_cap_bytes clone_allocated_cap_bytes overlay_cap_bytes readback_allocated_cap_bytes logs_cap_bytes '
 'reserve_bytes physical_free_bytes quota_initial_headroom_bytes quota_live_reserve_bytes guest_memory_bytes owner_memory_bytes '
 'host_reserve_bytes host_MemAvailable_bytes cpus pids prepare_seconds boot_seconds cleanup_seconds boot_overhead_seconds '
 'output_device host_uid gpg_seconds install_seconds probe_wait_seconds remove_seconds run_seconds sync_seconds log_bytes').split())


def need(ok, why):
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


def pin(path, cap=4*1024**3):
    p = ordinary(path)
    with os.fdopen(os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), 'rb') as stream:
        a = os.fstat(stream.fileno())
        need(stat.S_ISREG(a.st_mode) and a.st_nlink == 1 and 0 <= a.st_size <= cap, 'bounded single-link DATA')
        h = hashlib.sha256()
        total = 0
        while block := stream.read(65536):
            need(END is None or time.monotonic() < END, 'finite DATA hashing deadline')
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
        need(path.startswith('/usr/') or path == '/etc/profile.d/perlbin.sh', 'reviewed candidate/baseline alias domain')
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


def namespace(ns, baseline=False):
    need(type(ns) is dict and ns, 'complete package namespace required')
    expanded = 0
    for path, row in ns.items():
        guest_path(path); need(type(row) is dict and row.get('kind') in ('f', 'd', 'l'), 'candidate inode kind')
        kind = row['kind']
        keys(row, {'kind', 'mode', 'uid', 'gid'} | ({'bytes', 'sha256'} if kind == 'f' else {'link_target'} if kind == 'l' else set()), 'inode')
        need(type(row['mode']) is int and 0 <= row['mode'] <= 0o7777 and not row['mode'] & 0o6000 and
             (kind == 'l' or not row['mode'] & 0o002) and type(row['uid']) is type(row['gid']) is int and row['uid'] == row['gid'] == 0, 'safe root-owned inode')
        need((path.startswith('/usr/') or path == '/usr' and kind == 'd' or baseline and (path in ('/etc','/etc/profile.d') and kind == 'd' or path == '/etc/profile.d/perlbin.sh' and kind == 'f')) and not path.startswith('/usr/local/') and '/..' not in path, 'system Perl payload confined to /usr excluding site modules')
        if kind == 'f':
            need(type(row['bytes']) is int and 0 <= row['bytes'] < 2**63 and sha(row['sha256']), 'file pin'); expanded += row['bytes']
        elif kind == 'l':
            target = row['link_target']; need(type(target) is str and re.fullmatch('[A-Za-z0-9._+/-]+', target) is not None, 'literal contained alias')
            candidate_target(ns, path)
    return expanded


def runtime(value, case, base):
    expected_kind = 'ROOT_REVIEWED_PERL5423_VM_EXPECTED_PAYLOAD_INPUTS_V1'
    expected_input = type(value) is dict and value.get('kind') == expected_kind
    root_cert(value, expected_kind if expected_input else 'ROOT_REVIEWED_PERL5423_VM_RUNTIME_V1')
    keys(value, ('kind', 'issued_by', 'accepted', 'baseline_certificate', 'package', 'namespace_coverage', 'candidate_namespace',
                 'baseline_namespace', 'baseline_files', 'hardlinks', 'dependency_transaction', 'elf_inventory', 'full_payload_elf_coverage', 'elfs', 'files', 'tools', 'loader',
                 'alpm_dependencies', 'PKGINFO', 'effective_hook_policy', 'dependency_resolution', 'reverse_dependencies', 'rollback', 'probe_qualification', 'baseline_namespace_pin', 'restoration_allowances') + (('expected_payload','actual_guest_hashes','actual_guest_ALPM_ownership','actual_guest_namespace','Root_runtime_certificate','runtime_acceptance') if expected_input else ()), 'runtime input certificate')
    if expected_input:
        need(all(value[n] is None for n in ('actual_guest_hashes','actual_guest_ALPM_ownership','actual_guest_namespace','Root_runtime_certificate')) and value['runtime_acceptance'] is False, 'expected payload inputs never claim installed guest or runtime acceptance')
        import importlib.util
        spec=importlib.util.spec_from_file_location('perl_expected_inputs',HERE/'expected_payload.py');E=importlib.util.module_from_spec(spec);spec.loader.exec_module(E);E.join_runtime(value['expected_payload'],value,base)
    need(value['baseline_certificate'] == case['evidence']['baseline_certificate'] and value['package'] == case['package']['archive'], 'exact runtime joins')
    pin_shape(value['baseline_namespace_pin']); pin_shape(value['elf_inventory'])
    need(value['full_payload_elf_coverage'] is True and value['namespace_coverage'] == 'ALL_PACKAGE_OWNED_PATHS', 'full ELF/ownership coverage')
    expanded = namespace(value['candidate_namespace'])
    need(value['hardlinks'] == HARDLINKS, 'two actual accepted archive hardlink associations')
    for path, target in value['hardlinks'].items():
        a,b = value['candidate_namespace'].get(path,{}),value['candidate_namespace'].get(target,{})
        need(a.get('kind') == b.get('kind') == 'f' and a == b, 'hardlinks join equal regular target bytes/mode/ownership')
    dep = value['dependency_transaction']; added = {}
    need(type(dep) is dict, 'explicit dependency transaction map; no silent packages')
    if dep:
        keys(dep, ('name','version','archive','signature','namespace','files','elf_paths','full_ELF_coverage','requires','resolution','baseline_public_trust','signature_authenticated','current_trust_reviewed','recovery'), 'explicit db5.3 addition')
        need(all(dep[n] == DB53[n] for n in DB53) and 'db5.3' not in base and dep['requires'] == ['libgcc','libstdc++','sh'] and dep['recovery'] == 'NORMAL_REMOVE_AFTER_PERL_RECOVERY' and dep['signature_authenticated'] is dep['current_trust_reviewed'] is dep['full_ELF_coverage'] is True, 'only exact separately admitted cached official db5.3 addition')
        pin_shape(dep['baseline_public_trust']); expanded += namespace(dep['namespace']); added['db5.3'] = dep['version']
        need(type(dep['files']) is dict and dep['files'] and type(dep['elf_paths']) is list and dep['elf_paths'] and set(dep['resolution']) == set(dep['requires']), 'complete dependency namespace, ELF and ALPM provider inputs')
        for constraint,row in dep['resolution'].items():
            keys(row, ('owner','version','satisfied','providers'), 'db5.3 dependency provider')
            need(base.get(row['owner']) == row['version'] and row['satisfied'] is True and type(row['providers']) is list and row['providers'] and all(p in value['baseline_files'] and value['baseline_files'][p]['owner'] == row['owner'] for p in row['providers']), 'db5.3 own dependencies resolve in unchanged actual baseline')
        for path,row in dep['files'].items():
            need(path in value['files'] and row == value['files'][path] and row['owner'] == 'db5.3' and row['version'] == dep['version'], 'exact actual added dependency file closure')
        for path in dep['elf_paths']: need(path in dep['files'] and path in value['elfs'], 'complete dependency-owned ELF inventory')
    dependency_base = dict(base, **added)

    before = value['baseline_namespace']; need(type(before) is dict, 'actual complete baseline Perl namespace or empty map')
    if before: namespace(before, baseline=True)
    need(bool(before) == ('perl' in base), 'baseline presence cannot be assumed')
    for label, files, owners in [('baseline', value['baseline_files'], base), ('candidate', value['files'], dict(dependency_base, perl=PACKAGE['version']))]:
        need(type(files) is dict and files, 'complete ' + label + ' runtime file closure')
        for path, row in files.items():
            guest_path(path); keys(row, ('bytes', 'sha256', 'mode', 'owner', 'version', 'resolved'), label + ' runtime inode')
            guest_path(row['resolved']); need(type(row['bytes']) is int and row['bytes'] >= 0 and sha(row['sha256']) and
                type(row['mode']) is int and 0 <= row['mode'] <= 0o7777 and not row['mode'] & 0o6002 and owners.get(row['owner']) == row['version'], 'file bytes/mode/ALPM owner version')
            if row['owner'] == 'db5.3' and dep and label == 'candidate':
                actual = dep['namespace'].get(row['resolved'],{})
                need(actual.get('kind') == 'f' and all(row[n] == actual[n] for n in ('bytes','sha256','mode')), 'actual added dependency file namespace')
            if row['owner'] == 'perl':
                ns = before if label == 'baseline' else value['candidate_namespace']
                resolved = candidate_target(ns, path); actual = ns[resolved]
                need(row['resolved'] == resolved and actual['kind'] == 'f' and all(row[n] == actual[n] for n in ('bytes', 'sha256', 'mode')), 'Perl file must join exact namespace')
    need(value['tools'] == ['/usr/bin/' + n for n in TOOLS], 'exact runtime helper vectors')
    for path in value['tools']:
        need(path in value['baseline_files'] and path in value['files'] and value['baseline_files'][path] == value['files'][path] and value['files'][path]['mode'] & 0o005 == 0o005, 'preserved executable baseline helper')
    need(value['PKGINFO'] == dict(bytes=4483,sha256='31461fa035ad9f3761775dc412f3966c1c451c817e51eb5a2412808027133edc'), 'actual accepted package metadata bytes')
    requires = value['alpm_dependencies']
    need(requires == ALPM_DEPENDS, 'exact actual accepted1.3 PKGINFO constraints')
    need(type(requires) is list and len(requires) == len(set(requires)) and all(type(n) is str and re.fullmatch('[A-Za-z0-9@+_.<>=:-]+', n) for n in requires), 'complete actual PKGINFO dependency literals')
    need(set(PACKAGE['depends']) - {'libcrypt.so'} <= set(requires) and any(re.fullmatch(r'libcrypt[.]so=[0-9]+-64', n) for n in requires), 'actual makepkg-expanded64-bit libcrypt SONAME and all recipe constraints')
    hooks = value['effective_hook_policy']
    keys(hooks, ('baseline_configuration', 'transaction_same_effective_policy', 'hook_directories', 'namespace_pin', 'scriptlets_enabled', 'suppression_added'), 'complete effective ALPM hook policy')
    need(hooks['baseline_configuration'] == '/etc/pacman.conf' and hooks['baseline_configuration'] in value['baseline_files'] and
         hooks['transaction_same_effective_policy'] is hooks['scriptlets_enabled'] is True and hooks['suppression_added'] is False and
         hooks['hook_directories'] == ['/usr/share/libalpm/hooks', '/etc/pacman.d/hooks'], 'independently reviewed unchanged default effective hooks; alternate baseline HookDir needs a new reviewed case')
    pin_shape(hooks['namespace_pin'])
    deps = value['dependency_resolution']; need(type(deps) is dict and set(deps) == set(requires), 'every actual ALPM constraint including expanded SONAME')
    for constraint, row in deps.items():
        keys(row, ('owner', 'version', 'satisfied', 'providers'), 'ALPM dependency resolution')
        need(dependency_base.get(row['owner']) == row['version'] and row['satisfied'] is True and type(row['providers']) is list and row['providers'], 'actual baseline plus explicit admitted dependency satisfies candidate')
        need(all(path in value['files'] and value['files'][path]['owner'] == row['owner'] for path in row['providers']), 'dependency bytes and actual owner')
    need(type(value['reverse_dependencies']) is list and all(n in base and n != 'perl' for n in value['reverse_dependencies']), 'actual reverse dependency census')
    rollback = value['rollback']
    keys(rollback, ('mode', 'version', 'archive', 'signature', 'reason', 'exact_payload_verified', 'local_database_policy'), 'recovery branch')
    if 'perl' in base:
        need(rollback['mode'] == 'SIGNED_EXACT_OLD_PACKAGE' and rollback['version'] == base['perl'] and
             rollback['reason'] in ('explicit', 'dependency') and rollback['exact_payload_verified'] is True and
             rollback['local_database_policy'] == 'NORMAL_INSTALLDATE_AND_TRANSACTION_TIMESTAMPS', 'reviewed old package rollback; DB differences cannot be relabeled preserved')
        pin_shape(rollback['archive']); pin_shape(rollback['signature'])
    else:
        need(rollback == dict(mode='REMOVE', version=None, archive=None, signature=None, reason=None, exact_payload_verified=True, local_database_policy='EXACT') and not value['reverse_dependencies'], 'normal removable package with no baseline Perl dependents')
    allowance = value['restoration_allowances']
    old = '/var/lib/pacman/local/perl-' + base['perl'] if 'perl' in base else None
    expected = dict(install_date_path=old+'/desc' if old else None, database_timestamp_paths=['/var/lib/pacman/local']+([old,old+'/desc',old+'/files'] if old else []),
                    payload_directory_timestamps=True, normal_pacman_log='/var/log/pacman.log', pacman_log_before=allowance.get('pacman_log_before'), cache_directory_timestamps=['/var/cache','/var/cache/ldconfig'])
    if allowance.get('pacman_log_before') is not None: pin_shape(allowance['pacman_log_before'])
    need(allowance == expected, 'exact certificate-described normal transaction variance; no unrelated file/database/user waiver')
    qualification = value['probe_qualification']
    path_evidence = 'expected_paths_source_verified' if expected_input else 'actual_paths_verified'
    keys(qualification, ('commands', 'modules', 'network', 'CPAN', 'compiler', path_evidence), 'exact probe input qualification')
    need(qualification == dict(commands=['/usr/bin/' + n for n in COMMANDS], modules=['Config', 'JSON::PP', 'Digest::SHA', 'DB_File', 'GDBM_File', 'Compress::Raw::Zlib', 'Compress::Raw::Bzip2', 'threads'],
         network=False, CPAN=False, compiler=False, **{path_evidence: True}), 'runtime probes require no CPAN or development assumptions')
    for path in ['/usr/bin/perl'] + qualification['commands']:
        need(path in value['files'] and value['files'][path]['owner'] == 'perl' and value['files'][path]['mode'] & 0o005 == 0o005, 'qualified package-owned runtime command')
    files = value['files']; need(value['loader'] in files, 'exact actual ELF loader')
    elfs = value['elfs']; need(type(elfs) is dict and set(PERL_ELFS) <= set(elfs), 'interpreter, shared libperl and all required real XS extensions')
    for path, elf in elfs.items():
        need(path in files and files[path]['sha256'] == elf.get('sha256') and files[path]['mode'] & 0o004, 'ELF joins ordinary-user readable file input closure')
        keys(elf, ('sha256', 'class', 'byte_order', 'machine', 'interpreter', 'needed', 'version_needs', 'providers', 'static_16k_geometry'), 'ELF facts')
        need(elf['class'] == 64 and elf['byte_order'] == 'little' and elf['machine'] == 183 and elf['static_16k_geometry'] is True and
             (elf['interpreter'] is None or elf['interpreter'] == value['loader']), 'actual ARM16K ELF facts')
        need(type(elf['needed']) is list and set(elf['providers']) == set(elf['needed']) and set(elf['version_needs']) <= set(elf['needed']), 'complete actual ELF provider closure')
        for soname, provider in elf['providers'].items():
            keys(provider, ('path', 'version_definitions'), 'ELF provider')
            need(provider['path'] in files and provider['path'] in elfs and type(provider['version_definitions']) is list and
                 set(elf['version_needs'].get(soname, [])) <= set(provider['version_definitions']), 'recursive provider ELF and GNU version closure')
    required = {PERL_ELFS[0]: 'libperl.so', PERL_ELFS[2]: 'libdb-5.3.so', PERL_ELFS[3]: 'libgdbm.so.6', PERL_ELFS[4]: 'libz.so.1', PERL_ELFS[5]: 'libbz2.so.1.0'}
    for path, soname in required.items(): need(soname in elfs[path]['needed'], 'actual requested shared-library composition: ' + path)
    return expanded


def resources(value, case, base, expanded, rollback, dependency):
    root_cert(value, 'ROOT_REVIEWED_PERL5423_VM_RESOURCES_V1')
    keys(value, {'kind', 'issued_by', 'accepted', 'baseline_certificate', 'package', 'quota_guard'} | set(LIMITS), 'resource certificate')
    need(value['baseline_certificate'] == case['evidence']['baseline_certificate'] and value['package'] == case['package']['archive'], 'resource baseline/candidate joins')
    home = type(value['quota_guard']) is dict and value['quota_guard'].get('method') == 'READ_ONLY_HOME_BTRFS_ENOSYS_FSTATVFS'
    quota_fields = ('quota_initial_headroom_bytes','quota_live_reserve_bytes')
    need(all(positive(value[n]) for n in LIMITS if not home or n not in quota_fields), 'all physical/resource/guest-phase numbers explicit positive integers')
    if home: need(all(value[n] is None for n in quota_fields), 'unsupported HOME quota never supplies headroom')
    need(all(value[n] <= 999999999 for n in ('gpg_seconds', 'install_seconds', 'probe_wait_seconds', 'remove_seconds',
         'run_seconds', 'sync_seconds', 'guest_output_cap_bytes')) and 1024 <= value['log_bytes'] <= 16777216,
         'exact guest case.env scalar grammar')
    need(value['baseline_raw_bytes'] == base['raw']['bytes'] and value['package_expanded_bytes'] == expanded and value['prepared_raw_bytes'] >= value['baseline_raw_bytes'], 'actual candidate-expanded/raw geometry')
    need(value['case_staging_bytes'] >= sum(case['package'][n]['bytes'] for n in MATERIALS) + sum(rollback[n]['bytes'] for n in ('archive','signature') if rollback[n] is not None) + sum(dependency[n]['bytes'] for n in ('archive','signature') if dependency) + value['fixture_source_bytes'], 'staging includes compressed archive/signature/certificate/receipt and reviewed fixture Source')
    writes = value['baseline_allocated_bytes'] + value['case_staging_bytes'] + expanded + value['guest_output_cap_bytes']
    need(value['clone_allocated_cap_bytes'] >= writes and value['readback_allocated_cap_bytes'] >= writes and
         value['guest_filesystem_free_bytes'] >= value['case_staging_bytes'] + expanded + value['guest_output_cap_bytes'] and value['prepared_raw_bytes'] >= writes, 'clone/readback/raw/guest capacity includes staged and expanded candidate and output')
    peak = sum(value[n] for n in ('clone_allocated_cap_bytes', 'overlay_cap_bytes', 'readback_allocated_cap_bytes', 'logs_cap_bytes', 'reserve_bytes'))
    need(value['physical_free_bytes'] >= peak, 'simultaneous physical clone+overlay+readback+logs+reserve')
    if not home: need(value['quota_initial_headroom_bytes'] >= peak and value['quota_live_reserve_bytes'] >= value['reserve_bytes'], 'simultaneous own-UID quota clone+overlay+readback+logs+reserve')
    need(value['owner_memory_bytes'] >= value['guest_memory_bytes'] and value['host_MemAvailable_bytes'] >= value['owner_memory_bytes'] + value['host_reserve_bytes'], 'actual host RAM reserve')
    # Twelve fixed runtime operations and sync; no compiler or XS build. Root's
    # wait encloses these calls, so the outer envelope counts that wait once.
    probe = 12*value['run_seconds'] + value['sync_seconds']
    need(value['probe_wait_seconds'] >= probe, 'probe wait covers twelve runtime commands and sync')
    # Root: five gpg calls plus gpgconf retirement; two database checks and two
    # durable syncs. Root separately supplies nondefault boot/PAM/snapshot overhead.
    phase = (7*value['gpg_seconds'] + 2*value['install_seconds'] + value['probe_wait_seconds'] + 2*value['remove_seconds'] +
             6*value['run_seconds'] + 2*value['sync_seconds'] + value['cleanup_seconds'] + value['boot_overhead_seconds'])
    need(value['boot_seconds'] >= phase and value['prepare_seconds'] > value['cleanup_seconds'] and value['logs_cap_bytes'] >= value['log_bytes'], 'finite guest/cleanup/log envelopes')
    need(value['prepared_raw_bytes'] == value['baseline_raw_bytes'] <= 4*1024**3 and value['overlay_cap_bytes'] <= 4*1024**3 and value['guest_memory_bytes'] % 1024**2 == 0 and value['cpus'] <= 64 and value['pids'] <= 4096, 'supported fixed raw/overlay/guest geometry and finite actor controls')
    need(value['cleanup_seconds'] >= 45 and all(value[n] >= 5 for n in ('gpg_seconds','install_seconds','remove_seconds','run_seconds','sync_seconds')), 'frozen owned cleanup and command retirement minimum envelopes')
    q = value['quota_guard']
    if home:
        import importlib.util
        spec=importlib.util.spec_from_file_location('perl_resource_home',HERE/'home_btrfs.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        m.profile(q,value,now=int(time.time()))
    else:
        keys(q, ('issued_by', 'method', 'whole_actor', 'read_only', 'uid', 'device', 'initial_headroom_bytes', 'live_reserve_bytes', 'on_unknown_or_exhausted'), 'quota guard')
        need(q == dict(issued_by='Root', method='READ_ONLY_Q_GETQUOTA', whole_actor=True, read_only=True, uid=value['host_uid'], device=value['output_device'], initial_headroom_bytes=value['quota_initial_headroom_bytes'], live_reserve_bytes=value['quota_live_reserve_bytes'], on_unknown_or_exhausted='HOLD_AND_OWNED_CLEANUP'), 'actual readonly own-UID whole-actor quota guard')


def validate(case, observed_materials, baseline_certificate, runtime_certificate, resource_certificate, Root_decision, installed_Reader, installed_component_decision):
    keys(case, ('schema', 'operation', 'source', 'package', 'native', 'evidence', 'trust'), 'case')
    need(type(case['schema']) is int and case['schema'] == 1 and case['operation'] == OP and case['source'] == SOURCE, 'exact published Perl5423 Source/case identity')
    keys(case['package'], set(PACKAGE) | set(MATERIALS), 'package')
    need(all(case['package'][n] == v for n, v in PACKAGE.items()), 'fixed system Perl identity/dependencies')
    keys(case['native'], ('run', 'job', 'artifact'), 'native tuple')
    need(case['native'] == dict(run='43692477455',job='132745843566',artifact='14153417247'), 'exact Root-retained accepted native pair tuple')
    keys(case['evidence'], EVIDENCE, 'case evidence'); keys(observed_materials, MATERIALS + EVIDENCE, 'observed materials')
    certificates = dict(zip(EVIDENCE, (baseline_certificate, runtime_certificate, resource_certificate, Root_decision, installed_Reader, installed_component_decision)))
    for name in MATERIALS + EVIDENCE:
        expected = case['package'][name] if name in MATERIALS else case['evidence'][name]
        pin_shape(expected); need(pin_shape(observed_materials[name]) == expected, 'actual material pin join: ' + name)
        if name in certificates: need(type(certificates[name]) is dict and json_pin(certificates[name]) == expected, 'canonical actual certificate byte join: ' + name)
    need(case['package']['archive'] == NATIVE_ARCHIVE, 'exact accepted native archive bytes; older1.2 is not the accepted pair')
    trust = case['trust']; keys(trust, ('fingerprint', 'created_utc', 'expires_utc', 'evaluated_utc', 'public_only', 'signature_valid', 'revoked'), 'trust')
    need(type(trust['fingerprint']) is str and re.fullmatch('[A-F0-9]{40}', trust['fingerprint']) and
         all(type(trust[n]) is int and 100000000 <= trust[n] <= 999999999999 for n in ('created_utc', 'expires_utc', 'evaluated_utc')),
         'actual public TEST signer identity and guest 9-to12-digit epochs')
    now = int(time.time()); need(trust['created_utc'] <= trust['evaluated_utc'] < trust['expires_utc'] and trust['created_utc'] <= now < trust['expires_utc'] and 0 <= now-trust['evaluated_utc'] <= 3600 and trust['public_only'] is trust['signature_valid'] is True and trust['revoked'] is False, 'fresh nonrevoked public-only authenticated TEST signature')
    report = installed_Reader
    need(json_pin(report) == dict(bytes=3797,sha256='96138206dedec2d49f16475ba7daa5200ff8ab401ccb720f764685e63853d205'), 'actual retained installed Reader2 bytes')
    need(report.get('status') == 'PASS_INDEPENDENT_RETAINED_OUTPUT_AND_PINNED_LIFECYCLE_DATA_ONLY' and report.get('acceptance') is False and
         report.get('Root_authentication') is False and report.get('Root_decision') is None, 'finite passive installed Reader2 scope')
    installed = installed_component_decision
    need(json_pin(installed) == dict(bytes=6168,sha256='084794319bf849ed1cc2a2387f502acf8cc82dec3fad11b00e3dc8cfc4096535'), 'actual Root accepted installed ARM4K component decision bytes')
    need(installed.get('issuer') == 'Root' and installed.get('accepted') is True and installed.get('archive') == NATIVE_ARCHIVE and
         installed.get('candidate_version') == PACKAGE['version'] and installed.get('page_bytes') == 4096 and installed.get('full_uninstall') == 'NOT_RUN' and
         installed.get('binding') == report.get('binding') and installed['binding']['source'] == INSTALLED_SOURCE and
         installed['binding']['run'] == '43734696338' and installed['binding']['job'] == '132874611601' and
         installed['references']['reader_result']['sha256'] == json_pin(report)['sha256'], 'actual installed component/Reader/archive tuple and limited scope')
    decision = Root_decision; root_cert(decision, 'ROOT_ACCEPTED_PERL5423_INPUT_FOR_VM_V1')
    keys(decision, ('kind', 'issued_by', 'accepted', 'operation', 'accepted_for_vm_input', 'source', 'native', 'package', 'trust', 'evidence', 'package_signature_authenticated', 'input_kind'), 'Root decision')
    need(decision['input_kind'] == runtime_certificate['kind'] and decision['operation'] == OP and decision['accepted_for_vm_input'] is decision['package_signature_authenticated'] is True and decision['source'] == SOURCE and decision['native'] == case['native'] and decision['package'] == case['package'] and decision['trust'] == trust and decision['evidence'] == {n: case['evidence'][n] for n in EVIDENCE if n != 'Root_decision'}, 'explicit Root acceptance and all evidence joins')
    inventory = baseline(baseline_certificate)
    expanded = runtime(runtime_certificate, case, inventory)
    resources(resource_certificate, case, baseline_certificate, expanded, runtime_certificate['rollback'], runtime_certificate['dependency_transaction'])
    return json.loads(canonical(case))


def helper(name):
    need(type(name) is str and '/' not in name and name.endswith('.py'), 'fixed frozen helper name')
    path = HERE/'frozen'/name
    origin = load(HERE/'helper-origin.json')['files'][name]
    need(pin(path) == {n: origin[n] for n in ('bytes', 'sha256')}, 'frozen reviewed helper bytes')
    import importlib.util
    spec = importlib.util.spec_from_file_location('perl_vm_frozen_' + name[:-3], path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value

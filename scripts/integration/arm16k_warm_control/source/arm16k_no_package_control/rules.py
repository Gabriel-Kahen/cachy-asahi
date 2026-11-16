# SPDX-License-Identifier: MIT
"""Pure Source65 policy projection for review, never control acceptance.

The caller supplies only policy metadata, not a runtime certificate or inode
bodies. This validates a bounded projection; it does not authenticate a Source65
certificate, resolve payload aliases, or prove any preservation comparison.
"""
import re

SOURCE65 = '57c0aa8ad61b8128cc7a224030bebbc759a41df3'
MAX_PATHS = 150000
MAX_PATH_BYTES = 16 * 1024**2
DATA = 'var/lib/arm16k-perl5423-vm/'
DB = 'var/lib/pacman/local'
LOG = 'var/log/pacman.log'
COMPARE_PREFIXES = ('root/', 'home/builder/', 'etc/', DB+'/', DATA)
COMPARE_EXACT = ('root', 'home/builder', DB, LOG)
RESIDUE_PREFIXES = ('root/', 'home/builder/', 'usr/', 'etc/', DB+'/', 'var/log/')
STRICT_FIELDS = ('inode', 'links', 'type', 'mode', 'uid', 'gid', 'xattrs', 'mtime', 'mtime_ns')
ABSENCES = ('etc/.pwd.lock', 'etc/.updated', 'etc/audisp', 'etc/audit/plugins.d',
            'etc/audit/rules.d', 'etc/ld.so.cache', 'etc/os-release',
            'etc/udev/hwdb.bin', 'etc/vconsole.conf')


def need(ok, message):
    if not ok:
        # Never include caller-supplied path names, metadata or values in errors.
        raise ValueError(message)


def keys(value, expected):
    need(type(value) is dict and value.keys() == set(expected), 'exact policy projection keys required')


def path(value, absolute=False):
    need(type(value) is str and 0 < len(value) <= 4096, 'bounded literal path required')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeError:
        raise ValueError('literal UTF-8 path required') from None
    need(size <= 4096 and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'bounded literal path required')
    if absolute:
        need(re.fullmatch('/[A-Za-z0-9._+/@:~-]+', value) is not None, 'public namespace path required')
        value = value[1:]
    else:
        need(not value.startswith('/'), 'image-relative path required')
    need(all(part not in ('', '.', '..') for part in value.split('/')), 'canonical path required')
    return value, size


def path_set(value):
    need(type(value) in (list, tuple, set, frozenset) and len(value) <= MAX_PATHS, 'bounded path-key collection required')
    result = set()
    total = 0
    for entry in value:
        name, size = path(entry)
        total += size
        need(total <= MAX_PATH_BYTES and name not in result, 'bounded unique path keys required')
        result.add(name)
    return result


def namespace(value, baseline=False, empty=False):
    need(type(value) is dict and len(value) <= MAX_PATHS and (empty or bool(value)), 'bounded public namespace projection required')
    directories = set()
    total = 0
    for name, row in value.items():
        relative, size = path(name, absolute=True)
        total += size
        need(total <= MAX_PATH_BYTES, 'public namespace byte bound')
        keys(row, ('kind', 'mode', 'uid', 'gid'))
        kind, mode = row['kind'], row['mode']
        need(type(kind) is str and kind in ('f', 'd', 'l'), 'projected namespace inode kind required')
        need(type(mode) is int and 0 <= mode <= 0o7777 and not mode & 0o6000 and
             (kind == 'l' or not mode & 0o002) and
             type(row['uid']) is type(row['gid']) is int and row['uid'] == row['gid'] == 0,
             'Source65 safe root-owned namespace metadata required')
        public = name.startswith('/usr/') or name == '/usr' and kind == 'd'
        public |= baseline and (name in ('/etc', '/etc/profile.d') and kind == 'd' or
                                name == '/etc/profile.d/perlbin.sh' and kind == 'f')
        need(public and not name.startswith('/usr/local/') and '/..' not in name,
             'Source65 payload namespace confinement required')
        if kind == 'd':
            directories.add(relative)
    return directories


def review_policy(projection, inventory, owned_paths=(), before_paths=()):
    """Return public rules/counts only; never mark observed drift acceptable.

    Projection keys mirror only image.preserve's inputs. Namespace rows contain
    exactly kind/mode/uid/gid, dependency_transaction is {} or {'namespace': ...}.
    Ownership/before keys may be private and are never returned or fingerprinted.
    Bounds and the safe Perl version spelling further restrict accepted review
    inputs; this is not a replacement for contracts.runtime's full validation.
    """
    keys(projection, ('candidate_namespace', 'baseline_namespace', 'dependency_transaction', 'restoration_allowances'))
    need(type(inventory) is dict and 0 < len(inventory) <= 10000, 'bounded baseline inventory required')
    for name, version in inventory.items():
        need(type(name) is str and len(name) <= 128 and re.fullmatch('[a-z0-9@+_.-]+', name) is not None and
             type(version) is str and 0 < len(version) <= 128 and not any(c.isspace() for c in version),
             'bounded baseline inventory entry required')
    old = None
    if 'perl' in inventory:
        need(re.fullmatch('[A-Za-z0-9.+_:~-]{1,128}', inventory['perl']) is not None, 'safe public Perl version spelling required')
        old = '/'+DB+'/perl-'+inventory['perl']
    candidate_dirs = namespace(projection['candidate_namespace'])
    baseline_dirs = namespace(projection['baseline_namespace'], baseline=True, empty=True)
    need(bool(projection['baseline_namespace']) == (old is not None), 'baseline Perl namespace presence must match inventory')
    dependency = projection['dependency_transaction']
    need(type(dependency) is dict, 'explicit dependency namespace projection required')
    dependency_dirs = set()
    if dependency:
        keys(dependency, ('namespace',))
        dependency_dirs = namespace(dependency['namespace'])
    allow = projection['restoration_allowances']
    keys(allow, ('install_date_path', 'database_timestamp_paths', 'payload_directory_timestamps',
                 'normal_pacman_log', 'pacman_log_before', 'cache_directory_timestamps'))
    log_pin = allow['pacman_log_before']
    if log_pin is not None:
        keys(log_pin, ('bytes', 'sha256'))
        need(type(log_pin['bytes']) is int and 0 < log_pin['bytes'] < 2**63 and
             type(log_pin['sha256']) is str and re.fullmatch('[0-9a-f]{64}', log_pin['sha256']) is not None,
             'public log pin shape required')
    db_paths = ['/'+DB] + ([old, old+'/desc', old+'/files'] if old else [])
    expected = dict(install_date_path=old+'/desc' if old else None, database_timestamp_paths=db_paths,
                    payload_directory_timestamps=True, normal_pacman_log='/'+LOG,
                    pacman_log_before=log_pin, cache_directory_timestamps=['/var/cache', '/var/cache/ldconfig'])
    need(allow == expected and allow['payload_directory_timestamps'] is True,
         'exact Source65 restoration allowance formula required')
    dirs = candidate_dirs | baseline_dirs | dependency_dirs | {p[1:] for p in db_paths} | {'var/cache', 'var/cache/ldconfig'}
    if log_pin is None:
        dirs.add('var/log')
    owned, before = path_set(owned_paths), path_set(before_paths)
    need(owned <= before, 'ownership keys must be present before comparison')
    compared = owned | {p for p in before if p.startswith(COMPARE_PREFIXES) or p in COMPARE_EXACT}
    return dict(kind='SOURCE65_POLICY_REVIEW_ONLY_V1', source_commit=SOURCE65,
        control_acceptance_waiver=False, image_relative_paths=True,
        eligible_directory_timestamp_paths=sorted(dirs), database_timestamp_paths=[p[1:] for p in db_paths],
        directory_timestamp_paths_require_before_type='directory',
        fixture_directory_timestamp_prefix=DATA, normal_log_timestamp_path=LOG,
        changed_timestamp_rule='exact DB path OR exact normal log OR before.type==directory AND (explicit directory path OR fixture prefix)',
        install_date=dict(path=old[1:]+'/desc' if old else None,
            change='ONLY_ONE_ASCII_DECIMAL_INSTALLDATE_LINE; all other desc bytes exact'),
        normal_log=dict(path=LOG, initially_absent=log_pin is None,
            condition='ABSENT_BEFORE_AND_FINAL; before/final normal log data must be None' if log_pin is None else
                      'ORIGINAL_BYTES_MATCH_CERTIFIED_SIZE_AND_SHA256; final bytes start with original bytes',
            final_existing_shape=dict(type='file', uid=0, gid=0, forbidden_mode_bits=0o6002),
            absent_baseline_receipt=dict(path=DATA+'receipts/pacman-log-after', type='file', mode=0o600,
                uid=0, gid=0, nonempty=True, exact_size_and_sha256=True)),
        stable_fields=['type', 'mode', 'uid', 'gid', 'sha256', 'target_b64', 'xattrs'],
        nondirectory_stable_fields=['mtime', 'mtime_ns'],
        nondirectory_timestamp_normalization_exact=[p[1:] for p in db_paths]+[LOG],
        compared=dict(formula='owned UNION before(prefixes OR exact); skip exact trust only in second loop',
            prefixes=list(COMPARE_PREFIXES), exact=list(COMPARE_EXACT), owned_paths=len(owned),
            before_paths=len(before), union_paths=len(compared),
            second_loop_paths=len(compared- {DATA+'trust'}), second_loop_skip_exact=DATA+'trust'),
        strict_parents=dict(paths=['etc', 'etc/audit', 'etc/udev', 'root'], fields=list(STRICT_FIELDS),
            original_modes=dict(etc=0o755, **{'etc/audit': 0o755, 'etc/udev': 0o755, 'root': 0o700}),
            original_uid=0, original_gid=0,
            final_absent_paths=list(ABSENCES)+['root/.ssh'], absence_includes_descendants=True,
            etc_absence_enforcement='certified preboot absence plus final denied new etc/ prefix',
            root_ssh_absence_enforcement='preinventory guard plus separate before/final target-and-descendant gate'),
        residue=dict(denied_new_prefixes=list(RESIDUE_PREFIXES),
            bare_prefix_names_denied_by_this_loop=False, trust_absent_exact=DATA+'trust',
            trust_absent_descendant_prefix=DATA+'trust/',
            additional_gates='exact bounded flat results/receipts allowlists and root SSH preinventory absence'),
        limitations=['No certificate authentication, alias resolution, file-byte read or preservation execution',
            'No /var timestamp allowance under valid Source65 namespace confinement',
            'Directory timestamp eligibility applies only to compared paths; ancestors are not implicitly included',
            'Fixture prefix eligibility is directory-only; DB/log exceptions are exact paths',
            'No global complete-namespace equality or whole-boot atime/ctime/inode/nlink promise',
            'Trust skip does not waive the owned-path loop or the separate final trust-absence gate',
            'Source65 allowances are review data only; no control difference is normalized or accepted'])

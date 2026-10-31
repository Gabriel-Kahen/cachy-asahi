#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Future finite source-tools installed/moved probe, with caller-owned actors.

Only source-pinned installed project helpers may run. Retained Python, recipe,
verifier and package files remain inert. Caller creates an empty alarm-owned
0700 work directory and supplies supervised run(step, argv, expected, cwd).
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import io

NAMES = ('cachy-asahi-maintenance', 'cachy-asahi-session-diagnostics')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def probe(cli, fixtures, work, command):
    cli, fixtures, work = Path(cli), Path(fixtures), Path(work)
    installed = validate_cli(cli)
    info = validate_fixtures(fixtures)
    need(work.is_dir() and not any(work.iterdir()) and stat.S_IMODE(work.stat().st_mode) == 0o700,
         'fresh empty private alarm-owned work required')
    records, contexts = [], []

    def call(arguments, success=True):
        key = STEPS[len(records)]
        argv = ['/usr/bin/runuser', '-u', 'alarm', '--', '/usr/bin/env',
                'HOME=' + str(work), 'PATH=/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE=1', str(cli), *map(str, arguments)]
        raw = command(key, argv, 0 if success else 1, cwd=work)
        need(type(raw) is bytes and len(raw) <= 1024**2, 'bounded supervised raw CLI output required')
        report = decode(raw)
        need(report.get('status') == (STATUS[arguments[0]] if success else 'REFUSED'), 'exact CLI result/refusal required')
        records.append(dict(step=key, argv=argv, expected=0 if success else 1, stdout=data_pin(raw)))
        return report

    old, current = info['fixtures']
    first = call(['mirror-export', '--release-dir', fixtures / old['label'], '--release-sha256', old['release_sha256'],
                  '--output', work / 'first'])
    need(first['packages'] == 2, 'exact two-package export required')
    need(digest(read(work / 'first/mirror.tar')) == first['mirror_sha256'], 'actual first mirror pin required')
    repeat = call(['mirror-export', '--release-dir', fixtures / old['label'], '--release-sha256', old['release_sha256'],
                   '--output', work / 'repeat'])
    need(first['mirror_sha256'] == repeat['mirror_sha256'], 'exact repeat digest required')
    need(read(work / 'first/mirror.tar') == read(work / 'repeat/mirror.tar'), 'byte-identical repeat mirror required')
    successor = call(['mirror-successor', '--previous-bundle', work / 'first/mirror.tar',
        '--previous-sha256', first['mirror_sha256'], '--previous-release-sha256', old['release_sha256'],
        '--release-dir', fixtures / current['label'], '--release-sha256', current['release_sha256'], '--output', work / 'history'])
    need(successor['packages'] == 2, 'two-package successor required')
    need(successor['stats']['pruned_objects'] == 0, 'no history pruning allowed')
    need(set(successor['retained_releases']) == {old['release_sha256'], current['release_sha256']}, 'both exact releases retained')
    mirror = work / 'history/mirror.tar'
    need(digest(read(mirror)) == successor['mirror_sha256'], 'actual successor mirror pin required')
    for fixture in (old, current):
        verified = call(['mirror-verify', '--bundle', mirror, '--sha256', successor['mirror_sha256'],
                         '--release-sha256', fixture['release_sha256']])
        need(verified['release_sha256'] == fixture['release_sha256'] and verified['mirror_sha256'] == successor['mirror_sha256'], 'exact selected mirror release required')
        need(set(verified['retained_releases']) == {old['release_sha256'], current['release_sha256']}, 'both history releases verified')
        for package in fixture['packages']:
            dest = work / (fixture['label'] + '-' + package['name'])
            receipt = call(['build-context', '--bundle', mirror, '--mirror-sha256', successor['mirror_sha256'],
                '--release-sha256', fixture['release_sha256'], '--package', package['name'], '--version', package['version'],
                '--arch', package['arch'], '--package-sha256', package['package_sha256'],
                '--recipe-sha256', package['recipe_sha256'], '--srcinfo-sha256', package['srcinfo_sha256'], '--output', dest])
            need(source_map(dest / 'recipe') == package['sources'], 'exact context source/license/notices required')
            identity = {key: package[key] for key in ('name', 'version', 'arch')}
            identity['sha256'] = package['package_sha256']
            request = decode(read(dest / 'builder-request.json', 1024**2))
            need(receipt['package'] == request['input_identity'] == identity, 'exact context package/archive identity required')
            need(set(request['actual_selectors']) == ACTUAL_KEYS and all(value is None for value in request['actual_selectors'].values())
                 and request['status'] == 'HELD_ACTUAL_SELECTORS_NULL'
                 and all(request.get(key, 'MISSING') is None for key in ('actual_archive_sha256', 'actual_archive_bytes', 'actual_buildinfo_sha256')),
                 'held native actual selectors must stay NULL')
            need(digest(read(dest / 'selection.json')) == receipt['selection_sha256'], 'exact selection pin required')
            sources = package['sources']
            contexts.append(dict(label=fixture['label'], package=package['name'], source_files=len(sources),
                source_map=data_pin(encoded(sources)), selection_sha256=receipt['selection_sha256'],
                license_sha256=sources['LICENSE'], notice_sha256=sources['NOTICE'], actual_selectors='ALL_NULL'))
            moved = dest.with_name(dest.name + '-moved')
            dest.rename(moved)
            checked = call(['verify-context', '--context', moved, '--selection-sha256', receipt['selection_sha256']])
            need(checked['selection_sha256'] == receipt['selection_sha256'] and checked['package'] == identity, 'exact moved context verification required')
    tampered = work / 'tampered.tar'
    tampered.write_bytes(read(mirror) + b'tampered')
    negative_operand(tampered, work)
    refused = call(['mirror-verify', '--bundle', tampered, '--sha256', successor['mirror_sha256'],
          '--release-sha256', current['release_sha256']], False)
    need(refused.get('reason') == 'mirror checksum/bound mismatch', 'exact tamper checksum refusal required')
    incomplete = work / 'incomplete.tar'
    with tarfile.open(fileobj=io.BytesIO(read(mirror)), mode='r:') as source, tarfile.open(incomplete, 'w', format=tarfile.USTAR_FORMAT) as target:
        omitted = False
        for node in source:
            need(node.isfile() and node.size <= MAX_FILE, 'ordinary bounded mirror DATA required')
            if node.name.startswith('objects/') and not omitted:
                omitted = True
                continue
            with source.extractfile(node) as body:
                target.addfile(node, body)
    need(omitted, 'mirror object required for incomplete control')
    negative_operand(incomplete, work)
    refused = call(['mirror-verify', '--bundle', incomplete, '--sha256', digest(read(incomplete)),
          '--release-sha256', current['release_sha256']], False)
    need(refused.get('reason') == 'history object set mismatch', 'exact incomplete mirror refusal required')
    bad_dest = work / 'must-not-exist'
    refused = call(['mirror-successor', '--previous-bundle', incomplete, '--previous-sha256', digest(read(incomplete)),
          '--previous-release-sha256', current['release_sha256'], '--release-dir', fixtures / current['label'],
          '--release-sha256', current['release_sha256'], '--output', bad_dest], False)
    need(refused.get('reason') == 'history object set mismatch', 'exact incomplete previous mirror refusal required')
    need(not os.path.lexists(bad_dest), 'refused operation must not create output')
    release = work / 'incomplete-release'
    shutil.copytree(fixtures / current['label'], release)
    owner = work.stat()
    for item in (release, *release.rglob('*')):
        copied_info = item.lstat()
        need(stat.S_ISDIR(copied_info.st_mode) or stat.S_ISREG(copied_info.st_mode), 'copied fixture links/special files refused')
        os.chown(item, owner.st_uid, owner.st_gid, follow_symlinks=False)
        item.chmod(0o700 if stat.S_ISDIR(copied_info.st_mode) else 0o644)
    (release / 'evidence/cachy-asahi-maintenance-source.tar').unlink()
    refused = call(['mirror-export', '--release-dir', release, '--release-sha256', current['release_sha256'],
          '--output', bad_dest], False)
    need('No such file or directory' in refused.get('reason', '') and 'cachy-asahi-maintenance-source.tar' in refused['reason'],
         'exact absent-source refusal required, not incidental permission failure')
    need(not os.path.lexists(bad_dest), 'refused operation must not create output')
    need(validate_cli(cli) == installed and validate_fixtures(fixtures) == info, 'trusted payload/fixtures must stay exact')
    need(len(records) == 17 and not list(work.rglob('__pycache__')), 'all17 controls without generated code cache required')
    report = dict(status='PASS_SOURCE_TOOLS_FINITE_INSTALLED_PROBE', version='0.1.0-1', scope='system' if cli == Path('/usr/bin/cachy-asahi-source-tools') else 'moved', cli=str(cli), installed=installed, fixture=data_pin(read(fixtures / 'fixtures.json')), fixture_info=info, contexts=contexts, reports={row['step']:row['stdout'] for row in records}, steps={row['step']:row['step'] for row in records}, no_pruning=True, actual_selectors='ALL_NULL', retained_code_execution='FORBIDDEN', controls=len(records), packages_per_release=2, retained_releases=sorted((old['release_sha256'], current['release_sha256'])), retained_release_count=2,
        exact_contexts=4, fixture_data_sha256=digest(read(fixtures / 'fixtures.json')),
        mirror_sha256=successor['mirror_sha256'], mirror_bytes=mirror.stat().st_size, mirror=data_pin(read(mirror)),
        source_execution='FORBIDDEN', native_build='NOT_ESTABLISHED_BY_PROBE', alpm_installation='NOT_ESTABLISHED_BY_PROBE', hardware='NOT_RUN', physical_M2='NOT_RUN', release='NOT_ADMITTED',
        commands=records)
    (work / 'results.json').write_bytes(encoded(report))
    return report


# Public finite protocol; actor labels these keys system/moved without changing argv.
STEPS = ('export', 'repeat', 'successor', 'legacy-verify', 'legacy-0-context',
         'legacy-0-verify-context', 'legacy-1-context', 'legacy-1-verify-context',
         'current-verify', 'current-0-context', 'current-0-verify-context',
         'current-1-context', 'current-1-verify-context', 'tampered', 'incomplete',
         'incomplete-successor', 'incomplete-release')
STATUS = {'mirror-export': 'EXPORTED_SOURCE_MIRROR', 'mirror-successor': 'UPDATED_SOURCE_MIRROR',
          'mirror-verify': 'VERIFIED_OFFLINE_SOURCE_MIRROR_HISTORY',
          'build-context': 'MATERIALIZED_MIRROR_BUILDER_CONTEXT',
          'verify-context': 'VERIFIED_MIRROR_BUILDER_CONTEXT'}
ACTUAL_KEYS = {'builder_image', 'expected_packages_lock', 'expected_packages_sha256',
              'source_date_epoch', 'output', 'native_host_binding', 'native_build_record'}
FIXTURE_SHA256 = 'fc4b8f4fa1709a4054d2dccf97c961a3e9ab3d6f687c1f1c28110cbdb5844b83'
FIXTURE_ARCHIVE_SHA256 = '6e307625ad97381ec6a4efb9a0ae651ad4c38c1c88a81fc19d4e931584d468c0'
PAYLOAD_MAP_SHA256 = 'dc411ac7bb373b7758c7afa004e17a4e4c73127b922cf8dcb2232ede603e5189'
NAME, VERSION = 'cachy-asahi-source-tools', '0.1.0-1'
MAX_FILE, MAX_TOTAL, MAX_FILES = 64 * 1024**2, 128 * 1024**2, 128


def negative_operand(path, work):
    """Prepare root-created negative DATA for the work owner's ordinary CLI."""
    owner = work.stat()
    os.chown(path, owner.st_uid, owner.st_gid, follow_symlinks=False)
    path.chmod(0o644)


def need(value, reason):
    if not value:
        raise ValueError(reason)


def data_pin(raw):
    return dict(bytes=len(raw), sha256=digest(raw))


def ordinary_path(value):
    value = Path(value)
    need(value.is_absolute() and '..' not in value.parts and value.anchor == '/', 'absolute nonaliased path required')
    need(not any(part.is_symlink() for part in (value, *value.parents)), 'symlink ancestor refused')
    return value


def relative(value):
    from pathlib import PurePosixPath
    need(type(value) is str and value and PurePosixPath(value).as_posix() == value
         and not value.startswith('/') and all(part not in ('.', '..') for part in value.split('/'))
         and '\\' not in value and '\x00' not in value, 'canonical relative DATA path required')
    return value


def read(value, maximum=MAX_FILE):
    value = ordinary_path(value)
    fd = os.open(value, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
             'bounded ordinary single-link DATA required')
        blocks, size = [], 0
        while block := os.read(fd, min(65536, maximum + 1 - size)):
            blocks.append(block); size += len(block)
            need(size <= maximum, 'DATA byte cap exceeded')
        after = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_uid', 'st_gid', 'st_mtime_ns', 'st_ctime_ns')
        need(all(getattr(before, key) == getattr(after, key) for key in keys) and size == after.st_size,
             'DATA changed during read')
        return b''.join(blocks)
    finally:
        os.close(fd)


def decode(raw):
    need(len(raw) <= 1024**2, 'JSON cap exceeded')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate DATA JSON key'); result[key] = value
        return result
    def invalid(_):
        raise ValueError('noninteger/nonfinite DATA JSON refused')
    return json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)


def file_pins(root):
    root = ordinary_path(root)
    need(root.is_dir(), 'DATA directory required')
    found, total = {}, 0
    for item in sorted(root.rglob('*')):
        info = item.lstat()
        need(not item.is_symlink() and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)), 'DATA links/special files refused')
        if stat.S_ISREG(info.st_mode):
            key = item.relative_to(root).as_posix(); relative(key)
            raw = read(item); total += len(raw)
            need(len(found) < MAX_FILES and total <= MAX_TOTAL, 'DATA aggregate cap exceeded')
            found[key] = data_pin(raw)
    return found


def source_map(root):
    return {key: row['sha256'] for key, row in file_pins(root).items()}


def validate_cli(cli):
    cli = ordinary_path(cli)
    need(cli.name == NAME and cli.parent.name == 'bin' and cli.parent.parent.name == 'usr', 'fixed installed CLI layout required')
    root = cli.parents[2]; key = 'usr/share/doc/' + NAME + '/payload-map.json'
    raw = read(root / key, 64 * 1024)
    need(digest(raw) == PAYLOAD_MAP_SHA256, 'fixed source-tools payload map required')
    mapping = decode(raw)
    need(mapping['schema_version'] == 1 and mapping['package'] == NAME and mapping['self'] == key, 'exact payload identity required')
    expected = dict(mapping['files']); expected[key] = dict(**data_pin(raw), mode=0o644)
    need(len(expected) == 17 and {'usr/bin/' + NAME, key} <= expected.keys(), 'exact17 payload required')
    for leaf, row in expected.items():
        relative(leaf); item = root / leaf
        need(data_pin(read(item)) == {k: row[k] for k in ('bytes', 'sha256')}
             and stat.S_IMODE(item.stat().st_mode) == row['mode'], 'source-tools payload mismatch: ' + leaf)
    return dict(files=17, payload_map=data_pin(raw), launcher=data_pin(read(cli)))


def validate_fixtures(fixtures):
    fixtures = ordinary_path(fixtures); raw = read(fixtures / 'fixtures.json', 1024**2)
    need(digest(raw) == FIXTURE_SHA256, 'exact frozen two-package fixtures required')
    info = decode(raw)
    need(info['purpose'] == 'source-tools-synthetic-two-package-roundtrip'
         and info['source_execution'] == 'FORBIDDEN' and info['native_build'] == 'NOT_RUN', 'inert fixture identity required')
    expected = {'fixtures.json': data_pin(raw)}
    need([row['label'] for row in info['fixtures']] == ['legacy', 'current'], 'two exact fixture releases required')
    for row in info['fixtures']:
        need(tuple(item['name'] for item in row['packages']) == NAMES, 'two exact original package fixtures required')
        raw_release = read(fixtures / row['label'] / 'release.json', 1024**2)
        need(digest(raw_release) == row['release_sha256'], 'exact fixture release pin required')
        manifest = decode(raw_release); need(manifest['symlinks'] == {}, 'fixture aliases refused')
        expected[row['label'] + '/release.json'] = data_pin(raw_release)
        for leaf, checksum in manifest['files'].items():
            relative(leaf); key = row['label'] + '/' + leaf; body = read(fixtures / key)
            need(digest(body) == checksum, 'fixture release DATA mismatch: ' + key); expected[key] = data_pin(body)
        for package in row['packages']:
            need(package['arch'] == 'any' and {'LICENSE', 'NOTICE', 'PKGBUILD', '.SRCINFO'} <= package['sources'].keys(),
                 'exact fixture source/notices required')
    need(file_pins(fixtures) == expected and len(expected) == 41, 'complete exact41 fixture DATA required')
    return info

# Namespace diagnostics run only as fresh, caller-supervised alarm actors after
# the original check failure. No child, mount, map/sysctl write, signal or fallback.
NS_MODES = {'context': 0, 'user': 0x10000000, 'mount': 0x00020000,
            'user_mount': 0x10020000, 'user_net': 0x50000000,
            'user_mount_net': 0x50020000}
NS_STATUS = ('CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs','Seccomp','Seccomp_filters')
NS_POLICY = {'userns_clone':'/proc/sys/kernel/unprivileged_userns_clone',
             'max_user_namespaces':'/proc/sys/user/max_user_namespaces',
             'apparmor_userns':'/proc/sys/kernel/apparmor_restrict_unprivileged_userns'}


def namespace_read(path, cap):
    try:
        fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            chunks=[];size=0
            while size<=cap:
                part=os.read(fd,min(4096,cap+1-size))
                if not part:break
                chunks.append(part);size+=len(part)
            raw=b''.join(chunks)
        finally:os.close(fd)
        if len(raw)>cap:return dict(status='UNKNOWN',reason='BYTE_CAP')
        return dict(status='OBSERVED',text=raw.decode('ascii'))
    except (OSError,UnicodeError) as error:
        return dict(status='UNKNOWN',reason=type(error).__name__,errno=getattr(error,'errno',None))


def namespace_binary():
    path='/usr/bin/bwrap';fd=None
    def identity(info):
        return tuple(getattr(info,key)for key in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
    try:
        fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK);info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode)or info.st_nlink!=1 or not 0<info.st_size<=4*1024**2:raise ValueError('ordinary bounded fixed bwrap required')
        parts=[];size=0
        while size<=info.st_size:
            part=os.read(fd,min(65536,info.st_size+1-size))
            if not part:break
            parts.append(part);size+=len(part)
        body=b''.join(parts)
        try:
            value=os.getxattr(fd,'security.capability')
            caps=value.hex() if len(value)<=128 else 'UNKNOWN_BYTE_CAP'
        except OSError as error:caps=dict(status='UNKNOWN_OR_ABSENT',errno=error.errno)
        if size!=info.st_size or identity(info)!=identity(os.fstat(fd))or identity(info)!=identity(os.stat(path,follow_symlinks=False)):raise ValueError('bwrap identity changed')
        return dict(status='OBSERVED',path=path,bytes=size,sha256=digest(body),mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,file_capabilities=caps)
    except (OSError,ValueError)as error:return dict(status='UNKNOWN',reason=type(error).__name__)
    finally:
        if fd is not None:os.close(fd)


def namespace_context():
    status=namespace_read('/proc/self/status',16384);fields={}
    if status['status']=='OBSERVED':
        for line in status['text'].splitlines():
            key,sep,value=line.partition(':')
            if sep and key in NS_STATUS:
                value=value.strip()
                if len(value)<=32 and all(c in '0123456789abcdefABCDEF' for c in value):fields[key]=value
    links={}
    for name in ('user','mnt','net'):
        try:
            value=os.readlink('/proc/self/ns/'+name)
            links[name]=value if len(value)<=64 and value.startswith(name+':[') and value.endswith(']') else 'UNKNOWN'
        except OSError:links[name]='UNKNOWN'
    maps={name:namespace_read('/proc/self/'+name,4096) for name in ('uid_map','gid_map')}
    policy={key:namespace_read(path,64) for key,path in NS_POLICY.items()}
    lsm=namespace_read('/proc/self/attr/current',256)
    # Paths, device sources and super options from unrelated mounts are omitted.
    mounts=namespace_read('/proc/self/mountinfo',131072);selected=[]
    if mounts['status']=='OBSERVED':
        lines=mounts['text'].splitlines()
        if len(lines)>512:mounts=dict(status='UNKNOWN',reason='ROW_CAP')
        else:
            cwd=os.getcwd()
            for line in lines:
                left,sep,right=line.partition(' - ');parts=left.split();tail=right.split()
                if sep and len(parts)>=6 and tail and (parts[4]=='/proc'or any(target==parts[4]or target.startswith(parts[4].rstrip('/')+'/')for target in(cwd,'/usr/bin/bwrap'))):
                    selected.append(dict(mount_id=parts[0],parent_id=parts[1],mountpoint=parts[4],filesystem=tail[0],
                                         options=[v for v in parts[5].split(',')if v in('ro','rw','nosuid','nodev','noexec')]))
    if len(selected)>32:mounts=dict(status='UNKNOWN',reason='SELECTED_ROW_CAP');selected=selected[:32]
    executable=namespace_binary()
    groups=os.getgroups()
    return dict(uid=os.getuid(),euid=os.geteuid(),gid=os.getgid(),egid=os.getegid(),cwd=os.getcwd(),
                groups=groups[:32],group_count=len(groups),groups_truncated=len(groups)>32,
                status_fields=fields,status_state=status['status'],namespaces=links,maps=maps,policy=policy,lsm=lsm,
                mounts=dict(status=mounts['status'],rows=selected),bwrap=executable)


def namespace_unshare(flags):
    import ctypes
    import errno
    try:
        libc=ctypes.CDLL(None,use_errno=True);call=libc.unshare;call.argtypes=(ctypes.c_int,);call.restype=ctypes.c_int
        ctypes.set_errno(0);rc=call(flags);number=ctypes.get_errno() if rc else 0
        return dict(interface='libc.unshare',flags=flags,returncode=rc,errno=number,
                    errno_name=errno.errorcode.get(number,'NONE'if number==0 else 'UNKNOWN'))
    except (OSError,AttributeError) as error:
        return dict(interface='libc.unshare',flags=flags,returncode=None,errno=None,errno_name='UNKNOWN',reason=type(error).__name__)


def namespace_observation(mode,map_sha256):
    need(mode in NS_MODES,'fixed namespace observation mode required')
    before=namespace_context()
    need(before['uid']==before['euid'] and before['uid']>0,'ordinary same alarm identity required')
    syscall=None if mode=='context' else namespace_unshare(NS_MODES[mode])
    after=before if mode=='context' else namespace_context()
    return dict(schema=1,status='NAMESPACE_PREREQUISITE_DATA_ONLY',mode=mode,source_map_sha256=map_sha256,
                before=before,syscall=syscall,after=after,scope='OWN_BUILD_ACTOR_SELF_ONLY_NO_CHILD_OR_GLOBAL_MUTATION',
                namespace_acceptance='NOT_ESTABLISHED',native_acceptance='NOT_ADMITTED')


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--namespace-mode',choices=tuple(NS_MODES),required=True);parser.add_argument('--map-sha256',required=True);args=parser.parse_args()
    raw=read(Path(__file__).resolve().with_name('source-map.json'),1024**2)
    need(digest(raw)==args.map_sha256,'exact current Source map before namespace observation')
    value=namespace_observation(args.namespace_mode,args.map_sha256);body=encoded(value)
    need(len(body)<=32768,'namespace observation output32KiB cap');print(body.decode(),end='')

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private full-composition guest builder; invoked only by the owned controller."""
import argparse
import importlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import sys
import tempfile
import time

GIB = 1024**3
SHARED = 'usr/local/share/full-installer'
DISK_BYTES = 20 * GIB
UNIT = '''[Unit]
Description=Disposable full composition installer software trial
Requires=basic.target systemd-udevd.service systemd-udev-trigger.service
After=basic.target systemd-udev-trigger.service
[Service]
Type=oneshot
Environment=CACHY_ASAHI_FULL_INSTALLER_GUEST=1
ExecStart=/usr/bin/python3 /usr/local/share/full-installer/guest.py boot
TimeoutStartSec=5200
LimitNOFILE=8192
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyAMA0
'''
TARGET = '''[Unit]
Description=Disposable generic full installer software trial only
Requires=full-installer.service
After=full-installer.service
AllowIsolate=yes
'''


def need(ok, reason):
    if not ok: raise ValueError(reason)


# The accepted desktop574 runtime preserves existing packages and adds only16
# missing tooling rows. This sole known version difference is not a downgrade
# request: admit it only on the exact original574 inventory and keep its version.
BUILDER_LOCK = 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
PRESERVED_TOOLING_TUPLE = ('snappy', '1.3.1-1', '1.2.2-3')


def tooling_additions(base, rows):
    need(type(base) is dict and len(base) == 574, 'exact producer builder574 required')
    need(type(rows) is list and len(rows) == 21 and len({r['name'] for r in rows}) == 21,
         'exact held 21 tooling rows required')
    for row in rows:
        if row['name'] not in base or base[row['name']] == row['version']: continue
        selected = (row['name'], base[row['name']], row['version'])
        digest = hashlib.sha256(''.join(n+' '+v+'\n' for n,v in sorted(base.items())).encode()).hexdigest()
        need(selected == PRESERVED_TOOLING_TUPLE and digest == BUILDER_LOCK,
             'tooling version replacement refused: ' + row['name'])
    return [row for row in rows if row['name'] not in base]


def union_inventory(base, rows):
    return dict(base, **{row['name']:row['version'] for row in tooling_additions(base, rows)})


def tooling_inputs(base, lock, signature):
    return lock['keyring_files'] + [item for row in tooling_additions(base, lock['packages'])
                                   for item in (row, signature(row))]


def checked_file(root, name, row, common):
    path = common.pinned(root, name, row['sha256'])
    need(type(row['bytes']) is int and 0 <= row['bytes'] <= GIB and path.stat().st_size == row['bytes'],
         'input size differs: ' + name)
    return path


def verify_contract(path, sha, common, *, input_bytes=True):
    need(path == Path('/selection/vm-contract.json'), 'fixed selection path required')
    c = common.json_load(common.pinned('/selection', path.name, sha))
    need(c['schema_version'] == 1 and c['purpose'] == 'full-composition-installer-vm' and
         re.fullmatch('[0-9a-f]{32}', c['nonce']) and
         re.fullmatch('[0-9a-f]{40}', c['source_commit']), 'VM selection identity differs')
    for name, row in c['runner_files'].items(): checked_file('/candidate', name, row, common)
    for name, row in c['code_files'].items(): checked_file('/code', name, row, common)
    # The UID23001 VM supervisor consumes only the sealed prepared disk. The
    # producer's0700 cache remains unreadable to it and is rehashed by its owner.
    if input_bytes:
        for name, row in c['input_files'].items(): checked_file('/inputs', name, row, common)
    lock = common.json_load(checked_file('/code', 'scripts/virtual/tooling.lock.json',
                                       c['code_files']['scripts/virtual/tooling.lock.json'], common))
    need(union_inventory(c['builder_inventory'], lock['packages']) == c['tooling_inventory'],
         'declared tooling union differs')
    need(c['tooling_lock_sha256'] == common.digest('/code/scripts/virtual/tooling.lock.json'),
         'tooling lock differs')
    return c, lock


def guard(common, mode, c):
    f = common.facts()
    if mode == 'disk': common.validate_environment(f, preparation=True)
    else:
        need(f['uid'] == 0 and f['docker'] and f['arch'] == 'aarch64' and f['marker'] == '1' and
             f['nnp'] == '1' and f['caps']['CapEff'] == common.SAFE_CAPS and
             all(v & ~common.SAFE_CAPS == 0 for v in f['caps'].values()),
             'isolated metadata-only tooling child required')
        need('rw' in f['mounts']['/']['flags'] and f['mounts']['/']['type'] in ('overlay','fuse-overlayfs'),
             'owned writable tooling overlay required')
    need(f['nonce'] == c['nonce'] and f['image_id'] == c['active_image'] and
         f['interfaces'] == ['lo'] and not f['devices'] and not f['docker_socket'],
         'network/device/nonce/image isolation differs')
    for mount in ('/inputs', '/code', '/runner', '/candidate', '/selection', '/tooling-cache'):
        need('ro' in f['mounts'].get(mount, {}).get('flags', []), 'readonly input mount required: ' + mount)
    for point in f['mounts']:
        need(not any(point.startswith(p + '/') for p in
             ('/inputs','/code','/runner','/candidate','/selection','/tooling-cache','/out','/tmp')),
             'nested input/output mount refused')
        if any(point == p or point.startswith(p + '/') for p in ('/usr','/etc','/var','/boot','/home','/root','/run')):
            need(point in ('/etc/hosts','/etc/hostname','/etc/resolv.conf'), 'system mount refused')
    need(not any(os.getenv(k) for k in ('DISPLAY','WAYLAND_DISPLAY','WAYLAND_SOCKET',
             'DBUS_SESSION_BUS_ADDRESS','PIPEWIRE_REMOTE','PULSE_SERVER')), 'host connection refused')


def installed(common, expected):
    actual = common.inventory(__import__('subprocess').check_output(['/usr/bin/pacman','-Q'], text=True, timeout=30))
    need(actual == expected, 'exact full installed inventory differs')
    return actual


def tooling(c, lock, common, command, report):
    sys.path.insert(0, '/runner/virtual')
    auditor = importlib.import_module('audit_tooling')
    auditor.validate_lock(lock)
    installed(common, c['builder_inventory'])
    additions = tooling_additions(c['builder_inventory'], lock['packages'])
    for row in tooling_inputs(c['builder_inventory'], lock, auditor.signature):
        checked_file('/tooling-cache', row['filename'], {'sha256':row['sha256'],'bytes':row['size']}, common)
    temporary = Path(tempfile.mkdtemp(prefix='full-installer-trust-', dir='/tmp'))
    keyring, hooks, conf = temporary/'keys', temporary/'hooks', temporary/'pacman.conf'
    hooks.mkdir()
    try:
        for folder in ('/usr/share/libalpm/hooks','/etc/pacman.d/hooks'):
            for path in Path(folder).glob('*.hook'):
                need(re.fullmatch('[A-Za-z0-9._+-]+[.]hook', path.name), 'unsafe hook name')
                target = hooks/path.name
                if not target.is_symlink(): target.symlink_to('/dev/null')
        conf.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\n'
                        + 'HookDir = '+str(hooks)+'\nGPGDir = '+str(keyring)+'\n')
        command(['/usr/bin/pacman-key','--gpgdir',str(keyring),'--init'], 120)
        command(['/usr/bin/pacman-key','--gpgdir',str(keyring),'--add','/tooling-cache/archlinuxarm.gpg'])
        command(['/usr/bin/pacman-key','--gpgdir',str(keyring),'--lsign-key',lock['signer_fingerprint']])
        for row in additions:
            result = command(['/usr/bin/gpg','--batch','--homedir',str(keyring),'--status-fd','1',
                 '--verify','/tooling-cache/'+row['filename']+'.sig','/tooling-cache/'+row['filename']])
            auditor.verify(result['stdout'], lock['signer_fingerprint'])
            need(not auditor.inspect(Path('/tooling-cache')/row['filename'],row)['hooks'], 'tooling hooks refused')
        if additions:
            command(['/usr/bin/pacman','--config',str(conf),'--noconfirm','--noscriptlet',
                     '--logfile',str(temporary/'pacman.log'),'-U',
                     *['/tooling-cache/'+r['filename'] for r in additions]],300)
        command(['/usr/bin/ldconfig'])
        report['package_inventory'] = installed(common, c['tooling_inventory'])
    finally:
        # Agent retirement must succeed before committing this private image.
        command(['/usr/bin/gpgconf','--homedir',str(keyring),'--kill','all'])
        shutil.rmtree(temporary)
    report.update(status='TOOLING_READY', trust_cleanup='PASS',
        added_tooling=[row['name'] for row in additions],
        preserved_tooling={row['name']:c['builder_inventory'][row['name']]
                           for row in lock['packages'] if row['name'] in c['builder_inventory']})


def change(root, name, data, report, mode=0o644):
    path = root/name
    need(not any(p.is_symlink() for p in (path,*path.parents)), 'staging symlink refused')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data); path.chmod(mode)
    report['fixture_changes'].append(name)


def disk(c, common, command, report):
    installed(common, c['tooling_inventory'])
    common.transaction_launcher(Path('/'))
    need(common.digest('/boot/Image') == common.IMAGE_SHA, 'held generic4K kernel differs')
    output, root = Path('/out/prepared'), Path('/out/prepared/root')
    need(not output.exists(), 'fresh disk preparation required')
    output.mkdir(); root.mkdir()
    source_bytes = sum(int(line.split()[0]) for line in command(
        ['/usr/bin/du','-s','-B1','--','/usr','/etc','/var','/boot'],60)['stdout'].splitlines())
    cache_bytes = sum(row['bytes'] for row in c['input_files'].values())
    staged_bound = source_bytes + cache_bytes + sum(r['bytes'] for r in c['code_files'].values()) + 64*1024**2
    need(staged_bound <= 10*GIB and common.free_bytes('/out') >= 2*staged_bound + 2*GIB,
         'finite source/stage/disk capacity preflight failed')
    report['resources'] = dict(source_allocated_bytes=source_bytes, input_bytes=cache_bytes,
        stage_bound_bytes=staged_bound, disk_virtual_bytes=DISK_BYTES)
    command(['/usr/bin/cp','-a','--no-preserve=xattr','--reflink=never','--',
             '/usr','/etc','/var','/boot',str(root)],600)
    need(not (root/SHARED).exists(), 'full installer fixture namespace already occupied')
    # Never put a builder's pacman local-master secret material in the guest.
    trust=root/'etc/pacman.d/gnupg'
    need(not trust.is_symlink(), 'staged trust directory alias refused')
    if trust.exists(): shutil.rmtree(trust)
    trust.mkdir(mode=0o700,parents=True)
    report['fixture_changes'].append('etc/pacman.d/gnupg: guest-only empty keyring')
    for name in ('usr','etc','var','boot'):
        for source in (Path('/')/name).rglob('*'):
            before=source.lstat()
            if stat.S_ISREG(before.st_mode) and before.st_mode & (stat.S_ISUID|stat.S_ISGID):
                after=(root/source.relative_to('/')).lstat()
                need((before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode))==
                     (after.st_uid,after.st_gid,stat.S_IMODE(after.st_mode)),
                     'special mode/ownership lost during stage')
    for name in ('bin','sbin','lib','lib64'):
        source = Path('/')/name
        if source.is_symlink(): (root/name).symlink_to(os.readlink(source))
        else: need(not source.exists(), 'unexpected root link layout')
    for name in ('dev','proc','sys','run','tmp','home','root','mnt','srv','opt'):
        (root/name).mkdir(mode=0o1777 if name=='tmp' else 0o755, exist_ok=True)
    for name,row in c['code_files'].items():
        change(root,SHARED+'/code/'+name,checked_file('/code',name,row,common).read_bytes(),report)
    for name,row in c['input_files'].items():
        source = checked_file('/inputs',name,row,common)
        target = root/SHARED/'input'/name; target.parent.mkdir(parents=True,exist_ok=True)
        with source.open('rb') as src, target.open('xb') as dst: shutil.copyfileobj(src,dst,1024**2)
        target.chmod(0o444)
        need(common.digest(target)==row['sha256'], 'staged input changed')
    for name in ('guest.py','installer.py','profile.py','numeric_vm.py','payload.json'):
        change(root,SHARED+'/'+name,checked_file('/candidate',name,c['runner_files'][name],common).read_bytes(),report)
    profile = checked_file('/candidate','installer-profile.json',c['runner_files']['installer-profile.json'],common)
    change(root,SHARED+'/installer-profile.json',profile.read_bytes(),report)
    change(root,SHARED+'/contract.json',(json.dumps(c,sort_keys=True)+'\n').encode(),report)
    change(root,'etc/fstab',b'/dev/vda / ext4 defaults 0 0\n',report)
    change(root,'etc/machine-id',b'',report)
    change(root,'etc/hostname',b'full-installer-generic-vm\n',report)
    change(root,'etc/hosts',b'127.0.0.1 localhost\n::1 localhost\n',report)
    change(root,'etc/systemd/system/full-installer.service',UNIT.encode(),report)
    change(root,'etc/systemd/system/full-installer.target',TARGET.encode(),report)
    command(['/usr/bin/depmod','-b',str(root),common.KERNEL],120)
    shutil.copyfile('/boot/Image',output/'Image')
    actual = common.allocated(root)
    need(actual <= 10*GIB and common.free_bytes(output)>=actual+2*GIB, 'mkfs capacity guard failed')
    image=output/'guest.raw'
    with image.open('xb') as stream: stream.truncate(DISK_BYTES)
    command(['/usr/bin/mkfs.ext4','-F','-m','0','-L','FULL_INSTALLER','-d',str(root),str(image)],600)
    need(common.free_bytes(output)>=2*GIB,'post-mkfs capacity guard failed')
    report.update(status='PREPARED',kernel_sha256=common.digest(output/'Image'),
                  guest_image_sha256=common.digest(image),package_inventory=c['tooling_inventory'])
    shutil.rmtree(root)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('tooling','disk'))
    parser.add_argument('--contract-sha256',required=True)
    args=parser.parse_args()
    sys.path.insert(0,'/runner/virtual')
    common=importlib.import_module('common')
    c,lock=verify_contract(Path('/selection/vm-contract.json'),args.contract_sha256,common)
    guard(common,args.mode,c)
    report=dict(status='FAIL',mode=args.mode,nonce=c['nonce'],contract_sha256=args.contract_sha256,
                fixture_changes=[],commands=[],hardware_validation='NOT RUN')
    start=time.monotonic()
    def cancelled(*_): raise InterruptedError('preparation owner cancelled/deadline')
    previous={sig:signal.signal(sig,cancelled) for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM)}
    signal.setitimer(signal.ITIMER_REAL,1800)
    def command(argv,timeout=60):
        remaining=1800-(time.monotonic()-start)
        need(remaining>0,'absolute preparation deadline')
        result=common.bounded(argv,timeout=min(timeout,remaining),limit=4*1024**2,
                             log=Path('/out')/('command-%03d.log'%len(report['commands'])))
        report['commands'].append(dict(argv=argv,returncode=result['returncode'],error=result['error']))
        need(result['error'] is None and result['returncode']==0,'preparation command failed: '+argv[0])
        return result
    try:
        if args.mode=='tooling': tooling(c,lock,common,command,report)
        else: disk(c,common,command,report)
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        for sig,handler in previous.items(): signal.signal(sig,handler)
        report['elapsed_seconds']=round(time.monotonic()-start,3)
        common.save('/out/'+args.mode+'.json',report)
        for path in [Path('/out'),*Path('/out').rglob('*')]:
            if not path.is_symlink(): os.chown(path,c['output_uid'],c['output_gid'])


if __name__=='__main__': main()

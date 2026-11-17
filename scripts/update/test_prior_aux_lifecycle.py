#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Genuine host TEST transactions, explicitly distinct from the ARM aux profile.

Requires an owned user/mount/network namespace and a <=512MiB cgroup fence.
Mounts only the caller's empty private sandbox. No host installation or fetching.
"""
import argparse
from contextlib import ExitStack, contextmanager
from dataclasses import asdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import aux_checkpoint as aux
import aux_copy
import full_root as roots
import prior_aux_runtime as prior
import root_link_selection as links
import scale_update as scale
import supervision
from test_snapshot import signing, make_bundle, make_envelope, encoded, digest, module

PROFILE = 'TEST-cachyos-x86_64-glibc244-raw-caches-v1'
ALPM_SHA = 'da30edd45277cf4b1000485658976042f8106fe0b97378d1e6c4e81a9d7c4888'
HOST_FILES = {
    'usr/bin/ldconfig': (1321200, '8b5b2cb6ded837a2c645459d658afdfd8dd4cc4599edb981f7a018ac9dc4b829'),
    'usr/lib/libc.so.6': (2444640, '848dae1dfcff0fc864292b28b2d426b0093425002a856a55c3a2b8ed31e2ea40'),
}
COMPARATOR = HERE.parent/'ci/full-development-composition/audio_aux.py'
CASES = ('commit', 'stale-prior', 'postcommit-drift')


def need(value, reason):
    if not value: raise RuntimeError(reason)


def limits():
    return roots.Limits(deadline=time.monotonic()+60, max_nodes=4000,
                        max_bytes=16*1024**2, max_file_bytes=8*1024**2, max_package_files=4000)


def fenced():
    group = Path('/sys/fs/cgroup'+Path('/proc/self/cgroup').read_text().strip().split('::', 1)[1])
    memory, swap, pids, cpu = ((group/name).read_text().strip() for name in
                             ('memory.max', 'memory.swap.max', 'pids.max', 'cpu.max'))
    need(memory != 'max' and 0 < int(memory) <= 512*1024**2 and swap == '0', '512MiB/swap0 cgroup required')
    quota, period = cpu.split()
    need(quota != 'max' and 0 < int(quota) <= int(period) and pids != 'max' and int(pids) <= 64,
         'one CPU/64PID cgroup required')
    return dict(group=str(group), memory_max=memory, swap_max=swap, pids_max=pids, cpu_max=cpu)


def verify_host():
    need(digest('/usr/lib/libalpm.so.16.0.1') == ALPM_SHA, 'known frozen host ALPM required')
    for name, (size, pin) in HOST_FILES.items():
        source = Path('/')/name
        need(source.stat().st_size == size and digest(source) == pin, 'known host helper/libc profile required')


@contextmanager
def host_profile():
    verify_host()
    # Preserve the genuine original source/binding loader in a private namespace.
    # This validates ARM-origin comparator source, NOT host source correspondence.
    pristine = module('_lifecycle_original_aux_loader', HERE/'aux_checkpoint.py')
    with ExitStack() as selected:
        selected.enter_context(patch.object(aux, 'HELPER', (HOST_FILES['usr/bin/ldconfig'][1], HOST_FILES['usr/bin/ldconfig'][0])))
        selected.enter_context(patch.object(aux, 'TARGETS', {}))
        selected.enter_context(patch.object(aux, 'load_comparator', pristine.load_comparator))
        for name, value in dict(CHAIN_PATHS=(), LINK_NODES={}, RESOLVED_ENDPOINTS={}, DATA_ONLY_ENDPOINTS={}, MTAB_TARGETS=()).items():
            selected.enter_context(patch.object(links, name, value))
        yield


def observe(root):
    return roots.observe(root, limits=limits(), hardlinks='generic-development-internal')


def capacity(path):
    info = os.statvfs(path)
    return dict(bytes=info.f_bavail*info.f_frsize, inodes=info.f_favail, device=Path(path).stat().st_dev)


def helper(root, evidence, label):
    for name,(size,pin) in HOST_FILES.items():
        need((root/name).stat().st_size==size and digest(root/name)==pin,'copied native profile changed before execution')
    def enter():
        os.chroot(root); os.chdir('/')
    result = subprocess.run(['/usr/bin/ldconfig'], preexec_fn=enter,
        env={'PATH':'/usr/bin:/bin', 'LC_ALL':'C'}, capture_output=True, timeout=10)
    (evidence/(label+'.stdout')).write_bytes(result.stdout)
    (evidence/(label+'.stderr')).write_bytes(result.stderr)
    (evidence/(label+'.json')).write_bytes(encoded(dict(exit=result.returncode,helper_sha256=HOST_FILES['usr/bin/ldconfig'][1])))
    need(result.returncode == 0, 'real static helper initialization failed')
    return result.returncode


def write(root, name, data, mode=0o644):
    path = root/name; path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data); path.chmod(mode)


def source_root(root):
    verify_host()
    root.mkdir(mode=0o700)
    for name in (*aux.TARGET_PARENTS, aux.FAKE_DIR): (root/name).mkdir(parents=True, exist_ok=True)
    for name in HOST_FILES: write(root, name, (Path('/')/name).read_bytes(), 0o755)
    write(root, 'etc/ld.so.conf', b'# Dynamic linker/loader configuration.\n# See ld.so(8) and ldconfig(8) for details.\n\ninclude /etc/ld.so.conf.d/*.conf\ninclude /usr/lib/ld.so.conf.d/*.conf\n')
    write(root, aux.FAKE_CONF, b'/usr/lib/libfakeroot\n')
    (root/'var/cache/ldconfig').mkdir(parents=True, mode=0o700)
    (root/'usr/lib64').symlink_to('lib'); (root/'usr/sbin').symlink_to('bin'); (root/'sbin').symlink_to('usr/bin')
    write(root, 'etc/pacman.conf', b'# TEST ONLY base trust\n')
    write(root, 'etc/pacman.d/base-public', b'TEST ONLY public marker\n')
    write(root, 'home/user/config', b'USER TEST ONLY\n')
    old = {'usr/share/selected/data': b'old data\n', 'usr/share/selected/retired': b'retired data\n'}
    for name, data in old.items(): write(root, name, data)
    versions = dict(selected='1-1', glibc='1-1', pacman='1-1', **{'fixture-kernel':'1-1'},
                    **{f'held-{i:03d}':'1-1' for i in range(583)})
    owned = {name: [] for name in versions}
    owned.update(selected=list(old), glibc=list(HOST_FILES), pacman=['etc/pacman.conf','etc/pacman.d/base-public'],
                 **{'fixture-kernel':['usr/lib/modules/fixture-release/kernel/fixture.ko']})
    write(root, owned['fixture-kernel'][0], b'TEST ONLY NOT A LOADABLE MODULE\n')
    write(root, 'var/lib/pacman/local/ALPM_DB_VERSION', b'9\n')
    for name, version in versions.items():
        base = f'var/lib/pacman/local/{name}-{version}/'
        write(root, base+'desc', f'%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%ARCH%\nany\n\n'.encode())
        write(root, base+'files', ('%FILES%\n'+'\n'.join(owned[name])+'\n\n').encode())
    return versions, owned, old


def old_archive(path, entries, sign):
    import io, tarfile
    with tarfile.open(path, 'w:gz') as archive:
        for name, data in {'.PKGINFO':b'pkgname = selected\npkgver = 1-1\narch = any\nlicense = MIT\n', **entries}.items():
            item = tarfile.TarInfo(name); item.size = len(data); item.mode = 0o644
            archive.addfile(item, io.BytesIO(data))
    sign(path)


def configure(case, root, workspace, versions, owned, old, signer, public, sign):
    base = [dict(name=n, version=v, arch='any', depend=[], provides=[], conflict=[], files=owned[n]) for n,v in versions.items()]
    bundle = make_bundle(case, signer, sign, base_packages=base, name='selected', version='2-1',
        payload={'usr/share/selected/data':b'new data\n','usr/share/selected/new':b'new leaf\n'})
    args, settings = make_envelope(case, bundle, signer, public, sign)
    before, after = scale.inventory_sha(versions), scale.inventory_sha(dict(versions, selected='2-1'))
    policy_module = scale.load('generic_policy')
    policy = dict(schema_version=1, purpose='cachy-asahi-generic-development-update-policy', release_id='fixture-1',
        protected_packages=sorted(set(versions)-{'selected'}), protected_versions={n:v for n,v in versions.items() if n!='selected'},
        platform_roles={'kernel':['fixture-kernel']}, protected_units={s:sorted(u) for s,u in policy_module.asahi.REQUIRED_UNITS.items()},
        before_lock_sha256=before, after_lock_sha256=after)
    config = dict(schema_version=1,purpose='disposable-bound-update-scale',platform_mode='generic-development',
        before_lock_sha256=before,after_lock_sha256=after,
        limits=dict(root_nodes=4000,root_bytes=16*1024**2,file_bytes=8*1024**2,package_files=4000,
            archive_bytes=1024**2,archive_total_bytes=2*1024**2,decoded_bytes=4*1024**2,
            archive_members=10000,window_bytes=1024**2,seconds=40),
        capacity=dict(root_reserve_bytes=1024**2,root_reserve_inodes=100,workspace_future_bytes=1024**2,workspace_future_inodes=100))
    settings.update(schema_version=1,purpose='disposable-generic-bound-update',
        model='generic-development-only',running_kernel_release='NOT-HARDWARE-OBSERVED',operations=['repository-update'],
        base_trust_sha256=scale.bound.trust_digest(observe(root)['nodes']))
    values = vars(args); values.update(root=str(root),workspace=str(workspace),operation='repository-update')
    for name, value in (('settings',settings),('policy',policy),('scale',config)):
        path=case/(name+'.json'); path.write_bytes(encoded(value)); values[name]=str(path); values[name+'_sha256']=digest(path)
    path=case/'prior.pkg.tar.gz'; old_archive(path,old,sign); values['prior_archive']=str(path)
    return values


def worker(request):
    request=json.loads(Path(request).read_bytes()); args=argparse.Namespace(**request['args'])
    original=prior.Runtime
    class Fault(original):
        def precommit(self):
            if request['case']=='stale-prior':
                path=Path(self.args.prior_archive); before=digest(path)
                path.write_bytes(path.read_bytes()+b'TEST STALE')
                Path(request['result']).with_name('fault.json').write_bytes(encoded(
                    dict(stage='Runtime.precommit',before=before,after=digest(path))))
            return super().precommit()
        def tree(self,root):
            if request['case']=='postcommit-drift' and getattr(self,'commit_ready',False):
                write(Path(root),'home/user/config',b'TEST postcommit drift\n')
                Path(request['result']).with_name('fault.json').write_bytes(encoded(dict(stage='Runtime.tree-after-commit')))
            return super().tree(root)
    with host_profile(), patch.object(prior,'Runtime',Fault), ExitStack() as selected:
        for name,value in request['selection'].items():
            selected.enter_context(patch.object(links,name,tuple(value) if name=='CHAIN_PATHS' else value))
        result=prior.apply(args,comparator_path=COMPARATOR)
    Path(request['result']).write_bytes(encoded(result))


def gdb_script(path, trace):
    # GDB observes only this fresh worker and its descendants. No status is inferred
    # from ALPM's ignored helper return or from cache equality.
    path.write_text('''set pagination off
set confirm off
set auto-load off
set auto-solib-add off
set debuginfod enabled off
set detach-on-fork off
set follow-fork-mode parent
set schedule-multiple on
set startup-with-shell off
handle SIGCHLD nostop noprint pass
python
import gdb, json, hashlib
from pathlib import Path
tracked={}
def emit(row):
    with open(TRACE, 'a') as stream: stream.write(json.dumps(row)+'\\n')
def execution():
    inferior=gdb.selected_inferior()
    try:
        data=Path('/proc/%d/exe'%inferior.pid).read_bytes()
        sha=hashlib.sha256(data).hexdigest()
        if sha==HELPER:
            tracked[inferior.num]=inferior.pid
            emit(dict(event='helper-exec',inferior=inferior.num,pid=inferior.pid,sha256=sha,bytes=len(data)))
    except OSError as error: emit(dict(event='exec-read-error',error=str(error)))
def exited(event):
    if event.inferior.num in tracked:
        emit(dict(event='helper-exit',inferior=event.inferior.num,pid=tracked[event.inferior.num],exit=getattr(event,'exit_code',None)))
gdb.events.exited.connect(exited)
end
catch exec
commands
silent
python execution()
continue
end
run
python
while any(inferior.pid for inferior in gdb.inferiors()):
    active=next(inferior for inferior in gdb.inferiors() if inferior.pid)
    gdb.execute('inferior %d'%active.num)
    gdb.execute('continue')
end
'''.replace('import gdb, json, hashlib',f'import gdb, json, hashlib\nTRACE={str(trace)!r}\nHELPER={HOST_FILES["usr/bin/ldconfig"][1]!r}'))


def run_case(sandbox,evidence,mode,signer,public,sign):
    case=sandbox/mode; case.mkdir(mode=0o700)
    exported=evidence/mode; exported.mkdir(mode=0o700)
    source=case/'source'; versions,owned,old=source_root(source)
    helper(source,exported,'source-initialize')
    with host_profile():
        source_before=observe(source)
        (exported/'source-before.json').write_bytes(encoded(source_before))
        with aux_copy.copied_root(source,case/'workspace',limits=limits(),cleanup_seconds=10) as (root,report):
            helper(root,exported,'copied-initialize')  # Bind native keys to copied inodes.
            args=configure(case,root,root.parent,versions,owned,old,signer,public,sign)
            inputs=exported/'inputs'; inputs.mkdir()
            shutil.copytree(case/'bundle',inputs/'bundle')
            for name in ('public.gpg','metadata.json','metadata.json.sig','settings.json','policy.json',
                         'scale.json','prior.pkg.tar.gz','prior.pkg.tar.gz.sig'):
                shutil.copy2(case/name,inputs/name)
            (exported/'input-pins.json').write_bytes(encoded({str(p.relative_to(inputs)):
                dict(bytes=p.stat().st_size,sha256=digest(p)) for p in inputs.rglob('*') if p.is_file()}))
            absolute,mask='usr/share/preserved-link','builder-disabled-hooks/test.hook'
            # Only these two measured links are selected in this host fixture.
            (root/absolute).symlink_to('/usr/lib/libc.so.6'); (root/'builder-disabled-hooks').mkdir()
            (root/mask).symlink_to('/dev/null')
            before=observe(root); caches={n:(root/n).read_bytes() for n in (aux.MAIN_CACHE,aux.AUX_CACHE)}
            for name,data in caches.items(): (exported/('before-'+Path(name).name)).write_bytes(data)
            state=aux.checkpoint(root,before,limits())
            comparator=aux.load_comparator(COMPARATOR,limits())
            joined=aux.live_keys(state,comparator)
            need(joined['records']>0,'nonempty genuine native-library auxiliary keys required')
            selection=dict(CHAIN_PATHS=sorted((absolute,mask)),LINK_NODES={n:before['nodes'][n] for n in (absolute,mask)},
                           RESOLVED_ENDPOINTS={absolute:'usr/lib/libc.so.6'},DATA_ONLY_ENDPOINTS={mask:'dev/null'})
            request=dict(args=args,case=mode,result=str(exported/'result.json'),selection=selection)
            request_path=exported/'request.json'; request_path.write_bytes(encoded(request))
            trace=exported/'helper-trace.jsonl'; script=exported/'observe.gdb'; gdb_script(script,trace)
            row=supervision.run(['/usr/bin/gdb','-nx','-nh','--batch','-x',str(script),'--args',
                '/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),'--worker',str(request_path)],
                env={'PATH':'/usr/bin:/bin','HOME':str(case),'TMPDIR':str(sandbox/'tmp'),'LC_ALL':'C'},cwd=str(case),timeout=45,output_limit=1024**2)
            for name in ('stdout','stderr'): (exported/('worker.'+name)).write_bytes(row.pop(name))
            (exported/'supervision.json').write_bytes(encoded(row))
            need(row['termination'] is None and row['returncode']==0 and row['direct_child_reaped'], 'worker/debugger failed')
            result=json.loads((exported/'result.json').read_bytes()); after=observe(root)
            alpm=roots.Alpm(root,Path(args['public_keyring']).parent,exported/'query-alpm.log',os.uname().machine,limits=limits())
            try: installed=alpm.inventory()
            finally: alpm.close()
            need(installed==(versions if mode=='stale-prior' else dict(versions,selected='2-1')),'actual postcase inventory differs')
            (exported/'inventory.json').write_bytes(encoded(installed))
            for name in (aux.MAIN_CACHE,aux.AUX_CACHE):
                data=(root/name).read_bytes(); (exported/('after-'+Path(name).name)).write_bytes(data)
                need(data==caches[name], 'host fixture requires RAW_EQUAL caches')
            need(all(after['nodes'].get(n)==before['nodes'][n] for n in (absolute,mask,*HOST_FILES)), 'literal/native closure changed')
            for name,value in (('before',before),('after',after)): (exported/(name+'.json')).write_bytes(encoded(value))
            records=[json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
            exits=[r for r in records if r['event']=='helper-exit']; executed=[r for r in records if r['event']=='helper-exec']
            if mode=='stale-prior':
                fault=json.loads((exported/'fault.json').read_bytes())
                need(fault['stage']=='Runtime.precommit' and result['status']=='FAIL' and result['phase']=='prepare'
                     and result['packages_committed'] is False and 'prior input' in result.get('error',''),'real stale prior refusal missing')
                need(before['nodes']==after['nodes'] and not executed,'stale prior changed root/helper')
            else:
                need(result['packages_committed'] is True and result['commit_started'] is True,'real commit did not complete')
                need(len(executed)==len(exits)==1 and exits[0]['exit']==0,'actual helper normal exit0 not observed')
                need((root/'usr/share/selected/data').read_bytes()==b'new data\n' and not (root/'usr/share/selected/retired').exists(),'real payload update/removal missing')
                if mode=='commit': need(result['status']=='PASS' and result['checkpoint_changed'] is True,'positive actual apply failed')
                else: need(result['status']=='FAIL' and result['phase']=='observe-after' and result['checkpoint_changed'] is False,'postcommit failure truth lost')
            need(not (root/'var/lib/pacman/db.lck').exists(),'real ALPM lock leaked')
            need(observe(source)['nodes']==source_before['nodes'],'source mutated')
            summary=dict(case=mode,status='PASS-host-TEST-case',transaction=result,helper_execs=executed,helper_exits=exits,
                capacity=capacity(root),raw_caches='RAW_EQUAL',live_auxiliary_keys=joined,
                comparator_host_source_correspondence='NOT VERIFIED',production_ARM_closure='NOT EXERCISED')
        need(report['cleanup']=='PASS-owned-workspace-removed','owned copied root cleanup failed')
        summary['copy']=report; (exported/'summary.json').write_bytes(encoded(summary))
    shutil.rmtree(case)
    return dict(case=mode,status=summary['status'],evidence=str(exported))


def retire_agents(sandbox,evidence):
    retired=subprocess.run(['/usr/bin/gpgconf','--homedir',str(sandbox/'keys'),'--kill','all'],
                           capture_output=True,timeout=5)
    (evidence/'key-retirement.stdout').write_bytes(retired.stdout)
    (evidence/'key-retirement.stderr').write_bytes(retired.stderr)
    need(retired.returncode==0,'TEST agent retirement failed')
    end=time.monotonic()+5
    while True:
        found=[]
        for process in Path('/proc').iterdir():
            if not process.name.isdigit(): continue
            try:
                argv=(process/'cmdline').read_bytes().split(b'\0')
                if argv[0] and Path(argv[0].decode()).name in ('gpg-agent','dirmngr','scdaemon') and any(
                        str(sandbox).encode() in arg for arg in argv): found.append(int(process.name))
            except (OSError,UnicodeError): pass
        if not found: return dict(gpgconf_exit=retired.returncode,owned_agents_absent=True)
        need(time.monotonic()<end,'owned TEST agent did not retire within5 seconds')
        time.sleep(.05)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker',type=Path)
    parser.add_argument('--sandbox',type=Path); parser.add_argument('--evidence',type=Path)
    args=parser.parse_args()
    if args.worker:
        worker(args.worker)
        return
    fence=fenced(); need(args.sandbox and args.evidence,'explicit sandbox/evidence required')
    need(os.getuid()==0 and not any(args.sandbox.iterdir()),'fresh mapped-root empty sandbox required')
    mapping=Path('/proc/self/uid_map').read_text().split()
    need(len(mapping)==3 and mapping[0]=='0' and int(mapping[1])>0 and mapping[2]=='1','owned one-UID user namespace required')
    interfaces={line.split(':',1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines() if ':' in line}
    need(interfaces=={'lo'},'private network namespace required')
    mount_target=args.sandbox.absolute()
    subprocess.run(['/usr/bin/mount','-t','tmpfs','-o','size=67108864,nr_inodes=20000,nodev,nosuid,mode=0700','tmpfs',str(mount_target)],check=True,timeout=5)
    status={'status':'FAIL','profile':PROFILE,'native_file_pins':HOST_FILES,'ALPM_pin':ALPM_SHA,'fence':fence,'cases':[],
        'production_helper_binding':'OVERRIDDEN ONLY BY FIXED TEST PROFILE',
        'production_ARM_closure':'NOT EXERCISED','comparator_host_source_correspondence':'NOT VERIFIED'}
    primary=None
    try:
        (args.sandbox/'tmp').mkdir(mode=0o700); os.environ['TMPDIR']=str(args.sandbox/'tmp')
        with signing(args.sandbox/'keys') as (signer,public,sign):
            for mode in CASES:
                status['active_case']=mode
                status['cases'].append(run_case(args.sandbox,args.evidence,mode,signer,public,sign))
            status.pop('active_case',None)
        status['status']='PASS-host-TEST-lifecycle'
    except BaseException as error:
        primary=error
        status['primary_error']=dict(type=type(error).__name__,message=str(error)[:2048])
    finally:
        status['case_status']=status['status']
        errors=[]
        def attempt(stage,action):
            try: return action()
            except BaseException as error:
                errors.append(dict(stage=stage,type=type(error).__name__,message=str(error)[:2048]))
        status['resource_peak']={n:attempt('resource_peak/'+n,
            lambda n=n:(Path(fence['group'])/n).read_text().strip()) for n in ('memory.peak','pids.peak')}
        def agents():
            result=retire_agents(args.sandbox,args.evidence)
            need(isinstance(result,dict) and result.get('gpgconf_exit')==0
                 and result.get('owned_agents_absent') is True,'owned TEST agent absence unverified')
            return result
        status['key_retirement']=attempt('key_retirement',agents)
        if status['key_retirement'] is None:
            status['key_retirement']=dict(gpgconf_exit=None,owned_agents_absent=None,status='UNKNOWN')
        attempt('leave_mount',lambda:os.chdir(HERE))
        def unmount():
            result=subprocess.run(['/usr/bin/umount',str(mount_target)],capture_output=True,timeout=5)
            status['unmount']=dict(exit=result.returncode,stderr=result.stderr.decode(errors='replace'))
            need(result.returncode==0,'private fixture unmount failed')
        status['unmount']=dict(exit=None,stderr=None,status='UNKNOWN')
        attempt('unmount',unmount)
        status['cleanup']=dict(status='HOLD' if errors else 'PASS',errors=errors)
        if errors: status['status']='FAIL-cleanup'
        status['report_write']=dict(status='PASS')
        written=attempt('report_write',lambda:(args.evidence/'lifecycle.json').write_bytes(encoded(status)))
        if written is None:
            status['status']='FAIL-cleanup'
            status['cleanup']['status']='HOLD'
            status['report_write']=dict(status='FAIL')
            attempt('report_fallback',lambda:print(json.dumps(status,sort_keys=True),file=sys.stderr))
    if primary is not None: raise primary
    need(not errors,'private fixture cleanup/report unverified')


if __name__=='__main__': main()

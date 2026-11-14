#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite x86 NetworkManager candidate TEST-repository journey; container only."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import signal
import stat
import tarfile
import traceback

NAMES={'networkmanager','libnm','nm-cloud-setup','networkmanager-docs'}
VERSION='1.58.1-2.1'
INPUT=Path('/opt/nm-journey-input')
ROOT=Path('/scratch/system')
CONFIG='etc/NetworkManager/NetworkManager.conf'
USER_FILES={
 'etc/NetworkManager/conf.d/70-TEST-user.conf':b'# TEST user-owned networking preferences; never activated\n',
 'etc/NetworkManager/system-connections/TEST-user.nmconnection':b'# TEST inert user connection sentinel; never read by a daemon\n',
 'etc/TEST-unrelated.conf':b'TEST unrelated administrator state\n',
 'home/TEST/.config/TEST-preserve':b'TEST ordinary user state\n',
}
EDIT=b'# TEST edited package backup; recovery must be explicit\n[main]\nplugins=keyfile\n'


def load_repository():
    spec=importlib.util.spec_from_file_location('nm_journey_repository',INPUT/'repository.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    return mod


def archive(path):
    """Read bounded members as DATA, never extract source or follow archive links."""
    leaves={};info={};total=0;seen=set()
    with tarfile.open(path)as tar:
        members=tar.getmembers();assert len(members)<2048
        for m in members:
            name=m.name.removeprefix('./').rstrip('/')
            assert name and not name.startswith('/') and '..'not in Path(name).parts and Path(name).as_posix()==name
            assert name not in seen,name
            seen.add(name)
            assert not m.mode&0o6000 and m.uid==m.gid==0 and not m.issparse()
            assert m.isfile()or m.isdir()or m.issym(),name
            if m.isdir():continue
            assert name not in leaves,name
            if name.startswith('.'):
                assert name in {'.PKGINFO','.BUILDINFO','.MTREE'},name
                assert m.isfile()and m.size<2*1024**2
                if name=='.PKGINFO':
                    for line in tar.extractfile(m).read().decode().splitlines():
                        if line and not line.startswith('#'):
                            k,v=line.split(' = ',1);info.setdefault(k,[]).append(v)
                continue
            assert not name.startswith(('usr/share/libalpm/hooks/','etc/pacman','boot/','var/lib/NetworkManager/','etc/resolv.conf')),name
            assert not name.startswith('etc/NetworkManager/system-connections/'),name
            row={'type':'symlink'if m.issym()else'regular','mode':m.mode,'uid':m.uid,'gid':m.gid}
            if m.issym():
                assert not Path(m.linkname).is_absolute()
                parts=list(Path(name).parent.parts)
                for part in Path(m.linkname).parts:
                    if part=='..':assert parts;parts.pop()
                    elif part!='.':parts.append(part)
                row['target']=m.linkname
            else:
                total+=m.size;assert m.size<=32*1024**2 and total<=128*1024**2
                row['sha256']=hashlib.sha256(tar.extractfile(m).read()).hexdigest()
            leaves[name]=row
    assert info['pkgname'][0]in NAMES and info['pkgver']==[VERSION]and info['arch']==['x86_64']
    assert leaves and len(info['pkgname'])==1
    return {'name':info['pkgname'][0],'version':VERSION,'path':path,'leaves':leaves,'info':info}


def all_absent(records,state):
    return all(state(name)['type']=='missing'for row in records.values()for name in row['leaves'])


def execute():
    if not __debug__:raise RuntimeError('optimized Python refused; assertions are acceptance checks')
    if not(os.geteuid()==0 and platform.machine()=='x86_64'and Path('/.dockerenv').is_file()and os.environ.get('CACHY_ASAHI_NM_TEST_CONTAINER')=='1'):
        raise RuntimeError('explicit x86 TEST container required before loading the held helper')
    R=load_repository()
    class Journey(R.Integration):
        def command(self,label,argv,**kw):
            R.need(not any(str(x)in {'systemctl','NetworkManager','/usr/bin/NetworkManager','/usr/bin/nm-cloud-setup'}for x in argv),'daemon/service command refused')
            return super().command(label,argv,**kw)

        def inventory(self,label):
            return R.package_inventory(self.pacman(label,['-Q']))

        def snapshot(self,label):
            value=self.inventory(label),{p:R.owned_state(ROOT,p)for p in self.observed_paths}
            R.write(self.out/(label+'-snapshot.json'),{'inventory':value[0],'files':value[1]})
            return value

        def installed(self,label,edited=False):
            assert self.inventory(label+'-inventory')==dict(self.base_versions,**{n:VERSION for n in NAMES})
            self.pacman(label+'-dependencies',['-Dk'])
            for name,row in self.packages.items():
                text=self.pacman(label+'-ownership-'+name,['-Ql',name]);owned=set()
                for line in text.splitlines():
                    identity,p=line.split(maxsplit=1);assert identity==name
                    rel=Path(p).relative_to(ROOT).as_posix()
                    if not p.endswith('/'):owned.add(rel)
                assert owned==set(row['leaves']),(name,owned^set(row['leaves']))
                for rel,wanted in row['leaves'].items():
                    actual=R.owned_state(ROOT,rel)
                    if edited and rel==CONFIG:wanted=dict(wanted,sha256=hashlib.sha256(EDIT).hexdigest())
                    assert actual==wanted,(rel,actual,wanted)
            assert not (ROOT/'usr/lib/systemd/system/NetworkManager.service.d/NetworkManager-ovs.conf').exists()
            example=ROOT/'usr/share/doc/networkmanager/NetworkManager-ovs.conf.example'
            assert example.is_file()
            self.preserve()
            self.cases.append({'name':label,'result':'PASS_EXACT_INVENTORY_OWNERSHIP_BYTES_DEPS','edited_backup':edited})

        def preserve(self):
            for rel,data in USER_FILES.items():
                actual=R.owned_state(ROOT,rel)
                assert actual==self.user_states[rel]and (ROOT/rel).read_bytes()==data,rel
            for rel,wanted in self.base_files.items():assert R.owned_state(ROOT,rel)==wanted,rel

        def removed(self,label):
            assert self.inventory(label+'-inventory')==self.base_versions
            assert all_absent(self.packages,lambda p:R.owned_state(ROOT,p))
            assert (ROOT/(CONFIG+'.pacsave')).read_bytes()==EDIT
            self.pacman(label+'-dependencies',['-Dk']);self.preserve()
            self.cases.append({'name':label,'result':'PASS_PACKAGE_LEAVES_ABSENT_BASE_AND_USER_PRESERVED'})

    j=Journey({'source_commit':json.loads((INPUT/'contract.json').read_text())['source_commit']})
    j.result.update(purpose='NetworkManager candidate x86 TEST repository lifecycle',native_ARM='NOT RUN',M2='NOT RUN',release_acceptance='HOLD',historical_ALARM_correspondence='UNBOUND')
    try:
        assert os.geteuid()==0 and platform.machine()=='x86_64'and Path('/.dockerenv').is_file(),'container root/x86/marker'
        assert os.environ.get('CACHY_ASAHI_NM_TEST_CONTAINER')=='1'
        assert set(p.name for p in Path('/sys/class/net').iterdir())=={'lo'}
        assert not any(Path(p).exists()for p in ['/run/docker.sock','/var/run/docker.sock','/run/dbus/system_bus_socket','/dev/net','/dev/dri','/dev/snd'])
        R.privileges(Path('/proc/self/status').read_text())
        mounts=R.mounts(Path('/proc/self/mountinfo').read_text())
        allowed={'/'}|set(R.STANDARD_MOUNTS)|R.RUNTIME_FILES|set(R.STANDARD_DEVICES)|{'/usr/bin/docker-init'}
        assert set(mounts)<=allowed,sorted(set(mounts)-allowed)
        for path,(major,minor)in R.STANDARD_DEVICES.items():
            node=Path(path).stat();assert stat.S_ISCHR(node.st_mode)and(os.major(node.st_rdev),os.minor(node.st_rdev))==(major,minor),path
        init=Path('/usr/bin/docker-init');assert init.is_file()and not init.stat().st_mode&0o022
        assert 'ro'in mounts['/usr/bin/docker-init']['options']
        assert all(not p.is_symlink()and p.is_file()and p.stat().st_uid==0 and not stat.S_IMODE(p.stat().st_mode)&0o222 for p in INPUT.iterdir())
        j.result['guard']={'network':'none/lo-only','caller_mounts':False,'standard_runtime_mounts':'Docker metadata, default character devices and read-only docker-init','host_bus':False,'capabilities':sorted(['CHOWN','DAC_OVERRIDE','FOWNER','SETGID','SETUID','SYS_CHROOT']),'scriptlets':False,'hooks':'every copied hook name masked with /dev/null','daemon_service_execution':False}
        contract=json.loads((INPUT/'contract.json').read_text());j.packages={}
        for filename in ['journey.py','repository.py']:assert R.sha(INPUT/filename)==contract['source_pins'][filename]
        for ref in contract['archives']:
            path=INPUT/ref['name'];assert path.stat().st_size==ref['bytes']and R.sha(path)==ref['sha256']
            row=archive(path);assert row['name']not in j.packages;j.packages[row['name']]=row
        assert set(j.packages)==NAMES
        paths=[p for row in j.packages.values()for p in row['leaves']];assert len(set(paths))==len(paths)
        j.result['input_archives']=contract['archives']
        j.copy_base()
        hooks={p.name for directory in [ROOT/'usr/share/libalpm/hooks',ROOT/'etc/pacman.d/hooks']for p in directory.glob('*.hook')}
        masks={p.name:os.readlink(p)for p in (Path('/scratch/masked-hooks')).iterdir()}
        assert set(masks)==hooks and all(v=='/dev/null'for v in masks.values())
        j.result['masked_hook_names']=sorted(hooks)
        assert all_absent(j.packages,lambda p:R.owned_state(ROOT,p)),'candidate leaves must not overwrite base files'
        # Mirror Arch's root aliases for CLI execution/ldconfig, entirely inside scratch.
        for name in ('bin','sbin','lib','lib64'):
            assert Path('/'+name).is_symlink();(ROOT/name).symlink_to(os.readlink('/'+name))
        j.key('verifier','cert')
        j.base_versions=j.inventory('baseline-inventory');assert not NAMES&set(j.base_versions)
        j.base_files={rel:R.owned_state(ROOT,rel)for rel in ['usr/bin/pacman','usr/lib/libc.so.6','etc/os-release']}
        j.user_states={}
        for rel,data in USER_FILES.items():
            p=ROOT/rel;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data);p.chmod(0o600)
            if rel.startswith('home/'):os.chown(p,1000,1000)
            j.user_states[rel]=R.owned_state(ROOT,rel)
        j.observed_paths=set(paths)|set(USER_FILES)|set(j.base_files)
        j.result['baseline_file_pins']=j.base_files;j.result['user_file_pins']=j.user_states
        j.key('signer','sign')
        # Keys/trust remain private TEST-only, independent of all system keyrings.
        repo=Path('/scratch/repos/active');repo.mkdir(parents=True)
        for row in j.packages.values():
            dest=repo/row['path'].name;shutil.copyfile(row['path'],dest);j.sign(dest,'signer')
        key=j.keys['signer'];(key['home']/'gpg.conf').write_text('no-auto-key-retrieve\nno-default-keyring\nkeyring '+str(key['home']/'pubring.gpg')+'\n')
        env=dict(os.environ,GNUPGHOME=str(key['home']),TMPDIR='/scratch')
        j.add_database('nm-candidate',repo/'integration.db.tar.gz',sorted(repo.glob('*.pkg.tar.zst')),key['fingerprint'],env)
        for name in ['integration.db.tar.gz','integration.files.tar.gz']:
            status=j.command('validate-'+name,j.gpg(key['home'])+['--status-fd','1','--verify',str(repo/name)+'.sig',repo/name]);R.signature_status(status,key['fingerprint'])
        # copy_base intentionally preserves frozen helper policy; this new adapter
        # explicitly selects x86 only, without changing its ARM actor or guard.
        strict=R.STRICT_OPTIONS.replace('aarch64','x86_64')
        j.query_config.write_text(strict);j.config.write_text(strict+R.STRICT_REPOSITORY)
        before=j.snapshot('before-unknown-key')
        j.pacman('unknown-TEST-key-refused',['-Syy','--noscriptlet'],reject=True)
        assert j.snapshot('after-unknown-key')==before
        j.cases.append({'name':'unknown-TEST-key','result':'PASS_REFUSAL_UNCHANGED'})
        j.trust('signer');j.pacman('trusted-TEST-database',['-Syy','--noscriptlet'])
        victim=repo/j.packages['libnm']['path'].name;original=victim.read_bytes();bad=bytearray(original);bad[len(bad)//2]^=1;victim.write_bytes(bad)
        before=j.snapshot('before-tamper')
        output=j.pacman('archive-byte-tamper-refused',['-S','--noscriptlet',*sorted(NAMES)],reject=True)
        assert any(word in output.lower()for word in ['invalid','corrupted','checksum','signature'])
        assert j.snapshot('after-tamper')==before
        victim.write_bytes(original);assert R.sha(victim)==R.sha(j.packages['libnm']['path'])
        shutil.rmtree('/scratch/cache');Path('/scratch/cache').mkdir()
        j.cases.append({'name':'archive-byte-tamper','result':'PASS_REFUSAL_UNCHANGED'})
        j.pacman('install-all-four',['-S','--noscriptlet',*sorted(NAMES)]);j.installed('installed')
        version=j.command('installed-nmcli-version',['chroot',ROOT,'/usr/bin/nmcli','--version']);assert '1.58.1'in version
        gir=j.command('installed-GIR-pure-settings',['chroot',ROOT,'/usr/bin/python3','-I','-c',"import gi;gi.require_version('NM','1.0');from gi.repository import NM;assert(NM.MAJOR_VERSION,NM.MINOR_VERSION)==(1,58);s=NM.SettingWired.new();assert s.get_name()=='802-3-ethernet';print('NM1.58 GIR setting construction PASS; no Client/bus/daemon')"])
        j.result['runtime_smoke']={'nmcli_version':version.strip(),'introspection':gir.strip(),'no_daemon_or_bus':True}
        (ROOT/CONFIG).write_bytes(EDIT)
        j.pacman('remove-all-four',['-R','--noscriptlet',*sorted(NAMES)]);j.removed('removed')
        recovery=ROOT/'home/TEST/retained-NetworkManager.conf';shutil.copyfile(ROOT/(CONFIG+'.pacsave'),recovery);(ROOT/(CONFIG+'.pacsave')).unlink()
        j.pacman('reinstall-all-four',['-S','--noscriptlet',*sorted(NAMES)]);j.installed('reinstalled')
        assert recovery.read_bytes()==EDIT
        # Explicit administrator recovery; pacman must not invent this policy.
        shutil.copyfile(recovery,ROOT/CONFIG)
        j.pacman('repeat-install-preserves-edit',['-S','--noscriptlet',*sorted(NAMES)]);j.installed('repeat-installed',edited=True)
        assert not (ROOT/(CONFIG+'.pacnew')).exists()
        j.pacman('final-remove-all-four',['-R','--noscriptlet',*sorted(NAMES)]);j.removed('final-removed')
        assert recovery.read_bytes()==EDIT
        j.result.update(status='PASS_X86_TEST_REPOSITORY_LIFECYCLE_ONLY',package_leaf_counts={n:len(p['leaves'])for n,p in j.packages.items()},baseline_package_count=len(j.base_versions),final_package_owned_leaves_absent=True,user_and_unrelated_preserved=True,config_recovery='pacsave verified; explicit copy recovery; repeated install preserved edit; final pacsave retained',source_and_legal_acceptance='HOLD; no historical binding/new legal decision')
    except BaseException as error:
        j.result.update(status='HOLD_FAILURE',failure={'category':type(error).__name__,'message':str(error)[:2048],'traceback':traceback.format_exc(limit=8)[-4096:]})
    finally:
        try:j.cleanup()
        except BaseException as error:j.result.update(status='HOLD_CLEANUP_FAILURE',cleanup_failure=str(error)[:2048])
        R.write(Path('/out/report.json'),j.result)
        print(json.dumps({'status':j.result['status'],'failure':j.result.get('failure'),'commands':len(j.receipts)}),flush=True)
    return 0 if j.result['status']=='PASS_X86_TEST_REPOSITORY_LIFECYCLE_ONLY'else 1


def main():
    p=argparse.ArgumentParser();p.add_argument('--allow-disposable-x86-TEST-journey',action='store_true');args=p.parse_args()
    if not args.allow_disposable_x86_TEST_journey:p.error('explicit TEST-only opt-in required')
    def expired(*_):raise TimeoutError('450-second whole guest journey deadline')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,expired);signal.alarm(450)
    return execute()


if __name__=='__main__':raise SystemExit(main())

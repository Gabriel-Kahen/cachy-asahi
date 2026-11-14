#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed x86 Perl candidate lifecycle in a mount-free, offline Docker root."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import sys
import tarfile
import time

HERE = Path('/opt/perl-candidate')
sys.path.insert(0, str(HERE/'support'))
import lifecycle
import repository
import virtual_common as virtual
import glibc_abi as abi

need = virtual.require
sha = virtual.digest
DEADLINE = time.monotonic() + 165
REPORT = {'schema': 1, 'status': 'RUNNING', 'commands': [], 'checks': []}
OUT = Path('/tmp/perl-result')


def command(argv, *, allowed=(0,), data=None, timeout=30):
    remaining = min(timeout, DEADLINE-time.monotonic())
    need(remaining > 0, 'aggregate deadline exhausted')
    value = lifecycle.bounded_process(argv, timeout=remaining, stdout_limit=2*1024**2,
        stderr_limit=256*1024, env=dict(PATH='/usr/bin:/bin', HOME='/tmp', LC_ALL='C', TZ='UTC'), stdin=data)
    REPORT['commands'].append(dict(argv=list(map(str, argv)), **{
        k: v.decode(errors='replace') if isinstance(v, bytes) else v for k,v in value.items()}))
    need(value['reason']=='exit' and value['returncode'] in allowed, 'command failed: '+str(argv))
    return value['stdout'].decode(errors='strict'), value['stderr'].decode(errors='strict')


def check(name, value):
    REPORT['checks'].append(dict(name=name, passed=bool(value)))
    need(value, name)


def guard():
    need(Path(__file__).resolve()==HERE/'container.py' and Path('/.dockerenv').is_file()
         and os.geteuid()==0 and platform.machine()=='x86_64', 'fixed disposable x86 Docker root required')
    need(os.environ.get('CACHY_ASAHI_PERL_TEST')=='1', 'explicit container opt-in required')
    mounts=repository.mounts(Path('/proc/self/mountinfo').read_text())
    permitted={'/'} | repository.RUNTIME_FILES | set(repository.STANDARD_MOUNTS) | set(repository.STANDARD_DEVICES)
    need(set(mounts)<=permitted and mounts['/']['fs'] in {'overlay','fuse-overlayfs'}
         and mounts['/']['root']=='/' and 'rw' in mounts['/']['options'], 'caller mounts or non-disposable root refused')
    for name in repository.RUNTIME_FILES:
        need(name in mounts and mounts[name]['fs'] in repository.BIND_FILESYSTEMS, 'Docker metadata mount required')
    for name in set(repository.STANDARD_DEVICES)&set(mounts):
        need(mounts[name]['fs']=='devtmpfs' and mounts[name]['root']=='/'+Path(name).name
             and {'rw','nosuid'}<=mounts[name]['options'], 'exact rootless Docker standard-device bind required')
    repository.privileges(Path('/proc/self/status').read_text())
    repository.validate_exposure(repository.exposed_nodes())
    need(not any(Path(p).exists() for p in ('/run/docker.sock','/var/run/docker.sock','/dev/dri','/dev/snd','/dev/input','/dev/kvm')), 'device/bus/socket refused')
    need({p.name for p in Path('/sys/class/net').iterdir()}=={'lo'}, 'network-none required')
    resources={name:Path('/sys/fs/cgroup/'+name).read_text().strip() for name in ('cpu.max','memory.max','pids.max')}
    need(resources=={'cpu.max':'200000 100000','memory.max':'4294967296','pids.max':'256'}, 'exact cgroup resources required')
    REPORT['environment']=dict(architecture=platform.machine(), page_bytes=os.sysconf('SC_PAGE_SIZE'),
        interfaces=['lo'], mounts=sorted(mounts), resources=resources, caller_mounts=0)


def mask_hooks():
    target=Path('/etc/pacman.d/hooks');target.mkdir(parents=True,exist_ok=True)
    for source in Path('/usr/share/libalpm/hooks').glob('*.hook'):
        dest=target/source.name
        need(not dest.exists() and not dest.is_symlink(), 'preexisting hook override refused')
        dest.symlink_to('/dev/null')
    REPORT['hooks_masked']=len(list(target.glob('*.hook')))
    need(REPORT['hooks_masked']>0, 'expected preinstalled hooks')


def config(keyring, name):
    path=Path('/tmp')/name
    path.write_text('[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\n'
        'LocalFileSigLevel = Required TrustedOnly\nGPGDir = '+str(keyring)+'\n'
        'HookDir = /etc/pacman.d/hooks\nCacheDir = /tmp/perl-cache\nLogFile = /tmp/perl-pacman.log\n'
        'DisableSandboxFilesystem\n')
    Path('/tmp/perl-cache').mkdir(exist_ok=True)
    return path


def prepare():
    guard();OUT.mkdir()
    contract=json.loads((HERE/'manifest.json').read_bytes())
    for name,pin in contract['inputs'].items():
        p=HERE/'inputs'/name
        need(p.is_file() and not p.is_symlink() and p.stat().st_size==pin['bytes'] and sha(p)==pin['sha256'], 'input pin: '+name)
    db=HERE/'inputs/core.db';pkg=HERE/'inputs/db5.3.pkg.tar.zst';sig=Path(str(pkg)+'.sig')
    with tarfile.open(db) as archive:
        members=[m for m in archive if m.name.startswith('db5.3-') and m.name.endswith('/desc')]
        need(len(members)==1, 'one frozen db5.3 repository entry')
        fields={};key=None
        for line in archive.extractfile(members[0]).read().decode().splitlines():
            if line.startswith('%') and line.endswith('%'):key=line[1:-1];fields[key]=[]
            elif line and key:fields[key].append(line)
    need(fields['VERSION']==['5.3.28-7'] and fields['SHA256SUM']==[sha(pkg)] and
         base64.b64decode(fields['PGPSIG'][0])==sig.read_bytes(), 'frozen repository package/signature join')
    status,_=command(['gpg','--homedir','/etc/pacman.d/gnupg','--batch','--status-fd','1','--verify',str(sig),str(pkg)])
    need('[GNUPG:] VALIDSIG ' in status, 'official prerequisite signature required')
    mask_hooks();conf=config('/etc/pacman.d/gnupg','official-prerequisite.conf')
    before=virtual.inventory(command(['pacman','--config',str(conf),'-Q'])[0])
    need('perl' not in before and 'db5.3' not in before, 'exact absent Perl/db5.3 starting baseline')
    command(['pacman','--config',str(conf),'--noconfirm','--noscriptlet','-U',str(pkg)])
    after=virtual.inventory(command(['pacman','--config',str(conf),'-Q'])[0])
    check('only exact db5.3 prerequisite added',after==dict(before,**{'db5.3':'5.3.28-7'}))
    REPORT.update(status='PASS_FROZEN_SIGNED_PREREQUISITE', inventory=after,
        prerequisite_frozen_repository=contract['prerequisite'], official_signature_status=status)
    (HERE/'prepared.json').write_text(json.dumps(REPORT,sort_keys=True,indent=2)+'\n')


def nodes(paths):
    result={}
    for name in sorted(paths):
        path=Path('/')/name
        if not path.exists() and not path.is_symlink():result[name]=None;continue
        info=path.lstat();row=dict(mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid)
        if stat.S_ISLNK(info.st_mode):row.update(type='link',target=os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):row.update(type='directory')
        else:
            need(stat.S_ISREG(info.st_mode),'ordinary installed node required')
            row.update(type='file',sha256=sha(path),bytes=info.st_size)
        result[name]=row
    return result


def payload(path):
    result={}
    with tarfile.open(path) as archive:
        for item in archive:
            name=item.name.removeprefix('./').rstrip('/')
            if name.startswith('.'):continue
            need((name=='usr' or name.startswith('usr/')) and '..' not in Path(name).parts, 'bounded Perl usr payload required')
            row=dict(mode=item.mode,uid=item.uid,gid=item.gid)
            if item.isdir():row.update(type='directory')
            elif item.issym():row.update(type='link',target=item.linkname)
            else:
                need(item.isfile() or item.islnk(),'ordinary Perl payload')
                body=archive.extractfile(item).read();row.update(type='file',bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
            result[name]=row
    return result


def vendor_fixture(path):
    files={'usr/share/perl5/vendor_perl/CandidateSentinel.pm':b'1; # TEST VENDOR SENTINEL\n',
        'usr/lib/perl5/5.42/vendor_perl/auto/CandidateSentinel/CandidateSentinel.so':b'TEST XS PRESERVATION SENTINEL, NOT LOADABLE\n',
        'usr/bin/vendor_perl/candidate-sentinel':b'#!/usr/bin/perl\nprint "TEST VENDOR\\n";\n',
        'etc/perl-candidate-vendor-TEST.conf':b'pristine TEST fixture config\n'}
    info='pkgname = perl-candidate-vendor-TEST\npkgver = 1-1\narch = any\npkgdesc = Synthetic TEST ONLY ownership fixture, not functional XS\nlicense = MIT\noptdepend = perl: TEST command interpreter\nbackup = etc/perl-candidate-vendor-TEST.conf\nsize = 512\n'
    with tarfile.open(path,'w:xz') as archive:
        for name,body in {'.PKGINFO':info.encode(),**files}.items():
            item=tarfile.TarInfo(name);item.size=len(body);item.mode=0o755 if name.startswith('usr/bin/') else 0o644
            archive.addfile(item,io.BytesIO(body))
    return set(files)


def main():
    guard()
    if OUT.exists():
        need({p.name for p in OUT.iterdir()}=={'result.json'} and
             json.loads((OUT/'result.json').read_bytes())['status']=='PASS_FROZEN_SIGNED_PREREQUISITE', 'only prepared output may be reset')
        shutil.rmtree(OUT)
    OUT.mkdir(exist_ok=False)
    prepared=json.loads((HERE/'prepared.json').read_bytes());REPORT['prepared_inventory']=prepared['inventory']
    need(prepared['status']=='PASS_FROZEN_SIGNED_PREREQUISITE','verified prepared image required')
    contract=json.loads((HERE/'manifest.json').read_bytes())
    for name,row in contract['inputs'].items():
        need(sha(HERE/'inputs'/name)==row['sha256'],'immutable input:'+name)
    old=HERE/'inputs/old.pkg.tar.zst';candidate=HERE/'inputs/candidate.pkg.tar.zst'
    oldnodes=payload(old);newnodes=payload(candidate);allpaths=set(oldnodes)|set(newnodes)
    need(not any(n.startswith('usr/local/') or '/vendor_perl/' in n for n in allpaths),'operator/vendor package paths refused')
    for p in (old,candidate):
        with tarfile.open(p) as t:
            info=t.extractfile('.PKGINFO').read().decode()
            need(not any(line.startswith('backup = ') for line in info.splitlines()),'candidate backup policy changed')
    sign=Path('/tmp/perl-sign');trust=Path('/tmp/perl-trust')
    for p in (sign,trust):p.mkdir(mode=0o700)
    gpg=['gpg','--homedir',str(sign),'--batch','--pinentry-mode','loopback','--passphrase','']
    command(gpg+['--quick-generate-key','Perl Candidate TEST ONLY <perl-test.invalid>','ed25519','sign','1d'])
    keys=command(gpg+['--with-colons','--list-secret-keys'])[0]
    fingerprint=next(line.split(':')[9] for line in keys.splitlines() if line.startswith('fpr:'))
    public=OUT/'TEST-public.asc'
    command(gpg+['--armor','--output',str(public),'--export',fingerprint])
    command(['pacman-key','--gpgdir',str(trust),'--init'])
    conf=config(trust,'perl-test.conf')
    pacman=['pacman','--config',str(conf),'--noconfirm','--noscriptlet']
    query=['pacman','--config',str(conf)]
    def inventory():return virtual.inventory(command(query+['-Q'])[0])
    initial=inventory();need(initial==prepared['inventory'],'prepared inventory drift')
    def sign_file(path):
        command(gpg+['--output',str(path)+'.sig','--detach-sign',str(path)])
        output,_=command(['gpg','--homedir',str(trust),'--batch','--status-fd','1','--verify',str(path)+'.sig',str(path)])
        repository.signature_status(output,fingerprint)
    # Sign first, then prove ALPM refuses that exact package before trust import.
    command(gpg+['--output',str(candidate)+'.sig','--detach-sign',str(candidate)])
    before=nodes(allpaths);out,err=command(pacman+['-U',str(candidate)],allowed=(1,))
    check('initialized TEST keyring refuses specifically missing signer', 'required key missing from keyring' in err and 'keyring is not writable' not in err and 'Public keyring not found' not in err)
    check('unknown TEST key refuses without inventory/payload mutation',inventory()==initial and nodes(allpaths)==before)
    REPORT['unknown_key_refusal']=dict(stdout=out,stderr=err)
    command(['gpg','--homedir',str(trust),'--batch','--import',str(public)])
    command(['gpg','--homedir',str(trust),'--batch','--import-ownertrust'],data=fingerprint+':6:\n')
    command(['gpg','--homedir',str(trust),'--batch','--check-trustdb'])
    sign_file(old)
    vendor=Path('/tmp/vendor.pkg.tar.xz');sentinels=vendor_fixture(vendor);sign_file(vendor)
    command(pacman+['-U',str(old),str(vendor)])
    baseline_inventory=inventory();check('r3 and vendor fixture installed',baseline_inventory==dict(initial,perl='5.42.3-1.1',**{'perl-candidate-vendor-TEST':'1-1'}))
    check('actual r3 payload matches retained archive',nodes(oldnodes)==oldnodes)
    local={'usr/local/bin/candidate-sentinel':b'OPERATOR COMMAND\n','usr/local/share/perl5/site_perl/LocalSentinel.pm':b'OPERATOR MODULE\n',
           'usr/local/lib/perl5/5.42/site_perl/LocalSentinel.so':b'OPERATOR XS SENTINEL, NOT LOADABLE\n',
           'etc/profile.d/perl-candidate-operator.sh':b'# OPERATOR PROFILE\n'}
    for name,body in local.items():
        p=Path('/')/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(body);p.chmod(0o640);os.chown(p,1000,1000)
    sentinels|=set(local);configfile=Path('/etc/perl-candidate-vendor-TEST.conf');configfile.write_text('operator changed TEST config\n')
    preserved=nodes(sentinels);baseline=nodes(allpaths)
    sentinel_inodes={n:(Path('/')/n).stat().st_ino for n in sentinels}
    unknown=Path('/tmp/perl-unknown-trust');unknown.mkdir(mode=0o700)
    command(['pacman-key','--gpgdir',str(unknown),'--init'])
    out,err=command(pacman+['--gpgdir',str(unknown),'-U',str(candidate)],allowed=(1,))
    check('installed refusal is specifically unknown signer', 'required key missing from keyring' in err and 'keyring is not writable' not in err and 'Public keyring not found' not in err)
    check('installed r3 unknown-key refusal preserves full state',inventory()==baseline_inventory and nodes(allpaths)==baseline and nodes(sentinels)==preserved)
    REPORT['installed_unknown_key_refusal']=dict(stdout=out,stderr=err)
    tampered=Path('/tmp/tampered.pkg.tar.zst');tampered.write_bytes(candidate.read_bytes()+b'PERL-TEST-TAMPER')
    shutil.copyfile(str(candidate)+'.sig',str(tampered)+'.sig')
    out,err=command(pacman+['-U',str(tampered)],allowed=(1,))
    check('tampered archive specifically fails PGP signature', 'invalid or corrupted package (PGP signature)' in err)
    check('tamper refuses with exact inventory/payload/sentinel preservation',inventory()==baseline_inventory and nodes(allpaths)==baseline and nodes(sentinels)==preserved)
    REPORT['tamper_refusal']=dict(stdout=out,stderr=err)
    transitions=[]
    def state(name,version,expected):
        check(name+' inventory',inventory()==dict(baseline_inventory,perl=version))
        check(name+' payload',nodes(expected)==expected)
        check(name+' sentinels',nodes(sentinels)==preserved)
        check(name+' sentinel inodes',all((Path('/')/n).stat().st_ino==inode for n,inode in sentinel_inodes.items()))
        transitions.append(dict(stage=name,perl=version,inventory=inventory()))
    command(pacman+['-U',str(candidate)]);state('upgrade','5.42.3-1.2',newnodes)
    smoke=command(['python3','-B',str(HERE/'smoke/test_staged_commands.py'),'--inside'],timeout=45)[0]
    REPORT['installed_command_smoke']=json.loads(smoke)
    REPORT['installed_command_smoke_context']='Reused no-install smoke called after actual ALPM installation and exact installed payload match'
    command(['perl',str(HERE/'smoke/check_config.pl'),str(HERE/'smoke/provides.txt')])
    # Existing source-only glibc ELF helpers establish a bounded symbol join;
    # actual external XS and target ABI remain separate gates.
    exports=set()
    for name in ('libc.so.6','libm.so.6','ld-linux-x86-64.so.2'):
        exports|={r[0].replace('@@','@') for r in abi.symbols(abi.readelf(Path('/usr/lib')/name,'--dyn-syms'))}
    required=set()
    for name in ('usr/bin/perl','usr/lib/perl5/5.42/core_perl/CORE/libperl.so'):
        text=abi.readelf(Path('/')/name,'--dyn-syms')
        required|={line.split()[7] for line in text.splitlines() if len(line.split())>=8 and line.split()[6]=='UND' and '@GLIBC_' in line.split()[7]}
    check('nonempty Perl/libperl public glibc symbol requirements resolve',required and required<=exports)
    REPORT['bounded_glibc_symbol_join']=dict(requirements=len(required),missing=sorted(required-exports),scope='HOST_SYMBOL_NAMES_VERSIONS_ONLY_NOT_TARGET_ABI')
    aliases=[n for n,r in newnodes.items() if n.startswith('usr/bin/') and r['type']=='link']
    owned=command(query+['-Qoq',*['/'+n for n in aliases]])[0].splitlines();check('all29 aliases ALPM owned by Perl',len(aliases)==29 and set(owned)=={'perl'})
    command(pacman+['-R','perl'])
    check('candidate removed with vendor fixture inventory preserved',inventory()==dict(initial,**{'perl-candidate-vendor-TEST':'1-1'}))
    check('all29 package aliases removed',all(nodes([n])[n] is None for n in aliases))
    check('every selected Perl file removed',all(nodes([n])[n] is None for n in allpaths if (newnodes.get(n) or oldnodes[n])['type']!='directory'))
    check('all operator/vendor/XS sentinels survive Perl removal',nodes(sentinels)==preserved)
    command(pacman+['-U',str(candidate)])
    check('reinstall exact candidate payload',nodes(newnodes)==newnodes)
    state('reinstall','5.42.3-1.2',newnodes)
    command(pacman+['-U',str(old)]);state('retained-r3-rollback','5.42.3-1.1',oldnodes)
    check('rollback removes every candidate-only file',all(nodes([n])[n] is None for n in set(newnodes)-set(oldnodes) if newnodes[n]['type']!='directory'))
    check('rollback full selected-path baseline restored',nodes(allpaths)==baseline)
    command(pacman+['-R','perl'])
    check('all sentinels survive final Perl removal',nodes(sentinels)==preserved)
    check('every selected Perl file absent after final removal',all(nodes([n])[n] is None for n in allpaths if (newnodes.get(n) or oldnodes[n])['type']!='directory'))
    command(pacman+['-R','perl-candidate-vendor-TEST'])
    pacsave=Path(str(configfile)+'.pacsave');check('real TEST fixture pacsave preserves operator bytes',pacsave.read_text()=='operator changed TEST config\n')
    command(pacman+['-U',str(vendor)])
    check('existing pacsave survives fixture reinstall',pacsave.read_text()=='operator changed TEST config\n')
    command(pacman+['-R','perl-candidate-vendor-TEST'])
    check('final exact original package inventory',inventory()==initial)
    check('final operator local files preserved',nodes(local)=={k:preserved[k] for k in local})
    check('final modified fixture pacsave preserved',pacsave.read_text()=='operator changed TEST config\n')
    for p in (sign,trust,unknown):
        command(['gpgconf','--homedir',str(p),'--kill','all'])
        shutil.rmtree(p)
    # Retain only public TEST certificate/signatures; never export private keys.
    for p in (old,candidate,vendor):shutil.copyfile(str(p)+'.sig',OUT/(p.name+'.sig'))
    for name,row in contract['inputs'].items():check('input bytes preserved '+name,sha(HERE/'inputs'/name)==row['sha256'])
    REPORT.update(status='PASS_TEST_SIGNED_X86_64_ALPM_COMPONENT', transitions=transitions,
        test_fingerprint=fingerprint,final_inventory=initial,baseline_inventory=baseline_inventory,
        sentinel_paths=sorted(sentinels),rollback='RETAINED_EXACT_R3_1.1_TEST_SIGNED_ARCHIVE',
        perl_pacsave='NOT_APPLICABLE_NO_BACKUP_ENTRIES',fixture_pacsave='PASS_ACTUAL_ALPM_MODIFIED_BACKUP',
        limits=['EXTERNAL_XS_AND_TARGET_ABI_NOT_QUALIFIED','NATIVE_ARM_16K_M2_NOT_RUN','PRODUCTION_TRUST_RELEASE_NOT_ADMITTED'])


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--prepare',action='store_true');args=parser.parse_args()
    try:
        prepare() if args.prepare else main()
    except BaseException as error:
        REPORT.update(status='FAIL',failure=type(error).__name__+': '+str(error))
        raise
    finally:
        if OUT.is_dir():(OUT/'result.json').write_text(json.dumps(REPORT,sort_keys=True,indent=2)+'\n')

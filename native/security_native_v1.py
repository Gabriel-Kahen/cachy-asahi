#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit native image package pair/TEST lifecycle; never host install."""
import argparse,base64,importlib.util,json,os,platform,pwd,re,shutil,stat,subprocess,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import need,pin,read,save,verify_source,input_contract
PREFIX=Path('/opt/native-security-v1')
SOURCE=PREFIX/'source'
STORE=PREFIX/'public'
NAME='cachy-asahi-security-maintenance'
ARCHIVE=NAME+'-0.1.0-2-any.pkg.tar.zst'
STATUS='PASS_SECURITY_TEST_ALPM_LIFECYCLE_V1'

def prepare(root,context,map_hash,carrier,cache):
    manifest=verify_source(root,map_hash);target=context/'security-source';target.mkdir()
    for name in sorted(set(manifest['files'])|{'native/source-map.json'}):
        source=root/name;output=target/name;output.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,output);output.chmod(stat.S_IMODE(source.stat().st_mode))

def dockerfile(base,map_hash):
    need(re.fullmatch('[0-9a-f]{64}',map_hash or ''),'explicit security whole source map')
    ending='USER alarm\nWORKDIR /tmp\n'
    need(base.endswith(ending) and base.count(ending)==1,'held native191 overlay suffix')
    lines=base[:-len(ending)].splitlines(keepends=True)
    need(lines[0].startswith('FROM ') and ' AS ' not in lines[0],'held tools image stage')
    lines[0]=lines[0].rstrip()+' AS security-dependencies\n'
    result=''.join(lines)+'COPY security-source/ /opt/native-security-v1/source/\nRUN cp /builder-packages.lock /builder-dependency-packages.lock\n'
    for label in ('one','two'):
        result+='FROM security-dependencies AS security-build-'+label+'\n'
        result+='RUN /usr/bin/python3 -I -B /opt/native-security-v1/source/native/security_native_v1.py --unpack --map-sha256 '+map_hash+' && echo '+label+' > /security-pair-slot\nUSER alarm\nWORKDIR /tmp/security-build\n'
        result+='RUN SOURCE_DATE_EPOCH=1793145600 PKGDEST=/tmp/security-build SRCDEST=/tmp/security-build BUILDDIR=/tmp/security-build makepkg --check --cleanbuild --nosign --noconfirm --config /opt/native-security-v1/source/native/security-makepkg.conf\n'
    result+='FROM security-dependencies\n'
    for label in ('one','two'):
        result+='COPY --from=security-build-'+label+' /tmp/security-build/'+ARCHIVE+' /opt/native-security-v1/pair/'+label+'/'+ARCHIVE+'\n'
    for label in ('one','two'):
        result+='COPY --from=security-build-'+label+' /security-pair-slot /opt/native-security-v1/pair/'+label+'/stage-slot\n'
    result+='RUN /usr/bin/python3 -I -B /opt/native-security-v1/source/native/security_native_v1.py --inside-image --map-sha256 '+map_hash+'\n'
    return result+ending

def run_overlay(actor,command):
    need('DOCKER_BUILDKIT' not in os.environ,'no ambient builder override')
    os.environ['DOCKER_BUILDKIT']='1'
    try:return actor.run(command,timeout=1800)
    finally:os.environ.pop('DOCKER_BUILDKIT',None)

def policy(root):return json.loads(read(root/'native/security-contract-v1.json'))


def stage_snapshot(root,contract,owner,destination):
    data=json.loads(read(root/'security-inputs/snapshot-data.json'))
    need(set(data)=={'advisories.json','provenance.json','snapshot.json'},'exact retained snapshot names')
    bodies={}
    for name,body in data.items():
        raw=base64.b64decode(body,validate=True)
        need(pin(raw)==contract['snapshot_files'][name],'retained snapshot bytes')
        bodies[name]=raw
    destination.mkdir(mode=0o700);destination.chmod(0o700)
    os.chown(destination,owner.pw_uid,owner.pw_gid)
    for name,raw in bodies.items():
        target=destination/name
        with target.open('xb')as stream:stream.write(raw)
        target.chmod(0o600);os.chown(target,owner.pw_uid,owner.pw_gid)
    return destination

def unpack(root,map_hash):
    need(os.getuid()==os.geteuid()==0 and platform.machine()=='aarch64' and root==SOURCE,'unpack only in disposable native image')
    verify_source(root,map_hash)
    path=root/'security-inputs/security_maintenance_source_delivery_v2.py'
    spec=importlib.util.spec_from_file_location('_security_delivery_v2',path)
    adapter=importlib.util.module_from_spec(spec);spec.loader.exec_module(adapter)
    profile_raw=adapter.read(path.with_name(adapter.PROFILE_NAME));value=adapter.profile(profile_raw,adapter.PROFILE_SHA256)
    raw=adapter.read(root/'security-inputs/recipe.tar',adapter.MAX_BUNDLE)
    files=adapter.verified(raw,policy(root)['source_bundle']['sha256'],value,profile_raw,adapter.read(path))
    destination=Path('/tmp/security-unpack');adapter.unpack(destination,files)
    build=Path('/tmp/security-build');need(not build.exists(),'fresh clean native build root')
    (destination/'recipe').rename(build);alarm=pwd.getpwnam('alarm')
    for child in (build,*build.rglob('*')):os.chown(child,alarm.pw_uid,alarm.pw_gid)

def snapshot(root):
    rows={}
    for path in sorted(root.rglob('*')):
        info=path.lstat();row=dict(mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid)
        if stat.S_ISREG(info.st_mode):row.update(pin(read(path)))
        elif stat.S_ISLNK(info.st_mode):row['link']=os.readlink(path)
        elif not stat.S_ISDIR(info.st_mode):row['special']=True
        rows[str(path.relative_to(root))]=row
    return rows

class Commands:
    def __init__(self,home):self.home,self.records=home,[]
    def run(self,step,argv,expected=0,timeout=180,cwd=None,limit=262144):
        env=dict(PATH='/usr/bin:/bin',HOME=str(self.home),LANG='C',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1')
        with tempfile.TemporaryFile() as stdout,tempfile.TemporaryFile() as stderr:
            result=subprocess.run(list(map(str,argv)),cwd=cwd or self.home,env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=timeout)
            stdout.seek(0);stderr.seek(0);out,err=stdout.read(limit+1),stderr.read(limit+1)
        need(len(out)<=limit and len(err)<=limit,'bounded lifecycle command DATA')
        self.records.append(dict(step=step,exit=result.returncode,stdout=pin(out),stderr=pin(err)))
        need(result.returncode!=0 if expected=='nonzero' else result.returncode==expected,'lifecycle command failed: '+step)
        return out

def strict_signature(status,fingerprint):
    need(re.fullmatch('[0-9A-F]{40}',fingerprint or ''),'explicit scoped TEST fingerprint')
    rows=[line.split()[1:] for line in status.splitlines() if line.startswith('[GNUPG:] ')]
    bad={'EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','FAILURE','NODATA','TRUST_NEVER','TRUST_UNDEFINED'}
    need(not any(r and r[0] in bad for r in rows),'bad TEST signature')
    valid=[r for r in rows if r and r[0]=='VALIDSIG']
    need(len(valid)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==fingerprint,'one exact TEST primary signer')
    need(any(r and r[0]=='TRUST_ULTIMATE' for r in rows),'explicit TEST trust required')

def test_config(trust):
    need(trust.is_absolute() and trust.name=='trust' and trust.parent.name.startswith('security-test-'),'scoped TEST home only')
    return '[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+str(trust)+'\nHookDir = /builder-disabled-hooks\n'

def archive_payload(command,archive):
    listing=command.run('archive-list',['/usr/bin/bsdtar','-tf',archive]).decode().splitlines()
    need(len(listing)==len(set(listing)) and all(not n.startswith('/') and '..' not in Path(n).parts for n in listing),'unique safe archive names')
    result={}
    for name in listing:
        if not name.endswith('/'):result[name]=command.run('archive-file',['/usr/bin/bsdtar','-xOf',archive,name])
    need({'.PKGINFO','.BUILDINFO','.MTREE'}<=set(result),'original makepkg metadata required')
    return result


CLEANUP_FLAGS=frozenset(('required_signatures','installed','removed','payload_absent',
    'inventory_restored','user_data_preserved','moved_prefix_absent','global_trust_unchanged',
    'global_config_unchanged','private_homes_absent'))
CLEANUP_ERRORS=frozenset(('ValueError','OSError','PermissionError','FileNotFoundError','TimeoutExpired','Other'))


def cleanup_failure_data(report,map_hash,retirement):
    need(re.fullmatch('[0-9a-f]{64}',map_hash or '')is not None,'explicit cleanup diagnostic source')
    need(type(retirement)is list and len(retirement)==2,'two scoped retirement observations')
    flags={key:report['lifecycle'].get(key)for key in sorted(CLEANUP_FLAGS)}
    need(all(value is None or type(value)is bool for value in flags.values()),'finite cleanup flags')
    rows=[]
    for role,row in zip(('signing','trust'),retirement):
        need(type(row)is dict and set(row)=={'role','retired','error','commands'}and row['role']==role
             and type(row['retired'])is bool and (row['error']is None or row['error']in CLEANUP_ERRORS)
             and type(row['commands'])is list and len(row['commands'])<=2,'scoped cleanup observation schema')
        commands=[]
        for command in row['commands']:
            need(type(command)is dict and set(command)=={'step','exit','stdout','stderr'}
                 and command['step']in ('retire-test-home','no-autostart-proof')
                 and type(command['exit'])is int and -255<=command['exit']<=255,'finite cleanup command outcome')
            for channel in ('stdout','stderr'):
                value=command[channel]
                need(type(value)is dict and set(value)=={'bytes','sha256'}and type(value['bytes'])is int
                     and 0<=value['bytes']<=262144 and type(value['sha256'])is str
                     and re.fullmatch('[0-9a-f]{64}',value['sha256'])is not None,'bounded output pin only')
            commands.append({key:command[key]for key in ('step','exit','stdout','stderr')})
        rows.append(dict(role=role,retired=row['retired'],error=row['error'],commands=commands))
    return dict(schema=1,status='SECURITY_INNER_CLEANUP_FAILURE_DATA_ONLY',source_map_sha256=map_hash,
        operation='security-alpm-v1',native='NOT_ADMITTED',scope='DISPOSABLE_IMAGE_INNER_CLEANUP',
        flags=flags,retirement=rows)


def emit_cleanup_failure(report,map_hash,retirement):
    try:
        value=cleanup_failure_data(report,map_hash,retirement)
        text=json.dumps(value,sort_keys=True,allow_nan=False)
        need(len(text.encode())<=8192,'cleanup diagnostic byte cap')
        print('SECURITY_CLEANUP_FAILURE_DATA '+text,flush=True)
    except BaseException:
        try:
            print('SECURITY_CLEANUP_DIAGNOSTIC_REFUSED '+json.dumps(dict(schema=1,
                status='REFUSED_INNER_CLEANUP_DIAGNOSTIC',source_map_sha256=(map_hash if type(map_hash)is str and re.fullmatch('[0-9a-f]{64}',map_hash)else None),
                code='SOURCE_DIAGNOSTIC_SCHEMA_OR_OUTPUT_REFUSED'),sort_keys=True),flush=True)
        except BaseException:pass


def inside(root,map_hash):
    need(os.getuid()==os.geteuid()==0 and platform.machine()=='aarch64' and root==SOURCE,'owned disposable native image root only')
    verify_source(root,map_hash);contract=policy(root);_,_,expected=input_contract(root)
    baseline=read(Path('/builder-dependency-packages.lock'))
    need(baseline==expected==read(Path('/builder-packages.lock')) and len(baseline.splitlines())==349,'exact authenticated retained349 dependencies')
    versions=dict(line.decode().split(' ',1) for line in baseline.splitlines())
    need(all(versions.get(k)==v for k,v in contract['required_dependencies'].items()),'required retained runtime dependencies')
    unpack(root,map_hash)
    alarm=pwd.getpwnam('alarm')
    snapshot_root=stage_snapshot(root,contract,alarm,PREFIX/'snapshot')
    paths=contract['payload_files']
    need(len(paths)==29 and all(not os.path.lexists('/usr/'+name) for name in paths),'package paths initially absent')
    protected_config=pin(read(Path('/etc/pacman.conf')));protected_trust=snapshot(Path('/etc/pacman.d/gnupg'))
    private=Path(tempfile.mkdtemp(prefix='security-test-',dir='/tmp'));private.chmod(0o700)
    signing,trust=private/'signing',private/'trust'
    for home in (signing,trust):home.mkdir(mode=0o700)
    c=Commands(private)
    user=PREFIX/'user-data';user.mkdir();(user/'keep.txt').write_text('TEST existing security choices\n')
    os.chown(user,alarm.pw_uid,alarm.pw_gid);os.chown(user/'keep.txt',alarm.pw_uid,alarm.pw_gid)
    (user/'keep.txt').chmod(0o600);before_user=snapshot(user)
    report=dict(schema=1,status='FAIL',source_map_sha256=map_hash,architecture=platform.machine(),page_size=os.sysconf('SC_PAGE_SIZE'),
        packages=pin(baseline),physical_M2='NOT_RUN',native_16K='NOT_QUALIFIED',release='NOT_ADMITTED',remediation='NOT_ESTABLISHED',
        execution_scope='OWNED_NATIVE_IMAGE_BUILD_STAGE; ordinary alarm workflows; consumer exports DATA',pair={},lifecycle={},workflows={},commands=c.records)
    primary=None;installed=False;retired=[]
    archive=PREFIX/'pair/one'/ARCHIVE;second=PREFIX/'pair/two'/ARCHIVE
    def inventory(step):return b''.join(sorted(c.run(step,['/usr/bin/pacman','-Q']).splitlines(keepends=True)))
    try:
        need(inventory('baseline')==baseline,'actual complete349 inventory')
        need(read(archive.parent/'stage-slot')==b'one\n' and read(second.parent/'stage-slot')==b'two\n','distinct clean build stages')
        one=archive_payload(c,archive);two=archive_payload(c,second)
        need(one==two and pin(read(archive))==pin(read(second)),'two clean archives bytes and full documented contents equal')
        need(set(one)=={'usr/'+name for name in paths}|{'.PKGINFO','.BUILDINFO','.MTREE'},'exact29 files plus original makepkg metadata')
        for name,row in paths.items():need(pin(one['usr/'+name])=={k:row[k] for k in ('bytes','sha256')},'documented payload bytes')
        need(b'pkgname = cachy-asahi-security-maintenance\n' in one['.PKGINFO'] and b'pkgver = 0.1.0-2\n' in one['.PKGINFO'],'original package identity')
        recorded=[line.removeprefix('installed = ') for line in one['.BUILDINFO'].decode().splitlines() if line.startswith('installed = ')]
        metadata=c.run('actual-alpm-buildinfo-inventory',['/usr/bin/pacman','-Qi'],limit=2*1024**2).decode()
        expected_buildinfo=set()
        for block in metadata.strip().split('\n\n'):
            fields={}
            for line in block.splitlines():
                if ':' in line and not line.startswith(' '):
                    key,value=line.split(':',1);fields[key.strip()]=value.strip()
            name,version,arch=fields['Name'],fields['Version'],fields['Architecture']
            need(versions.get(name)==version and arch in ('aarch64','any'),'actual ALPM metadata matches retained349')
            expected_buildinfo.add(name+'-'+version+'-'+arch)
        need(set(recorded)==expected_buildinfo and len(recorded)==len(expected_buildinfo)==349,'whole retained349 BUILDINFO inventory including architecture')
        report['pair']=dict(archive_equal=True,payload_equal=True,buildinfo_equal=True,pkginfo_equal=True,checks='ORIGINAL_CHECK_BOTH',
            one=pin(read(archive)),two=pin(read(second)),archives={'one':base64.b64encode(read(archive)).decode(),'two':base64.b64encode(read(second)).decode()},buildinfo=pin(one['.BUILDINFO']),pkginfo=pin(one['.PKGINFO']),payload={name:pin(body) for name,body in one.items()})
        gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',signing,'--no-auto-key-retrieve','--pinentry-mode','loopback','--passphrase','']
        c.run('fresh-test-key',gpg+['--quick-generate-key','TEST ONLY security-maintenance <security@test.invalid>','ed25519','sign','1d'])
        listing=c.run('test-fingerprint',gpg+['--with-colons','--list-keys']).decode()
        keys=[line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
        need(len(keys)==1 and re.fullmatch('[0-9A-F]{40}',keys[0]),'one fresh TEST key')
        fingerprint=keys[0];public=private/'TEST-public.asc'
        public.write_bytes(c.run('test-public-export',gpg+['--armor','--export',fingerprint]));signature=Path(str(archive)+'.sig')
        c.run('sign-exact-archive',gpg+['--local-user',fingerprint,'--output',signature,'--detach-sign',archive])
        verifier=['/usr/bin/gpg','--batch','--no-options','--homedir',trust,'--no-auto-key-retrieve']
        unknown=c.run('unknown-key-refusal',verifier+['--status-fd=1','--verify',signature,archive],'nonzero')
        need(b'NO_PUBKEY' in unknown,'unknown key really refused')
        config=private/'pacman.conf';config.write_text(test_config(trust));pacman=['/usr/bin/pacman','--config',config]
        c.run('required-untrusted-install-refusal',pacman+['--noconfirm','--noscriptlet','-U',archive],'nonzero')
        need(inventory('refused-inventory')==baseline,'untrusted refusal preserves inventory')
        c.run('import-scoped-test-public',verifier+['--import',public]);listing=c.run('trust-membership',verifier+['--with-colons','--list-keys']).decode()
        need([l.split(':')[9] for l in listing.splitlines() if l.startswith('fpr:')]==[fingerprint],'trust contains only TEST key')
        ownertrust=private/'ownertrust';ownertrust.write_text(fingerprint+':6:\n')
        c.run('explicit-test-ownertrust',verifier+['--import-ownertrust',ownertrust])
        status=c.run('verify-test-signature',verifier+['--status-fd=1','--verify',signature,archive]).decode();strict_signature(status,fingerprint)
        c.run('required-install',pacman+['--noconfirm','--noscriptlet','-U',archive]);installed=True
        wanted=b''.join(sorted(baseline.splitlines(keepends=True)+[b'cachy-asahi-security-maintenance 0.1.0-2\n']))
        need(inventory('installed-inventory')==wanted,'exact350 installed inventory')
        for name,row in paths.items():
            target=Path('/usr')/name;info=target.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==row['mode'] and pin(read(target))=={k:row[k] for k in ('bytes','sha256')},'installed payload bytes/modes/root owner')
            need(c.run('alpm-file-owner',pacman+['-Qoq',target]).strip()==NAME.encode(),'actual pacman file ownership')
        moved=PREFIX/'moved-prefix';moved.mkdir()
        for name in paths:
            target=moved/'usr'/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(Path('/usr')/name,target);target.chmod(paths[name]['mode'])
        for label,prefix in (('installed',Path('/')),('moved',moved)):
            output=Path('/tmp/security-workflow-'+label)
            journey_home=Path('/tmp/security-home-'+label);journey_home.mkdir(mode=0o700);os.chown(journey_home,alarm.pw_uid,alarm.pw_gid)
            sentinel=journey_home/'keep.txt';sentinel.write_text('TEST existing user profile\n');os.chown(sentinel,alarm.pw_uid,alarm.pw_gid);sentinel.chmod(0o600)
            argv=['/usr/bin/runuser','-u','alarm','--','/usr/bin/python3','-I','-B',root/'native/security_workflow_v1.py','--prefix',prefix,
                '--fixture',Path('/tmp/security-build/fixture_security.py'),'--snapshot',snapshot_root,'--snapshot-sha256',contract['snapshot_sha256'],
                '--home',journey_home,'--output',output]
            result=json.loads(c.run('offline-'+label,argv,timeout=400,cwd=Path('/tmp')))
            need(result['status']=='PASS_OFFLINE_SECURITY_WORKFLOWS','complete actual offline installed/moved journey')
            report['workflows'][label]=result['status']
            shutil.rmtree(output);shutil.rmtree(journey_home)
        shutil.rmtree(moved);need(not moved.exists(),'moved prefix retired')
        c.run('remove',pacman+['--noconfirm','--noscriptlet','-R',NAME]);installed=False
        need(inventory('removed-inventory')==baseline,'complete349 inventory restored')
        need(all(not os.path.lexists('/usr/'+name) for name in paths),'all package paths absent')
        need(snapshot(user)==before_user,'existing user data preserved')
        report['lifecycle'].update(required_signatures=True,installed=True,removed=True,payload_absent=True,inventory_restored=True,user_data_preserved=True,moved_prefix_absent=True)
        report['test_authority']=dict(fingerprint=fingerprint,public_key=public.read_text('ascii'),signature_base64=base64.b64encode(signature.read_bytes()).decode(),signature_status=status,semantics='Required/Required; scoped ephemeral TEST ONLY')
        report['status']=STATUS
    except BaseException as error:
        primary=error;report['failure']=dict(type=type(error).__name__,phase=c.records[-1]['step'] if c.records else 'admission')
        print('SECURITY_IMAGE_FAILURE '+json.dumps(report['failure'],sort_keys=True),flush=True)
        raise
    finally:
        if installed:
            try:c.run('failure-remove',['/usr/bin/pacman','--config',private/'pacman.conf','--noconfirm','--noscriptlet','-R',NAME])
            except BaseException:report['failure_removal']='UNKNOWN'
        cleanup_retirement=[]
        for role,home in zip(('signing','trust'),(signing,trust)):
            before_commands=len(c.records);cleanup_error=None
            try:
                c.run('retire-test-home',['/usr/bin/gpgconf','--homedir',home,'--kill','all'])
                c.run('no-autostart-proof',['/usr/bin/gpg-connect-agent','--homedir',home,'--no-autostart','/bye'],'nonzero')
                need(not any(stat.S_ISSOCK(p.lstat().st_mode) for p in home.rglob('*')),'scoped sockets absent');retired.append(home)
            except BaseException as error:
                report['status']='FAIL'
                name=type(error).__name__;cleanup_error=name if name in CLEANUP_ERRORS else 'Other'
            cleanup_retirement.append(dict(role=role,retired=home in retired,error=cleanup_error,
                commands=c.records[before_commands:]))
        shutil.rmtree(private)
        for label in ('installed','moved'):
            for kind in ('workflow','home'):
                output=Path('/tmp/security-'+kind+'-'+label)
                if output.exists():shutil.rmtree(output)
        report['lifecycle'].update(global_trust_unchanged=snapshot(Path('/etc/pacman.d/gnupg'))==protected_trust,
            global_config_unchanged=pin(read(Path('/etc/pacman.conf')))==protected_config,
            private_homes_absent=len(retired)==2 and not private.exists() and all(not Path('/tmp/security-'+kind+'-'+label).exists() for kind in ('home','workflow') for label in ('installed','moved')))
        if not all(report['lifecycle'].values()):report['status']='FAIL'
        STORE.mkdir();save(STORE/'result.json',report);(STORE/'result.json').chmod(0o644)
        if primary is None and report['status']!=STATUS:
            emit_cleanup_failure(report,map_hash,cleanup_retirement)
        if primary is None:need(report['status']==STATUS,'lifecycle cleanup qualification failed')

def export(root,output,map_hash):
    verify_source(root,map_hash);need(os.getuid()==os.geteuid()!=0 and not output.exists(),'unprivileged fresh security DATA export')
    raw=read(STORE/'result.json',2*1024**2);result=json.loads(raw)
    need(result['source_map_sha256']==map_hash and result['status']==STATUS,'same-source completed security DATA')
    output.mkdir(mode=0o700);(output/'result.json').write_bytes(raw)

def main():
    parser=argparse.ArgumentParser(description=__doc__);group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--unpack',action='store_true');group.add_argument('--inside-image',action='store_true');group.add_argument('--export',action='store_true')
    parser.add_argument('--output',type=Path);parser.add_argument('--map-sha256',required=True);args=parser.parse_args();root=Path(__file__).resolve().parents[1]
    if args.unpack:unpack(root,args.map_sha256)
    elif args.inside_image:inside(root,args.map_sha256)
    else:export(root,args.output,args.map_sha256)
if __name__=='__main__':main()

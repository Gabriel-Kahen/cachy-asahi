# SPDX-License-Identifier: MIT
"""Explicit owned-image TEST ALPM upgrade actor and finite passive export."""
import argparse
import base64
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
import release_tools_v1 as T
import release_build_cause_v1 as D

need=T.need
PREFIX=T.PREFIX
SOURCE=T.SOURCE
STORE=T.STORE
TEST_UID='TEST ONLY release-tools <release-tools@test.invalid>'


def prepare(root,context,map_hash):
    from common import verify_source
    root,context=Path(root),Path(context);manifest=verify_source(root,map_hash)
    target=context/'release-alpm-v1'/'source';target.mkdir(parents=True)
    for name in sorted(set(manifest['files'])|{'native/source-map.json'}):
        source=root/name;out=target/name;out.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,out);out.chmod(stat.S_IMODE(source.stat().st_mode))
    return target


def dockerfile(base,map_hash):
    need(re.fullmatch('[0-9a-f]{64}',map_hash or ''),'explicit source-map checksum')
    ending='USER alarm\nWORKDIR /tmp\n'
    need(base.endswith(ending) and base.count(ending)==1,'exact genuine187 image suffix; no fallback seam')
    return base[:-len(ending)]+('COPY release-alpm-v1/source/ /opt/native-release-tools-alpm-v1/source/\n'
        'RUN /usr/bin/python3 -I -B /opt/native-release-tools-alpm-v1/source/native/release_alpm_v1.py --inside-image --map-sha256 '+map_hash+'\n'+ending)


def strict_signature(status,fingerprint):
    need(re.fullmatch('[0-9A-F]{40}',fingerprint or ''),'explicit TEST primary fingerprint')
    rows=[line.split()[1:] for line in status.splitlines() if line.startswith('[GNUPG:] ')]
    forbidden={'EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','FAILURE','NODATA','TRUST_NEVER','TRUST_UNDEFINED'}
    need(not any(row and row[0] in forbidden for row in rows),'bad/expired/revoked/unknown TEST signature refused')
    valid=[row for row in rows if row and row[0]=='VALIDSIG']
    need(len(valid)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==fingerprint,'exact TEST primary signer required')
    need(any(row and row[0]=='TRUST_ULTIMATE' for row in rows),'explicitly trusted TEST primary required')


def test_config(trust):
    trust=Path(trust)
    need(trust.is_absolute() and trust.name=='trust' and trust.parent.parent==Path('/tmp')
         and trust.parent.name.startswith('release-tools-test-'),'owned TEST trust path only')
    return ('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\n'
            'GPGDir = '+str(trust)+'\nHookDir = /builder-disabled-hooks\n')


def retire_homes(run,homes,work):
    """Best-effort complete cleanup; never raises over the primary failure."""
    work=Path(work);failures=[];retired=[];no_sockets=True
    try:
        need(work.parent==Path('/tmp') and work.name.startswith('release-tools-test-') and not work.is_symlink(),'owned private cleanup directory')
        identity=work.stat();need(stat.S_ISDIR(identity.st_mode) and stat.S_IMODE(identity.st_mode)==0o700,'private directory identity/mode')
    except BaseException as error:
        return dict(homes_retired=False,no_sockets=False,private_directory_absent=False,failures=['ownership:'+type(error).__name__])
    for home in homes:
        home=Path(home);okay=True
        for step,argv,expected in (
            ('retire-'+home.name,['/usr/bin/gpgconf','--homedir',str(home),'--kill','all'],0),
            ('no-autostart-'+home.name,['/usr/bin/gpg-connect-agent','--homedir',str(home),'--no-autostart','/bye'],'nonzero')):
            try:
                need(home.parent==work and home.name in ('signing','trust') and not home.is_symlink(),'owned GPG home')
                run(step,argv,expected)
            except BaseException as error:okay=False;failures.append(step+':'+type(error).__name__)
        try:
            sockets=any(stat.S_ISSOCK(path.lstat().st_mode) for path in home.rglob('*'))
            need(not sockets,'scoped GPG socket remains')
        except BaseException as error:okay=False;no_sockets=False;failures.append('sockets-'+home.name+':'+type(error).__name__)
        if okay:retired.append(home.name)
    try:
        current=work.stat();need((current.st_dev,current.st_ino)==(identity.st_dev,identity.st_ino) and not work.is_symlink(),'private cleanup identity changed')
        shutil.rmtree(work)
    except BaseException as error:failures.append('private-directory:'+type(error).__name__)
    return dict(homes_retired=set(retired)=={'signing','trust'},no_sockets=no_sockets,
                private_directory_absent=not os.path.lexists(work),failures=failures)


def primary_failure(primary,cleanup):
    if primary is not None:return primary
    if cleanup['failures'] or not all(cleanup[k] for k in ('homes_retired','no_sockets','private_directory_absent')):
        return ValueError('scoped TEST signing/trust cleanup unqualified')
    return None


def build_recipes(run,source,recipes,policy,alarm):
    result={};config=source/policy['makepkg_config']['path']
    for version in T.VERSIONS:
        row=policy['recipes'][version];directory=recipes/row['prefix']
        for path in (directory,*directory.iterdir()):os.chown(path,alarm.pw_uid,alarm.pw_gid)
        argv=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(directory),'PKGDEST='+str(directory),
              'SRCDEST='+str(directory),'BUILDDIR='+str(directory),'/usr/bin/makepkg','--cleanbuild','--nodeps','--nosign','--noconfirm','--config',str(config)]
        need('--nocheck' not in argv,'makepkg check cannot be skipped')
        step='build-'+row['prefix'];raw=run(step,argv,cwd=directory)
        count=row['expected_test_count']
        need(b'Starting check()' in raw and re.search(rb'Ran '+str(count).encode()+rb' tests? in ',raw)
             and re.search(rb'\nOK(?:\n|$)',raw),'actual makepkg check/test result required')
        archive=directory/row['archive'];need(archive.is_file() and not archive.is_symlink(),'actual built archive')
        result[version]=dict(version=version,archive=dict(filename=row['archive'],**T.pin(archive)),recipe_sha256=row['source_files']['PKGBUILD']['sha256'],
            build_step=step,check_invoked=True,check_tests=count,check_policy='POSITIVE_CHECK_NO_NOCHECK')
    return result


def inside(source,map_hash):
    source=Path(source)
    need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and source==SOURCE
         and Path('/builder-packages.lock').is_file(),'explicit owned disposable native image root only')
    from common import verify_source
    verify_source(source,map_hash);policy,base=T.source_policy(source)
    need(Path('/builder-packages.lock').read_bytes()==base,'actual genuine187 base349 image')
    payload_union=set().union(*(r['payload_files'] for r in policy['recipes'].values()))
    need(all(not os.path.lexists('/'+name) for name in payload_union),'all project package paths absent initially')
    need(not STORE.exists(),'fresh fixed image evidence store');scope=STORE/'journey'/'release-alpm-v1';scope.mkdir(parents=True)
    work=Path(tempfile.mkdtemp(prefix='release-tools-test-',dir='/tmp'));work.chmod(0o700)
    try:
        signing,trust=work/'signing',work/'trust'
        for home in (signing,trust):home.mkdir(mode=0o700)
        (work/'command-home').mkdir(mode=0o700)
        alarm=pwd.getpwnam('alarm');W=T.load_workflow(source,policy)
        commands=W.RetirementCommands(scope,work/'command-home','/usr/bin:/bin',timeout=300,total=600,max_output=1024*1024)
        def run(step,argv,expected=0,cwd=work):return commands.run(step,list(map(str,argv)),Path(cwd),expected)
        def inventory(step):return b''.join(sorted(run(step,['/usr/bin/pacman','-Q']).splitlines(keepends=True)))
        def reasons(step):
            explicit=b''.join(sorted(run(step+'-explicit',['/usr/bin/pacman','-Qqe']).splitlines(keepends=True)))
            dependency=b''.join(sorted(run(step+'-dependencies',['/usr/bin/pacman','-Qqd']).splitlines(keepends=True)))
            return dict(explicit=explicit,dependencies=dependency)
        report=dict(schema_version=1,operation=T.OPERATION,status='FAIL',source_map_sha256=map_hash,versions=list(T.VERSIONS),
            contract=T.pin(source/'native/release-contract-v1.json'),stages=[],inventory={},payloads={},builds={},signatures={},business={},
            signature_policy=dict(SigLevel='Required',LocalFileSigLevel='Required'),commands=commands.records,
            native=dict(architecture=os.uname().machine,page_bytes=os.sysconf('SC_PAGE_SIZE'),execution='OWNED_IMAGE_BUILD_STAGE',physical_M2='NOT_RUN',release='NOT_ADMITTED'))
        protected_config=T.pin(Path('/etc/pacman.conf'));protected_trust=T.snapshot(Path('/etc/pacman.d/gnupg'))
        report['global_config_before']=protected_config;report['global_trust_before']=T.data_pin(T.encoded(protected_trust))
        user=PREFIX/'user-data';user.mkdir(mode=0o755);(user/'keep.txt').write_bytes(b'SYNTHETIC existing user export; preserve exact bytes.\n');T.own_user_tree(user,alarm.pw_uid,alarm.pw_gid)
        sentinel=T.pin(user/'keep.txt');exports_before=None;baseline_reasons=None;primary=None;traceback=None;pacman=None;installed=False
        buildroot=PREFIX/'build-inputs';archives={}
    except BaseException as error:
        # No command has launched yet. Even an initialization failure must not
        # retain the private directory; deletion failure cannot mask its cause.
        try:shutil.rmtree(work)
        except BaseException as cleanup:error.add_note('private initialization cleanup: '+type(cleanup).__name__)
        raise
    try:
        need(inventory('baseline-inventory')==base,'actual exact349 baseline')
        baseline_reasons=reasons('baseline-reasons')
        report['install_reasons_before']={k:T.data_pin(v) for k,v in baseline_reasons.items()}
        report['inventory']['baseline']=dict(**T.data_pin(base),count=349,version=None)
        recipes=T.extract_recipes(source,buildroot,policy)
        report['builds']=build_recipes(run,source,recipes,policy,alarm);report['stages']+=['build-v1','build-v2']
        for version in T.VERSIONS:archives[version]=recipes/policy['recipes'][version]['prefix']/policy['recipes'][version]['archive']
        gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',str(signing),'--no-auto-key-retrieve','--pinentry-mode','loopback','--passphrase','']
        run('generate-test-key',gpg+['--quick-generate-key',TEST_UID,'ed25519','sign','1d'])
        listing=run('test-primary-fingerprint',gpg+['--with-colons','--list-keys']).decode()
        fingerprints=[line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
        need(len(fingerprints)==1 and re.fullmatch('[0-9A-F]{40}',fingerprints[0]),'one explicit TEST primary key');fingerprint=fingerprints[0]
        public=work/'TEST-public.asc';public.write_bytes(run('export-only-test-public',gpg+['--armor','--export',fingerprint]))
        verifier=['/usr/bin/gpg','--batch','--no-options','--homedir',str(trust),'--no-auto-key-retrieve']
        for version in T.VERSIONS:
            archive=archives[version];run('sign-'+version,gpg+['--local-user',fingerprint,'--output',str(archive)+'.sig','--detach-sign',str(archive)])
        unknown=run('untrusted-signature-control',verifier+['--status-fd=1','--verify',str(archives[T.VERSIONS[0]])+'.sig',str(archives[T.VERSIONS[0]])],'nonzero')
        need(b'NO_PUBKEY' in unknown,'actual unknown TEST key refusal')
        run('import-only-test-public',verifier+['--import',str(public)])
        membership=run('trust-key-membership',verifier+['--with-colons','--list-keys']).decode()
        need([line.split(':')[9] for line in membership.splitlines() if line.startswith('fpr:')]==[fingerprint],'trust contains only TEST primary')
        ownertrust=work/'ownertrust.txt';ownertrust.write_text(fingerprint+':6:\n');run('trust-only-test-primary',verifier+['--import-ownertrust',str(ownertrust)])
        for version in T.VERSIONS:
            archive=archives[version];step='verify-'+version
            status=run(step,verifier+['--status-fd=1','--verify',str(archive)+'.sig',str(archive)]).decode();strict_signature(status,fingerprint)
            signature=Path(str(archive)+'.sig')
            report['signatures'][version]=dict(signer=fingerprint,status=status,verify_step=step,
                signature=dict(**T.pin(signature),base64=base64.b64encode(signature.read_bytes()).decode('ascii')))
        tampered=work/'tampered.pkg.tar.zst';tampered.write_bytes(archives[T.VERSIONS[0]].read_bytes()+b'tamper')
        bad=run('tampered-signature-control',verifier+['--status-fd=1','--verify',str(archives[T.VERSIONS[0]])+'.sig',str(tampered)],'nonzero')
        need(b'BADSIG' in bad or b'ERRSIG' in bad,'actual tampered archive signature refusal')
        public_text=public.read_text('ascii');need(public_text.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----') and 'PRIVATE KEY' not in public_text,'public TEST key only')
        report['public_key']=dict(**T.pin(public),text=public_text);report['fingerprint']=fingerprint
        config=work/'pacman.conf';config.write_text(test_config(trust));report['signature_config']=T.pin(config)
        run('required-signature-config',['/usr/bin/cat',str(config)]);pacman=['--config',str(config)];report['stages'].append('sign')
        for stage,version,key in (('install-v1',T.VERSIONS[0],'installed_v1'),('upgrade-v2',T.VERSIONS[1],'upgraded_v2')):
            run(stage,['/usr/bin/pacman',*pacman,'--noconfirm','--noscriptlet','-U',str(archives[version])]);installed=True
            actual=inventory(key+'-inventory');need(actual==T.inventory_expected(base,version),'exact350 installed version/dependencies')
            report['inventory'][key]=dict(**T.data_pin(actual),count=350,version=version)
            report['payloads'][key]=T.check_payload('/',policy,version,run,pacman)
            other='usr/lib/cachy-asahi/release-tools-v2' if version==T.VERSIONS[0] else 'usr/lib/cachy-asahi/release-tools'
            need(not os.path.lexists('/'+other),'stale other-version private root absent')
            expected=(T.NAME+' '+version.rsplit('-',1)[0]+'\n').encode()
            need(run(stage+'-version',['/usr/bin/runuser','-u','alarm','--','/usr/bin/'+T.NAME,'--version'])==expected,'actual installed version output')
            report['stages'].append(stage)
        topmem=T.topmem_sources(recipes/'v1')
        report['business']['system']=T.business(run,Path('/usr/bin')/T.NAME,user/'system',topmem,alarm.pw_uid,alarm.pw_gid,'system')
        report['stages'].append('commands-system')
        moved=user/'moved-prefix';moved.mkdir()
        for name,item in policy['recipes'][T.VERSIONS[1]]['payload_files'].items():
            target=moved/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile('/'+name,target);target.chmod(item['mode'])
            need(T.pin(target)=={k:item[k] for k in ('bytes','sha256')},'moved exact actual installed payload')
            os.chown(target,alarm.pw_uid,alarm.pw_gid)
        for directory in (moved,*[p for p in moved.rglob('*') if p.is_dir()]):os.chown(directory,alarm.pw_uid,alarm.pw_gid);directory.chmod(0o755)
        report['business']['moved']=T.business(run,moved/'usr/bin'/T.NAME,user/'relocated',topmem,alarm.pw_uid,alarm.pw_gid,'moved')
        report['stages'].append('commands-moved');exports_before=T.snapshot(user);report['exports_before']=T.snapshot_receipt(user)
        version=T.VERSIONS[0];run('downgrade-v1',['/usr/bin/pacman',*pacman,'--noconfirm','--noscriptlet','-U',str(archives[version])])
        actual=inventory('downgraded-v1-inventory');need(actual==T.inventory_expected(base,version),'exact350 downgraded version')
        report['inventory']['downgraded_v1']=dict(**T.data_pin(actual),count=350,version=version)
        report['payloads']['downgraded_v1']=T.check_payload('/',policy,version,run,pacman)
        need(not os.path.lexists('/usr/lib/cachy-asahi/release-tools-v2'),'v2 private runtime absent after downgrade');report['stages'].append('downgrade-v1')
        run('remove',['/usr/bin/pacman',*pacman,'--noconfirm','--noscriptlet','-R',T.NAME]);installed=False
        actual=inventory('removed-inventory');need(actual==base,'exact349 final dependencies')
        report['inventory']['removed']=dict(**T.data_pin(actual),count=349,version=None)
        need(all(not os.path.lexists('/'+name) for name in payload_union),'all15 owned files absent after removal')
        need(all(not os.path.lexists('/usr/lib/cachy-asahi/'+leaf) for leaf in ('release-tools','release-tools-v2')),'all private runtime roots absent')
        report['stages'].append('remove')
        after_reasons=reasons('restored-reasons');need(after_reasons==baseline_reasons,'exact explicit/dependency install reasons restored')
        report['install_reasons_after']={k:T.data_pin(v) for k,v in after_reasons.items()}
        need(T.snapshot(user)==exports_before and T.pin(user/'keep.txt')==sentinel,'operator exports preserved across downgrade/remove')
        report['exports_preserved']=True;report['exports_after']=T.snapshot_receipt(user);report['stages'].append('restore')
    except BaseException as error:
        primary=error;traceback=error.__traceback__;report['failure']=dict(type=type(error).__name__,message=str(error)[:1024])
    finally:
        def finish_cleanup():
            nonlocal primary
            # A fresh owned cleanup supervisor has its own bounded deadline, so an
            # exhausted/cancelled business Commands object cannot prevent retirement.
            try:
                cleanup_commands=W.RetirementCommands(scope,work/'command-home','/usr/bin:/bin',timeout=30,total=120,max_output=1024*1024)
                cleanup_commands.records=commands.records
                def clean_run(step,argv,expected=0):return cleanup_commands.run(step,list(map(str,argv)),work,expected)
            except BaseException as error:
                if primary is None:primary=error
                def clean_run(step,argv,expected=0):raise ValueError('owned cleanup supervisor unavailable')
            cleanup_failures=[]
            if primary is not None and pacman is not None:
                try:
                    actual=b''.join(sorted(clean_run('cleanup-inventory',['/usr/bin/pacman','-Q']).splitlines(keepends=True)))
                    if any(line.startswith((T.NAME+' ').encode()) for line in actual.splitlines()):
                        clean_run('cleanup-remove',['/usr/bin/pacman',*pacman,'--noconfirm','--noscriptlet','-R',T.NAME])
                    need(b''.join(sorted(clean_run('cleanup-restored-inventory',['/usr/bin/pacman','-Q']).splitlines(keepends=True)))==base,'failure cleanup restores exact349')
                    if baseline_reasons is not None:
                        restored={key:b''.join(sorted(clean_run('cleanup-reasons-'+key,['/usr/bin/pacman',flag]).splitlines(keepends=True)))
                                  for key,flag in (('explicit','-Qqe'),('dependencies','-Qqd'))}
                        need(restored==baseline_reasons,'failure cleanup restores install reasons')
                except BaseException as error:cleanup_failures.append('ALPM-restore:'+type(error).__name__)
            cleanup=retire_homes(clean_run,(signing,trust),work);cleanup['failures']+=cleanup_failures;report['cleanup']=cleanup
            try:report['global_config_unchanged']=T.pin(Path('/etc/pacman.conf'))==protected_config
            except BaseException:report['global_config_unchanged']=False
            try:report['global_trust_unchanged']=T.snapshot(Path('/etc/pacman.d/gnupg'))==protected_trust
            except BaseException:report['global_trust_unchanged']=False
            if not report['global_config_unchanged'] or not report['global_trust_unchanged']:cleanup['failures'].append('global-policy-drift')
            if primary is None and not cleanup['failures']:report['stages'].append('cleanup')
            primary=primary_failure(primary,cleanup)
            if primary is None and report['stages']==list(T.STAGES):report['status']='PASS_RELEASE_TOOLS_NATIVE_ALPM_UPGRADE'
            report['commands']=commands.records
            try:
                (scope/'commands.json').write_bytes(T.encoded(commands.records));(scope/'result.json').write_bytes(T.encoded(report))
                for path in scope.iterdir():path.chmod(0o644)
                for directory in (scope,scope.parent,STORE):directory.chmod(0o755)
            except BaseException as failure:
                if primary is None:primary=failure
                else:primary.add_note('report retained incompletely: '+type(failure).__name__)
            return primary
        # Preserve the original rejection even if any later cleanup step fails.
        primary=D.preserve_primary(primary,finish_cleanup)
        if primary is not None:
            if traceback is None:traceback=primary.__traceback__
            try:D.emit(scope,commands.records,report,map_hash,primary)
            except BaseException:pass
    if primary is not None:raise primary.with_traceback(traceback)
    need(report['status']=='PASS_RELEASE_TOOLS_NATIVE_ALPM_UPGRADE','complete lifecycle required')
    for path in scope.iterdir():path.chmod(0o644)
    scope.chmod(0o755);(STORE/'journey').chmod(0o755);STORE.chmod(0o755)
    return report


def export(output,map_hash):
    """Copy only component DATA and its pinned owned-command logs, no actors."""
    from common import verify_source
    verify_source(Path(__file__).resolve().parents[1],map_hash)
    output=Path(output).absolute();scope=STORE/'journey'/'release-alpm-v1'
    need(os.getuid()==os.geteuid()!=0 and not os.path.lexists(output)
         and not any(p.is_symlink() for p in output.parents),'unprivileged fresh component DATA export')
    raw=T.ordinary(scope/'result.json',4*1024**2);report=json.loads(raw)
    need(report.get('schema_version')==1 and report.get('operation')==T.OPERATION
         and report.get('source_map_sha256')==map_hash,'same-source lifecycle DATA identity')
    commands_raw=T.ordinary(scope/'commands.json',4*1024**2);commands=json.loads(commands_raw)
    need(type(commands) is list and len(commands)<=160 and commands==report['commands'],'finite original command index join')
    files={'result.json':raw,'commands.json':commands_raw};total=len(raw)+len(commands_raw)
    for row in commands:
        name=row['log'];need(re.fullmatch(r'[0-9]{3}-[A-Za-z0-9._+-]{1,96}\.log',name) and name not in files,'unique finite command log')
        body=T.ordinary(scope/name,1024**2);need(T.data_pin(body)==row['log_pin'],'raw original owned command log pin')
        total+=len(body);need(total<=32*1024**2,'finite release lifecycle DATA total');files[name]=body
    output.mkdir(mode=0o700)
    for name,body in files.items():
        with (output/name).open('xb') as stream:stream.write(body)
        (output/name).chmod(0o600)
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside-image',action='store_true');parser.add_argument('--map-sha256',required=True)
    args=parser.parse_args();need(args.inside_image,'explicit owned image operation required')
    inside(Path(__file__).resolve().parents[1],args.map_sha256)

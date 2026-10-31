# SPDX-License-Identifier: MIT
"""Owned-image TEST signing/ALPM lifecycle and finite public DATA export."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import sys
import tempfile
import tarfile
import importlib.util

sys.path.insert(0,str(Path(__file__).resolve().parent))
from installed_tools_v1 import PREFIX, SDK, load_packaged_workflow, need, pin

STORE=Path('/opt/native-developer-alpm-v1/evidence')
ARCHIVE=Path('/tmp/installed-package-build/cachy-asahi-developer-tools-0.1.0-1-any.pkg.tar.zst')
NAME='cachy-asahi-developer-tools'
UID='TEST ONLY developer-tools <developer-tools@test.invalid>'


# Versioned enum-only failure protocol. No arbitrary exception names/messages.
_DIAGNOSTIC_PHASE_V1='UNKNOWN'
_DIAGNOSTIC_FIRST_FAILURE_V1=None
DIAGNOSTIC_PHASES_V1=frozenset(['UNKNOWN', 'PAIR_ENTRY', 'PAIR_SOURCE_VERIFY', 'PAIR_INPUT_CONTRACT', 'PAIR_MAKEPKG_ONE', 'PAIR_MAKEPKG_TWO', 'PAIR_ARCHIVE_ONE', 'PAIR_ARCHIVE_TWO', 'PAIR_COMPARE', 'PAIR_COMPLETE', 'ALPM_ENTRY', 'ALPM_SOURCE_VERIFY', 'ALPM_BASELINE', 'OFFICIAL_GIT_INPUTS', 'ALPM_TEST_KEY', 'ALPM_TEST_FINGERPRINT', 'ALPM_EXPORT_TEST_PUBLIC', 'ALPM_SIGN_ARCHIVE', 'ALPM_UNTRUSTED_CONTROL', 'ALPM_IMPORT_TEST_PUBLIC', 'ALPM_TRUST_MEMBERSHIP', 'ALPM_OWNERTRUST', 'ALPM_VERIFY_TEST_SIGNATURE', 'ALPM_INSTALL', 'ALPM_INSTALLED_INVENTORY', 'ALPM_OWNER_CHECK', 'ALPM_VERSION', 'ALPM_RUNTIME_VERIFY', 'USR_JOURNEYS', 'MOVED_JOURNEYS', 'ALPM_REMOVE', 'ALPM_REMOVED_INVENTORY', 'ALPM_KEY_HOME_RETIREMENT', 'ALPM_AGENT_ABSENCE', 'ALPM_OTHER_STEP', 'ALPM_PRESERVATION', 'ALPM_COMPLETE'])
DIAGNOSTIC_CODES_V1=frozenset(('FILE_NOT_FOUND','PERMISSION','TIMEOUT','OS_ERROR','VALUE_GUARD','RUNTIME_GUARD','UNCLASSIFIED'))

def diagnostic_error_code_v1(error):
    for cls,code in ((FileNotFoundError,'FILE_NOT_FOUND'),(PermissionError,'PERMISSION'),(TimeoutError,'TIMEOUT'),(OSError,'OS_ERROR'),(ValueError,'VALUE_GUARD'),(RuntimeError,'RUNTIME_GUARD')):
        if isinstance(error,cls):return code
    return 'UNCLASSIFIED'

def remember_failure_v1(error):
    global _DIAGNOSTIC_FIRST_FAILURE_V1
    if _DIAGNOSTIC_FIRST_FAILURE_V1 is None:
        _DIAGNOSTIC_FIRST_FAILURE_V1=dict(phase=_DIAGNOSTIC_PHASE_V1 if _DIAGNOSTIC_PHASE_V1 in DIAGNOSTIC_PHASES_V1 else 'UNKNOWN',error_code=diagnostic_error_code_v1(error))

def emit_failure_v1(map_hash,emit=print):
    if not re.fullmatch('[0-9a-f]{64}',map_hash or ''):return
    failure=_DIAGNOSTIC_FIRST_FAILURE_V1 or dict(phase='UNKNOWN',error_code='UNCLASSIFIED')
    value=dict(schema=1,status='INSTALLED_IMAGE_FAILURE_STAGE_DATA_ONLY_V1',source_map_sha256=map_hash,phase=failure['phase'],error_code=failure['error_code'])
    if value['phase'] not in DIAGNOSTIC_PHASES_V1 or value['error_code'] not in DIAGNOSTIC_CODES_V1:return
    try:emit('NATIVE_INSTALLED_ALPM_DIAGNOSTIC_V1 '+json.dumps(value,sort_keys=True,separators=(',',':')),flush=True)
    except Exception:pass


def prepare(root,context,map_hash,carrier,cache):
    from common import verify_source
    manifest=verify_source(root,map_hash);target=context/'alpm-source';target.mkdir()
    for name in sorted(set(manifest['files'])|{'native/source-map.json'}):
        source=root/name;out=target/name;out.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,out);out.chmod(stat.S_IMODE(source.stat().st_mode))
    git_context(root,context,carrier,cache)


def dockerfile(base,map_hash):
    need(re.fullmatch('[0-9a-f]{64}',map_hash),'whole source map required')
    needle='RUN cp /builder-packages.lock /builder-dependency-packages.lock'
    need(base.count(needle)==1,'exact prefix overlay seam')
    text=base.replace(needle,'COPY alpm-source/ /opt/native-developer-alpm-v1/source/\nCOPY installed-git/ /opt/native-developer-alpm-v1/git-inputs/\nRUN pacman -U --noconfirm --noscriptlet /opt/native-developer-alpm-v1/git-inputs/*.pkg.tar.xz && ldconfig && pacman -Q | LC_ALL=C sort > /builder-packages.lock\n'+needle)
    original='RUN cd /tmp/installed-package-build && PKGDEST=/tmp/installed-package-build SRCDEST=/tmp/installed-package-build BUILDDIR=/tmp/installed-package-build makepkg --nodeps --nocheck --nosign --noconfirm --config /opt/native-developer-installed-v1/makepkg.conf\n'
    need(text.count(original)==1,'exact single-build seam for explicit ALPM pair')
    paired='RUN /usr/bin/python3 -I -B /opt/native-developer-alpm-v1/source/native/installed_alpm_v1.py --build-pair --map-sha256 '+map_hash+'\n'
    text=text.replace(original,paired)
    needle='&& rm -rf /tmp/installed-package-build\n'
    need(text.count(needle)==1,'exact post-prefix-install seam')
    command='&& /usr/bin/python3 -I -B /opt/native-developer-alpm-v1/source/native/installed_alpm_v1.py --inside-image --map-sha256 '+map_hash+' '+needle
    return text.replace(needle,command)


def strict_signature(status, fingerprint):
    need(re.fullmatch('[0-9A-F]{40}',fingerprint or ''),'explicit TEST primary fingerprint')
    records=[line.split()[1:] for line in status.splitlines() if line.startswith('[GNUPG:] ')]
    need(not any(r and r[0] in ('EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','FAILURE','NODATA','TRUST_NEVER','TRUST_UNDEFINED') for r in records),
         'bad/expired/revoked/unknown TEST signature refused')
    valid=[r for r in records if r and r[0]=='VALIDSIG']
    need(len(valid)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==fingerprint,
         'exact TEST primary signer required')
    need(any(r and r[0]=='TRUST_ULTIMATE' for r in records),'only explicitly trusted TEST primary accepted')


def test_config(trust):
    need(trust.is_absolute() and trust.name=='trust' and trust.parent.name.startswith('developer-tools-test-'), 'owned TEST trust path only')
    return ('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\n'
            'GPGDir = '+str(trust)+'\nHookDir = /builder-disabled-hooks\n')


def snapshot(root):
    rows={}
    if not root.exists():return rows
    for path in sorted(root.rglob('*')):
        info=path.lstat();name=str(path.relative_to(root))
        if stat.S_ISREG(info.st_mode):rows[name]=dict(mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,**pin(path))
        elif stat.S_ISLNK(info.st_mode):rows[name]=dict(link=os.readlink(path))
        elif not stat.S_ISDIR(info.st_mode):rows[name]=dict(kind='special')
    return rows


# SPDX-License-Identifier: MIT
# Inserted into the separately versioned installed_alpm_v1 module; no new actor.
def git_policy(root):
    from common import DESKTOP,input_contract
    raw=(root/'native/desktop574-inputs.lock.json').read_bytes()
    need(hashlib.sha256(raw).hexdigest()==DESKTOP,'held desktop574 authority required')
    value=json.loads((root/'native/alpm-contract-v1.json').read_text())['git_inputs']
    rows=value['rows'];names={'git','perl-error','perl-mailtools','perl-timedate','zlib-ng'}
    need(len(rows)==5 and {r['name'] for r in rows}==names,'exact five Git dependency additions')
    available={r['name']:r for r in json.loads(raw)['packages']}
    need(all(available.get(r['name'])==r for r in rows),'Git rows must be unchanged frozen release rows')
    _,_,base=input_contract(root);versions=dict(line.decode().split(' ',1) for line in base.splitlines())
    need(not names & versions.keys(),'no existing dependency version replacement')
    complete=set(versions)|names
    need(all(not {re.split(r'[<>=]',n)[0] for n in r['conflicts']+r['replaces']} & complete
             and set(r['depends'])<=complete for r in rows),'closed additions cannot replace or conflict with selected dependencies')
    expected=b''.join(sorted(base.splitlines(keepends=True)+[(r['name']+' '+r['version']+'\n').encode() for r in rows]))
    need(len(expected.splitlines())==354 and hashlib.sha256(expected).hexdigest()==value['expected354_sha256'],'exact selected354 inventory')
    return value,expected


def git_context(root,context,carrier,cache):
    import time
    import provision
    from common import input_contract
    policy,_=git_policy(root);profile=provision.carrier_profile(root)
    need(profile['source_commit']==policy['carrier_source'] if 'source_commit' in profile else provision.CARRIER_SOURCE==policy['carrier_source'],'genuine existing1154 carrier source')
    target=context/'installed-git';target.mkdir();deadline=time.monotonic()+120
    for row in policy['leaves']:
        name=row['filename'];relative='packages/'+name
        need(profile['files'].get(relative)=={'bytes':row['bytes'],'sha256':row['sha256']},'selected leaf in original1154 carrier')
        source=carrier/relative
        need(not any(p.is_symlink() for p in (source,*source.parents)),'Git input aliases refused')
        expected=dict(size=row['bytes'],sha256=row['sha256'])
        with (target/name).open('xb') as stream:
            provision.checked_file(source,expected,deadline,stream);stream.flush();os.fsync(stream.fileno())
        provision.checked_file(target/name,expected,deadline);(target/name).chmod(0o644)
    _,original,_=input_contract(root)
    ring=next(r for r in original['keyring_files'] if r['filename']=='archlinuxarm.gpg')
    with (target/'archlinuxarm.gpg').open('xb') as stream:
        provision.checked_file(cache/'archlinuxarm.gpg',ring,deadline,stream)
    (target/'archlinuxarm.gpg').chmod(0o644)
    # Original cache/carrier are read only. New package bytes go only to the
    # new-operation context, never the512-row/default cache or fetch callbacks.


def official_signature(status,fingerprint):
    records=[line.split()[1:] for line in status.splitlines() if line.startswith('[GNUPG:] ')]
    need(not any(r and r[0] in ('EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','KEYEXPIRED','KEYREVOKED','FAILURE','NODATA') for r in records),'official Git signature refusal')
    valid=[r for r in records if r and r[0]=='VALIDSIG']
    need(len(valid)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==fingerprint,'original pinned official ALARM primary signer')


def verify_git_inputs(commands,root,home):
    from common import input_contract
    policy,_=git_policy(root);_,original,_=input_contract(root)
    directory=Path('/opt/native-developer-alpm-v1/git-inputs')
    ring=next(r for r in original['keyring_files'] if r['filename']=='archlinuxarm.gpg')
    need(pin(directory/'archlinuxarm.gpg')=={'bytes':ring['size'],'sha256':ring['sha256']},'same original public ALARM keyring')
    for row in policy['leaves']:
        need(pin(directory/row['filename'])=={'bytes':row['bytes'],'sha256':row['sha256']},'exact Git archive/signature input')
    gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve']
    commands.run('git-original-key-import',gpg+['--import',str(directory/'archlinuxarm.gpg')],directory)
    statuses={}
    for row in policy['rows']:
        raw=commands.run('git-official-'+row['name'],gpg+['--status-fd=1','--verify',str(directory/(row['filename']+'.sig')),str(directory/row['filename'])],directory)
        official_signature(raw.decode(),policy['signer_fingerprint'])
        statuses[row['filename']]=raw.decode()
    return dict(status='PASS_EXACT_FIVE_ORIGINAL_SIGNED_GIT_INPUTS',signer=policy['signer_fingerprint'],statuses=statuses,
        files=policy['leaves'],expected354_sha256=policy['expected354_sha256'],keyring={'bytes':ring['size'],'sha256':ring['sha256']})



PAIR_EPOCH='1791748800'
PAIR_ROOTS=('/tmp/developer-pair-one','/tmp/developer-pair-two')
PAIR_BUILD='/tmp/developer-pair-build'
PAIR_EVIDENCE=Path('/tmp/developer-pair-evidence')


def archive_data(path):
    """Inert complete native package comparison; no archive member execution."""
    payload={};metadata={}
    with tarfile.open(path,'r:*') as archive:
        for member in archive.getmembers():
            name=member.name.removeprefix('./');part=Path(name)
            need(name and not part.is_absolute() and '..' not in part.parts and name not in payload,'ordinary unique package member')
            need(member.isfile() or member.isdir(),'developer package permits only regular files/directories')
            row=dict(mode=member.mode,uid=member.uid,gid=member.gid,type='file' if member.isfile() else 'directory')
            if member.isfile():
                body=archive.extractfile(member).read();row.update(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
                if name in ('.PKGINFO','.BUILDINFO'):metadata[name]=body
            payload[name]=row
    need(set(metadata)=={'.PKGINFO','.BUILDINFO'},'actual PKGINFO/BUILDINFO required')
    return payload,metadata


def build_pair(source,map_hash):
    global _DIAGNOSTIC_PHASE_V1
    _DIAGNOSTIC_PHASE_V1='PAIR_ENTRY'
    from common import verify_source
    need(os.getuid()==os.geteuid()!=0 and os.uname().machine=='aarch64','actual ordinary native pair builder')
    _DIAGNOSTIC_PHASE_V1='PAIR_SOURCE_VERIFY'
    verify_source(source,map_hash)
    _DIAGNOSTIC_PHASE_V1='PAIR_INPUT_CONTRACT'
    _,expected=git_policy(source)
    need(Path('/builder-packages.lock').read_bytes()==expected,'exact selected354 pair environment')
    path=source/'scripts/workflows/developer_workflow.py'
    need(hashlib.sha256(path.read_bytes()).hexdigest()=='531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba','held original supervision producer')
    spec=importlib.util.spec_from_file_location('_native_developer_pair_workflow',path);W=importlib.util.module_from_spec(spec);spec.loader.exec_module(W)
    need(not PAIR_EVIDENCE.exists() and not Path(PAIR_BUILD).exists() and all(not Path(p).exists() for p in PAIR_ROOTS),'fresh independent pair trees')
    PAIR_EVIDENCE.mkdir(mode=0o700);(PAIR_EVIDENCE/'home').mkdir(mode=0o700)
    commands=W.Commands(PAIR_EVIDENCE,PAIR_EVIDENCE/'home','/usr/bin:/bin',timeout=400,total=600,max_output=256*1024)
    commands.env.update(SOURCE_DATE_EPOCH=PAIR_EPOCH,PACKAGER='TEST ONLY native developer pair <developer-tools@test.invalid>',BUILDDIR=PAIR_BUILD)
    before=pin(Path('/builder-packages.lock'));builds=[];views=[]
    for number,directory in enumerate(PAIR_ROOTS,1):
        root=Path(directory);root.mkdir(mode=0o700);Path(PAIR_BUILD).mkdir(mode=0o700)
        for original in sorted((PREFIX/'recipe').iterdir()):
            need(original.is_file() and not original.is_symlink(),'fixed pair recipe file only');shutil.copyfile(original,root/original.name)
        commands.env.update(PKGDEST=str(root),SRCDEST=str(root))
        _DIAGNOSTIC_PHASE_V1='PAIR_MAKEPKG_ONE' if number==1 else 'PAIR_MAKEPKG_TWO'
        pair_argv=['/usr/bin/makepkg','--nodeps','--nocheck','--nosign','--noconfirm','--config',str(PREFIX/'makepkg.conf')]
        try:
            commands.run('native-makepkg-'+str(number),pair_argv,root)
        except BaseException:
            try:emit_pair_command_v1(commands,number,root,map_hash,pair_argv)
            except BaseException:pass  # The original command failure remains primary.
            raise
        _DIAGNOSTIC_PHASE_V1='PAIR_ARCHIVE_ONE' if number==1 else 'PAIR_ARCHIVE_TWO'
        package=root/ARCHIVE.name;payload,metadata=archive_data(package)
        builds.append(dict(directory=str(root),archive=pin(package),payload=payload,PKGINFO=dict(bytes=len(metadata['.PKGINFO']),sha256=hashlib.sha256(metadata['.PKGINFO']).hexdigest()),BUILDINFO=dict(bytes=len(metadata['.BUILDINFO']),sha256=hashlib.sha256(metadata['.BUILDINFO']).hexdigest())))
        views.append(metadata)
        shutil.rmtree(PAIR_BUILD)
    _DIAGNOSTIC_PHASE_V1='PAIR_COMPARE'
    need(builds[0]['archive']==builds[1]['archive'] and builds[0]['payload']==builds[1]['payload'] and views[0]==views[1],'exact native archive/payload/PKGINFO/BUILDINFO pair required')
    need(pin(Path('/builder-packages.lock'))==before,'pair dependency inventory unchanged')
    shutil.copyfile(Path(PAIR_ROOTS[0])/ARCHIVE.name,ARCHIVE)
    report=dict(schema=1,status='PASS_REAL_NATIVE_DEVELOPER_PAIR_V1',source_map_sha256=map_hash,builds=builds,
        epoch=PAIR_EPOCH,builddir=PAIR_BUILD,independent_clean_recipe_roots=True,recreated_builddir_each_time=True,
        check='NOT_RUN_EXPLICIT_NOCHECK',inventory_before=before,inventory_after=pin(Path('/builder-packages.lock')),
        commands=commands.records,comparison='EXACT_ARCHIVE_PAYLOAD_PKGINFO_BUILDINFO')
    (PAIR_EVIDENCE/'result.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    for root in PAIR_ROOTS:shutil.rmtree(root)
    _DIAGNOSTIC_PHASE_V1='PAIR_COMPLETE'


def protected_file(path):
    path=Path(path);info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_size<=16*1024**2,'ordinary finite protected file')
    return dict(mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,**pin(path))


def protected_state(root):
    """Complete owned-image metadata and hashes; never original file bodies."""
    root=Path(root);info=root.lstat()
    need(stat.S_ISDIR(info.st_mode) and not root.is_symlink(),'ordinary protected home/trust root')
    rows={};total=0
    for path in sorted(root.rglob('*')):
        info=path.lstat();name=str(path.relative_to(root))
        row=dict(mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid)
        if stat.S_ISREG(info.st_mode):
            total+=info.st_size;need(total<=16*1024**2,'finite owned-image protected state')
            row.update(kind='file',**pin(path))
        elif stat.S_ISDIR(info.st_mode):row['kind']='directory'
        elif stat.S_ISLNK(info.st_mode):row.update(kind='symlink',link=os.readlink(path))
        else:need(False,'special protected path refused')
        rows[name]=row;need(len(rows)<=4096,'finite protected namespace')
    info=root.lstat()
    return dict(root=dict(mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid),entries=rows)


def inside(source,map_hash):
    global _DIAGNOSTIC_PHASE_V1
    _DIAGNOSTIC_PHASE_V1='ALPM_ENTRY'
    need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'
         and source==Path('/opt/native-developer-alpm-v1/source')
         and Path('/builder-dependency-packages.lock').is_file(), 'owned disposable native image root only')
    from common import verify_source,input_contract
    _DIAGNOSTIC_PHASE_V1='ALPM_SOURCE_VERIFY'
    verify_source(source,map_hash);_,expected=git_policy(source)
    W=load_packaged_workflow();base=Path('/builder-packages.lock').read_bytes()
    need(base==expected==Path('/builder-dependency-packages.lock').read_bytes()
         and len(base.splitlines())==354 and b'cachy-asahi-developer-tools ' not in base, 'exact selected354 and package absent')
    contract=json.loads((PREFIX/'installed-contract-v1.json').read_text())
    payload=contract['payload_files'];need(all(not os.path.lexists('/usr/'+r['path']) for r in payload), 'all project-owned paths absent before install')
    protected_config=pin(Path('/etc/pacman.conf'));protected_trust=snapshot(Path('/etc/pacman.d/gnupg'))
    user=Path('/opt/native-developer-alpm-v1/user-data');user.mkdir(parents=True)
    (user/'keep.txt').write_text('TEST existing developer choices\n');(user/'keep.txt').chmod(0o600)
    alarm=pwd.getpwnam('alarm');protected_home=Path(alarm.pw_dir);home_before=protected_state(protected_home);trust_before=protected_state(Path('/etc/pacman.d/gnupg'));os.chown(user,alarm.pw_uid,alarm.pw_gid);os.chown(user/'keep.txt',alarm.pw_uid,alarm.pw_gid)
    user_before=snapshot(user)
    out=Path('/out');need(not out.exists(),'fresh image-only lifecycle evidence root');out.mkdir();os.chown(out,alarm.pw_uid,alarm.pw_gid)
    journey=out/'journey'
    raw=out/'alpm-v1';raw.mkdir(mode=0o700);(raw/'home').mkdir(mode=0o700)
    commands=W.Commands(raw,raw/'home','/usr/bin:/bin',timeout=400,total=600,max_output=256*1024)
    report=dict(schema=1,status='FAIL',purpose='TEST_ONLY_DISPOSABLE_NATIVE_IMAGE_ALPM_V1',
        source_map_sha256=map_hash,package=pin(ARCHIVE),before_inventory=pin(Path('/builder-packages.lock')),
        execution_scope='OWNED_IMAGE_BUILD_STAGE; runuser alarm; not184 read-only consumer execution',
        global_config_before=protected_config,global_trust_before=protected_trust,
        physical_M2='NOT_RUN',release='NOT_ADMITTED',commands=commands.records,
        protected_paths=dict(home=str(protected_home),trust='/etc/pacman.d/gnupg',config='/etc/pacman.conf'),
        protected_before=dict(home=home_before,trust=trust_before,config=protected_file(Path('/etc/pacman.conf'))))
    versions=dict(line.decode().split(' ',1) for line in base.splitlines())
    report['tools']={name:dict(path='/usr/bin/'+name,provider=provider,version=versions[provider],**pin(Path('/usr/bin')/name))
        for name,provider in {'gpg':'gnupg','gpgconf':'gnupg','gpg-connect-agent':'gnupg','pacman':'pacman','runuser':'util-linux','git':'git'}.items()}
    work=Path(tempfile.mkdtemp(prefix='developer-tools-test-',dir='/tmp'));work.chmod(0o700)
    signing,trust,official=work/'signing',work/'trust',work/'official'
    for path in (signing,trust,official):path.mkdir(mode=0o700)
    primary=None;retired=[]
    def run(step,argv,expected=0,cwd=work):
        global _DIAGNOSTIC_PHASE_V1
        _DIAGNOSTIC_PHASE_V1={'baseline-inventory': 'ALPM_BASELINE', 'generate-test-key': 'ALPM_TEST_KEY', 'test-primary-fingerprint': 'ALPM_TEST_FINGERPRINT', 'export-only-test-public': 'ALPM_EXPORT_TEST_PUBLIC', 'sign-exact-built-package': 'ALPM_SIGN_ARCHIVE', 'untrusted-test-signature-control': 'ALPM_UNTRUSTED_CONTROL', 'import-only-test-public': 'ALPM_IMPORT_TEST_PUBLIC', 'trust-key-membership': 'ALPM_TRUST_MEMBERSHIP', 'trust-only-test-primary': 'ALPM_OWNERTRUST', 'verify-exact-test-signature': 'ALPM_VERIFY_TEST_SIGNATURE', 'required-signature-install': 'ALPM_INSTALL', 'installed-inventory': 'ALPM_INSTALLED_INVENTORY', 'installed-owner': 'ALPM_OWNER_CHECK', 'alpm-installed-version': 'ALPM_VERSION', 'alpm-installed-runtime-verify': 'ALPM_RUNTIME_VERIFY', 'usr-installed-user-journeys': 'USR_JOURNEYS', 'installed-user-journeys': 'MOVED_JOURNEYS', 'required-policy-remove': 'ALPM_REMOVE', 'removed-inventory': 'ALPM_REMOVED_INVENTORY', 'retire-test-gpg-home': 'ALPM_KEY_HOME_RETIREMENT', 'test-agent-no-autostart-control': 'ALPM_AGENT_ABSENCE'}.get(step,'ALPM_OTHER_STEP')
        return commands.run(step,list(map(str,argv)),cwd,expected)
    def inventory(step):return b''.join(sorted(run(step,['/usr/bin/pacman','-Q']).splitlines(keepends=True)))
    try:
        need(inventory('baseline-inventory')==base,'actual baseline349 inventory')
        _DIAGNOSTIC_PHASE_V1='OFFICIAL_GIT_INPUTS'
        report['git_inputs']=verify_git_inputs(commands,source,official)
        pair=json.loads((PAIR_EVIDENCE/'result.json').read_text())
        need(pair['status']=='PASS_REAL_NATIVE_DEVELOPER_PAIR_V1' and pair['source_map_sha256']==map_hash and {r['archive']['sha256'] for r in pair['builds']}=={pin(ARCHIVE)['sha256']},'verified exact pair before signing/install')
        report['native_pair']=pair
        gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',str(signing),'--no-auto-key-retrieve','--pinentry-mode','loopback','--passphrase','']
        run('generate-test-key',gpg+['--quick-generate-key',UID,'ed25519','sign','1d'])
        listing=run('test-primary-fingerprint',gpg+['--with-colons','--list-keys']).decode()
        fingerprints=[line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
        need(len(fingerprints)==1 and re.fullmatch('[0-9A-F]{40}',fingerprints[0]),'one explicit TEST primary key')
        fingerprint=fingerprints[0];public=work/'TEST-public.asc'
        public.write_bytes(run('export-only-test-public',gpg+['--armor','--export',fingerprint]))
        run('sign-exact-built-package',gpg+['--local-user',fingerprint,'--output',str(ARCHIVE)+'.sig','--detach-sign',str(ARCHIVE)])
        verifier=['/usr/bin/gpg','--batch','--no-options','--homedir',str(trust),'--no-auto-key-retrieve']
        unknown=run('untrusted-test-signature-control',verifier+['--status-fd=1','--verify',str(ARCHIVE)+'.sig',str(ARCHIVE)],'nonzero')
        need(b'NO_PUBKEY' in unknown,'untrusted key must actually refuse')
        run('import-only-test-public',verifier+['--import',str(public)])
        trusted=run('trust-key-membership',verifier+['--with-colons','--list-keys']).decode()
        need([l.split(':')[9] for l in trusted.splitlines() if l.startswith('fpr:')]==[fingerprint], 'trust context contains only explicit TEST key')
        ownertrust=work/'ownertrust.txt';ownertrust.write_text(fingerprint+':6:\n')
        run('trust-only-test-primary',verifier+['--import-ownertrust',str(ownertrust)])
        status=run('verify-exact-test-signature',verifier+['--status-fd=1','--verify',str(ARCHIVE)+'.sig',str(ARCHIVE)]).decode()
        strict_signature(status,fingerprint)
        config=work/'pacman.conf';config.write_text(test_config(trust))
        pacman=['/usr/bin/pacman','--config',str(config)]
        run('required-signature-install',pacman+['--noconfirm','--noscriptlet','-U',str(ARCHIVE)])
        wanted=b''.join(sorted(base.splitlines(keepends=True)+[b'cachy-asahi-developer-tools 0.1.0-1\n']))
        need(inventory('installed-inventory')==wanted,'exact355 while installed')
        for row in payload:
            path=Path('/usr')/row['path'];info=path.lstat()
            need(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==row['mode'] and pin(path)=={k:row[k] for k in ('bytes','sha256')},'actual ALPM payload pin/mode/root ownership')
            need(run('installed-owner',pacman+['-Qoq',str(path)]).strip()==NAME.encode(),'actual ALPM file ownership')
        version=run('alpm-installed-version',['/usr/bin/runuser','-u','alarm','--','/usr/bin/cachy-asahi-developer-tools','--version'])
        need(version.strip()==b'cachy-asahi-developer-tools 0.1.0','actual ALPM-installed launcher version')
        verified=json.loads(run('alpm-installed-runtime-verify',['/usr/bin/runuser','-u','alarm','--','/usr/bin/cachy-asahi-developer-tools','verify']))
        need(verified['status']=='PASS_PACKAGED_RUNTIME' and verified['runtime']=='/usr/lib/cachy-asahi-developer-tools/0.1.0','actual ALPM-installed runtime path')
        Path('/builder-packages.lock').write_bytes(wanted)
        # The helper has no access to the TEST signing directory; all developer
        # commands execute as the same non-root user in the owned image.
        run('usr-installed-user-journeys',['/usr/bin/runuser','-u','alarm','--','/usr/bin/python3','-I','-B',
            str(source/'native/installed_guest_v1.py'),'--output','/out/journey','--map-sha256',map_hash,'--alpm-installed','--installed-usr'])
        usr_journey=Path('/out/usr-journey');journey.rename(usr_journey)
        run('installed-user-journeys',['/usr/bin/runuser','-u','alarm','--','/usr/bin/python3','-I','-B',
            str(source/'native/installed_guest_v1.py'),'--output','/out/journey','--map-sha256',map_hash,'--alpm-installed'])
        run('required-policy-remove',pacman+['--noconfirm','--noscriptlet','-R',NAME])
        need(inventory('removed-inventory')==base,'complete354 dependencies restored')
        need(all(not os.path.lexists('/usr/'+r['path']) for r in payload),'all34 package-owned paths absent')
        need(snapshot(user)==user_before,'user bytes/modes/ownership preserved')
        Path('/builder-packages.lock').write_bytes(base)
        signature=Path(str(ARCHIVE)+'.sig');public_text=public.read_text('ascii')
        need(public_text.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----') and 'PRIVATE KEY' not in public_text,'only TEST public key DATA may be retained')
        report.update(status='PASS_TEST_SIGNED_ALPM_LIFECYCLE_V1',fingerprint=fingerprint,
            signature=dict(**pin(signature),base64=base64.b64encode(signature.read_bytes()).decode('ascii')),
            public_key=dict(**pin(public),text=public_text),alpm_runtime=verified,
            signature_status=status,trust_context='ONLY_EXPLICIT_TEST_PUBLIC_PRIMARY',signature_semantics='Required/Required',
            installed_count=355,restored_count=354,package_owned_paths_absent=True,user_data_preserved=True,
            user_before=user_before,user_after=snapshot(user))
    except BaseException as error:
        remember_failure_v1(error)
        primary=error;report['failure']=dict(type=type(error).__name__,message=str(error)[:1024])
        try:
            from build_summary import validate_summary
            safe=json.loads(Path('/out/journey/build-summary.json').read_text());validate_summary(safe,map_hash)
            print('NATIVE_INSTALLED_BUILD_SUMMARY '+json.dumps(safe,sort_keys=True),flush=True)
        except Exception:pass
        raise
    finally:
        for home in (signing,trust,official):
            try:
                run('retire-test-gpg-home',['/usr/bin/gpgconf','--homedir',str(home),'--kill','all'])
                run('test-agent-no-autostart-control',['/usr/bin/gpg-connect-agent','--homedir',str(home),'--no-autostart','/bye'],'nonzero')
                need(not any(stat.S_ISSOCK(p.lstat().st_mode) for p in home.rglob('*')),'no scoped GPG sockets after retirement')
                retired.append(str(home))
            except BaseException as error:
                remember_failure_v1(error)
                report['status']='FAIL';report['retirement_error']=type(error).__name__
        report['test_homes_retired']=str(signing) in retired and str(trust) in retired
        report['official_home_retired']=str(official) in retired
        report['global_trust_unchanged']=snapshot(Path('/etc/pacman.d/gnupg'))==protected_trust
        report['global_config_unchanged']=pin(Path('/etc/pacman.conf'))==protected_config
        report['protected_after']=dict(home=protected_state(protected_home),trust=protected_state(Path('/etc/pacman.d/gnupg')),config=protected_file(Path('/etc/pacman.conf')))
        report['protected_state_restored']=report['protected_before']==report['protected_after']
        shutil.rmtree(work);report['private_test_directory_absent']=not work.exists()
        report['commands']=commands.records
        (raw/'result.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        if primary is None:
            _DIAGNOSTIC_PHASE_V1='ALPM_PRESERVATION'
            need(report['test_homes_retired'] and report['official_home_retired'] and report['global_trust_unchanged'] and report['global_config_unchanged'] and report['protected_state_restored'], 'test trust cleanup/global protection unqualified')
    # Only our aggregate report is augmented. Original v1 command reports remain
    # byte-identical. Move the child guest output into the retained journey root.
    aggregate=json.loads((journey/'result.json').read_text());aggregate['test_alpm']=report
    aggregate['usr_journey']=json.loads((usr_journey/'result.json').read_text())
    for feature in ('workflow','build-systems','debugger','python','control','backend-v1'):
        (usr_journey/feature).rename(journey/('usr-'+feature))
    (usr_journey/'result.json').rename(journey/'usr-result.json')
    for name in ('package.json','build-summary.json'):
        if (usr_journey/name).exists():(usr_journey/name).rename(journey/('usr-'+name))
    shutil.rmtree(usr_journey)
    PAIR_EVIDENCE.rename(journey/'pair-v1')
    (journey/'result.json').write_text(json.dumps(aggregate,indent=2,sort_keys=True)+'\n')
    raw.rename(journey/'alpm-v1');raw=journey/'alpm-v1';raw.chmod(0o755)
    for path in raw.iterdir():
        if path.is_file():path.chmod(0o644)
    STORE.parent.mkdir(parents=True,exist_ok=True);out.rename(STORE)
    _DIAGNOSTIC_PHASE_V1='ALPM_COMPLETE'


def export(output,map_hash):
    """Copy only the source-defined finite public reports, never private trees."""
    from common import verify_source
    source=Path(__file__).resolve().parents[1];verify_source(source,map_hash)
    need(os.getuid()==os.geteuid()!=0 and not output.exists(),'unprivileged fresh DATA export only')
    import installed_projection_v1 as P
    original=STORE/'journey';output.mkdir(mode=0o700)
    def copy(name,expected=None):
        result=P._read(STORE,'journey/'+name,optional=True)
        if result is None:return
        body,_=result
        if expected is not None:need(P.C.pin(body)==expected,'original installed DATA pin differs')
        target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body);target.chmod(0o600)
    for name in ('result.json','package.json','build-summary.json','usr-result.json','usr-package.json','usr-build-summary.json'):copy(name)
    for feature,reports in P.REPORTS.items():
        for name in sorted(reports):copy(feature+'/'+name)
        raw=P._read(STORE,'journey/'+feature+'/result.json',optional=True)
        if raw is not None:
            for row in json.loads(raw[0]).get('commands',[]):
                need(P.LOG.fullmatch(row['log']),'finite original command log required');copy(feature+'/'+row['log'],row['log_pin'])
    for alias in ('','usr-'):
        backend=json.loads((original/(alias+'backend-v1')/'result.json').read_text())
        for name,row in backend['members'].items():
            need(name.startswith('/out/journey/python/venv/'),'fixed backend prefix');relative=name.removeprefix('/out/journey/')
            need(relative.removeprefix('python/venv/') in P.BACKEND,'fixed backend member only');copy(alias+relative,row)
    return json.loads((output/'result.json').read_text())


# SPDX-License-Identifier: MIT
"""Finite original command custody DATA; no raw strings or actor operations."""
import json
import re

PAIR_COMMAND_CENSUS_V1 = frozenset((
    'NOT_OBSERVED', 'RESERVED_LEADER_ONLY', 'RESERVED_MEMBERS_REMAIN',
    'UNKNOWN', 'PRESENT_OR_REUSED', 'EMPTY_ONCE', 'EMPTY_TWICE'))
PAIR_COMMAND_OWNERSHIP_V1 = frozenset(('OWNED', 'REAPED', 'UNKNOWN'))
PAIR_COMMAND_ROW_FIELDS_V1 = frozenset((
    'success', 'expected', 'launch_error_present', 'log_pin', 'supervision'))
PAIR_COMMAND_SUPERVISION_FIELDS_V1 = frozenset((
    'exit', 'reaped', 'ownership', 'group_census', 'output_complete',
    'timeout', 'signal_count', 'error_present'))


def _pair_need_v1(value):
    if not value:
        raise ValueError('PAIR_COMMAND_SCHEMA_REFUSED')


def validate_pair_command_v1(value, map_hash):
    """Validate the same exact finite schema for emission and host reuse."""
    _pair_need_v1(type(map_hash) is str and re.fullmatch('[0-9a-f]{64}', map_hash))
    _pair_need_v1(type(value) is dict and set(value) == {
        'schema', 'status', 'source_map_sha256', 'step', 'record_status', 'row'})
    _pair_need_v1(type(value['schema']) is int and value['schema'] == 1
        and value['status'] == 'PAIR_COMMAND_FAILURE_DATA_ONLY_V1'
        and value['source_map_sha256'] == map_hash
        and type(value['step']) is str and value['step'] in ('MAKEPKG_ONE', 'MAKEPKG_TWO')
        and type(value['record_status']) is str and value['record_status'] in (
            'NOT_OBSERVED', 'MATCHED_ORIGINAL_ROW', 'REFUSED'))
    row = value['row']
    if value['record_status'] != 'MATCHED_ORIGINAL_ROW':
        _pair_need_v1(row is None)
        return value
    _pair_need_v1(type(row) is dict and set(row) == PAIR_COMMAND_ROW_FIELDS_V1
        and type(row['success']) is bool and type(row['expected']) is int
        and row['expected'] == 0 and type(row['launch_error_present']) is bool)
    pinned = row['log_pin']
    _pair_need_v1(type(pinned) is dict and set(pinned) == {'bytes', 'sha256'}
        and type(pinned['bytes']) is int and 0 <= pinned['bytes'] <= 256*1024
        and type(pinned['sha256']) is str and re.fullmatch('[0-9a-f]{64}', pinned['sha256']))
    state = row['supervision']
    if state is not None:
        _pair_need_v1(type(state) is dict and set(state) == PAIR_COMMAND_SUPERVISION_FIELDS_V1)
        _pair_need_v1(state['exit'] is None or type(state['exit']) is int and -255 <= state['exit'] <= 255)
        _pair_need_v1(type(state['ownership']) is str and state['ownership'] in PAIR_COMMAND_OWNERSHIP_V1
            and type(state['group_census']) is str and state['group_census'] in PAIR_COMMAND_CENSUS_V1
            and type(state['signal_count']) is int and 0 <= state['signal_count'] <= 2
            and all(type(state[key]) is bool for key in (
                'reaped', 'output_complete', 'timeout', 'error_present')))
    return value


def capture_pair_command_v1(commands, number, cwd, map_hash, expected_argv):
    """Missing originals do not prove that no child launched."""
    _pair_need_v1(type(number) is int and number in (1, 2))
    value = dict(schema=1, status='PAIR_COMMAND_FAILURE_DATA_ONLY_V1',
        source_map_sha256=map_hash, step='MAKEPKG_ONE' if number == 1 else 'MAKEPKG_TWO',
        record_status='REFUSED', row=None)
    validate_pair_command_v1(value, map_hash)
    try:
        records = commands.records
        _pair_need_v1(type(records) is list)
        if len(records) < number:
            value['record_status'] = 'NOT_OBSERVED'
            return validate_pair_command_v1(value, map_hash)
        _pair_need_v1(len(records) == number and type(expected_argv) is list and expected_argv
            and all(type(arg) is str for arg in expected_argv))
        row = records[number-1]
        _pair_need_v1(type(row) is dict and row.get('step') == 'native-makepkg-'+str(number)
            and type(row.get('expected')) is int and row['expected'] == 0
            and type(row.get('argv')) is list and row['argv'] == expected_argv
            and type(row.get('cwd')) is str and row['cwd'] == str(cwd)
            and row.get('log') == '%03d-native-makepkg-%d.log' % (number-1, number))
        _pair_need_v1('launch_error' not in row or type(row['launch_error']) is str)
        original = row['supervision']
        state = None
        if original is not None:
            _pair_need_v1(type(original) is dict
                and type(original.get('signals')) is list and len(original['signals']) <= 2
                and all(type(sig) is str and sig in ('SIGTERM', 'SIGKILL') for sig in original['signals'])
                and (original.get('error') is None or type(original['error']) is str))
            state = {key:original[key] for key in (
                'exit', 'reaped', 'ownership', 'group_census', 'output_complete', 'timeout')}
            state.update(signal_count=len(original['signals']), error_present=original['error'] is not None)
        selected = dict(success=row['success'], expected=row['expected'],
            launch_error_present='launch_error' in row,
            log_pin={key:row['log_pin'][key] for key in ('bytes', 'sha256')}, supervision=state)
        _pair_need_v1(type(row['log_pin']) is dict and set(row['log_pin']) == {'bytes', 'sha256'})
        matched = dict(value, record_status='MATCHED_ORIGINAL_ROW', row=selected)
        return validate_pair_command_v1(matched, map_hash)
    except Exception:
        return value


def emit_pair_command_v1(commands, number, cwd, map_hash, expected_argv, emit=print):
    """Emission failure never replaces the caller's primary exception."""
    value = None
    try:
        value = capture_pair_command_v1(commands, number, cwd, map_hash, expected_argv)
        validate_pair_command_v1(value, map_hash)
        emit('NATIVE_INSTALLED_ALPM_COMMAND_DIAGNOSTIC_V1 '+json.dumps(
            value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False), flush=True)
    except Exception:
        pass
    return value


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--inside-image',action='store_true');parser.add_argument('--build-pair',action='store_true');parser.add_argument('--map-sha256',required=True);args=parser.parse_args()
    need(args.inside_image != args.build_pair,'one explicit owned image operation required')
    try:
        (build_pair if args.build_pair else inside)(Path(__file__).resolve().parents[1],args.map_sha256)
    except BaseException as error:
        remember_failure_v1(error);emit_failure_v1(args.map_sha256)
        raise

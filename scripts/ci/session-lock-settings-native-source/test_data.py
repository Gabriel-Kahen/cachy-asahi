#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-fenced modeled DATA controls; no constructor, role or actual Reader run."""
import ast
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
from types import SimpleNamespace
import unittest

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
NATIVE=HERE/'payload/native'
CONTRACT=json.loads((NATIVE/'build-tools-contract-v2.json').read_bytes())
PROFILE=json.loads((HERE/'profile.json').read_bytes())
OPERATION='session-lock-settings-alpm-v1'
PREFIX=Path('/opt/native-session-lock-settings-alpm-v1')


def fence(event,args):
    if event.startswith(('subprocess.','os.exec','os.spawn','os.fork','socket.','ctypes.')):
        raise AssertionError('native actor denied by DATA fence: '+event)
sys.addaudithook(fence)


def need(value,message='DATA condition'):
    if not value:raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def functions(filename,names,**extra):
    path=HERE/filename;s=path.read_text();tree=ast.parse(s);wanted=set(names.split(','))
    selected=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name in wanted]
    need(len(selected)==len(wanted),'exact isolated DATA definitions')
    producers=next((ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='PRODUCERS'for t in n.targets)),{})
    scope=dict(__file__=str(path),hashlib=hashlib,json=json,re=re,io=io,tarfile=tarfile,base64=base64,os=os,stat=stat,Path=Path,PurePosixPath=PurePosixPath,
               need=need,pin=pin,data_pin=pin,encoded=encoded,OPERATION=OPERATION,PREFIX=PREFIX,PRODUCERS=producers,
               PASS='PASS_SESSION_LOCK_SETTINGS_NATIVE_ALPM_COMPONENT',
               MAX_FILE=64*1024**2,MAX_TOTAL=128*1024**2,MAX_FILES=256,MAP='native/source-map.json',
               PARENT=PROFILE['parent'],PARENT_TREE=PROFILE['parent_tree'],ALLOWED=frozenset(PROFILE['overlay']))
    marker=next((n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='PRIVATE_MARKER'for t in n.targets)),None)
    if marker is not None:exec(compile(ast.Module(body=[marker],type_ignores=[]),'privacy-DATA-predicate','exec'),scope)
    scope.update(extra)
    exec(compile(ast.Module(body=selected,type_ignores=[]),'isolated-modeled-DATA-functions','exec'),scope)
    return SimpleNamespace(**scope)


def members():
    with tarfile.open(NATIVE/'build-tools-sources-v2.tar')as archive:
        return {m.name:archive.extractfile(m).read()for m in archive}


def archive(kind,mutate=None):
    """Explicit modeled uncompressed tar; never represented as a built package."""
    recipe=CONTRACT['recipes'][kind];source=members();pkg=copy.deepcopy(recipe['metadata'])
    pkg.update(builddate=['1794667200'],packager=['MODELED TEST ONLY'],size=[str(sum(v['bytes']for v in recipe['payload_files'].values()))])
    build={k:[v]for k,v in [('format','2'),('pkgname',recipe['name']),('pkgbase',recipe['name']),('pkgver',recipe['version']),('pkgarch','any'),('pkgbuild_sha256sum',recipe['source_files']['PKGBUILD']['sha256'])]}
    build.update(installed=recipe['buildinfo_installed'],buildenv=['check'])
    text=lambda value:''.join(k+' = '+x+'\n'for k,vs in value.items()for x in vs).encode()
    data={'.PKGINFO':text(pkg),'.BUILDINFO':text(build),'.MTREE':b'MODELED MTREE DATA'}
    data.update({name:source[f'recipes/{kind}/{Path(name).name}']for name in recipe['payload_files']})
    if mutate:mutate(data)
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w',format=tarfile.USTAR_FORMAT)as tar:
        for name in sorted({str(p)for n in recipe['payload_files']for p in Path(n).parents if str(p)!='.'}):
            item=tarfile.TarInfo(name+'/');item.type=tarfile.DIRTYPE;item.mode=0o755;tar.addfile(item)
        for name,raw in data.items():
            item=tarfile.TarInfo(name);item.mode=recipe['payload_files'].get(name,{}).get('mode',0o644);item.size=len(raw);tar.addfile(item,io.BytesIO(raw))
    return out.getvalue()


def custody(kind,raw,reader=False):
    filename='payload/native/build_tools_reader_v2.py'if reader else'payload/native/build_tools_projection_v2.py'
    name='hyprland_archive_custody'if reader else'_archive_custody'
    f=functions(filename,name+(','+'build_tools_metadata'if reader else',_metadata'),C=SimpleNamespace(need=need,pin=pin))
    recipe=CONTRACT['recipes'][kind];command=dict(step='archive-a-'+kind,argv=['/usr/bin/zstd','-dc',str(PREFIX/'build-inputs/a'/kind/recipe['archive'])],log='000-archive-a-'+kind+'.log',log_pin=pin(raw),expected=0)
    marker=re.compile(br'PRIVATE_KEY|password\s*[=:]',re.I)
    return getattr(f,name)(raw,command,CONTRACT,0,marker)if reader else getattr(f,name)(raw,command,CONTRACT,0)


def modeled_component():
    """Complete synthetic command/history DATA for isolated passive join controls."""
    scope='journey/'+OPERATION+'/';data={};commands=[];work=Path('/tmp/build-tools-test-MODELED');trust=work/'trust';config=str(work/'pacman.conf')
    base=(HERE/'fixtures/expected349.lock').read_bytes();fingerprint='A'*40
    report=dict(schema_version=1,operation=OPERATION,status='PASS_SESSION_LOCK_SETTINGS_NATIVE_ALPM_COMPONENT',pair=CONTRACT['pair'],source_map_sha256=PROFILE['map_sha256'],
        contract=pin((NATIVE/'build-tools-contract-v2.json').read_bytes()),stages=[],builds={},comparison={},inventory={},signatures={},payloads={},verification={},business={},commands=commands,
        first_failure=None,signature_policy=dict(SigLevel='Required',LocalFileSigLevel='Required'),
        process_layout=dict(schema=1,contract='bash-pid1-direct-python-child-v1',python_pid=2,python_ppid=1,status='OBSERVED_NON_PID1_PYTHON_DIRECT_CHILD'))
    def emit(step,argv,raw=b'',expected=0,cwd=None):
        leaf='%03d-%s.log'%(len(commands),step);data[scope+leaf]=raw
        commands.append(dict(step=step,argv=argv,cwd=str(cwd or work),expected=expected,success=True,log=leaf,log_pin=pin(raw),
            supervision=dict(exit=1 if expected=='nonzero'else 0,reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,error=None,timeout=False,signals=[])))
    def inventory(state,kinds=()):
        raw=b''.join(sorted(base.splitlines(keepends=True)+[(CONTRACT['recipes'][k]['name']+' '+CONTRACT['recipes'][k]['version']+'\n').encode()for k in kinds]))
        report['inventory'][state]=dict(**pin(raw),count=349+len(kinds));emit(state+'-inventory',['/usr/bin/pacman','-Q'],raw)
    inventory('baseline')
    reasons={'explicit':b'base\nhyprland\n','dependencies':b'python\nswaylock\n'}
    for key,flag in [('explicit','-Qqe'),('dependencies','-Qqd')]:emit('baseline-reasons-'+key,['/usr/bin/pacman',flag],reasons[key])
    report['install_reasons_before']={k:pin(v)for k,v in reasons.items()}
    fpr=(':'.join(['fpr']+['']*8+[fingerprint,''])+'\n').encode()
    emit('test-primary-fingerprint',['/usr/bin/gpg','--with-colons','--list-keys'],fpr)
    public='-----BEGIN PGP PUBLIC KEY BLOCK-----\nMODELED PUBLIC DATA\n-----END PGP PUBLIC KEY BLOCK-----\n'
    report['public_key']=dict(**pin(public.encode()),text=public);report['fingerprint']=fingerprint
    emit('export-only-test-public',['/usr/bin/gpg','--armor','--export',fingerprint],public.encode())
    cfg=('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+str(trust)+'\nHookDir = /builder-disabled-hooks\n').encode()
    emit('required-signature-config',['/usr/bin/cat',config],cfg);report['signature_config']=pin(cfg);report['stages'].append('sign')
    verifier=['/usr/bin/gpg','--batch','--no-options','--homedir',str(trust),'--no-auto-key-retrieve']
    archives={};decoded={}
    for label in ('a','b'):
        for kind in ('helper','settings'):
            key=label+'-'+kind;recipe=CONTRACT['recipes'][kind];slot=PREFIX/'build-current'
            f=functions('payload/native/build_tools_alpm_v2.py','build_argv')
            raw=('Starting check()\n'+''.join(f'Ran {n} tests in 0.01s\n\nOK\n'for n in recipe['test_blocks'])+'Finished making: '+recipe['name']+' '+recipe['version']+'\n').encode()
            emit('build-'+key,f.build_argv(slot,Path(CONTRACT['invocation']['source'])/CONTRACT['makepkg_config']['path'],CONTRACT),raw,cwd=slot)
            receipt=dict(filename=recipe['archive'],**pin(b'MODELED COMPRESSED ARCHIVE '+kind.encode()))
            report['builds'][key]=dict(label=label,kind=kind,version=recipe['version'],recipe_sha256=recipe['source_files']['PKGBUILD']['sha256'],
                build_directory=dict(logical=str(slot),identity=dict(device=1,inode=len(report['builds'])+1),initial_files=sorted(recipe['source_files'])),
                check_result=dict(status='PASS_EXACT_RECIPE_CHECK_STAGE',tests=sum(recipe['test_blocks']),blocks=recipe['test_blocks']),archive=receipt)
            path=str(PREFIX/'build-inputs'/label/kind/recipe['archive']);archives[key]=dict(path=path,pin={k:receipt[k]for k in ('bytes','sha256')})
            report['stages'].append('build-'+key)
            if key=='a-helper':
                emit('untrusted-signature-control',verifier+['--status-fd=1','--verify',path+'.sig',path],b'[GNUPG:] NO_PUBKEY\n','nonzero')
                emit('trust-key-membership',verifier+['--with-colons','--list-keys'],fpr)
            status=f'[GNUPG:] VALIDSIG {fingerprint} 2026-11-14 1794667200 0 4 0 22 8 00 {fingerprint}\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n'
            emit('verify-'+key,verifier+['--status-fd=1','--verify',path+'.sig',path],status.encode())
            signature=b'MODELED DETACHED SIGNATURE';report['signatures'][key]=dict(signer=fingerprint,status=status,verify_step='verify-'+key,signature=dict(**pin(signature),base64=base64.b64encode(signature).decode()))
            if kind=='helper':
                emit('bootstrap-'+label+'-install',['/usr/bin/pacman','--config',config,'--noconfirm','--noscriptlet','-U',path])
                inventory('bootstrap-'+label+'-installed',('helper',));report['stages'].append('bootstrap-'+label+'-install')
            else:
                emit('bootstrap-'+label+'-remove',['/usr/bin/pacman','--config',config,'--noconfirm','--noscriptlet','-R',CONTRACT['recipes']['helper']['name']])
                inventory('bootstrap-'+label+'-removed');report['stages'].append('bootstrap-'+label+'-remove')
    packages={}
    for kind in ('helper','settings'):
        recipe=CONTRACT['recipes'][kind];pair={}
        for label in ('a','b'):
            key=label+'-'+kind;raw=archive(kind);emit('archive-'+key,['/usr/bin/zstd','-dc',archives[key]['path']],raw)
            with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as stream:decoded[key]={m.name:stream.extractfile(m).read()for m in stream if m.isfile()}
            pair[label]=dict(archive=archives[key]['pin'],metadata={n:pin(decoded[key][n])for n in ('.PKGINFO','.BUILDINFO','.MTREE')},payload={n:pin(decoded[key][n])for n in recipe['payload_files']})
        packages[kind]=dict(status='PASS_EXACT_NATIVE_BUILD_PAIR',builds=pair,payload_files=len(recipe['payload_files']),buildinfo_count=len(recipe['buildinfo_installed']))
    report['comparison']=dict(status='PASS_EXACT_NATIVE_PAIR_OF_PACKAGES',source_map_sha256=PROFILE['map_sha256'],packages=packages)
    hashes={n:item['sha256']for recipe in CONTRACT['recipes'].values()for n,item in recipe['payload_files'].items()}
    def verify(phase,label):
        def meta(kind):
            result={}
            for line in decoded[label+'-'+kind]['.PKGINFO'].decode().splitlines():
                key,value=line.split(' = ',1);result.setdefault(key,[]).append(value)
            return {key:result[key]for key in ('builddate','packager','size')}
        value=dict(schema=1,record_type='offline-desktop-session-lock-prefix-verification',profile='hyprland011-session-lock010',host_arch='aarch64',
            packages={recipe['name']:dict(**archives[label+'-'+kind]['pin'],volatile_metadata=meta(kind))for kind,recipe in CONTRACT['recipes'].items()},
            checks=dict(exact_archives_metadata_payload='PASS',audited_Lua_binding_delta='PASS',exact_assembled_prefix='PASS'),
            status='desktop-session-lock-prefix-pass',payload_files=13,payload_sha256=hashes,profile_sha256=CONTRACT['verification']['profile_sha256'],payload_executed=False,read_only=True,
            **{key:'NOT RUN'for key in ('native_build','installed_database_ownership','dependency_resolution','session_runtime','hardware_validation')})
        argv=['/usr/bin/python3','-I','-B',str(PREFIX/'verification/desktop_session_lock.py'),'--profile',str(PREFIX/'verification/desktop-session-lock011.json'),'--profile-sha256',CONTRACT['verification']['profile_sha256'],
            '--settings-package',archives[label+'-settings']['path'],'--settings-sha256',archives[label+'-settings']['pin']['sha256'],'--session-lock-package',archives[label+'-helper']['path'],'--session-lock-sha256',archives[label+'-helper']['pin']['sha256'],'--prefix',str(PREFIX/('verified-prefix-'+phase))]
        emit('verify-prefix-'+phase,argv,encoded(value));report['verification'][phase]=value
    verify('build-a','a');verify('build-b','b');report['stages'].append('compare')
    emit('tampered-signature-control',verifier+['--status-fd=1','--verify',archives['a-helper']['path']+'.sig',str(work/'tampered.pkg.tar.zst')],b'[GNUPG:] BADSIG\n','nonzero')
    for label,phase,install,remove,removed in [('a','installed','install','remove','removed'),('b','reinstalled','reinstall','remove-again','removed-again')]:
        emit(install,['/usr/bin/pacman','--config',config,'--noconfirm','--noscriptlet','-U',archives[label+'-helper']['path'],archives[label+'-settings']['path']]);inventory(phase,('helper','settings'))
        report['payloads'][phase]=dict(count=13,verified=True,packages={kind:dict(name=r['name'],version=r['version'],files=r['payload_files'])for kind,r in CONTRACT['recipes'].items()})
        for kind,recipe in CONTRACT['recipes'].items():
            for path in recipe['payload_files']:emit(('reinstall-'if label=='b'else '')+'owner-'+recipe['name'],['/usr/bin/pacman','--config',config,'-Qoq','/'+path],recipe['name'].encode()+b'\n')
            dirs={str(p)for n in recipe['payload_files']for p in Path(n).parents if str(p)!='.'};raw=''.join('/'+n+'/\n'for n in sorted(dirs))+''.join('/'+n+'\n'for n in sorted(recipe['payload_files']))
            emit(('reinstall-'if label=='b'else '')+'owned-files-'+recipe['name'],['/usr/bin/pacman','--config',config,'-Qlq',recipe['name']],raw.encode())
        verify(phase,label);report['business'][phase]={}
        env=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(PREFIX/'business-home'),'XDG_RUNTIME_DIR='+str(PREFIX/'business-home')]
        for key,argv in {'helper-help':['/usr/bin/cachy-asahi-session-lock','--help'],'screenshot-help':['/usr/bin/cachy-asahi-screenshot','--help'],'config-verify':['/usr/bin/Hyprland','--verify-config','--config','/usr/share/cachy-asahi/hyprland/hyprland.lua']}.items():
            raw=b'config ok\n'if key=='config-verify'else b'usage: MODELED DATA ONLY\n';emit(phase+'-'+key,env+argv,raw);report['business'][phase][key]=dict(argv=env+argv,output=pin(raw))
        report['stages'].append(install);emit(remove,['/usr/bin/pacman','--config',config,'--noconfirm','--noscriptlet','-R',CONTRACT['recipes']['settings']['name'],CONTRACT['recipes']['helper']['name']]);inventory(removed);report['stages'].append(remove)
    for key,flag in [('explicit','-Qqe'),('dependencies','-Qqd')]:emit('restored-reasons-'+key,['/usr/bin/pacman',flag],reasons[key])
    report['install_reasons_after']=report['install_reasons_before'];report['exports_preserved']=report['payload_absent']=report['private_roots_absent']=True
    snapshot=dict(files=1,**pin(b'MODELED PROTECTED SNAPSHOT'));report['exports_before']=report['exports_after']=snapshot
    report['restore']={name:dict(before=snapshot,after=snapshot,unchanged=True)for name in ('alpm_db','alarm_home','root_home','global_trust','global_config','package_cache')}
    report['stages'].append('restore')
    for home in ('signing','trust'):
        emit('retire-'+home,['/usr/bin/gpgconf','--homedir',str(work/home),'--kill','all'])
        emit('no-autostart-'+home,['/usr/bin/gpg-connect-agent','--homedir',str(work/home),'--no-autostart','/bye'],b'gpg-connect-agent: no gpg-agent running in this session\n')
    report['cleanup']=dict(homes_retired=True,no_sockets=True,private_directory_absent=True,failures=[]);report['stages'].append('cleanup')
    report['native']=dict(architecture='aarch64',page_bytes=4096,execution='OWNED_IMAGE_BUILD_STAGE',physical_M2='NOT_RUN',release='NOT_ADMITTED')
    def refresh():data[scope+'result.json']=encoded(report);data[scope+'commands.json']=encoded(commands)
    refresh();view=SimpleNamespace(read=lambda name:data[name],load=lambda name:json.loads(data[name]))
    files={name:dict(kind='file',mode=0o600,**pin(raw))for name,raw in data.items()}
    guest=dict(build_tools_alpm=report,packages=pin(base),page_size=4096)
    return view,files,guest,report,data,refresh


def check_modeled(view,files,guest):
    def read(path):return (HERE/'fixtures/expected349.lock').read_bytes()if Path(path).name=='expected349.lock'else (NATIVE/Path(path).name).read_bytes()
    names='build_tools_contract,build_tools_positive_state,build_tools_process_layout,build_tools_commands,pair_builds,pair_check_result,hyprland_archive_custody,build_tools_metadata,strict_test_signature,build_tools_restoration,retained_build_tools_alpm'
    f=functions('payload/native/build_tools_reader_v2.py',names,read=read)
    return f.retained_build_tools_alpm(view,files,guest,PROFILE['map_sha256'])


class DataTests(unittest.TestCase):
    def test_01_profile_and_null_actuals(self):
        f=functions('prepare.py','need,pin,relative,decode,profile')
        raw=(HERE/'profile.json').read_bytes();self.assertEqual(f.profile(raw,pin(raw)['sha256']),PROFILE)
        bad=copy.deepcopy(PROFILE);bad['actual']['run']='1';raw=encoded(bad)
        with self.assertRaises(ValueError):f.profile(raw,pin(raw)['sha256'])
        with self.assertRaises(ValueError):f.profile((HERE/'profile.json').read_bytes(),'0'*64)

    def test_02_overlay_map_closure_and_complete_inverse(self):
        rows=copy.deepcopy(PROFILE['parent_files']);blobs=copy.deepcopy(PROFILE['parent_blobs'])
        self.assertEqual(len(rows),200);self.assertEqual(len(PROFILE['overlay']),13)
        for name,row in PROFILE['overlay'].items():
            path=HERE/'payload'/name;raw=path.read_bytes();self.assertEqual(dict(**pin(raw),mode=path.stat().st_mode&0o777),row)
            rows[name]=row;blobs[name]=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        mapping=json.loads((HERE/'parent-map.json').read_bytes());mapping['session_lock_settings_operation']=OPERATION;mapping['files']={n:r for n,r in rows.items()if n!='native/source-map.json'}
        raw=encoded(mapping);self.assertEqual(pin(raw)['sha256'],PROFILE['map_sha256'])
        rows['native/source-map.json']=dict(**pin(raw),mode=0o644);blobs['native/source-map.json']=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        nodes={}
        for name,row in rows.items():
            node=nodes
            for part in Path(name).parts[:-1]:node=node.setdefault(part,{})
            node[Path(name).name]=(row['mode'],bytes.fromhex(blobs[name]))
        def tree(node):
            raw=b''
            for name,value in sorted(node.items(),key=lambda p:p[0].encode()+(b'/'if isinstance(p[1],dict)else b'')):
                raw+=(b'40000'if isinstance(value,dict)else b'100755'if value[0]==0o755 else b'100644')+b' '+name.encode()+b'\0'+(tree(value)if isinstance(value,dict)else value[1])
            return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).digest()
        self.assertEqual(tree(nodes).hex(),PROFILE['prospective_tree'])
        changed={n for n in rows if rows[n]!=PROFILE['parent_files'][n]};self.assertEqual(changed,set(PROFILE['overlay'])|{'native/source-map.json'})
        self.assertEqual(len(changed),14)
        for name in changed:rows[name]=PROFILE['parent_files'][name]
        self.assertEqual(rows,PROFILE['parent_files'])

    def test_03_source_bundle_exact_original_recipes_and_verifier(self):
        files=members();self.assertEqual(len(files),CONTRACT['bundle']['members']);self.assertEqual(pin((NATIVE/'build-tools-sources-v2.tar').read_bytes()),{k:CONTRACT['bundle'][k]for k in ('bytes','sha256')})
        for kind,path in [('helper','packages/tools/cachy-asahi-session-lock'),('settings','packages/desktop/cachy-asahi-hyprland-settings011')]:
            for name,row in CONTRACT['recipes'][kind]['source_files'].items():
                raw=files[f'recipes/{kind}/{name}'];self.assertEqual(raw,(ROOT/path/name).read_bytes());self.assertEqual(pin(raw),{k:row[k]for k in ('bytes','sha256')})
        self.assertEqual(files['verification/desktop_session_lock.py'],(ROOT/'scripts/integration/desktop_session_lock.py').read_bytes())
        self.assertEqual(pin(files['verification/desktop-session-lock011.json'])['sha256'],CONTRACT['verification']['profile_sha256'])

    def test_04_base349_exact_dependencies_and_settings350(self):
        raw=(HERE/'fixtures/expected349.lock').read_bytes();versions=dict(line.split(' ',1)for line in raw.decode().splitlines())
        self.assertEqual(len(versions),349);self.assertEqual(pin(raw),{k:CONTRACT['expected349'][k]for k in ('bytes','sha256')})
        for name,version in CONTRACT['dependencies'].items():self.assertEqual(versions[name],version)
        self.assertEqual(versions['hyprland'],'0.56.2-4');self.assertEqual(versions['lua'],'5.5.1-1');self.assertEqual(versions['swaylock'],'1.8.6-1')
        self.assertEqual(len(CONTRACT['recipes']['helper']['buildinfo_installed']),349)
        self.assertEqual(CONTRACT['recipes']['settings']['buildinfo_installed'],sorted(CONTRACT['recipes']['helper']['buildinfo_installed']+['cachy-asahi-session-lock-0.1.0-1-any']))

    def test_05_exact_meaningful_unittest_classes_and_counts(self):
        files=members()
        for kind,tests in [('helper',[('test_session_lock.py','SessionLock',24),('test_package.py','Package',2)]),('settings',[('test_settings.py','Settings',5),('test_package.py','Package',2)])]:
            for filename,classname,count in tests:
                tree=ast.parse(files[f'recipes/{kind}/{filename}']);cls=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name==classname)
                self.assertEqual(len([n for n in cls.body if isinstance(n,ast.FunctionDef)and n.name.startswith('test_')]),count)
            self.assertEqual(CONTRACT['recipes'][kind]['expected_test_count'],sum(n for _,_,n in tests))

    def test_06_positive_and_wrong_count_skipped_or_failed_check_logs(self):
        actor=functions('payload/native/build_tools_alpm_v2.py','check_result');reader=functions('payload/native/build_tools_reader_v2.py','pair_check_result')
        for kind,recipe in CONTRACT['recipes'].items():
            text='Starting check()\n'+''.join(f'Ran {n} tests in 0.01s\n\nOK\n'for n in recipe['test_blocks'])+'Finished making: '+recipe['name']+' '+recipe['version']+'\n'
            self.assertEqual(actor.check_result(text.encode(),recipe),reader.pair_check_result(text.encode(),recipe))
            for changed in (text.replace('Ran ','Ran 0',1),text.replace('OK','OK (skipped=1)',1),text+'ERROR: failed\n',text.replace('Starting check()','Skipping check()')):
                with self.assertRaises(ValueError):actor.check_result(changed.encode(),recipe)
                with self.assertRaises(ValueError):reader.pair_check_result(changed.encode(),recipe)

    def test_07_argv_checks_dependencies_without_sync_or_mutation_escape(self):
        f=functions('payload/native/build_tools_alpm_v2.py','build_argv')
        argv=f.build_argv(PREFIX/'build-current',Path('/source/native/build-tools-makepkg-v2.conf'),CONTRACT)
        self.assertIn('--cleanbuild',argv);self.assertIn('--nosign',argv)
        for forbidden in ('--nodeps','--nocheck','--syncdeps','--asroot'):self.assertNotIn(forbidden,argv)

    def test_08_independent_projection_reader_archive_framing_for_both_packages(self):
        for kind in ('helper','settings'):
            raw=archive(kind);a=custody(kind,raw);b=custody(kind,raw,True);self.assertEqual(a,b)
            self.assertEqual(a['payload_files'],4 if kind=='helper'else 9)
            with self.assertRaises(ValueError):custody(kind,raw+b'private trailing',True)
            with self.assertRaises(ValueError):custody(kind,raw+b'private trailing')

    def test_09_archive_dependency_or_buildinfo_bootstrap_tamper_refused(self):
        for field in ('.PKGINFO','.BUILDINFO'):
            def mutate(data):data[field]=data[field].replace(b'cachy-asahi-session-lock',b'unreviewed-session-lock')
            raw=archive('settings',mutate)
            with self.assertRaises(ValueError):custody('settings',raw)
            with self.assertRaises(ValueError):custody('settings',raw,True)

    def test_10_duplicate_json_and_aliased_paths_refused(self):
        f=functions('prepare.py','need,relative,decode')
        with self.assertRaises(ValueError):f.decode(b'{"x":1,"x":2}')
        for value in ('../escape','/absolute','a//b','a\\b'):
            with self.assertRaises(ValueError):f.relative(value)

    def test_11_whole_parent_commit_and_construction_actor_fence(self):
        raw=(HERE/'parent.raw').read_bytes();self.assertEqual(pin(raw),PROFILE['parent_raw'])
        self.assertEqual(hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),PROFILE['parent'])
        source=(HERE/'prepare.py').read_text();self.assertIn('complete byte/mode inverse differs',source);self.assertIn('renameat2',source)
        self.assertNotIn('subprocess',source);self.assertIn('O_NOFOLLOW',source);self.assertIn('st_nlink == 1',source)

    def test_12_held_supervision_cleanup_and_pid1_predicates(self):
        old=ROOT/'scripts/ci/hyprland03-native-source-v1/payload/native'
        for name in ('strict_signature','retire_homes','primary_failure','preserve_command_failure','retain_first_failure','retain_exception'):
            def node(path):return next(n for n in ast.parse(path.read_bytes()).body if isinstance(n,ast.FunctionDef)and n.name==name)
            self.assertEqual(ast.dump(node(old/'build_tools_alpm_v2.py')),ast.dump(node(NATIVE/'build_tools_alpm_v2.py')))
        source=(NATIVE/'build_tools_alpm_v2.py').read_text();self.assertIn('if primary is not None:raise primary',source)
        self.assertIn('timeout=180,total=450,max_output=1024**2',source);self.assertIn('timeout=20,total=90,max_output=1024**2',source)
        self.assertIn('os.getpid()>1 and os.getppid()==1',source);self.assertIn('"$BASHPID" -eq 1',source)

    def test_13_quiet_image_build_and_safe_first_failure_route(self):
        owner=(NATIVE/'owner.py').read_text();reader=(NATIVE/'build_tools_reader_v2.py').read_text();lifecycle=(NATIVE/'image_lifecycle.py').read_text()
        self.assertIn("command = [*DOCKER, 'build', '--quiet', '--network=none'",owner)
        self.assertIn("DOCKER+['build','--quiet','--network=none'",lifecycle)
        self.assertIn("docker + ['build', '--quiet', '--network=none'",reader)
        self.assertIn('retain_pair(args.work,output,own,args.map_sha256)',owner)
        self.assertIn("'pair-failure.json'",reader)
        self.assertIn('validate_refusal(detail)',owner)

    def test_14_reader_authenticates_closed_source_and_self_before_ingress(self):
        source=(NATIVE/'build_tools_reader_v2.py').read_text();tree=ast.parse(source)
        validate=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='validate');body=ast.get_source_segment(source,validate)
        self.assertLess(body.index('build_tools_local_binding('),body.index('open_capsule('))
        self.assertIn("rows['native/build_tools_reader_v2.py']['sha256']",source)
        self.assertIn("manifest.get('session_lock_settings_operation')==OPERATION",source)
        self.assertIn("state.get('group_census') == 'EMPTY_TWICE'",source)
        self.assertIn("'VALIDATED_NATIVE_SESSION_LOCK_SETTINGS_ALPM_COMPONENT_EVIDENCE_ONLY'",source)

    def test_15_all_new_source_compiles_without_importing_roles(self):
        for path in [HERE/'prepare.py',*NATIVE.glob('*.py')]:compile(path.read_bytes(),str(path),'exec')

    def test_16_modeled_positive_pair_all_passive_native_joins(self):
        view,files,guest,report,data,refresh=modeled_component()
        value=check_modeled(view,files,guest)
        self.assertEqual(value['status'],'MATCHED_SESSION_LOCK_SETTINGS_ALPM_COMPONENT_DATA_ONLY')
        self.assertEqual(value['native'],'NOT_ADMITTED')
        self.assertLessEqual(len(report['commands']),160)

    def test_17_model_refuses_failed_retirement_and_incomplete_cleanup(self):
        for change in ('retirement','cleanup','first_failure','restoration'):
            with self.subTest(change=change):
                view,files,guest,report,data,refresh=modeled_component()
                if change=='retirement':report['commands'][0]['supervision']['group_census']='UNKNOWN'
                elif change=='cleanup':report['cleanup']['homes_retired']=False
                elif change=='first_failure':report['first_failure']=dict(phase='build-a-helper',type='Failure',message='MODELED',command_index=0)
                else:report['restore']['alpm_db']['unchanged']=False
                refresh()
                with self.assertRaises(ValueError):check_modeled(view,files,guest)

    def test_18_model_refuses_unsigned_bootstrap_and_real_lock_business_command(self):
        for step in ('bootstrap-a-install','installed-helper-help'):
            with self.subTest(step=step):
                view,files,guest,report,data,refresh=modeled_component()
                command=next(row for row in report['commands']if row['step']==step)
                command['argv']=['/usr/bin/pacman','--nodeps','-U','UNSIGNED']if step.startswith('bootstrap')else ['/usr/bin/cachy-asahi-session-lock','suspend']
                refresh()
                with self.assertRaises(ValueError):check_modeled(view,files,guest)

    def test_19_build_pair_rethrows_original_after_retiring_owned_slot(self):
        operations=[]
        class ModelPath:
            def __init__(self,name):self.value=str(name)
            def __truediv__(self,name):return ModelPath(self.value+'/'+str(name))
            def __str__(self):return self.value
            @property
            def name(self):return self.value.rsplit('/',1)[-1]
            def iterdir(self):return [self/name for name in CONTRACT['recipes']['helper']['source_files']]
            def stat(self):return SimpleNamespace(st_dev=1,st_ino=1)
            def rename(self,target):operations.append((str(self),str(target)))
            def is_dir(self):return True
            def is_symlink(self):return False
        fake_os=SimpleNamespace(path=SimpleNamespace(lexists=lambda _:False),chown=lambda *args:None)
        f=functions('payload/native/build_tools_alpm_v2.py','build_pair,build_argv',os=fake_os,PREFIX=ModelPath(str(PREFIX)),T=SimpleNamespace(KINDS=('helper','settings')))
        original=ValueError('MODELED ORIGINAL BUILD FAILURE')
        def run(*args,**kwargs):raise original
        def forbidden(*args):raise AssertionError('no signature/inventory actor after failed build')
        try:
            f.build_pair(run,ModelPath('/source'),ModelPath('/recipes'),CONTRACT,SimpleNamespace(pw_uid=1000,pw_gid=1000),dict(builds={},stages=[]),forbidden,[],forbidden,b'')
        except ValueError as actual:self.assertIs(actual,original)
        else:self.fail('build failure was swallowed')
        self.assertEqual(operations,[('/recipes/a/helper',str(PREFIX/'build-current')),(str(PREFIX/'build-current'),'/recipes/a/helper')])

    def test_20_safe_failure_preserves_identity_and_hashes_private_message(self):
        filename='payload/native/safe_diagnostic.py';source=(HERE/filename).read_text();tree=ast.parse(source)
        values={}
        for node in tree.body:
            if isinstance(node,ast.Assign)and any(isinstance(target,ast.Name)and target.id.startswith('PAIR_')for target in node.targets):
                exec(compile(ast.Module(body=[node],type_ignores=[]),'safe-DATA-labels','exec'),values)
        def safe_text(raw):need(not re.search(br'password\s*[=:]|PRIVATE_KEY',raw,re.I),'privacy marker remains refused')
        c=SimpleNamespace(need=need,pin=pin,_json=encoded,_load=json.loads)
        f=functions(filename,'check_binding,_pin,_hashed_label,pair_context,check_pair',C=c,safe_text=safe_text,**{k:v for k,v in values.items()if k.startswith('PAIR_')})
        own=dict(source='1'*40,ref='refs/heads/codex/MODELED',run='1',attempt=1)
        own['token']=hashlib.sha256((own['source']+':'+own['ref']+':'+own['run']).encode()).hexdigest()[:24]
        failure=dict(phase='build-a-helper',type='Failure',message='password=DO_NOT_EXPORT',command_index=0)
        report=dict(schema_version=1,operation=OPERATION,source_map_sha256=PROFILE['map_sha256'],status='FAIL',first_failure=failure,
            commands=[dict(step='build-a-helper',success=False,log_pin=pin(b'MODELED RAW PRIVATE OUTPUT'),supervision=dict(exit=1,ownership='REAPED',group_census='EMPTY_TWICE',reaped=True,output_complete=True,timeout=False))],
            stages=['sign'],cleanup=dict(homes_retired=True,no_sockets=True,private_directory_absent=True))
        value=f.pair_context(encoded(report),own,PROFILE['map_sha256'])
        self.assertEqual(value['first_failure']['identity'],pin(encoded(failure)))
        self.assertEqual(value['first_failure']['message'],pin(failure['message'].encode()))
        self.assertNotIn(b'DO_NOT_EXPORT',encoded(value));self.assertEqual(value['native'],'NOT_ADMITTED')
        changed=copy.deepcopy(value);changed['first_failure']['phase']['label']='password=DO_NOT_EXPORT'
        with self.assertRaises(ValueError):f.check_pair(changed,own,PROFILE['map_sha256'])

    def test_21_expired_unknown_or_untrusted_signatures_never_pass(self):
        f=functions('payload/native/build_tools_alpm_v2.py','strict_signature')
        fingerprint='A'*40;status=f'[GNUPG:] VALIDSIG {fingerprint} 2026-11-14 1794667200 0 4 0 22 8 00 {fingerprint}\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n'
        f.strict_signature(status,fingerprint)
        for marker in ('EXPKEYSIG','BADSIG','NO_PUBKEY','TRUST_UNDEFINED'):
            with self.assertRaises(ValueError):f.strict_signature(status+'[GNUPG:] '+marker+'\n',fingerprint)

    def test_22_local_source_guard_matches_original_whole_tree_predicates(self):
        def function(path):
            source=path.read_text().replace('session_lock_settings_operation','hyprland03_operation')
            node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)and n.name=='build_tools_local_binding')
            return ast.dump(node)
        self.assertEqual(function(NATIVE/'build_tools_reader_v2.py'),function(ROOT/'scripts/ci/hyprland03-native-source-v1/payload/native/build_tools_reader_v2.py'))

    def test_23_supervisor_core_and_makepkg_configuration_remain_genuine_parent_bytes(self):
        workflow=CONTRACT['original_workflow'];self.assertEqual({k:workflow[k]for k in ('bytes','sha256')},{k:PROFILE['parent_files'][workflow['path']][k]for k in ('bytes','sha256')})
        self.assertEqual(PROFILE['parent_files']['scripts/virtual/owned_process.py']['sha256'],'83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f')
        config=CONTRACT['makepkg_config'];self.assertEqual({k:config[k]for k in ('bytes','sha256')},{k:PROFILE['parent_files'][config['path']][k]for k in ('bytes','sha256')})
        self.assertNotIn(workflow['path'],PROFILE['overlay']);self.assertNotIn('scripts/virtual/owned_process.py',PROFILE['overlay'])

    def test_24_model_rejects_missing_payload_owner_or_mismatched_profile_result(self):
        for change in ('owner','profile'):
            with self.subTest(change=change):
                view,files,guest,report,data,refresh=modeled_component()
                if change=='owner':
                    command=next(row for row in report['commands']if row['step']=='owner-cachy-asahi-session-lock');command['argv'][-1]='/unreviewed'
                else:
                    row=next(row for row in report['commands']if row['step']=='verify-prefix-installed')
                    value=json.loads(data['journey/'+OPERATION+'/'+row['log']]);value['payload_sha256'].pop('usr/bin/cachy-asahi-session-lock')
                    raw=encoded(value);data['journey/'+OPERATION+'/'+row['log']]=raw;row['log_pin']=pin(raw)
                    files['journey/'+OPERATION+'/'+row['log']].update(pin(raw));report['verification']['installed']=value
                refresh()
                with self.assertRaises(ValueError):check_modeled(view,files,guest)


if __name__=='__main__':unittest.main()

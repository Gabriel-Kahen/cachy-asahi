#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Modeled DATA/function controls; no emitted Source, native actor or actual Reader."""
import ast
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import unittest
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
NATIVE = HERE/'payload/native'
PROFILE = json.loads((HERE/'profile.json').read_bytes())
CONTRACT = json.loads((NATIVE/'build-tools-contract-v2.json').read_bytes())


def fence(event, args):
    if event.startswith(('subprocess.', 'os.exec', 'os.spawn', 'os.fork', 'socket.', 'ctypes.')):
        raise AssertionError('actor denied by DATA fence: '+event)
sys.addaudithook(fence)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def need(value, message):
    if not value: raise ValueError(message)


def function(name, filename, **extra):
    """Compile reviewed function definitions, without importing a producer/Reader."""
    tree = ast.parse((NATIVE/filename).read_bytes())
    names = name.split(',')
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
    need(len(nodes) == len(names), 'exact requested DATA functions')
    scope = dict(base64=base64, hashlib=hashlib, io=io, json=json, os=os, Path=Path,
                 re=re, stat=stat, tarfile=tarfile, need=need, pin=pin, data_pin=pin,
                 VERSION='0.1.0-3', NAME='cachy-asahi-hyprland-settings', OPERATION='hyprland03-alpm-v1',
                 PRODUCERS=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)
                                               and any(isinstance(t,ast.Name) and t.id=='PRODUCERS' for t in n.targets)))
                 if any(isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PRODUCERS' for t in n.targets) for n in tree.body) else {})
    scope.update(extra)
    exec(compile(ast.Module(body=nodes,type_ignores=[]), 'isolated-DATA-functions', 'exec'),scope)
    return SimpleNamespace(**{name:scope[name] for name in names})


def factory():
    tree=ast.parse((HERE/'prepare.py').read_bytes())
    names={'need','pin','oid','relative','decode','profile','descriptors','tree','compose','encoded'}
    scope=dict(hashlib=hashlib,json=json,re=re,Path=Path,PurePosixPath=__import__('pathlib').PurePosixPath,
               MAX_FILE=64*1024**2,MAX_TOTAL=128*1024**2,MAX_FILES=256,MAP='native/source-map.json',
               ALLOWED=frozenset(PROFILE['overlay']),PARENT=PROFILE['parent'],PARENT_TREE=PROFILE['parent_tree'],OPERATION=PROFILE['operation'])
    exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names],type_ignores=[]),
                 'isolated-constructor-DATA-functions','exec'),scope)
    return SimpleNamespace(**scope)


def git_tree(rows):
    nodes={}
    for path,(mode,digest) in rows.items():
        node=nodes
        for part in Path(path).parts[:-1]: node=node.setdefault(part,{})
        node[Path(path).name]=(mode,bytes.fromhex(digest))
    def emit(node):
        raw=b''
        for n,v in sorted(node.items(),key=lambda p:p[0].encode()+(b'/' if isinstance(p[1],dict) else b'')):
            raw+=(b'40000' if isinstance(v,dict) else b'100755' if v[0]==0o755 else b'100644')+b' '+n.encode()+b'\0'+(emit(v) if isinstance(v,dict)else v[1])
        return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).digest()
    return emit(nodes).hex()


def source_members():
    with tarfile.open(NATIVE/'build-tools-sources-v2.tar') as archive:
        return {m.name:archive.extractfile(m).read() for m in archive}


def modeled_archive():
    """Explicit MODELED package tar DATA, never a claimed built archive."""
    members=source_members();pkg={k:[v] for k,v in [('pkgname','cachy-asahi-hyprland-settings'),('pkgbase','cachy-asahi-hyprland-settings'),('pkgver','0.1.0-3'),('arch','any'),('license','MIT')]}
    pkg.update(depend=CONTRACT['recipe']['depends'],makedepend=CONTRACT['recipe']['makedepends'],optdepend=CONTRACT['recipe']['optdepends'])
    build={k:[v] for k,v in [('format','2'),('pkgname','cachy-asahi-hyprland-settings'),('pkgbase','cachy-asahi-hyprland-settings'),('pkgver','0.1.0-3'),('pkgarch','any'),('pkgbuild_sha256sum',CONTRACT['recipe']['source_files']['PKGBUILD']['sha256'])]}
    build.update(installed=CONTRACT['buildinfo_installed'],buildenv=['check'])
    text=lambda v:''.join(k+' = '+x+'\n' for k,values in v.items() for x in values).encode()
    data={'.PKGINFO':text(pkg),'.BUILDINFO':text(build),'.MTREE':b'MODELED mtree DATA'}
    expected=CONTRACT['recipe']['payload_files']
    for n in expected:data[n]=members['recipe/'+Path(n).name]
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        dirs={str(p)for n in expected for p in Path(n).parents if str(p)!='.'}
        for n in sorted(dirs):
            m=tarfile.TarInfo(n+'/');m.type=tarfile.DIRTYPE;m.mode=0o755;archive.addfile(m)
        for n,raw in data.items():
            m=tarfile.TarInfo(n);m.mode=expected[n]['mode']if n in expected else 0o644;m.size=len(raw);archive.addfile(m,io.BytesIO(raw))
    return out.getvalue()


class DataTests(unittest.TestCase):
    def test_01_whole_profile_external_pin_and_nulls(self):
        f=factory();raw=(HERE/'profile.json').read_bytes();self.assertEqual(f.profile(raw,pin(raw)['sha256']),PROFILE)
        with self.assertRaises(ValueError): f.profile(raw,'0'*64)
        bad=copy.deepcopy(PROFILE);bad['actual']['run']='123';raw=json.dumps(bad).encode()
        with self.assertRaises(ValueError):f.profile(raw,pin(raw)['sha256'])

    def test_02_exact_parent_commit_and_200_blob_tree(self):
        raw=(HERE/'parent.raw').read_bytes();self.assertEqual(pin(raw),PROFILE['parent_raw'])
        self.assertEqual(pin((HERE/'parent-map.json').read_bytes()),{k:PROFILE['parent_files']['native/source-map.json'][k]for k in ('bytes','sha256')})
        self.assertEqual(hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),PROFILE['parent'])
        self.assertEqual(git_tree({n:(r['mode'],PROFILE['parent_blobs'][n])for n,r in PROFILE['parent_files'].items()}),PROFILE['parent_tree'])

    def test_03_complete_virtual_tree_map_and_inverse(self):
        rows=copy.deepcopy(PROFILE['parent_files']);blobs=copy.deepcopy(PROFILE['parent_blobs'])
        self.assertEqual(len(rows),200);self.assertEqual(len(PROFILE['overlay']),11)
        for n,r in PROFILE['overlay'].items():
            p=HERE/'payload'/n;raw=p.read_bytes();self.assertEqual(dict(**pin(raw),mode=p.stat().st_mode&0o777),r)
            rows[n]=r;blobs[n]=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        # The original map body is not imported; bind its held fields as DATA.
        mapping=json.loads((HERE/'parent-map.json').read_bytes());mapping['hyprland03_operation']=PROFILE['operation'];mapping['files']={n:r for n,r in rows.items()if n!='native/source-map.json'}
        raw=(json.dumps(mapping,sort_keys=True,indent=2)+'\n').encode();self.assertEqual(pin(raw)['sha256'],PROFILE['map_sha256']);rows['native/source-map.json']=dict(**pin(raw),mode=0o644);blobs['native/source-map.json']=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        self.assertEqual(git_tree({n:(r['mode'],blobs[n])for n,r in rows.items()}),PROFILE['prospective_tree'])
        changed={n for n in rows if rows[n]!=PROFILE['parent_files'][n]};self.assertEqual(changed,set(PROFILE['overlay'])|{'native/source-map.json'})
        for n in changed:rows[n]=PROFILE['parent_files'][n]
        self.assertEqual(rows,PROFILE['parent_files'])

    def test_04_duplicate_json_unsafe_names_and_bool_descriptor_refused(self):
        f=factory()
        with self.assertRaises(ValueError):f.decode(b'{"x":1,"x":2}')
        for n in ('../escape','/absolute','a//b','a\\b'):
            with self.subTest(n=n),self.assertRaises(ValueError):f.relative(n)
        bad=copy.deepcopy(PROFILE);bad['overlay'][next(iter(bad['overlay']))]['bytes']=True;raw=json.dumps(bad).encode()
        with self.assertRaises(ValueError):f.profile(raw,pin(raw)['sha256'])

    def test_05_constructor_is_data_only_and_atomic_noreplace(self):
        s=(HERE/'prepare.py').read_text();tree=ast.parse(s)
        imports={n.names[0].name for n in tree.body if isinstance(n,ast.Import)}
        self.assertFalse(imports&{'subprocess','socket','requests'});self.assertIn('renameat2',s);self.assertIn('O_NOFOLLOW',s);self.assertIn('st_nlink == 1',s)
        self.assertIn('complete byte/mode inverse differs',s);self.assertIn('complete physical genuine Source97',s)

    def test_06_bundle_matches_current_recipe_sources_and_sha256sums(self):
        members=source_members();recipe=ROOT/'packages/desktop/cachy-asahi-hyprland-settings'
        self.assertEqual(len(members),9)
        for n,r in CONTRACT['recipe']['source_files'].items():
            self.assertEqual(members['recipe/'+n],(recipe/n).read_bytes());self.assertEqual(pin(members['recipe/'+n]),{k:r[k]for k in ('bytes','sha256')})
        self.assertEqual(pin((NATIVE/'build-tools-sources-v2.tar').read_bytes()),{k:CONTRACT['bundle'][k]for k in ('bytes','sha256')})
        hashes=re.findall("'([0-9a-f]{64})'",members['recipe/PKGBUILD'].decode());self.assertEqual(hashes,[CONTRACT['recipe']['source_files'][n]['sha256']for n in ['hyprland.lua','waybar.json','waybar.css','mako.conf','README.md','NOTICE','LICENSE','cachy-asahi-screenshot']])

    def test_07_real_frozen_dependency_closure_without_waivers(self):
        raw=(HERE/'fixtures/expected349.lock').read_bytes();versions=dict(x.split(' ',1)for x in raw.decode().splitlines())
        self.assertEqual(len(versions),349);self.assertEqual(pin(raw),{k:CONTRACT['expected349'][k]for k in ('bytes','sha256')})
        self.assertEqual(versions['hyprland'],'0.56.2-4');self.assertEqual({n:versions[n]for n in CONTRACT['dependencies']},CONTRACT['dependencies'])
        self.assertEqual(CONTRACT['dependency_closure']['missing'],[])
        for name in ('build_tools_alpm_v2.py','build_tools_reader_v2.py'):
            s=(NATIVE/name).read_text();self.assertNotIn("'--nodeps'",s);self.assertNotIn("'--nocheck'",s)

    def test_08_exact_payload_and_optional_capture_boundary(self):
        p=CONTRACT['recipe']['payload_files'];self.assertEqual(len(p),8)
        self.assertEqual([n for n,r in p.items()if r['mode']==0o755],['usr/bin/cachy-asahi-screenshot'])
        self.assertEqual(CONTRACT['recipe']['depends'][:2],['hyprland>=0.56.2','hyprland<0.57.0'])
        self.assertIn('grim: optional explicit screenshot-to-file capture',CONTRACT['recipe']['optdepends'])
        s=(NATIVE/'build_tools_alpm_v2.py').read_text();self.assertNotIn('T.business(',s);self.assertIn('business={}',s)

    def test_09_check_stage_positive_and_refusals(self):
        a=function('check_result','build_tools_alpm_v2.py');b=function('build_tools_check_result','build_tools_reader_v2.py')
        good=b'==> Starting check()...\n==> Finished making: cachy-asahi-hyprland-settings 0.1.0-3 (MODELED)\n'
        self.assertEqual(a.check_result(good),b.build_tools_check_result(good));self.assertEqual(a.check_result(good)['tests'],3)
        for bad in (good.replace(b'check()',b'package()'),good+good,good.replace(b'0.1.0-3',b'0.1.0-2'),good+b'ERROR: broken\n',good[:-40]):
            with self.subTest(bad=bad),self.assertRaises(ValueError):a.check_result(bad)

    def test_10_pid1_launcher_and_exact_suffix_refusal(self):
        d=function('dockerfile','build_tools_alpm_v2.py');base='FROM MODEL\nUSER alarm\nWORKDIR /tmp\n';out=d.dockerfile(base,'1'*64)
        argv=json.loads(next(x[4:]for x in out.splitlines()if x.startswith('RUN ')))
        self.assertEqual(argv[:5],['/usr/bin/bash','--noprofile','--norc','-p','-c']);self.assertIn('"$BASHPID" -eq 1',argv[5]);self.assertIn('wait "$build_tools_owner"',argv[5]);self.assertIn('exit "$build_tools_status"',argv[5])
        for b,h in ((base+'extra','1'*64),(base,'wrong')):
            with self.assertRaises(ValueError):d.dockerfile(b,h)
        s=(NATIVE/'build_tools_alpm_v2.py').read_text();self.assertLess(s.index('os.getpid()>1 and os.getppid()==1'),s.index('verify_source(source,map_hash)'))

    def test_11_reader_process_layout_types(self):
        f=function('build_tools_process_layout','build_tools_reader_v2.py');layout=dict(schema=1,contract='bash-pid1-direct-python-child-v1',python_pid=2,python_ppid=1,status='OBSERVED_NON_PID1_PYTHON_DIRECT_CHILD')
        f.build_tools_process_layout(dict(process_layout=layout))
        for k,v in [('python_pid',True),('python_pid',1),('python_ppid',2),('schema',True)]:
            bad=dict(layout);bad[k]=v
            with self.subTest(k=k,v=v),self.assertRaises(ValueError):f.build_tools_process_layout(dict(process_layout=bad))

    def test_12_all_eight_archive_payload_and_metadata_data(self):
        t=function('_metadata,_archive_data','build_tools_tools_v2.py');result=t._archive_data(modeled_archive(),CONTRACT)
        self.assertEqual(len(result['payload']),8);self.assertEqual(set(result['metadata']),{'.PKGINFO','.BUILDINFO','.MTREE'})
        raw=modeled_archive();bad=raw.replace(b'hyprland>=0.56.2',b'hyprland>=0.55.2')
        with self.assertRaises((ValueError,tarfile.TarError)):t._archive_data(bad,CONTRACT)

    def test_13_projector_reader_independent_archive_custody(self):
        raw=modeled_archive();command=dict(step='archive-a',log='000-archive-a.log',expected=0,argv=['/usr/bin/zstd','-dc','/opt/native-hyprland03-alpm-v1/build-inputs/a/'+CONTRACT['recipe']['archive']],log_pin=pin(raw))
        p=function('_metadata,_archive_custody','build_tools_projection_v2.py',C=SimpleNamespace(need=need,pin=pin),PRIVATE_MARKER=re.compile(b'PRIVATE KEY'))
        # The reader archive function intentionally has its own metadata parser.
        r=function('build_tools_metadata,hyprland_archive_custody','build_tools_reader_v2.py')
        self.assertEqual(p._archive_custody(raw,command,CONTRACT,0),r.hyprland_archive_custody(raw,command,CONTRACT,0,re.compile(b'PRIVATE KEY')))
        bad=dict(command,argv=command['argv'][:-1]+['/tmp/unowned'])
        with self.assertRaises(ValueError):p._archive_custody(raw,bad,CONTRACT,0)
        with self.assertRaises(ValueError):p._archive_custody(raw[:-512]+b'x'*512,dict(command,log_pin=pin(raw[:-512]+b'x'*512)),CONTRACT,0)

    def test_14_passive_command_retirement_and_raw_log_join(self):
        f=function('build_tools_commands','build_tools_reader_v2.py');raw=b'MODELED output';prefix='journey/hyprland03-alpm-v1/';leaf='000-model.log'
        row=dict(step='model',log=leaf,log_pin=pin(raw),success=True,expected=0,argv=['/usr/bin/model'],supervision=dict(exit=0,reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,error=None,timeout=False,signals=[]))
        view=SimpleNamespace(load=lambda n:[row],read=lambda n:raw);files={prefix+leaf:dict(kind='file',**pin(raw))};f.build_tools_commands(view,files,prefix,[row])
        for key,val in [('group_census','UNKNOWN'),('reaped',False),('output_complete',False),('signals',['TERM'])]:
            bad=copy.deepcopy(row);bad['supervision'][key]=val;view.load=lambda n:[bad]
            with self.subTest(key=key),self.assertRaises(ValueError):f.build_tools_commands(view,files,prefix,[bad])

    def test_15_reinstall_second_archive_ownership_and_final_absence(self):
        f=function('hyprland_reinstall','build_tools_reader_v2.py');recipe=CONTRACT['recipe'];config='/tmp/build-tools-test-MODELED/pacman.conf';archives=dict(b='/fixed/b.pkg.tar.zst')
        commands=[dict(step='unused')for _ in range(25)];commands[5]=dict(step='reinstall',argv=['/usr/bin/pacman','--config',config,'--noconfirm','--noscriptlet','-U',archives['b']]);commands[20]=dict(step='remove-again',argv=['/usr/bin/pacman','--config',config,'--noconfirm','--noscriptlet','-R','cachy-asahi-hyprland-settings'])
        for i,n in enumerate(recipe['payload_files'],7):commands[i]=dict(step='reinstall-owner-cachy-asahi-hyprland-settings',argv=['/usr/bin/pacman','--config',config,'-Qoq','/'+n],log=str(i))
        selected=lambda n:next((i,c)for i,c in enumerate(commands)if c['step']==n)
        report=dict(commands=commands,final_payload_absent=True,payloads=dict(installed='MODELED payload',reinstalled='MODELED payload'))
        args=(SimpleNamespace(read=lambda n:b'cachy-asahi-hyprland-settings\n'),'prefix/',report,selected,recipe,archives,config,dict(removed=4,reinstalled=6,**{'removed-again':21}),[1,3])
        f.hyprland_reinstall(*args)
        report['final_payload_absent']=False
        with self.assertRaises(ValueError):f.hyprland_reinstall(*args)
        report['final_payload_absent']=True;commands[7]['argv'][-1]='/tmp/unowned'
        with self.assertRaises(ValueError):f.hyprland_reinstall(*args)

    def test_16_first_failure_and_carrier_exit_preserved(self):
        f=function('carrier_exit','build_tools_alpm_v2.py',PASS='PASS_HYPRLAND03_NATIVE_ALPM_COMPONENT')
        self.assertEqual(f.carrier_exit(dict(status='FAIL'),False),1);self.assertEqual(f.carrier_exit(dict(status='FAIL'),True),0)
        self.assertEqual(f.carrier_exit(dict(status='PASS_HYPRLAND03_NATIVE_ALPM_COMPONENT',first_failure={'phase':'failed'}),True),1)
        self.assertEqual(f.carrier_exit(dict(status='FAIL',retention_failures=['lost']),True),1)
        s=(NATIVE/'build_tools_alpm_v2.py').read_text();self.assertIn('if primary is not None:raise primary',s)

    def test_17_root_lane_and_unchanged_resource_caps(self):
        a=HERE/'payload/.github/workflows/native-arm-build.yml';b=HERE/'payload/.github/workflows/native-arm-developer-workflows.yml';self.assertEqual(a.read_bytes(),b.read_bytes())
        s=a.read_text();self.assertIn('group: native-arm-build',s);self.assertIn('cancel-in-progress: false',s);self.assertIn('queue: max',s);self.assertIn('ubuntu-24.04-arm',s)
        owner=(NATIVE/'owner.py').read_text()
        for text in ("'--network=none'","'--read-only'","'--cap-drop=ALL'","'--security-opt=no-new-privileges'","'--pids-limit=256'","'--memory=4g'","'--cpus=2'","size=2g"):
            self.assertIn(text,owner)
        self.assertIn("daemon_policy='UNKNOWN'",owner)

    def test_18_matching_source_guard_precedes_capsule_ingress(self):
        tree=ast.parse((NATIVE/'build_tools_reader_v2.py').read_bytes());v=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='validate');s=ast.unparse(v)
        self.assertLess(s.index('build_tools_local_binding('),s.index('open_capsule('))
        local=ast.unparse(next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='build_tools_local_binding'))
        self.assertIn('os.O_NOFOLLOW',local);self.assertIn('hyprland03_operation',local);self.assertIn('native/build_tools_reader_v2.py',local)

    def test_19_exact_signed_lifecycle_and_cleanup_scope(self):
        s=(NATIVE/'build_tools_alpm_v2.py').read_text();self.assertIn('SigLevel = Required',s);self.assertIn('LocalFileSigLevel = Required',s)
        for step in ('untrusted-signature-control','tampered-signature-control','install','remove','reinstall','remove-again'):
            self.assertIn("'"+step+"'",s)
        self.assertNotIn('--assume-installed',s);self.assertNotIn('--overwrite',s);self.assertIn("timeout=20,total=90",s);self.assertIn("timeout=180,total=450",s)

    def test_20_all_emitted_python_parses_and_recipe_is_held(self):
        for p in NATIVE.glob('*.py'):
            with self.subTest(path=p.name):ast.parse(p.read_bytes())
        self.assertEqual(PROFILE['main_base'],'dd12e3cc59a8669f9c5e0bcc02d04171339870a3')
        self.assertEqual(CONTRACT['recipe']['source_files']['LICENSE']['sha256'],'51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7')

    def test_21_modeled_complete_pair_passive_joins_and_drift_refusals(self):
        parser=function('build_tools_metadata,build_tools_check_result,build_tools_check_output,build_tools_build_pair','build_tools_reader_v2.py')
        tools=function('_metadata,_archive_data','build_tools_tools_v2.py')
        raw=modeled_archive();decoded=tools._archive_data(raw,CONTRACT);recipe=CONTRACT['recipe']
        fixed=Path(CONTRACT['invocation']['source']).parent;slot=fixed/'build-current'
        check=b'==> Starting check()...\n==> Finished making: cachy-asahi-hyprland-settings 0.1.0-3 (MODELED)\n'
        archive=pin(b'MODELED compressed archive identifier')
        detail=dict(archive=archive,pkginfo=pin(decoded['metadata']['.PKGINFO']),buildinfo=pin(decoded['metadata']['.BUILDINFO']),mtree=pin(decoded['metadata']['.MTREE']),payload=decoded['payload'])
        comparison=dict(status='PASS_EXACT_NATIVE_BUILD_PAIR',equality={k:True for k in ('archive','payload','pkginfo','buildinfo','mtree')},source_map_sha256='1'*64,payload_files=8,base_inventory_count=349,pkgbuild_sha256=recipe['source_files']['PKGBUILD']['sha256'],builds=dict(a=detail,b=detail),archive=archive,pkginfo_text=decoded['metadata']['.PKGINFO'].decode(),buildinfo_text=decoded['metadata']['.BUILDINFO'].decode(),mtree_base64=base64.b64encode(decoded['metadata']['.MTREE']).decode())
        report=dict(builds={},comparison=comparison);commands=[];logs={}
        for i,label in enumerate(('a','b')):
            report['builds'][label]=dict(version='0.1.0-3',recipe_sha256=recipe['source_files']['PKGBUILD']['sha256'],check_invoked=True,check_tests=3,check_policy='POSITIVE_CHECK_NO_NOCHECK',build_directory=dict(logical=str(slot),retained=str(fixed/'build-inputs'/label),initial_files=sorted(recipe['source_files']),identity=dict(device=1,inode=i+2)),archive=dict(filename=recipe['archive'],**archive),build_step='build-'+label,check_result=pin((json.dumps(parser.build_tools_check_result(check),sort_keys=True,indent=2)+'\n').encode()))
            argv=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(slot),'PKGDEST='+str(slot),'SRCDEST='+str(slot),'BUILDDIR='+str(slot),'SOURCE_DATE_EPOCH=1793145600','PACKAGER=cachy-asahi native TEST builder','/usr/bin/makepkg','--cleanbuild','--nosign','--noconfirm','--config',str(Path(CONTRACT['invocation']['source'])/CONTRACT['makepkg_config']['path'])]
            commands.append(dict(step='build-'+label,argv=argv,cwd=str(slot),expected=0,log='build-'+label));logs['build-'+label]=check
        for label in ('a','b'):
            commands.append(dict(step='archive-'+label,argv=['/usr/bin/zstd','-dc',str(fixed/'build-inputs'/label/recipe['archive'])],expected=0,log='archive-'+label));logs['archive-'+label]=raw
        selected=lambda name:next((i,c)for i,c in enumerate(commands)if c['step']==name)
        view=SimpleNamespace(read=lambda name:logs[name])
        self.assertEqual(parser.build_tools_build_pair(view,'',report,CONTRACT,selected,'1'*64)[0],[0,1])
        commands[0]['argv'].insert(-1,'--nodeps')
        with self.assertRaises(ValueError):parser.build_tools_build_pair(view,'',report,CONTRACT,selected,'1'*64)
        commands[0]['argv'].remove('--nodeps');report['builds']['b']['build_directory']['identity']['inode']=2
        with self.assertRaises(ValueError):parser.build_tools_build_pair(view,'',report,CONTRACT,selected,'1'*64)

    def test_22_actor_fence_and_finite_operation(self):
        with self.assertRaises(AssertionError):sys.audit('subprocess.Popen','MODELED_DATA_EVENT_ONLY')
        source=(NATIVE/'owner.py').read_text()
        self.assertIn("operation == 'hyprland03-alpm-v1'",source)
        self.assertIn("choices=('hyprland03-alpm-v1',)",source)
        value=json.loads((NATIVE/'invocation.json').read_bytes())
        self.assertEqual(value['retention']['reader'][3],'native/build_tools_reader_v2.py')

    def test_23_source97_strict_local_binding_held_with_only_operation_guard(self):
        baseline=ast.parse((HERE/'fixtures/source97-local-binding.py.txt').read_bytes()).body[0]
        tree=ast.parse((NATIVE/'build_tools_reader_v2.py').read_bytes())
        current=copy.deepcopy(next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='build_tools_local_binding'))
        added=current.body.pop(-2)
        self.assertEqual(ast.dump(added,include_attributes=False),ast.dump(ast.parse("need(manifest.get('hyprland03_operation')==OPERATION,'exact Hyprland03 operation in Root-bound local Source map')").body[0],include_attributes=False))
        self.assertEqual(ast.dump(current,include_attributes=False),ast.dump(baseline,include_attributes=False))
        source=ast.unparse(current)
        for predicate in ('os.O_NOFOLLOW','os.O_NONBLOCK','os.fstat(fd)','path.lstat()',
                          'before.st_nlink == 1','before.st_size <= cap','nodes <= 1024',
                          'len(path.relative_to(root).parts) <= 16','len(rows) == 199',
                          'actual_dirs == expected_dirs','total <= 128 * 1024 ** 2',
                          "rows['native/build_tools_reader_v2.py']",'PRODUCERS.items()'):
            self.assertIn(predicate,source)


if __name__=='__main__':unittest.main(verbosity=2)

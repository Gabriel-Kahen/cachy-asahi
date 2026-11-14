#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert source/DATA controls. No native actor, Source publication or Reader run."""
import ast
import base64
import copy
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest

HERE=Path(__file__).resolve().parent
NATIVE=HERE/'payload/native'
PROFILE=json.loads((HERE/'profile.json').read_bytes())
CONTRACT=json.loads((NATIVE/'build-tools-contract-v2.json').read_bytes())


def fence(event,args):
    if event.startswith(('subprocess.','os.exec','os.spawn','os.fork','socket.','ctypes.')):
        raise AssertionError('actor denied by DATA fence: '+event)
sys.addaudithook(fence)


def need(value,message):
    if not value:raise ValueError(message)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def functions(filename,names,**extra):
    text=(NATIVE/filename).read_text() if filename!='prepare.py' else (HERE/filename).read_text()
    tree=ast.parse(text);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    need({n.name for n in nodes}==set(names),'exact isolated DATA function set')
    scope=dict(ast=ast,base64=base64,hashlib=hashlib,io=io,json=json,math=math,os=os,Path=Path,
               PurePosixPath=PurePosixPath,re=re,shutil=shutil,stat=stat,sys=sys,tarfile=tarfile,tempfile=tempfile,
               need=need,pin=pin,data_pin=pin,MAX_FILE=64*1024**2,MAX_TOTAL=128*1024**2,MAX_FILES=256,
               MAX_NODES=100000,OPERATION=PROFILE['operation'],PARENT=PROFILE['parent'],PARENT_TREE=PROFILE['parent_tree'],
               MAP='native/source-map.json',ALLOWED=frozenset(PROFILE['overlay']))
    scope.update(extra)
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'isolated-pair-DATA-functions','exec'),scope)
    return SimpleNamespace(**scope)


def members():
    with tarfile.open(NATIVE/'build-tools-sources-v2.tar') as archive:
        return {m.name:archive.extractfile(m).read() for m in archive}


def payload_bodies(kind):
    carrier=members();recipe=CONTRACT['recipes'][kind];result={}
    private={}
    if kind=='enrollment':
        with tarfile.open(fileobj=io.BytesIO(carrier['recipes/enrollment/private-source.tar.gz']),mode='r:gz') as archive:
            private={m.name.removeprefix('private/'):archive.extractfile(m).read() for m in archive}
    for name in recipe['payload_files']:
        if name.startswith('usr/lib/cachy-asahi/repository-enrollment/'):
            result[name]=private[name.removeprefix('usr/lib/cachy-asahi/repository-enrollment/')]
        else:result[name]=carrier['recipes/'+kind+'/'+Path(name).name]
    return result


def modeled_package(kind,private_header=False):
    recipe=CONTRACT['recipes'][kind];values=payload_bodies(kind)
    pkg=dict(pkgname=[recipe['name']],pkgbase=[recipe['name']],pkgver=[recipe['version']],arch=['any'],license=['MIT'])
    for key,field in [('depend','depends'),('makedepend','makedepends'),('checkdepend','checkdepends'),('optdepend','optdepends')]:
        pkg[key]=recipe[field]
    build=dict(format=['2'],pkgname=[recipe['name']],pkgbase=[recipe['name']],pkgver=[recipe['version']],pkgarch=['any'],
               pkgbuild_sha256sum=[recipe['source_files']['PKGBUILD']['sha256']],installed=CONTRACT['buildinfo_installed'],buildenv=['check'])
    encode=lambda rows:''.join(key+' = '+item+'\n' for key,items in rows.items() for item in items).encode()
    values.update({'.PKGINFO':encode(pkg),'.BUILDINFO':encode(build),'.MTREE':b'MODELED MTREE DATA - NO BUILD EXECUTED'})
    directories={str(p) for name in recipe['payload_files'] for p in Path(name).parents if str(p)!='.'}
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for index,name in enumerate(sorted(directories)):
            member=tarfile.TarInfo(name+'/');member.type=tarfile.DIRTYPE;member.mode=0o755
            if private_header and index==1:member.uname='PRIVATE_KEY'
            archive.addfile(member)
        for name,body in sorted(values.items()):
            member=tarfile.TarInfo(name);member.size=len(body);member.mode=recipe['payload_files'].get(name,dict(mode=420))['mode']
            archive.addfile(member,io.BytesIO(body))
    return stream.getvalue()


def check_log(kind):
    if kind=='enrollment':return b'==> Starting check()...\n'+json.dumps(CONTRACT['recipes'][kind]['check_report'],sort_keys=True).encode()+b'\n'
    carrier=members();text='==> Starting check()...\n'
    for filename,class_name,count in [('test_first_login.py','FirstLoginTests',11),('test_delivery.py','DeliveryTests',3)]:
        methods=[n.name for n in ast.walk(ast.parse(carrier['recipes/first-login/'+filename])) if isinstance(n,ast.FunctionDef) and n.name.startswith('test_')]
        for name in sorted(methods):text+=f'{name} (__main__.{class_name}.{name}) ... ok\n'
        text+=f'Ran {count} tests in 0.123s\n\nOK\n'
    return text.encode()


def tree_from_blobs(rows,blobs):
    nodes={}
    for name,row in rows.items():
        target=nodes
        for part in name.split('/')[:-1]:target=target.setdefault(part,{})
        target[name.split('/')[-1]]=(row['mode'],bytes.fromhex(blobs[name]))
    def emit(node):
        raw=b''
        for name,value in sorted(node.items(),key=lambda pair:pair[0].encode()+(b'/' if isinstance(pair[1],dict) else b'')):
            raw+=(b'40000' if isinstance(value,dict) else b'100755' if value[0]==493 else b'100644')+b' '+name.encode()+b'\0'+(emit(value) if isinstance(value,dict) else value[1])
        return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).digest()
    return emit(nodes).hex()


class PairDataTests(unittest.TestCase):
    def test_profile_whole_pin_nulls_and_typed_source_descriptors(self):
        f=functions('prepare.py',{'need','pin','relative','decode','profile'})
        raw=(HERE/'profile.json').read_bytes();self.assertEqual(f.profile(raw,pin(raw)['sha256']),PROFILE)
        for field,value in [('actual',dict(PROFILE['actual'],run='123')),('operation','hyprland03-alpm-v1')]:
            bad=copy.deepcopy(PROFILE);bad[field]=value;body=json.dumps(bad).encode()
            with self.assertRaises(ValueError):f.profile(body,pin(body)['sha256'])
        with self.assertRaises(ValueError):f.profile(raw,'0'*64)
        bad=copy.deepcopy(PROFILE);bad['overlay'][next(iter(bad['overlay']))]['bytes']=True;body=json.dumps(bad).encode()
        with self.assertRaises(ValueError):f.profile(body,pin(body)['sha256'])

    def test_virtual_complete200_tree_map_and_full_inverse(self):
        parent=(HERE/'parent.raw').read_bytes()
        self.assertEqual(pin(parent),PROFILE['parent_raw'])
        self.assertEqual(hashlib.sha1(b'commit '+str(len(parent)).encode()+b'\0'+parent).hexdigest(),PROFILE['parent'])
        rows=copy.deepcopy(PROFILE['parent_files']);blobs=dict(PROFILE['parent_blobs'])
        self.assertEqual(tree_from_blobs(rows,blobs),PROFILE['parent_tree'])
        for name,row in PROFILE['overlay'].items():
            path=HERE/'payload'/name;raw=path.read_bytes()
            self.assertEqual(dict(**pin(raw),mode=path.stat().st_mode&0o777),row)
            rows[name]=row;blobs[name]=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        mapping=json.loads((HERE/'parent-map.json').read_bytes());mapping['first_login_enrollment_operation']=PROFILE['operation']
        mapping['files']={name:row for name,row in rows.items() if name!='native/source-map.json'}
        raw=(json.dumps(mapping,sort_keys=True,indent=2)+'\n').encode()
        self.assertEqual(pin(raw)['sha256'],PROFILE['map_sha256'])
        rows['native/source-map.json']=dict(**pin(raw),mode=420)
        blobs['native/source-map.json']=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        self.assertEqual((len(rows),len(mapping['files'])),(200,199))
        self.assertEqual(tree_from_blobs(rows,blobs),PROFILE['prospective_tree'])
        changed={name for name in rows if rows[name]!=PROFILE['parent_files'][name]}
        self.assertEqual(changed,set(PROFILE['overlay'])|{'native/source-map.json'})
        for name in changed:rows[name]=PROFILE['parent_files'][name]
        self.assertEqual(rows,PROFILE['parent_files'])

    def test_exact_current_packages_and_authentic_setup8_dependency_data(self):
        self.assertEqual({kind:row['version'] for kind,row in CONTRACT['recipes'].items()},
                         {'first-login':'0.1.0-2','enrollment':'0.3.0-1'})
        self.assertEqual([len(CONTRACT['recipes'][kind]['payload_files']) for kind in ('first-login','enrollment')],[6,15])
        self.assertIn('cachy-asahi-setup>=0.3.0',CONTRACT['recipes']['first-login']['depends'])
        self.assertEqual(CONTRACT['recipes']['enrollment']['checkdepends'],['bubblewrap','util-linux'])
        data=members();dependency=CONTRACT['dependency']
        self.assertEqual(pin(data[dependency['carrier_member']]),dependency['archive_pin'])
        self.assertEqual(dependency['archive_pin'],dict(bytes=33900,sha256='8de3bd0cf2d9333b41925fecdef5cbfe2ec6d40c3424d90746182142e0c7dc47'))
        self.assertEqual(len(CONTRACT['buildinfo_installed']),350)
        for prefix in ('bubblewrap-','util-linux-','fish-','zsh-','python-','libarchive-'):
            self.assertTrue(any(row.startswith(prefix) for row in CONTRACT['buildinfo_installed']))
        self.assertEqual(len(data),25)
        for kind,recipe in CONTRACT['recipes'].items():
            for name,row in recipe['source_files'].items():self.assertEqual(dict(mode=420,**pin(data['recipes/'+kind+'/'+name])),row)
            for name,body in payload_bodies(kind).items():self.assertEqual(pin(body),{k:recipe['payload_files'][name][k] for k in ('bytes','sha256')})

    def test_recipe_checker_requires_real14_and_full_enrollment_report(self):
        f=functions('build_tools_tools_v2.py',{'check_result'})
        self.assertEqual(f.check_result(check_log('first-login'),'first-login',CONTRACT)['tests'],14)
        f.check_result(check_log('enrollment'),'enrollment',CONTRACT)
        for kind in ('first-login','enrollment'):
            for raw in (check_log(kind)+b'skipped=1',check_log(kind).replace(b'Starting check()',b'nocheck'),b'OK\n'):
                with self.assertRaises(ValueError):f.check_result(raw,kind,CONTRACT)
        bad=check_log('enrollment').replace(b'"runtime_files": 9',b'"runtime_files": 8')
        with self.assertRaises(ValueError):f.check_result(bad,'enrollment',CONTRACT)

    def test_both_modeled_package_metadata_payloads_and_archive_frame(self):
        f=functions('build_tools_tools_v2.py',{'_metadata','archive_data'})
        for kind in ('first-login','enrollment'):
            raw=modeled_package(kind);parsed=f.archive_data(raw,CONTRACT['recipes'][kind],CONTRACT['buildinfo_installed'])
            self.assertEqual(parsed['payload'],CONTRACT['recipes'][kind]['payload_files'])
            for tamper in (raw[:512],raw+b'private trailer',raw.replace(b'pkgarch = any',b'pkgarch = x86',1)):
                with self.assertRaises(ValueError):f.archive_data(tamper,CONTRACT['recipes'][kind],CONTRACT['buildinfo_installed'])

    def test_reader_custody_scans_every_header_and_rejects_wrong_path(self):
        f=functions('build_tools_reader_v2.py',{'_metadata','archive_data','hyprland_archive_custody'},PRODUCERS={
                    'native/build-tools-contract-v2.json':pin((NATIVE/'build-tools-contract-v2.json').read_bytes())['sha256']})
        for kind in ('first-login','enrollment'):
            raw=modeled_package(kind);step='archive-'+kind+'-a'
            command=dict(step=step,expected=0,argv=['/usr/bin/zstd','-dc','/opt/native-first-login-enrollment-alpm-v1/build-inputs/'+kind+'-a/'+CONTRACT['recipes'][kind]['archive']],log='003-'+step+'.log',log_pin=pin(raw))
            f.hyprland_archive_custody(raw,command,CONTRACT,3,re.compile(br'PRIVATE_KEY'))
            bad=modeled_package(kind,True);command['log_pin']=pin(bad)
            with self.assertRaisesRegex(ValueError,'private package header'):f.hyprland_archive_custody(bad,command,CONTRACT,3,re.compile(br'PRIVATE_KEY'))
            command['argv'][2]+='.wrong';command['log_pin']=pin(raw)
            with self.assertRaises(ValueError):f.hyprland_archive_custody(raw,command,CONTRACT,3,re.compile(br'PRIVATE_KEY'))

    def test_build_pair_preserves_first_failure_and_never_runs_second_build(self):
        with tempfile.TemporaryDirectory(prefix='MODELED-pair-') as temporary:
            root=Path(temporary);prefix=root/'prefix';prefix.mkdir();recipes=root/'recipes';recipes.mkdir()
            policy=copy.deepcopy(CONTRACT);recipe=policy['recipes']['first-login'];data=members()
            for label in ('a','b'):
                path=recipes/('first-login-'+label);path.mkdir()
                for name in recipe['source_files']:(path/name).write_bytes(data['recipes/first-login/'+name])
            f=functions('build_tools_tools_v2.py',{'build_pair','check_result','ordinary','pin'},PREFIX=prefix)
            original=ValueError('MODELED original validation failure');calls=[]
            def reject(step,argv,expected=0,cwd=None):calls.append(step);raise original
            with self.assertRaises(ValueError) as caught:f.build_pair(reject,root,recipes,'first-login',policy,SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid()),dict(builds={},stages=[]))
            self.assertIs(caught.exception,original);self.assertEqual(calls,['build-first-login-a'])
            self.assertTrue((recipes/'first-login-a').is_dir());self.assertFalse((prefix/'build-current').exists())

    def test_modeled_positive_pair_keeps_two_clean_inodes_one_logical_path(self):
        with tempfile.TemporaryDirectory(prefix='MODELED-pair-positive-') as temporary:
            root=Path(temporary);prefix=root/'prefix';prefix.mkdir();recipes=root/'recipes';recipes.mkdir()
            data=members();recipe=CONTRACT['recipes']['first-login']
            for label in ('a','b'):
                path=recipes/('first-login-'+label);path.mkdir()
                for name in recipe['source_files']:(path/name).write_bytes(data['recipes/first-login/'+name])
            f=functions('build_tools_tools_v2.py',{'build_pair','check_result','ordinary','pin'},PREFIX=prefix)
            records=[];report=dict(builds={},stages=[])
            def model(step,argv,expected=0,cwd=None):
                records.append((step,list(argv),cwd));(cwd/recipe['archive']).write_bytes(b'MODELED ARCHIVE - NEVER A BUILD')
                return check_log('first-login')
            f.build_pair(model,root,recipes,'first-login',CONTRACT,SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid()),report)
            self.assertEqual(len(records),2);self.assertTrue(all(row[2]==prefix/'build-current' for row in records))
            self.assertTrue(all('--nodeps' not in row[1] and '--nocheck' not in row[1] for row in records))
            values=report['builds']['first-login'];self.assertNotEqual(values['a']['directory'],values['b']['directory'])
            self.assertEqual(report['stages'],['first-login-a','first-login-b'])

    def test_matching_command_data_requires_natural_reaping_and_finite_clocks(self):
        f=functions('build_tools_reader_v2.py',{'pair_commands'})
        prefix='journey/MODELED/';body=b'MODELED LOG - NO ACTOR'
        observed=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,
                      timeout=False,signals=[],error=None,exit=0,seconds=.01)
        row=dict(step='modeled',log='000-modeled.log',argv=['/usr/bin/true'],expected=0,success=True,
                 log_pin=pin(body),supervision=observed)
        class View:
            def load(self,name):return [row]
            def read(self,name):return body
        files={prefix+row['log']:dict(kind='file',**pin(body))}
        f.pair_commands(View(),files,prefix,[row],True)
        for key,value in [('group_census','LIVE'),('ownership','LOST'),('reaped',False),('seconds',float('nan')),('seconds',181),('exit',2)]:
            saved=copy.deepcopy(row['supervision']);row['supervision'][key]=value
            with self.assertRaises(ValueError):f.pair_commands(View(),files,prefix,[row],True)
            row['supervision']=saved

    def test_modeled_private_retirement_preserves_foreign_paths_and_reports_failure(self):
        f=functions('build_tools_tools_v2.py',{'retire_private'})
        with tempfile.TemporaryDirectory(prefix='foreign-pair-DATA-') as foreign:
            keep=Path(foreign)/'keep';keep.write_bytes(b'FOREIGN DATA')
            for wrong in (False,True):
                work=Path(tempfile.mkdtemp(prefix='build-tools-test-'))
                homes=[work/'signing',work/'trust']
                for home in homes:home.mkdir(mode=0o700)
                if wrong:homes.append(work/'..'/Path(foreign).name)
                records=[]
                def model(step,argv,expected=0):
                    records.append(argv)
                    return b'gpg-connect-agent: no gpg-agent running in this session\n' if 'no-agent' in step else b''
                result=f.retire_private(model,work,list(map(str,homes)))
                self.assertEqual(result['homes_retired'],not wrong)
                self.assertFalse(work.exists());self.assertEqual(keep.read_bytes(),b'FOREIGN DATA')
                self.assertTrue(all(str(foreign) not in argv for argv in records))

    def test_owned_pid1_quiet_source_layout_and_unchanged_resource_windows(self):
        owner=(NATIVE/'owner.py').read_text();actor=(NATIVE/'build_tools_alpm_v2.py').read_text();tools=(NATIVE/'build_tools_tools_v2.py').read_text()
        self.assertIn("[*DOCKER, 'build', '--quiet'",owner)
        self.assertIn('"$BASHPID" -eq 1',actor);self.assertIn("'--noprofile','--norc','-p','-c'",actor)
        self.assertIn('os.getpid()>1 and os.getppid()==1',actor)
        self.assertIn('timeout=180,total=450,max_output=1024**2',actor)
        self.assertIn('timeout=20,total=90,max_output=1024**2',actor)
        self.assertIn('if primary is not None:raise primary',tools)
        self.assertNotIn("'--nodeps'",ast.get_source_segment(tools, next(n for n in ast.parse(tools).body if isinstance(n,ast.FunctionDef) and n.name=='build_pair')).split('argv=')[1].split('need(')[0])
        self.assertEqual(CONTRACT['bounds']['consumer_memory_bytes'],4*1024**3)
        self.assertEqual(CONTRACT['bounds']['consumer_pids'],256)

    def test_owner_and_workflows_preserve_all_existing_generic_bounds_and_privacy(self):
        original=HERE.parent/'hyprland03-native-source-v1/payload'
        paths=['native/owner.py','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-developer-workflows.yml']
        for name in paths:
            before=(original/name).read_text();after=(HERE/'payload'/name).read_text()
            inverse=after.replace(PROFILE['operation'],'hyprland03-alpm-v1').replace(
                'PASS_FIRST_LOGIN_ENROLLMENT_NATIVE_ALPM_COMPONENT','PASS_HYPRLAND03_NATIVE_ALPM_COMPONENT')
            if name=='native/owner.py':inverse=inverse.replace("[*DOCKER, 'build', '--quiet',", "[*DOCKER, 'build',")
            self.assertEqual(inverse,before)
        for role in ('build_tools_projection_v2.py','build_tools_reader_v2.py'):
            before=ast.parse((original/'native'/role).read_text())
            after=ast.parse((NATIVE/role).read_text())
            assignment=lambda tree:next(node.value for node in tree.body if isinstance(node,ast.Assign)
                and any(isinstance(target,ast.Name) and target.id=='PRIVATE_MARKER' for target in node.targets))
            if role=='build_tools_projection_v2.py':self.assertEqual(ast.dump(assignment(before)),ast.dump(assignment(after)))

    def test_peer_user_journey_is_exact_source_without_second_supervisor(self):
        raw=members()[CONTRACT['first_login_journey']['path']]
        self.assertEqual(pin(raw),{k:CONTRACT['first_login_journey'][k] for k in ('bytes','sha256')})
        imports={node.names[0].name for node in ast.parse(raw).body if isinstance(node,ast.Import)}
        self.assertFalse(imports & {'subprocess','socket','pty','ctypes'})
        self.assertIn(b"expected=75",raw);self.assertIn(b"shell_startups=10",raw)
        self.assertIn(b"'pty': 'NOT RUN'",raw)
        actor=(NATIVE/'build_tools_tools_v2.py').read_text()
        self.assertIn('PASS_REINSTALLED_AND_MOVED_CLI_SMOKE_ONLY',actor)
        self.assertIn("setup='/usr/bin/cachy-asahi-setup'",actor)
        phases=[ast.literal_eval(node.args[0]) for node in ast.walk(ast.parse(raw))
                if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='shells']
        self.assertEqual(phases,['first','edited','removed','recovered','final'])
        self.assertIn("[('first',True),('edited',True),('removed',False),('recovered',True),('final',False)]",
                      (NATIVE/'build_tools_reader_v2.py').read_text())

    def test_reader_refuses_null_actuals_before_local_source_or_capsule(self):
        calls=[]
        def denied(*args):calls.append(args);raise AssertionError('ingress must not happen')
        f=functions('build_tools_reader_v2.py',{'validate'},build_tools_local_binding=denied,open_capsule=denied)
        with self.assertRaises(ValueError):f.validate(Path('/never-open'),dict(source=None,ref=None,run=None,map_sha256=PROFILE['map_sha256']))
        self.assertEqual(calls,[])

    def test_source_constructor_is_inert_atomic_and_requires_explicit_setup8(self):
        text=(HERE/'prepare.py').read_text();imports={node.names[0].name for node in ast.parse(text).body if isinstance(node,ast.Import)}
        self.assertFalse(imports & {'subprocess','socket','requests'})
        for needle in ('renameat2','O_NOFOLLOW','st_nlink == 1','--setup8-package','caller-selected authentic dependency'):
            self.assertIn(needle,text)
        self.assertIn("'8de3bd0cf2d9333b41925fecdef5cbfe2ec6d40c3424d90746182142e0c7dc47'",text)

    def test_real_nofollow_single_link_reads_and_mode_retention(self):
        f=functions('prepare.py',{'need','absolute','directory','identity','read_at','read'})
        with tempfile.TemporaryDirectory(prefix='pair-DATA-read-') as temporary:
            root=Path(temporary);path=root/'source';path.write_bytes(b'INERT DATA');path.chmod(0o644)
            self.assertEqual(f.read(path),(b'INERT DATA',0o644))
            alias=root/'alias';alias.symlink_to(path)
            with self.assertRaises((ValueError,OSError)):f.read(alias)
            os.link(path,root/'hardlink')
            with self.assertRaises(ValueError):f.read(path)


if __name__=='__main__':unittest.main()

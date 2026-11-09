#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-fenced exact quiet argv and modeled image-evidence controls; no Docker."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest

HERE=Path(__file__).resolve().parent
BASE=HERE.parent
N=HERE/'payload/native'
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def load(path):return json.loads(Path(path).read_bytes())
def need(ok,why):
    if not ok:raise ValueError(why)
def function(path,name,extra=None,image_only=False):
    node=next(n for n in ast.parse(Path(path).read_bytes()).body if isinstance(n,ast.FunctionDef)and n.name==name)
    if image_only:
        # Exact image portion only; subsequent container guards remain byte-held.
        end=next(i for i,n in enumerate(node.body)if isinstance(n,ast.FunctionDef)and n.name=='referenced');node.body=node.body[:end]
    scope=dict(need=need,re=re,json=json,Path=Path,pin=pin,hashlib=hashlib,**(extra or {}))
    exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),scope);return scope[name]
BLOCKED=('subprocess.Popen','os.system','os.exec','os.spawn','os.fork','os.posix_spawn','socket.connect','socket.bind','ctypes.dlopen','ctypes.dlsym')
def audit(event,args):
    if any(event==p or event.startswith(p+'.')for p in BLOCKED):raise AssertionError('Actor denied by quiet DATA control: '+event)
sys.addaudithook(audit)
L={'__name__':'modeled_image_lifecycle'}
exec(compile((N/'image_lifecycle.py').read_bytes(),str(N/'image_lifecycle.py'),'exec'),L)
READ=function(N/'developer_tools_reader_v1.py','retained_image_lifecycle',image_only=True)
TREE=function(BASE/'build-pair-first-failure-v1/test_data.py','object_tree')
DOCKER=L['DOCKER'];LABEL=L['LABEL']
OWN=dict(source='a'*40,ref='refs/heads/codex/modeled-quiet',run='1',attempt=1)
OWN['token']=hashlib.sha256((OWN['source']+':'+OWN['ref']+':'+OWN['run']).encode()).hexdigest()[:24]
ALIASES=L['_aliases'](OWN)

def argv(role):
    prefix=(DOCKER+['build','--no-cache','--tag',ALIASES[role],'--label',LABEL+'='+OWN['token'],'--label',LABEL+'.source='+OWN['source'],'--network=none','--pull=false','--platform=linux/arm64']if role=='base'else DOCKER+['build','--quiet','--network=none','--pull=false','--no-cache','--platform=linux/arm64','--tag',ALIASES[role],'--label',LABEL+'='+OWN['token'],'--label',LABEL+'.source='+OWN['source']])
    directory='bootstrap'if role=='base'else'overlay'
    return prefix+['--iidfile','/MODELED/'+directory+'/image-id','/MODELED/'+directory+'/context']

class ModelActor:
    """In-memory callback only: no process, daemon, image or filesystem mutation."""
    def __init__(self,scope,images,logs):self.scope=scope;self.images=images;self.logs=logs;self.rows=[]
    def record(self,command,text,log=None):
        name='actor-logs/'+self.scope+'-'+str(len(self.rows))+'.log';raw=text.encode()
        row=dict(argv=list(command),log=log or '/MODELED/'+name,status='PASS',exit=0,natural_exit=True,group_absent=True,exit_observed_via_waitpid=True,leader_held_until_group_inspection=True,ownership_lost=False,forced_cleanup=False,retirement='REAPED',public_log=name,log_pin=pin(raw))
        self.rows.append(row);self.logs[name]=raw;return row
    def docker(self,*args,timeout):
        need(timeout==10,'held callback timeout');text=''
        if args[:2]==('image','ls'):
            selector=args[-1];ids=sorted(i for i,row in self.images.items()if selector.startswith('label=')or selector.removeprefix('reference=')in row['RepoTags']);text='\n'.join(ids)
        elif args[:2]==('image','inspect'):
            rows=[row for i,row in self.images.items()if args[2]==i or args[2]in row['RepoTags']];need(len(rows)==1,'modeled identity');text=json.dumps(rows,sort_keys=True)
        elif args[:2]==('image','rm'):
            found=[i for i,row in self.images.items()if args[2]in row['RepoTags']];need(len(found)==1,'modeled no-force alias removal');del self.images[found[0]];text='Untagged: '+args[2]
        else:raise AssertionError('unmodeled actor callback')
        self.record(DOCKER+list(args),text+'\n'if text else'');return text

class View:
    def __init__(self,raw):self.raw=raw
    def read(self,name):return self.raw[name]
    def load(self,name):return json.loads(self.read(name))

def capsule():
    images={};logs={};actor=ModelActor('owner',images,logs);ledger=L['reserve'](actor,OWN);builds=[]
    for role,digit in(('base','b'),('tools','c')):
        image='sha256:'+digit*64
        images[image]=dict(Id=image,Architecture='arm64',Os='linux',RepoTags=[ALIASES[role]],Config=dict(Labels={LABEL:OWN['token'],LABEL+'.source':OWN['source']}))
        row=actor.record(argv(role),image+'\n','/MODELED/bootstrap/bootstrap.log'if role=='base'else None);builds.append(dict(role=role,terminal=True,actor=row))
        if role=='tools':L['verify_base'](actor,ledger)
        L['register'](actor,ledger,role,image,row)
        if role=='base':L['verify_base'](actor,ledger)
    ledger['source_map_sha256']='d'*64;retirer=ModelActor('retirement',images,logs);retirement=L['retire'](retirer,ledger);retirement['source_map_sha256']='d'*64
    receipt=dict(actors=actor.rows,image_ledger=ledger,bootstrap=dict(image='sha256:'+'b'*64),consumer=dict(image='sha256:'+'c'*64))
    cleanup=dict(actors=retirer.rows,image_retirement=retirement,build_operations=builds)
    logs.update({'image-ledger.json':encoded(ledger),'image-retirement.json':encoded(retirement),'bootstrap-proof/overlay-Dockerfile':('FROM '+ALIASES['base']+'\n# MODELED inert Dockerfile\n').encode()})
    files={name:dict(kind='file',**pin(raw))for name,raw in logs.items()}
    return SimpleNamespace(view=View(logs),files=files,receipt=receipt,cleanup=cleanup,images=images)
def read(c):return READ(c.view,c.files,c.receipt,c.cleanup,OWN,'d'*64)

class QuietToolsBuildTests(unittest.TestCase):
    def test01_exact_owner_command_and_three_minimal_inverse_bodies(self):
        parent=load(BASE/'build-pair-first-failure-v1/payload/native/source-map.json')['files']
        edits={'owner.py':[("command = [*DOCKER, 'build', '--quiet', '--network=none'","command = [*DOCKER, 'build', '--network=none'")],
          'image_lifecycle.py':[("len(argv) == (16 if role == 'base' else 17)","len(argv) == 16"),("DOCKER+['build','--quiet','--network=none'","DOCKER+['build','--network=none'")],
          'developer_tools_reader_v1.py':[("len(argv) == (16 if role == 'base' else 17), 'exact source-owned image build argv required'","len(argv) == 16, 'exact source-owned image build argv required'"),("docker + ['build', '--quiet', '--network=none'","docker + ['build', '--network=none'")]}
        for name,changes in edits.items():
            text=(N/name).read_text()
            for new,old in changes:self.assertEqual(text.count(new),1);text=text.replace(new,old)
            self.assertEqual(pin(text.encode()),{k:parent['native/'+name][k]for k in('bytes','sha256')})
        command=next(n.value for n in ast.walk(ast.parse((N/'owner.py').read_bytes()))if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='command'for t in n.targets)and isinstance(n.value,ast.List)and any(isinstance(v,ast.Constant)and v.value=='--quiet'for v in n.value.elts))
        actual=eval(compile(ast.Expression(command),'<MODELED exact owner argv>','eval'),dict(DOCKER=DOCKER,LABEL=LABEL,own=OWN,overlay=Path('/MODELED/overlay'),context=Path('/MODELED/overlay/context')))
        self.assertEqual(actual,argv('tools'));self.assertEqual(len(actual),17);self.assertEqual(len(argv('base')),16)
    def test02_complete_modeled_image_registration_bracketing_retirement_and_reader_image_join(self):
        c=capsule();self.assertEqual(c.cleanup['image_retirement']['status'],'PASS_EXACT_OWNED_IMAGE_ALIASES_RETIRED');self.assertEqual(c.images,{});self.assertIsNone(read(c))
        tools=c.receipt['image_ledger']['created']['tools'];row=c.receipt['actors'][tools['build_actor_index']]
        self.assertEqual(c.view.read(row['public_log']),('sha256:'+'c'*64+'\n').encode());self.assertEqual(row['log_pin'],pin(c.view.read(row['public_log'])));self.assertEqual(tools['build']['argv'],argv('tools'));self.assertEqual(row['retirement'],'REAPED')
    def test03_quiet_is_required_only_at_the_fixed_tools_position(self):
        for role in('base','tools'):
            command=argv(role);wrong=[command[:3]+['--quiet']+command[3:],command+['--quiet']]
            if role=='tools':wrong.extend([[v for v in command if v!='--quiet'],command[:3]+command[4:6]+['--quiet']+command[6:]])
            for value in wrong:
                c=capsule();created=c.receipt['image_ledger']['created'][role];row=c.receipt['actors'][created['build_actor_index']];row['argv']=value;created['build']['argv']=value
                with self.subTest(role=role,argv=value),self.assertRaises(L['ImageGuard']):L['_build'](row,c.receipt['image_ledger'],role)
                with self.subTest(reader=role,argv=value),self.assertRaises(ValueError):read(c)
    def test04_fixed_daemon_network_pull_cache_platform_labels_tag_and_iid_still_refuse_drift(self):
        for role in('base','tools'):
            for index,value in enumerate(argv(role)):
                c=capsule();created=c.receipt['image_ledger']['created'][role];row=c.receipt['actors'][created['build_actor_index']];changed=list(row['argv']);changed[index]=value+'-MODELED-DRIFT';row['argv']=changed;created['build']['argv']=changed
                with self.subTest(role=role,index=index),self.assertRaises(L['ImageGuard']):L['_build'](row,c.receipt['image_ledger'],role)
                with self.subTest(reader=role,index=index),self.assertRaises(ValueError):read(c)
    def test05_complete_stdout_pin_and_natural_retirement_still_required(self):
        for key,value in dict(status='FAIL',exit=1,natural_exit=False,group_absent=False,exit_observed_via_waitpid=False,leader_held_until_group_inspection=False,ownership_lost=True,forced_cleanup=True,retirement='UNKNOWN').items():
            c=capsule();created=c.receipt['image_ledger']['created']['tools'];row=c.receipt['actors'][created['build_actor_index']];row[key]=value;created['build'][key]=value
            with self.subTest(key=key),self.assertRaises(L['ImageGuard']):L['_build'](row,c.receipt['image_ledger'],'tools')
            with self.subTest(reader=key),self.assertRaises(ValueError):read(c)
        c=capsule();row=c.receipt['actors'][c.receipt['image_ledger']['created']['tools']['build_actor_index']];c.view.raw[row['public_log']]+=b'MODELED missing original bytes\n'
        with self.assertRaises(ValueError):read(c)
    def test06_declared_policy_unchanged_quiet_full_argv_retained_without_effective_policy_claim(self):
        owner=function(N/'owner.py','build_policy_declared');reader=function(N/'developer_tools_reader_v1.py','build_policy_declared')
        for role in('base','tools'):
            current=argv(role);old=[v for v in current if v!='--quiet'];self.assertEqual(owner(current),owner(old));self.assertEqual(owner(current),reader(current));self.assertNotIn('quiet',owner(current));self.assertEqual(owner(current)['network'],'none');self.assertEqual(owner(current)['pull'],'false');self.assertEqual(owner(current)['platform'],'linux/arm64')
        policies=[next(n for n in ast.parse((N/name).read_bytes()).body if isinstance(n,ast.FunctionDef)and n.name=='build_policy_declared')for name in('owner.py','developer_tools_reader_v1.py')]
        self.assertEqual(ast.dump(policies[0]),ast.dump(policies[1]))
    def test07_virtual_actual8238_parent_closed200_four_leaf_map_and196_inverse(self):
        profile=load(HERE/'profile.json');rows=load(BASE/'parent-git-objects.json');base=load(BASE/'profile.json')
        for name in base['removed']:rows.pop(name)
        def apply(root,p):
            for name,row in p['overlay'].items():
                raw=(root/'payload'/name).read_bytes();rows[name]=dict(mode=row['mode'],blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest());self.assertEqual(pin(raw),{k:row[k]for k in('bytes','sha256')})
        apply(BASE,base)
        for variant in('safe-failure-v1','build-pair-first-failure-v1'):apply(BASE/variant,load(BASE/variant/'profile.json'))
        self.assertEqual(TREE(rows),profile['parent_tree']);before=copy.deepcopy(rows);apply(HERE,profile);self.assertEqual(TREE(rows),profile['source_tree']);self.assertEqual(len(rows),200);self.assertEqual((profile['changed'],profile['held']),(4,196))
        changed={k for k in rows if rows[k]!=before[k]};self.assertEqual(changed,set(profile['overlay']))
        for name in changed:rows[name]=before[name]
        self.assertEqual(rows,before);manifest=load(N/'source-map.json');self.assertEqual(len(manifest['files']),199);self.assertEqual(manifest['actual'],dict(source=None,ref=None,run=None));self.assertEqual(pin((N/'source-map.json').read_bytes()),profile['source_map'])
        raw=(HERE/'parent.raw-commit').read_bytes();self.assertEqual(pin(raw),profile['parent_raw']);self.assertEqual(hashlib.sha1(b'commit '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),profile['parent_source']);self.assertTrue(raw.startswith(('tree '+profile['parent_tree']+'\n').encode()))
        oldmap=(BASE/'build-pair-first-failure-v1/payload/native/source-map.json').read_bytes();self.assertEqual(pin(oldmap),profile['parent_map'])
        old=load(BASE/'build-pair-first-failure-v1/payload/native/source-map.json');expected=copy.deepcopy(old);expected['developer_quiet_tools_build_parent']=profile['parent_source']
        for name,row in profile['overlay'].items():
            if name!='native/source-map.json':expected['files'][name]=row
        self.assertEqual(manifest,expected)

if __name__=='__main__':unittest.main(verbosity=2)

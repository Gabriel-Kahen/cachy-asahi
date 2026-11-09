#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Modeled failure DATA only; no Source constructor, projector or Reader actor."""
import ast
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import types
import unittest

HERE=Path(__file__).resolve().parent
BASE=HERE.parent
N=HERE/'payload/native'
def need(ok,why):
    if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
oldtree=ast.parse((BASE/'payload/native/developer_tools_projection_v1.py').read_bytes())
marker=next(n for n in oldtree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='PRIVATE_MARKER'for t in n.targets))
ns={'re':re};exec(compile(ast.Module(body=[marker],type_ignores=[]),'_held_privacy_expression','exec'),ns)
MARKER=ns['PRIVATE_MARKER']
def safe_text(raw):
    need(not MARKER.search(raw),'full held privacy marker refused')
    text=raw.decode('utf-8');need(not any(ord(c)<32 and c not in '\n\r\t'for c in text),'control text refused');return text

def scope(ordinary=None):
    calls=[]
    def read(path,cap):
        path=Path(path);calls.append(path)
        if ordinary is not None:return ordinary(path,cap)
        need(path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary DATA leaf')
        with path.open('rb')as stream:raw=stream.read(cap+1)
        need(len(raw)<=cap,'bounded DATA leaf');return raw
    @contextlib.contextmanager
    def directory(path,mutable=False):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:yield fd
        finally:os.close(fd)
    c=types.SimpleNamespace(need=need,pin=pin,_json=encoded,_load=json.loads,_ordinary=read,_absolute=lambda p:Path(p).absolute(),_directory=directory)
    env=dict(C=c,hashlib=hashlib,os=os,re=re,safe_text=safe_text,DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock'],FIELDS=())
    tree=ast.parse((N/'safe_diagnostic.py').read_bytes());nodes=[n for n in tree.body if not isinstance(n,(ast.Import,ast.ImportFrom))]
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'_developer_safe_data_functions','exec'),env)
    return env,calls

def own():
    value=dict(source='f'*40,ref='refs/heads/codex/modeled-data',run='1',attempt=1)
    value['token']=hashlib.sha256((value['source']+':'+value['ref']+':'+value['run']).encode()).hexdigest()[:24];return value
MAP='a'*64

def result():
    failure=dict(phase='build-a',type='ValueError',message='secret=MODELED_ONLY password:DO_NOT_EMIT',command_index=0)
    return dict(schema_version=1,operation='developer-tools-alpm-v1',source_map_sha256=MAP,status='FAIL',first_failure=failure,
        failure=dict(failure),phase='cleanup',commands=[dict(step='build-a',success=False,log_pin=pin(b'MODELED OMITTED RAW'),
        supervision=dict(exit=1,ownership='REAPED',group_census='EMPTY_TWICE',reaped=True,output_complete=True,timeout=False))],
        stages=[],cleanup=dict(homes_retired=True,no_sockets=True,private_directory_absent=True))

def object_tree(rows):
    nodes={}
    for name,row in rows.items():
        target=nodes
        for part in Path(name).parts[:-1]:target=target.setdefault(part,{})
        target[Path(name).name]=(row['mode'],row['blob'])
    def branch(node):
        body=b''
        for name,value in sorted(node.items(),key=lambda r:r[0].encode()+(b'/'if type(r[1])is dict else b'')):
            mode,digest=(b'40000',branch(value))if type(value)is dict else(b'100755'if value[0]==0o755 else b'100644',bytes.fromhex(value[1]))
            body+=mode+b' '+name.encode()+b'\0'+digest
        return hashlib.sha1(b'tree '+str(len(body)).encode()+b'\0'+body).digest()
    return branch(nodes).hex()

class SafeFailureTests(unittest.TestCase):
    def test01_private_first_message_is_hashed_and_first_identity_held(self):
        S,_=scope();r=result();r['failure']['message']='later cleanup error';value=S['developer_context'](encoded(r),own(),MAP)
        first=value['first_failure'];self.assertEqual(first['phase']['label'],'build-a');self.assertEqual(first['error_type']['label'],'ValueError')
        self.assertEqual(first['message'],pin(r['first_failure']['message'].encode()));self.assertEqual(first['identity'],pin(encoded(r['first_failure'])))
        self.assertEqual(first['command_index'],0);self.assertEqual(value['selected_command']['exit'],1)
        self.assertNotIn(b'MODELED_ONLY',encoded(value));self.assertNotIn(b'DO_NOT_EMIT',encoded(value));self.assertNotIn(b'later cleanup',encoded(value));self.assertFalse(MARKER.search(encoded(value)))
    def test02_unknown_phase_type_and_command_are_never_raw(self):
        S,_=scope();r=result();r['first_failure'].update(phase='password:MODELED',type='secret=MODELED');r['commands'][0]['step']='access_token=MODELED'
        value=S['developer_context'](encoded(r),own(),MAP)
        for row in(value['first_failure']['phase'],value['first_failure']['error_type'],value['selected_command']['step']):self.assertEqual(row['label'],'UNLISTED')
        self.assertNotIn(b'MODELED',encoded(value));self.assertFalse(MARKER.search(encoded(value)))
    def test03_no_first_failure_means_no_invented_cause(self):
        S,_=scope();r=result();r['first_failure']=None;r['commands']=[]
        value=S['developer_context'](encoded(r),own(),MAP);self.assertIsNone(value['first_failure']);self.assertIsNone(value['selected_command']);self.assertEqual(value['component_status'],'FAIL')
    def test04_cap_status_map_and_type_fail_closed(self):
        S,_=scope()
        for key,v in(('status','PASS_DEVELOPER_TOOLS_NATIVE_ALPM_COMPONENT'),('source_map_sha256','b'*64),('operation','other')):
            r=result();r[key]=v
            with self.assertRaises(ValueError):S['developer_context'](encoded(r),own(),MAP)
        for r in(result()|{'commands':[{}]*161},result()|{'first_failure':dict(phase='build-a',type='ValueError',message='x',command_index=True)}):
            with self.assertRaises(ValueError):S['developer_context'](encoded(r),own(),MAP)
        with self.assertRaises(ValueError):S['developer_context'](b'x'*(4*1024**2+1),own(),MAP)
    def test05_summary_validator_rejects_free_text_extra_fields_and_native_credit(self):
        S,_=scope();value=S['developer_context'](encoded(result()),own(),MAP)
        for mutate in(lambda v:v.update(message='password:MODELED'),lambda v:v.update(native='PASS'),lambda v:v['first_failure']['phase'].update(label='unreviewed-string'),lambda v:v['first_failure']['message'].update(sha256='not-a-pin')):
            bad=copy.deepcopy(value);mutate(bad)
            with self.assertRaises(ValueError):S['check_developer'](bad,own(),MAP)
    def test06_fixed_capture_and_fallback_survive_other_raw_privacy_refusal(self):
        S,calls=scope()
        with tempfile.TemporaryDirectory()as tmp:
            work=Path(tmp);public=work/'public';component=public/'journey/developer-tools-alpm-v1';component.mkdir(parents=True)
            (component/'result.json').write_bytes(encoded(result()));actor=public/'actor-logs';actor.mkdir();refused=actor/'0025.log';secret=b'password=MODELED_PRIVATE_REFUSED';refused.write_bytes(secret)
            receipt=S['retain_developer'](work,public,own(),MAP);self.assertEqual(receipt['status'],'RETAINED_DEVELOPER_FIRST_FAILURE_CONTEXT')
            capture_calls=list(calls);self.assertEqual(capture_calls,[component/'result.json']);calls.clear()
            authority=S['create'](work,own(),MAP)
            self.assertEqual(authority['files']['developer-failure.json']['status'],'RETAINED');self.assertEqual(authority['original_public'],'PRESERVED_UNTRAVERSED');self.assertEqual(authority['original_projection'],'PRESERVED_UNTRAVERSED')
            self.assertNotIn(refused,calls);self.assertNotIn(component/'result.json',calls);self.assertEqual(refused.read_bytes(),secret)
            retained=(work/'safe-diagnostic/developer-failure.json').read_bytes();self.assertNotIn(b'MODELED_PRIVATE',retained);self.assertFalse(MARKER.search(retained));self.assertEqual(authority['files']['developer-failure.json']['sha256'],pin(retained)['sha256'])
    def test07_capture_missing_source_and_repeated_output_do_not_overwrite(self):
        S,_=scope()
        with tempfile.TemporaryDirectory()as tmp:
            work=Path(tmp);public=work/'public';public.mkdir()
            self.assertEqual(S['retain_developer'](work,public,own(),MAP)['status'],'ABSENT_OR_REFUSED_DEVELOPER_FIRST_FAILURE_CONTEXT')
            component=public/'journey/developer-tools-alpm-v1';component.mkdir(parents=True);(component/'result.json').write_bytes(encoded(result()))
            self.assertEqual(S['retain_developer'](work,public,own(),MAP)['status'],'RETAINED_DEVELOPER_FIRST_FAILURE_CONTEXT')
            before=(work/'developer-failure.json').read_bytes();self.assertEqual(S['retain_developer'](work,public,own(),MAP)['status'],'ABSENT_OR_REFUSED_DEVELOPER_FIRST_FAILURE_CONTEXT');self.assertEqual((work/'developer-failure.json').read_bytes(),before)
    def test08_raw_guard_and_non_diagnostic_owner_functions_held(self):
        old=(BASE/'payload/native/owner.py').read_text();new=(N/'owner.py').read_text();hook="            if operation=='developer-tools-alpm-v1':\n                from safe_diagnostic import retain_developer\n                report['developer_failure_context']=retain_developer(args.work,output,own,args.map_sha256)\n"
        self.assertEqual(new.replace(hook,''),old)
        self.assertLess(new.index('retain_developer(args.work'),new.index('project(root, output'))
        reader=(N/'developer_tools_reader_v1.py').read_text();self.assertIn('check_developer(document,binding,map_sha256)',reader);self.assertIn("native='NOT_ADMITTED'",reader)
        oldtree=ast.parse((BASE/'payload/native/developer_tools_reader_v1.py').read_bytes());newtree=ast.parse(reader)
        oldf={n.name:ast.dump(n,include_attributes=False)for n in oldtree.body if isinstance(n,ast.FunctionDef)};newf={n.name:ast.dump(n,include_attributes=False)for n in newtree.body if isinstance(n,ast.FunctionDef)}
        self.assertEqual({n for n in oldf if oldf[n]!=newf[n]},{'retained_safe_diagnostic'})
    def test09_exact_four_leaf_variant_and_no_constructor_actor(self):
        profile=json.loads((HERE/'profile.json').read_bytes());self.assertEqual((profile['source_files'],profile['changed'],profile['held']),(200,4,196));self.assertEqual(profile['actual'],dict(source=None,ref=None,run=None));self.assertEqual(profile['original_inner_cause'],'UNKNOWN_NOT_RECONSTRUCTED')
        for name,row in profile['overlay'].items():self.assertEqual(pin((HERE/'payload'/name).read_bytes()),{k:row[k]for k in('bytes','sha256')})
        old=json.loads((BASE/'payload/native/source-map.json').read_bytes());new=json.loads((N/'source-map.json').read_bytes());self.assertEqual(set(old['files']),set(new['files']));self.assertEqual({n for n in old['files']if old['files'][n]!=new['files'][n]},{'native/owner.py','native/developer_tools_reader_v1.py','native/safe_diagnostic.py'})
        self.assertEqual(profile['parent_map'],pin((BASE/'payload/native/source-map.json').read_bytes()))
        rows=json.loads((BASE/'parent-git-objects.json').read_bytes());baseprofile=json.loads((BASE/'profile.json').read_bytes())
        for name in baseprofile['removed']:rows.pop(name)
        for name,row in baseprofile['overlay'].items():
            body=(BASE/'payload'/name).read_bytes();rows[name]=dict(mode=row['mode'],blob=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest())
        self.assertEqual(object_tree(rows),profile['parent_tree'])
        for name,row in profile['overlay'].items():
            body=(HERE/'payload'/name).read_bytes();rows[name]=dict(mode=row['mode'],blob=hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest())
        self.assertEqual(len(rows),200);self.assertEqual(object_tree(rows),profile['source_tree'])
    def test10_fallback_still_rejects_privacy_in_selected_summary(self):
        S,_=scope()
        with tempfile.TemporaryDirectory()as tmp:
            work=Path(tmp);value=S['developer_context'](encoded(result()),own(),MAP);value['extra']='password=MODELED'
            (work/'developer-failure.json').write_bytes(encoded(value));authority=S['create'](work,own(),MAP)
            self.assertEqual(authority['files']['developer-failure.json'],dict(status='REFUSED',code='SOURCE_DIAGNOSTIC_SCHEMA_OR_PRIVACY_REFUSED'));self.assertFalse((work/'safe-diagnostic/developer-failure.json').exists())

if __name__=='__main__':unittest.main(verbosity=2)

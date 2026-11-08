#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""PID1 source/layout DATA controls. Never starts Bash, imports Source or reads capsules."""
import sys
EVENTS=[]
def audit(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in {'os.system','os.exec','os.fork','os.forkpty','os.posix_spawn','os.kill','os.killpg','os.wait','os.waitpid'}:
        EVENTS.append(event);raise AssertionError('DATA controls forbid '+event)
sys.addaudithook(audit)
sys.dont_write_bytecode=True
import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import shlex
from types import SimpleNamespace
import unittest

HERE=Path(__file__).resolve().parent
PARENT='52a425ef08c5dc84ba1a7c5b53be8d21dc42f9dd'
OLD_ALPM='1300cf9156e4f607b8838e54011f1665b4a0d21aefb8863fef6e2752c81caea5'
GUARD=" need(os.getpid()>1 and os.getppid()==1,'PID1-shell variant requires non-PID1 Python directly parented by namespace init')\n"
LAYOUT=" report['process_layout']=dict(schema=1,contract='bash-pid1-direct-python-child-v1',python_pid=os.getpid(),python_ppid=os.getppid(),status='OBSERVED_NON_PID1_PYTHON_DIRECT_CHILD')\n"
MAP='a'*64
BASE='FROM SYNTHETIC\nUSER alarm\nWORKDIR /tmp\n'

def need(ok,why):
    if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def oid(kind,raw):return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def function(raw,name):
    rows=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name==name]
    need(len(rows)==1,'one inspected function');return rows[0]
def isolated(node,**namespace):
    module=ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)],type_ignores=[]))
    exec(compile(module,'<isolated-data-function>','exec'),namespace);return namespace[node.name]
def tree(rows):
    root={}
    for name,row in rows.items():
        at=root;parts=name.split('/')
        for part in parts[:-1]:at=at.setdefault(part,{})
        at[parts[-1]]=(row['mode'],row['oid'])
    def walk(at):
        raw=b''
        for name,row in sorted(at.items(),key=lambda x:(x[0]+('/' if isinstance(x[1],dict) else '')).encode()):
            mode,digest=('40000',walk(row)) if isinstance(row,dict) else row
            raw+=mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(digest)
        return oid('tree',raw)
    return walk(root)
def layout(pid=17,ppid=1):return dict(schema=1,contract='bash-pid1-direct-python-child-v1',python_pid=pid,python_ppid=ppid,status='OBSERVED_NON_PID1_PYTHON_DIRECT_CHILD')

class LayoutData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profile=json.loads((HERE/'profile.json').read_bytes());cls.rows=json.loads((HERE/'parent-files.json').read_bytes())
        cls.payload={n:(HERE/'payload'/n).read_bytes() for n in cls.profile['payload']}
        cls.alpm=cls.payload['native/build_tools_alpm_v2.py'];cls.reader=cls.payload['native/build_tools_reader_v2.py']
    def tearDown(self):self.assertEqual(EVENTS,[])
    def formatter(self):return isolated(function(self.alpm,'dockerfile'),need=need,re=re,json=json)
    def checker(self):return isolated(function(self.reader,'build_tools_process_layout'),need=need)
    def test_whole_actor_inverse(self):
        text=self.alpm.decode();node=function(text,'dockerfile');lines=text.splitlines(keepends=True)
        lines[node.lineno-1:node.end_lineno]= (HERE/'baseline-dockerfile-function.txt').read_text().splitlines(keepends=True)
        # Function replacement includes its trailing newline; preserve the untouched separator.
        rebuilt=''.join(lines).replace(GUARD,'').replace(LAYOUT,'')
        self.assertEqual(hashlib.sha256(rebuilt.encode()).hexdigest(),OLD_ALPM)
    def test_exec_form_pid1_wait_and_exact_status(self):
        result=self.formatter()(BASE,MAP);run=next(line for line in result.splitlines() if line.startswith('RUN '));argv=json.loads(run[4:])
        self.assertEqual(argv[:5],['/usr/bin/bash','--noprofile','--norc','-p','-c']);self.assertEqual(len(argv),6)
        wanted=('test "$BASHPID" -eq 1 || exit 125; /usr/bin/python3 -I -B /opt/native-build-tools-alpm-v2/source/native/build_tools_alpm_v2.py '
                '--inside-image --retain-failure-image --map-sha256 '+MAP+' & build_tools_owner=$!; build_tools_status=0; wait "$build_tools_owner" || build_tools_status=$?; exit "$build_tools_status"')
        self.assertEqual(argv[5],wanted);self.assertEqual(shlex.split(argv[5]),shlex.split(wanted));self.assertNotIn('exec ',argv[5])
        self.assertTrue(result.endswith('\nUSER alarm\nWORKDIR /tmp\n'));self.assertEqual(result.count('RUN '),1)
    def test_exact_suffix_no_fallback(self):
        for base in ('FROM other\n',BASE+'\n',BASE+BASE,BASE.replace('alarm','root')):
            with self.subTest(base=base),self.assertRaises(ValueError):self.formatter()(base,MAP)
    def test_map_injection_refused(self):
        for value in (None,'',MAP+'; id',MAP+'\n',MAP.upper(),42):
            with self.subTest(value=value),self.assertRaises((ValueError,TypeError)):self.formatter()(BASE,value)
    def test_direct_child_guard(self):
        node=function(self.alpm,'inside');node.body=node.body[:2]+[ast.Return(ast.Name('source',ast.Load()))]
        for pid,ppid,passes in ((17,1,True),(1,0,False),(1,1,False),(17,2,False)):
            fn=isolated(node,Path=Path,need=need,os=SimpleNamespace(getpid=lambda:pid,getppid=lambda:ppid))
            if passes:self.assertEqual(fn('/synthetic',MAP),Path('/synthetic'))
            else:
                with self.assertRaises(ValueError):fn('/synthetic',MAP)
    def test_guard_before_source_or_actor(self):
        inside=function(self.alpm,'inside');self.assertEqual(ast.get_source_segment(self.alpm.decode(),inside.body[1]),GUARD.strip())
        self.assertIsInstance(inside.body[3],ast.ImportFrom);self.assertEqual(inside.body[3].module,'common')
    def test_observed_layout_preserves_real_ids(self):
        node=function(self.alpm,'inside');statement=next(n for n in node.body if isinstance(n,ast.Assign) and ast.get_source_segment(self.alpm.decode(),n)==LAYOUT.strip())
        module=ast.fix_missing_locations(ast.Module(body=[statement],type_ignores=[]))
        ns=dict(report={},os=SimpleNamespace(getpid=lambda:37,getppid=lambda:1));exec(compile(module,'<layout-DATA>','exec'),ns)
        self.assertEqual(ns['report']['process_layout'],layout(37,1))
    def test_reader_exact_layout_positive(self):self.assertEqual(self.checker()(dict(process_layout=layout())),layout())
    def test_reader_rejects_missing_or_marker_only(self):
        for report in ({},{'process_layout':None},{'status':'PASS_BUILD_TOOLS_NATIVE_ALPM_COMPONENT'},{'process_layout':{'status':'OBSERVED_NON_PID1_PYTHON_DIRECT_CHILD'}}):
            with self.subTest(report=report),self.assertRaises(ValueError):self.checker()(report)
    def test_reader_rejects_forged_types_parents_and_pid1(self):
        for key,values in dict(schema=[True,0,2],python_pid=[True,1,0,-1,2**31,'17'],python_ppid=[True,0,2,'1'],contract=['other'],status=['PASS']).items():
            for value in values:
                row=layout();row[key]=value
                with self.subTest(key=key,value=value),self.assertRaises(ValueError):self.checker()(dict(process_layout=row))
        row=layout();row['reaped']=True
        with self.assertRaises(ValueError):self.checker()(dict(process_layout=row))
    def test_positive_state_cannot_override_failures(self):
        fn=isolated(function(self.reader,'build_tools_positive_state'),need=need,build_tools_process_layout=self.checker())
        fn(dict(process_layout=layout(),first_failure=None))
        for extra in ({'retention_failures':['x']},{'first_failure':{}},{'failure':'x'}):
            with self.subTest(extra=extra),self.assertRaises(ValueError):fn(dict(process_layout=layout(),**extra))
        with self.assertRaises(ValueError):fn(dict(first_failure=None))
    def test_failure_data_independently_checks_layout(self):
        body=ast.dump(function(self.reader,'build_tools_failure_data'))
        self.assertIn("func=Name(id='build_tools_process_layout'",body)
        self.assertIn("value='process_layout'",body)
    def test_companion_pins_and_no_other_projection_change(self):
        new=pin(self.alpm)['sha256']
        projection=self.payload['native/build_tools_projection_v2.py']
        before=projection.replace(new.encode(),OLD_ALPM.encode())
        self.assertEqual(pin(before),{k:self.rows['native/build_tools_projection_v2.py'][k] for k in ('bytes','sha256')})
        for name in ('native/build_tools_projection_v2.py','native/build_tools_reader_v2.py'):
            module=ast.parse(self.payload[name]);assignment=next(n for n in module.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PRODUCERS' for t in n.targets))
            pins=ast.literal_eval(assignment.value);self.assertEqual(pins['native/build_tools_alpm_v2.py'],new)
            self.assertEqual(pins['native/build-tools-contract-v2.json'],self.rows['native/build-tools-contract-v2.json']['sha256'])
    def test_whole_reader_inverse_preserves_all_other_guards(self):
        text=self.reader.decode();node=function(text,'build_tools_process_layout');lines=text.splitlines(keepends=True)
        del lines[node.lineno-1:node.end_lineno+2]
        text=''.join(lines).replace("    build_tools_process_layout(report)\n",'').replace("    result['process_layout']=build_tools_process_layout(report)\n",'')
        text=text.replace(pin(self.alpm)['sha256'],OLD_ALPM)
        self.assertEqual(pin(text.encode()),{k:self.rows['native/build_tools_reader_v2.py'][k] for k in ('bytes','sha256')})
    def test_actual_parent_commit_full200_tree(self):
        raw=(HERE/'parent.raw-commit').read_bytes();self.assertEqual(oid('commit',raw),PARENT)
        self.assertEqual(len(self.rows),200);self.assertEqual(tree(self.rows),self.profile['parent_tree'])
        self.assertTrue(raw.startswith(('tree '+self.profile['parent_tree']+'\n').encode()))
        self.assertEqual([line for line in raw.decode().split('\n\n')[0].splitlines() if line.startswith('parent ')],['parent c5e2c80a6dc2c66b471b4ea5d5162963c08a36b8'])
    def test_virtual_map_full_inverse_196held(self):
        manifest=json.loads((HERE/'parent-source-map.json').read_bytes());rows=copy.deepcopy(self.rows)
        self.assertEqual(set(manifest['files']),set(rows)-{'native/source-map.json'})
        for name,row in manifest['files'].items():self.assertEqual(row,dict(bytes=rows[name]['bytes'],sha256=rows[name]['sha256'],mode=int(rows[name]['mode'],8)&0o777))
        for name,body in self.payload.items():
            self.assertEqual(pin(body),self.profile['payload'][name]);manifest['files'][name]=dict(pin(body),mode=0o644)
            rows[name]=dict(pin(body),mode='100644',oid=oid('blob',body))
        manifest['build_tools_pid1_shell_parent']=PARENT;raw=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()
        rows['native/source-map.json']=dict(pin(raw),mode='100644',oid=oid('blob',raw))
        self.assertEqual(pin(raw),self.profile['source_map']);self.assertEqual(tree(rows),self.profile['source_tree'])
        changed={n for n in rows if rows[n]!=self.rows[n]};self.assertEqual(changed,set(self.payload)|{'native/source-map.json'});self.assertEqual(len(rows)-len(changed),196)
        self.assertEqual(self.profile['actual'],dict(source=None,ref=None,run=None))
    def test_profile_raw_and_map_pins(self):
        for field,name in (('parent_raw','parent.raw-commit'),('parent_files','parent-files.json'),('parent_source_map','parent-source-map.json')):
            self.assertEqual(pin((HERE/name).read_bytes()),self.profile[field])
        self.assertEqual(self.profile['matching_reader'],dict(target='native/build_tools_reader_v2.py',**pin(self.reader)))
        self.assertEqual(pin((ARGS.maintained_root/'scripts/ci/build-tools-v2-native-source/prepare.py').read_bytes()),self.profile['base_factory'])
    def test_old_variant_defaults_and_strict_runtime_held(self):
        base=ARGS.maintained_root/'scripts/ci/build-tools-v2-native-source'
        self.assertEqual(pin((base/'overlay/native/build_tools_alpm_v2.py').read_bytes())['sha256'],OLD_ALPM)
        self.assertEqual(pin((base/'overlay/native/build_tools_reader_v2.py').read_bytes())['sha256'],'090a08ccd2848908baa4f760b4eb1efdd95786fcc4d2aa1aa43c8b5eeeed21a6')
        core=(ARGS.maintained_root/'scripts/workflows/developer_workflow.py').read_text()
        self.assertIn("result['group_census'] == 'EMPTY_TWICE'",core)
    def test_new_constructor_never_imports_source(self):
        node=function((HERE/'prepare.py').read_bytes(),'construct');text=ast.dump(node)
        self.assertNotIn('subprocess',text);self.assertNotIn('import_module',text)
        self.assertIn("value='snapshot'",text);self.assertIn("value='publish'",text)
        self.assertLess(text.index("value='snapshot'"),text.index("value='publish'"))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--maintained-root',type=Path,required=True);ARGS=p.parse_args()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LayoutData))
    if EVENTS or not result.wasSuccessful() or result.testsRun!=19 or result.skipped:raise SystemExit(1)

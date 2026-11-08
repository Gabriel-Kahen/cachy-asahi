#!/usr/bin/env python3
"""Portable PID1 launcher DATA/AST controls. No Bash, actor, reader or module import."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import shlex
import sys
from types import SimpleNamespace
import unittest

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
PRIMARY=HERE/'payload/native/desktop_alpm_v1.py'
CANDIDATE=PRIMARY if PRIMARY.is_file() else HERE/'candidate/native/desktop_alpm_v1.py'
BASE_SHA='8651601d55ea799c57010c4a61fe8cdd40783175b38eac41d4d56855a488888e'
BASE_DOCKERFILE_SOURCE="def dockerfile(base,map_hash,*,owned_retirement_v2=False):\n need(type(owned_retirement_v2)is bool,'explicit boolean owned-retirement-v2 selection')\n need(re.fullmatch('[0-9a-f]{64}',map_hash or ''),'explicit source-map checksum')\n ending='USER alarm\\nWORKDIR /tmp\\n'\n need(base.endswith(ending) and base.count(ending)==1,'exact genuine191 image suffix; no fallback')\n if owned_retirement_v2:\n  return base[:-len(ending)]+('COPY desktop-alpm-v1/source/ /opt/native-desktop-tools-alpm-v1/source/\\nRUN /usr/bin/python3 -I -B /opt/native-desktop-tools-alpm-v1/source/native/desktop_alpm_v1.py --inside-image --retain-failure-image --owned-retirement-v2 --map-sha256 '+map_hash+'\\n'+ending)\n return base[:-len(ending)]+('COPY desktop-alpm-v1/source/ /opt/native-desktop-tools-alpm-v1/source/\\nRUN /usr/bin/python3 -I -B /opt/native-desktop-tools-alpm-v1/source/native/desktop_alpm_v1.py --inside-image --retain-failure-image --map-sha256 '+map_hash+'\\n'+ending)\n"
PID1_GUARD_SOURCE=" if owned_retirement_v2:need(os.getpid()>1 and os.getppid()==1,'owned-v2 Python must be the direct non-PID1 child of the fresh PID1 shell')\n"
PID1_REPORT_SOURCE=" if owned_retirement_v2:report['process_layout']=dict(schema=1,contract='bash-pid1-direct-python-child-v1',python_pid=os.getpid(),python_ppid=os.getppid(),status='OBSERVED_NON_PID1_PYTHON_DIRECT_CHILD')\n"
MAP='a'*64
ENDING='USER alarm\nWORKDIR /tmp\n'
BASE_IMAGE='FROM SYNTHETIC\n'+ENDING
CAPABILITIES=[]


def audit(event,args):
    forbidden=event.startswith(('subprocess.','socket.','ctypes.')) or event in {
        'os.system','os.fork','os.forkpty','os.exec','os.posix_spawn','os.kill','os.killpg','os.wait','os.waitpid'}
    if forbidden:CAPABILITIES.append(event);raise AssertionError('PID1 DATA controls forbid '+event)
sys.addaudithook(audit)


def need(value,message):
    if not value:raise ValueError(message)


def function(tree,name):
    rows=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name]
    need(len(rows)==1,'one inspected function required');return rows[0]


def isolated(node,namespace):
    module=ast.fix_missing_locations(ast.Module(body=[copy.deepcopy(node)],type_ignores=[]))
    exec(compile(module,'<isolated-PID1-DATA-function>','exec'),namespace)
    return namespace[node.name]


def dump(node):return ast.dump(node,include_attributes=False)


def script(map_hash):
    return ('test "$$" -eq 1 || exit 125; '
            '/usr/bin/python3 -I -B /opt/native-desktop-tools-alpm-v1/source/native/desktop_alpm_v1.py '
            '--inside-image --retain-failure-image --owned-retirement-v2 --map-sha256 '+map_hash+
            ' & desktop_owner=$!; desktop_status=0; wait "$desktop_owner" || desktop_status=$?; exit "$desktop_status"')


def reconstructed_baseline(raw):
    """Reverse exactly three line spans, then authenticate the complete old body."""
    lines=raw.decode('utf-8').splitlines(keepends=True);tree=ast.parse(raw)
    docker=function(tree,'dockerfile');inside=function(tree,'inside')
    segment=lambda node:''.join(lines[node.lineno-1:node.end_lineno])
    need(len(inside.body)>1 and isinstance(inside.body[1],ast.If)
         and segment(inside.body[1])==PID1_GUARD_SOURCE,'exact early PID1 guard block required')
    guard=inside.body[1]
    layouts=[node for node in inside.body if isinstance(node,ast.If)and segment(node)==PID1_REPORT_SOURCE]
    need(len(layouts)==1,'one exact v2 process-layout report block required');layout=layouts[0]
    edits=[(docker.lineno-1,docker.end_lineno,BASE_DOCKERFILE_SOURCE.splitlines(keepends=True)),
           (guard.lineno-1,guard.end_lineno,[]),(layout.lineno-1,layout.end_lineno,[])]
    spans=sorted((start,end)for start,end,_ in edits)
    need(all(a_end<=b_start for (_,a_end),(b_start,_)in zip(spans,spans[1:])),'reversible source spans must not overlap')
    for start,end,replacement in sorted(edits,reverse=True):lines[start:end]=replacement
    baseline=''.join(lines).encode('utf-8')
    need(hashlib.sha256(baseline).hexdigest()==BASE_SHA,'whole reconstructed ALPM865 baseline differs')
    return baseline


class PID1LayoutData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.candidate_raw=CANDIDATE.read_bytes();cls.baseline_raw=reconstructed_baseline(cls.candidate_raw)
        cls.baseline=ast.parse(cls.baseline_raw);cls.candidate=ast.parse(cls.candidate_raw)
    def tearDown(self):self.assertEqual(CAPABILITIES,[])
    def formatter(self,baseline=False):
        return isolated(function(self.baseline if baseline else self.candidate,'dockerfile'),dict(need=need,re=re,json=json))
    def guard(self,pid,ppid):
        events=[]
        def getpid():events.append('getpid');return pid
        def getppid():events.append('getppid');return ppid
        def path(value):events.append('Path');return value
        node=copy.deepcopy(function(self.candidate,'inside'));node.name='guard'
        self.assertEqual(len(node.body[:3]),3)
        node.body=node.body[:3]+[ast.Return(value=ast.Name(id='source',ctx=ast.Load()))]
        fn=isolated(node,dict(need=need,os=SimpleNamespace(getpid=getpid,getppid=getppid),Path=path))
        return fn,events
    def layout(self,pid,ppid):
        inside=function(self.candidate,'inside')
        branch=next(n for n in inside.body if isinstance(n,ast.If) and any(isinstance(x,ast.Constant) and x.value=='process_layout' for x in ast.walk(n)))
        node=ast.parse('def layout(owned_retirement_v2, report):\n pass\n').body[0]
        node.body=[copy.deepcopy(branch),ast.Return(value=ast.Name(id='report',ctx=ast.Load()))]
        events=[]
        def getpid():events.append('getpid');return pid
        def getppid():events.append('getppid');return ppid
        return isolated(node,dict(os=SimpleNamespace(getpid=getpid,getppid=getppid))),events
    def test_baseline_is_exact_reviewed_alpm_body(self):
        self.assertEqual(hashlib.sha256(self.baseline_raw).hexdigest(),BASE_SHA)
        for before,after in ((b'os.getpid()>1',b'os.getpid()>=1'),
                             (b"contract='bash-pid1-direct-python-child-v1'",b"contract='SYNTHETIC_TAMPER'"),
                             (b'timeout=180,total=450',b'timeout=181,total=450')):
            self.assertEqual(self.candidate_raw.count(before),1)
            with self.subTest(before=before),self.assertRaises(ValueError):
                reconstructed_baseline(self.candidate_raw.replace(before,after,1))
    def test_legacy_formatter_is_byte_identical_for_omitted_and_false(self):
        old,new=self.formatter(True),self.formatter()
        for value in ('0'*64,'0123456789abcdef'*4,'f'*64):
            expected=old(BASE_IMAGE,value)
            self.assertEqual(new(BASE_IMAGE,value),expected)
            self.assertEqual(new(BASE_IMAGE,value,owned_retirement_v2=False),expected)
            self.assertNotIn('/usr/bin/bash',expected)
            self.assertNotIn('--owned-retirement-v2',expected)
    def test_only_v2_uses_exact_json_exec_shell_and_python_arguments(self):
        result=self.formatter()(BASE_IMAGE,MAP,owned_retirement_v2=True)
        lines=result.splitlines();run=[x for x in lines if x.startswith('RUN ')]
        self.assertEqual(len(run),1)
        argv=json.loads(run[0][4:])
        self.assertEqual(argv,['/usr/bin/bash','--noprofile','--norc','-p','-c',script(MAP)])
        self.assertEqual(result,'FROM SYNTHETIC\nCOPY desktop-alpm-v1/source/ /opt/native-desktop-tools-alpm-v1/source/\nRUN '+json.dumps(argv)+'\n'+ENDING)
        self.assertEqual(argv[-1].count('/usr/bin/python3'),1)
        self.assertNotIn('exec /usr/bin/python3',argv[-1])
    def test_closed_shell_grammar_and_wait_status_model(self):
        result=self.formatter()(BASE_IMAGE,MAP,owned_retirement_v2=True)
        text=json.loads(next(x[4:] for x in result.splitlines() if x.startswith('RUN ')))[-1]
        lexer=shlex.shlex(text,posix=True,punctuation_chars=';&|');lexer.whitespace_split=True
        tokens=list(lexer)
        expected=['test','$$','-eq','1','||','exit','125',';',
                  '/usr/bin/python3','-I','-B','/opt/native-desktop-tools-alpm-v1/source/native/desktop_alpm_v1.py',
                  '--inside-image','--retain-failure-image','--owned-retirement-v2','--map-sha256',MAP,'&',
                  'desktop_owner=$!',';','desktop_status=0',';','wait','$desktop_owner','||','desktop_status=$?',';','exit','$desktop_status']
        self.assertEqual(tokens,expected)
        # Pure DATA model of the exact guard/wait/exit grammar above; no shell execution.
        for shell_pid in (0,1,2,99):
            for wait_status in (0,1,2,125,126,127,130,137,143,255):
                launched=shell_pid==int(tokens[3])
                final=int(tokens[6]) if not launched else (wait_status if wait_status else 0)
                self.assertEqual(final,wait_status if shell_pid==1 else 125)
                self.assertEqual(launched,shell_pid==1)
    def test_map_hash_cannot_inject_shell_or_json(self):
        formatter=self.formatter()
        for value in (None,'',True,'a'*63,'a'*65,'A'*64,'a'*64+'\n','a'*64+';exit 0','";echo X','$(touch x)','a'*63+' '):
            for selected in (False,True):
                with self.subTest(value=value,selected=selected),self.assertRaises((ValueError,TypeError)):
                    formatter(BASE_IMAGE,value,owned_retirement_v2=selected)
    def test_nonboolean_optin_and_bad_base_refuse_before_formatting(self):
        formatter=self.formatter()
        for selected in (None,0,1,'true',[]):
            with self.subTest(selected=selected),self.assertRaises(ValueError):formatter(BASE_IMAGE,MAP,owned_retirement_v2=selected)
        for base in ('FROM SYNTHETIC\n',BASE_IMAGE+ENDING,BASE_IMAGE+'\n',BASE_IMAGE.replace('USER alarm','USER root')):
            for selected in (False,True):
                with self.subTest(base=base,selected=selected),self.assertRaises(ValueError):formatter(base,MAP,owned_retirement_v2=selected)
    def test_v2_layout_refuses_pid1_and_wrong_parent_before_path(self):
        for pid,ppid in ((0,1),(1,1),(2,0),(2,2),(99,20)):
            fn,events=self.guard(pid,ppid)
            with self.subTest(pid=pid,ppid=ppid),self.assertRaises(ValueError):fn('SYNTHETIC',MAP,owned_retirement_v2=True)
            self.assertNotIn('Path',events)
    def test_v2_layout_admits_direct_child_before_path(self):
        for pid in (2,99,2147483647):
            fn,events=self.guard(pid,1)
            self.assertEqual(fn('SYNTHETIC',MAP,owned_retirement_v2=True),'SYNTHETIC')
            self.assertEqual(events,['getpid','getppid','Path'])
    def test_default_does_not_add_pid_queries_and_bad_bool_refuses_first(self):
        fn,events=self.guard(1,99);self.assertEqual(fn('SYNTHETIC',MAP),'SYNTHETIC');self.assertEqual(events,['Path'])
        fn,events=self.guard(1,99);self.assertEqual(fn('SYNTHETIC',MAP,owned_retirement_v2=False),'SYNTHETIC');self.assertEqual(events,['Path'])
        for value in (None,0,1,'true'):
            fn,events=self.guard(2,1)
            with self.assertRaises(ValueError):fn('SYNTHETIC',MAP,owned_retirement_v2=value)
            self.assertEqual(events,[])
    def test_report_layout_is_exact_and_v2_only(self):
        fn,events=self.layout(77,1);report={'HELD':'SYNTHETIC'}
        self.assertIs(fn(False,report),report);self.assertEqual(report,{'HELD':'SYNTHETIC'});self.assertEqual(events,[])
        self.assertIs(fn(True,report),report)
        self.assertEqual(report['process_layout'],dict(schema=1,contract='bash-pid1-direct-python-child-v1',python_pid=77,python_ppid=1,status='OBSERVED_NON_PID1_PYTHON_DIRECT_CHILD'))
        self.assertEqual(events,['getpid','getppid'])
    def test_inside_body_is_held_except_early_guard_and_layout_projection(self):
        old=function(self.baseline,'inside');new=copy.deepcopy(function(self.candidate,'inside'))
        self.assertIsInstance(new.body[1],ast.If)
        self.assertEqual(ast.unparse(new.body[1].test),'owned_retirement_v2')
        self.assertIn('os.getpid() > 1 and os.getppid() == 1',ast.unparse(new.body[1]))
        del new.body[1]
        layout=next(n for n in new.body if isinstance(n,ast.If) and any(isinstance(x,ast.Constant) and x.value=='process_layout'for x in ast.walk(n)))
        report_index=next(i for i,n in enumerate(new.body)if isinstance(n,ast.Assign)and any(isinstance(x,ast.Name)and x.id=='report'for x in n.targets))
        self.assertEqual(new.body.index(layout),report_index+1);new.body.remove(layout)
        self.assertEqual(dump(new),dump(old))
    def test_all_other_functions_and_formatter_default_branch_are_held(self):
        old_nodes=[n for n in self.baseline.body if not isinstance(n,ast.FunctionDef) or n.name not in ('inside','dockerfile')]
        new_nodes=[n for n in self.candidate.body if not isinstance(n,ast.FunctionDef) or n.name not in ('inside','dockerfile')]
        self.assertEqual([dump(n)for n in new_nodes],[dump(n)for n in old_nodes])
        for old,new in zip(old_nodes,new_nodes):
            self.assertEqual(ast.get_source_segment(self.baseline_raw.decode(),old),ast.get_source_segment(self.candidate_raw.decode(),new))
        old=function(self.baseline,'dockerfile');new=copy.deepcopy(function(self.candidate,'dockerfile'))
        branch=next(n for n in new.body if isinstance(n,ast.If));old_branch=next(n for n in old.body if isinstance(n,ast.If))
        new.body[new.body.index(branch)]=copy.deepcopy(old_branch)
        self.assertEqual(dump(new),dump(old))


if __name__=='__main__':unittest.main(verbosity=2)

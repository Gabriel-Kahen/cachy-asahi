# SPDX-License-Identifier: MIT
"""Inert models plus real temporary-filesystem controls. Never run APT."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
SPEC=importlib.util.spec_from_file_location('MODEL_host_prerequisites',HERE/'payload/native/host_prerequisites_current_v3.py')
P=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(P)
ENV=dict(GITHUB_ACTIONS='true',RUNNER_OS='Linux',RUNNER_ARCH='ARM64',GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',
 GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID='123456',GITHUB_SHA='a'*40,
 GITHUB_REF='refs/heads/codex/current-MODEL',GITHUB_JOB='backend')
RELEASE=b'ID=ubuntu\nVERSION_ID="24.04"\n'


class Controls(unittest.TestCase):
 def test_no_action_on_import(self):
  with patch.object(P.subprocess,'Popen',side_effect=AssertionError('actor forbidden')),patch.object(P.os,'system',side_effect=AssertionError('shell forbidden')):
   P.module(Path(P.__file__).read_bytes(),'MODEL_inert',P.__file__)
 def test_actual_current_identity_and_no_secret_retention(self):
  env=dict(ENV,GH_TOKEN='NEVER_RETAIN',ImageOS='informational-only')
  facts=P.current_context(env,'aarch64',RELEASE,0,ENV)
  self.assertNotIn('NEVER_RETAIN',json.dumps(facts)); self.assertEqual(facts['environment'],ENV)
  self.assertIsNone(facts['Root_acceptance'])
 def test_identity_refusals_are_durable_before_action(self):
  for key in ENV:
   env=dict(ENV); env[key]='WRONG'; records=[]
   with self.subTest(key=key),self.assertRaises(ValueError): P.current_context(env,'aarch64',RELEASE,0,ENV,records.append)
   self.assertEqual(len(records),1); self.assertTrue(records[0]['reason_codes'])
 def test_platform_and_release_refusals(self):
  for machine,raw,uid in [('x86_64',RELEASE,0),('aarch64',RELEASE,1000),('aarch64',b'ID=ubuntu\nVERSION_ID=22.04\n',0),('aarch64',RELEASE+b'ID=ubuntu\n',0)]:
   with self.subTest(raw=raw,machine=machine,uid=uid),self.assertRaises(ValueError): P.current_context(ENV,machine,raw,uid,ENV)
 def test_exact_descriptor_and_tamper(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp); path=root/'tiny.py'; path.write_bytes(b'MODEL=True\n'); row=dict(member='tiny.py',**P.pin(path.read_bytes()))
   self.assertEqual(P.body(root,row),b'MODEL=True\n')
   for bad in [dict(row,member='../tiny.py'),dict(row,member='tiny.py/.'),dict(row,extra=True),dict(row,bytes=True),dict(row,sha256='0'*64)]:
    with self.subTest(bad=bad),self.assertRaises((ValueError,FileNotFoundError)): P.body(root,bad)
   path.write_bytes(b'MODEL=False\n')
   with self.assertRaises(ValueError):P.body(root,row)
 def test_links_and_foreign_output_preserved(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp); a=root/'public'; a.write_bytes(b'inert'); b=root/'alias';b.symlink_to(a)
   with self.assertRaises(ValueError):P.read(b)
   b.unlink();os.link(a,b)
   with self.assertRaises(ValueError):P.read(a)
   owner=SimpleNamespace(out=root,Q=SimpleNamespace(cleanup=lambda *a:True,DECLARATION={}))
   before={p.name:p.read_bytes() for p in root.iterdir()}
   with self.assertRaises(ValueError):P.finish(owner,time.monotonic()+10)
   self.assertEqual({p.name:p.read_bytes() for p in root.iterdir()},before)
 def test_scope_uses_actual_exact_kernel_values_and_time(self):
  nonce='a'*64; group='/system.slice/cachy-current-prerequisites-'+nonce+'.scope'
  domain=dict(pid=os.getpid(),starttime=1,cgroup=group,limits=P.SCOPE.copy())
  raw=('RuntimeMaxUSec=495000000\nActiveEnterTimestampMonotonic='+str(int(time.monotonic()*1000000))+'\nControlGroup='+group+'\n').encode()
  E=SimpleNamespace(runtime_microseconds=int)
  self.assertEqual(P.scope_observation(E,domain,raw,nonce)[0]['domain'],domain)
  for bad in [dict(domain,cgroup='/'),dict(domain,limits=dict(P.SCOPE,**{'memory.max':'max'})),dict(domain,pid=os.getpid()+1)]:
   with self.assertRaises(ValueError):P.scope_observation(E,bad,raw,nonce)
  for bad in [raw.replace(b'495000000',b'7560000000'),raw+b'ControlGroup=/\n',raw.replace(b'495000000',b'0')]:
   with self.assertRaises(ValueError):P.scope_observation(E,domain,bad,nonce)
 def test_tool_bridge_has_complete_current_set_and_correct_checker(self):
  calls=[]; E=SimpleNamespace(probe_tools=lambda:dict(tools={str(i):i for i in range(16)}),checked_tool=lambda r:calls.append('current'))
  H=SimpleNamespace(checked=lambda r:calls.append('apt'),inspect=lambda p:p)
  T=P.Tools(E,H);self.assertEqual(len(T.probe_all()['tools']),16)
  T.checked(dict(candidate='/usr/bin/apt-get'));T.checked(dict(candidate='/usr/bin/python3'))
  self.assertEqual(calls,['apt','current'])
 def test_external_pin_refuses_before_any_program_or_privilege(self):
  with patch.object(P,'selected',side_effect=AssertionError('no Source execution before external pin')):
   with self.assertRaises(ValueError):P.prepare_host_prerequisites(source_root=Path('/MODEL'),delegation_raw=b'{}',delegation_sha256='0'*64,context={},environment={},output=Path('/MODEL'))
 def test_unissued_capability_refuses_before_executor_or_privilege(self):
  raw=b'{"MODEL":true}';root=Path('/MODEL');binding=dict(source='a'*40,ref='refs/heads/codex/MODEL')
  d=dict(binding=binding,expires_epoch=int(time.time())+600,capability=dict(allow_host_prerequisites=False))
  calls=[];C=SimpleNamespace(validate_delegation=lambda *a:d,source=lambda *a:calls.append('closed_source'),validate_context=lambda *a:calls.append('actual_context'))
  with patch.object(P,'selected',return_value=C) as selected,patch.object(P.os,'getuid',side_effect=AssertionError('privilege entry forbidden')):
   with self.assertRaisesRegex(ValueError,'conditional host-prerequisite'):
    P.prepare_host_prerequisites(source_root=root,delegation_raw=raw,delegation_sha256=P.pin(raw)['sha256'],context=dict(source_root=str(root),binding=binding),environment={},output=root)
  self.assertEqual(calls,['closed_source','actual_context']);self.assertEqual(selected.call_count,1)
 def test_owned_cleanup_retains_only_selected_public_receipt(self):
  with tempfile.TemporaryDirectory() as tmp:
   out=Path(tmp);(out/'prerequisite.json').write_bytes(b'{"Root_acceptance":null}');(out/'command-001.bin').write_bytes(b'DO_NOT_RETAIN_RAW');(out/'command-001.json').write_bytes(b'{}')
   owner=SimpleNamespace(out=out,Q=SimpleNamespace(cleanup=lambda *a:True,DECLARATION={}))
   P.finish(owner,time.monotonic()+10)
   self.assertEqual([p.name for p in out.iterdir()],['prerequisite.json'])
 def test_unknown_or_duplicate_json_refused(self):
  with self.assertRaises(ValueError):P.decode(b'{"x":1,"x":2}')
  with self.assertRaises(ValueError):P.decode(b'{"x":NaN}')
 def test_fresh_custody_before_each_runner(self):
  calls=[];O=SimpleNamespace(prepare=lambda:calls.append('prepare'))
  owner=P.Owner(SimpleNamespace(DECLARATION={}),None,O,None,0,lambda *a:calls.append('run'))
  owner.run_prerequisite();owner.run_prerequisite();self.assertEqual(calls,['prepare','run']*2)
  owner.commands=[None]*10
  with self.assertRaises(ValueError):owner.run_prerequisite()


# Explicit fixture consists solely of the three pinned public code blobs. No Git,
# historical checkout, network, large package body or private cache is needed.
FIXTURE=os.environ.get('CACHY_HOST_PREREQUISITE_FIXTURE')
if FIXTURE:
 class AuditedDonorControls(unittest.TestCase):
  def setUp(self):
   root=Path(FIXTURE).resolve();self.raw={}
   for role,name in [('host_prerequisite_plan','host_prerequisites.py'),('host_prerequisite_tools','host_tools.py'),('host_prerequisite_runner_basis','hosted_owner.py')]:
    raw=P.read(root/name);size,digest=P.DONORS[role];self.assertEqual(P.pin(raw),dict(bytes=size,sha256=digest));self.raw[role]=raw
   self.Q=P.module(self.raw['host_prerequisite_plan'],'MODEL_audited_plan',root/'host_prerequisites.py')
   self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
   for name,data in [('etc/os-release',RELEASE),('etc/apt/sources.list.d/ubuntu.sources',b'Types: deb\nURIs: https://archive.ubuntu.com/ubuntu\nSuites: noble\nComponents: main\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n'),('usr/share/keyrings/ubuntu-archive-keyring.gpg',b'PUBLIC MODEL KEYRING'),('etc/apt/auth.conf',b'PRIVATE_SENTINEL_NEVER_READ')]:
    path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data);path.chmod(0o644)
  def test_public_keyring_and_private_auth_preservation(self):
   before={str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
   snapshot=self.Q.trust_snapshot(self.root,os.getuid())
   self.assertIn('usr/share/keyrings/ubuntu-archive-keyring.gpg',snapshot);self.assertNotIn('etc/apt/auth.conf',snapshot)
   self.assertEqual(before,{str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
   original=self.Q.public_file
   def public(path,*args):
    self.assertNotIn('auth.conf',str(path));return original(path,*args)
   with patch.object(self.Q,'public_file',side_effect=public):self.Q.trust_snapshot(self.root,os.getuid())
  def test_insecure_or_mutated_trust_is_refused(self):
   path=self.root/'etc/apt/sources.list.d/ubuntu.sources';path.write_bytes(path.read_bytes()+b'Trusted: yes\n')
   with self.assertRaises(ValueError):self.Q.trust_snapshot(self.root,os.getuid())
  def test_candidate_and_installed_exact_join(self):
   self.assertEqual(self.Q.candidate(b'  Candidate: 3.7.2-2ubuntu0.4\n'),'3.7.2-2ubuntu0.4')
   for raw in [b'Candidate: (none)\n',b'Candidate: 1\nCandidate: 2\n',b'Candidate: 1;evil\n']:
    with self.assertRaises(ValueError):self.Q.candidate(raw)
   self.Q.installed(b'libarchive-tools\tinstall ok installed\t1\tarm64\n','1')
   with self.assertRaises(ValueError):self.Q.installed(b'libarchive-tools\tinstall ok installed\t2\tarm64\n','1')
  def model_plan(self,mutation=False):
   Q=self.Q;out=self.root/'output';out.mkdir();installed=[False];records=[];calls=[]
   names=('systemd-run','systemctl','dockerd','docker','fallocate','losetup','mkfs.ext4','mount','umount','python3','gpg','bsdtar','zstd','env','gpgconf','gpg-connect-agent')
   def row(name):return dict(path='/usr/bin/'+name,candidate='/usr/bin/'+name,bytes=1,sha256='a'*64)
   def probe():return dict(tools={n:dict(selected=row(n) if n!='bsdtar' or installed[0] else None) for n in names},missing_or_invalid=[] if installed[0] else ['bsdtar'])
   H=SimpleNamespace(probe_all=probe,inspect=lambda path:row(Path(path).name))
   owner=SimpleNamespace(policy={'host_prerequisites':Q.DECLARATION},end=time.monotonic()+450,out=out,H=H,record_prerequisite=lambda r:records.append(copy.deepcopy(r)))
   owner.tool=lambda name:owner.tools[name]['path']
   def run(argv,seconds,check,end,cache,limits):
    calls.append(argv);self.assertLessEqual(seconds,120);self.assertEqual(limits,Q.DECLARATION)
    if argv[0].endswith('/apt-get'):
     for flag in Q.APT_FIXED:self.assertIn(flag,argv)
    if '--download-only' in argv or '--no-download' in argv:self.assertEqual(records[-1]['selected_version'],'1.2.3')
    if '--no-download' in argv:
     installed[0]=True
     if mutation:(self.root/'usr/share/keyrings/ubuntu-archive-keyring.gpg').write_bytes(b'MUTATED')
    if argv[0].endswith('/dpkg'):return 0,b'arm64\n'
    if argv[0].endswith('/apt-cache'):return 0,b' Candidate: 1.2.3\n'
    if argv[0].endswith('/dpkg-query'):return (0,b'libarchive-tools\tinstall ok installed\t1.2.3\tarm64\n') if installed[0] else (1,b'')
    if argv[0].endswith('/bsdtar'):return 0,b'bsdtar 3.7.2\n'
    return 0,b''
   owner.run_prerequisite=run
   guard=lambda env,machine,release,uid,record=None:P.current_context(env,machine,release,0,ENV,record)
   plan=P.FunctionType(Q.prepare.__code__,dict(Q.__dict__,context=guard),Q.prepare.__name__,Q.prepare.__defaults__)
   try:return plan(owner,ENV,'aarch64',self.root,os.getuid()),calls
   finally:Q.cleanup(out,time.monotonic()+10,Q.DECLARATION)
  def test_exact_nine_signed_commands_and_fresh16_observations(self):
   report,calls=self.model_plan();self.assertEqual(len(calls),9);self.assertEqual(len(report['tools_after']['tools']),16)
   installs=[c for c in calls if 'install' in c];self.assertEqual(len(installs),3)
   self.assertTrue(all('libarchive-tools=1.2.3' in c and '--no-remove' in c for c in installs))
   self.assertTrue(report['cache_absent']);self.assertIsNone(report['Root_acceptance'])
  def test_real_trust_mutation_aborts_before_next_command(self):
   with self.assertRaisesRegex(ValueError,'unchanged'):self.model_plan(mutation=True)
  def test_cache_cleanup_preserves_foreign_files_and_rejects_alias(self):
   out=self.root/'own';out.mkdir();foreign=self.root/'foreign';foreign.write_bytes(b'UNCHANGED')
   cache=out/self.Q.CACHE;cache.mkdir();(cache/'inert').write_bytes(b'MODEL')
   self.Q.cleanup(out,time.monotonic()+10,self.Q.DECLARATION);self.assertEqual(foreign.read_bytes(),b'UNCHANGED')
   cache.symlink_to(self.root)
   with self.assertRaises(ValueError):self.Q.cleanup(out,time.monotonic()+10,self.Q.DECLARATION)
   self.assertTrue(foreign.exists())
  def test_audited_runner_natural_retirement_and_forced_refusal(self):
   Q=self.Q;out=self.root/'logs';out.mkdir();cache=out/Q.CACHE;cache.mkdir()
   H=SimpleNamespace(checked=lambda row:row['path'])
   runner=P.runner_from(self.raw['host_prerequisite_runner_basis'],Q,H)
   good=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,exit=0,passed=True)
   owner=SimpleNamespace(tools={'apt-get':dict(path='/usr/bin/apt-get')},commands=[],out=out,end=time.monotonic()+60,O=SimpleNamespace(supervise=lambda *a,**kw:dict(good)))
   def spawn(argv,**kw):
    self.assertEqual(kw['env'],dict(PATH='/usr/bin:/bin',HOME=str(out),LC_ALL='C',DEBIAN_FRONTEND='noninteractive'))
    with patch.object(P.resource,'setrlimit') as limits:kw['preexec_fn']();self.assertEqual(limits.call_count,4)
    return SimpleNamespace(pid=123)
   with patch.object(P.subprocess,'Popen',side_effect=spawn),patch.object(P.os,'waitid',return_value=object()):
    self.assertEqual(runner(owner,['/usr/bin/apt-get','MODEL'],15,True,owner.end,cache,Q.DECLARATION),(0,b''))
    good['signals']=[15]
    with self.assertRaisesRegex(ValueError,'natural complete'):runner(owner,['/usr/bin/apt-get','MODEL'],15,True,owner.end,cache,Q.DECLARATION)


if __name__=='__main__':unittest.main()

# SPDX-License-Identifier: MIT
"""FENCED Ubuntu/APT protocol DATA; no host setup, network, privilege or actor."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def module(name):
 s=importlib.util.spec_from_file_location('CI_prerequisite_DATA_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
Q,H,O,D,R=map(module,('host_prerequisites','host_tools','hosted_owner','data','retain'))
ENV=dict(GITHUB_ACTIONS='true',RUNNER_OS='Linux',RUNNER_ARCH='ARM64',ImageOS='ubuntu24',GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',GITHUB_EVENT_NAME='workflow_dispatch')
VERSION='3.7.2-2ubuntu0.4'
POLICY=json.loads((HERE/'policy.json').read_bytes())
REAL_CONTEXT=Q.context

def forbidden(*args,**kwargs):raise AssertionError('FENCED: no actual apt/network/privilege/domain/lease')
def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.fork','os.exec','os.posix_spawn','fcntl.flock','resource.setrlimit'):forbidden(event)
sys.addaudithook(fence)

class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='FENCED-Ubuntu24-libarchive-');self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name)
  self.root=self.base/'ROOT-DATA';self.root.mkdir(mode=0o700);self.out=self.base/'OUT-DATA';self.out.mkdir(mode=0o700)
  for name,raw in(('etc/os-release',b'ID=ubuntu\nVERSION_ID="24.04"\n'),('etc/apt/sources.list.d/ubuntu.sources',b'Types: deb\nURIs: http://ports.ubuntu.com/ubuntu-ports\nSuites: noble noble-updates noble-security\nComponents: main\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n'),('usr/share/keyrings/ubuntu-archive-keyring.gpg',b'FENCED PUBLIC KEY DATA')):
   path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o644)
  (self.root/'usr/bin').mkdir(parents=True,exist_ok=True);(self.root/'usr/sbin').mkdir()
  for name in(*H.NAMES,*Q.CI_TOOLS):
   if name!='bsdtar':self.binary(name)
  self.commands=[];self.records=[];self.installed=False;self.behavior={};self.probes=[]
  observer=lambda c:H.inspect(c,root=self.root,trusted_uid=os.getuid())
  def probe():self.probes.append(len(self.commands));return H.probe_all(observer)
  owner=SimpleNamespace(policy=copy.deepcopy(POLICY),end=time.monotonic()+1650,out=self.out,H=SimpleNamespace(probe_all=probe,inspect=observer),tools={},prerequisite={})
  def tool(name):
   row=owner.tools[name];current=observer(row['candidate']);Q.need(row==current,'fresh exact executable observations before use');return current['path']
  owner.tool=tool;owner.record_prerequisite=lambda value:self.records.append(copy.deepcopy(value))
  def run(argv,seconds,check,end,cache,limits):
   self.commands.append((argv,seconds,check));name=Path(argv[0]).name
   if name=='dpkg':return 0,b'arm64\n'
   if name=='dpkg-query':
    if not self.installed:return 1,b'dpkg-query: no packages found matching libarchive-tools\n'
    return 0,('libarchive-tools\tinstall ok installed\t'+self.behavior.get('installed_version',VERSION)+'\tarm64\n').encode()
   if name=='apt-cache':return 0,self.behavior.get('candidate',('libarchive-tools:\n  Installed: (none)\n  Candidate: '+VERSION+'\n  Version table:\n').encode())
   if name=='bsdtar':return 0,b'bsdtar 3.7.2 - libarchive 3.7.2\n'
   if 'update'in argv and self.behavior.get('trust_change'):(self.root/'etc/apt/sources.list.d/ubuntu.sources').write_bytes(b'FENCED changed repository')
   if '--download-only'in argv or '--no-download'in argv:
    self.assertTrue(self.records);self.assertEqual(self.records[0]['selected_version'],VERSION)
   if '--no-download'in argv:
    if self.behavior.get('install_failure'):raise ValueError('FENCED apt install failed')
    self.installed=True;self.binary('bsdtar')
    if self.behavior.get('other_tool_changed'):self.binary('docker',body=b'FENCED unexpected replacement')
   return 0,b'FENCED normal APT output\n'
  owner.run_prerequisite=run;self.owner=owner
 def binary(self,name,body=None):
  path=self.root/'usr/bin'/name;path.write_bytes(body or('FENCED EXECUTABLE DATA '+name).encode());path.chmod(0o755);return path
 def prepare(self):
  # Only the fixture UID seam is translated to the modeled root context. No UID
  # change or operational grant exists; every subprocess/syscall actor is fenced.
  with patch.object(Q,'context',side_effect=lambda e,m,r,u:REAL_CONTEXT(e,m,r,0)):
   return Q.prepare(self.owner,ENV,'aarch64',root=self.root,uid=os.getuid())
 def test_exact_nine_command_plan_candidate_durable_and_complete_reobservation(self):
  old=self.owner.H.inspect('/usr/bin/docker');result=self.prepare()
  self.assertEqual(result['status'],'PASS_CI_LIBARCHIVE_TOOLS_PREREQUISITE_ONLY');self.assertEqual(len(self.commands),9)
  self.assertEqual([Path(v[0][0]).name for v in self.commands],['dpkg','dpkg-query','apt-get','apt-cache','apt-get','apt-get','apt-get','dpkg-query','bsdtar'])
  for argv,cap,check in self.commands:
   self.assertGreater(cap,0);self.assertLessEqual(cap,120)
   if Path(argv[0]).name=='apt-get':
    for option in('Acquire::Retries=0','APT::Get::AllowUnauthenticated=false','Acquire::AllowInsecureRepositories=false','Acquire::Check-Valid-Until=true'):self.assertIn(option,argv)
    self.assertFalse(set(argv)&{'--allow-unauthenticated','--force-yes','--allow-downgrades','--allow-remove-essential'})
   if 'install'in argv:self.assertEqual(argv[-1],'libarchive-tools='+VERSION);self.assertIn('--no-install-recommends',argv);self.assertIn('--no-remove',argv)
  self.assertGreaterEqual(len(self.probes),3);self.assertNotEqual(old,self.owner.H.inspect('/usr/bin/docker'))
  self.assertEqual(result['tools_after']['missing_or_invalid'],[]);self.assertEqual(result['installed']['version'],VERSION)
  self.assertTrue(result['cache_absent']);self.assertFalse((self.out/Q.CACHE).exists());self.assertIsNone(result['Root_acceptance'])
 def test_candidate_missing_duplicate_or_shell_text_refuses_before_download_install(self):
  for raw in(b'Candidate: (none)\n',b'Candidate: one\nCandidate: two\n',b'Candidate: x;touch_BAD\n'):
   with self.assertRaises(ValueError):Q.candidate(raw)
  self.behavior['candidate']=b'Candidate: (none)\n'
  with self.assertRaises(ValueError):self.prepare()
  self.assertFalse(any('--download-only'in a or '--no-download'in a for a,_,_ in self.commands))
 def test_wrong_platform_or_ubuntu_or_unadmitted_declaration_refuses(self):
  for env,machine,release,uid in((dict(ENV,GITHUB_ACTIONS='false'),'aarch64',b'ID=ubuntu\nVERSION_ID=24.04',0),(ENV,'x86_64',b'ID=ubuntu\nVERSION_ID=24.04',0),(ENV,'aarch64',b'ID=arch\nVERSION_ID=24.04',0),(ENV,'aarch64',b'ID=ubuntu\nVERSION_ID=24.04',1000)):
   with self.assertRaises(ValueError):Q.context(env,machine,release,uid)
  self.owner.policy['host_prerequisites']['seconds']=451
  with self.assertRaises(ValueError):self.prepare()
  self.assertEqual(self.commands,[])
 def test_insecure_existing_source_or_repository_key_drift_refuses(self):
  source=self.root/'etc/apt/sources.list.d/ubuntu.sources';source.write_bytes(b'Trusted: yes\n')
  with self.assertRaises(ValueError):self.prepare()
  self.assertEqual(self.commands,[])
  source.write_bytes(b'Types: deb\nURIs: http://ports.ubuntu.com/ubuntu-ports\n');self.behavior['trust_change']=True
  with self.assertRaises(ValueError):self.prepare()
  self.assertFalse(self.installed)
 def test_install_failure_wrong_version_and_unrelated_tool_mutation_hold(self):
  for behavior in('install_failure','installed_version','other_tool_changed'):
   with self.subTest(behavior=behavior):
    if (self.out/Q.CACHE).exists():Q.cleanup(self.out,time.monotonic()+10,Q.DECLARATION)
    self.behavior={behavior:('WRONG'if behavior=='installed_version'else True)};self.installed=False;self.records.clear()
    with self.assertRaises(ValueError):self.prepare()
    self.assertNotEqual(self.owner.prerequisite['status'],'PASS_CI_LIBARCHIVE_TOOLS_PREREQUISITE_ONLY')
 def test_other_missing_tool_is_not_installed_by_generalized_fallback(self):
  (self.root/'usr/bin/docker').unlink()
  with self.assertRaises(ValueError):self.prepare()
  self.assertEqual(self.commands,[])
 def test_cache_byte_node_alias_deadline_bounds_and_owned_cleanup(self):
  cache=self.out/Q.CACHE;cache.mkdir();(cache/'data').write_bytes(b'x'*8192)
  with self.assertRaises(ValueError):Q.cache_census(cache,time.monotonic()+10,dict(Q.DECLARATION,cache_bytes=1))
  self.assertTrue(Q.cleanup(self.out,time.monotonic()+10,dict(Q.DECLARATION,cache_bytes=1))) # over-budget work never prevents safe owned retirement
  cache.mkdir();(cache/'alias').symlink_to('/NEVER_OPEN_PRIVATE_DATA')
  with self.assertRaises(ValueError):Q.cache_census(cache,time.monotonic()+10,Q.DECLARATION)
  (cache/'alias').unlink()
  with self.assertRaises(ValueError):Q.cache_census(cache,time.monotonic()-1,Q.DECLARATION)
  for i in range(3):(cache/str(i)).write_bytes(b'x')
  with self.assertRaises(ValueError):Q.cache_census(cache,time.monotonic()+10,dict(Q.DECLARATION,cache_nodes=2))
 def test_public_trust_snapshot_never_follows_authentication_paths(self):
  for name in('etc/apt/auth.conf','etc/apt/auth.conf.d/private'):
   path=self.root/name;path.parent.mkdir(exist_ok=True);path.symlink_to('/NEVER_OPEN_CREDENTIAL_DATA')
  self.assertFalse(any('auth.conf'in name for name in Q.trust_snapshot(self.root,os.getuid())))
 def test_retention_excludes_failed_cache_but_retains_public_prerequisite(self):
  (self.out/Q.CACHE).symlink_to('/NEVER_OPEN_PRIVATE_CACHE');(self.out/'owner-report.json').write_bytes(b'{}');(self.out/'host-prerequisite.json').write_bytes(b'{}')
  self.assertEqual(set(R.selected(self.out)),{'owner-report.json','host-prerequisite.json'})
 def test_source_workflow_budget_and_setup_order_are_explicit(self):
  source=(HERE/'hosted_owner.py').read_text();setup=source.split('    def setup(self):',1)[1].split('    def loop_identity',1)[0]
  self.assertLess(setup.index('Q.prepare('),setup.index('self.preflight()'));self.assertLess(setup.index('self.preflight()'),setup.index("image=self.out/'storage.img'"))
  self.assertEqual(POLICY['controller_work_seconds'],Q.DECLARATION['seconds']+POLICY['pair_seconds']);self.assertEqual(POLICY['controller_scope_seconds'],POLICY['controller_work_seconds']+90)
  self.assertEqual((POLICY['pair_seconds'],POLICY['cleanup_seconds']),(1200,90))
  workflow=(HERE.parents[3]/'.github/workflows/native-arm-fish-config02-source-v2.yml').read_text()
  self.assertIn('--property=RuntimeMaxSec=1740s',workflow);self.assertIn('timeout-minutes: 35',workflow);self.assertIn('GITHUB_ACTIONS,GITHUB_SHA',workflow);self.assertNotIn('sudo apt',workflow)
  runtime=json.loads((HERE/'runtime.TEMPLATE.json').read_bytes());self.assertIsNone(runtime['host_prerequisites'])
 def test_child_wrapper_natural_nonzero_forced_and_cancellation_transfer(self):
  cache=self.out/Q.CACHE;cache.mkdir();tool=dict(path='/usr/bin/apt-get')
  natural=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,exit=0,passed=True)
  for mode in('natural','nonzero','forced','cancel','overrun','output_bound'):
   owner=O.Controller.__new__(O.Controller);owner.out=self.out;owner.end=time.monotonic()+100;owner.tools={'apt-get':tool};owner.commands=[];transfers=[]
   row=copy.deepcopy(natural)
   if mode=='nonzero':row.update(exit=7,passed=False)
   if mode=='forced':row.update(signals=['SIGTERM'],passed=False)
   owner.O=SimpleNamespace(supervise=lambda child,**kwargs:(transfers.append((child,kwargs))or copy.deepcopy(row)))
   child=SimpleNamespace(pid=123456)
   def spawn(argv,**kwargs):kwargs['stdout'].write(b'x'*(Q.DECLARATION['command_output_bytes']+1)if mode=='output_bound'else b'FENCED stdout');kwargs['stderr'].write(b'FENCED stderr');return child
   original=KeyboardInterrupt('FENCED cancellation')
   for p in cache.iterdir():p.unlink()
   for p in self.out.glob('command-*'):p.unlink()
   clock=iter((100,100,100,200)) if mode=='overrun'else None
   original_clock=time.monotonic
   with patch.object(O.time,'monotonic',side_effect=lambda:next(clock)if clock else original_clock()),patch.object(O.H,'checked',return_value='/usr/bin/apt-get'),patch.object(O.subprocess,'Popen',side_effect=spawn),patch.object(O.os,'waitid',side_effect=original if mode=='cancel'else None,return_value=SimpleNamespace()):
    if mode=='natural':self.assertEqual(owner.run_prerequisite(['/usr/bin/apt-get','update'],15,True,owner.end,cache,Q.DECLARATION)[0],0)
    else:
     with self.assertRaises(KeyboardInterrupt if mode=='cancel'else TimeoutError if mode=='overrun'else ValueError):owner.run_prerequisite(['/usr/bin/apt-get','update'],15,True,owner.end,cache,Q.DECLARATION)
   self.assertEqual([v[0]for v in transfers],[child])
   if mode=='overrun':
    self.assertEqual(transfers[0][1]['cap'],.5);self.assertTrue(owner.commands[-1]['retirement']['emergency_retirement'])
   if mode=='output_bound':self.assertEqual((self.out/'command-001.bin').read_bytes(),b'')

if __name__=='__main__':unittest.main()

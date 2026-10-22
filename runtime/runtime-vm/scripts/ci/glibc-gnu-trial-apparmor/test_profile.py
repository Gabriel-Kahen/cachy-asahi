# SPDX-License-Identifier: MIT
"""Finite inert ownership/policy controls. No Docker, sudo, parser or mount executes."""
import importlib.util,json,os,re,shutil,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('owned_apparmor_controls',HERE/'profile.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
TOKEN='a'*32;IMAGE='sha256:'+'b'*64;CID='c'*64
class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.directory=self.root/'owned';self.kernel={'docker-default':'enforce'};self.calls=[];self.remaining=False;self.foreign=False;self.fail_compile=False;self.fail_add=False;self.producer_profile='docker-default'
  self.proof=dict(consumer_token=TOKEN,producer_token='d'*16,source_sha='e'*40)
  self.base=dict(image=IMAGE,ownership=dict(token='d'*16,probe_name='producer-probe',image=IMAGE,before_images=[],probe_started=True,probe_complete=True))
  self.gate=patch.object(P,'ci_gate',return_value=P.PARSER);self.gate.start();self.addCleanup(self.gate.stop)
  self.facts=patch.object(P,'host_facts',return_value=dict(daemon_profile='unconfined',macros={}));self.facts.start();self.addCleanup(self.facts.stop)
 def command(self,argv,**kw):
  self.calls.append((argv,kw));out=b''
  if argv[:5]==['/usr/bin/sudo','-n','--','/usr/bin/cat','--']:
   self.assertEqual(argv[5],str(P.REGISTRY));self.assertEqual(kw,dict(seconds=10,private_stdout=True));out=''.join(n+' ('+m+')\n' for n,m in self.kernel.items()).encode()
  elif argv[:3]==['/usr/bin/docker','container','ls']:
   out=(CID+'\n').encode() if '--filter' not in argv or self.remaining and argv[-1].startswith('label=') else b''
  elif argv[:3]==['/usr/bin/docker','image','inspect']:
   out=json.dumps([dict(Id=IMAGE,Architecture='arm64',Os='linux',Config={'Labels':{'org.cachy-asahi.bootstrap574.job':('d'*16 if self.producer_profile=='docker-default' else 'bad')}})]).encode()
  elif argv[:3]==['/usr/bin/docker','container','inspect']:
   if '--format' in argv:out=json.dumps(P.profile_name(TOKEN,'lifecycle') if self.foreign else self.producer_profile).encode()
   else:out=json.dumps([dict(Name='/producer-probe',Id=CID,Image=IMAGE,Config={'Labels':{'org.cachy-asahi.bootstrap574.job':'d'*16}},AppArmorProfile=self.producer_profile)]).encode()
  elif argv[0]==str(P.PARSER):
   self.assertEqual(argv[1:4],['--skip-kernel-load','--skip-cache','--jobs=1']);self.assertEqual(kw,dict(seconds=30))
   if self.fail_compile:raise ValueError('modeled parser compile failure')
  elif argv[:4]==['/usr/bin/sudo','-n','--',str(P.PARSER)]:
   self.assertEqual(argv[5:7],['--skip-cache','--jobs=1']);self.assertEqual(kw,dict(seconds=30));name=P.profile_name(TOKEN,'lifecycle')
   if argv[4]=='--add':
    self.assertNotIn(name,self.kernel);self.kernel[name]='enforce'
    if self.fail_add:raise ValueError('modeled command outcome uncertainty')
   else:self.assertEqual(argv[4],'--remove');del self.kernel[name]
  else:self.fail('unmodeled command '+repr(argv))
  return dict(out=out,err=b'',code=0)
 def load(self):return P.load(self.directory,self.proof,self.base,'lifecycle',self.command,CID)
 def remove(self):return P.unload(self.directory,self.proof,self.base,'lifecycle',self.command)
 def parser_mutations(self):return [a[4] for a,_ in self.calls if a[:4]==['/usr/bin/sudo','-n','--',str(P.PARSER)]]
 def test_exact_inherited_baseline_only_five_mount_rules(self):
  for lane in P.LANES:
   raw,baseline=P.render(TOKEN,lane,abi=True,global_include=True,base_include=True,daemon_profile='dockerd-profile')
   self.assertEqual(raw.replace(P.MOUNTS.encode(),b'  deny mount,\n'),baseline);self.assertEqual(raw.count(b'  mount '),5);self.assertIn(b'  umount,',raw);self.assertIn(b'deny /sys/kernel/security/** rwklx,',raw);self.assertIn(('ptrace (trace,tracedby,read,readby) peer="'+P.profile_name(TOKEN,lane)+'"').encode(),raw)
 def test_exact_proc_flags_targets_and_bind_sources(self):
  rules=[x for x in P.MOUNTS.splitlines() if x.startswith('  mount ')];self.assertEqual(len(rules),5)
  self.assertEqual([re.search(r' -> (.*),$',x)[1] for x in rules],['/work/.gnu-readonly-proc-probe/','/work/pristine/root/proc/','/work/modified/root/proc/','/work/pristine/root/dev/null','/work/modified/root/dev/null'])
  self.assertTrue(all('fstype=proc options=(ro,nosuid,nodev,noexec) proc ->' in x for x in rules[:3]));self.assertTrue(all('options=(bind) /dev/null ->' in x for x in rules[3:]));self.assertNotIn('*',P.MOUNTS)
 def test_all_macro_combinations_render_without_template_fragments(self):
  for a in (False,True):
   for g in (False,True):
    for b in (False,True):
     raw,_=P.render(TOKEN,'lifecycle',abi=a,global_include=g,base_include=b,daemon_profile='unconfined');self.assertNotIn(b'{{',raw);self.assertEqual(b'abi <abi/3.0>' in raw,a);self.assertEqual(b'#include <tunables/global>' in raw,g);self.assertEqual(b'#include <abstractions/base>' in raw,b)
 def test_name_and_daemon_pattern_injection_refused(self):
  for token,lane in (('x'*32,'lifecycle'),(TOKEN,'other'),(TOKEN+'*','lifecycle')):
   with self.assertRaises(ValueError):P.profile_name(token,lane)
  with self.assertRaises(ValueError):P.render(TOKEN,'lifecycle',abi=False,global_include=False,base_include=False,daemon_profile='peer*')
 def test_pinned_vendor_tampering_fails_before_commands(self):
  shutil.copytree(HERE/'vendor',self.root/'vendor');p=self.root/'vendor/apparmor/template.go';p.write_bytes(p.read_bytes()+b'\n')
  with patch.object(P,'HERE',self.root),self.assertRaisesRegex(ValueError,'pinned Moby'):self.load()
  self.assertFalse(self.directory.exists());self.assertFalse(self.parser_mutations())
 def test_fresh_add_then_ordered_remove_exact_owned_name(self):
  state=self.load();self.assertEqual(state['status'],'LOADED_ENFORCE');self.assertEqual(P.binding(self.directory,TOKEN,'lifecycle',IMAGE),state);removed=self.remove();self.assertEqual(removed['status'],'PASS_OWNED_PROFILE_REMOVED_AFTER_ALL_CONSUMERS');self.assertEqual(self.kernel,{'docker-default':'enforce'});self.assertEqual(self.parser_mutations(),['--add','--remove'])
 def test_existing_profile_collision_never_adds_or_removes(self):
  self.kernel[P.profile_name(TOKEN,'lifecycle')]='enforce'
  with self.assertRaisesRegex(ValueError,'fresh profile'):self.load()
  self.assertFalse(self.directory.exists());self.assertFalse(self.parser_mutations())
 def test_non_enforcing_default_refuses_before_mutation(self):
  self.kernel['docker-default']='complain'
  with self.assertRaises(ValueError):self.load()
  self.assertFalse(self.parser_mutations())
 def test_compile_failure_has_no_load_ownership_and_cleanup_never_removes(self):
  self.fail_compile=True
  with self.assertRaises(ValueError):self.load()
  self.assertEqual(self.remove()['status'],'PASS_NEVER_ADDED_PROFILE_ABSENT');self.assertFalse(self.parser_mutations())
 def test_uncertain_add_retains_profile_and_blocks_remove(self):
  self.fail_add=True
  with self.assertRaises(ValueError):self.load()
  with self.assertRaisesRegex(ValueError,'uncertain'):self.remove()
  self.assertEqual(self.parser_mutations(),['--add']);self.assertIn(P.profile_name(TOKEN,'lifecycle'),self.kernel)
 def test_remaining_owned_consumer_blocks_remove(self):
  self.load();self.remaining=True
  with self.assertRaisesRegex(ValueError,'owned consumers'):self.remove()
  self.assertEqual(self.parser_mutations(),['--add'])
 def test_foreign_profile_user_blocks_remove_without_deconfinement(self):
  self.load();self.foreign=True
  with self.assertRaisesRegex(ValueError,'foreign profile user'):self.remove()
  self.assertEqual(self.parser_mutations(),['--add'])
 def test_producer_default_identity_required(self):
  self.producer_profile='other'
  with self.assertRaisesRegex(ValueError,'producer exact'):self.load()
  self.assertFalse(self.parser_mutations())
 def test_profile_bytes_drift_prevents_binding_and_remove(self):
  self.load();p=self.directory/'trial.profile';p.chmod(0o600);p.write_bytes(p.read_bytes()+b'\n')
  with self.assertRaisesRegex(ValueError,'bytes changed'):P.binding(self.directory,TOKEN,'lifecycle',IMAGE)
  with self.assertRaisesRegex(ValueError,'bytes changed'):self.remove()
  self.assertEqual(self.parser_mutations(),['--add'])
 def test_source_or_image_binding_drift_cannot_remove(self):
  self.load();self.proof['source_sha']='f'*40
  with self.assertRaisesRegex(ValueError,'original source'):self.remove()
  self.assertEqual(self.parser_mutations(),['--add'])
 def test_live_profile_lease_blocks_retirement(self):
  self.load()
  with P.lease(self.directory),self.assertRaises(BlockingIOError):self.remove()
  self.assertEqual(self.parser_mutations(),['--add'])
 def test_second_cleanup_verifies_absence_without_repeat_remove(self):
  self.load();self.remove();self.remove();self.assertEqual(self.parser_mutations(),['--add','--remove'])
 def test_unregistered_name_is_never_unloaded(self):
  name=P.profile_name(TOKEN,'lifecycle');self.kernel[name]='enforce'
  with self.assertRaises(ValueError):P.unregistered_absent(TOKEN,'lifecycle',self.command)
  self.assertFalse(self.parser_mutations())
 def test_observer_refuses_general_root_reads(self):
  for path in ('/etc/shadow','/proc/self/attr/current','/proc/0/attr/current','/proc/12/../attr/current'):
   with self.assertRaises(ValueError):P.observe(self.command,Path(path))
  self.assertFalse(self.calls)
 def test_inside_exact_enforce_context_required(self):
  name=P.profile_name(TOKEN,'lifecycle')
  with patch.dict(os.environ,GNU_TRIAL_APPARMOR_PROFILE=name),patch.object(Path,'read_bytes',return_value=(name+' (enforce)\n').encode()):self.assertEqual(P.inside(TOKEN,'lifecycle')['name'],name)
  for context in ('docker-default (enforce)',name+' (complain)'):
   with patch.dict(os.environ,GNU_TRIAL_APPARMOR_PROFILE=name),patch.object(Path,'read_bytes',return_value=context.encode()),self.assertRaises(ValueError):P.inside(TOKEN,'lifecycle')
 def test_inspect_trial_custom_scrub_default_and_seccomp_unchanged(self):
  for role in ('trial','scrub'):
   name=P.profile_name(TOKEN,'lifecycle') if role=='trial' else 'docker-default';options=['no-new-privileges']+(['apparmor='+name] if role=='trial' else []);v=dict(AppArmorProfile=name,HostConfig=dict(SecurityOpt=options));self.assertEqual(P.docker_profile(v,TOKEN,'lifecycle',role)['AppArmorProfile'],name)
   v['HostConfig']['SecurityOpt'].append('seccomp=unconfined')
   with self.assertRaises(ValueError):P.docker_profile(v,TOKEN,'lifecycle',role)
 def test_ci_gate_refuses_non_ci_without_any_command(self):
  self.gate.stop()
  with patch.dict(os.environ,{'GITHUB_ACTIONS':'false'}),self.assertRaisesRegex(ValueError,'CI-only'):P.ci_gate()
  self.assertFalse(self.calls)
 def test_json_duplicate_keys_and_symlink_registration_refused(self):
  with self.assertRaises(ValueError):P.decode(b'{"x":1,"x":2}')
  self.load();alias=self.root/'alias';alias.symlink_to(self.directory,target_is_directory=True)
  with self.assertRaises(ValueError):P.binding(alias,TOKEN,'lifecycle',IMAGE)

if __name__=='__main__':unittest.main()

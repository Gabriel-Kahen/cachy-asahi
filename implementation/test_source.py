#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact archive/source/generator and genuine private ALPM607 payload controls."""
import argparse,ast,copy,importlib.util,json,os,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;sys.path.insert(0,str(HERE))
import source_guard as G,latest_common as C,latest_inputs as L,accepted_inputs,workflow_contract as W,stage_inputs,closed_data
ARGS=None

def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='latest607-source-control-',dir=ROOT.parent);self.addCleanup(self.tmp.cleanup);self.work=Path(self.tmp.name)
 def test_full_source_inverse_exacttarget_noCore_or_current_authority(self):
  q=G.verify();self.assertEqual((q['packages'],q['optional_absent'],q['parent_files']),(607,605,574));self.assertEqual((q['service_seconds'],q['prior_selected_service_seconds'],q['default_service_seconds']),(3460,1800,1200));selected=q['reserved_profile'];basis=load('_latest607_held_service1800_expectation',HERE/'factory/service_capacity.py').profile();self.assertEqual((basis['service_seconds'],basis['default_service_seconds']),(1800,1200));self.assertEqual((selected['profile'],selected['service_seconds'],selected['default_service_seconds']),('GUI_TCG_RESERVED_READBACK_3460_V1',3460,1200));reserve=selected['reservation'];self.assertEqual((reserve['pre_observer_seconds'],reserve['observer_seconds'],reserve['caller_seconds'],reserve['cleanup_seconds'],reserve['readback_tail_seconds']),(1800,1200,1210,450,1660));self.assertIs(reserve['one_shared_deadline'],True);self.assertEqual(reserve['admission'],'REFUSE_BEFORE_VERIFY_IF_SHARED_REMAINING_BELOW1660');self.assertEqual((selected['old1800_fit'],selected['current3460_fit']),('NOT_ESTABLISHED','NOT_ESTABLISHED'));self.assertIs(selected['acceptance'],False);self.assertTrue(all(selected[k]is None for k in('actual','source','ref','run')));self.assertIsNone(q['current_actual']);before=dict(x.split()for x in G.read(ROOT/'parent574/factory/expected606.lock').decode().splitlines());after=dict(x.split()for x in C.read(HERE/'expected607.lock').decode().splitlines());self.assertEqual({n:(before[n],after[n])for n in before if before[n]!=after[n]},{'cachy-asahi-setup':('0.1.0-5','0.1.0-6')});self.assertEqual(set(after)-set(before),{'cachy-asahi-boot-report'});self.assertNotIn('cachy-asahi-core',after)
  for r in G.obj(HERE/'body-inverses.json'):self.assertEqual(G.inverse(G.read(ROOT/r['after_path']),r['seams']),G.read(ROOT/r['before_path']))
  class Reached(Exception):pass
  if q['parent_context']=='known':
   with self.assertRaisesRegex(Reached,'FULL574'):G.old_prove(ROOT/'parent574',lambda _:(_ for _ in()).throw(Reached('FULL574_SOURCE_GUARD_REQUIRED')))
  else:
   self.assertEqual(q['parent_context'],'null')
   with self.assertRaisesRegex(ValueError,'NULL.*(?:actors|ACTORS)'):G.old_prove(ROOT/'parent574',lambda _:(_ for _ in()).throw(Reached('NULL_PARENT_MUST_NOT_REACH_ORIGINAL_PROVE')))
 def test_issued_record22_original991_all_eight_full_metadata_payload_and_origin(self):
  checks=load('_latest607_control_package_checks',ROOT/'parent574/original/scripts/checks/package_checks.py');fact=L.verify(ARGS.record,ARGS.public,checks);req=G.obj(ROOT/'parent574/input-policy33.json')['packages'];after=L.apply(req,fact);self.assertEqual(len(after),34);self.assertEqual(after['cachy-asahi-boot-report']['sha256'],'4400e766391b27021c6f40d29c35eb215d9fad12e4555f0d8b6637967baa6472');self.assertEqual(after['cachy-asahi-welcome']['size'],40400);self.assertEqual(after['cachy-asahi-apps']['size'],29664)
  for n in set(fact['rows'])-{'cachy-asahi-setup','cachy-asahi-boot-report'}:self.assertEqual((req[n]['version'],req[n]['size'],req[n]['sha256']),(after[n]['version'],after[n]['size'],after[n]['sha256']))
  for field,value in(('sha256','0'*64),('size',1),('version','0.1.0-7')):
   bad=copy.deepcopy(req);bad['cachy-asahi-welcome'][field]=value
   with self.assertRaises(ValueError):L.apply(bad,fact)
  original=checks.package
  def altered(path):
   r=original(path)
   if Path(path).name.startswith('cachy-asahi-setup-'):r=copy.deepcopy(r);r['metadata']['.PKGINFO']['pkgdesc']=['same version but foreign full metadata']
   return r
  with patch.object(checks,'package',side_effect=altered),self.assertRaises(ValueError):L.verify(ARGS.record,ARGS.public,checks)
 def test_actual_four_selected_generators_source1800_clocks_frames_and_complete607(self):
  saved=dict(sys.modules);paths=sys.path[:];proofs=[]
  try:
   for profile in('minimal','overlay'):
    for mode in('generic4k','generic16k'):
     f=load('_latest607_actual_factory_'+profile+mode,HERE/'factory/factory.py');selected=load('_explicit_historical_source',HERE/'historical_source.py').historical_factory(f,ROOT/'parent574/original',ARGS.assets);out=self.work/(profile+'-'+mode)
     with patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):p,ch=selected.prepare_code(ROOT/'parent574/original',ARGS.assets,out,profile,mode);r=selected.seal(out,profile,mode,p,ch,False)
     self.assertEqual((r['packages'],r['optional_absent'],r['page_size']),(607,605,16384 if mode=='generic16k'else 4096));self.assertIsNone(r['actual_run']);self.assertEqual((out/'expected606.lock').read_bytes(),(HERE/'expected607.lock').read_bytes());life=(out/'doctor_lifetime.py').read_text();self.assertIn('SERVICE_SECONDS=1800',life);self.assertEqual(life.count('TCG_VALIDATION_FIXTURE_SERVICE_1800S'),3);self.assertIn('SECONDS=1080',life);runtime=(out/'desktop574_runtime.py').read_text();self.assertIn('time.monotonic() + 1900',runtime);self.assertIn('signal.ITIMER_REAL, 2350',runtime);self.assertIn('TimeoutStartSec=1800',(out/'desktop574_fixture.sh').read_text());self.assertIn('timeout=600',(out/'base_guest.py').read_text());self.assertIn("len(baseline)==607",(out/'management_root.py').read_text());self.assertIn("len(inventory())==605",(out/'management_root.py').read_text());self.assertEqual(G.pin((out/'alpm_reader.py').read_bytes())['sha256'],'d567aea0616bf92450e25e40daa54049ecc630dc7c988d2a55e19459e1958a8f');self.assertEqual(r['service_validation_profile']['owner_wait_seconds'],2800);self.assertEqual(r['service_validation_profile']['native_owner_seconds'],6600);proofs.append(dict(profile=profile,mode=mode,files=r['files'],derivatives=r['derivatives']))
   target=ROOT.parent/('latest607-generated-controls'+str(sys.version_info.minor)+'.json')
   # Author runner may retain the complete map; CI fixtures need no extra source leaves.
   if os.environ.get('LATEST607_AUTHOR_RECEIPTS')=='1':target.write_bytes(C.enc(proofs))
  finally:
   sys.path[:]=paths
   for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
   sys.modules.update(saved)
 def test_genuine_private607_ALPM_all_owned_nodes_and_metadata_mutation_refusal(self):
  helper=load('_latest607_owned_ALPM',HERE/'factory/support/alpm_reader.py');m=load('_latest607_actual_owned_payload_observer',HERE/'factory/installed607.py');expected=dict(line.split()for line in C.read(HERE/'expected607.lock').decode().splitlines());root=self.work/'root';(root/'var/lib/pacman/local').mkdir(parents=True);(root/'payload').mkdir();(root/'var/lib/pacman/local/ALPM_DB_VERSION').write_bytes(b'9\n')
  for n,v in expected.items():
   d=root/'var/lib/pacman/local'/(n+'-'+v);d.mkdir();(d/'desc').write_text('%NAME%\n'+n+'\n\n%VERSION%\n'+v+'\n\n%ARCH%\nany\n\n');(d/'files').write_text('%FILES%\npayload/'+n+'\n\n');(root/'payload'/n).write_bytes((n+' '+v+'\n').encode())
  # The observer loads the exact original capability helper by sibling.
  shutil.copyfile(HERE/'factory/support/file_capabilities.py',self.work/'file_capabilities.py');m.__file__=str(self.work/'installed607.py')
  first=m.observe(root,helper,expected);self.assertEqual((len(first['packages']),len(first['nodes'])),(607,607));self.assertTrue(m.verify(m.observe(root,helper,expected),first));self.assertIn('cachy-asahi-boot-report',first['ownership']);self.assertEqual(first['packages']['cachy-asahi-setup'],'0.1.0-6')
  target=root/'payload/cachy-asahi-boot-report';target.write_bytes(b'changed actual Boot payload')
  with self.assertRaises(ValueError):m.verify(m.observe(root,helper,expected),first)
  wrong=dict(expected,**{'cachy-asahi-setup':'0.1.0-5'})
  with self.assertRaises(ValueError):m.observe(root,helper,wrong)
  with self.assertRaises(ValueError):m.observe(root,helper,expected,deadline=0)
 def test_actual_product607_validator_and_explicit_service_namespace(self):
  m=load('_latest607_actual_current_products',HERE/'factory/current_products.py');r=dict(status='ACTUAL_INSTALLED_APPS16_AND_KSM2_READONLY',uid=23001,page_size=4096,apps=dict(status='OBSERVED_LOCAL_DB_METADATA',package_count=607,applied='NOT_APPLIED',sha256='b'*64),apps_expected_lock=C.profile()['target']['sha256'],expected606_lock=C.profile()['target']['sha256'],apps_file_sha256='b'*64,ksm=dict(before_run='0',after_run='0',returncode=3,stdout='',stderr='cachy-asahi-ksmctl: KSM interface unavailable\n',report=None));self.assertEqual(m._original_validate(r,4096),r)
  bad=copy.deepcopy(r);bad['apps']['package_count']=606
  with self.assertRaises(ValueError):m._original_validate(bad,4096)
  f=load('_latest607_service_namespace_factory',HERE/'factory/factory.py');selected=f.service1800();self.assertIs(selected.emit.__globals__['prepare_code'],selected.prepare_code);self.assertIs(selected.emit.__globals__['seal'],selected.seal);self.assertEqual(selected.emit.__code__,f.emit.__code__)
 def test_closed_record_and_public_names_refuse_nested_Git_and_aliases(self):
  root=self.work/'data';root.mkdir();(root/'held').write_bytes(b'held');self.assertEqual(closed_data.names(root),{'held'});(root/'.git').mkdir();(root/'.git/admin').write_bytes(b'admin');self.assertEqual(closed_data.names(root,admin=True),{'held'})
  with self.assertRaises(ValueError):closed_data.names(root)
  foreign=root/'foreign';foreign.mkdir();(foreign/'.git').write_bytes(b'foreign')
  with self.assertRaises(ValueError):closed_data.names(root,admin=True)
  (foreign/'.git').unlink();(foreign/'alias').symlink_to(root/'held')
  with self.assertRaises(ValueError):closed_data.names(root,admin=True)
 def test_whole_workflow_inverse_decoded_five_controls_separate_exactly_once(self):
  raw=C.read(ROOT/'parent574/.github/workflows/native-arm-current606-welcome8-gui.yml');new,p=W.derive(raw);self.assertTrue(p['whole_inverse'])
  # Recover the entire authenticated historical context before its unchanged guard.
  B=__import__('build_inventory');BG=__import__('build_inventory_guard');A=__import__('fresh_adaptation')
  current={n:G.read(ROOT/n)for n in G.table(ROOT)};prior=BG.source_control_fixture_inverse(current);positive=BG.renewal_inverse(prior);historical=BG.positive_inverse(positive)
  binding=json.loads(historical['implementation/fresh-signer-policy.json'])['binding'];step=__import__('runner_context').workflow(__import__('observer_apply').workflow(new))
  parent=A.workflow_transform(B._fresh_signer_prior_workflow(step),binding)[0];self.assertEqual(parent,historical['.github/workflows/native-arm-build.yml'])
  renderer=types.ModuleType('_historical676_workflow_control');exec(compile(B._POSITIVE_WORKFLOW_RENDERER,'<Source-owned-positive-workflow>','exec'),vars(renderer))
  self.assertEqual(G.pin(parent),renderer.PARENT_PIN);derived=renderer.positive_workflow(parent);self.assertEqual(renderer.inverse_workflow(derived),parent)
  old=('          ref: '+binding['carrier_source']+'\n').encode();fresh=G.obj(HERE/'fresh-signer-policy.json')['binding']['carrier_source'];self.assertNotEqual(binding['carrier_source'],fresh);self.assertEqual(derived.count(old),2)
  self.assertEqual(derived.replace(old,('          ref: '+fresh+'\n').encode()),C.read(ROOT/'.github/workflows/native-arm-build.yml'))
  lines=W.commands(new);self.assertEqual(len(lines),5);self.assertEqual(sum('service_controls.py'in x for x in lines),1);self.assertIn(b'eea3f3022c9214deacc60c92dfca13704420756b',new)
  with self.assertRaises(ValueError):W.commands(new.replace(b'apps16_common.py\\npython3',b'apps16_common.py python3',1))
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--record',type=Path,required=True);p.add_argument('--public',type=Path,required=True);p.add_argument('--assets',type=Path,required=True);ARGS=p.parse_args();unittest.main(argv=[sys.argv[0]],verbosity=2)

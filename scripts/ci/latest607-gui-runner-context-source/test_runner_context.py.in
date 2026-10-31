# SPDX-License-Identifier: MIT
"""Real source-generated runners and executing owner globals, never native actors."""
import argparse,copy,importlib.util,json,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
sys.path.insert(0,str(HERE));import runner_context as R
class PreActorSentinel(RuntimeError):pass

def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def original_owner(legacy=False):
 # Reproduce the genuine682 import namespace: parent574 factory/context remain
 # generic names even though the owner body is loaded from current607 source.
 previous={n:sys.modules.get(n)for n in('factory','context606')};F=load('_held606_factory',ROOT/'parent574/factory/factory.py');C=load('_held606_context',ROOT/'parent574/factory/context606.py');sys.modules.update(factory=F,context606=C)
 try:return load('_current607_held_owner',(ROOT/'parent574/factory/run.py')if legacy else HERE/'factory/run.py')
 finally:
  for n,v in previous.items():
   if v is None:sys.modules.pop(n,None)
   else:sys.modules[n]=v

def generated(out,selected='minimal',mode='generic4k',legacy=False):
 base=ROOT/'parent574'if legacy else ROOT;home=base/'factory'if legacy else HERE/'factory';F=load('_source_generated_selected_factory',home/'factory.py').service1800()
 if not legacy:F=load('_source_generated_observer',HERE/'observer_apply.py').factory(F)
 with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS')):profile,changes=F.prepare_code(ROOT/'parent574/original',ARGS.assets,out,selected,mode)
 if not legacy:
  # Execute the exact source-owned copy operands of context606.stage and
  # qemu_context.prepare. No signed-cache/native readiness is simulated.
  for sub,names in [('install-context606',('alpm_reader.py','contract604.py','lifecycle604.py','build_scope.py','install606.py')),('qemu-context',('alpm_reader.py','contract604.py','lifecycle604.py','build_scope.py','install_tooling.py'))]:
   (out/sub).mkdir()
   for n in names:shutil.copyfile(home/('support/'+n if n in('alpm_reader.py','contract604.py','lifecycle604.py')else n),out/sub/n)
 F.seal(out,selected,mode,profile,changes,True)
 return F

class Controls(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory(prefix='selected607-owner-');self.work=Path(self.temp.name)
 def tearDown(self):self.temp.cleanup()
 def test_genuine_607_all_four_emissions_match_source_code_policy(self):
  for selected in('minimal','overlay'):
   for mode in('generic4k','generic16k'):
    out=self.work/(selected+'-'+mode);generated(out,selected,mode);p=R.authorize_runner(out);self.assertEqual((p['packages'],p['optional_absent']),(607,605));self.assertEqual(p['observer_diagnostic']['observer_seconds'],600)
 def test_actual_owner_globals_cross_authorization_before_actor_sentinel(self):
  out=self.work/'runner';generated(out);old=original_owner()
  with patch.object(old.platform,'machine',side_effect=PreActorSentinel('ACTOR_REFUSED')):
   with self.assertRaisesRegex(ValueError,'ready source-owned606'):old.run_service1800(ROOT/'parent574/original',out,self.work/'base',self.work/'runtime','minimal','generic4k')
   current=R.owner(old);self.assertIs(current.run_service1800.__globals__['C'].authorize_runner,R.authorize_runner)
   with self.assertRaisesRegex(PreActorSentinel,'ACTOR_REFUSED'):current.run_service1800(ROOT/'parent574/original',out,self.work/'base',self.work/'runtime','minimal','generic4k')
  self.assertFalse((self.work/'runtime').exists())
 def test_legacy606_generator_and_authorizer_same_behavior(self):
  out=self.work/'legacy';generated(out,legacy=True);legacy=original_owner(legacy=True)
  with patch.object(legacy.platform,'machine',side_effect=PreActorSentinel('ACTOR_REFUSED')),self.assertRaises(PreActorSentinel):legacy.run_service1800(ROOT/'parent574/original',out,self.work/'base',self.work/'runtime','minimal','generic4k')
  with self.assertRaises(ValueError):R.authorize_runner(out)
 def test_wrong_counts_annotations_helper_and_full_code_closure_refuse(self):
  out=self.work/'runner';generated(out);proof=out/'current606-proof.json';original=proof.read_bytes();p=json.loads(original)
  for key,bad in(('packages',606),('optional_absent',604),('observer_diagnostic',{}),('service_validation_profile',{}),('accepted_input_source','0'*40),('actual_run',1)):
   q=copy.deepcopy(p);q[key]=bad;proof.write_bytes(R.enc(q))
   with self.assertRaises((ValueError,KeyError)):R.authorize_runner(out)
  proof.write_bytes(original);helper=out/'alpm_reader.py';raw=helper.read_bytes();helper.write_bytes(raw+b'\n');q=copy.deepcopy(p);q['files']['alpm_reader.py']=R.pin(helper.read_bytes());proof.write_bytes(R.enc(q))
  with self.assertRaises(ValueError):R.authorize_runner(out)
  helper.write_bytes(raw);proof.write_bytes(original);foreign=out/'foreign.py';foreign.write_text('pass\n');q=copy.deepcopy(p);q['files']['foreign.py']=R.pin(foreign.read_bytes());proof.write_bytes(R.enc(q))
  with self.assertRaises(ValueError):R.authorize_runner(out)
  foreign.unlink();proof.write_bytes(original);(out/'foreign-input.json').write_text('{}')
  with self.assertRaises(ValueError):R.authorize_runner(out)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--assets',type=Path,required=True);ARGS=p.parse_args();unittest.main(argv=[sys.argv[0]],verbosity=2)

# SPDX-License-Identifier: MIT
"""Real source emission/evolution controls. No native actors or old positive replays."""
import hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('HISTORICAL_INVENTORY_TEST_ROOT',next(p for p in HERE.parents if(p/'manifests/packages.toml').is_file())))
s=importlib.util.spec_from_file_location('fixed_historical_inventory_source',HERE/'prepare.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
def rows(root):return{p.relative_to(root).as_posix():P.pin(p.read_bytes())for p in sorted(root.rglob('*'))if p.is_file()}
# Only source generators run inside these children; every attempted actor call is fatal.
EMIT="""import importlib.util,subprocess,sys
from pathlib import Path
from unittest.mock import patch
root,out=map(Path,sys.argv[1:3]);s=importlib.util.spec_from_file_location('unchanged_historical_emitter',root/sys.argv[3]);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m)
with patch.object(subprocess,'Popen',side_effect=AssertionError('no source-generation actor')):m.emit(root,out)
"""
EMITTERS=('scripts/ci/apps-full574-repair-native/prepare.py','scripts/ci/orphans-full574-native/prepare.py','scripts/ci/glibc-debian-maintained-installed16k/generator.py','scripts/ci/glibc-gnu-provider-installed16k-interruption/generator.py')
class Controls(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.work=Path(self.t.name);self.base=self.work/'base';P.prepare(ROOT,self.base,['all']);self.evolved=self.work/'evolved';shutil.copytree(self.base,self.evolved);self.inventory=self.evolved/'manifests/packages.toml';self.inventory.write_bytes(self.inventory.read_bytes()+b'\n# UNIT: current metadata evolves; historical input does not.\n')
 def test_all_fourteen_closed_views_and_seventeen_original_manifest_sections(self):
  p=P.profile();manifest_count=0
  for n,v in p['factories'].items():
   output=self.work/n;r=P.prepare(self.evolved,output,[n]);self.assertEqual(rows(output),v['files']);self.assertNotEqual(r['current_inventory'],r['historical_inventory']);self.assertFalse(r['current_inventory_used_for_historical_emission']);self.assertEqual(self.inventory.read_bytes().splitlines()[-1],b'# UNIT: current metadata evolves; historical input does not.')
   for row in v['manifests']:
    data=json.loads((output/row['path']).read_bytes())
    for k in row['section']:data=data[k]
    self.assertTrue(all(P.pin((output/path).read_bytes())==want for path,want in data.items()));manifest_count+=1
  self.assertEqual(manifest_count,17)
 def test_unchanged_real_family_emitters_have_exact_same_full_output_after_inventory_evolution(self):
  after=self.work/'after';P.prepare(self.evolved,after,['all']);counts={}
  for i,entry in enumerate(EMITTERS):
   before_out=self.work/('before-'+str(i));after_out=self.work/('after-'+str(i))
   for root,out in((self.base,before_out),(after,after_out)):
    r=subprocess.run([sys.executable,'-I','-B','-c',EMIT,str(root),str(out),entry],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60);self.assertEqual(r.returncode,0,r.stderr.decode());self.assertEqual(r.stdout,b'')
   self.assertEqual(rows(before_out),rows(after_out),entry);counts[entry]=len(rows(after_out))
  self.assertEqual(len(counts),4)
 def test_original_factory_refuses_evolved_inventory_without_explicit_baseline_view(self):
  out=self.work/'old-direct';r=subprocess.run([sys.executable,'-I','-B','-c',EMIT,str(self.evolved),str(out),EMITTERS[0]],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30);self.assertNotEqual(r.returncode,0);self.assertIn(b'manifests/packages.toml',r.stderr);self.assertFalse(out.exists())
 def test_noninventory_drift_missing_hardlink_alias_snapshot_and_selector_refuse_before_output(self):
  profile=P.profile();name=next(n for n in profile['factories']['apps-full574-repair-native']['files']if n!='manifests/packages.toml');path=self.evolved/name;raw=path.read_bytes()
  for kind in('drift','missing','symlink','hardlink'):
   if path.exists()or path.is_symlink():path.unlink()
   if kind=='drift':path.write_bytes(raw+b'\n')
   elif kind=='symlink':path.symlink_to(self.base/name)
   elif kind=='hardlink':os.link(self.base/name,path)
   out=self.work/('refused-'+kind)
   with self.assertRaises((ValueError,FileNotFoundError)):P.prepare(self.evolved,out,['apps-full574-repair-native'])
   self.assertFalse(out.exists())
  path.unlink();path.write_bytes(raw)
  for names,baseline in((['unknown'],P.BASELINE),(['all','apps-full574-native'],P.BASELINE),(['apps-full574-native']*2,P.BASELINE),(['all'],'moving-current')):
   out=self.work/'refused-selector'
   with self.assertRaises(ValueError):P.prepare(self.evolved,out,names,baseline)
   self.assertFalse(out.exists())
  helper=self.work/'helper';shutil.copytree(HERE,helper);snapshot=helper/profile['snapshot']['path'];snapshot.write_bytes(snapshot.read_bytes()+b'\n');out=self.work/'refused-snapshot'
  with patch.object(P,'HERE',helper),self.assertRaises(ValueError):P.prepare(self.evolved,out,['all'])
  self.assertFalse(out.exists())
  alias=self.work/'alias';alias.symlink_to(self.evolved,target_is_directory=True)
  with self.assertRaises(ValueError):P.prepare(alias,self.work/'refused-source-alias',['all'])
  with self.assertRaises(ValueError):P.prepare(self.evolved,self.base,['all'])
  outalias=self.work/'output-alias';outalias.symlink_to(self.base,target_is_directory=True)
  with self.assertRaises(ValueError):P.prepare(self.evolved,outalias,['all'])
 def test_actual_isolated_CLI_emits_closed_historical_view(self):
  before=rows(self.evolved);out=self.work/'cli';r=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--source',str(self.evolved),'--output',str(out),'--factory','all','--baseline',P.BASELINE],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30);self.assertEqual(r.returncode,0,r.stderr.decode());self.assertEqual(r.stderr,b'');v=json.loads(r.stdout);self.assertEqual(v['files'],len(rows(self.base)));self.assertEqual(rows(out),rows(self.base));self.assertEqual(rows(self.evolved),before);self.assertFalse(v['acceptance'])
  h=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--help'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30);self.assertEqual(h.returncode,0);self.assertIn(b'--baseline',h.stdout)
if __name__=='__main__':unittest.main(verbosity=2)

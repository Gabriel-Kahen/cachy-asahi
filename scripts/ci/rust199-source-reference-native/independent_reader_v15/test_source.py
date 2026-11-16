#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Read genuine public Source361 as DATA and exercise both complete inverses."""
import argparse
import ast
import importlib.util
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','resource.setrlimit'):
  raise AssertionError('Source361 DATA controls forbid actor/network/authority: '+event)


sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('reader15_source_data',HERE/'storage.py')
S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)


class SourceControls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.profile=(HERE/'source-profile.DATA.json').read_bytes()
  # Check the input namespace/map before copying, then hold one whole snapshot.
  # Re-reading two43MiB trees in one process needlessly retains allocator arenas.
  names=S.namespace(SOURCE_ROOT,361);raw=S.read(SOURCE_ROOT/'source-map.json',S.MIB)
  S.need(S.pin(raw)==dict(bytes=S.SOURCE_MAP_BYTES,sha256=S.SOURCE['map_sha256'])and
   names==set(S.decode(raw)['files'])|{'source-map.json'},'PUBLIC_SOURCE361_INPUT_NAMESPACE_MAP')
  cls.temp=tempfile.TemporaryDirectory(prefix='reader15-genuine-public-source-')
  cls.root=Path(cls.temp.name)/'relocated-source'
  shutil.copytree(SOURCE_ROOT,cls.root)
  try:cls.files=S.source(cls.root,cls.profile,S.SOURCE)
  except BaseException:cls.temp.cleanup();raise
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def setUp(self):S.END=None
 def remap(self,files):
  mapping=S.decode(self.files['source-map.json'][0]);mapping['files']={n:dict(S.pin(raw),mode=mode)for n,(raw,mode)in files.items()if n!='source-map.json'}
  files['source-map.json']=(S.canonical(mapping),0o644);return files
 def marker(self,mutate):
  files=dict(self.files);name='owned-job-directory-v15.json';value=S.decode(files[name][0]);mutate(value)
  files[name]=(S.canonical(value),0o644);return self.remap(files)
 def test_genuine_relocated361_whole_tree_modes_and_both_inverses(self):
  files=self.files
  self.assertEqual(len(files),361);self.assertEqual(sum(len(raw)for raw,mode in files.values()),S.SOURCE['bytes'])
  self.assertEqual(S.git_tree(files),S.SOURCE['tree'])
  self.assertTrue(all(mode==0o644 for raw,mode in files.values()))
  self.assertEqual(S.source_inverse(files),S.PARENT355)
 def test_initializer_fixed_source_data_matches_independent_digest(self):
  text=self.files['hosted/volume.py'][0].decode();node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='INIT_CODE'for t in n.targets))
  raw=ast.literal_eval(node.value).encode()
  self.assertEqual(raw,(HERE/'fixtures/initializer-code.DATA.txt').read_bytes())
  self.assertEqual(S.pin(raw)['sha256'],'e3da33c401407b1d0bc04caa5a67bde354a0ad54727450003cda5f57c611fc1a')
  self.assertNotIn(b'os.fchmod(',raw);self.assertNotIn(b'os.fchown(',raw)
  self.assertIn(b"NO_CAPS_NO_MUTATION_OWNED_DIRECTORY",raw)
 def test_wrong_source_contract_refuses_before_namespace(self):
  with patch.object(S,'namespace',side_effect=AssertionError('must refuse before Source read')):
   with self.assertRaisesRegex(S.Hold,'EXTERNAL_SOURCE_PROFILE_PIN'):S.source(self.root,self.profile,dict(S.SOURCE,files=344))
 def test_no_root_claims_or_issued_markers(self):
  for mutate in(lambda m:m.update(Root_grants=True),lambda m:m.update(dispatch={}),lambda m:m.update(unadmitted=False),
                lambda m:m.update(holds_preserved=False),lambda m:m['actual'].update(source='MODEL_FORGED'),lambda m:m.update(schema=True)):
   with self.assertRaisesRegex(S.Hold,'SOURCE361_UNISSUED_INVERSE_SCOPE'):S.source_inverse(self.marker(mutate))
 def test_kernel_required_and_narrow_scope_bits_cannot_be_changed(self):
  for key in('external_owned_job_directory_setup','kernel_preentry_required','source_enforced_order','resources_changed','recipe_changed','workflows_changed','carrier_transport_changed','metadata_normalization_changed','request_bounds_changed'):
   files=self.marker(lambda m:m.update({key:not m[key]}))
   with self.subTest(key=key),self.assertRaisesRegex(S.Hold,'SOURCE361_FINITE_CHANGE_SCOPE'):S.source_inverse(files)
 def test_exact_changed_roster_preserves_actor_and_helper(self):
  files=self.marker(lambda m:m['changes'].update({'actor/mount_proof.py':{}}))
  with self.assertRaisesRegex(S.Hold,'SOURCE361_EXACT_ARCHIVED355_NAMESPACE'):S.source_inverse(files)
 def test_all_ancestor_inverses_retained(self):
  marker=S.decode(self.files['owned-job-directory-v15.json'][0]);extra={'owned-job-directory-v15.json','hosted/owned_dir.py',*marker['archives']}
  restored={n:row for n,row in self.files.items()if n not in extra}
  for name in marker['changes']:
   if name!='hosted/owned_dir.py':restored[name]=self.files['previous-v14/'+name]
  restored['source-map.json']=self.files['previous-v14/source-map.json']
  self.assertEqual(S.source355_inverse(restored),S.PARENT351)
  self.assertEqual(S.git_tree(restored),S.PARENT355['tree'])
  bad=dict(restored);name='previous-v12/actor/entry.py';bad[name]=(bad[name][0]+b'\nMODEL_DRIFT\n',0o644)
  mapping=S.decode(restored['source-map.json'][0]);mapping['files']={n:dict(S.pin(raw),mode=mode)for n,(raw,mode)in bad.items()if n!='source-map.json'}
  bad['source-map.json']=(S.canonical(mapping),0o644)
  with self.assertRaisesRegex(S.Hold,'SOURCE355_FULL_SOURCE351_INVERSE'):S.source355_inverse(bad)
 def test_exact_archived_replacement_body(self):
  files=dict(self.files);name='previous-v14/hosted/producer.py';files[name]=(files[name][0]+b'\nMODEL_DRIFT\n',0o644)
  with self.assertRaisesRegex(S.Hold,'SOURCE361_EXACT_REPLACEMENT_BEFORE'):S.source_inverse(self.remap(files))
 def test_protected_resource_or_recipe_substitution_refuses(self):
  for name in('resource-policy.json','packages/port/rust199-source-reference/PKGBUILD'):
   files=dict(self.files);files[name]=(files[name][0]+b'\nMODEL_DRIFT\n',0o644)
   with self.subTest(name=name),self.assertRaisesRegex(S.Hold,'SOURCE361_FULL_SOURCE355_INVERSE'):S.source_inverse(self.remap(files))
 def test_missing_extra_or_forged_archive_roster_refuses(self):
  files=dict(self.files);files.pop('previous-v14/hosted/producer.py')
  with self.assertRaisesRegex(S.Hold,'SOURCE361_EXACT_ARCHIVED355_NAMESPACE'):S.source_inverse(files)
  files=self.marker(lambda m:m['archives'].append('previous-v13/EXTRA'))
  with self.assertRaisesRegex(S.Hold,'SOURCE361_EXACT_ARCHIVED355_NAMESPACE'):S.source_inverse(files)
 def test_physical_extra_and_alias_refuse_without_source_mutation(self):
  extra=self.root/'MODEL_EXTRA';extra.write_bytes(b'MODEL\n')
  try:
   with self.assertRaises(S.Hold):S.source(self.root,self.profile,S.SOURCE)
  finally:extra.unlink()
  target=self.root/'actor/mount_proof.py';raw=target.read_bytes();target.unlink();target.symlink_to('entry.py')
  try:
   with self.assertRaisesRegex(S.Hold,'NAMESPACE_ALIAS'):S.source(self.root,self.profile,S.SOURCE)
  finally:target.unlink();target.write_bytes(raw);target.chmod(0o644)
 def test_physical_mode_drift_refuses(self):
  target=self.root/'actor/mount_proof.py';target.chmod(0o755)
  try:
   with self.assertRaisesRegex(S.Hold,'SOURCE_MODE'):S.source(self.root,self.profile,S.SOURCE)
  finally:target.chmod(0o644)


if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source-root',type=Path,required=True)
 args,rest=parser.parse_known_args();SOURCE_ROOT=args.source_root
 unittest.main(argv=[sys.argv[0],*rest])

# SPDX-License-Identifier: MIT
"""Portable MODEL Source188 basis; real v6/v5/v4 inverse transformations."""
import contextlib
import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
M=load('capture_v6_constructor',HERE/'prepare.py')
B=load('capture_v6_v5_DATA_fixture',HERE.parent/'successor_v5_source/test_data.py')


class Controls(unittest.TestCase):
 def setUp(self):
  self.fixture=B.Controls();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
  b=self.fixture;self.C=b.C;self.H=b.H
  self.model=contextlib.ExitStack();self.addCleanup(self.model.close);self.model.enter_context(b.model())
  self.basis188,_=b.rebind();self.basis179=b.files;self.basis139=b.original
  self.basis=dict(files=len(self.basis188),bytes=sum(len(v[0])for v in self.basis188.values()),tree=self.H.tree(self.basis188),source_map=self.C.pin(self.basis188['source-map.json'][0]))
  self.real_pins=M.REPLACEMENTS;self.real_basis=M.SOURCE188
  self.replacements={role:(('MODEL INERT CAPTURE '+role+'\n').encode(),0o644)for role in M.REPLACEMENTS}
  self.pins={role:dict(member=M.REPLACEMENTS[role]['member'],**self.C.pin(raw))for role,(raw,_)in self.replacements.items()}
  self.construction={name:((HERE/name).read_bytes(),0o644)for name in('prepare.py','README.md')};self.commit='c'*40
  self.model.enter_context(patch.multiple(M,SOURCE188=self.basis,REPLACEMENTS=self.pins,load_helpers=lambda:(B.M,b.V4,b.P,b.C,b.H)))
 def rebind(self,files=None,replacements=None,**kw):
  return M.rebind(self.basis188 if files is None else files,self.replacements if replacements is None else replacements,commit=kw.get('commit',self.commit),constructor_files=kw.get('constructor_files',self.construction))
 def test_fixed_real_pins_and_source188_identity_match_retained_basis_contract(self):
  self.assertEqual(self.real_basis,dict(files=188,bytes=45544942,tree='50bf7aab34ee5497f12d078709354aa69b0cdb9d',source_map=dict(bytes=37091,sha256='ba06925244cd010ab2223325e2e324d4d3b469befbea5e7eb8e0de68383d4908')))
  self.assertEqual(set(self.real_pins),{'hosted_launcher','material_domain_executor'})
  for row in self.real_pins.values():self.assertEqual(self.C.pin((HERE.parents[3]/row['member']).read_bytes()),{k:row[k]for k in('bytes','sha256')})
 def test_two_replacements_eight_additions_and_exact_188_179_139_inverses(self):
  before=copy.deepcopy(self.basis188);candidate,profile=self.rebind()
  self.assertEqual(M.inverse_v5(candidate),before);self.assertEqual(M.inverse_v4(candidate),self.basis179);self.assertEqual(M.inverse_v3(candidate),self.basis139)
  self.assertEqual(len(set(candidate)-set(before)),8);self.assertEqual({n for n in before if before[n]!=candidate[n]},{'source-map.json','source.lock.json',*(v['member']for v in self.pins.values())})
  self.assertEqual(self.basis188,before);self.assertEqual(profile['prospective_tree'],self.H.tree(candidate))
  for name in (M.OLD_PROGRAM,B.M.PREFIX+'/inverse.json',B.M.PREFIX+'/prepare.py',B.M.PREFIX+'/README.md','provenance/v5/source179-map.json'):
   self.assertEqual(candidate[name],before[name])
  mapping=self.C.decode(candidate['source-map.json'][0]);self.assertEqual(mapping['files'],self.C.descriptors({n:v for n,v in candidate.items()if n not in('source-map.json','source.lock.json')}))
 def test_new_registry_preserves_schema5_provenance_materials_and_null_acceptance(self):
  files,profile=self.rebind();old=self.C.decode(self.basis188[M.OLD_PROGRAM][0]);new=self.C.decode(files[M.PREFIX+'/program.json'][0]);provenance=self.C.decode(files[M.PROVENANCE+'/rebind.json'][0])
  self.assertEqual(new['schema'],6);self.assertEqual(new['kind'],'DELEGATED_CURRENT_CAPTURE_PROGRAM_REGISTRY_V6')
  self.assertEqual(new['capture_commit'],self.commit);self.assertEqual(new['diagnostics_commit'],old['diagnostics_commit']);self.assertEqual(new['rebind_provenance'],old['rebind_provenance']);self.assertEqual(new['basis_closure_commit'],old['basis_closure_commit'])
  self.assertEqual(new['capture_rebind_provenance'],dict(member=M.PROVENANCE+'/rebind.json',**self.C.pin(files[M.PROVENANCE+'/rebind.json'][0])))
  self.assertEqual({n for n in old['roles']if new['roles'][n]!=old['roles'][n]},set(self.pins));self.assertEqual(len(new['delegation_programs']),25)
  self.assertEqual(profile['staging_materials'],old['staging_materials']);self.assertEqual(len(profile['materials'])+len(profile['staging_materials']),64)
  for value in (new,profile,provenance):self.assertTrue(all(v is None for v in value['actual'].values()))
 def test_incorrect_basis_body_mode_map_namespace_and_historical_inverse_refuse(self):
  for mode in ('body','mode','map','alias','extra','missing','historical'):
   files=copy.deepcopy(self.basis188)
   if mode in('body','mode'):
    name=next(iter(self.pins.values()))['member'];raw,permissions=files[name];files[name]=(raw+b'DRIFT'if mode=='body'else raw,0o755 if mode=='mode'else permissions)
   elif mode=='map':files['source-map.json']=(b'DRIFT',0o644)
   elif mode=='alias':files['source.lock.json']=(b'DRIFT',0o644)
   elif mode=='extra':files['FOREIGN.DATA']=(b'FOREIGN',0o644)
   elif mode=='missing':files.pop(next(iter(self.pins.values()))['member'])
   else:files['provenance/v5/source179-map.json']=(b'DRIFT',0o644)
   with self.subTest(mode=mode),self.assertRaises(ValueError):self.rebind(files)
 def test_replacement_commit_constructor_collision_authority_and_caps_refuse(self):
  for mode in ('missing','extra','body','mode','commit','constructor','collision','authority','files-cap','bytes-cap'):
   replacements=copy.deepcopy(self.replacements);files=copy.deepcopy(self.basis188);construction=dict(self.construction);commit=self.commit;limits=dict(MAX_FILES=self.C.MAX_FILES)
   role=next(iter(replacements));raw,_=replacements[role]
   if mode=='missing':replacements.pop(role)
   elif mode=='extra':replacements['unknown']=(b'MODEL',0o644)
   elif mode=='body':replacements[role]=(raw+b'DRIFT',0o644)
   elif mode=='mode':replacements[role]=(raw,0o755)
   elif mode=='commit':commit='HEAD'
   elif mode=='constructor':construction.pop('README.md')
   elif mode=='collision':files[M.PROVENANCE+'/rebind.json']=(b'FOREIGN',0o644)
   elif mode=='authority':
    registry=self.C.decode(files[M.OLD_PROGRAM][0]);registry['actual']['Root_delegation']='REFUSED';files[M.OLD_PROGRAM]=(self.C.encoded(registry),0o644)
   elif mode=='files-cap':limits=dict(MAX_FILES=len(files))
   else:limits=dict(MAX_TOTAL=1)
   with self.subTest(mode=mode),patch.multiple(self.C,**limits),self.assertRaises(ValueError):self.rebind(files,replacements,commit=commit,constructor_files=construction)
 def test_inverse_refuses_any_backup_map_removal_restoration_or_untouched_drift(self):
  candidate,_=self.rebind()
  for mode in('backup','map','remove','restore','untouched','extra','basis'):
   files=copy.deepcopy(candidate);inverse=self.C.decode(files[M.PREFIX+'/inverse.json'][0])
   if mode=='backup':files[next(iter(inverse['restore'].values()))]=(b'DRIFT',0o644)
   elif mode=='map':files[M.PROVENANCE+'/source188-map.json']=(b'DRIFT',0o644)
   elif mode=='remove':inverse['remove'].pop()
   elif mode=='restore':inverse['restore'].pop(next(iter(inverse['restore'])))
   elif mode=='untouched':files[M.OLD_PROGRAM]=(b'DRIFT',0o644)
   elif mode=='extra':files['FOREIGN.DATA']=(b'FOREIGN',0o644)
   else:inverse['basis']['tree']='0'*40
   files[M.PREFIX+'/inverse.json']=(self.C.encoded(inverse),0o644)
   with self.subTest(mode=mode),self.assertRaises(ValueError):M.inverse_v5(files)
 def test_assemble_requires_exact_local_committed_operands(self):
  calls=[];P=self.fixture.P
  def blob(repo,revision,name,expected=None):
   calls.append((revision,name,expected))
   for role,row in self.pins.items():
    if row['member']==name:self.assertEqual(expected,dict(bytes=row['bytes'],sha256=row['sha256'],mode=0o644));return self.replacements[role]
   return self.construction[Path(name).name]
  with patch.object(M,'load_basis',return_value=self.basis188),patch.object(P,'commit')as commit,patch.object(P,'blob',side_effect=blob),patch.object(M,'rebind',return_value=('MODEL FILES','MODEL PROFILE'))as rebind:
   self.assertEqual(M.assemble(Path('/MODEL/repo'),Path('/MODEL/source188'),self.commit),('MODEL FILES','MODEL PROFILE'))
   commit.assert_called_once_with(Path('/MODEL/repo'),self.commit);self.assertEqual(len(calls),4);rebind.assert_called_once_with(self.basis188,self.replacements,commit=self.commit,constructor_files=self.construction)
  with patch.object(M,'load_basis',return_value=self.basis188),patch.object(P,'commit'),patch.object(P,'blob',side_effect=blob),patch.object(self.C,'read',return_value=(b'UNCOMMITTED',0o644)),self.assertRaises(ValueError):M.assemble(Path('/MODEL/repo'),Path('/MODEL/source188'),self.commit)


if __name__=='__main__':unittest.main(verbosity=2)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure full574 BUILDINFO DATA joins; no packages, ALPM, actors or originals."""
import copy,hashlib,importlib.util,json,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
spec=importlib.util.spec_from_file_location('source574_buildinfo',HERE/'buildinfo_supplement.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)

class Full574(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  raw=(ROOT/B.LOCK).read_bytes();lock=json.loads(raw);cls.recipe=(ROOT/'packages/tools/cachy-asahi-orphans03/PKGBUILD').read_bytes();cls.inputs=dict(body={B.LOCK:raw},base={r['name']:r['version'] for r in lock['packages']});cls.positive=dict(pkgbuild_sha256sum=[B.sha(cls.recipe)],installed=B.expected(cls.inputs))
 def refuse(self,value,inputs=None,recipe=None):
  with self.assertRaises(ValueError):B.verify(value,self.recipe if recipe is None else recipe,self.inputs if inputs is None else inputs)
 def test_complete_source574_architecture_vector_and_recipe(self):
  result=B.verify(copy.deepcopy(self.positive),self.recipe,self.inputs);self.assertEqual(result['installed'],574);self.assertEqual(result['architectures'],{'aarch64':510,'any':64});self.assertEqual(result['recipe_sha256'],hashlib.sha256(self.recipe).hexdigest());self.assertIsNone(result['actual']);self.assertIsNone(result['Root_acceptance']);self.assertEqual(result['native'],'NOT_RUN')
 def test_vector_order_is_irrelevant_without_losing_any_row(self):
  value=copy.deepcopy(self.positive);value['installed'].reverse();self.assertEqual(B.verify(value,self.recipe,self.inputs)['installed'],574)
 def test_missing_installed_row_refuses(self):
  value=copy.deepcopy(self.positive);value['installed'].pop();self.refuse(value)
 def test_extra_installed_row_refuses(self):
  value=copy.deepcopy(self.positive);value['installed'].append('foreign-1-1-any');self.refuse(value)
 def test_duplicate_with_full_denominator_refuses(self):
  value=copy.deepcopy(self.positive);value['installed'][-1]=value['installed'][0];self.refuse(value)
 def test_wrong_architecture_cannot_be_replaced_by_host_architecture(self):
  for old,new in [('any','aarch64'),('aarch64','any'),('aarch64','x86_64')]:
   value=copy.deepcopy(self.positive);index=next(i for i,n in enumerate(value['installed']) if n.endswith('-'+old));value['installed'][index]=value['installed'][index].rsplit('-',1)[0]+'-'+new
   with self.subTest(old=old,new=new):self.refuse(value)
 def test_wrong_version_refuses_even_with_same_package_name(self):
  value=copy.deepcopy(self.positive);row=json.loads(self.inputs['body'][B.LOCK])['packages'][0];index=value['installed'].index(row['name']+'-'+row['version']+'-'+row['arch']);value['installed'][index]=row['name']+'-9999-1-'+row['arch'];self.refuse(value)
 def test_wrong_or_changed_recipe_refuses(self):
  value=copy.deepcopy(self.positive);value['pkgbuild_sha256sum']=['0'*64];self.refuse(value);self.refuse(self.positive,recipe=self.recipe+b'\n')
 def test_changed_source_lock_bytes_refuse(self):
  inputs=copy.deepcopy(self.inputs);inputs['body'][B.LOCK]+=b'\n';self.refuse(self.positive,inputs)
 def test_incomplete_or_different_base_map_refuses(self):
  for change in ('missing','version'):
   inputs=copy.deepcopy(self.inputs);key=next(iter(inputs['base']))
   if change=='missing':inputs['base'].pop(key)
   else:inputs['base'][key]='9999-1'
   with self.subTest(change=change):self.refuse(self.positive,inputs)
 def test_changed_source_denominator_or_duplicate_name_refuses(self):
  for change in ('extra','duplicate'):
   inputs=copy.deepcopy(self.inputs);lock=json.loads(inputs['body'][B.LOCK])
   if change=='extra':lock['packages'].append(dict(lock['packages'][0]))
   else:lock['packages'][-1]=dict(lock['packages'][0])
   inputs['body'][B.LOCK]=json.dumps(lock).encode()
   with self.subTest(change=change):self.refuse(self.positive,inputs)
 def test_typed_bounded_source_recipe_and_installed_data_required(self):
  for raw in (None,bytearray(self.inputs['body'][B.LOCK]),b'x'*(2*1024**2+1)):
   inputs=copy.deepcopy(self.inputs);inputs['body'][B.LOCK]=raw
   with self.subTest(source_type=type(raw).__name__):self.refuse(self.positive,inputs)
  for recipe in (b'',bytearray(self.recipe)):
   with self.subTest(recipe_type=type(recipe).__name__):self.refuse(self.positive,recipe=recipe)
  value=copy.deepcopy(self.positive);value['installed'][0]=None;self.refuse(value)

if __name__=='__main__':unittest.main()

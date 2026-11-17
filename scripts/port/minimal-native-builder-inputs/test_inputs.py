# SPDX-License-Identifier: MIT
"""Fixed actual metadata/retrieval evidence plus adversarial MODEL controls."""
import base64,copy,hashlib,importlib.util,io,json,subprocess,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
H=Path(__file__).resolve().parent

def mod(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
A=mod('intake',H/'acquire.py');P=mod('gate',H/'preflight.py');E=mod('operand_projection',H/'export.py');D=json.loads((H/'builder.lock.json').read_bytes());PROFILE=json.loads((H/'profile.DATA.json').read_bytes())
class Controls(unittest.TestCase):
 def test_ACTUAL_fixed_snapshot_complete_base_devel_and_recipes(self):
  self.assertEqual(A.pin(H/'builder.lock.json'),PROFILE['builder_lock']);self.assertEqual(D['metadata_graph_status'],'PASS');self.assertEqual(D['graph_blockers'],[]);self.assertEqual(len(D['packages']),206);self.assertEqual(D['rootfs_reconciliation'],dict(installed=165,selected=165,missing=[]));names={r['name']for r in D['packages']};base=next(r for r in D['packages']if r['name']=='base-devel');self.assertEqual(len(base['depends']),26);self.assertTrue(set(base['depends'])<=names);self.assertEqual(D['recipe_inputs']['llhttp']['makedepends'],['cmake>=3.25','ninja']);self.assertIn('python',D['recipe_inputs']['libgit2']['makedepends']);self.assertTrue(all(e['status']=='SATISFIED'for e in D['edges']));self.assertEqual(len(D['explicit_provider_bindings']),2)
 def test_ACTUAL_embedded_signatures_and_source_pins_are_complete(self):
  self.assertEqual(len({r['archive']['filename']for r in D['packages']}),206)
  for r in D['packages']:
   a=r['archive'];b=base64.b64decode(a['signature_b64'],validate=True);self.assertEqual(dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest()),dict(bytes=a['signature_bytes'],sha256=a['signature_sha256']));self.assertIn(r['arch'],('aarch64','any'));self.assertEqual(a['signature_bytes'],566)
  self.assertEqual({r['filename']for r in D['upstream_sources']},{'llhttp-9.3.1.tar.gz','libgit2-1.9.7.tar.gz'});self.assertIsNone(D['project_llhttp_dependency']['actual_project_archive'])
 def test_native_operand_projection_retains_normal_dependencies_and_complete_inventory(self):
  n=E.project(D);self.assertEqual(len(n['packages']),206);self.assertEqual(n['rootfs_packages'],D['rootfs_original_inventory']);self.assertEqual(n['rootfs'],D['rootfs']);self.assertEqual(n['signer_fingerprint'],D['signer_fingerprint'])
  for r,q in zip(D['packages'],n['packages']):self.assertEqual(q['depends'],r['depends']);self.assertEqual(q['provides'],r['provides']);self.assertEqual(q['sha256'],r['archive']['sha256'])
 def test_default_Root_authentication_refuses_before_material_or_GPG(self):
  for a in(None,json.loads((H/'Root-authentication.TEMPLATE.json').read_bytes())):
   with patch.object(P,'material_check',side_effect=AssertionError('no native/GPG/material action')):self.assertRaisesRegex(ValueError,'UNISSUED',P.authenticated,D,PROFILE['builder_lock'],Path('/MODEL/unused'),a)
 def test_libgit2_target_refuses_unissued_project_provider(self):
  self.assertEqual(P.target_gate(D,'llhttp'),'llhttp');self.assertRaisesRegex(ValueError,'provider UNISSUED',P.target_gate,D,'libgit2')
 def test_wrong_lock_refuses_before_cache_or_transfer(self):
  with tempfile.TemporaryDirectory(prefix='minimal-input-refusal-')as t:
   root=Path(t);cache=root/'absent';f=root/'wrong.json';f.write_text('{}')
   with patch.object(A,'engine',side_effect=AssertionError('no network')):self.assertRaises(ValueError,A.acquire,f,'0'*64,cache)
   self.assertFalse(cache.exists())
 def test_symbolic_and_multiple_link_inputs_refuse(self):
  with tempfile.TemporaryDirectory(prefix='minimal-alias-')as t:
   root=Path(t);f=root/'input';f.write_bytes(b'MODEL');a=root/'alias';a.symlink_to(f);self.assertRaises(ValueError,P.read,a)
   a.unlink();a.hardlink_to(f);self.assertRaises(ValueError,P.read,f)
 def test_incomplete_manifest_refuses_native_operand_projection(self):
  for field,value in(('graph_blockers',[dict(code='MODEL')]),('metadata_graph_status','FAIL'),('rootfs_reconciliation',dict(missing=['MODEL']))):
   d=copy.deepcopy(D);d[field]=value;self.assertRaises(ValueError,E.project,d)
 def test_MODEL_complete_package_parser_rejects_identity_arch_and_dependency_changes(self):
  n=P.module(P.ROOT/'scripts/ci/native_arm.py','MODEL_existing_inspector');row=dict(name='model',version='1-1',arch='aarch64',license=['MIT'],depends=['glibc'],provides=[],conflicts=[],replaces=[])
  with tempfile.TemporaryDirectory(prefix='minimal-pkginfo-')as t:
   p=Path(t)/'MODEL.pkg.tar.xz';raw=b'pkgname = model\npkgver = 1-1\narch = aarch64\nlicense = MIT\ndepend = glibc\n'
   with tarfile.open(p,'w:xz')as archive:m=tarfile.TarInfo('.PKGINFO');m.size=len(raw);archive.addfile(m,io.BytesIO(raw))
   self.assertEqual(n.inspect_package(p,row)['metadata']['arch'],['aarch64'])
   for key,value in(('name','wrong'),('version','2-1'),('arch','x86_64'),('depends',[])):
    bad=dict(row);bad[key]=value;self.assertRaises(ValueError,n.inspect_package,p,bad)
 def test_MODEL_signature_parser_rejects_wrong_expired_or_multiple_signatures(self):
  n=P.module(P.ROOT/'scripts/ci/native_arm.py','MODEL_existing_signature_parser');f=D['signer_fingerprint'];s='[GNUPG:] VALIDSIG '+f+' 2026-11-17 1794910000 0 4 0 1 10 00 '+f+'\n';n.valid_signature(s,f)
  for bad in(s.replace(f,'0'*40),s+s,s+'[GNUPG:] EXPKEYSIG '+f+' MODEL\n','[GNUPG:] NO_PUBKEY MODEL\n'):self.assertRaises(ValueError,n.valid_signature,bad,f)
 def test_no_host_mutation_or_nodeps_execution_interface(self):
  for n in('plan.py','acquire.py','export.py','preflight.py'):
   s=(H/n).read_text();self.assertNotIn('--nodeps',s);self.assertNotIn('docker run',s);self.assertNotIn('pacman -U',s)
if __name__=='__main__':unittest.main(verbosity=2)

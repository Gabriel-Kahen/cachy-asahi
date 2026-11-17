#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Genuine pinned source checks plus explicitly MODEL stage/adversarial controls."""
import ast,hashlib,importlib.util,json,os,re,struct,sys,tempfile,unittest
from pathlib import Path
H=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('source',H/'source.py');S=importlib.util.module_from_spec(spec);sys.modules['source']=S;spec.loader.exec_module(S)
spec=importlib.util.spec_from_file_location('stage',H/'check_stage.py');T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)
D=S.document(H/'BUILD-CONTRACT.json')
def model_elf(soname=None,machine=183):
 b=bytearray(1024);b[:7]=b'\x7fELF\x02\x01\x01';struct.pack_into('<HHI',b,16,3,machine,1);struct.pack_into('<Q',b,32,64);struct.pack_into('<HHH',b,52,64,56,2);struct.pack_into('<IIQQQQQQ',b,64,1,5,0,0x4000,0x4000,len(b),len(b),16384);strings=b'\0'+soname.encode()+b'\0'if soname else b'\0';b[512:512+len(strings)]=strings;entries=[(5,0x4200),(10,len(strings))]+([(14,1)]if soname else[])+[(0,0)];struct.pack_into('<IIQQQQQQ',b,120,2,6,256,0x4100,0x4100,len(entries)*16,len(entries)*16,8)
 for i,row in enumerate(entries):struct.pack_into('<qQ',b,256+i*16,*row)
 return bytes(b)
class Controls(unittest.TestCase):
 def test_genuine_selected_source_and_revision(self):
  rows=S.document(H/'upstream/selected-source.lock.json')
  for n,r in rows.items():
   b=S.ordinary(H/'upstream/source'/n);self.assertEqual(dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest()),{k:r[k]for k in('bytes','sha256')})
  self.assertEqual(len(S.verify(H/'upstream/source',H/'source-notices.json')),23)
 def test_primary_archive_checksum_and_tag_correspondence(self):
  d=S.document(H/'SOURCE-INPUTS.lock.json');self.assertEqual(d['archive_tag'],d['tree']);self.assertEqual(S.document(H/'upstream/git-release-commit.DATA.json')['tree']['sha'],d['tree']);self.assertEqual(S.document(H/'upstream/git-release-commit.DATA.json')['sha'],d['revision']);self.assertEqual((H/'upstream/git-tag-template.txt').read_bytes(),b'$Format:%T$\n');self.assertEqual(d['revision'],S.REVISION);self.assertIn(d['archive']['sha256'],(H/'upstream/qtdeclarative-everywhere-src-6.12.0.tar.xz.mirrorlist').read_text());self.assertIn(d['archive']['sha256'],(H/'PKGBUILD').read_text())
 def test_source_notices_closed_and_mutation_refuses(self):
  with tempfile.TemporaryDirectory()as t:
   p=Path(t)/'policy';d=S.document(H/'source-notices.json');d['source_notices']['LICENSES/MIT.txt']='0'*64;p.write_text(json.dumps(d));self.assertRaises(ValueError,S.verify,H/'upstream/source',p);d['source_notices']['../private']='0'*64;p.write_text(json.dumps(d));self.assertRaises(ValueError,S.verify,H/'upstream/source',p)
 def test_all56_common_features_source_derived_not_platform_waivers(self):
  found=set()
  for p in(H/'upstream/source/src').rglob('configure.cmake'):found.update(x.replace('-','_')for x in re.findall(r'qt_feature\("([^"]+)"',p.read_text()))
  excluded={x.replace('-','_')for x in D['excluded_platform_features']};self.assertEqual(set(D['required_features']),found-excluded);self.assertEqual(len(D['required_features']),56)
  configure=(H/'configure.cmake').read_text()
  for f in D['required_features']:self.assertIn('set(FEATURE_'+f+' ON ',configure)
 def test_actual_missing_qsb_skips_all_quick_therefore_guard_requires_it(self):
  src=(H/'upstream/source/src/CMakeLists.txt').read_text();self.assertIn('TARGET Qt::Gui AND TARGET Qt::qsb AND QT_FEATURE_qml_animation',src);self.assertIn("not finding the qtshadertools 'qsb'",src);guard=(H/'dependency_guard.cmake').read_text();self.assertIn('if(NOT TARGET Qt6::qsb)',guard);self.assertIn('6.12.0 EXACT CONFIG REQUIRED',guard)
 def test_SRCINFO_exact_local_sources_checksums(self):
  text=(H/'.SRCINFO').read_text();names=re.findall(r'^\s*source = (.+)$',text,re.M);digests=re.findall(r'^\s*sha256sums = ([0-9a-f]{64})$',text,re.M);self.assertEqual(len(names),len(digests));self.assertEqual(len(names),13)
  for name,digest in zip(names[1:],digests[1:]):self.assertEqual(hashlib.sha256((H/name).read_bytes()).hexdigest(),digest,name)
 def test_normal_dependencies_and_no_install_hooks(self):
  p=(H/'PKGBUILD').read_text()
  for x in D['required_providers']:self.assertIn("'"+x+"'",p)
  for x in('--nodeps','--assume-installed','--skippgpcheck','pacman -','sudo ','post_install','curl ','wget '):self.assertNotIn(x,p)
  self.assertIn('conflicts=(\'qt6-declarative\')',p);self.assertNotIn('replaces=',p)
 def test_47_QML_imports_and_plugin_contracts_primary_join(self):
  self.assertEqual(len(D['qml_modules']),47);self.assertEqual(len({r['uri']for r in D['qml_modules']}),47)
  for r in D['qml_modules']:
   src=(H/'upstream/source'/r['source']).read_text();self.assertRegex(src,r'URI\s+"?'+re.escape(r['uri'])+r'"?(?:\s|$)');self.assertIn('import '+r['uri'],(H/'smoke.qml').read_text())
 def test_MODEL_qmldir_valid_and_missing_plugin_refuses(self):
  with tempfile.TemporaryDirectory()as t:
   p=Path(t)/'QtQuick';p.mkdir();(p/'qmldir').write_text('module QtQuick\nplugin qtquick2plugin\ntypeinfo plugins.qmltypes\n');(p/'plugins.qmltypes').write_text('MODEL');(p/'libqtquick2plugin.so').write_bytes(model_elf());row=[dict(uri='QtQuick',plugin='qtquick2plugin')];self.assertEqual(T.qml_contract(Path(t),row),1);(p/'libqtquick2plugin.so').unlink();self.assertRaises(ValueError,T.qml_contract,Path(t),row)
 def test_MODEL_wrong_URI_and_external_plugin_refuse(self):
  with tempfile.TemporaryDirectory()as t:
   p=Path(t)/'QtQuick';p.mkdir();row=[dict(uri='QtQuick',plugin='qtquick2plugin')]
   for text in('module Wrong\n','module QtQuick\nplugin qtquick2plugin /usr/foreign\n','module QtQuick\nplugin qtquick2plugin\nplugin duplicate\n'):
    (p/'qmldir').write_text(text);self.assertRaises(ValueError,T.qml_contract,Path(t),row)
 def test_MODEL_ELF_architecture_geometry_and_truncation(self):
  d=T.elf_info(model_elf('libQt6Quick.so.6'));self.assertEqual(d['soname'],'libQt6Quick.so.6');self.assertEqual(d['machine'],183)
  self.assertRaises(ValueError,T.elf_info,model_elf(machine=62));self.assertRaises(ValueError,T.elf_info,model_elf()[:80]);b=bytearray(model_elf());struct.pack_into('<Q',b,112,4096);self.assertRaises(ValueError,T.elf_info,bytes(b))
 def test_ELF_parser_whole_function_pinned_reuse(self):
  d=S.document(H/'ELF-PARSER-ORIGIN.DATA.json');text=(H/'check_stage.py').read_text();fn=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='elf_info');b=(ast.get_source_segment(text,fn)+'\n').encode();self.assertEqual(hashlib.sha256(b).hexdigest(),d['function_sha256'])
 def model_stage(self,root):
  def put(n,b):
   p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b);p.chmod(0o644)
  for m in D['required_shared_modules']:
   put('usr/lib/libQt6'+m+'.so.6.12.0',model_elf('libQt6'+m+'.so.6'));put('usr/lib/cmake/Qt6'+m+'/Qt6'+m+'Config.cmake',b'MODEL CMake API')
  for m in ('Qml','Quick'):put('usr/include/qt6/Qt'+m+'/6.12.0/Qt'+m+'/private/MODEL.h',b'MODEL private API')
  for n in D['required_cmake_packages']:put('usr/lib/cmake/'+n+'/'+n+'Config.cmake',b'MODEL private/build package')
  for n in D['required_pkgconfig']:put('usr/lib/pkgconfig/'+n+'.pc',b'MODEL pkgconfig API')
  for n in D['required_cmake_helpers']:put('usr/lib/cmake/'+n,b'MODEL QML build helper')
  for n in D['required_tools']:put('usr/lib/qt6/'+n,model_elf())
  for row in D['qml_modules']:
   base='usr/lib/qt6/qml/'+row['uri'].replace('.','/');plugin=row['plugin'];plugin=row['target']+'plugin'if plugin=='FROM_QMLDIR'else plugin;put(base+'/qmldir',('module '+row['uri']+'\n'+('plugin '+plugin+'\n'if plugin else'')+'typeinfo plugins.qmltypes\n').encode());put(base+'/plugins.qmltypes',b'MODEL type registration')
   if plugin:put(base+'/lib'+plugin+'.so',model_elf())
  for n in S.document(H/'source-notices.json')['source_notices']:put('usr/share/licenses/'+S.PACKAGE+'/source/'+n,(H/'upstream/source'/n).read_bytes())
 def test_MODEL_complete_stage_then_arch_and_notice_mutations_refuse(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);self.model_stage(root);report=T.check(root,H/'BUILD-CONTRACT.json',H/'source-notices.json');self.assertEqual(report['QML_modules'],47);self.assertIsNone(report['native_execution']);p=root/'usr/lib/libQt6Quick.so.6.12.0';old=p.read_bytes();p.write_bytes(model_elf('libQt6Quick.so.6',machine=62));self.assertRaises(ValueError,T.check,root,H/'BUILD-CONTRACT.json',H/'source-notices.json');p.write_bytes(old);p=root/('usr/share/licenses/'+S.PACKAGE+'/source/LICENSES/MIT.txt');p.write_bytes(b'MODEL corrupted notice');self.assertRaises(ValueError,T.check,root,H/'BUILD-CONTRACT.json',H/'source-notices.json')
 def test_MODEL_stage_alias_escape_and_permission_refuse(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);self.model_stage(root);alias=root/'usr/lib/libQt6Quick.so.6';alias.symlink_to('libQt6Quick.so.6.12.0');T.check(root,H/'BUILD-CONTRACT.json',H/'source-notices.json');alias.unlink();alias.symlink_to('/usr/lib/libc.so.6');self.assertRaises(ValueError,T.check,root,H/'BUILD-CONTRACT.json',H/'source-notices.json');alias.unlink();(root/'usr/lib/libQt6Quick.so.6.12.0').chmod(0o666);self.assertRaises(ValueError,T.check,root,H/'BUILD-CONTRACT.json',H/'source-notices.json')
 def test_empty_stage_cannot_be_claimed_complete(self):
  with tempfile.TemporaryDirectory()as t:self.assertRaises(ValueError,T.check,Path(t),H/'BUILD-CONTRACT.json',H/'source-notices.json')
 def test_configuration_rejects_silent_feature_loss(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);rows=dict(CMAKE_BUILD_TYPE='Release',CMAKE_INSTALL_PREFIX='/usr',BUILD_SHARED_LIBS='ON',QT_BUILD_TESTS='OFF');rows.update({'QT_FEATURE_'+x:'ON'for x in D['required_features']});rows['QT_FEATURE_quick_dialogs']='OFF';(root/'CMakeCache.txt').write_text(''.join(k+':STRING='+v+'\n'for k,v in rows.items()));self.assertRaisesRegex(ValueError,'required feature absent quick_dialogs',S.configuration,root,H/'BUILD-CONTRACT.json')
 def test_no_product_personal_paths_or_runtime_acceptance(self):
  for n in('PKGBUILD','configure.cmake','dependency_guard.cmake','source.py','check_stage.py','SmokeCMakeLists.txt','smoke.cpp','smoke.qml'):
   b=(H/n).read_bytes();self.assertNotIn(b'/home/',b,n)
  self.assertIsNone(D['Root_acceptance']);self.assertIsNone(D['native']);self.assertIn('NOT_CLAIMED',D['optional_developer_component']['qmlls'])
if __name__=='__main__':unittest.main(verbosity=2)

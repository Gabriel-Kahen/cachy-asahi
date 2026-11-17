#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pinned actual archive controls and explicitly MODEL payload/reflection fixtures."""
import argparse,ast,copy,hashlib,importlib.util,json,re,struct,sys,tarfile,tempfile,unittest
from pathlib import Path,PurePosixPath
H=Path(__file__).resolve().parent
A=argparse.ArgumentParser(add_help=False);A.add_argument('--archive',type=Path,default=H/'upstream/qtshadertools-everywhere-src-6.12.0.tar.xz');ARGS,REST=A.parse_known_args()
for name in('source','elf','check_stage','reflection'):
 spec=importlib.util.spec_from_file_location(name,H/(name+'.py'));module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
S=sys.modules['source'];E=sys.modules['elf'];T=sys.modules['check_stage'];R=sys.modules['reflection'];D=S.document(H/'BUILD-CONTRACT.json')

def model_elf(soname=None,needed=(),executable=False,machine=183):
 b=bytearray(1024);b[:7]=b'\x7fELF\x02\x01\x01';struct.pack_into('<HHI',b,16,3,machine,1);struct.pack_into('<Q',b,32,64);struct.pack_into('<HHH',b,52,64,56,3 if executable else 2);struct.pack_into('<IIQQQQQQ',b,64,1,5,0,0x4000,0x4000,len(b),len(b),16384);strings=bytearray(b'\0');entries=[]
 for name in needed:entries.append((1,len(strings)));strings.extend(name.encode()+b'\0')
 if soname:entries.append((14,len(strings)));strings.extend(soname.encode()+b'\0')
 entries.extend(((5,0x4200),(10,len(strings)),(0,0)));b[512:512+len(strings)]=strings;struct.pack_into('<IIQQQQQQ',b,120,2,6,256,0x4100,0x4100,len(entries)*16,len(entries)*16,8)
 for i,row in enumerate(entries):struct.pack_into('<qQ',b,256+i*16,*row)
 if executable:
  interpreter=b'/lib/ld-linux-aarch64.so.1\0';b[768:768+len(interpreter)]=interpreter;struct.pack_into('<IIQQQQQQ',b,176,3,4,768,0x4300,0x4300,len(interpreter),len(interpreter),1)
 return bytes(b)

def model_reflection(stage):
 name,kind,size=('mvp','mat4',64)if stage=='vertex'else('opacity','float',4);member=dict(name=name,type=kind,size=size,offset=0)
 if stage=='vertex':member['matrixStride']=16
 d=dict(inputs=[dict(name='iPosition'if stage=='vertex'else'vColor',type='vec4',location=0)],outputs=[dict(name='vColor'if stage=='vertex'else'fragColor',type='vec4',location=0)],uniformBlocks=[dict(blockName='buf',binding=0,set=0,size=size,members=[member])])
 if stage=='fragment':d['combinedImageSamplers']=[dict(name='uTexture',type='sampler2D',binding=1,set=0)]
 return d
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(c):
  b=S.ordinary(ARGS.archive,8*1024**2);S.need(hashlib.sha256(b).hexdigest()=='c7d84f436e1aaef39fdcadebf2bd71bdf24dc69497e13f2e0198873cbbfea2ab','genuine whole pinned component archive required');c.temp=tempfile.TemporaryDirectory(prefix='qt612-shader-DATA-');c.root=Path(c.temp.name);total=0;count=0
  with tarfile.open(ARGS.archive)as archive:
   for m in archive:
    count+=1;total+=m.size;S.need(count<=1024 and total<=16*1024**2,'finite component source');name=PurePosixPath(m.name);S.need(name.parts[0]=='qtshadertools-everywhere-src-6.12.0'and '..'not in name.parts and not name.is_absolute(),'fixed archive namespace')
    if m.isdir():continue
    S.need(m.isfile(),'no special archive members');n=Path(*name.parts[1:]);p=c.root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(archive.extractfile(m).read())
 @classmethod
 def tearDownClass(c):c.temp.cleanup()
 def test_actual_component_commit_tree_and_template(self):
  api=S.document(H/'upstream/commit.DATA.json');self.assertEqual(api['sha'],D['release_commit']);self.assertEqual(api['tree']['sha'],D['release_tree']);self.assertEqual((H/'upstream/tag-template.txt').read_bytes(),b'$Format:%H$\n');self.assertEqual((self.root/'.tag').read_text().strip(),D['release_commit']);self.assertNotEqual(D['release_tree'],D['release_commit'])
 def test_actual_primary_source_checksum_agreement(self):
  digest='c7d84f436e1aaef39fdcadebf2bd71bdf24dc69497e13f2e0198873cbbfea2ab'
  for n in('upstream/archive.sha256','upstream/archive.mirrorlist.html','PKGBUILD'):self.assertIn(digest,(H/n).read_text())
 def test_actual_selected_source_and_notices(self):
  for n,r in S.document(H/'upstream/selected-source.lock.json').items():
   b=S.ordinary(self.root/n);self.assertEqual(b,S.ordinary(H/'upstream/source'/n));self.assertEqual(dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest()),{k:r[k]for k in('bytes','sha256')})
  self.assertEqual(len(S.verify(self.root,H/'source-notices.json')),19)
 def test_actual168_vendored_inputs_complete(self):
  r=S.vendors(self.root,H/'vendored-inputs.lock.json');self.assertEqual(r,dict(files=168,bytes=9682834))
 def test_added_vendor_member_refuses(self):
  p=self.root/'src/3rdparty/MODEL-extra';p.write_bytes(b'MODEL unpinned member')
  try:self.assertRaises(ValueError,S.vendors,self.root,H/'vendored-inputs.lock.json')
  finally:p.unlink()
 def test_actual_vendor_license_and_build_backend_correspondence(self):
  notices=S.document(H/'source-notices.json')['source_notices']
  for stem in('src/3rdparty/glslang','src/3rdparty/SPIRV-Cross'):
   for row in S.document(self.root/stem/'qt_attribution.json'):
    for field in('LicenseFile','CopyrightFile'):
     if field in row:self.assertIn(stem+'/'+row[field],notices)
  cmake=(self.root/'src/shadertools/CMakeLists.txt').read_text();self.assertIn('Qt::BundledSpirv_Cross',cmake);self.assertIn('Qt::BundledGlslang_Glslang',cmake);cross=(self.root/'src/SPIRV-Cross/CMakeLists.txt').read_text()
  for backend in('GLSL','HLSL','MSL'):self.assertIn('SPIRV_CROSS_C_API_'+backend+'=1',cross)
 def test_modified_vendor_policy_or_notice_refuses(self):
  with tempfile.TemporaryDirectory()as t:
   p=Path(t)/'policy';d=S.document(H/'vendored-inputs.lock.json');next(iter(d['files'].values()))['sha256']='0'*64;p.write_text(json.dumps(d));self.assertRaises(ValueError,S.vendors,self.root,p);d=S.document(H/'source-notices.json');d['source_notices']['LICENSES/MIT.txt']='0'*64;p.write_text(json.dumps(d));self.assertRaises(ValueError,S.verify,self.root,p)
 def test_no_silent_GUI_tool_skip_or_wrong_version_fallback(self):
  actual=(self.root/'CMakeLists.txt').read_text();self.assertIn('if(NOT TARGET Qt::Gui)',actual);guard=(H/'dependency_guard.cmake').read_text();self.assertIn('6.12.0 EXACT CONFIG REQUIRED',guard);self.assertIn('Qt6::GuiPrivate',guard);self.assertIn('QT_NO_PACKAGE_VERSION_CHECK',guard);self.assertIn('real qsb and shared-library build rules', (H/'source.py').read_text())
 def test_MODEL_configuration_requires_real_qsb_build_rule(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);(root/'CMakeCache.txt').write_text('CMAKE_INSTALL_PREFIX:PATH=/usr\nCMAKE_BUILD_TYPE:STRING=Release\nBUILD_SHARED_LIBS:BOOL=ON\n')
   for name in D['cmake_packages']:
    p=root/'lib/cmake'/name/(name+'Config.cmake');p.parent.mkdir(parents=True);p.write_text('MODEL')
   p=root/'build.ninja';p.write_text('build lib/qt6/bin/qsb: MODEL\nbuild lib/libQt6ShaderTools.so.6.12.0: MODEL\n');self.assertEqual(S.configuration(root)['status'],'SHADERTOOLS_QSB_AND_APIS_PRESENT');p.write_text('MODEL skipped tools\n');self.assertRaises(ValueError,S.configuration,root)
 def test_public_RHI_private_and_tools_api_primary_join(self):
  module=(self.root/'src/shadertools/CMakeLists.txt').read_text();self.assertIn('RHI_HEADER_FILTERS',module);self.assertIn('qshaderbaker',module);self.assertIn('qspirvcompiler_p.h',module);tool=(self.root/'tools/qsb/CMakeLists.txt').read_text();self.assertIn('ShaderToolsMacros.cmake',tool);self.assertIn('TOOLS_TARGET',tool);helpers=(H/'upstream/QtToolHelpers.cmake').read_text();self.assertIn('set(install_dir "${INSTALL_BINDIR}")',helpers);self.assertIn('files that will be included in the Qt6${module}Tools.cmake file',helpers)
 def test_model_reflection_valid_both_stages(self):
  for stage in('vertex','fragment'):self.assertTrue(R.check_reflection(model_reflection(stage),stage))
 def test_model_reflection_geometry_binding_and_duplicates_refuse(self):
  for field,value in(('binding',2),('set',True),('size',65)):
   d=model_reflection('vertex');d['uniformBlocks'][0][field]=value;self.assertRaises(ValueError,R.check_reflection,d,'vertex')
  d=model_reflection('fragment');d['combinedImageSamplers'][0]['binding']=0;self.assertRaises(ValueError,R.check_reflection,d,'fragment');d=model_reflection('vertex');d['inputs']*=2;self.assertRaises(ValueError,R.check_reflection,d,'vertex');self.assertRaises(ValueError,json.loads,'{"binding":0,"binding":1}',object_pairs_hook=R.no_duplicates)
 def test_model_finite_reflection_files_and_corrupt_spirv(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);(root/'qsb-version.txt').write_text('qsb 6.12.0\n')
   for stage in('vertex','fragment'):
    (root/(stage+'.json')).write_text(json.dumps(model_reflection(stage)));(root/(stage+'.spv')).write_bytes(struct.pack('<5I',0x07230203,0x10000,0,1,0))
    for ext,text in(('glsl','#version 150\nMODEL'),('hlsl','cbuffer MODEL'),('msl','metal_stdlib MODEL')):(root/(stage+'.'+ext)).write_text(text)
   self.assertEqual(R.check(root)['status'],'PASS_FINITE_SHADER_COMPILE_REFLECTION_ONLY');(root/'vertex.spv').write_bytes(b'MODEL');self.assertRaises(ValueError,R.check,root)
 def model_stage(self,root):
  def put(n,b,mode=0o644):
   p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b);p.chmod(mode)
  put(D['qsb'],model_elf(needed=['libQt6ShaderTools.so.6','libQt6Core.so.6','libQt6Gui.so.6'],executable=True),0o755);put(D['shared_library'],model_elf(D['SONAME'],['libQt6Core.so.6','libQt6Gui.so.6']))
  for key in('pkgconfig','RHI_header','private_header','public_header'):put(D[key],b'MODEL API')
  for name in D['cmake_packages']:put('usr/lib/cmake/'+name+'/'+name+'Config.cmake',b'MODEL CMake API')
  put(D['cmake_macro'],b'function(qt6_add_shaders target)\nendfunction()\n');put('usr/lib/cmake/Qt6ShaderToolsTools/Qt6ShaderToolsToolsTargets.cmake',b'add_executable(Qt6::qsb IMPORTED)')
  for n in S.document(H/'source-notices.json')['source_notices']:put('usr/share/licenses/'+S.PACKAGE+'/source/'+n,(self.root/n).read_bytes())
 def test_MODEL_complete_stage_and_wrong_arch_refusal(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);self.model_stage(root);r=T.check(root,H/'BUILD-CONTRACT.json',H/'source-notices.json');self.assertEqual(r['ELF'],2);self.assertIsNone(r['native_execution']);(root/D['qsb']).write_bytes(model_elf(needed=['libQt6ShaderTools.so.6'],executable=True,machine=62));self.assertRaises(ValueError,T.check,root,H/'BUILD-CONTRACT.json',H/'source-notices.json')
 def test_MODEL_unknown_system_vendor_and_ownership_refuse(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);self.model_stage(root);(root/D['qsb']).write_bytes(model_elf(needed=['libQt6ShaderTools.so.6','libglslang.so'],executable=True));self.assertRaises(ValueError,T.check,root,H/'BUILD-CONTRACT.json',H/'source-notices.json');self.model_stage(root);p=root/'usr/lib/libQt6Core.so.6';p.write_bytes(model_elf());self.assertRaises(ValueError,T.check,root,H/'BUILD-CONTRACT.json',H/'source-notices.json')
 def test_MODEL_escaping_alias_refuses(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);self.model_stage(root);p=root/'usr/lib/libQt6ShaderTools.so.6';p.symlink_to('libQt6ShaderTools.so.6.12.0');T.check(root,H/'BUILD-CONTRACT.json',H/'source-notices.json');p.unlink();p.symlink_to('/usr/lib/libQt6ShaderTools.so.6');self.assertRaises(ValueError,T.check,root,H/'BUILD-CONTRACT.json',H/'source-notices.json')
 def test_maintained_ELF_parser_exact_and_boundary_refusals(self):
  d=S.document(H/'ELF-PARSER-ORIGIN.DATA.json');text=(H/'elf.py').read_text();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='elf_info');b=(ast.get_source_segment(text,node)+'\n').encode();self.assertEqual(hashlib.sha256(b).hexdigest(),d['function_sha256']);self.assertRaises(ValueError,E.elf_info,model_elf()[:80]);self.assertRaises(ValueError,E.elf_info,model_elf(machine=62))
 def test_source_checksums_and_normal_dependency_no_hooks(self):
  text=(H/'.SRCINFO').read_text();names=re.findall(r'^\s*source = (.+)$',text,re.M);digests=re.findall(r'^\s*sha256sums = ([0-9a-f]{64})$',text,re.M);self.assertEqual(len(names),16);self.assertEqual(len(names),len(digests))
  for n,d in zip(names[1:],digests[1:]):self.assertEqual(hashlib.sha256((H/n).read_bytes()).hexdigest(),d,n)
  pkg=(H/'PKGBUILD').read_text();self.assertIn("'cachy-asahi-qt612-gui-server-source-reference=6.12.0'",pkg)
  for x in('--nodeps','--assume-installed','--skippgpcheck','sudo ','pacman -','install=','replaces='):self.assertNotIn(x,pkg)
 def test_smoke_is_finite_own_qsb_no_native_external_compilers(self):
  pkg=(H/'PKGBUILD').read_text();self.assertIn('local qsb="$srcdir/build/lib/qt6/bin/qsb"',pkg);self.assertIn('for stage in vertex fragment',pkg);self.assertEqual(pkg.count('--qt6'),2);self.assertIn('Equivalent to --glsl', (self.root/'tools/qsb/qsb.cpp').read_text())
  for x in('-x reflect','-x spirv,100','-x glsl,150','-x hlsl,50','-x msl,12','timeout 60'):self.assertIn(x,pkg)
  for x in('--fxc','--metallib','spirv-opt',' PRECOMPILE',' OPTIMIZED'):self.assertNotIn(x,pkg+(H/'SmokeCMakeLists.txt').read_text())
  for n in('PKGBUILD','source.py','elf.py','check_stage.py','reflection.py','smoke.cpp','SmokeCMakeLists.txt'):self.assertNotIn('/home/',(H/n).read_text(),n)
  self.assertIsNone(D['Root_acceptance']);self.assertIsNone(D['native']);self.assertIsNone(D['hardware'])
if __name__=='__main__':unittest.main(argv=['test_recipe.py',*REST],verbosity=2)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Strict finite ShaderTools DESTDIR inspection; never load target ELF."""
import argparse,hashlib,json,os,stat
from pathlib import Path
from source import PACKAGE,need,document,ordinary
from elf import elf_info

def check(root,contract,notices):
 root=Path(root);need(root.is_absolute()and root==root.resolve()and root!=Path('/'),'canonical separate stage');d=document(contract);nodes=list(root.rglob('*'));need(0<len(nodes)<=8192,'finite staged namespace');files={};ELF={};total=0
 for p in nodes:
  n=p.relative_to(root).as_posix();s=p.lstat();need((n=='usr'or n.startswith('usr/'))and not(s.st_mode&0o6000),'only usr payload, no privilege bits')
  if stat.S_ISDIR(s.st_mode):continue
  exact={d[k]for k in('qsb','shared_library','pkgconfig','RHI_header','private_header','public_header')}|{'usr/lib/libQt6ShaderTools.so','usr/lib/libQt6ShaderTools.so.6','usr/lib/libQt6ShaderTools.prl','usr/lib/cmake/Qt6BuildInternals/StandaloneTests/QtShaderToolsTestsConfig.cmake'}
  allowed_path=n in exact or any(n.startswith('usr/lib/cmake/'+package+'/')for package in d['cmake_packages'])or n.startswith(('usr/include/qt6/QtShaderTools/','usr/share/licenses/'+PACKAGE+'/','usr/lib/qt6/mkspecs/modules/qt_lib_shadertools','usr/lib/qt6/metatypes/qt6shadertools','usr/lib/qt6/modules/ShaderTools','usr/lib/qt6/sbom/qtshadertools'))
  need(allowed_path,'unexpected ownership outside ShaderTools namespace '+n)
  if stat.S_ISLNK(s.st_mode):need(not Path(os.readlink(p)).is_absolute()and p.resolve().is_relative_to(root)and p.resolve().is_file(),'internal ordinary file alias');continue
  need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and not(s.st_mode&0o022)and 0<s.st_size<=64*1024**2,'ordinary bounded private-written payload');b=p.read_bytes();total+=len(b);need(total<=256*1024**2,'finite payload bytes');files[n]=b
  if b.startswith(b'\x7fELF'):ELF[n]=elf_info(b)
 need(d['qsb']in ELF and ELF[d['qsb']]['interpreter']=='/lib/ld-linux-aarch64.so.1','normal AArch64 qsb executable/loader required');need(root.joinpath(d['qsb']).stat().st_mode&0o111,'qsb executable permission')
 need(d['shared_library']in ELF and ELF[d['shared_library']]['soname']==d['SONAME'],'exact shared ShaderTools SONAME');need('libQt6ShaderTools.so.6'in ELF[d['qsb']]['needed'],'qsb must link own shared ShaderTools provider')
 for name in d['cmake_packages']:need('usr/lib/cmake/'+name+'/'+name+'Config.cmake'in files,'CMake API missing '+name)
 for key in('cmake_macro','pkgconfig','RHI_header','private_header','public_header'):need(d[key]in files,'required API/header missing '+key)
 macros=files[d['cmake_macro']];need(b'function(qt6_add_shaders'in macros,'normal qt6_add_shaders macro export');need(any(b'Qt6::qsb'in b for n,b in files.items()if n.startswith('usr/lib/cmake/Qt6ShaderToolsTools/')),'normal imported qsb tool target')
 for n,sha in document(notices)['source_notices'].items():need(hashlib.sha256(files.get('usr/share/licenses/'+PACKAGE+'/source/'+n,b'')).hexdigest()==sha,'complete exact vendored/source notices '+n)
 allowed={'libQt6ShaderTools.so.6','libQt6Core.so.6','libQt6Gui.so.6','libstdc++.so.6','libgcc_s.so.1','libc.so.6','libm.so.6','libpthread.so.0','libdl.so.2','librt.so.1','ld-linux-aarch64.so.1'};needed={n for row in ELF.values()for n in row['needed']};need(needed<=allowed,'undeclared dependency/system-vendor substitution '+str(needed-allowed));need(not any(n.startswith(('usr/lib/systemd/','usr/share/libalpm/'))for n in files),'no service or ALPM hooks')
 return dict(status='PASS_STAGED_BYTES_ONLY',files=len(files),bytes=total,ELF=len(ELF),elf_metadata=ELF,DT_NEEDED=sorted(needed),qsb=d['qsb'],native_execution=None,hardware=None,Root_acceptance=None)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--contract',type=Path,required=True);p.add_argument('--notices',type=Path,required=True);a=p.parse_args();print(json.dumps(check(a.root,a.contract,a.notices),indent=2,sort_keys=True))

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite source, notice and configuration checks. No installation outside DESTDIR."""
import argparse,hashlib,json,os,re,stat
from pathlib import Path,PurePosixPath
PACKAGE='cachy-asahi-qt612-shadertools-source-reference'
REVISION='bccd516b990a6396900051470ac86cc27a7042ea'
TREE='00cf97838baca2f2b1a4833f6498ca39e6e073ec'
def need(ok,why):
 if not ok:raise ValueError(why)
def ordinary(path, cap=4 * 1024**2):
    path = Path(path)
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary non-symlink path')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap,
         'finite single-link file')
    body = path.read_bytes()
    # Reading can change atime without changing the input.
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
              'st_size', 'st_mtime_ns', 'st_ctime_ns')
    after = path.lstat()
    need(len(body) == before.st_size and all(getattr(before, k) == getattr(after, k) for k in fields),
         'stable complete bytes')
    return body
def document(p):return json.loads(ordinary(p))
def verify(root,policy):
 root=Path(root);rows=document(policy);need(set(rows)=={'schema_version','source_notices'}and rows['schema_version']==1 and 1<=len(rows['source_notices'])<=512,'closed notice schema');need(ordinary(root/'.tag').decode().strip()==REVISION,'exact ShaderTools release commit (upstream .tag uses %H)' );need(b'set(QT_REPO_MODULE_VERSION "6.12.0")'in ordinary(root/'.cmake.conf'),'exact source version')
 for n,digest in rows['source_notices'].items():
  p=PurePosixPath(n);need(not p.is_absolute()and p.as_posix()==n and '..'not in p.parts and re.fullmatch('[0-9a-f]{64}',digest),'canonical notice reference');need(hashlib.sha256(ordinary(root/n)).hexdigest()==digest,'exact source notice '+n)
 return rows['source_notices']
def install_notices(root,policy,stage):
 rows=verify(root,policy);stage=Path(stage);uid=next(l.split()[1:]for l in Path('/proc/self/status').read_text().splitlines()if l.startswith('Uid:'));need(len(uid)==4 and len(set(uid))==1 and int(uid[0])>0,'real unprivileged package process');need(stage.is_absolute()and stage==stage.resolve()and stage.name==PACKAGE and stage.is_dir()and stage.stat().st_uid==os.getuid()and not(stage.stat().st_mode&0o022),'own private package DESTDIR');dest=stage/'usr/share/licenses'/PACKAGE/'source';need(not dest.exists()and not any(p.is_symlink()for p in dest.parents),'fresh notice destination')
 for n in rows:
  p=dest/n;p.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
  with p.open('xb')as f:f.write(ordinary(Path(root)/n));os.fchmod(f.fileno(),0o644)
 return dict(status='DESTDIR_NOTICE_COPY_ONLY',notices=len(rows))
def vendors(root,policy):
 rows=document(policy);need(set(rows)=={'schema','scope','files'}and rows['schema']==1 and 1<=len(rows['files'])<=512,'closed finite vendor policy');nodes=list((Path(root)/'src/3rdparty').rglob('*'));need(len(nodes)<=1024 and not any(p.is_symlink()for p in nodes),'bounded ordinary vendor namespace');need({p.relative_to(root).as_posix()for p in nodes if p.is_file()}==set(rows['files']),'exact complete vendor membership');total=0
 for name,row in rows['files'].items():
  p=PurePosixPath(name);need(p.as_posix()==name and name.startswith('src/3rdparty/')and '..'not in p.parts,'fixed vendor source namespace');b=ordinary(Path(root)/name);total+=len(b);need(dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())==row,'exact bundled vendor source '+name)
 need(total<=16*1024**2,'finite vendor input bytes');return dict(files=len(rows['files']),bytes=total)
def configuration(build):
 build=Path(build);cache=ordinary(build/'CMakeCache.txt',16*1024**2).decode();rows={}
 for line in cache.splitlines():
  match=re.fullmatch(r'([^/#][^:]*):[^=]*=(.*)',line)
  if match:need(match[1]not in rows,'duplicate cache field');rows[match[1]]=match[2]
 need(rows.get('CMAKE_INSTALL_PREFIX')=='/usr'and rows.get('CMAKE_BUILD_TYPE')=='Release'and rows.get('BUILD_SHARED_LIBS')in('ON','TRUE','1'),'release/shared/package prefix')
 for name in('Qt6ShaderTools','Qt6ShaderToolsPrivate','Qt6ShaderToolsTools'):need((build/'lib/cmake'/name/(name+'Config.cmake')).is_file(),'required exported ShaderTools API '+name)
 ninja=ordinary(build/'build.ninja',32*1024**2).decode();need(re.search(r'^build lib/qt6/bin/qsb:',ninja,re.M)and re.search(r'^build lib/libQt6ShaderTools\.so\.6\.12\.0:',ninja,re.M),'real qsb and shared-library build rules required; no empty skipped configure');return dict(status='SHADERTOOLS_QSB_AND_APIS_PRESENT')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=('verify','install-notices','configuration'));p.add_argument('--root',type=Path);p.add_argument('--policy',type=Path);p.add_argument('--vendors',type=Path);p.add_argument('--stage',type=Path);p.add_argument('--build',type=Path);a=p.parse_args()
 if a.operation=='configuration':r=configuration(a.build)
 elif a.operation=='verify':r=dict(status='SOURCE_NOTICES_AND_VENDORS_VERIFIED',notices=len(verify(a.root,a.policy)),vendors=vendors(a.root,a.vendors))
 else:r=install_notices(a.root,a.policy,a.stage)
 print(json.dumps(r,sort_keys=True))

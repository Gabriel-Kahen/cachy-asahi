#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite source, notice and configuration checks. No installation outside DESTDIR."""
import argparse,hashlib,json,os,re,stat
from pathlib import Path,PurePosixPath
PACKAGE='cachy-asahi-qt612-declarative-source-reference'
REVISION='4332fbbb4c340463dc8cee36dda0c85d932122d8'
TREE='98324181f2eebf01e806603a01829a40b8683631'
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
 root=Path(root);rows=document(policy);need(set(rows)=={'schema_version','source_notices'}and rows['schema_version']==1 and 1<=len(rows['source_notices'])<=512,'closed notice schema');need(ordinary(root/'.tag').decode().strip()==TREE,'exact release source tree (upstream .tag uses %T)' );need(b'set(QT_REPO_MODULE_VERSION "6.12.0")'in ordinary(root/'.cmake.conf'),'exact source version')
 for n,digest in rows['source_notices'].items():
  p=PurePosixPath(n);need(not p.is_absolute()and p.as_posix()==n and '..'not in p.parts and re.fullmatch('[0-9a-f]{64}',digest),'canonical notice reference');need(hashlib.sha256(ordinary(root/n)).hexdigest()==digest,'exact source notice '+n)
 return rows['source_notices']
def install_notices(root,policy,stage):
 rows=verify(root,policy);stage=Path(stage);uid=next(l.split()[1:]for l in Path('/proc/self/status').read_text().splitlines()if l.startswith('Uid:'));need(len(uid)==4 and len(set(uid))==1 and int(uid[0])>0,'real unprivileged package process');need(stage.is_absolute()and stage==stage.resolve()and stage.name==PACKAGE and stage.is_dir()and stage.stat().st_uid==os.getuid()and not(stage.stat().st_mode&0o022),'own private package DESTDIR');dest=stage/'usr/share/licenses'/PACKAGE/'source';need(not dest.exists()and not any(p.is_symlink()for p in dest.parents),'fresh notice destination')
 for n in rows:
  p=dest/n;p.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
  with p.open('xb')as f:f.write(ordinary(Path(root)/n));os.fchmod(f.fileno(),0o644)
 return dict(status='DESTDIR_NOTICE_COPY_ONLY',notices=len(rows))
def configuration(build,contract):
 d=document(contract);cache=ordinary(Path(build)/'CMakeCache.txt',16*1024**2).decode();rows={}
 for line in cache.splitlines():
  m=re.fullmatch(r'([^/#][^:]*):[^=]*=(.*)',line)
  if m:need(m[1]not in rows,'duplicate cache field');rows[m[1]]=m[2]
 need(rows.get('CMAKE_BUILD_TYPE')=='Release'and rows.get('CMAKE_INSTALL_PREFIX')=='/usr','release and package prefix');need(rows.get('BUILD_SHARED_LIBS')in('ON','TRUE','1'),'shared libraries');need(rows.get('QT_BUILD_TESTS')in('OFF','FALSE','0'),'upstream tests excluded from this finite smoke profile')
 for feature in d['required_features']:need(rows.get('QT_FEATURE_'+feature)in('ON','TRUE','1'),'required feature absent '+feature)
 for module in d['required_shared_modules']:need((Path(build)/'lib/cmake'/('Qt6'+module)/('Qt6'+module+'Config.cmake')).is_file(),'required module skipped '+module)
 for package in d['required_cmake_packages']:need((Path(build)/'lib/cmake'/package/(package+'Config.cmake')).is_file(),'required exported build/private API '+package)
 for helper in d['required_cmake_helpers']:need((Path(build)/'lib/cmake'/helper).is_file(),'required QML build interface '+helper)
 return dict(status='REQUIRED_QML_QUICK_FEATURES_PRESENT',features=len(d['required_features']))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('operation',choices=('verify','install-notices','configuration'));p.add_argument('--root',type=Path);p.add_argument('--policy',type=Path);p.add_argument('--stage',type=Path);p.add_argument('--build',type=Path);p.add_argument('--contract',type=Path);a=p.parse_args()
 if a.operation=='configuration':r=configuration(a.build,a.contract)
 elif a.operation=='verify':r=dict(status='SOURCE_NOTICES_VERIFIED',notices=len(verify(a.root,a.policy)))
 else:r=install_notices(a.root,a.policy,a.stage)
 print(json.dumps(r,sort_keys=True))

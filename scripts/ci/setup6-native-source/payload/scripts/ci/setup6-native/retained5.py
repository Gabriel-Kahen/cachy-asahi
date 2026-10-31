# SPDX-License-Identifier: MIT
"""Exact public Setup5 bodies as passive inputs for a fresh installed continuation."""
import json,shutil,stat
from pathlib import Path
import contract as C
HERE=Path(__file__).resolve().parent
ARCHIVE='cachy-asahi-setup-0.1.0-5-any.pkg.tar.xz'
SHA='1aafee365e3bcb04e1fce694c110a997914a07f4359697df5e017375897385fc'
def verify(root):
 p=json.loads((HERE/'setup5-carrier.json').read_bytes());C.safe(root);C.need(not any(q.is_symlink()for q in root.rglob('*')if'.git'not in q.relative_to(root).parts),'no retained5 source aliases');actual={q.relative_to(root).as_posix()for q in root.rglob('*')if not q.is_dir()and'.git'not in q.relative_to(root).parts};C.need(actual==set(p['files'])and len(actual)==149 and p['source']=='79d8d2f53510e4f3a04f39c1b1e24c999aa32e44','whole exact public Setup5 source')
 for n,row in p['files'].items():
  q=root/n;C.safe(q);s=q.lstat();C.need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size==row['bytes']and C.digest(q)==row['sha256'],'whole exact retained Setup5 input '+n)
 index=json.loads((root/'index.json').read_bytes());C.need(index['native_run']==38934198468 and index['native_source']==p['native_source']and index['archive_bytes']==26872 and index['archive_sha256']==SHA,'original native Setup5 body provenance');return p

def stage(root,context,source,checks,bind):
 p=verify(root);reports=[]
 for side in('a','b'):
  path=root/'packages'/('cachy-asahi-setup-'+side)/ARCHIVE;report=checks.package(path);meta=checks.metadata((root/'source/cachy-asahi-setup/.SRCINFO').read_text());C.need(path.stat().st_size==26872 and C.digest(path)==SHA and not report['errors']and not report['elf']and not bind.bind_artifact(meta,report,C.digest(root/'source/cachy-asahi-setup/PKGBUILD')),'complete original retained5 static/recipe/body checks');reports.append(report)
 C.need(reports[0]==reports[1],'complete retained5 pair package reports')
 payload={n:r for n,r in reports[0]['members'].items()if r['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')};C.need(set(payload)==set(C.files()),'complete retained5 six-file payload')
 for n,(original,mode)in C.files().items():
  row=payload[n];C.need(row['type']=='0'and row['mode']==mode and row['uid']==row['gid']==0 and row['sha256']==C.digest(root/'source/cachy-asahi-setup'/original),'retained5 full payload/source/license binding')
 out=context/'setup5';out.mkdir();shutil.copyfile(root/'packages/cachy-asahi-setup-a'/ARCHIVE,out/ARCHIVE);(out/'product.json').write_text(json.dumps(dict(version='0.1.0-5',archive=ARCHIVE,sha256=SHA,payload=payload),sort_keys=True,indent=2)+'\n');dest=context/'retained-setup5';dest.mkdir()
 for n in p['files']:
  target=dest/n;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/n,target)
 tests=context/'setup6-tests';tests.mkdir()
 for n in('setup.py','test_setup.py','test_shell_modules.py','test_recovery_preview.py'):shutil.copyfile(source/'scripts/setup'/n,tests/n)

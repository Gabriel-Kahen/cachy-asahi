# SPDX-License-Identifier: MIT
"""Join two independently archive-checked contexts from the SAME producer."""
import shutil
from pathlib import Path
import contract as C,lifecycle,roles

def compose(*,apps_context,welcome_context,output):
 """Called after native192 Apps inputs and four fresh Welcome builders qualify.

 No carrier73 or future Root decision is manufactured here. Existing bound
 constructors create each input context, including its complete archive report,
 exact signatures and source fixtures; this join independently reopens archives.
 """
 C.need(output.is_absolute()and not output.exists()and not output.is_symlink(),'fresh owned joint input output')
 plans={role:C.decode(C.ordinary(home/'lifecycle-plan.json',4*1024**2))for role,home in [('apps',apps_context),('welcome',welcome_context)]};apis={k:roles.load(k)for k in plans};lifecycle.operands(plans,apis)
 inspector=__import__('importlib').util.spec_from_file_location('_joint_input_inspector',Path(__file__).resolve().parents[3]/'held-apps-worker/held-apps/checks/package_checks.py');checks=__import__('importlib').util.module_from_spec(inspector);inspector.loader.exec_module(checks)
 for role,keys in [('apps',('original6','new7','runtime')),('welcome',('original4','new5'))]:
  home=apps_context if role=='apps'else welcome_context;P=apis[role]['plan']
  for key in keys:
   row=plans[role][key];p=Path(row['path']);C.need(p.parent==Path('/runner/inputs/archives')and p.name not in('.','..'),'fixed selected archive');a=home/'archives'/p.name
   C.need(C.pin(C.ordinary(a,64*1024**2))=={k:row[k]for k in('bytes','sha256')}and row['signature']['path']==str(p)+'.sig'and C.pin(C.ordinary(a.with_name(a.name+'.sig'),65536))=={k:row['signature'][k]for k in('bytes','sha256')},'whole original/new selected archive/signature')
   report=checks.package(a)
   wanted=P.archive_fields(report,row,name='cachy-asahi-repository-runtime'if key=='runtime'else'cachy-asahi-apps')if role=='apps'else P.archive_fields(report,row)
   C.need(all(row[k]==v for k,v in wanted.items()),'independent complete archive PKGINFO/rawMTREE/full payload')
  for row in plans[role]['verification_keys']:
   p=Path(row['path']);C.need(p.parent==Path('/runner/inputs/keys')and C.pin(C.ordinary(home/'keys'/p.name,65536))=={k:row[k]for k in('bytes','sha256')},'exact original/native public TEST key')
 original=plans['apps']['original6']['signer'];C.need(plans['welcome']['verification_keys'][0]['signer']==original and len(plans['welcome']['verification_keys'])==1,'same original producer TEST role')
 oldkey=next(r for r in plans['apps']['verification_keys']if r['signer']==original);welkey=plans['welcome']['verification_keys'][0]
 C.need({k:oldkey[k]for k in('bytes','sha256')}=={k:welkey[k]for k in('bytes','sha256')},'same producer TEST key bytes, never just same fingerprint')
 output.mkdir(mode=0o700)
 for home in(apps_context,welcome_context):
  C.need(not any(p.is_symlink()for p in(home,*home.parents)),'ordinary constructor context')
  for p in sorted(home.rglob('*')):
   C.need(not p.is_symlink(),'input context alias');relative=p.relative_to(home)
   if p.is_dir()or relative==Path('lifecycle-plan.json'):continue
   raw=C.ordinary(p,64*1024**2);out=output/relative;out.parent.mkdir(parents=True,exist_ok=True)
   if out.exists():C.need(C.ordinary(out,64*1024**2)==raw,'conflicting role input paths')
   else:
    with out.open('xb')as f:f.write(raw)
 (output/'lifecycle-plan.json').write_bytes(C.encoded(plans));return output

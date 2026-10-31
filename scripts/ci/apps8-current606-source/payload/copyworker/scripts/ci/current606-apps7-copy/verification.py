# SPDX-License-Identifier: MIT
"""Public TEST verification-only keyring in the newly owned work lease."""
import os,re,time
from pathlib import Path
import contract as C,supervised

def prepare(rows,*,signers,budget):
 C.need(type(rows)is list and 1<=len(rows)<=3 and len(signers)<=3,'finite TEST public-key set')
 selected={};raws=[]
 for row in rows:
  C.need(type(row)is dict and set(row)=={'path','bytes','sha256','signer'}and re.fullmatch('[A-F0-9]{40}',row['signer']or''),'typed exact TEST public key')
  p=Path(row['path']);C.need(p.parent==Path('/runner/inputs/keys')and p.name not in('.','..'),'fixed readonly TEST public key path')
  raw=C.ordinary(p,65536);C.need(C.pin(raw)=={k:row[k]for k in('bytes','sha256')}and raw.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----\n')and raw.count(b'-----BEGIN PGP PUBLIC KEY BLOCK-----')==1 and b'PRIVATE KEY'not in raw,'exact public-only TEST key armor')
  C.need(row['signer']not in selected,'distinct TEST key identities');selected[row['signer']]=p;raws.append(raw)
 C.need(set(selected)==set(signers),'only exact original6/new7 TEST signers')
 trust=Path('/work/test-verification');C.need(not trust.exists()and not trust.is_symlink(),'fresh private verification directory');trust.mkdir(mode=0o700)
 receipts=[]
 def call(args):
  budget.tick();r=supervised.run(['/usr/bin/gpg','--batch','--no-options','--no-autostart','--homedir',str(trust),'--no-auto-key-retrieve',*args],env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},cwd='/',timeout=min(20,budget.deadline-time.monotonic()),output_limit=65536)
  C.need(r['returncode']==0 and r['termination']is None and r['direct_child_reaped']and r['group_retired'],'bounded TEST verification keyring operation')
  receipts.append(dict(stdout=C.pin(r['stdout']),stderr=C.pin(r['stderr']),returncode=r['returncode'],group_retired=r['group_retired']));return r['stdout']
 for signer,path in selected.items():
  shown=call(['--with-colons','--import-options','show-only','--import',str(path)]).decode();lines=shown.splitlines();C.need(sum(x.startswith('pub:')for x in lines)==1 and not any(x.startswith(('sec:','ssb:'))for x in lines),'exact one public primary; secret keys refused')
  fprs=[x.split(':')[9]for x in lines if x.startswith('fpr:')];C.need(fprs and fprs[0]==signer,'exact TEST primary fingerprint')
  call(['--import',str(path)])
 ownertrust=trust/'ownertrust';ownertrust.write_text(''.join(s+':6:\n'for s in selected));ownertrust.chmod(0o600);call(['--import-ownertrust',str(ownertrust)])
 return dict(status='PRIVATE_TEST_VERIFICATION_ONLY',signers=sorted(selected),operations=receipts,production_trust='UNCHANGED',private_keys='REFUSED')

def verify_product(product,*,budget):
 """Authenticate Runtime1's exact public pair without selecting/mutating it."""
 C.need(product['version']=='0.1.0-1'and product['sha256']=='1c8a9149da02e60a4c14598cdf7007d6dbffcd6150757fcf6711977aa00cf8aa'and product['signer']=='DA8AD638E79414E661656E4C23132CAA1000DA38','exact authenticated protected Runtime1 public pair')
 path=Path(product['path']);signature=product['signature'];C.need(path.parent==Path('/runner/inputs/archives')and signature['path']==str(path)+'.sig','fixed complete dependency archive/signature')
 C.need(C.pin(C.ordinary(path,64*1024**2))=={k:product[k]for k in('bytes','sha256')}and C.pin(C.ordinary(Path(signature['path']),65536))=={k:signature[k]for k in('bytes','sha256')},'exact whole dependency public bytes')
 result=supervised.run(['/usr/bin/gpg','--batch','--no-options','--no-autostart','--homedir','/work/test-verification','--no-auto-key-retrieve','--status-fd','1','--verify',signature['path'],str(path)],env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},cwd='/',timeout=min(20,budget.deadline-time.monotonic()),output_limit=65536)
 status=result['stdout'].decode();C.need(result['returncode']==0 and result['termination']is None and result['direct_child_reaped']and result['group_retired']and re.search(r'^\[GNUPG:\] VALIDSIG '+product['signer']+r' ',status,re.M)and not re.search(r'\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|KEYEXPIRED|KEYREVOKED|NO_PUBKEY)',status),'original expiry/revocation/signature guards on protected Runtime1')
 return dict(status='AUTHENTICATED_PROTECTED_RUNTIME1_NOT_SELECTED',signer=product['signer'],stdout=C.pin(result['stdout']),stderr=C.pin(result['stderr']),returncode=0,group_retired=True)

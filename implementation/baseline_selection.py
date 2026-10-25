# SPDX-License-Identifier: MIT
"""Fixed Apps6-before607 installer selection; no installation or signing."""
import hashlib
import json

APPS='cachy-asahi-apps'
EDITS=(
 ('Hold599 archive bodies, replace five and add Boot/DNS2/Sysctl2',
  'Hold600 archive bodies, replace four and add Boot/DNS2/Sysctl2'),
 ("len(held)==599,'exact599 held original604 archive rows'",
  "len(held)==600,'exact600 held original604 archive rows'"),
 ("len(sign)==8", "len(sign)==7"),
 ("'exact607/eight current TEST signature operands'",
  "'exact607/seven current TEST signature operands'"),
 ('held_original604=599,incoming_exact_archives=8',
  'held_original604=600,incoming_exact_archives=7'),
 ('fresh_TEST_signatures=8', 'fresh_TEST_signatures=7'),
 ("status='SOURCE_ONLY_FRESH_TRANSACTION_REQUIRES_NATIVE_TRIAL'",
  "status='SOURCE_ONLY_APPS6_BASELINE_REQUIRES_INDEPENDENT_NATIVE_TRIAL'"),
)
def need(ok,why):
 if not ok:raise ValueError(why)
def encode(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def profile(raw,after_lock,before_lock):
 p=json.loads(raw)
 need(p['target']==pin(after_lock),'exact parent after607 lock')
 after=dict(x.split()for x in after_lock.decode().splitlines())
 before=dict(x.split()for x in before_lock.decode().splitlines())
 need(len(after)==len(before)==607,'complete607 locks')
 need(after[APPS]=='0.1.0-16'and before[APPS]=='0.1.0-6','fixed Apps16/6 roles')
 need({k:v for k,v in after.items()if k!=APPS}=={k:v for k,v in before.items()if k!=APPS},'all other606 versions held')
 need(len(p['incoming'])==8 and p['incoming'][APPS]['version']=='0.1.0-16'and p['held604'][APPS]['version']=='0.1.0-6','source-bound incoming and original Apps roles')
 out=json.loads(raw);del out['incoming'][APPS];out['target']=pin(before_lock)
 out['status']='SOURCE_ONLY_LATEST607_APPS6_BASELINE_NOT_RUN'
 out['baseline_selection']=dict(target_kind='baseline607',Apps_version='0.1.0-6',held_original604=600,incoming_exact_archives=7,other606_lock_sha256=pin(''.join(n+' '+v+'\n'for n,v in sorted(before.items())if n!=APPS).encode())['sha256'],parent_target=pin(after_lock),actual_source=None,actual_ref=None,actual_run=None,acceptance='NOT_ISSUED')
 need(len(out['incoming'])==7 and APPS not in out['incoming'],'original Apps6 archive remains in held600')
 return encode(out)
def materializer(raw):
 text=raw.decode()
 for old,new in EDITS:
  need(text.count(old)==1,'one baseline materializer seam: '+old)
  text=text.replace(old,new,1)
 back=text
 for old,new in reversed(EDITS):
  need(back.count(new)==1,'one whole materializer inverse')
  back=back.replace(new,old,1)
 need(back.encode()==raw,'whole parent materializer inverse')
 return text.encode()

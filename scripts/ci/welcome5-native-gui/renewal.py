# SPDX-License-Identifier: MIT
"""Finite public TEST-signature overlay; never transfers native/GUI acceptance."""
import hashlib,json,os,re,shutil,stat,time
from pathlib import Path

HERE=Path(__file__).resolve().parent
NATIVE='31fddcfcae34903f95aa2d34556d2b9497dd7b12'
NATIVE_REF='refs/heads/codex/welcome5-dns2-original-gui-inputs-v1'
HELD='77bd2c6ecf2e5c28a04116c3da85c45f70d1cc90'
CARRIER='409bfb8fb66969a5f7dd395997342ae7404d1384'
REF='refs/heads/codex/welcome5-dns2-gui-test-renewal-v1'
INDEX=dict(bytes=38428,sha256='543c5c6d9e190c60e1068cb07b68518e2e20ce4a6ff2ff427d55054189724f19')
SIGNER='DF75594196D289B622585504BEC4017F3DB8EDF7'
NATIVE_INDEX=dict(bytes=39808,sha256='e92a0d58e247c7cc87f1282e318daf50d8f4201f03cd2a94ec773716f375079a')
HELD_INDEX=dict(bytes=34490,sha256='4e6a8fb3285a53dacd2ce06348b40238b32256df40ecc8b5e07a93fb5b0310b6')
KINDS={'welcome5':('native73','packages/welcome5/a/cachy-asahi-welcome-0.1.0-5-aarch64.pkg.tar.xz','85ffec834fc72ef8764cdcae828a12ec8ddf7f20',39104384568),
 'dns2':('native73','packages/dns2/a/cachy-asahi-dns-0.1.0-2-any.pkg.tar.xz','59a9aee351226e93e22574fd14bd3e0b45c8368d',39101228683),
 'doctor':('held77','signed/cachy-asahi-doctor-0.1.0-1-any.pkg.tar.xz','3c06dad15dec0dbfe47d5f064a9c56ce76f59756',39002929704),
 'orphans':('held77','signed/cachy-asahi-orphans-0.1.0-2-any.pkg.tar.xz','3c06dad15dec0dbfe47d5f064a9c56ce76f59756',39002929704)}
BAD={'BADSIG','ERRSIG','EXPKEYSIG','KEYEXPIRED','REVKEYSIG','KEYREVOKED','EXPSIG','SIGEXPIRED','NO_PUBKEY','NODATA','FAILURE','ERROR'}

def need(ok,message):
 if not ok:raise ValueError(message)
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(path):
 path=Path(path);need(path.is_absolute()and not any(p.is_symlink()for p in (path,*path.parents)),'ordinary absolute renewal operand required');s=path.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<s.st_size<=16*1024**2,'bounded renewal file required');raw=path.read_bytes();need(len(raw)==s.st_size,'renewal file changed');return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path):
 pin(path)
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate renewal JSON field');out[k]=v
  return out
 return json.loads(Path(path).read_bytes(),object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite renewal JSON required'))
def relative(name):
 need(type(name)is str and name and not name.startswith('/')and '\\'not in name and all(p not in ('','.','..')for p in name.split('/')),'safe renewal relative path required');return name

def selection(source):
 policy=read(HERE/'renewal-policy.json')
 need(policy.get('schema_version')==1 and policy.get('status')=='ROOT_SELECTED_CURRENT_TEST_SIGNATURES'and
      (policy.get('carrier_source'),policy.get('carrier_ref'),policy.get('index_pin'))==(CARRIER,REF,INDEX)and
      all(policy.get(k)is None for k in ('actual_source','actual_ref','minimal_run','overlay_run')),'public TEST renewal selection remains NULL or differs')
 return policy

def closed(root,files):
 actual=set()
 for directory,dirs,names in os.walk(root,followlinks=False):
  if Path(directory)==root:dirs[:]=[n for n in dirs if n!='.git'];names=[n for n in names if n!='.git']
  for name in dirs:need(not (Path(directory)/name).is_symlink(),'DATA directory alias refused')
  actual.update(str((Path(directory)/name).relative_to(root))for name in names)
 need(actual==set(files),'closed renewal/native DATA members required')
 for name,row in files.items():need(pin(root/relative(name))==row,'whole original/renewed DATA pin differs: '+name)

def overlay(root):
 root=Path(root);need(pin(root/'index.json')==INDEX,'exact public renewal index required');value=read(root/'index.json')
 need(value['schema_version']==1 and value['kind']=='WELCOME5_DNS2_GUI_TEST_SIGNATURE_RENEWAL_OVERLAY_ONLY'and value['authority_scope']=='FRESH_TEST_SIGNATURES_ONLY_HISTORICAL_NATIVE_CREDIT_NO_GUI_OR_RELEASE_ACCEPTANCE','signature-only overlay scope required')
 need(value['signer']==SIGNER and type(value['created'])is int and type(value['expires'])is int and value['expires']-value['created']==604800 and value['created']<=time.time()<value['expires'],'current seven-day public TEST key required')
 expected={'TEST-public.asc','provenance.json'}|{'signatures/'+role+'.sig'for role in KINDS}
 need(set(value['files'])==expected and value['public_key']==dict(path='TEST-public.asc',**value['files']['TEST-public.asc']),'exact public7 overlay closure required');closed(root,dict(value['files'],**{'index.json':INDEX}))
 need(set(value['inputs'])=={'native73','held77'}and len(value['inputs']['native73']['files'])==73 and len(value['inputs']['held77']['files'])==98 and
      (value['inputs']['native73']['source'],value['inputs']['native73']['ref'],value['inputs']['native73']['files']['index.json'])==(NATIVE,NATIVE_REF,NATIVE_INDEX)and
      (value['inputs']['held77']['source'],value['inputs']['held77']['ref'],value['inputs']['held77']['files']['index.json'])==(HELD,None,HELD_INDEX),'whole historical native/public carrier maps required')
 need(set(value['roles'])==set(KINDS),'exact four installed signature roles required')
 proof=read(root/'provenance.json');need(proof['status']=='REAL_CURRENT_PUBLIC_TEST_SIGNATURES_NO_NEW_NATIVE_BUILD'and proof['signer']==SIGNER and proof['created']==value['created']and proof['expires']==value['expires']and
      proof['native_build_credit']=='HISTORICAL_NATIVE_SOURCES_AND_ROOT_DECISIONS_ONLY'and all(proof[k]is None for k in ('actual_source','actual_ref','minimal_run','overlay_run'))and
      all(proof[k]=='NOT_RUN'for k in ('GUI','current606','generic16k','hardware'))and proof['release']=='NOT_ADMITTED','renewal is neither a new build nor GUI authority')
 for role,expected in KINDS.items():
  row=value['roles'][role];need((row['carrier'],row['archive'],row['native_source'],row['native_run'])==expected and row['signer']==SIGNER and row['signature']=='signatures/'+role+'.sig'and row['signature_pin']==value['files'][row['signature']],'renewed archive/native role differs')
  files=value['inputs'][row['carrier']]['files'];need(row['archive_pin']==files[row['archive']]and row['prior_signature_pin']==files[row['prior_signature']]and row['Root_decision_pin']==files[row['Root_decision']],'original archive/signature/whole Root decision pins required')
  actual=proof['verification'][role];lines=actual['status'].splitlines();tags=[line.split()[1]for line in lines if line.startswith('[GNUPG:] ')]
  need(actual['gpg_exit']==0 and tags.count('VALIDSIG')==tags.count('GOODSIG')==1 and not BAD.intersection(tags)and next(line.split()[2]for line in lines if line.startswith('[GNUPG:] VALIDSIG '))==SIGNER and
       actual['archive_pin']==row['archive_pin']and actual['signature_pin']==row['signature_pin'],'complete current GPG status receipt required')
 return value

def inspect(root,native,held):
 value=overlay(root)
 for role,directory in [('native73',native),('held77',held)]:closed(Path(directory),value['inputs'][role]['files'])
 return value

def apply(source,assets,output,lock):
 selection(source);root=assets/'renewal';value=overlay(root)
 control=read(output/'control.json');need(type(control)is dict and set(control)=={'signer'}and type(control['signer'])is str and re.fullmatch('[0-9A-F]{40}',control['signer']),'closed installed fixture signer control required')
 for role,row in value['roles'].items():
  archive=output/Path(row['archive']).name;need(pin(archive)==row['archive_pin'],'installed archive body changed during signature renewal')
  shutil.copyfile(root/row['signature'],output/(archive.name+'.sig'))
 # This existing runtime filename is already projected into /tmp/products.
 # Its fresh explicit signer is shared by these four TEST input signatures.
 shutil.copyfile(root/'TEST-public.asc',output/'welcome5-TEST.asc')
 # The guest restoration uses these existing names, independently of image trust.json.
 shutil.copyfile(root/'TEST-public.asc',output/'TEST-public.asc')
 (output/'control.json').write_bytes(encoded(dict(signer=SIGNER)))
 (output/'trust.json').write_bytes(encoded([dict(key='welcome5-TEST.asc',signer=SIGNER)]))
 receipt=dict(status='CURRENT_TEST_SIGNATURES_ONLY_NATIVE_CREDIT_UNCHANGED',carrier=CARRIER,index_pin=INDEX,signer=SIGNER,
  created=value['created'],expires=value['expires'],archives={k:v['archive_pin']for k,v in value['roles'].items()},GUI='NOT_RUN')
 (output/'test-signature-renewal.json').write_bytes(encoded(receipt))
 return lock

# SPDX-License-Identifier: MIT
"""Explicit TCG inspect capacity and four exact carrier export aliases.

No retries, skipped checks, partial acceptance or product transaction grants.
"""
import hashlib,json,os,re,stat,types
from pathlib import Path
PROFILE='REPAIR_GENERIC16K_OWNED_INSPECT_VALIDATION_1200_V1'
FLAG='--tcg-owned-inspect-profile'
PATH='/execution/scripts/ci/apps7-full574-repair-native/transaction.py'
KEYS=('--workspace','--apps-source','--apps-provenance-sha256','--repository-source','--full574-policy','--full574-policy-sha256','--full574-lease','--full574-lease-sha256','--ownership-sha256')
FIXED={'--apps-source':'/inputs/apps-source','--repository-source':'/inputs/candidate/usr/share/cachy-asahi/repository-runtime','--full574-policy':'/inputs/full574-policy.json','--full574-lease':'/inputs/full574-lease.json'}
PIN=dict(bytes=29664,sha256='319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af')
CARRIER_PROFILE_SHA='805e3ef1b4e2be899476c3d215468af02f824eb8a071e473e22aeb7bae3aed0e'
ALIASES={prefix+'/cachy-asahi-apps-'+side+'/cachy-asahi-apps-0.1.0-16-any.pkg.tar.xz':'native/packages/cachy-asahi-apps-'+side+'/cachy-asahi-apps-0.1.0-16-any.pkg.tar.xz'for prefix in('native/packages','Root-strict/current-apps16/original-public/packages')for side in('a','b')}

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)
def role(argv,seconds,expected=0,*,selected=False):
 if type(argv)is not list or any(type(v)is not str or len(v)>256 for v in argv)or type(seconds)is not int or type(expected)is not int or expected!=0:return False
 if selected:
  if len(argv)!=25 or argv[-2:]!=[FLAG,PROFILE]or seconds!=1210:return False
  argv=argv[:-2]
 elif len(argv)!=23 or seconds!=610:return False
 if argv[:5]!=['/usr/bin/python3','-I','-B',PATH,'inspect']or tuple(argv[5::2])!=KEYS:return False
 values=dict(zip(KEYS,argv[6::2]))
 return values['--workspace']in('/work/main','/work/interrupted')and all(values[k]==v for k,v in FIXED.items())and all(re.fullmatch('[a-f0-9]{64}',values[k])for k in KEYS if k not in FIXED and k!='--workspace')

def wrap(original):
 def seconds(args=None):
  value=original(args) # Original authenticated policy/lease always runs first.
  profile=getattr(args,'tcg_owned_inspect_profile',None)if args is not None else None
  if profile is None:return value
  need(profile==PROFILE and type(value)is int and value==600,'exact explicit inspect profile after original600 policy')
  argv=['/usr/bin/python3','-I','-B',PATH,getattr(args,'action',None)]
  for key in KEYS:argv.extend((key,getattr(args,key[2:].replace('-','_'),None)))
  need(role(argv,610),'only exact source-owned copy inspect role')
  need(all(getattr(args,n,None)is None for n in('source','release','release_sha256','catalog','catalog_sha256','catalog_signature','keyring','signer','plan','plan_sha256','before_tree_sha256','before_database_sha256','before_packages_sha256','before_inventory_sha256','operation','applications'))and not getattr(args,'worker',False)and not getattr(args,'confirm_disposable_transaction',False),'inspect profile cannot grant a transaction or foreign input role')
  return 1200
 return seconds

def backend(raw,helper=None):
 text=raw.decode();parser=' a=p.parse_args()\n';option=" p.add_argument('"+FLAG+"',choices=('"+PROFILE+"',))\n"
 entry="if __name__=='__main__':raise SystemExit(main())";setup="import types as _inspect_types\n_inspect_validation=_inspect_types.ModuleType('_source_owned_inspect_validation')\nexec(compile("+repr(Path(__file__).read_text()if helper is None else helper)+",'<source-owned-inspect-validation>','exec'),vars(_inspect_validation))\nexecution_seconds=_inspect_validation.wrap(execution_seconds)\n"
 need(text.count(parser)==text.count(entry)==1,'one exact private backend parser and entry');out=text.replace(parser,option+parser,1).replace(entry,setup+entry,1)
 need(out.replace(setup,'',1).replace(option,'',1)==text,'entire original rendered backend inverse');compile(out,'<inspect1200-private-backend>','exec');return out.encode()

def note(helper,record,out,err,error,expected):
 # Reuse the complete fixed-note algorithm, retaining the real1210 supervisor.
 need(role(record['argv'],record['time_limit'],expected,selected=True),'typed selected inspect DATA role');m=types.ModuleType('_selected_inspect_note');exec(compile(helper,'<whole-original-inspect-note>','exec'),vars(m));m.role=lambda a,s,e:role(a,s,e,selected=True);line=m.note(record,out,err,error,expected)
 if line is None:return None
 prefix='APPS574_INSPECT_FAILURE ';value=json.loads(line[len(prefix):]);value['validation_profile']=PROFILE;new=prefix+encoded(value)
 if len(new.encode())<=1900:return new
 value.pop('streams',None);value['capture']='HASH_AND_LENGTH_ONLY';new=prefix+encoded(value);return new if len(new.encode())<=1900 else None

def lifecycle(raw,helper=None):
 text=raw.decode();anchor="if __name__=='__main__':main()";need(text.count(anchor)==1,'one original lifecycle entry')
 setup="""_tcg_inspect_original_call=H.Calls.call
def _tcg_owned_inspect_call(self,argv,*,seconds=610,expected=0):
 if not _tcg_inspect.role(argv,seconds,expected):return _tcg_inspect_original_call(self,argv,seconds=seconds,expected=expected)
 selected=argv+[_tcg_inspect.FLAG,_tcg_inspect.PROFILE];original=self.api;captured=[]
 def capture(*a,**kw):
  row=original.run_command(*a,**kw);captured.append(row);return row
 self.api=types.SimpleNamespace(run_command=capture)
 try:return _tcg_inspect_original_call(self,selected,seconds=1210,expected=expected)
 except Exception as error:
  try:
   if len(captured)==1:
    note=_tcg_inspect.note(_VM_INSPECT_NOTE_SOURCE,*captured[0],expected)
    if note is not None:error.add_note(note)
  except BaseException:pass # Diagnostic loss never replaces the original failure.
  raise
 finally:self.api=original
H.Calls.call=_tcg_owned_inspect_call
"""
 prefix="_tcg_inspect=types.ModuleType('_source_owned_inspect_profile')\nexec(compile("+repr(Path(__file__).read_text()if helper is None else helper)+",'<source-owned-inspect-validation>','exec'),vars(_tcg_inspect))\n";out=text.replace(anchor,prefix+setup+anchor,1)
 need(out.replace(prefix+setup,'',1)==text,'entire original lifecycle body inverse');compile(out,'<inspect1200-lifecycle>','exec');return out.encode()

def identity(s):return tuple(getattr(s,n)for n in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,cap):
 path=Path(path);need(path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary unaliased carrier/export path');a=path.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<a.st_size<=cap,'ordinary bounded single-link carrier/export file');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  need(identity(os.fstat(fd))==identity(a),'opened carrier identity');raw=b''
  while len(raw)<=cap:
   b=os.read(fd,min(65536,cap+1-len(raw)))
   if not b:break
   raw+=b
  need(len(raw)==a.st_size and identity(os.fstat(fd))==identity(a)and identity(path.lstat())==identity(a),'carrier/export changed during read');return raw,identity(a)
 finally:os.close(fd)

def copy_reference(copy,args,name,row,result):
 if name not in ALIASES:
  return copy(args.source.parent/'apps16-native-pair'/name[len('APPS16_CARRIER/'):]if name.startswith('APPS16_CARRIER/')else args.packet/name,'native-inputs/'+name,16*1024**2)
 need(type(row)is dict and set(row)=={'path','bytes','sha256'}and row==dict(path=name,**PIN),'only four exact source-bound accepted archive aliases')
 raw,_=read(args.source/'apps16-repair/carrier-profile.json',4*1024**2);need(hashlib.sha256(raw).hexdigest()==CARRIER_PROFILE_SHA,'whole held carrier policy');p=json.loads(raw);declared=p['archives']+p['acceptance']['accepted_pair']['archives'];need({r['path']:r for r in declared}=={n:dict(path=n,**PIN)for n in ALIASES},'exact four declared historical/current archive references')
 target=ALIASES[name];need(p['files'][target]==PIN,'actual native archive member in independently proved carrier');carrier=args.source.parent/'apps16-native-pair';path=carrier/target;body,owned=read(path,PIN['bytes']);need(pin(body)==PIN,'whole actual accepted native archive bytes')
 export='native-inputs/'+name;copy(path,export,16*1024**2);need(result['files'].get(export)==PIN,'copied complete alias byte/hash proof required');copied,_=read(args.public/export,PIN['bytes']);need(copied==body and identity(path.lstat())==owned,'export/source mutation refused')

def retention(raw,*,selected=False):
 if not selected:return raw
 old="copy(args.source.parent/'apps16-native-pair'/name[len('APPS16_CARRIER/'):]if name.startswith('APPS16_CARRIER/')else args.packet/name,'native-inputs/'+name,16*1024**2)";new="_inspect_validation.copy_reference(copy,args,name,pin,result)"
 need(raw.count(old)==1,'one entire source-owned retention routing seam');out=raw.replace(old,new,1);need(out.replace(new,old,1)==raw,'whole original239 retention body inverse');return out

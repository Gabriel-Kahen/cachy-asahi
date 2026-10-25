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
 # Add all selected fields inside this private encoder BEFORE the entire
 # unchanged original algorithm considers every complete stream subset.
 need(role(record['argv'],record['time_limit'],expected,selected=True),'typed selected inspect DATA role');m=types.ModuleType('_selected_inspect_note');exec(compile(helper,'<whole-original-inspect-note>','exec'),vars(m));m.role=lambda a,s,e:role(a,s,e,selected=True)
 operands=dict(zip(KEYS,record['argv'][6:23:2]));original=m.encoded
 def selected_encoded(value):
  if type(value)is dict and value.get('purpose')=='RETURNED_FAILURE_DATA_ONLY'and value.get('role')=='OWNED_COPY_INSPECT':
   value=dict(value,validation_profile=PROFILE,selected_operands=[operands[k]for k in KEYS if k not in FIXED],command_row_source='SOURCE_PROJECTED_NOT_EXPORTED_COMMAND_ROW')
  return original(value)
 m.encoded=selected_encoded
 return m.note(record,out,err,error,expected)

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

# Failure DATA projection only: this is never an exported physical command row.
def projected_record(value):
 base={'schema_version','role','purpose','source_argv_sha256','supervisor_sha256','supervisor_codec','supervisor','supervisor_error','capture','acceptance_authority','cleanup_authority','validation_profile','selected_operands','command_row_source'}
 need(type(value)is dict and set(value)in(base,base|{'streams'})and type(value.get('schema_version'))is int and value['schema_version']==1 and value.get('supervisor_codec')=='CANONICAL_COMPACT_ASCII_JSON','closed selected note schema')
 need(value.get('supervisor_error')is None or type(value['supervisor_error'])is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',value['supervisor_error']),'typed original supervisor error')
 need(type(value)is dict and value.get('validation_profile')==PROFILE and
  value.get('command_row_source')=='SOURCE_PROJECTED_NOT_EXPORTED_COMMAND_ROW'and
  value.get('role')=='OWNED_COPY_INSPECT'and value.get('purpose')=='RETURNED_FAILURE_DATA_ONLY'and
  value.get('acceptance_authority')is False and value.get('cleanup_authority')is False,
  'closed source-projected selected failure DATA only')
 values=value.get('selected_operands');names=[k for k in KEYS if k not in FIXED]
 need(type(values)is list and len(values)==len(names)==5 and all(type(v)is str for v in values),
  'five exact source-role workspace/hash operands')
 operands=dict(FIXED,**dict(zip(names,values)));argv=['/usr/bin/python3','-I','-B',PATH,'inspect']
 for k in KEYS:argv.extend((k,operands[k]))
 argv.extend((FLAG,PROFILE));need(role(argv,1210,selected=True),'exact projected25 selected argv')
 need(value.get('source_argv_sha256')==hashlib.sha256(encoded(argv).encode()).hexdigest(),
  'source-projected argv must match original recorded commitment')
 row=value.get('supervisor');keys={'exit_code','seconds','time_limit','output_limit','group_absence_verified','stdout_bytes','stdout_sha256','stderr_bytes','stderr_sha256'}
 need(type(row)is dict and set(row)==keys and type(row['time_limit'])is int and row['time_limit']==1210 and
  type(row['output_limit'])is int and row['output_limit']==1024**2 and
  type(row['exit_code'])is int and -255<=row['exit_code']<=255 and
  type(row['group_absence_verified'])is bool and
  type(row['seconds'])in(int,float)and __import__('math').isfinite(row['seconds'])and row['seconds']>=0,
  'exact recorded supervisor scalar scope')
 for side in('stdout','stderr'):
  need(type(row[side+'_bytes'])is int and 0<=row[side+'_bytes']<=1024**2 and
   type(row[side+'_sha256'])is str and re.fullmatch('[0-9a-f]{64}',row[side+'_sha256']),
   'bounded recorded original stream commitment')
 need(row['stdout_bytes']+row['stderr_bytes']<=1024**2 and not(row['exit_code']==0 and row['group_absence_verified']),
  'only failed original selected supervisor, never positive authority')
 full=dict(row,argv=argv)
 need(value.get('supervisor_sha256')==hashlib.sha256(encoded(full).encode()).hexdigest(),
  'whole reconstructed supervisor matches original source commitment')
 choices={'HASH_AND_LENGTH_ONLY':set(),'COMPLETE_RETURNED_BUFFERS':{'stdout','stderr'},'COMPLETE_STDOUT_STDERR_HASH_ONLY':{'stdout'},'COMPLETE_STDERR_STDOUT_HASH_ONLY':{'stderr'}}
 need(len(('APPS574_INSPECT_FAILURE '+encoded(value)).encode())<=1900,'fixed1900 selected note cap')
 capture=value.get('capture');need(capture in choices,'closed complete-stream capture scope');streams=value.get('streams',{});need(type(streams)is dict and set(streams)==choices[capture],'only declared complete returned streams')
 if not streams:need('streams'not in value,'hash-only capture has no stream aliases')
 complete={}
 import base64,zlib
 for side,entry in streams.items():
  need(type(entry)is dict and set(entry)=={'encoding','base64'}and entry['encoding']=='ZLIB_BASE64'and type(entry['base64'])is str and len(entry['base64'])<=1900,'closed bounded returned-buffer codec')
  maximum=1024 if side=='stdout'else 65536;need(row[side+'_bytes']<=maximum,'original returned-buffer exposure cap')
  d=zlib.decompressobj();raw=d.decompress(base64.b64decode(entry['base64'],validate=True),row[side+'_bytes']+1)
  need(d.eof and not d.unused_data and not d.unconsumed_tail and len(raw)==row[side+'_bytes']and hashlib.sha256(raw).hexdigest()==row[side+'_sha256'],'complete exported returned-buffer bytes/hash required')
  complete[side]=pin(raw)
 return dict(record=full,source='SOURCE_PROJECTED_NOT_EXPORTED_COMMAND_ROW',complete_returned_streams=complete,
  acceptance_authority=False,cleanup_authority=False,case_credit='NOT_GRANTED')

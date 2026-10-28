# SPDX-License-Identifier: MIT
"""Four whole accepted real240 suites, with fresh ordinary retirement and registries."""
import base64,hashlib,json,os,pwd,time
from pathlib import Path
import latest_plan as P

def ordinary_absent(uid):
 entries=list(Path('/proc').iterdir());P.need(len(entries)<=512,'bounded actual process namespace')
 for p in entries:
  if not p.name.isdigit():continue
  try:raw=(p/'status').read_text()
  except FileNotFoundError:continue
  fields=[line.split()[1:]for line in raw.splitlines()if line.startswith('Uid:')];P.need(len(fields)==1 and len(fields[0])==4 and str(uid)not in fields[0],'ordinary fixture process remains')

class Suites:
 def __init__(self,g,context,N,supervised,deadline,nonce,scope):
  self.g,self.context,self.N,self.supervised,self.deadline,self.nonce=g,context,N,supervised,deadline,nonce;C=g['C'];self.account=pwd.getpwnam('alarm');P.need(self.account.pw_uid>0 and self.account.pw_gid>0,'same original ordinary account');self.source=Path('/runner/setup240');self.SC=C.load('_next_whole_original_setup240_contract',self.source/'scripts/ci/setup6-real-modules/contract.py');self.SC.verify_source(self.source);self.H=C.load('_next_whole_original_setup_homes',self.source/'scripts/ci/setup5-real-modules/run.py');self.LC=C.scoped_load('_next_whole_original_setup_registry',self.source/'scripts/ci/setup6-real-modules/lifecycle.py',{'contract':self.SC});self.retained={};self.rows=[];self.scope=scope
  base=P.baseline(context['expected']);P.need({n:v for n,v in self.SC.VERSIONS.items()if n!='cachy-asahi-setup'}=={n:base[n]for n in self.SC.VERSIONS if n!='cachy-asahi-setup'},'all six exact installed project module versions unchanged')
 def registry(self,parent,report):
  accepted=self.LC.workspace_snapshot(parent,report,self.context['L'],self.H);identities={}
  for relative in accepted:
   p=parent/relative;s=p.lstat();identities[relative]=dict(identity=self.scope.key(s),capability=os.getxattr(p,'security.capability',follow_symlinks=False).hex()if'security.capability'in os.listxattr(p,follow_symlinks=False)else None)
  return dict(accepted=accepted,identities=identities)
 def users(self):
  ordinary_absent(self.account.pw_uid)
  for parent,(report,before)in self.retained.items():P.need(self.registry(parent,report)==before,'every previous fifteen-home real module registry/hash/identity/capability preserved')
 def run(self,phase):
  P.need(phase in P.REAL_PHASES and phase not in {r['phase']for r in self.rows}and len(self.rows)<4,'one of four exact new real-module boundaries');self.users();parent=Path('/tmp')/('setup6-real-'+P.REAL_PHASES[phase]);P.need(not parent.exists()and not parent.is_symlink(),'fresh owned real-module workspace');parent.mkdir(mode=0o700);os.chown(parent,self.account.pw_uid,self.account.pw_gid)
  value=self.supervised.run(['/usr/bin/python3','-I','-B','/runner/real606/ordinary_entry.py',str(self.context['home']),str(parent)],env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',CACHY_ASAHI_EXPANDED604=os.environ['CACHY_ASAHI_EXPANDED604']),cwd='/',timeout=min(240,max(.001,self.deadline-time.monotonic())),output_limit=128*1024,grace=1,signal_uid=self.account.pw_uid)
  P.need(value['returncode']==0 and value['termination']is None and value['direct_child_reaped']is True and value['group_retired']is True,'whole original240 real fixture/group retirement');ordinary_absent(self.account.pw_uid);real=self.N.decode(value['stdout']);self.SC.validate_real(real);P.need(self.g['C'].read(parent/'work/receipt.json')==real,'whole actual real fixture file/stdout join');self.retained[parent]=(real,self.registry(parent,real));row=dict(phase=phase,workspace=parent.name,nonce=self.nonce,receipt=real,process={k:v for k,v in value.items()if k not in('stdout','stderr')},stdout=self.N.pin(value['stdout']),stdout_base64=base64.b64encode(value['stdout']).decode('ascii'),stderr=self.N.pin(value['stderr']),source='WHOLE_UNCHANGED_SETUP240_INSTALLED_AND_REAL_RECOVERY',ordinary_retirement=True);self.rows.append(row);(self.g['OUT']/('latest607-setup-real-'+phase+'.json')).write_bytes(self.g['C'].encoded(row));return row
 def summary(self):
  self.users();validate(self.rows,self.nonce,self.SC.validate_real);return dict(status='FOUR_WHOLE_REAL240_SUITES_SOURCE_ENFORCED_PRIVATE_REGISTRIES_HELD',suites=self.rows,whole_source_files=240,source_owned_nonce=self.nonce,new_composition_acceptance='NOT_ISSUED',notification_delivery='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN')

def validate(rows,nonce,validate_real):
 P.need(type(rows)is list and len(rows)==4 and [r['phase']for r in rows]==list(P.REAL_PHASES)and callable(validate_real),'all four real240 suites and original validator required')
 for row in rows:
  P.need(set(row)=={'phase','workspace','nonce','receipt','process','stdout','stdout_base64','stderr','source','ordinary_retirement'}and row['workspace']=='setup6-real-'+P.REAL_PHASES[row['phase']]and row['nonce']==nonce and row['source']=='WHOLE_UNCHANGED_SETUP240_INSTALLED_AND_REAL_RECOVERY'and row['ordinary_retirement']is True,'exact phase/workspace/nonce/source lifetime');validate_real(row['receipt']);p=row['process'];P.need(p['returncode']==0 and p['termination']is None and p['direct_child_reaped']is p['group_retired']is True,'actual whole ordinary fixture owned group retirement')
  value=row['stdout_base64'];P.need(type(value)is str and len(value)<=4*((128*1024+2)//3),'bounded exact raw installed stdout encoding');raw=base64.b64decode(value,validate=True);P.need(len(raw)<=128*1024,'unchanged complete installed stdout cap')
  def pairs(items):
   result={}
   for key,item in items:P.need(key not in result,'duplicate original installed stdout JSON field');result[key]=item
   return result
  printed=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:P.need(False,'nonfinite original installed stdout JSON'))
  P.need(type(printed)is dict and printed==row['receipt'],'complete original stdout/typed receipt join')
  P.need(raw==(json.dumps(printed)+'\n').encode(),'exact unchanged original unsorted installed.py printer codec')
  P.need(row['stdout']==dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),'complete original installed.py printed receipt/stdout codec join')
  for key in('stdout','stderr'):P.need(type(row[key])is dict and set(row[key])=={'bytes','sha256'}and type(row[key]['bytes'])is int and 0<=row[key]['bytes']<=128*1024 and type(row[key]['sha256'])is str and len(row[key]['sha256'])==64 and all(c in'0123456789abcdef'for c in row[key]['sha256']),'whole bounded real fixture process stream pin')
 return rows

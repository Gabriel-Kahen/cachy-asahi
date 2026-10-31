# SPDX-License-Identifier: MIT
"""Same finite correctness matrix over retained executables; no compilation."""
import hashlib
from pathlib import Path
REFERENCE=b'cachy-asahi gzip correctness reference\n'*8
ENV=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',HOME='/tmp/arm16k',TMPDIR='/tmp/arm16k',PYTHONDONTWRITEBYTECODE='1')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def fixed_argv(argv):return ['/usr/bin/bash','--noprofile','--norc','-c','input=$1; shift; exec "$@" < "$input"','arm16k','/tmp/arm16k/stdin.bin',*argv]
def validate_records(receipt,commands):
 need(type(commands) is list and len(commands)==468,'complete ordered runtime graph');position=0;corpus={r['path']:{k:r[k] for k in ('bytes','sha256')} for r in receipt['corpus']['files']}
 def take(argv,source,allowed=(0,),output=None):
  nonlocal position
  row=commands[position];position+=1;supervisor=row['supervisor'];need(row['argv']==argv and row['stdin']==source and row['allowed']==list(allowed) and supervisor['argv']==fixed_argv(argv) and supervisor['exit_code'] in allowed and supervisor['group_absence_verified'] is True and supervisor['stdout_bytes']==row['stdout']['bytes'] and supervisor['stdout_sha256']==row['stdout']['sha256'],'exact ordered normal-exec/dataflow/supervisor join')
  if output is not None:need(row['stdout']==output,'exact original decoded output hash/bytes')
  return row['stdout']
 for build in receipt['builds']:
  for item in receipt['corpus']['files']:
   source=corpus[item['path']]
   if item['kind']=='corrupt':
    for decoder in receipt['builds']:take(['/experiments/'+decoder+'/strict-gzip'],source,(2,))
   else:
    for level in (1,6,9):
     encoded=take(['/experiments/'+build+'/minigzip','-'+str(level)],source)
     for decoder in receipt['builds']:take(['/experiments/'+decoder+'/minigzip','-d'],encoded,output=source)
 for build in receipt['builds']:
  take(['/experiments/'+build+'/strict-gzip'],corpus['gzip-reference.gz'],output=pin(REFERENCE));take(['/experiments/'+build+'/minigzip','-d'],corpus['corrupt-crc.gz'],(1,));take(['/experiments/'+build+'/minigzip','-d'],corpus['truncated-trailer.gz'],(0,1));take(['/experiments/'+build+'/example'],pin(b''))
 need(position==468,'closed runtime graph')

def suite(receipt,read,invoke):
 builds=receipt['builds'];rows=receipt['corpus']['files'];need(len(builds)==4 and len(rows)==9,'four original final builds/nine corpus cases');commands=[];checks=[]
 def call(argv,data,allowed=(0,)):
  code,out,row=invoke(argv,data);need(type(out) is bytes and len(out)<=1024**2 and code in allowed and row['group_absence_verified'] is True,'exact exit/bounded output/owned group absence');commands.append(dict(argv=argv,stdin=pin(data),stdout=pin(out),supervisor=row,allowed=list(allowed)));return code,out
 for build in builds:
  for item in rows:
   data=read('corpus/'+item['path']);need(pin(data)=={k:item[k] for k in ('bytes','sha256')},'original corpus identity')
   if item['kind']=='corrupt':
    for decoder in builds:
     code,_=call(['/experiments/'+decoder+'/strict-gzip'],data,(2,));checks.append(dict(kind='strict-reject',producer=build,input=item['path'],decoder=decoder,exit=code))
   else:
    for level in (1,6,9):
     _,encoded=call(['/experiments/'+build+'/minigzip','-'+str(level)],data)
     for decoder in builds:
      _,decoded=call(['/experiments/'+decoder+'/minigzip','-d'],encoded);need(decoded==data,'exact original cross-decoded bytes');checks.append(dict(kind='cross-decode',producer=build,input=item['path'],level=level,decoder=decoder,decoded=pin(decoded)))
 for build in builds:
  _,out=call(['/experiments/'+build+'/strict-gzip'],read('corpus/gzip-reference.gz'));need(out==REFERENCE,'strict valid reference bytes')
  call(['/experiments/'+build+'/minigzip','-d'],read('corpus/corrupt-crc.gz'),(1,))
  code,_=call(['/experiments/'+build+'/minigzip','-d'],read('corpus/truncated-trailer.gz'),(0,1));checks.append(dict(kind='sample-truncation',build=build,exit=code,rejection_acceptance='NOT_CLAIMED'))
  call(['/experiments/'+build+'/example'],b'')
 need(len(commands)==468 and sum(c['kind']=='cross-decode' for c in checks)==336 and sum(c['kind']=='strict-reject' for c in checks)==32,'complete retained correctness matrix plus four upstream examples')
 return dict(status='PASS_RETAINED_ARM_EXPERIMENT_GENERIC16K_CORRECTNESS',experiment=receipt['experiment'],original_run=receipt['original_run'],commands=commands,checks=checks,normal_interpreter='KERNEL_EXEC_PT_INTERP_NO_LD_OVERRIDES',rebuild='NOT_RUN',profile_training='NOT_RUN',performance='NOT_MEASURED',hardware='NOT_RUN',installation='NOT_RUN',release='NOT_ADMITTED')

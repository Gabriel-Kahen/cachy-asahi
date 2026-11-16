# SPDX-License-Identifier: MIT
"""Pure fixed-public-directory metadata DATA; no files, images or actors opened.

Scan projection accesses only the fixed keys and eleven selected fields. Probe
rows have no type operand: their directory type is conditional on the pinned
probe's ordinary-directory gate, not established by this parser. Comparisons
observe changes, including atime; they provide no restoration or acceptance.
"""
from datetime import datetime,timezone
import re

PATHS=('root','etc','etc/audit','etc/udev','usr','usr/bin','usr/lib','usr/share',
       'var','var/cache','var/cache/ldconfig','var/lib','var/lib/pacman',
       'var/lib/pacman/local','var/log')
FIELDS=('type','mode','uid','gid','inode','links','size','mtime','mtime_ns','atime','atime_ns')
PHASES=('offline_before','after_login','before_logout','offline_after')
GUEST_PHASES=('after_login','before_logout')
SERIAL_CAP=65536
FRAME_CAP=8192
BOUNDS=dict(mode=(0,0o7777),uid=(0,2**32-1),gid=(0,2**32-1),
            inode=(1,2**64-1),links=(1,2**32-1),size=(0,2**40-1),
            mtime=(-2**31,2**34-1),mtime_ns=(0,999999999),
            atime=(-2**31,2**34-1),atime_ns=(0,999999999))
BEGIN=b'ARM16K_NO_PACKAGE_META_BEGIN '
END=b'ARM16K_NO_PACKAGE_META_END '
EPOCH=datetime(1970,1,1,tzinfo=timezone.utc)


def need(ok,message):
 if not ok:raise ValueError(message)


def _row(value):
 need(type(value)is dict,'public directory metadata row schema')
 kind=value.get('type')
 need(type(kind)is str and kind=='directory','public selected node must be an ordinary directory')
 result=dict(type='directory')
 for field in FIELDS[1:]:
  number=value.get(field);low,high=BOUNDS[field]
  need(type(number)is int and low<=number<=high,'bounded public directory integer: '+field)
  result[field]=number
 return result


def project_scan(scan):
 """Project fixed directories after explicit complete lookup coverage.

 ``observed_paths`` is an exact ordered scope attestation from the independent
 caller after all fifteen literal lookups, not provenance authentication. Only
 a covered missing node means absence; omitted/unobserved scope is refused.
 Unknown nodes and row fields are never traversed.
 """
 need(type(scan)is dict,'metadata scan schema')
 coverage=scan.get('observed_paths')
 need(type(coverage)is list and len(coverage)==len(PATHS),'complete fixed public metadata lookup coverage required')
 need(all(type(value)is str and value==path for value,path in zip(coverage,PATHS)),
      'exact ordered public metadata lookup coverage required')
 nodes=scan.get('nodes');need(type(nodes)is dict,'metadata scan nodes schema')
 missing=object();result={}
 for path in PATHS:
  value=nodes.get(path,missing)
  result[path]=None if value is missing else _row(value)
 return result


def _projection(value):
 need(type(value)is dict and len(value)==len(PATHS)and all(path in value for path in PATHS),
      'complete fixed public metadata projection required')
 return {path:None if value[path]is None else _row(value[path])for path in PATHS}


def _decimal(raw,field):
 need(type(raw)is bytes and 0<len(raw)<=20 and re.fullmatch(b'0|[1-9][0-9]*',raw)is not None,
      'canonical public numeric field')
 number=int(raw);low,high=BOUNDS[field]
 need(low<=number<=high,'bounded public numeric field: '+field)
 return number


def _time(raw):
 need(type(raw)is bytes and len(raw)==35,'canonical UTC metadata timestamp')
 match=re.fullmatch(rb'([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{9}) \+0000',raw)
 need(match is not None,'canonical UTC metadata timestamp')
 try:
  year,month,day,hour,minute,second=(int(match[i])for i in range(1,7))
  delta=datetime(year,month,day,hour,minute,second,tzinfo=timezone.utc)-EPOCH
 except (ValueError,OverflowError):raise ValueError('valid bounded UTC metadata calendar')from None
 seconds=delta.days*86400+delta.seconds;ns=int(match[7])
 need(BOUNDS['mtime'][0]<=seconds<=BOUNDS['mtime'][1],'bounded UTC metadata seconds')
 return seconds,ns


def parse_frame(raw,nonce,stage):
 """Parse one probe frame from bounded serial DATA; discard outside bytes.

Only selected frame CRLF is normalized. The caller must supply a per-probe
slice; cumulative/replayed two-frame buffers are refused. No outside serial
text or invalid raw field is included in outputs or errors.
"""
 need(type(raw)is bytes and 0<len(raw)<=SERIAL_CAP,'bounded metadata serial bytes')
 need(type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce)is not None,'literal metadata nonce')
 need(type(stage)is str and stage in GUEST_PHASES,'literal guest metadata stage')
 need(raw.count(BEGIN)==raw.count(END)==1,'exactly one metadata frame required')
 first=raw.find(BEGIN);last=raw.find(END)
 need(first<last and (first==0 or raw[first-1:first]==b'\n')and (last==0 or raw[last-1:last]==b'\n'),
      'metadata frame line boundaries')
 tail=raw.find(b'\n',last)
 need(tail>=0,'complete metadata frame terminator')
 frame=raw[first:tail+1]
 need(len(frame)<=FRAME_CAP,'bounded selected metadata frame')
 frame=frame.replace(b'\r\n',b'\n')
 need(b'\r'not in frame,'canonical metadata frame newlines')
 lines=frame.split(b'\n');binding=(nonce+' '+stage).encode('ascii')
 need(len(lines)==len(PATHS)+3 and lines[-1]==b'' and lines[0]==BEGIN+binding and lines[-2]==END+binding,
      'exact metadata frame stage nonce and row count')
 result={}
 for path,line in zip(PATHS,lines[1:-2]):
  prefix=path.encode('ascii')+b'|'
  need(line.startswith(prefix),'exact ordered public metadata path')
  if line==prefix+b'ABSENT':result[path]=None;continue
  values=line[len(prefix):].split(b'|')
  need(len(values)==8,'exact public metadata row fields')
  mode=values[2]
  need(0<len(mode)<=4 and re.fullmatch(b'0|[1-7][0-7]*',mode)is not None,'canonical public permission mode')
  atime,atime_ns=_time(values[6]);mtime,mtime_ns=_time(values[7])
  row=dict(type='directory',inode=_decimal(values[0],'inode'),links=_decimal(values[1],'links'),mode=int(mode,8),
           uid=_decimal(values[3],'uid'),gid=_decimal(values[4],'gid'),size=_decimal(values[5],'size'),
           atime=atime,atime_ns=atime_ns,mtime=mtime,mtime_ns=mtime_ns)
  result[path]=_row(row)
 return result


def _changes(before,after):
 result=[]
 for path in PATHS:
  left,right=before[path],after[path];fields={}
  if (left is None)!=(right is None):fields['present']=dict(before=left is not None,after=right is not None)
  for field in FIELDS:
   a=None if left is None else left[field];b=None if right is None else right[field]
   if a!=b:fields[field]=dict(before=a,after=b)
  if fields:result.append(dict(path=path,fields=fields))
 return result


def compare_phases(phases):
 """Report exact sequential and endpoint changes. No field is waived."""
 need(type(phases)is dict and len(phases)==len(PHASES)and all(stage in phases for stage in PHASES),
      'exact four metadata phases required')
 selected={stage:_projection(phases[stage])for stage in PHASES}
 transitions=[dict(before=a,after=b,changes=_changes(selected[a],selected[b]))for a,b in zip(PHASES,PHASES[1:])]
 return dict(kind='ARM16K_NO_PACKAGE_FIXED_PUBLIC_METADATA_COMPARISON_V1',
             scope='OBSERVATION_ONLY_NO_ACCEPTANCE_OR_WAIVER',phases=list(PHASES),transitions=transitions,
             endpoint=dict(before=PHASES[0],after=PHASES[-1],changes=_changes(selected[PHASES[0]],selected[PHASES[-1]])),
             atime_policy='OBSERVED_ONLY_NO_RESTORATION',Root_acceptance=None,VM_acceptance=None,waiver=None,restoration=None)

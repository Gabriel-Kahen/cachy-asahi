# SPDX-License-Identifier: MIT
"""Bounded owner-self mount accounting; observations never grant confinement."""
import hashlib
import json
import os
from pathlib import PurePosixPath
import re

MAX_BYTES=1048576
MAX_ROWS=1024
MAX_LINE=16384
LABELS=('root','tmp','var_tmp','source','work')
CLASSES=(*LABELS,'proc','sys','dev','other')
FS_CLASSES=('ext4','overlay','tmpfs','proc','sysfs','devtmpfs','cgroup2','other')
ERRORS=('ValueError','TypeError','PermissionError','FileNotFoundError','OSError','MemoryError','OTHER')
DECLARATION=dict(kind='LLHTTP_FIXED_MOUNT_CLASS_DIAGNOSTIC_V4',diagnostic_only=True,
    fixed_path_labels=list(LABELS),mountinfo_bytes=MAX_BYTES,mountinfo_rows=MAX_ROWS,
    mountinfo_line_bytes=MAX_LINE,max_record_bytes=4096,raw_paths=False,
    raw_environment=False,confinement_acceptance=False,rw_summary_is_allowlist=False)

def need(value,why):
    if not value:raise ValueError(why)

def _path(value):
    value=str(value);path=PurePosixPath(value)
    need(value.startswith('/') and str(path)==value and '..' not in path.parts and '\0' not in value,'ordinary absolute diagnostic path')
    return value

def _unescape(raw):
    escapes={b'040':b' ',b'011':b'\t',b'012':b'\n',b'134':b'\\'};out=bytearray();position=0
    while position<len(raw):
        if raw[position]==92:
            token=raw[position+1:position+4];need(token in escapes,'known kernel mount escape');out.extend(escapes[token]);position+=4
        else:out.append(raw[position]);position+=1
    return bytes(out).decode('utf-8','surrogateescape')

def _readonly(raw):
    parts=raw.split(b',');need(parts and len(parts)<=256 and len(parts)==len(set(parts)) and all(parts),'complete finite mount options')
    need((b'ro' in parts) != (b'rw' in parts),'explicit unique mount write flag');return b'ro' in parts

def parse(raw):
    need(type(raw) is bytes and 0<len(raw)<=MAX_BYTES and raw.endswith(b'\n'),'complete bounded mountinfo bytes')
    lines=raw.splitlines();need(0<len(lines)<=MAX_ROWS,'bounded full mountinfo row count');rows=[];ids=set()
    for line in lines:
        need(0<len(line)<=MAX_LINE,'bounded complete mountinfo line');fields=line.split(b' ')
        need(all(fields) and fields.count(b'-')==1,'complete mountinfo framing');split=fields.index(b'-')
        need(split>=6 and len(fields)==split+4 and all(re.fullmatch(rb'[0-9]{1,20}',n) for n in fields[:2]) and re.fullmatch(rb'[0-9]{1,10}:[0-9]{1,10}',fields[2]),'finite mount identity and mandatory fields')
        ident=int(fields[0]);need(ident>0 and ident not in ids,'unique mount identity');ids.add(ident)
        point=_path(_unescape(fields[4]));_path(_unescape(fields[3]))
        fs=fields[split+1].decode('ascii','strict');fs=fs if fs in FS_CLASSES else 'other'
        rows.append(dict(mountpoint=point,mount_readonly=_readonly(fields[5]),super_readonly=_readonly(fields[split+3]),fstype_class=fs))
    return rows

def _inside(path,base):return path==base or path.startswith(base.rstrip('/')+'/')

def _class(point,paths):
    for label in ('work','source','tmp','var_tmp'):
        if _inside(point,paths[label]):return label
    if point=='/':return 'root'
    for label in ('proc','sys','dev'):
        if _inside(point,'/'+label):return label
    return 'other'

def _cover(rows,path,paths):
    candidates=[r for r in rows if _inside(path,r['mountpoint'])]
    value=dict(status='UNKNOWN',mount_readonly=None,super_readonly=None,mount_class=None,fstype_class=None)
    if not candidates:return value
    length=max(len(PurePosixPath(r['mountpoint']).parts) for r in candidates)
    best=[r for r in candidates if len(PurePosixPath(r['mountpoint']).parts)==length]
    if len(best)!=1:value['status']='AMBIGUOUS';return value
    row=best[0];return dict(status='OK',mount_readonly=row['mount_readonly'],super_readonly=row['super_readonly'],mount_class=_class(row['mountpoint'],paths),fstype_class=row['fstype_class'])

def _error(error):return type(error).__name__ if type(error).__name__ in ERRORS else 'OTHER'

def _probe(call):
    try:return call(),None
    except Exception as error:return None,_error(error)

def observe(root,work,*,mountinfo=None,access=None,statvfs=None):
    paths=dict(root='/',tmp='/tmp',var_tmp='/var/tmp',source=_path(root),work=_path(work))
    rows=[];status='UNKNOWN';error=None
    try:
        if mountinfo is None:
            with open('/proc/self/mountinfo','rb') as stream:mountinfo=stream.read(MAX_BYTES+1)
        rows=parse(mountinfo);status='OK'
    except Exception as failure:error=_error(failure)
    access=os.access if access is None else access;statvfs=os.statvfs if statvfs is None else statvfs
    observations={}
    for label,path in paths.items():
        def writable():
            value=access(path,os.W_OK);need(type(value) is bool,'boolean access observation');return value
        def readonly():
            flags=statvfs(path).f_flag;need(type(flags) is int and flags>=0,'integer filesystem flags');return bool(flags&os.ST_RDONLY)
        write,write_error=_probe(writable);read_only,stat_error=_probe(readonly)
        observations[label]=dict(cover=_cover(rows,path,paths),writable=write,statvfs_readonly=read_only,access_error=write_error,statvfs_error=stat_error)
    counts={label:0 for label in CLASSES};other=[]
    for row in rows:
        if not row['mount_readonly']:
            label=_class(row['mountpoint'],paths);counts[label]+=1
            if label=='other':other.append(row['mountpoint'])
    digest=hashlib.sha256(json.dumps(sorted(other),ensure_ascii=True,separators=(',',':')).encode()).hexdigest()
    summary=dict(counts=counts,other_rw_points_sha256=digest) if status=='OK' else dict(counts=None,other_rw_points_sha256=None)
    return dict(kind=DECLARATION['kind'],mountinfo=dict(status=status,rows=len(rows) if status=='OK' else None,error=error),paths=observations,rw_mount_classes=summary,confinement_acceptance=False)

def record(value):
    need(set(value)=={'kind','mountinfo','paths','rw_mount_classes','confinement_acceptance'} and value['kind']==DECLARATION['kind'] and value['confinement_acceptance'] is False,'fixed diagnostic schema, never acceptance')
    info=value['mountinfo'];need(set(info)=={'status','rows','error'} and info['status'] in ('OK','UNKNOWN') and info['error'] in (*ERRORS,None) and (info['rows'] is None or type(info['rows']) is int and 0<=info['rows']<=MAX_ROWS),'fixed bounded mountinfo status')
    need(set(value['paths'])==set(LABELS),'only five fixed path labels')
    for item in value['paths'].values():
        need(set(item)=={'cover','writable','statvfs_readonly','access_error','statvfs_error'} and all(item[k] is None or type(item[k]) is bool for k in ('writable','statvfs_readonly')) and all(item[k] in (*ERRORS,None) for k in ('access_error','statvfs_error')),'fixed path observations without raw values')
        cover=item['cover'];need(set(cover)=={'status','mount_readonly','super_readonly','mount_class','fstype_class'} and cover['status'] in ('OK','UNKNOWN','AMBIGUOUS') and all(cover[k] is None or type(cover[k]) is bool for k in ('mount_readonly','super_readonly')) and cover['mount_class'] in (*CLASSES,None) and cover['fstype_class'] in (*FS_CLASSES,None),'fixed covering mount classes without paths')
    summary=value['rw_mount_classes'];need(set(summary)=={'counts','other_rw_points_sha256'},'fixed class-only write summary')
    if info['status']=='UNKNOWN':need(summary['counts'] is None and summary['other_rw_points_sha256'] is None,'unknown mount table cannot claim zero writable mounts')
    else:need(set(summary['counts'])==set(CLASSES) and all(type(n) is int and 0<=n<=MAX_ROWS for n in summary['counts'].values()) and re.fullmatch('[0-9a-f]{64}',summary['other_rw_points_sha256']),'bounded observed class-only write summary')
    text='MOUNT_CLASS: '+json.dumps(value,sort_keys=True,separators=(',',':'));need(len((text+'\n').encode())<=4096,'bounded fixed mount diagnostic record');return text

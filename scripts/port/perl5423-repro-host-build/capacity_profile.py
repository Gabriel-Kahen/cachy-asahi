# SPDX-License-Identifier: MIT
"""Read-only, identity-bound capacity model for this finite Perl workload."""
import json
import os
from pathlib import Path
import re

MIB=1024**2
MAX_NODES=102000
METADATA_WORK=512*MIB
METADATA_RESERVE=512*MIB
FIXED={'ext2/ext3':(0xef53,{'ext2','ext3','ext4'}),'xfs':(0x58465342,{'xfs'}),'tmpfs':(0x1021994,{'tmpfs'})}


def need(value,message):
    if not value:raise ValueError(message)


def metadata(text):
    """Accept one raw separate Metadata,DUP allocation and global-reserve row."""
    need(len(text)<=65536,'Btrfs usage output bound')
    lines=[line.strip() for line in text.splitlines()]
    meta=[line for line in lines if line.startswith(('Metadata,','Data+Metadata,'))]
    reserve=[line for line in lines if line.startswith('Global reserve:')]
    need(len(meta)==len(reserve)==1,'one separate metadata and global reserve record required')
    m=re.fullmatch(r'Metadata,DUP: Size:([0-9]+), Used:([0-9]+) \([0-9]+\.[0-9]+%\)',meta[0])
    g=re.fullmatch(r'Global reserve:\s+([0-9]+)\s+\(used: ([0-9]+)\)',reserve[0])
    need(m is not None and g is not None,'raw supported Metadata,DUP/global reserve fields required')
    total,used=map(int,m.groups());global_total,global_used=map(int,g.groups())
    need(0<=used<=total and 0<=global_used<=global_total<=total,'inconsistent Btrfs metadata accounting')
    need(global_used==0,'Btrfs global emergency reserve is in use')
    free=total-used-global_total
    return dict(total_bytes=total,used_bytes=used,global_reserve_bytes=global_total,
        global_reserve_used_bytes=global_used,headroom_after_global_reserve_bytes=free,
        workload_budget_bytes=METADATA_WORK,retained_metadata_reserve_bytes=METADATA_RESERVE,
        required_headroom_bytes=METADATA_WORK+METADATA_RESERVE)


def kernel_mount(mount,text=None):
    if text is None:
        with Path('/proc/self/mountinfo').open('rb') as stream:raw=stream.read(1024**2+1)
        need(len(raw)<=1024**2,'kernel mount table bound');text=raw.decode()
    def unescape(value):return re.sub(r'\\([0-7]{3})',lambda m:chr(int(m[1],8)),value)
    matches=[]
    for line in text.splitlines():
        left,separator,right=line.partition(' - ');a=left.split();b=right.split()
        need(separator and len(a)>=6 and len(b)>=3,'malformed kernel mount table')
        if unescape(a[4])==mount['target']:
            need(a[2]==mount['maj:min'] and b[0]==mount['fstype'] and unescape(b[1])==mount['source'].split('[',1)[0],'kernel mount identity mismatch')
            matches.append(dict(mount_id=int(a[0]),mount_device=a[2],target=unescape(a[4]),filesystem=b[0],source=unescape(b[1])))
    need(len(matches)==1,'one matching kernel mount entry required')
    return matches[0]


def measure(command,path,device):
    """Bind query output to the exact stable path, mount, st_dev and statfs ID."""
    path=Path(path).resolve()
    def query(argv):
        result=command(argv)
        need(result.returncode==0,'filesystem capacity query failed')
        return result.stdout
    def snapshot():
        need(path.stat().st_dev==device,'capacity path crossed device')
        v=os.statvfs(path)
        raw=query(['stat','--file-system','--format=%T %t %i','--',str(path)]).decode().strip()
        need(len(raw)<=256,'filesystem identity bound')
        fields=raw.split();need(len(fields)==3,'filesystem identity fields required')
        kind,magic,fsid=fields
        need(re.fullmatch('[0-9a-f]+',magic) and re.fullmatch('[0-9a-f]+',fsid),'numeric filesystem identity required')
        body=query(['findmnt','--json','--target',str(path),'--output','TARGET,SOURCE,FSTYPE,UUID,MAJ:MIN'])
        need(len(body)<=16384,'mount identity output bound')
        rows=json.loads(body)['filesystems'];need(len(rows)==1,'one exact mounted filesystem required')
        mount=rows[0];target=Path(mount['target'])
        need(target.is_absolute() and path.is_relative_to(target.resolve()) and target.stat().st_dev==device,'mount/path device mismatch')
        need(isinstance(mount['source'],str) and mount['source'] and re.fullmatch('[0-9]+:[0-9]+',mount['maj:min']),'mount source/device identity required')
        if kind=='btrfs':
            need(int(magic,16)==0x9123683e and mount['fstype']=='btrfs' and re.fullmatch('[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}',mount['uuid'] or ''),'authenticated Btrfs mount required')
        else:
            need(kind in FIXED and int(magic,16)==FIXED[kind][0] and mount['fstype'] in FIXED[kind][1],'unknown filesystem resource model')
        need(path.stat().st_dev==device,'capacity path changed during identity query')
        return dict(path=str(path),device=device,filesystem=kind,magic=magic,statfs_id=fsid,
            f_fsid=v.f_fsid,mount=mount,kernel_mount=kernel_mount(mount))
    before=snapshot();result=dict(before)
    if before['filesystem']=='btrfs':
        usage=query(['btrfs','filesystem','usage','-b',str(path)]).decode()
        result['metadata']=metadata(usage)
        result['usage_query_path']=str(path)
    need(snapshot()==before,'filesystem/device identity changed during capacity measurement')
    return result


def counters(total,free,model=None):
    need(type(total) is int and type(free) is int and 0<=free<=total,'inconsistent inode counters')
    if model=='UNREPORTED_DYNAMIC':need(total==free==0,'dynamic inode counters changed')
    if model=='REPORTED_FIXED':need(total>0,'fixed inode pool is unreported or empty')


def inode_model(record,observation,nodes):
    """No fabricated inode counts: only proven Btrfs uses metadata instead."""
    need(record['device']==observation['device'] and record['f_fsid']==observation['f_fsid'] and
        Path(record['path'])==Path(observation['path']).resolve(),'cross-device or wrong-path capacity record')
    total,free=observation['total_inodes'],observation['available_inodes']
    counters(total,free)
    if record['filesystem']!='btrfs':
        need(total>0,'fixed inode pool is unreported or empty')
        need(record['filesystem'] in FIXED,'unknown filesystem resource model')
        return 'REPORTED_FIXED'
    need(0<nodes<=MAX_NODES,'Btrfs workload exceeds fixed102000-node model')
    need(record['usage_query_path']==record['path'],'cross-path Btrfs metadata record')
    m=record['metadata']
    need(m['headroom_after_global_reserve_bytes']>=m['required_headroom_bytes'],'insufficient measured Btrfs metadata headroom')
    need(m['required_headroom_bytes']==METADATA_WORK+METADATA_RESERVE,'Btrfs metadata reserve differs')
    if observation['total_inodes']==observation['available_inodes']==0:return 'UNREPORTED_DYNAMIC'
    need(observation['total_inodes']>0,'inconsistent Btrfs inode counters')
    return 'REPORTED_FIXED'

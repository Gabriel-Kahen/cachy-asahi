"""After all descendants/leases retire: exact mounts then owned DM, never force."""
import ast,errno,os,types
from pathlib import Path
import inputs,lease_table
P,C,_,_=inputs.broker()
def request_source(raw):
 text=raw.decode();node=next(n for n in ast.walk(ast.parse(text))if isinstance(n,ast.FunctionDef)and n.name=='request');old=ast.get_source_segment(text,node);anchor="os.open('/dev/mapper/control',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)";P.need(old.count(anchor)==1,'one source-bound DM open');new=old.replace(anchor,'os.dup(self._retained_control)');P.need(new.replace('os.dup(self._retained_control)',anchor)==old,'whole original DM request inverse');return new

def retire(bootstrap,device,prepared,context,row,mounts):
 C.pid1();P.need(row['group_absence_verified']is True and mounts.retired()['status']=='NO_ACTIVE_PID1_RUNTIME_MOUNTS','worker descendants and private mounts retired first');context.check();expected=lease_table.rows(context.mounts)
 P.need(device.dev==context.identity[0]and device.created is True,'only original owned mapping');prepared.close();context.close_source()
 for point in('/out','/work','/held','/source','/inputs','/immutable-inputs','/broker-authorities','/immutable'):
  current=lease_table.rows(mounts.inventory());P.need(current==expected,'complete mount inventory before disposal');selected=[k for k,v in expected.items()if v.split()[4]==os.fsencode(point)];P.need(len(selected)==1,'one exact owned runtime mount '+point)
  bootstrap.umount(point);del expected[selected[0]];P.need(lease_table.rows(mounts.inventory())==expected,'only exact owned mount retired')
 # Original mutate ioctl body and identity guard held; only retained private FD.
 path=inputs.D.parent/'gnu-verity-bootstrap-development-20261018/dm.py';raw=path.read_bytes();fn=request_source(raw);space=dict(vars(bootstrap.dm));exec(compile(fn,'<pid1-retained-control-disposal>','exec'),space);device._retained_control=context.disposal_control;device.request=types.MethodType(space['request'],device);dev=device.dev;device.remove()
 R=context.R;buf=bytearray(65536);h=R.Header.from_buffer(buf);h.version[:]=(4,0,0);h.data_size=len(buf);h.data_start=312;h.dev=dev;h.flags=1<<4
 import fcntl
 try:fcntl.ioctl(context.disposal_control,(3<<30)|(312<<16)|(0xfd<<8)|12,buf,True)
 except OSError as e:P.need(e.errno in(errno.ENXIO,errno.ENODEV),'exact removed mapping absence')
 else:raise ValueError('removed verity mapping still queryable')
 context.close();return dict(status='WORKER_GROUP_LEASES_MOUNTS_AND_OWNED_DM_RETIRED',mounts=8,raw_disks='HOST_OWNER_MAY_DISPOSE_ONLY_AFTER_QEMU_GROUP_ABSENCE',hardware='NOT_RUN',release='NOT_ADMITTED')

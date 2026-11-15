# SPDX-License-Identifier: MIT
"""Independent retained-output and stopped-export joins, never run package code."""
import importlib.util,io,stat,tarfile
from pathlib import Path
s=importlib.util.spec_from_file_location('retained_output_Source_DATA',Path(__file__).parent/'source.py');S=importlib.util.module_from_spec(s);s.loader.exec_module(S);D=S.D
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']

def natural(v):
 D.need(type(v)is dict and v.get('natural_exit')is True and v.get('forced_cleanup')is False and v.get('retirement')=='REAPED'and v.get('group_absent')is True and v.get('ownership_lost')is False and v.get('leader_held_until_group_inspection')is True and v.get('exit_observed_via_waitpid')is True and type(v.get('exit'))is int and v['exit']==0,'natural owned zero exit')
 D.need(type(v.get('elapsed_seconds'))in(int,float)and 0<v['elapsed_seconds']<=660,'bounded natural elapsed')

def inspect(row,a,admission_sha,domain,cid,created):
 h,x=row['HostConfig'],row['Config'];D.need(row['Id']==cid and row['Image']==a['image']and row['Name']=='/'+a['container']and row['State']['Running']is False and type(row['State']['Pid'])is int and row['State']['Pid']==0 and row['State']['Status']==('created'if created else'exited'),'exact stopped owned lifecycle container')
 if not created:D.need(type(row['State']['ExitCode'])is int and row['State']['ExitCode']==0 and row['State']['OOMKilled']is False and not row['State'].get('Error'),'zero non-OOM lifecycle stop')
 D.need(h['NanoCpus']==2000000000 and h['Memory']==h['MemorySwap']==2147483648 and h['PidsLimit']==128 and h['ReadonlyRootfs']is False and h['NetworkMode']=='none'and h['Init']is True and h['CapDrop']==['ALL']and h['SecurityOpt']==['no-new-privileges']and not h['Privileged']and not h.get('Devices')and not h.get('DeviceRequests')and h['Tmpfs']==domain['tmpfs'],'unchanged finite lifecycle confinement')
 raw=h['CapAdd'];D.need(type(raw)is list and len(raw)==7 and all(type(v)is str for v in raw),'seven raw capability names');caps=[v.removeprefix('CAP_')for v in raw];D.need(len(set(caps))==7 and set(caps)==set(domain['cap_add']),'exact semantic seven capabilities; raw receipts retained')
 labels=dict(a['base_labels'],**{'cachy-asahi.perl-lifecycle.operation':'perl5423-installed-lifecycle-v1','cachy-asahi.perl-lifecycle.admission':admission_sha,'cachy-asahi.perl-lifecycle.source':a['source_map_sha256']})
 D.need(x['Labels']==labels and x['User']=='0:0'and x['Hostname']=='perl-installed-lifecycle'and x['Entrypoint']==['/usr/bin/python3']and x['Cmd']==['-I','-B','/inputs/actor.py','--admission-sha256',admission_sha,'--source-map-sha256',a['source_map_sha256']],'actual exact labels/user/entry argv')
 m=row['Mounts'];D.need(len(m)==1 and m[0]['Type']=='bind'and m[0]['Destination']=='/inputs'and m[0]['Source']==a['inputs']and m[0]['RW']is False,'one exact readonly input bind; no retained-path mount')
 for mount in [*domain['tmpfs'],'/inputs']:D.need(not Path(S.RETENTION['path']).is_relative_to(mount),'persistent path outside every admitted mount')

def export(raw):
 D.need(len(raw)<=64*D.MIB and len(raw)%512==0,'bounded ordinary result TAR');out={};total=0
 with tarfile.open(fileobj=io.BytesIO(raw),mode='r:')as t:
  for item in t:
   parts=Path(item.name).parts;D.need(parts and parts[0]=='result'and len(parts)<=2 and '..'not in parts,'flat result namespace')
   if len(parts)==1:D.need(item.isdir(),'ordinary result root');continue
   n=parts[1];D.need(n not in out and item.isfile()and not item.sparse and 0<=item.size<=16*D.MIB,'ordinary bounded result member');total+=item.size;D.need(total<=64*D.MIB and len(out)<160,'finite result payload');b=t.extractfile(item).read(item.size+1);D.need(len(b)==item.size,'complete raw result body');out[n]=b
 return out

def create_argv(a,raw,sha,domain):
 argv=DOCKER+['create','--name',a['container'],'--hostname=perl-installed-lifecycle','--cpus=2','--memory=2g','--memory-swap=2g','--pids-limit=128','--init','--network=none','--user=0:0','--cap-drop=ALL','--security-opt=no-new-privileges','--ulimit=nofile=1024:1024','--ulimit=core=0:0']
 labels=dict(a['base_labels'],**{'cachy-asahi.perl-lifecycle.operation':'perl5423-installed-lifecycle-v1','cachy-asahi.perl-lifecycle.admission':sha,'cachy-asahi.perl-lifecycle.source':a['source_map_sha256']})
 for k,v in labels.items():argv+=['--label',k+'='+v]
 argv+=['--cap-add='+v for v in domain['cap_add']]+['--tmpfs='+k+':'+v for k,v in domain['tmpfs'].items()]
 return argv+['--mount','type=bind,src='+a['inputs']+',dst=/inputs,readonly','--env','LIFECYCLE_ADMISSION_SHA256='+sha,'--env','LIFECYCLE_ADMISSION_JSON='+raw.decode(),'--entrypoint=/usr/bin/python3',a['image'],'-I','-B','/inputs/actor.py','--admission-sha256',sha,'--source-map-sha256',a['source_map_sha256']]

def review(get,b,contract,domain):
 raw=get('installed/producer-report.json',8*D.MIB);p=D.decode(raw);D.need(D.pin(raw)['sha256']==b['producer_report_sha256']and p['source_map_sha256']==contract['capsule']['source_map_sha256']and p['first_failure']is None and p['status']=='PASS_PRODUCED_PERL_INSTALLED_LIFECYCLE_DATA_REQUIRES_INDEPENDENT_ROOT_REVIEW'and p['cleanup']==dict(status='OWNED_CONTAINER_REMOVED',natural=True),'complete new producer; old exit-zero failure cannot substitute')
 rows=p['commands'];steps=['image','daemon-architecture','daemon-storage','create','inspect-before','run','inspect-after','export','cleanup-inspect','remove-owned'];D.need([r['step']for r in rows]==steps,'exact ten producer commands')
 for r in rows:
  natural(r['lifecycle']);D.need(r['success']is True and type(r['returncode'])is int and r['returncode']==0,'actual natural successful CLI')
  for k in('stdout','stderr'):D.need(D.pin(get('installed/'+r['step']+'.'+k,64*D.MIB))==r[k],'whole producer channel join')
 a_raw=get('inner-admission.json');a=D.decode(a_raw);admission_sha=D.pin(a_raw)['sha256'];D.need(p['admission_sha256']==admission_sha and a['source_map_sha256']==contract['capsule']['source_map_sha256']and a['image']==b['image']and a['run']==b['run']+'-'+b['job']and a['container']=='cachy-perl-lifecycle-'+a['run'],'new immutable image/actual run/job/inner admission')
 D.need(rows[0]['argv']==DOCKER+['image','inspect',b['image']]and rows[1]['argv']==DOCKER+['info','--format','{{.Architecture}}']and rows[2]['argv']==DOCKER+['info','--format','{{.DockerRootDir}}']and rows[3]['argv']==create_argv(a,a_raw,admission_sha,domain),'exact fixed image/daemon/create argv')
 cid=p['container_id'];D.need(type(cid)is str and len(cid)==64 and all(c in'0123456789abcdef'for c in cid),'literal owned container ID')
 D.need(get('installed/create.stdout').decode().strip()==cid and rows[4]['argv']==DOCKER+['inspect',cid],'new created ID and initial inspection join')
 for step,created in [('inspect-before',True),('inspect-after',False),('cleanup-inspect',False)]:
  data=D.decode(get('installed/'+step+'.stdout'));D.need(len(data)==1,'one raw inspect');inspect(data[0],a,admission_sha,domain,cid,created)
 D.need(rows[5]['argv']==DOCKER+['start','--attach',cid]and rows[6]['argv']==DOCKER+['inspect',cid]and rows[7]['argv']==DOCKER+['cp',cid+':'+S.RETENTION['path'],'-']and rows[8]['argv']==DOCKER+['inspect',cid]and rows[9]['argv']==DOCKER+['rm',cid],'after-stopped persistent export and exact natural owned cleanup')
 members=export(get('installed/export.stdout',64*D.MIB));actor_raw=members.get('report.json',b'');D.need(actor_raw and D.pin(actor_raw)==p['actor_report']and get('installed/data/report.json',16*D.MIB)==actor_raw,'raw TAR and retained actor report join')
 report=D.decode(actor_raw);proof=report['retained_output'];D.need(type(proof)is dict and all(type(proof[k])is int for k in('uid','gid','mode'))and proof['parent_absent_before_entry']is True and proof['same_filesystem_as_parent_root']is True,'typed retained output assertions');D.need(proof==S.RETENTION and report['admission_sha256']==admission_sha and report['source_map_sha256']==a['source_map_sha256']and report['status']=='PASS_FINITE_NATIVE_ARM4K_PERL_INSTALLED_LIFECYCLE'and report['first_failure']is None,'exact new retained fresh0700/root-owner/root-device Source-mediated assertion')
 return dict(status='PASS_RETAINED_OUTPUT_DATA_JOINS_ONLY',retained_output=report['retained_output'],proof_boundary='PINNED_ACTOR_CHECKS_LSTAT_OWNER_MODE_ROOT_ST_DEV; BOOLEAN_ASSERTION_NOT_INDEPENDENT_NUMERIC_STAT',actor_report=D.pin(actor_raw),producer_report=D.pin(raw),natural_owned_cleanup=True,package_runtime_acceptance=False)

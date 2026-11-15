# SPDX-License-Identifier: MIT
"""Synthetic finite DATA only: independent complete23-command producer evidence."""
import copy,hashlib,io,json,stat,tarfile
from pathlib import PurePosixPath as Path

def encoded(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def fixture(P,d,b,root,cap='CAP_CHOWN'):
 image='sha256:'+'a'*64;work=Path('/modeled/work');name='perl-xs-'+b['run']+'-'+'b'*12;init=name+'-init';volume=name+'-work';bundle=work/'bundle';data={};rows=[]
 op=dict(schema=1,operation=P.OPERATION,authorization='ROOT_ACCEPTED_PAIR_AND_ADMITTED_NATIVE_XS',source=dict(sha=b['source'],ref=b['ref'].removeprefix('refs/heads/')),**{k:b[k]for k in ('run','job','approval')},pair=P.PAIR,image=image,source_readback_sha256='1'*64,native_daemon_identity_sha256='2'*64,input_signature_audit_sha256='3'*64,expected349_sha256=P.INVENTORY,runner_sha256=P.RUNNER_SHA,runtime_identity_generator_sha256=P.NATIVE_SHA,authorize_runtime_observation_only=True,accepted_reader_receipt=dict(path='/inputs/accepted-reader.json',**P.DECISION),nested_invocation='NOT_INVOKED',nested_qualification='NOT_QUALIFIED')
 for n,k in [('xs-admission.json','xs_admission_sha256'),('xs-inputs.json','inputs_sha256'),('xs-plan.json','plan_sha256'),('bundle-map.json','bundle_map_sha256')]:data['bundle/'+n]=encoded({});op[k]=d.pin(data['bundle/'+n])['sha256']
 raw=encoded(op);sha=d.pin(raw)['sha256'];data.update({'xs/operation.json':raw,'bundle/operation.json':raw,'daemon.json':b'MODELED_ROOT_DAEMON'})
 h=dict(operation_sha256=sha,source_readback_sha256=op['source_readback_sha256'],daemon_identity_sha256=op['native_daemon_identity_sha256'],bootstrap={'signatures_sha256':op['input_signature_audit_sha256']})
 keys=('ID','OSType','Architecture','SecurityOptions','CgroupVersion','CpuCfsQuota','MemoryLimit','SwapLimit','PidsLimit','DockerRootDir');daemon=dict(info={k:'MODELED'for k in keys},version=dict(Server={'Version':'MODELED'}));actual=copy.deepcopy(daemon);actual.update(socket_before=[1,2,stat.S_IFSOCK|0o600,0,0],socket_after=[1,2,stat.S_IFSOCK|0o600,0,0]);data['xs/actual-daemon.json']=encoded(actual);data['xs/root-daemon-proof.json']=data['daemon.json']
 token=hashlib.sha256((b['source']+':'+b['ref']+':'+b['run']).encode()).hexdigest()[:24];image_row=dict(Id=image,Architecture='arm64',Os='linux',RepoTags=['perl-native-base:'+token],Config={'Labels':{'cachy-asahi.hosted-perl':token,'cachy-asahi.hosted-perl.source':b['source']}})
 def row(actor):
  x=dict(User='1001:1001'if actor else'0:0',Hostname='perl5423-native',Entrypoint=['/usr/bin/python3']if actor else['/usr/bin/chown'],Cmd=['-I','-B','/inputs/consumer/native_adapter/native.py','actor','--admission-sha256',sha]if actor else['1001:1001','/work'],WorkingDir='/work',Labels={'cachy-asahi.admission':sha})
  host=dict(NanoCpus=2000000000,Memory=4294967296,MemorySwap=4294967296,PidsLimit=256,ReadonlyRootfs=True,NetworkMode='none',CapDrop=['ALL'],CapAdd=[]if actor else[cap],SecurityOpt=['no-new-privileges'],Privileged=False,Devices=[],DeviceRequests=None,Init=actor,CgroupnsMode='private',Tmpfs=P.TMPFS,Mounts=[dict(Type='volume',Source=volume,Target='/work',VolumeOptions={'NoCopy':True})])
  mounts=[dict(Type='volume',Name=volume,Destination='/work',RW=True)]
  if actor:mounts.insert(0,dict(Type='bind',Source=str(bundle),Destination='/inputs',RW=False))
  return dict(Id=('c'if actor else'd')*64,Name='/'+(name if actor else init),Image=image,Config=x,HostConfig=host,Mounts=mounts,State=dict(Status='created',Running=False,Pid=0,ExitCode=0,OOMKilled=False))
 actor,initializer=row(True),row(False);actor_after=copy.deepcopy(actor);actor_after['State']['Status']='exited';init_after=copy.deepcopy(initializer);init_after['State']['Status']='exited'
 lifecycle=dict(natural_exit=True,forced_cleanup=False,retirement='REAPED',group_absent=True,leader_held_until_group_inspection=True,ownership_lost=False,exit_observed_via_waitpid=True,pid=42,exit=0,elapsed_seconds=.1)
 def add(argv,body=b'',saved=None,tar=False):
  i=len(rows);r=dict(argv=argv,lifecycle=copy.deepcopy(lifecycle),log=f'command-{i:03d}.log',returncode=0,launched=True)
  if tar:r['stdout']='output.tar'
  rows.append(r);data['xs/'+r['log']]=body
  if saved:data[saved]=body
 D=P.DOCKER
 add(D+['image','inspect',image],encoded([image_row]),'xs/image-inspect.json')
 for k in ('info','version'):add(D+[k,'--format','{{json .}}'],encoded(actual[k]))
 add(D+['container','ls','--all','--format','{{.Names}}']);add(D+['volume','ls','--quiet']);label='cachy-asahi.admission='+sha
 add(D+['volume','create','--label',label,volume]);add(D+['create','--name',init,'--label',label,'--cpus=2','--memory=4g','--memory-swap=4g','--pids-limit=256','--network=none','--read-only','--user=0:0','--cap-drop=ALL','--cap-add=CHOWN','--security-opt=no-new-privileges','--mount',f'type=volume,src={volume},dst=/work,volume-nocopy','--entrypoint=/usr/bin/chown',image,'1001:1001','/work'])
 add(D+['inspect',init],encoded([initializer]),'xs/init-before.json');add(P.actor_argv(name,volume,image,bundle,sha));add(D+['inspect',name],encoded([actor]),'xs/actor-before.json');add(D+['start','--attach',init]);add(D+['inspect',init],encoded([init_after]),'xs/init-after.json');add(D+['start','--attach',name]);add(D+['inspect',name],encoded([actor_after]),'xs/actor-after.json');add(D+['cp',name+':/work/output','-'],tar=True)
 result=dict(schema=1,status='RUNNER_COMPLETED',failure=None,runner_status='FOUR_SMOKE_COMMANDS_COMPLETED',operation_sha256=sha,native_acceptance=False,XS_acceptance=False,qualification='NOT_GRANTED',nested_invocation='NOT_INVOKED',nested_qualification='NOT_QUALIFIED')
 observation=dict(schema=1,operation_sha256=sha,generator_sha256=P.NATIVE_SHA,native_acceptance=False,XS_acceptance=False)
 exported={'evidence-map.json':(encoded({'MODELED':dict(file='evidence-001.data',**d.pin(b'MODELED'))}),0o600),'evidence-001.data':(b'MODELED',0o600),'actor-result.json':(encoded(result),0o600),'runtime-observation.json':(encoded(observation),0o600),'actual-packages.txt':((root/'accepted/packages.txt').read_bytes(),0o600),'operation.json':(raw,0o600),'accepted-reader.json':((root/'accepted/Root-decision.json').read_bytes(),0o600)}
 pre=dict(schema=1,kind='XS_WORK_VOLUME_PREENTRY_V5',phase='OBSERVED_BEFORE_ANY_WORK_WRITE',operation_sha256=sha,**{k:op[k]for k in ('source','run','job','image')},native_adapter_sha256=P.NATIVE_SHA,work_root=dict(device=1,inode=2,uid=1001,gid=1001,mode=0o755,empty=True,writable=True),native_acceptance=False,XS_acceptance=False,runtime_observation=d.pin(exported['runtime-observation.json'][0]),actor_result=d.pin(exported['actor-result.json'][0]))
 exported['work-preentry-v5.json']=(encoded(pre),0o600)
 for kind,n,observed in [('container',name,actor_after),('container',init,init_after),('volume',volume,dict(Name=volume,Labels={'cachy-asahi.admission':sha}))]:add(D+[kind,'inspect',n],encoded([observed]));add(D+[kind,'rm',*([]if kind=='volume'else['--force']),observed.get('Id',n)])
 add(D+['container','ls','--all','--format','{{.Names}}']);add(D+['volume','ls','--quiet'])
 report=dict(schema=1,status='SMOKE_EVIDENCE_EXPORTED_PENDING_INDEPENDENT_READER',operation_sha256=sha,native_acceptance=False,XS_acceptance=False,qualification='NOT_GRANTED',owned_resources_absent=True,planned=dict(actor=name,init=init,volume=volume),operations=rows,cleanup=[dict(kind=k,name=n,removed=True)for k,n in [('container',name),('container',init),('volume',volume)]]);data['xs/producer-receipt.json']=encoded(report)
 def finish():
  stream=io.BytesIO()
  with tarfile.open(fileobj=stream,mode='w')as t:
   info=tarfile.TarInfo('output');info.type=tarfile.DIRTYPE;info.mode=0o700;t.addfile(info)
   for n,(body,mode)in exported.items():
    info=tarfile.TarInfo('output/'+n);info.mode=mode;info.size=len(body);t.addfile(info,io.BytesIO(body));data['xs/exported/'+n]=body
  data['xs/output.tar']=stream.getvalue();data['xs/producer-receipt.json']=encoded(report)
  return data
 finish();return dict(data=data,exported=exported,report=report,op=op,h=h,b=b,image=image,work=work,daemon=daemon,finish=finish)

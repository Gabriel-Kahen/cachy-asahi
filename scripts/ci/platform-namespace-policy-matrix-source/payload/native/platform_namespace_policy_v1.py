# SPDX-License-Identifier: MIT
"""Four-case namespace policy DATA/plan and one future guest exec; inert import."""
import base64,hashlib,json,os,re,sys
from pathlib import Path

PARENT='05df8c71ea2bcb525bb1cfbc59983452062a1e97'
CASES=('baseline','apparmor_only','seccomp_only','both')
POLICY=([],['apparmor=unconfined'],['seccomp=unconfined'],['apparmor=unconfined','seccomp=unconfined'])
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']
LABEL='org.cachy-asahi.namespace-policy'
PREFIX=b'PLATFORM_NAMESPACE_POLICY_CONTEXT_V1 '
OPERATION='platform-namespace-policy-matrix-v1'
CONTRACT='native/platform-namespace-policy-v1.json'
MODULE='native/platform_namespace_policy_v1.py'
TARGET='namespace-policy-prepared'

class MatrixGuard(ValueError):pass
def need(v,s):
 if not v:raise MatrixGuard(s)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def keys(v,w,label):need(type(v)is dict and set(v)==set(w),label+' exact fields')
def hexvalue(v,n):return type(v)is str and re.fullmatch('[0-9a-f]{'+str(n)+'}',v)is not None
def binding(v):
 keys(v,('source','ref','run','attempt','token'),'matrix binding')
 need(hexvalue(v['source'],40)and v['source']!=PARENT and type(v['ref'])is str and v['ref'].startswith('refs/heads/codex/')and type(v['run'])is str and re.fullmatch('[1-9][0-9]*',v['run'])and type(v['attempt'])is int and v['attempt']==1,'actual new Source/run/attempt; never reuse parent binding')
 need(v['token']==hashlib.sha256((v['source']+':'+v['ref']+':'+v['run']).encode()).hexdigest()[:24],'exact Source/ref/run token');return v
def contract(c):
 need(type(c)is dict and type(c['schema'])is int and c['schema']==1 and c['kind']=='platform-namespace-policy-matrix-contract-v1'and c['source_parent']==PARENT and c['operation']==OPERATION and c['actual']==dict(source=None,ref=None,run=None,image=None),'fixed inert matrix contract')
 need(c['cases']==[dict(id=n,security_opt=p)for n,p in zip(CASES,POLICY)]and c['prepared_target']==TARGET and c['package_target']=='platform-alpm-release','fixed four-axis contract')
 need(c['network']=='none'and c['privileged']is False and c['cap_add']==c['cap_drop']==[]and c['no_new_privileges_added']is False and c['no_host_mounts']is True and c['acceptance']is False,'no unrelated policy/capability change')
 need(c['resources']==dict(memory=536870912,memory_swap=536870912,nano_cpus=1000000000,pids_limit=32,nofile=128),'identical finite experimental controls')
 need(c['probe']['argv']==['/usr/bin/bwrap','--die-with-parent','--ro-bind','/','/','--unshare-net','--dev','/dev','--tmpfs','/home','--chdir','/tmp','--tmpfs','/var/lib/pacman','--','/usr/bin/true']and c['probe']['cwd']=='/tmp','single source-owned namespace operation')
 need(c['probe']['environment']=={'PATH':'/usr/bin:/bin','LC_ALL':'C','HOME':'/tmp','TMPDIR':'/tmp'}and c['probe']['one_exec']is True and c['build_network']=='none'and c['build_pull']is False and c['downloads_added']is False and c['package_install_during_probe']is False,'fixed environment and no extra preparation/probe actors')
 need(c['limits']==dict(cases=4,probe_seconds=20,container_start_seconds=30,whole_matrix_seconds=240,metadata_bytes=1048576,case_output_bytes=65536,result_bytes=1048576,Source_mapped_files=200,Source_leaf_bytes=33554432),'fixed existing/lower limits');return c

def split_tools_dockerfile(raw,map_hash):
 """Only name the original stage and insert a continuation before the held RUN."""
 need(type(raw)is bytes and len(raw)<=65536 and hexvalue(map_hash,64),'bounded original generated Dockerfile')
 first,rest=raw.split(b'\n',1);need(re.fullmatch(rb'FROM native-developer-base:[0-9a-f]{24}',first),'original owned base alias')
 run=('RUN /usr/bin/python3 -I -B /opt/native-platform-tools-alpm-v1/source/native/platform_alpm_v1.py --inside-image --retain-failure-image --map-sha256 '+map_hash+'\n').encode()
 seam=b'COPY platform-alpm-v1/source/ /opt/native-platform-tools-alpm-v1/source/\n'+run
 need(raw.count(seam)==1 and raw.endswith(run+b'USER alarm\nWORKDIR /tmp\n')and b' AS 'not in raw and raw.count(b'FROM ')==1,'exact existing Source COPY/package RUN seam')
 prefix=(b'USER root\nCOPY deps/ /tmp/developer-deps/\nCOPY tools/ /opt/native-developer-tools/\nCOPY disabled-hooks.txt /tmp/developer-hooks.txt\n'
         b'RUN while IFS= read -r hook; do ln -sf /dev/null \"/builder-disabled-hooks/$hook\"; done < /tmp/developer-hooks.txt '
         b'&& pacman -U --noconfirm --noscriptlet /tmp/developer-deps/*.pkg.tar.xz && ldconfig '
         b'&& rm -rf /tmp/developer-deps /tmp/developer-hooks.txt /var/cache/pacman/pkg/* '
         b'&& pacman -Q | LC_ALL=C sort > /builder-packages.lock\n')
 need(raw==first+b'\n'+prefix+seam+b'USER alarm\nWORKDIR /tmp\n','complete actual05df generated prefix; no injected or omitted instructions')
 boundary=b'FROM namespace-policy-prepared AS platform-alpm-release\n'
 transformed=first+b' AS namespace-policy-prepared\n'+rest.replace(run,boundary+run,1)
 inverse=transformed.replace(first+b' AS namespace-policy-prepared\n',first+b'\n',1).replace(boundary,b'',1)
 need(inverse==raw,'every original instruction and package command held byte-for-byte')
 return transformed

def labels(own,map_hash,module_sha,contract_sha,case):
 binding(own);need(hexvalue(map_hash,64)and hexvalue(module_sha,64)and hexvalue(contract_sha,64)and case in CASES,'explicit source/body/policy labels')
 return {LABEL:own['token'],LABEL+'.source':own['source'],LABEL+'.parent':PARENT,LABEL+'.map':map_hash,LABEL+'.body':module_sha,LABEL+'.contract':contract_sha,LABEL+'.case':case,LABEL+'.policy':digest(POLICY[CASES.index(case)])}

def create_plan(image,own,map_hash,module_sha,contract_sha,c):
 """DATA only. Root's separate prepared-image ownership seam must admit image."""
 contract(c);need(type(image)is str and re.fullmatch('sha256:[0-9a-f]{64}',image),'immutable exact prepared image ID');rows=[]
 for name,policy in zip(CASES,POLICY):
  lab=labels(own,map_hash,module_sha,contract_sha,name)
  argv=DOCKER+['create','--name','namespace-policy-'+own['token']+'-'+name,'--pull=never','--network=none','--user=1001:1001','--group-add=998','--group-add=1001','--memory=512m','--memory-swap=512m','--cpus=1','--pids-limit=32','--ulimit=nofile=128:128','--workdir=/tmp']
  for option in policy:argv+=['--security-opt',option]
  for k,v in sorted(lab.items()):argv+=['--label',k+'='+v]
  for k,v in sorted(c['probe']['environment'].items()):argv+=['--env',k+'='+v]
  argv+=['--entrypoint=/usr/bin/python3',image,'-I','-B','/opt/native-platform-tools-alpm-v1/source/'+MODULE,'--guest','--source',own['source'],'--ref',own['ref'],'--run',own['run'],'--map',map_hash,'--case',name,'--image',image]
  rows.append(dict(id=name,security_opt=policy,create=argv,labels=lab,start_seconds=30,probe_seconds=20))
 return dict(status='PLAN_ONLY_PREPARED_IMAGE_OWNER_ADMISSION_REQUIRED',operation=OPERATION,binding=own,source_parent=PARENT,image=image,cases=rows,whole_seconds=240,acceptance=False)

def _observed(row):return type(row)is dict and set(row)=={'status','value'}and row['status']=='OBSERVED'
def _context(ctx,c,map_hash,case):
 want=c['context'];need(type(ctx)is dict and type(ctx['schema'])is int and ctx['schema']==1 and ctx['kind']==want['kind']and ctx['position']==want['position']and ctx['source_map_sha256']==map_hash and ctx['cwd']=='/tmp','actual dedicated matrix context, never old makepkg context')
 p=ctx['process'];need(p==dict(uid=1001,euid=1001,gid=1001,egid=1001,groups=[998,1001],group_count=2,groups_truncated=False),'exact ordinary UID/GID/supplementary groups')
 status=ctx['status']
 for k,v in [('CapEff',want['cap_effective']),('CapPrm',want['cap_permitted']),('CapBnd',want['cap_bound']),('CapInh','0000000000000000'),('CapAmb','0000000000000000'),('NoNewPrivs',0),('Uid',[1001]*4),('Gid',[1001]*4)]:need(_observed(status[k])and type(status[k]['value'])is type(v)and status[k]['value']==v,'held capability/identity/NNP '+k)
 seccomp=0 if case in('seccomp_only','both')else 2
 need(_observed(status['Seccomp'])and type(status['Seccomp']['value'])is int and status['Seccomp']['value']==seccomp,'actual seccomp axis, not flags alone')
 filters=status['Seccomp_filters'];need((_observed(filters)and type(filters['value'])is int and filters['value']>=0)or filters==dict(status='UNKNOWN',reason='ABSENT'),'finite seccomp filter observation')
 need(ctx['lsm']==dict(status='OBSERVED',label='unconfined'if case in('apparmor_only','both')else'docker-default (enforce)'),'actual AppArmor axis, not flags alone')
 need(ctx['bwrap']==want['bwrap'],'same actual source-pinned bwrap identity')
 for n in('user','mnt','net','pid'):need(_observed(ctx['namespaces'][n])and re.fullmatch(n+r':\[[0-9]{1,20}\]',ctx['namespaces'][n]['value']),'complete actual namespace links')
 for n in('uid_map','gid_map'):
  need(_observed(ctx['maps'][n])and type(ctx['maps'][n]['value'])is list and 0<len(ctx['maps'][n]['value'])<=16,'complete identity maps')
  need(all(type(r)is list and len(r)==3 and all(type(v)is int and 0<=v<=2**32 for v in r)and r[2]>0 and r[0]+r[2]<=2**32 and r[1]+r[2]<=2**32 for r in ctx['maps'][n]['value']),'typed bounded identity-map triples')
 for n in('unprivileged_userns_clone','max_user_namespaces','apparmor_restrict_unprivileged_userns'):need(_observed(ctx['sysctls'][n])and type(ctx['sysctls'][n]['value'])is int and ctx['sysctls'][n]['value']>=0,'actual bounded public sysctl')
 # Namespace inode IDs differ across disposable containers. Match the user namespace;
 # retain the per-case mount/net/PID identities without asserting inode equality.
 stable=dict(process=p,status={k:v for k,v in status.items()if k not in('Seccomp','Seccomp_filters')},maps=ctx['maps'],sysctls=ctx['sysctls'],bwrap=ctx['bwrap'],mounts=ctx['mounts'],user_namespace=ctx['namespaces']['user'])
 return stable

def _ownership(v,label,nonzero=False):
 need(type(v)is dict and all(v.get(k)is True for k in('natural_exit','group_absent','exit_observed_via_waitpid','leader_held_until_group_inspection','pid_reserved_until_retirement'))and v.get('retirement')=='REAPED'and v.get('ownership_lost')is False and v.get('forced_cleanup')is False and v.get('timeout')is False,label+' natural reserved ownership')
 need(type(v.get('exit'))is int and 0<=v['exit']<=125 and(nonzero or v['exit']==0),label+' exact return')

def validate_result(value,c,expected=None):
 """Strict bounded DATA joins. Any refusal gives no policy-effect credit."""
 contract(c);need(len(encoded(value))<=c['limits']['result_bytes'],'whole result cap')
 keys(value,('schema','kind','binding','source_parent','source_map_sha256','body_sha256','contract_sha256','prepared','engine','cases','native','acceptance'),'result')
 need(type(value['schema'])is int and value['schema']==1 and value['kind']=='platform-namespace-policy-matrix-result-v1'and value['source_parent']==PARENT and value['native']=='NOT_ADMITTED'and value['acceptance']is False,'diagnostic only result')
 own=binding(value['binding']);map_hash=value['source_map_sha256'];need(all(hexvalue(value[k],64)for k in('source_map_sha256','body_sha256','contract_sha256')),'whole source/body/contract pins')
 need(value['contract_sha256']==pin((json.dumps(c,indent=2,sort_keys=True)+'\n').encode())['sha256'],'exact local canonical contract body')
 prepared=value['prepared'];need(type(prepared['labels'])is dict and len(prepared['labels'])<=64 and all(type(k)is str and type(v)is str and len(k)<=256 and len(v)<=4096 for k,v in prepared['labels'].items()),'bounded actual prepared image labels')
 need(prepared['status']=='ROOT_OWNED_EXACT_PREFIX_IMAGE'and re.fullmatch('sha256:[0-9a-f]{64}',prepared['image'])and prepared['binding']==own and prepared['source_parent']==PARENT and prepared['source_map_sha256']==map_hash and prepared['target']==TARGET and prepared['package_RUN_executed']is False and prepared['network']=='none'and prepared['pull']is False,'exact prepared image owner/Source/prefix proof')
 need(prepared['source_body']==value['body_sha256']and prepared['contract_body']==value['contract_sha256']and prepared['source_closure']=='FULL_RAW_PARENT_BODY_MODE_MAP_INVERSE_VERIFIED','prepared exact source closure and body labels')
 _ownership(prepared['build_ownership'],'prepared build')
 engine=value['engine'];need(type(engine)is dict and type(engine.get('id'))is str and engine['id']and type(engine.get('version'))is str and engine['version']and engine['arch']in('aarch64','arm64')and engine['endpoint']=='unix:///var/run/docker.sock','same native local Docker daemon identity')
 if expected is not None:
  keys(expected,('binding','source_parent','source_map_sha256','body_sha256','contract_sha256','image','engine_id'),'external Root authority')
  need(expected==dict(binding=own,source_parent=PARENT,source_map_sha256=map_hash,body_sha256=value['body_sha256'],contract_sha256=value['contract_sha256'],image=prepared['image'],engine_id=engine['id']),'independent Root Source/body/image/daemon authority join')
 rows=value['cases'];need(type(rows)is list and len(rows)==4 and all(type(r)is dict for r in rows)and [r.get('id')for r in rows]==list(CASES),'fixed four-entry order; no skip/duplicate')
 ids=set();common=None;results=[];inspect_common=None
 for row,name,policy in zip(rows,CASES,POLICY):
  keys(row,('id','security_opt','container','create_argv','inspect_before','inspect_after','context','output','returncode','namespace_errno','exec_errno','ownership','retirement'),'case')
  need(row['security_opt']==policy and hexvalue(row['container'],64)and row['container']not in ids,'exact independent case/container');ids.add(row['container'])
  plan=create_plan(prepared['image'],own,map_hash,value['body_sha256'],value['contract_sha256'],c)['cases'][CASES.index(name)];need(row['create_argv']==plan['create'],'only declared policy/name/label differences')
  before,after=row['inspect_before'],row['inspect_after'];need(before['Id']==after['Id']==row['container']and before['Image']==after['Image']==prepared['image'],'actual before/after container/image')
  cfg=before['Config'];need(cfg==after['Config']and cfg['User']=='1001:1001'and cfg['Labels']==dict(prepared['labels'],**plan['labels'])and cfg['Entrypoint']==['/usr/bin/python3']and cfg['Cmd']==plan['create'][plan['create'].index(prepared['image'])+1:]and cfg['WorkingDir']=='/tmp','exact inspected Source/body/policy/config identity')
  need(type(prepared['environment'])is list and len(prepared['environment'])<=64 and all(type(e)is str and '='in e and len(e)<=1024 for e in prepared['environment']),'bounded actual prepared-image environment')
  inherited=dict(e.split('=',1)for e in prepared['environment']);need(len(inherited)==len(prepared['environment']),'no duplicate image environment keys');inherited.update(c['probe']['environment']);need(sorted(cfg['Env'])==sorted(k+'='+v for k,v in inherited.items()),'prepared-image environment plus identical fixed probe environment')
  host=before['HostConfig'];need(host==after['HostConfig']and host['Privileged']is False and host['NetworkMode']=='none'and (host['SecurityOpt']or[])==policy and(host['CapAdd']or[])==[]and(host['CapDrop']or[])==[]and sorted(host['GroupAdd'])==['1001','998']and host['ReadonlyRootfs']is False and not host.get('Binds')and not host.get('Mounts'),'inspected policy-only deltas; no host mounts or capability changes')
  for key,want in [('Memory',536870912),('MemorySwap',536870912),('NanoCpus',1000000000),('PidsLimit',32)]:need(type(host[key])is int and host[key]==want,'identical bounded resource '+key)
  need(sorted(host['Ulimits'],key=lambda r:r['Name'])==[dict(Name='nofile',Soft=128,Hard=128)],'exact finite inherited ulimits')
  need(before['State']['Status']=='created'and before['State']['Running']is False,'actual fresh unstarted container before probe')
  normalized={k:v for k,v in host.items()if k!='SecurityOpt'}
  if inspect_common is None:inspect_common=normalized
  need(normalized==inspect_common,'no hidden per-container host configuration differences')
  expected_profile='unconfined'if name in('apparmor_only','both')else'docker-default'
  need(before['AppArmorProfile']==after['AppArmorProfile']==expected_profile,'actual inspected AppArmor profile')
  state=after['State'];need(state['Status']=='exited'and state['Running']is False and state['OOMKilled']is False and state['Dead']is False and state['Error']==''and type(row['returncode'])is int and type(state['ExitCode'])is int and state['ExitCode']==row['returncode'],'exact naturally stopped actual probe return')
  _ownership(row['ownership'],'case start',True);need(row['ownership']['exit']==row['returncode'],'Docker attach and container exit join')
  ret=row['retirement'];need(ret['container']==row['container']and ret['removed']is True and ret['absent']is True and ret['force']is False,'only owned stopped container removal/absence');_ownership(ret['ownership'],'case retirement')
  output=row['output'];keys(output,('raw_b64','bytes','sha256','complete'),'output');need(output['complete']is True and type(output['bytes'])is int and 0<output['bytes']<=65536,'complete bounded output')
  try:raw=base64.b64decode(output['raw_b64'],validate=True)
  except (ValueError,TypeError):raise MatrixGuard('invalid retained output base64')from None
  need(pin(raw)=={k:output[k]for k in('bytes','sha256')},'whole original output pin');need(row['returncode']in(0,1)and b'PLATFORM_NAMESPACE_POLICY_EXEC_ERROR_V1 'not in raw,'exec/configuration failure is UNKNOWN; bwrap0/1 only');lines=raw.splitlines();need(lines and lines[0].startswith(PREFIX)and sum(s.startswith(PREFIX)for s in lines)==1,'one first same-process context line')
  need(lines[0][len(PREFIX):]==encoded(row['context']),'exact canonical actual context/output inverse')
  tail=raw[len(lines[0])+1:];need((row['returncode']==0 and tail==b'')or(row['returncode']==1 and b'bwrap: No permissions to create a new namespace'in tail),'exact minimal true success or reproduced namespace denial')
  stable=_context(row['context'],c,map_hash,name)
  if common is None:common=stable
  need(stable==common,'contexts/resources/source/binary differ beyond the selected policies')
  need(row['namespace_errno']==dict(status='UNKNOWN',reason='BWRAP_EXIT_DOES_NOT_EXPOSE_CLONE_ERRNO'),'never infer numeric syscall errno from bwrap text')
  need(row['exec_errno']==dict(status='NOT_APPLICABLE_BWRAP_EXECUTED'),'failed or uncertain exec cannot establish a policy effect')
  results.append(row['returncode']==0)
 return dict(status='VALIDATED_FOUR_CASE_POLICY_DIAGNOSTIC_DATA_ONLY',external_authority=expected is not None,successes=results,binding=own,image=prepared['image'],native='NOT_ADMITTED',acceptance=False)

def interpret(value,c,expected=None):
 if expected is None:return dict(status='UNKNOWN',reason='independent Root Source/body/image/daemon authority required',native='NOT_ADMITTED',acceptance=False)
 try:q=validate_result(value,c,expected)
 except (MatrixGuard,KeyError,TypeError,ValueError,RecursionError,AttributeError)as error:return dict(status='UNKNOWN',reason=str(error)[:200],native='NOT_ADMITTED',acceptance=False)
 b,a,s,both=q['successes'];effect='UNKNOWN';reason='all failed or nonmonotonic/inconclusive matrix'
 if b:reason='baseline succeeded; observed failure was not reproduced'
 elif a and not s and both:effect='APPARMOR_RELAXATION_SUFFICIENT_IN_THIS_RUNTIME';reason='AppArmor-only and both succeeded; seccomp-only failed'
 elif s and not a and both:effect='SECCOMP_RELAXATION_SUFFICIENT_IN_THIS_RUNTIME';reason='seccomp-only and both succeeded; AppArmor-only failed'
 elif a and s and both:effect='EITHER_RELAXATION_SUFFICIENT_IN_THIS_RUNTIME';reason='both individual interventions succeeded; no unique policy cause'
 elif not a and not s and both:effect='BOTH_RELAXATIONS_REQUIRED_IN_THIS_RUNTIME';reason='only joint intervention succeeded; interaction remains'
 return dict(status=effect,reason=reason,binding=q['binding'],image=q['image'],syscall_errno='UNKNOWN',BuildKit_policy_equivalence='NOT_PROVED',package_ALPM='NOT_RUN',native='NOT_ADMITTED',acceptance=False)

def guest(args):
 """Future disposable-container entry only; no package/GPG/VM or extra PID probe."""
 from common import verify_source
 import platform_tools_v1 as T
 root=Path(__file__).resolve().parents[1];manifest=verify_source(root,args.map);c=contract(json.loads((root/CONTRACT).read_bytes()))
 own=dict(source=args.source,ref=args.ref,run=args.run,attempt=1,token=hashlib.sha256((args.source+':'+args.ref+':'+args.run).encode()).hexdigest()[:24]);binding(own)
 need(args.case in CASES and re.fullmatch('sha256:[0-9a-f]{64}',args.image)and os.uname().machine in('aarch64','arm64')and os.getuid()==os.geteuid()==1001 and os.getgid()==os.getegid()==1001 and sorted(os.getgroups())==[998,1001]and Path.cwd()==Path('/tmp'),'exact unprivileged prepared native guest')
 need(Path('/builder-packages.lock').is_file()and Path('/var/lib/pacman').is_dir(),'prepared tools prefix, no package work')
 need(all(os.environ.get(k)==v for k,v in c['probe']['environment'].items()),'fixed minimal probe environment')
 need(manifest['files'][MODULE]['sha256']==pin(Path(__file__).read_bytes())['sha256'],'source-owned probe body')
 ctx=T.namespace_context(args.map);ctx['kind']=c['context']['kind'];ctx['position']=c['context']['position']
 sys.stdout.buffer.write(PREFIX+encoded(ctx)+b'\n');sys.stdout.buffer.flush()
 # One bwrap operation; parent-owned container/attach supervisor supplies deadline,
 # complete output, exit/signal evidence and stopped-container retirement.
 import signal
 signal.alarm(c['limits']['probe_seconds']) # This owned probe only; never a foreign PID.
 try:os.execve(c['probe']['argv'][0],c['probe']['argv'],c['probe']['environment'])
 except OSError as error:
  sys.stdout.buffer.write(b'PLATFORM_NAMESPACE_POLICY_EXEC_ERROR_V1 '+encoded(dict(errno=error.errno))+b'\n');sys.stdout.buffer.flush();return 125

if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('--guest',action='store_true');p.add_argument('--source',required=True);p.add_argument('--ref',required=True);p.add_argument('--run',required=True);p.add_argument('--map',required=True);p.add_argument('--case',choices=CASES,required=True);p.add_argument('--image',required=True);a=p.parse_args();need(a.guest,'explicit future guest entry only');raise SystemExit(guest(a))

# Runtime integration is additive. The frozen DATA/guest contract above is held.
MATRIX_PARENT_TREE='7e66e27a352cee19a3d022d8c167c43b9ab72804'
def _matrix_tree(files):
 tree={}
 for name,row in files.items():
  path=Path(name);need(not path.is_absolute()and '..'not in path.parts and path.as_posix()==name,'closed Source path');node=tree
  for part in path.parts[:-1]:node=node.setdefault(part,{})
  node[path.name]=(row['mode'],row['blob'])
 def visit(node):
  raw=b''
  for name,value in sorted(node.items(),key=lambda pair:(pair[0]+('/'if type(pair[1])is dict else'')).encode()):
   mode,oid=('40000',visit(value))if type(value)is dict else value
   raw+=mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(oid)
  return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
 return visit(tree)

def validate_source_proof(proof,root,expected):
 """Passive full current-body/map and actual raw-parent/tree inverse joins."""
 from common import source_bytes,verify_source
 root=Path(root);own=binding(expected['binding']);map_hash=expected['source_map_sha256'];manifest=verify_source(root,map_hash)
 need(type(proof['schema'])is int and proof['schema']==1 and proof['operation']==OPERATION and proof['binding']==own and proof['source_map_sha256']==map_hash,'actual matrix source-proof selectors')
 files=proof['files'];need(len(manifest['files'])==200 and set(files)==set(manifest['files'])|{'native/source-map.json'},'complete closed current201 Source namespace')
 for name,row in files.items():
  body=source_bytes(root,name);need(pin(body)=={k:row[k]for k in('bytes','sha256')}and row['mode']==('100755'if(root/name).stat().st_mode&0o111 else'100644')
      and row['blob']==hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest(),'full current Source body/mode/blob inverse')
 def raw(name):
  row=proof[name];need(type(row['raw_b64'])is str and len(row['raw_b64'])<=1024**2,'bounded raw Git Source DATA')
  value=base64.b64decode(row['raw_b64'],validate=True);need(pin(value)=={k:row[k]for k in('bytes','sha256')},'complete raw Git body pin');return value
 source,parent=raw('raw_source'),raw('raw_parent');oid=lambda b:hashlib.sha1(b'commit '+str(len(b)).encode()+b'\0'+b).hexdigest()
 headers=source.split(b'\n\n',1)[0].splitlines();ph=parent.split(b'\n\n',1)[0].splitlines()
 need(oid(source)==own['source']and oid(parent)==PARENT and proof['raw_parent']['source']==PARENT
      and[line[7:].decode()for line in headers if line.startswith(b'parent ')]==[PARENT]
      and[line[5:].decode()for line in headers if line.startswith(b'tree ')]==[_matrix_tree(files)],'actual raw new Source/sole-parent05df/current tree')
 before=proof['parent_files'];need(type(before)is dict and len(before)==199,'complete actual05df parent namespace')
 for name,row in before.items():need(set(row)=={'mode','blob'}and row['mode']in('100644','100755')and hexvalue(row['blob'],40),'whole actual parent mode/blob rows')
 need([line[5:].decode()for line in ph if line.startswith(b'tree ')]==[_matrix_tree(before)]==[MATRIX_PARENT_TREE],'whole actual parent map/raw tree inverse')
 added=set(files)-set(before);need(added=={MODULE,CONTRACT}and not(set(before)-set(files)),'only two new mapped Source leaves')
 changed={n for n in before if(row:=files[n])['mode']!=before[n]['mode']or row['blob']!=before[n]['blob']}
 need(changed=={'native/owner.py','native/provision.py','native/source-map.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-developer-workflows.yml'},'exact existing Source driver/workflow/map layer; every other parent object held')
 need(files[MODULE]['sha256']==expected['body_sha256']and files[CONTRACT]['sha256']==expected['contract_sha256'],'independent actual Source module/contract body authority')
 return dict(status='FULL_RAW_PARENT_BODY_MODE_MAP_INVERSE_VERIFIED',binding=own,source_map_sha256=map_hash,files=201,parent=PARENT,parent_files=199,
             current_tree=_matrix_tree(files),parent_tree=_matrix_tree(before),native='NOT_ADMITTED',acceptance=False)

def _matrix_ownership(row):
 """Adapt actual unchanged native owned-child lifecycle, never an invented pass."""
 child=row.get('owned_child');need(type(child)is dict,'original native owned-child receipt required')
 for key in('exit','natural_exit','group_absent','leader_held_until_group_inspection','exit_observed_via_waitpid','ownership_lost','forced_cleanup','retirement'):
  need(key in child and row.get(key)==child[key],'actual actor/owned-child lifecycle inverse '+key)
 need(child['natural_exit']is child['group_absent']is child['leader_held_until_group_inspection']is child['exit_observed_via_waitpid']is True
      and child['ownership_lost']is child['forced_cleanup']is False and child['retirement']=='REAPED','natural original reserved supervisor ownership')
 need(type(child['exit'])is int,'actual direct wait exit')
 # The frozen primitive witnesses the leader without reaping, inspects its group,
 # then reaps it. Natural completion with no forced cleanup excludes its timeout.
 return dict(exit=child['exit'],natural_exit=True,group_absent=True,leader_held_until_group_inspection=True,
             exit_observed_via_waitpid=True,ownership_lost=False,forced_cleanup=False,retirement='REAPED',
             pid_reserved_until_retirement=True,timeout=False,
             reservation_evidence='ORIGINAL_NATIVE_LEADER_HELD_THROUGH_GROUP_INSPECTION_THEN_DIRECT_WAITPID')

def owner_matrix(actor,root,args,own,context,original_dockerfile,ledger,verify_base_callback,source_proof):
 """Own a prefix-only image and four policy-only containers; no ALPM success path.

 The caller supplies the existing signed341/eight-addition/uv context and base
 ledger. This independent ledger never widens or enters base/tools ownership.
 """
 import stat,subprocess,time
 from common import read,save,source_bytes,verify_source
 root,context=Path(root),Path(context);binding(own)
 scope=args.work/'public'/'namespace-policy';need(not scope.exists(),'fresh one-shot matrix output; no retry')
 scope.mkdir(mode=0o700);(scope/'logs').mkdir(mode=0o700)
 report=dict(schema=1,operation=OPERATION,binding=own,source_map_sha256=args.map_sha256,
             status='DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_UNKNOWN',native='NOT_ADMITTED',acceptance=False,source_root=str(root),work_root=str(args.work),
             first_failure=None,calls=[],prepared_ledger=None,cases=[],cleanup=dict(status='UNKNOWN'),
             controls=dict(build_seconds=600,matrix_seconds=240,case_seconds=30,case_output_bytes=65536),
             ownership_adapter='UNCHANGED_NATIVE_OWNED_CHILD_LEADER_RESERVATION_PROOF')
 result=None;expected=None;prepared=None;engine=None;pending=None;image=None;registered=False;matrix_deadline=None
 owned_containers={};removed=set();retirement_attempted=set();callback_started=False;callback_finished=False;total_logs=0
 new_alias='native-namespace-policy-prepared:'+own['token'];legacy='org.cachy-asahi.native-developer'
 def write_json(name,value):
  raw=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode();need(len(raw)<=1024**2,'bounded matrix JSON '+name)
  path=scope/name;need(not path.is_symlink(),'ordinary matrix output');save(path,value);path.chmod(0o600)
 def snapshot():write_json('owner.json',report)
 def failure(phase,error):
  detail=dict(phase=phase,type=type(error).__name__,message=str(error)[:512])
  if report['first_failure']is None:report['first_failure']=detail
  errors=report.setdefault('errors',[])
  if len(errors)<32:errors.append(detail)
  else:report['errors_truncated']=True
 def call(role,argv,seconds=5,cap=1024**2,allowed=(0,),deadline=None):
  """Original native supervisor, explicit caps, primary error before retention."""
  nonlocal total_logs
  now=time.monotonic();limit=min(seconds,actor.deadline-now,(deadline-now)if deadline is not None else seconds)
  need(limit>0 and len(report['calls'])<128,'finite owned matrix call budget')
  argv=list(map(str,argv));log=actor.directory/('matrix-%04d.log'%len(actor.rows));need(not log.exists(),'fresh exact actor log')
  original=type(actor).run.__globals__['owned_child']();need(Path(original.__file__).resolve()==root/'bootstrap/scripts/ci/zlib-pgo-native-hosted/owned_child.py','unchanged source-owned supervisor module')
  row=dict(argv=argv,log=str(log),status='FAIL',exit=None,natural_exit=False,group_absent=False);actor.rows.append(row);child={};error=None;body=None
  def retention_error(phase,caught):
   nonlocal error
   detail=dict(role=role,phase=phase,type=type(caught).__name__,message=str(caught)[:200]);errors=report.setdefault('retention_errors',[])
   if len(errors)<32:errors.append(detail)
   else:report['retention_errors_truncated']=True
   if error is None:error=caught;failure(role+'-retention',caught)
  try:
   with log.open('xb')as stream:
    completed=original.run(argv,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,
      timeout=limit,lifecycle=child,allowed_uids={os.geteuid()},stdout_limit=cap,stderr_limit=cap)
   need(completed.returncode==child.get('exit')and completed.returncode in allowed,'exact owned matrix return')
   row.update({k:v for k,v in child.items()if k!='status'});row['owned_child']=dict(child);_matrix_ownership(row);row['status']='PASS'
  except BaseException as caught:
   error=caught;failure(role,caught) # Freeze actual failure before any collector work.
  finally:
   row.update({k:v for k,v in child.items()if k!='status'});row['owned_child']=dict(child)
   try:save(actor.directory/'actors.json',actor.rows)
   except BaseException as caught:retention_error('actor-receipt',caught)
   entry=dict(role=role,actor=dict(row),cap=cap,seconds=limit,public_log=None,log_pin=None,output_retention='REFUSED_CAP_OR_MISSING')
   try:
    need(log.is_file()and not log.is_symlink()and log.stat().st_size<=cap,'complete bounded original actor output')
    body=read(log,cap);need(total_logs+len(body)<=24*1024**2,'total bounded matrix logs')
    # Read actual row.log first. The new public ordinal is only an explicit copy
    # mapping, never a filename inferred from a native actor index.
    name='logs/%04d.log'%len(report['calls']);target=scope/name;partial=actor.directory/('matrix-public-%04d.part'%len(report['calls']))
    need(not partial.exists()and not target.exists(),'fresh exclusive output-copy intent')
    try:
     with partial.open('xb')as stream:
      need(stream.write(body)==len(body),'whole retained actor output');stream.flush();os.fsync(stream.fileno())
     partial.chmod(0o600);need(pin(read(partial,cap))==pin(body),'full private log-copy pin before publication');os.link(partial,target)
    finally:
     if partial.exists():partial.unlink()
    target.chmod(0o600);total_logs+=len(body);row.update(public_log='namespace-policy/'+name,log_pin=pin(body));entry.update(actor=dict(row),public_log=name,log_pin=pin(body),output_retention='COMPLETE')
   except BaseException as caught:retention_error('original-log',caught)
   report['calls'].append(entry)
   try:snapshot()
   except BaseException as caught:retention_error('owner-snapshot',caught)
  if error is not None:raise error
  need(body is not None and entry['public_log']is not None,'complete original output required');return body,entry
 def docker(role,*argv,seconds=5,cap=1024**2,allowed=(0,),deadline=None):return call(role,DOCKER+list(argv),seconds,cap,allowed,deadline)
 def ids(raw):
  values=raw.decode().split();need(len(values)<=8 and len(values)==len(set(values))and all(re.fullmatch(r'(?:sha256:)?[0-9a-f]{64}',v)for v in values),'finite actual daemon ID list');return values
 def one(raw):
  values=json.loads(raw);need(type(values)is list and len(values)==1 and type(values[0])is dict,'sole actual inspect');return values[0]
 def engine_info(role,deadline=None):
  raw,_=docker(role,'info','--format','{"id":{{json .ID}},"version":{{json .ServerVersion}},"arch":{{json .Architecture}}}',deadline=deadline)
  value=json.loads(raw);need(set(value)=={'id','version','arch'}and type(value['id'])is str and value['id']and type(value['version'])is str and value['version']and value['arch']in('aarch64','arm64'),'actual native local Engine identity')
  value['endpoint']='unix:///var/run/docker.sock';return value
 def image_inspect(role,selector,deadline=None):return one(docker(role,'image','inspect',selector,deadline=deadline)[0])
 def owned_image(value):
  need(value['Id']==image and value['Architecture']=='arm64'and value['Os']=='linux'and set(value.get('RepoTags')or[])=={new_alias}
       and not value.get('RepoDigests')and value['Config']['Labels']==image_labels,'exact own prepared alias/image/body labels, no foreign references')
 def container_inspect(role,cid,plan,deadline=None):
  value=one(docker(role,'inspect',cid,deadline=deadline)[0]);cfg=value['Config'];host=value['HostConfig']
  need(value['Id']==cid and value['Image']==image and value['Name']=='/namespace-policy-'+own['token']+'-'+plan['id'],'actual independent owned CID/name/image')
  need(cfg['Labels']==dict(prepared['labels'],**plan['labels'])and cfg['User']=='1001:1001'and cfg['WorkingDir']=='/tmp'
       and cfg['Entrypoint']==['/usr/bin/python3']and cfg['Cmd']==plan['create'][plan['create'].index(image)+1:],'actual source/body/policy command labels')
  inherited=dict(e.split('=',1)for e in prepared['environment']);inherited.update(c['probe']['environment'])
  need(sorted(cfg['Env'])==sorted(k+'='+v for k,v in inherited.items()),'actual fixed prepared/probe environment')
  need(host['Privileged']is False and host['NetworkMode']=='none'and(host['SecurityOpt']or[])==plan['security_opt']and not host.get('Binds')and not host.get('Mounts')
       and not host.get('CapAdd')and not host.get('CapDrop')and host['ReadonlyRootfs']is False and sorted(host['GroupAdd'])==['1001','998'],'actual policy-only container settings')
  for key,want in [('Memory',536870912),('MemorySwap',536870912),('NanoCpus',1000000000),('PidsLimit',32)]:need(type(host[key])is int and host[key]==want,'actual finite case resource '+key)
  need(sorted(host['Ulimits'],key=lambda r:r['Name'])==[dict(Name='nofile',Soft=128,Hard=128)],'actual case FD bound');return value
 def retire_container(cid,plan,deadline=None):
  need(cid not in retirement_attempted,'prior retirement intent/uncertain outcome; no retry')
  retirement_attempted.add(cid);report.setdefault('retirement_intents',[]).append(dict(container=cid,case=plan['id'],attempt=1,force=False,binding=own,source_map_sha256=args.map_sha256));snapshot()
  value=container_inspect('retire-inspect-'+plan['id'],cid,plan,deadline)
  need(value['State']['Status']in('created','exited')and value['State']['Running']is False and value['State']['Dead']is False,'only exact unstarted/stopped owned CID may be removed')
  raw,removed_call=docker('remove-'+plan['id'],'rm',cid,deadline=deadline);need(raw.decode().strip()==cid,'exact removed CID')
  raw,absent_call=docker('absence-'+plan['id'],'ps','-aq','--no-trunc','--filter','id='+cid,deadline=deadline);need(ids(raw)==[],'actual removed CID absent');removed.add(cid)
  return dict(container=cid,removed=True,absent=True,force=False,ownership=_matrix_ownership(removed_call['actor']),
              removal_log=removed_call['public_log'],absence_log=absent_call['public_log'])
 try:
  snapshot();manifest=verify_source(root,args.map_sha256);c=contract(json.loads(read(root/CONTRACT)))
  need(len(manifest['files'])==200 and set(source_proof)=={'binding','files'}and source_proof['binding']==own,'full new Source201 proof input')
  files=source_proof['files'];need(set(files)==set(manifest['files'])|{'native/source-map.json'},'full new Source namespace')
  for name,row in files.items():
   body=source_bytes(root,name);need(pin(body)=={k:row[k]for k in('bytes','sha256')}and row['mode']==('100755'if(root/name).stat().st_mode&0o111 else'100644')
       and row['blob']==hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest(),'complete exact source body/mode/blob inverse')
  git=['/usr/bin/git','--no-replace-objects','--git-dir='+str(root/'.git'),'--work-tree='+str(root),'-c','protocol.allow=never','-c','core.fsmonitor=false']
  raw_source,_=call('raw-new-source',git+['cat-file','commit',own['source']],15)
  raw_parent,_=call('raw-actual-parent',git+['cat-file','commit',PARENT],15)
  parent_tree,_=call('full-actual-parent-tree',git+['ls-tree','-rz','--full-tree',PARENT],30)
  parent_files={}
  for line in parent_tree.split(b'\0'):
   if line:
    meta,name=line.split(b'\t',1);mode,kind,oid=meta.decode().split();name=name.decode()
    need(kind=='blob'and name not in parent_files,'complete distinct actual parent blobs');parent_files[name]=dict(mode=mode,blob=oid)
  commit_id=lambda b:hashlib.sha1(b'commit '+str(len(b)).encode()+b'\0'+b).hexdigest()
  headers=raw_source.split(b'\n\n',1)[0].splitlines()
  need(commit_id(raw_source)==own['source']and commit_id(raw_parent)==PARENT and[line[7:].decode()for line in headers if line.startswith(b'parent ')]==[PARENT]
       and[line[5:].decode()for line in headers if line.startswith(b'tree ')]==[_matrix_tree(files)],'actual raw sole-parent05df and complete source tree inverse')
  source_bound=dict(schema=1,operation=OPERATION,binding=own,source_map_sha256=args.map_sha256,files=files,parent_files=parent_files,
      raw_source=dict(pin(raw_source),raw_b64=base64.b64encode(raw_source).decode()),raw_parent=dict(pin(raw_parent),source=PARENT,raw_b64=base64.b64encode(raw_parent).decode()),
      tree=_matrix_tree(files),inverse=dict(parent_tree=MATRIX_PARENT_TREE,parent_files=199,current_files=201,added=[CONTRACT,MODULE],changed_existing=['.github/workflows/native-arm-build.yml','.github/workflows/native-arm-developer-workflows.yml','native/owner.py','native/provision.py','native/source-map.json'],unlisted_held=194),status='PENDING_SOURCE_INVERSE_VERIFICATION',native='NOT_ADMITTED',acceptance=False)
  write_json('source-proof.json',source_bound)
  module_sha=manifest['files'][MODULE]['sha256'];contract_sha=manifest['files'][CONTRACT]['sha256']
  source_bound['qualification']=validate_source_proof(source_bound,root,dict(binding=own,source_map_sha256=args.map_sha256,body_sha256=module_sha,contract_sha256=contract_sha))
  source_bound['status']=source_bound['qualification']['status'];write_json('source-proof.json',source_bound)
  need(contract_sha==pin((json.dumps(c,indent=2,sort_keys=True)+'\n').encode())['sha256'],'held canonical matrix contract')
  need(ledger['binding']==own and ledger['source_map_sha256']==args.map_sha256 and set(ledger['created'])=={'base'},'unchanged registered base-only ledger')
  base_alias=ledger['aliases']['base'];base_id=ledger['created']['base']['image_id']
  need(re.fullmatch('sha256:[0-9a-f]{64}',base_id)and original_dockerfile.startswith(('FROM '+base_alias+'\n').encode()),'original Dockerfile registered base alias')
  base_before=image_inspect('exact-base-before-prefix',base_id);need(base_before['Id']==base_id and base_before['Architecture']=='arm64'and base_before['Os']=='linux'and base_before['Config']['Labels'].get(legacy)==own['token']and base_before['Config']['Labels'].get(legacy+'.source')==own['source'],'actual registered signed base image identity')
  engine=engine_info('engine-before');report['engine_before']=engine
  need(ids(docker('fresh-matrix-containers','ps','-aq','--no-trunc','--filter','label='+LABEL+'='+own['token'])[0])==[]
       and ids(docker('fresh-matrix-images','image','ls','--no-trunc','-q','--filter','label='+LABEL+'='+own['token'])[0])==[]
       and ids(docker('fresh-prepared-alias','image','ls','--no-trunc','-q','--filter','reference='+new_alias)[0])==[],'fresh distinct matrix resource namespace')
  split=split_tools_dockerfile(original_dockerfile,args.map_sha256);dockerfile=context/'Dockerfile.namespace-policy';need(not dockerfile.exists(),'fresh prefix Dockerfile')
  with dockerfile.open('xb')as stream:stream.write(split)
  image_labels=dict(base_before['Config'].get('Labels')or{});image_labels.update({LABEL:own['token'],LABEL+'.source':own['source'],LABEL+'.parent':PARENT,LABEL+'.map':args.map_sha256,
                LABEL+'.body':module_sha,LABEL+'.contract':contract_sha,LABEL+'.target':TARGET,legacy:'',legacy+'.source':''})
  iid=args.work/'namespace-policy-image-id';need(not iid.exists(),'fresh exact prepared iidfile')
  build=DOCKER+['build','--network=none','--pull=false','--no-cache','--platform=linux/arm64','--target',TARGET,'--file',str(dockerfile),'--tag',new_alias]
  for key,value in sorted(image_labels.items()):build+=['--label',key+'='+value]
  build+=['--iidfile',str(iid),str(context)]
  report['prepared_ledger']=dict(binding=own,source_map_sha256=args.map_sha256,alias=new_alias,image=None,created=False,retired=False,
      original_dockerfile=dict(pin(original_dockerfile),raw_b64=base64.b64encode(original_dockerfile).decode()),
      target_dockerfile=dict(pin(split),raw_b64=base64.b64encode(split).decode()),build_argv=build,base_alias=base_alias,base_image=base_id)
  need(verify_base_callback()==base_alias,'registered actual base before prefix');callback_started=True
  try:_,build_call=call('prepared-prefix-build',build,600,16*1024**2)
  finally:
   if callback_started:need(verify_base_callback()==base_alias,'same actual base after prefix');callback_finished=True
  image=read(iid,128).decode().strip();need(re.fullmatch('sha256:[0-9a-f]{64}',image)and image!=base_id,'fresh immutable prepared image ID')
  need(ids(docker('registered-prepared-alias','image','ls','--no-trunc','-q','--filter','reference='+new_alias)[0])==[image],'exact created alias-to-image')
  inspected=image_inspect('prepared-image-inspect',image);owned_image(inspected);need(inspected['Config']['User']=='root','target stopped before later alarm/package stage')
  registered=True;report['prepared_ledger'].update(image=image,created=True,build_call=build_call['public_log'],image_inspect_pin=pin(encoded(inspected)))
  prepared=dict(status='ROOT_OWNED_EXACT_PREFIX_IMAGE',image=image,binding=own,source_parent=PARENT,source_map_sha256=args.map_sha256,target=TARGET,
       package_RUN_executed=False,network='none',pull=False,source_body=module_sha,contract_body=contract_sha,
       source_closure=source_bound['status'],build_ownership=_matrix_ownership(build_call['actor']),
       labels=inspected['Config']['Labels'],environment=inspected['Config'].get('Env')or[])
  expected=dict(binding=own,source_parent=PARENT,source_map_sha256=args.map_sha256,body_sha256=module_sha,contract_sha256=contract_sha,image=image,engine_id=engine['id'])
  report['root_expected']=expected;report['prepared']=prepared
  result=dict(schema=1,kind='platform-namespace-policy-matrix-result-v1',binding=own,source_parent=PARENT,source_map_sha256=args.map_sha256,
      body_sha256=module_sha,contract_sha256=contract_sha,prepared=prepared,engine=engine,cases=[],native='NOT_ADMITTED',acceptance=False)
  plans=create_plan(image,own,args.map_sha256,module_sha,contract_sha,c)['cases'];matrix_deadline=time.monotonic()+240
  for plan in plans:
   name='namespace-policy-'+own['token']+'-'+plan['id']
   need(ids(docker('fresh-name-'+plan['id'],'ps','-aq','--no-trunc','--filter','name=^/'+name+'$',deadline=matrix_deadline)[0])==[],'fresh exact case name')
   raw,_=call('create-'+plan['id'],plan['create'],5,1024**2,deadline=matrix_deadline);cid=raw.decode().strip();need(hexvalue(cid,64),'actual created CID')
   need(cid not in owned_containers,'four independent CIDs');owned_containers[cid]=plan
   before=container_inspect('before-'+plan['id'],cid,plan,matrix_deadline);need(before['State']['Status']=='created'and before['State']['Running']is False,'fresh unstarted owned case')
   output,start=docker('start-'+plan['id'],'start','-a',cid,seconds=30,cap=65536,allowed=tuple(range(256)),deadline=matrix_deadline)
   after=container_inspect('after-'+plan['id'],cid,plan,matrix_deadline);state=after['State'];need(state['Status']=='exited'and state['Running']is False and state['Dead']is False,'naturally stopped exact probe container')
   need(type(state['ExitCode'])is int and state['ExitCode']==start['actor']['exit'],'actual attach/container return inverse')
   lines=output.splitlines();ctx=None;exec_errno=dict(status='NOT_APPLICABLE_BWRAP_EXECUTED')
   if lines and lines[0].startswith(PREFIX):ctx=json.loads(lines[0][len(PREFIX):])
   else:exec_errno=dict(status='UNKNOWN',reason='NO_COMPLETE_SOURCE_CONTEXT')
   marker=b'PLATFORM_NAMESPACE_POLICY_EXEC_ERROR_V1 '
   for line in lines:
    if line.startswith(marker):
     value=json.loads(line[len(marker):]);exec_errno=dict(status='OBSERVED_EXEC_ERRNO',errno=value.get('errno'))
   row=dict(id=plan['id'],security_opt=plan['security_opt'],container=cid,create_argv=plan['create'],inspect_before=before,inspect_after=after,
       context=ctx,output=dict(raw_b64=base64.b64encode(output).decode(),**pin(output),complete=True),returncode=state['ExitCode'],
       namespace_errno=dict(status='UNKNOWN',reason='BWRAP_EXIT_DOES_NOT_EXPOSE_CLONE_ERRNO'),exec_errno=exec_errno,
       ownership=_matrix_ownership(start['actor']),retirement=None)
   row['retirement']=retire_container(cid,plan,matrix_deadline);result['cases'].append(row);report['cases'].append(dict(id=plan['id'],container=cid,returncode=state['ExitCode'],retired=True))
   if state['ExitCode']!=0:report.setdefault('probe_failures',[]).append(dict(case=plan['id'],container=cid,returncode=state['ExitCode'],output=pin(output),namespace_errno=row['namespace_errno'],exec_errno=exec_errno))
   snapshot()
  report['engine_after']=engine_info('engine-after',matrix_deadline);need(report['engine_after']==engine,'same actual Engine through all four cases')
  validate_result(result,c,expected);report['candidate_interpretation']=interpret(result,c,expected);report['status']='DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_COMPLETE'
 except BaseException as error:
  failure('matrix',error);pending=error if not isinstance(error,Exception)else None
 finally:
  # Cleanup never starts/retries/stops/kills a container or guesses an image ID.
  # A still-running or incompletely bound object remains UNKNOWN for Root.
  cleanup_deadline=min(time.monotonic()+90,matrix_deadline)if matrix_deadline is not None else time.monotonic()+90;cleanup_errors=[]
  for cid,plan in owned_containers.items():
   if cid not in removed:
    if cid in retirement_attempted:
     cleanup_errors.append('prior retirement attempted; uncertain outcome; no retry for '+cid);continue
    try:retire_container(cid,plan,cleanup_deadline)
    except BaseException as error:cleanup_errors.append(str(error)[:200])
  try:
   need(len(removed)==len(owned_containers),'all exact created containers retired')
   need(ids(docker('final-matrix-container-absence','ps','-aq','--no-trunc','--filter','label='+LABEL+'='+own['token'],deadline=cleanup_deadline)[0])==[],'no remaining owned matrix containers')
   if registered:
    value=image_inspect('retirement-image-inspect',image,cleanup_deadline);owned_image(value)
    need(ids(docker('retirement-owned-image-set','image','ls','--no-trunc','-q','--filter','label='+LABEL+'='+own['token'],deadline=cleanup_deadline)[0])==[image],'only registered prepared image in new scope')
    report['prepared_ledger']['alias_retirement_intent']=dict(alias=new_alias,image=image,once=True,retry=False);snapshot()
    docker('remove-prepared-alias','image','rm',new_alias,deadline=cleanup_deadline)
    remaining=ids(docker('prepared-image-after-alias','image','ls','--no-trunc','-q','--filter','label='+LABEL+'='+own['token'],deadline=cleanup_deadline)[0])
    if remaining:
     need(remaining==[image],'no foreign image after alias removal');value=image_inspect('unaliased-image-inspect',image,cleanup_deadline)
     need(value['Id']==image and not(value.get('RepoTags')or[])and not value.get('RepoDigests')and value['Config']['Labels']==image_labels,'exact unaliased owned prepared image only')
     report['prepared_ledger']['image_retirement_intent']=dict(image=image,once=True,retry=False);snapshot()
     docker('remove-prepared-image','image','rm',image,deadline=cleanup_deadline)
    need(ids(docker('final-prepared-alias-absence','image','ls','--no-trunc','-q','--filter','reference='+new_alias,deadline=cleanup_deadline)[0])==[]
         and ids(docker('final-prepared-image-absence','image','ls','--no-trunc','-q','--filter','label='+LABEL+'='+own['token'],deadline=cleanup_deadline)[0])==[],'actual prepared alias/image absence')
    report['prepared_ledger']['retired']=True
   else:
    need(ids(docker('unregistered-prepared-alias-absence','image','ls','--no-trunc','-q','--filter','reference='+new_alias,deadline=cleanup_deadline)[0])==[]
         and ids(docker('unregistered-matrix-image-absence','image','ls','--no-trunc','-q','--filter','label='+LABEL+'='+own['token'],deadline=cleanup_deadline)[0])==[],'unregistered or uncertain prepared image remains UNKNOWN; no guessed removal')
   need(not cleanup_errors,'all exact stopped container retirements complete');report['cleanup']=dict(status='PASS_EXACT_MATRIX_OWNED_RESOURCES_RETIRED',containers=sorted(removed),prepared_registered=registered,prepared_retired=registered)
  except BaseException as error:failure('retirement',error);report['cleanup']=dict(status='UNKNOWN',errors=cleanup_errors+[str(error)[:200]])
  if report['cleanup']['status']!='PASS_EXACT_MATRIX_OWNED_RESOURCES_RETIRED':report['status']='DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_UNKNOWN'
  report['interpretation']=(report['candidate_interpretation']if report['status']=='DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_COMPLETE'
       else dict(status='UNKNOWN',reason='matrix collection/ownership/retirement incomplete',native='NOT_ADMITTED',acceptance=False))
  if result is not None:
   try:write_json('result.json',result)
   except Exception as error:failure('result-retention',error);report['status']='DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_UNKNOWN'
  diagnostic={k:report[k]for k in('schema','operation','binding','source_map_sha256','status','native','acceptance','first_failure','cleanup')}
  diagnostic.update(cases=len(report['cases']),interpretation=report.get('interpretation',dict(status='UNKNOWN',reason='incomplete or unqualified actual matrix',native='NOT_ADMITTED',acceptance=False)),
       Root_external_expected_required=True,BuildKit_policy_equivalence='NOT_PROVED',package_ALPM='NOT_RUN',probe_failures=report.get('probe_failures',[]))
  write_json('diagnostic.json',diagnostic);snapshot()
 if pending is not None:raise pending
 return diagnostic

def validate_runtime_evidence(owner,result,payloads,expected,source_proof):
 """Passive joins from fixed actual command roles/raw bodies to matrix records.

 The caller has already verified capsule/index/manifest/projection/privacy and
 the independent Root local Source proof. This helper never runs an actor.
 """
 own=binding(expected['binding']);image=expected['image'];map_hash=expected['source_map_sha256'];token=own['token'];alias='native-namespace-policy-prepared:'+token
 need(owner['schema']==1 and owner['operation']==OPERATION and owner['binding']==own and owner['source_map_sha256']==map_hash
      and owner['status']=='DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_COMPLETE'and owner['cleanup']['status']=='PASS_EXACT_MATRIX_OWNED_RESOURCES_RETIRED'
      and owner['first_failure']is None,'complete actual runtime owner/retirement before policy effect')
 need(source_proof['binding']==own and source_proof['source_map_sha256']==map_hash and source_proof['files'][MODULE]['sha256']==expected['body_sha256']and source_proof['files'][CONTRACT]['sha256']==expected['contract_sha256'],'independent Root Source/module/contract proof authority')
 calls=owner['calls'];need(type(calls)is list and 0<len(calls)<=128,'bounded actual runtime calls');by_role={};selectors=set()
 for entry in calls:
  role=entry['role'];name=entry['public_log'];actor=entry['actor'];need(type(role)is str and role not in by_role and re.fullmatch(r'logs/[0-9]{4}\.log',name)
       and name not in selectors and entry['output_retention']=='COMPLETE','unique actual role and complete retained output')
  selectors.add(name);target='namespace-policy/'+name;need(target in payloads and type(payloads[target])is bytes,'actual projected runtime log body')
  body=payloads[target];need(len(body)<=entry['cap']and pin(body)==entry['log_pin']==actor['log_pin']and actor['public_log']==target,'actual actor/public selector/projection/body pin inverse')
  need(actor['status']=='PASS','successful owned command collection');_matrix_ownership(actor);by_role[role]=(actor,body)
 need(selectors=={n.removeprefix('namespace-policy/')for n in payloads if re.fullmatch(r'namespace-policy/logs/[0-9]{4}\.log',n)},'complete runtime public-log inverse')
 def call(role,argv=None):
  need(role in by_role,'required actual runtime role '+role);actor,body=by_role[role]
  if argv is not None:need(actor['argv']==argv,'exact actual role argv '+role)
  return actor,body
 def inspect(role,selector):
  _,body=call(role,DOCKER+['image','inspect',selector]if role in('exact-base-before-prefix','prepared-image-inspect','retirement-image-inspect','unaliased-image-inspect')else DOCKER+['inspect',selector])
  value=json.loads(body);need(type(value)is list and len(value)==1 and type(value[0])is dict,'sole actual raw inspect '+role);return value[0]
 def ids(role,argv):
  _,body=call(role,argv);values=body.decode().split();need(len(values)==len(set(values))and len(values)<=8,'whole actual bounded ID query');return values
 root=owner['source_root'];need(type(root)is str and root.startswith('/')and '..'not in Path(root).parts,'actual Source root path DATA')
 git=['/usr/bin/git','--no-replace-objects','--git-dir='+root+'/.git','--work-tree='+root,'-c','protocol.allow=never','-c','core.fsmonitor=false']
 raw_source=call('raw-new-source',git+['cat-file','commit',own['source']])[1];raw_parent=call('raw-actual-parent',git+['cat-file','commit',PARENT])[1]
 need(base64.b64decode(source_proof['raw_source']['raw_b64'],validate=True)==raw_source and base64.b64decode(source_proof['raw_parent']['raw_b64'],validate=True)==raw_parent,'actual raw commit logs and full Source proof inverse')
 parent_raw=call('full-actual-parent-tree',git+['ls-tree','-rz','--full-tree',PARENT])[1];parent={}
 for line in parent_raw.split(b'\0'):
  if line:
   meta,name=line.split(b'\t',1);mode,kind,oid=meta.decode().split();name=name.decode();need(kind=='blob'and name not in parent,'actual full parent tree rows');parent[name]=dict(mode=mode,blob=oid)
 need(parent==source_proof['parent_files']and _matrix_tree(parent)==MATRIX_PARENT_TREE,'actual parent raw-map/fullproof inverse')
 ledger=owner['prepared_ledger'];need(ledger['binding']==own and ledger['source_map_sha256']==map_hash and ledger['alias']==alias and ledger['image']==image
      and ledger['created']is True and ledger['retired']is True,'actual prepared ledger identity/retirement')
 original=base64.b64decode(ledger['original_dockerfile']['raw_b64'],validate=True);split=base64.b64decode(ledger['target_dockerfile']['raw_b64'],validate=True)
 need(pin(original)=={k:ledger['original_dockerfile'][k]for k in('bytes','sha256')}and pin(split)=={k:ledger['target_dockerfile'][k]for k in('bytes','sha256')}
      and split_tools_dockerfile(original,map_hash)==split,'complete exact prefix/body/package RUN inverse')
 base_alias=ledger['base_alias'];need(original.startswith(('FROM '+base_alias+'\n').encode()),'actual registered base FROM')
 base=inspect('exact-base-before-prefix',ledger['base_image']);need(base['Id']==ledger['base_image']and base['Architecture']=='arm64'and base['Os']=='linux'
      and base['Config']['Labels'].get('org.cachy-asahi.native-developer')==token and base['Config']['Labels'].get('org.cachy-asahi.native-developer.source')==own['source'],'actual registered signed-base inspect')
 build_actor,_=call('prepared-prefix-build',ledger['build_argv']);_ownership(_matrix_ownership(build_actor),'actual prefix build')
 build=ledger['build_argv'];work=owner['work_root'];need(type(work)is str and work.startswith('/')and '..'not in Path(work).parts,'actual work root DATA')
 expected_build=DOCKER+['build','--network=none','--pull=false','--no-cache','--platform=linux/arm64','--target',TARGET,'--file',work+'/overlay/context/Dockerfile.namespace-policy','--tag',alias]
 image_labels=dict(base['Config'].get('Labels')or{});image_labels.update({LABEL:token,LABEL+'.source':own['source'],LABEL+'.parent':PARENT,LABEL+'.map':map_hash,
      LABEL+'.body':expected['body_sha256'],LABEL+'.contract':expected['contract_sha256'],LABEL+'.target':TARGET,
      'org.cachy-asahi.native-developer':'','org.cachy-asahi.native-developer.source':''})
 for k,v in sorted(image_labels.items()):expected_build+=['--label',k+'='+v]
 expected_build+=['--iidfile',work+'/namespace-policy-image-id',work+'/overlay/context'];need(build==expected_build,'actual target-only/source/body/contract build argv')
 need(ids('registered-prepared-alias',DOCKER+['image','ls','--no-trunc','-q','--filter','reference='+alias])==[image],'actual prepared alias-to-ID')
 prepared=inspect('prepared-image-inspect',image);need(prepared['Id']==image and prepared['Architecture']=='arm64'and prepared['Os']=='linux'and prepared['Config']['User']=='root'
      and set(prepared.get('RepoTags')or[])=={alias}and not prepared.get('RepoDigests')and prepared['Config']['Labels']==image_labels
      and result['prepared']['labels']==image_labels and result['prepared']['environment']==(prepared['Config'].get('Env')or[]),'actual immutable prefix image/body/labels/environment')
 need(result['prepared']['build_ownership']==_matrix_ownership(build_actor),'actual original prefix supervisor receipt')
 info_argv=DOCKER+['info','--format','{"id":{{json .ID}},"version":{{json .ServerVersion}},"arch":{{json .Architecture}}}']
 for role in('engine-before','engine-after'):
  value=json.loads(call(role,info_argv)[1]);need(set(value)=={'id','version','arch'},'only finite actual Engine identity')
  value['endpoint']='unix:///var/run/docker.sock';need(value==result['engine']==owner[role.replace('-','_')]and value['id']==expected['engine_id'],'actual same Engine raw-body/result/Root inverse')
 need([row['id']for row in result['cases']]==list(CASES),'four actual runtime case records')
 intents=owner['retirement_intents'];need(type(intents)is list and len(intents)==4 and len({v['container']for v in intents})==4 and all(v['attempt']==1 and v['force']is False and v['binding']==own and v['source_map_sha256']==map_hash for v in intents),'one recorded retirement intent per actual CID')
 need({v['container']for v in intents}=={r['container']for r in result['cases']},'retirement intents actual case inverse')
 for row in result['cases']:
  case,cid=row['id'],row['container'];create,raw=call('create-'+case,row['create_argv']);need(raw.decode().strip()==cid and create['exit']==0,'actual created CID body')
  name='namespace-policy-'+token+'-'+case;need(ids('fresh-name-'+case,DOCKER+['ps','-aq','--no-trunc','--filter','name=^/'+name+'$'])==[],'actual fresh per-case name')
  before=inspect('before-'+case,cid);after=inspect('after-'+case,cid);need(before==row['inspect_before']and after==row['inspect_after'],'actual raw before/after inspect inverse')
  start,raw=call('start-'+case,DOCKER+['start','-a',cid]);need(raw==base64.b64decode(row['output']['raw_b64'],validate=True)and pin(raw)=={k:row['output'][k]for k in('bytes','sha256')}
       and start['exit']==row['returncode']==after['State']['ExitCode']and row['ownership']==_matrix_ownership(start),'actual complete attach/context/return/ownership inverse')
  retired=inspect('retire-inspect-'+case,cid)
  need(all(retired[k]==after[k]for k in('Id','Image','Name','Config','HostConfig','AppArmorProfile'))and all(retired['State'][k]==after['State'][k]for k in('Status','Running','Dead','OOMKilled','Error','ExitCode'))
       and retired['State']['Running']is False and retired['State']['Status']=='exited','actual stable identity/config/stopped-state pre-removal inspect')
  removal,raw=call('remove-'+case,DOCKER+['rm',cid]);need(raw.decode().strip()==cid and row['retirement']['ownership']==_matrix_ownership(removal),'actual non-force removal body/ownership')
  need(ids('absence-'+case,DOCKER+['ps','-aq','--no-trunc','--filter','id='+cid])==[],'actual exact removed CID absence')
  need(row['retirement']['removal_log']==next(e['public_log']for e in calls if e['role']=='remove-'+case)
       and row['retirement']['absence_log']==next(e['public_log']for e in calls if e['role']=='absence-'+case),'actual retirement receipt public-log selectors')
 need(ids('fresh-matrix-containers',DOCKER+['ps','-aq','--no-trunc','--filter','label='+LABEL+'='+token])==[]
      and ids('fresh-matrix-images',DOCKER+['image','ls','--no-trunc','-q','--filter','label='+LABEL+'='+token])==[]
      and ids('fresh-prepared-alias',DOCKER+['image','ls','--no-trunc','-q','--filter','reference='+alias])==[],'actual fresh matrix alias/label namespace')
 need(ids('final-matrix-container-absence',DOCKER+['ps','-aq','--no-trunc','--filter','label='+LABEL+'='+token])==[],'actual all-case container absence')
 retired=inspect('retirement-image-inspect',image);need(retired['Id']==image and retired['Config']['Labels']==image_labels and set(retired.get('RepoTags')or[])=={alias}and not retired.get('RepoDigests'),'actual own image pre-retirement identity')
 need(ids('retirement-owned-image-set',DOCKER+['image','ls','--no-trunc','-q','--filter','label='+LABEL+'='+token])==[image],'actual sole prepared image retirement scope')
 call('remove-prepared-alias',DOCKER+['image','rm',alias]);remaining=ids('prepared-image-after-alias',DOCKER+['image','ls','--no-trunc','-q','--filter','label='+LABEL+'='+token])
 if remaining:
  need(remaining==[image],'actual remaining own image only');value=inspect('unaliased-image-inspect',image)
  need(value['Id']==image and value['Config']['Labels']==image_labels and not(value.get('RepoTags')or[])and not value.get('RepoDigests'),'actual unaliased own image before removal');call('remove-prepared-image',DOCKER+['image','rm',image])
 need(ids('final-prepared-alias-absence',DOCKER+['image','ls','--no-trunc','-q','--filter','reference='+alias])==[]
      and ids('final-prepared-image-absence',DOCKER+['image','ls','--no-trunc','-q','--filter','label='+LABEL+'='+token])==[],'actual final prepared alias/image absence')
 return dict(status='VALIDATED_ACTUAL_MATRIX_RUNTIME_ROLE_BODY_OWNERSHIP_INVERSES',binding=own,calls=len(calls),logs=len(selectors),native='NOT_ADMITTED',acceptance=False)

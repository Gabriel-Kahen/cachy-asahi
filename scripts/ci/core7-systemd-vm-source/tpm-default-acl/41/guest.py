# SPDX-License-Identifier: MIT
"""Real systemd children. All mutation is behind nonce/block/page/PID1 guards."""
import argparse,base64,gzip,json,os,stat,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C,guest_guard as G,adapter,effects,boot,clock as W,graph_api as Q
OUT=Path('/out');ROOT=Path('/');SOURCE=Path('/workspace/core-source');END=None

def save(name,value):
 p=OUT/name;raw=C.encoded(value);C.need(len(raw)<=16*1024**2,'bounded whole source-owned guest receipt');temp=OUT/('.'+name+'.partial');C.need(not temp.exists(),'fresh atomic receipt lease');temp.write_bytes(raw);temp.replace(p)

def sources(s):
 adapter.verify(SOURCE,s['source_profiles']['core800']);profile=s['source_profiles']['ksm637'];runtime=dict(profile,files={n[len('runtime/'):]:v for n,v in profile['files'].items()if n.startswith('runtime/')});C.need(len(runtime['files'])==610,'whole original runtime610 closure');adapter.verify(Path('/source'),runtime);return adapter.core(SOURCE)

class Commands:
 def __init__(self,api,report):self.api=api;self.report=report;self.prefix='phase%d'%report['phase']+('-observer'if report.get('role')=='observer'else'')
 def call(self,argv,seconds=90,expect=0):
  cleanup=argv==['/usr/bin/gpgconf','--homedir','/tmp/core-public-gpg','--kill','all']and seconds==15
  C.need(END is not None and (cleanup or time.monotonic()<END) and type(argv)is list and all(type(a)is str and a for a in argv),'finite original argv and current boot deadline')
  row,out,err,error=self.api['runtime'].run_command(argv,Path('/tmp'),dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',HOME='/tmp',TMPDIR='/tmp',PYTHONDONTWRITEBYTECODE='1'),seconds if cleanup else min(seconds,max(.001,END-time.monotonic())),1024**2)
  number=len(self.report['commands']);C.need(number<128,'original128 foreground-command cap');self.report['commands'].append(row)
  for suffix,raw in(('stdout',out),('stderr',err)):(OUT/('%s-command-%03d.%s'%(self.prefix,number,suffix))).write_bytes(raw)
  save(self.prefix+'-progress.json',self.report)
  if error:raise error
  C.need(row['exit_code']==expect and row['group_absence_verified']is True,'real foreground exit and process group retirement');return out

def manager(commands):
 raw=commands.call(['/usr/bin/systemctl','--system','show','--property=Version,Virtualization,SystemState','--no-pager']);v=dict(line.split('=',1)for line in raw.decode().splitlines());C.need(set(v)=={'Version','Virtualization','SystemState'},'complete fixed actual manager response');return v

def pid1(commands,root):
 fd=os.open('/proc/1/exe',os.O_RDONLY|os.O_CLOEXEC)
 try:
  import hashlib
  st=os.fstat(fd);C.need(stat.S_ISREG(st.st_mode)and st.st_size<=16*1024**2,'bounded native actual PID1 executable');data=bytearray()
  while len(data)<=st.st_size:
   v=os.read(fd,min(1024**2,st.st_size-len(data)+1))
   if not v:break
   data.extend(v)
  C.need(len(data)==st.st_size and C.identity(st)==C.identity(os.fstat(fd)),'whole stable actual PID1 descriptor')
 finally:os.close(fd)
 version=commands.call(['/usr/lib/systemd/systemd','--version']).decode();package=commands.call(['/usr/bin/pacman','-Q','systemd']).decode()
 status=dict(v.split(':',1)for v in Path('/proc/1/status').read_text().splitlines()if ':'in v);capabilities={n:int(status[n],16)for n in('CapEff','CapPrm','CapBnd','CapInh','CapAmb')};capabilities.update(NoNewPrivs=int(status['NoNewPrivs']),Seccomp=int(status['Seccomp']),last=int(Path('/proc/sys/kernel/cap_last_cap').read_text()))
 return dict(architecture=os.uname().machine,page_size=os.sysconf('SC_PAGE_SIZE'),kernel=os.uname().release,capabilities=capabilities,pid=1,exe_link=os.readlink('/proc/1/exe'),exe=C.pin(bytes(data)),version=version,package_version=package,manager=manager(commands),root=root,boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())

def graph(core,label,report):
 scope=C.load('_core_guest_whole_scope',Path('/persistent_scope.py'));limits=core.T.budget(core.api,600);policy=scope.mount_policy(ROOT,Path('/measurement/inspection'),scope.mounts(scope._mount_table()));query=C.load('_core_guest_fresh_descriptor_query',core.root/'runtime/runtime-vm/scripts/ci/expanded600-installer-vm/observer600.py');roots=Q.roots(core.api['roots'],query);nodes,excluded=scope.source_manifest(ROOT,limits,roots,policy)
 helper=C.load('_core_guest_cap_scope',Path('/source/media-source/scripts/ci/current604-public-pair-updater16k/cap_scope.py'))
 raw_caps=C.read('/source/media-source/scripts/apps/file_capabilities.py');observer=Q.capabilities(helper.derive(raw_caps,set(policy['observed_mounts'])|scope.RUNTIME),query,raw_caps,ROOT,helper.nodes(nodes),label)
 try:mapping=observer.observe(ROOT,helper.nodes(nodes),limits)
 except ValueError as error:
  if hasattr(error,'metadata_refusal'):report.setdefault('metadata_refusals',{})[label]=error.metadata_refusal
  raise
 v=dict(complete=True,nodes=nodes,security_capabilities=mapping,posix_acl_defaults=observer.acl_defaults(),mounts=policy,excluded=excluded);__import__('acl_policy').check_graph(v,label)
 raw=C.encoded(v);compressed=gzip.compress(raw,mtime=0);C.need(len(raw)<=256*1024**2 and len(compressed)<=64*1024**2,'original full graph stream caps')
 C.need(sum(p.stat().st_size for p in OUT.iterdir()if p.is_file())+len(compressed)<=512*1024**2,'original aggregate evidence cap');name=label+'-root.json.gz';C.need(not(OUT/name).exists(),'fresh whole graph role');(OUT/name).write_bytes(compressed);report.setdefault('graphs',{})[label]=dict(file=name,raw=C.pin(raw),compressed=C.pin(compressed));return v

def inventory(core):return core.T.inventory(core.api,ROOT)

def unit(commands,name):
 fields=('ActiveState','SubState','Result','ExecMainCode','ExecMainStatus','MainPID','ControlGroup');raw=commands.call(['/usr/bin/systemctl','--system','show',name,'--property='+','.join(fields),'--no-pager']);result=dict(line.split('=',1)for line in raw.decode().splitlines());C.need(set(result)==set(fields),'whole typed unit result '+name);return result

def generated(commands,core,report,before):
 result={}
 for name,argv in effects.GENERATED.items():
  first=C.pin(C.read(ROOT/name,32*1024**2));number=len(report['commands']);commands.call(list(argv));second=C.pin(C.read(ROOT/name,32*1024**2));C.need(first==second,'real generated cache byte idempotence '+name)
  st=(ROOT/name).stat();node=dict(type='file',mode=stat.S_IMODE(st.st_mode),uid=st.st_uid,gid=st.st_gid,**second)
  result[name]=dict(before=before['nodes'].get(name),first=node,second=node,command=report['commands'][number])
 return result

def transact(commands,packages,names,nonce,label):
 rows=[packages[n]['transaction']for n in names];C.need(len(rows)<=20,'same original20 added package ceiling')
 wanted={r['name']:r['version']for r in rows};Path('/run/core-hook-expected.json').write_bytes(C.encoded(dict(nonce=nonce,label=label,targets=sorted(n for n in wanted if n in{'pacman','systemd','systemd-libs','systemd-resolvconf','systemd-sysvcompat','systemd-tests','systemd-ukify'}))))
 witness=Path('/run/core-hook-witness.json');C.need(not witness.exists(),'fresh automatic-hook witness')
 config='[options]\nArchitecture = aarch64\nGPGDir = /tmp/core-public-gpg\nSigLevel = Required DatabaseOptional\nLocalFileSigLevel = Required\nLogFile = /run/core-pacman.log\nCacheDir = /run/core-cache\nHookDir = /etc/pacman.d/hooks\nHookDir = /run/core-hooks\n'
 Path('/run/core-cache').mkdir(exist_ok=True);Path('/run/core-hooks').mkdir(exist_ok=True);Path('/run/core-hooks/99-caa-core-witness.hook').write_text('[Trigger]\nType = Package\nOperation = Install\nOperation = Upgrade\nTarget = pacman\nTarget = systemd\nTarget = systemd-*\n[Action]\nDescription = Exact owned Core automatic-hook witness\nWhen = PostTransaction\nExec = /usr/bin/python3 -I -B /workspace/hook.py\nNeedsTargets\n')
 Path('/run/core-pacman.conf').write_text(config)
 number=len(commands.report['commands']);commands.call(['/usr/bin/pacman','--debug','--config','/run/core-pacman.conf','--noconfirm','-U',*[str(r['archive'])for r in rows]],90)
 receipt=C.decode(C.read(witness));C.need(receipt==C.decode(C.read('/run/core-hook-expected.json')),'automatic libalpm dispatcher witnessed exact package target set')
 err=C.read(OUT/('phase%d-command-%03d.stderr'%(commands.report['phase'],number)),1024**2)
 C.need(b'command failed to execute correctly'not in err and b'error:'not in err,'no discarded scriptlet or post-transaction hook failure')
 log=C.read('/run/core-pacman.log',1024**2);C.need(b"running '20-systemd-sysusers.hook'"in log and b"running '21-systemd-tmpfiles.hook'"in log,'ordinary original upstream automatic sysusers/tmpfiles hooks ran')
 log_name='phase%d-%s-pacman.log'%(commands.report['phase'],label);C.need(not(OUT/log_name).exists(),'fresh exact transaction hook log');(OUT/log_name).write_bytes(log);witness.unlink();return dict(command=commands.report['commands'][number],witness=receipt,pacman_log=dict(file=log_name,**C.pin(log)),normal_flags='NO_NOHOOKS_NO_NOSCRIPTLET_NO_PRELOAD',after=wanted)

def worker(s,phase,root):
 global END
 END=time.monotonic()+3300;core=sources(s);core.T.END=END;report=dict(status='FAIL',phase=phase,commands=[],graphs={},hardware='NOT_RUN');commands=Commands(core.api,report);keys=None
 try:
  index=core.C.configuration('/inputs',C.pin(C.read('/inputs/lifecycle-input.json'))['sha256'])[0];C.need(index['token']==s['nonce'],'same source-owned assembly nonce');core.T.INPUTS=Path('/inputs')
  report['wallclock']=W.current(C.decode(C.read(OUT/('phase%d-wallclock.json'%phase))),s,phase,Path('/proc/cmdline').read_text());keys,packages=core.T.public_keys(commands,index);report['initial_pid1']=pid1(commands,root);before=graph(core,'phase%d-before'%phase,report);base,_,installed=core.C.states();report['inventories']={'before':inventory(core)}
  initial=C.decode(C.read(C.HERE/('pid1-baseline.json'if phase==1 else'pid1-expected.json')));initial.update(kernel=s['kernel']['profile']['release'],nonce=s['nonce'],serial=C.disk_serial(s['nonce'],'boot'));C.process(report['initial_pid1'],initial,'initializing')
  if phase==1:
   original_nodes=C.decode(C.read('/workspace/baseline-nodes.json',256*1024**2));overlay=C.decode(C.read('/workspace/overlay.json'));original_caps=C.decode(C.read('/workspace/capabilities.json',4*1024**2));C.need(before['nodes']==boot.expected_baseline(original_nodes,overlay)and before['security_capabilities']==original_caps,'entire copied original574 graph and caps plus exact boot/user overlay on first actual boot')
   C.need(report['inventories']['before']==base and report['initial_pid1']['exe']==C.pin(packages['systemd-original']['observed']['data']['usr/lib/systemd/systemd']),'actual original574 and baseline PID1 bytes')
   prior_accounts=core.F.accounts(ROOT);prior_shells=C.read('/etc/shells',65536)
   report['baseline_automatic']=transact(commands,packages,['systemd-original'],s['nonce'],'baseline-original-reinstall')
   report['inventories']['baseline']=inventory(core);C.need(report['inventories']['baseline']==base,'complete original574 remains after baseline automatic reinstall');first=graph(core,'baseline-automatic',report)
   report['install']=transact(commands,packages,sorted(core.C.NAMES)+[n+'-original'for n in core.C.profile()['support']],s['nonce'],'accepted-core7-install')
   report['inventories']['installed']=inventory(core);C.need(report['inventories']['installed']==installed,'all589 actual packages after ordinary signed transaction')
   generated_proof=generated(commands,core,report,before);after=graph(core,'phase1-installed',report)
   C.need(before['security_capabilities']==first['security_capabilities']==after['security_capabilities']==index['source_capabilities'],'complete source capability map unchanged across ordinary transactions');accounts=dict(before=prior_accounts,after=core.F.accounts(ROOT));cache=core.F.capture(core.api,ROOT,after,core.T.budget(core.api),core.F.read_aux(ROOT));tmp=commands.call(['/usr/bin/systemd-tmpfiles','--cat-config'])
   report['effects']=effects.changes(core,before['nodes'],after['nodes'],[p['observed']for p in packages.values()],[(p['transaction']['name'],p['transaction']['version'])for p in packages.values()],accounts,cache,generated_proof,dict(data=base64.b64encode(tmp).decode(),pin=C.pin(tmp)),dict(before=base64.b64encode(prior_shells).decode(),after=base64.b64encode(C.read('/etc/shells',65536)).decode()))
   core.T.configuration(after['nodes'],before['nodes'],[packages[n+'-original']['observed']for n in core.C.REPLACED],[packages[n]['observed']for n in core.C.NAMES],True)
   C.need(all(after['nodes'][n]==before['nodes'][n]for n in core.C.FIXTURES),'all owned preexisting user configuration bytes/mode/owner preserved');core.T.payload(after['nodes'],[packages[n]['observed']for n in core.C.NAMES]+[packages[n+'-original']['observed']for n in core.C.profile()['support']],{n for p in packages.values()for n in p['observed']['metadata'].get('backup',[])} )
   report.update(shells=dict(before=base64.b64encode(prior_shells).decode(),after=base64.b64encode(C.read('/etc/shells',65536)).decode()),accounts=accounts,auxiliary=cache,generated=generated_proof,tmpfiles=dict(data=base64.b64encode(tmp).decode(),pin=C.pin(tmp)),before_root=root)
  else:
   previous=C.decode(C.read(OUT/'phase1-custody.json',16*1024**2));C.need(previous['status']=='PASS_FULL_GRAPH_SIGNATURE_ACCOUNT_CACHE_AND_USER_PRESERVATION'and previous['root']==root and report['inventories']['before']==installed,'same prior completed root and all589 actual installed versions')
   old=C.decode(C.inflate(C.read(OUT/'phase1-installed-root.json.gz',64*1024**2)));C.need(before['nodes']==old['nodes']and before['security_capabilities']==old['security_capabilities'],'complete fresh second-boot persistent graph and capabilities match first boot')
   report['previous']=C.pin(C.encoded(previous));report['effects']=dict(status='EXACT_FIRST_BOOT_ALL_NODES_AND_CAPABILITIES')
  report.update(status='PASS_FULL_GRAPH_SIGNATURE_ACCOUNT_CACHE_AND_USER_PRESERVATION',root=root,nonce=s['nonce'],seconds=time.monotonic()-(END-3300),clock=3300)
 except BaseException as error:
  report.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:512]);raise
 finally:
  if keys is not None:
   commands.call(['/usr/bin/gpgconf','--homedir',str(keys),'--kill','all'],15)
   C.need(not any(os.path.lexists(keys/n)for n in('S.gpg-agent','S.gpg-agent.extra','S.gpg-agent.browser','S.gpg-agent.ssh')),'all public verifier agents absent')
   import shutil;shutil.rmtree(keys);report['public_home_retired']=True
  save('phase%d-custody.json'%phase,report)
 C.need(report['status']=='PASS_FULL_GRAPH_SIGNATURE_ACCOUNT_CACHE_AND_USER_PRESERVATION','complete actual stage required');return report

def observer(s,phase,root):
 global END
 END=time.monotonic()+175;core=sources(s);report=dict(phase=phase,role='observer',commands=[]);commands=Commands(core.api,report);custody=C.decode(C.read(OUT/('phase%d-custody.json'%phase),16*1024**2));C.need(custody['status']=='PASS_FULL_GRAPH_SIGNATURE_ACCOUNT_CACHE_AND_USER_PRESERVATION'and custody['public_home_retired']is True,'whole actual stage and independent key retirement')
 C.need(commands.call(['/usr/bin/systemctl','--system','is-system-running','--wait'],90)==b'running\n','manager startup actually finished with no failed unit before independent readback')
 value=dict(schema=1,nonce=s['nonce'],phase=phase,status='PASS_ACTUAL_SYSTEMD_PID1_AND_OWNED_STAGE',pid1=pid1(commands,root),worker=unit(commands,'caa-core-worker.service'),probe=unit(commands,'caa-core-probe.service'),custody=custody,previous=None if phase==1 else custody['previous'],observer_commands=report['commands'],hardware='NOT_RUN',release='NOT_ADMITTED')
 save('phase%d-observer.json'%phase,value);sys.stdout.buffer.write(C.PREFIX+C.encoded(value).replace(b'\n',b'')+b'\n');sys.stdout.flush()
 # SuccessAction=poweroff runs only after the natural observer and ExecStopPost.

def finish(s,phase):
 C.need(os.environ.get('SERVICE_RESULT')=='success'and os.environ.get('EXIT_CODE')=='exited'and os.environ.get('EXIT_STATUS')=='0','genuine natural observer exec-service exit, no shutdown simulation')
 observer=C.decode(C.read(OUT/('phase%d-observer.json'%phase),16*1024**2));C.need(observer['nonce']==s['nonce']and observer['phase']==phase,'same source-owned observer result')
 value=dict(schema=1,nonce=s['nonce'],phase=phase,event='observer-retired',status='NATURAL_OBSERVER_EXIT_BEFORE_OWNED_MANAGER_POWEROFF',observer=C.pin(C.encoded(observer)),service_result='success',exit_code='exited',exit_status='0')
 save('phase%d-retirement.json'%phase,value);sys.stdout.buffer.write(C.RETIRED+C.encoded(value).replace(b'\n',b'')+b'\n');sys.stdout.flush()

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('role',choices=('bootstrap','worker','observer','finish'));a=p.parse_args();s=C.decode(C.read('/workspace/selection.json'));phase,root=G.guard(s,a.role)
 if a.role=='bootstrap':
  sources(s);value=W.initialize(s,phase,Path('/proc/cmdline').read_text());save('phase%d-wallclock.json'%phase,value);return 0
 if a.role=='worker':worker(s,phase,root)
 elif a.role=='observer':observer(s,phase,root)
 else:finish(s,phase)
 return 0
if __name__=='__main__':raise SystemExit(main())

# SPDX-License-Identifier: MIT
"""Explicit ordinary-hook rollback in boots3/4; never callable outside the VM guard."""
import ast,base64,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import case as C,effects

def states(core):
 base,_,installed=core.C.states();middle=dict(installed,**{n:base[n]for n in core.C.REPLACED});remove={n:installed[n]for n in sorted(set(installed)-set(base))}
 C.need(len(base)==574 and len(installed)==len(middle)==589 and len(remove)==15 and set(core.C.REPLACED)=={'pacman','systemd','systemd-libs','systemd-resolvconf','systemd-sysvcompat'},'exact seven-product original574 restoration states')
 C.need({n:v for n,v in middle.items()if n not in remove}==base,'only15 declared additions removed after five signed downgrades')
 return base,middle,installed,remove

def expected(selected,phase,initial=False):
 C.need(type(phase)is int and phase in(1,2,3,4),'four source-owned boot phases')
 baseline=(phase in(1,4))if initial else phase in(3,4)
 value=C.decode(C.read(C.HERE/('pid1-baseline.json'if baseline else'pid1-expected.json')))
 value.update(kernel=selected['kernel']['profile']['release'],nonce=selected['nonce'],serial=C.disk_serial(selected['nonce'],'boot'));return value

def changes(core,*args):
 # Execute the complete held typed effects body with the explicit restored
 # original configuration branch; all account/cache/tmpfiles checks stay intact.
 raw=C.read(C.HERE/'effects.py').decode();tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='changes');body='\n'.join(raw.splitlines()[node.lineno-1:node.end_lineno])+'\n';anchor='core.T.configuration(after,before,old,new,True)'
 C.need(body.count(anchor)==1,'one complete effects configuration branch')
 changed=body.replace(anchor,'core.T.configuration(after,before,old,new,False)');C.need(changed.replace('core.T.configuration(after,before,old,new,False)',anchor)==body,'whole original effects inverse')
 namespace=dict(vars(effects));exec(compile(changed,'whole-typed-effects-with-original-config-branch','exec'),namespace);return namespace['changes'](core,*args)

def transaction(G,commands,core,packages,selected,role,report):
 base,middle,installed,remove=states(core);C.need(role in('downgrade','remove'),'two fixed rollback operations')
 before,after=(installed,middle)if role=='downgrade'else(middle,base)
 C.need(G.inventory(core)==before,'complete actual before589 inventory')
 names=sorted(core.C.REPLACED)if role=='downgrade'else sorted(remove)
 targets=sorted(n for n in names if n in core.C.NAMES)
 witness=Path('/run/core-hook-witness.json');C.need(not witness.exists(),'fresh ordinary rollback dispatcher witness')
 request=dict(nonce=selected['nonce'],label='rollback-'+role,targets=targets)
 Path('/run/core-hook-expected.json').write_bytes(C.encoded(request))
 hooks=Path('/run/core-hooks');C.need(hooks.is_dir()and not hooks.is_symlink(),'same owned literal hook directory')
 (hooks/'99-caa-core-witness.hook').write_text('[Trigger]\nType = Package\nOperation = Upgrade\nOperation = Remove\nTarget = pacman\nTarget = systemd\nTarget = systemd-*\n[Action]\nDescription = Exact owned Core rollback dispatcher witness\nWhen = PostTransaction\nExec = /usr/bin/python3 -I -B /workspace/hook.py\nNeedsTargets\n')
 prefix=['/usr/bin/pacman','--debug','--config','/run/core-pacman.conf','--noconfirm']
 argv=prefix+(['-U',*[str(packages[n+'-original']['transaction']['archive'])for n in names]]if role=='downgrade'else['-R',*names])
 number=len(report['commands']);commands.call(argv,90);raw=C.read(G.OUT/('phase3-command-%03d.stderr'%number),1024**2)
 C.need(b'command failed to execute correctly'not in raw and b'error:'not in raw,'no suppressed ordinary rollback hook or scriptlet failure')
 C.need(C.decode(C.read(witness))==request,'exact real upgrade/remove NeedsTargets stream');witness.unlink()
 log=C.read('/run/core-pacman.log',1024**2);name='phase3-rollback-'+role+'-pacman.log';C.need(not(G.OUT/name).exists(),'fresh full rollback log role');(G.OUT/name).write_bytes(log)
 if role=='downgrade':C.need(b"running '20-systemd-sysusers.hook'"in log and b"running '21-systemd-tmpfiles.hook'"in log,'real original upstream rollback Upgrade hooks')
 C.need(G.inventory(core)==after,'complete exact actual after inventory for rollback operation')
 return dict(command=report['commands'][number],before=before,after=after,witness=request,pacman_log=dict(file=name,**C.pin(log)),normal_flags='NO_NOHOOKS_NO_NOSCRIPTLET_NO_PRELOAD')

def configuration():
 return '[options]\nArchitecture = aarch64\nGPGDir = /tmp/core-public-gpg\nSigLevel = Required DatabaseOptional\nLocalFileSigLevel = Required\nLogFile = /run/core-pacman.log\nCacheDir = /run/core-cache\nHookDir = /etc/pacman.d/hooks\nHookDir = /run/core-hooks\n'

def worker(G,s,phase,root):
 C.need(phase in(3,4),'rollback worker only in two additional actual boots');G.END=time.monotonic()+3300;core=G.sources(s);core.T.END=G.END;report=dict(status='FAIL',phase=phase,commands=[],graphs={},hardware='NOT_RUN');commands=G.Commands(core.api,report);keys=None
 try:
  index=core.C.configuration('/inputs',C.pin(C.read('/inputs/lifecycle-input.json'))['sha256'])[0];C.need(index['token']==s['nonce'],'same authenticated assembly nonce');core.T.INPUTS=Path('/inputs');keys,packages=core.T.public_keys(commands,index)
  previous=C.decode(C.read(G.OUT/('phase%d-custody.json'%(phase-1)),16*1024**2));C.need(previous['status']=='PASS_FULL_GRAPH_SIGNATURE_ACCOUNT_CACHE_AND_USER_PRESERVATION'and previous['root']==root,'complete immediately preceding boot custody')
  report['previous']=C.pin(C.encoded(previous));report['initial_pid1']=G.pid1(commands,root);C.process(report['initial_pid1'],expected(s,phase,True),'initializing')
  before=G.graph(core,'phase%d-before'%phase,report);base,middle,installed,remove=states(core);report['inventories']={'before':G.inventory(core)}
  prior=C.decode(C.inflate(C.read(G.OUT/('phase1-installed-root.json.gz'if phase==3 else'phase3-restored-root.json.gz'),64*1024**2)))
  C.need(before['nodes']==prior['nodes']and before['security_capabilities']==prior['security_capabilities'],'complete persistent source graph/caps from prior completed boot')
  C.need(report['inventories']['before']==(installed if phase==3 else base),'exact initial589/574 map')
  if phase==3:
   Path('/run/core-cache').mkdir();Path('/run/core-hooks').mkdir();Path('/run/core-pacman.conf').write_text(configuration())
   accounts=core.F.accounts(G.ROOT);shells=C.read('/etc/shells',65536)
   report['stages']={}
   previous_graph=before
   for role,label in(('downgrade','downgraded'),('remove','restored')):
    report[role]=transaction(G,commands,core,packages,s,role,report);report['inventories'][label]=G.inventory(core)
    generated=G.generated(commands,core,report,previous_graph);after=G.graph(core,'phase3-'+label,report);C.need(after['security_capabilities']==before['security_capabilities']==index['source_capabilities'],'whole capability map across each actual rollback operation')
    account_proof=dict(before=accounts,after=core.F.accounts(G.ROOT));C.need(account_proof['before']==account_proof['after'],'all eight account/backup raw records unchanged by rollback')
    cache=core.F.capture(core.api,G.ROOT,after,core.T.budget(core.api),core.F.read_aux(G.ROOT));tmp=commands.call(['/usr/bin/systemd-tmpfiles','--cat-config']);shell_proof=dict(before=base64.b64encode(shells).decode(),after=base64.b64encode(C.read('/etc/shells',65536)).decode())
    observed=[p['observed']for p in packages.values()];versions=[(p['transaction']['name'],p['transaction']['version'])for p in packages.values()];tmp_proof=dict(data=base64.b64encode(tmp).decode(),pin=C.pin(tmp))
    proof=changes(core,previous_graph['nodes'],after['nodes'],observed,versions,account_proof,cache,generated,tmp_proof,shell_proof)
    originals=[packages[n+'-original']['observed']for n in core.C.REPLACED];candidate=[packages[n]['observed']for n in core.C.NAMES];backups={n for p in observed for n in p['metadata'].get('backup',[])}
    remaining=originals+([packages[n]['observed']for n in core.C.NAMES-core.C.REPLACED]+[packages[n+'-original']['observed']for n in core.C.profile()['support']]if role=='downgrade'else[])
    core.T.payload(after['nodes'],remaining,backups);core.T.configuration(after['nodes'],before['nodes'],originals,candidate,False)
    C.need(all(after['nodes'][n]==before['nodes'][n]for n in core.C.FIXTURES),'all existing owned user config bytes/mode/owner held')
    report['stages'][label]=dict(effects=proof,accounts=account_proof,auxiliary=cache,generated=generated,tmpfiles=tmp_proof,shells=shell_proof);previous_graph=after
   original=C.decode(C.inflate(C.read(G.OUT/'phase1-before-root.json.gz',64*1024**2)))
   removed=[packages[n if n in core.C.NAMES else n+'-original']['observed']for n in remove]
   for package in removed:
    for name,node in package['nodes'].items():
     if node['type']!='directory'and name not in original['nodes']:C.need(name not in after['nodes'],'every removed selected/support payload leaf absent '+name)
   report['effects']=dict(status='PASS_TWO_ORDINARY_ROLLBACK_BOUNDARIES_AND_FULL_ORIGINAL574_PAYLOAD',stages=list(report['stages']))
  else:report['effects']=dict(status='EXACT_RESTORED_FIRST_BOOT_ALL_NODES_AND_CAPABILITIES')
  report.update(status='PASS_FULL_GRAPH_SIGNATURE_ACCOUNT_CACHE_AND_USER_PRESERVATION',root=root,nonce=s['nonce'],seconds=time.monotonic()-(G.END-3300),clock=3300)
 except BaseException as error:report.update(error_type=type(error).__name__,error=str(error)[:512]);raise
 finally:
  if keys is not None:
   commands.call(['/usr/bin/gpgconf','--homedir',str(keys),'--kill','all'],15);C.need(not any(__import__('os').path.lexists(keys/n)for n in('S.gpg-agent','S.gpg-agent.extra','S.gpg-agent.browser','S.gpg-agent.ssh')),'original public-only key agent retirement');__import__('shutil').rmtree(keys);report['public_home_retired']=True
  G.save('phase%d-custody.json'%phase,report)
 return report

def validate_tail(directory,core,selected,boots,graph):
 C.need(len(boots)==4,'all four independent natural actual boots');directory=Path(directory);base,middle,installed,remove=states(core)
 first=C.decode(C.read(directory/'phase1-custody.json',16*1024**2));previous=C.decode(C.read(directory/'phase2-custody.json',16*1024**2));prior_graph=graph(directory,first['graphs']['phase1-installed']);original=graph(directory,first['graphs']['phase1-before'])
 catalog=C.decode(C.read(directory.parent/'inputs/catalog.json'));packages={}
 for name,row in catalog['products'].items():
  package=core.C.P.archive(directory.parent/'inputs/packages'/row['file']);C.need(package['metadata']['pkgname']==[row['name']]and package['metadata']['pkgver']==[row['version']],'complete authenticated original/candidate package metadata');packages[name]=dict(observed=package,transaction=dict(name=row['name'],version=row['version'],archive=Path('/inputs/packages')/row['file']))
 for phase,record in enumerate(boots[2:],3):
  C.need(record['phase']==phase,'fixed phase3/4 ordering');C.command(record['qemu'],3600);C.process(record['result']['pid1'],expected(selected,phase))
  row=C.decode(C.read(directory/('phase%d-custody.json'%phase),16*1024**2));C.need(row==record['result']['custody']and row['phase']==phase and row['status']=='PASS_FULL_GRAPH_SIGNATURE_ACCOUNT_CACHE_AND_USER_PRESERVATION'and row['public_home_retired']is True,'complete source custody and public verifier retirement')
  C.need(row['previous']==C.pin(C.encoded(previous))and record['result']['previous']==row['previous'],'whole immediately preceding natural boot custody')
  C.need(row['root']==first['root']and row['clock']==3300 and 0<=row['seconds']<=3300 and len(row['commands'])<=128,'same original root and held per-stage3300/command bounds')
  C.process(row['initial_pid1'],expected(selected,phase,True),'initializing')
  for prefix,commands in(('phase%d'%phase,row['commands']),('phase%d-observer'%phase,record['result']['observer_commands'])):
   for number,command in enumerate(commands):
    C.command(command,90)
    for suffix in('stdout','stderr'):
     raw=C.read(directory/('%s-command-%03d.%s'%(prefix,number,suffix)),1024**2);C.need(C.pin(raw)==dict(bytes=command[suffix+'_bytes'],sha256=command[suffix+'_sha256']),'every whole foreground rollback stream')
  wanted={'phase3-before','phase3-downgraded','phase3-restored'}if phase==3 else{'phase4-before'};C.need(set(row['graphs'])==wanted,'all rollback/full restoration graph captures')
  graphs={n:graph(directory,r)for n,r in row['graphs'].items()};before=graphs['phase%d-before'%phase];C.need(before['nodes']==prior_graph['nodes']and before['security_capabilities']==prior_graph['security_capabilities'],'all prior persistent nodes and capabilities on additional fresh boot')
  C.need(row['inventories']==(dict(before=installed,downgraded=middle,restored=base)if phase==3 else dict(before=base)),'full actual589/589/574 inventory equality')
  if phase==3:
   previous_graph=before;C.need(set(row['stages'])=={'downgraded','restored'},'both separately protected transaction boundaries')
   for role,label in(('downgrade','downgraded'),('remove','restored')):
    transaction=row[role];names=sorted(core.C.REPLACED)if role=='downgrade'else sorted(remove);argv=['/usr/bin/pacman','--debug','--config','/run/core-pacman.conf','--noconfirm']+(['-U',*[str(packages[n+'-original']['transaction']['archive'])for n in names]]if role=='downgrade'else['-R',*names]);targets=sorted(set(names)&core.C.NAMES)
    C.need(transaction['command']in row['commands']and transaction['command']['argv']==argv and transaction['normal_flags']=='NO_NOHOOKS_NO_NOSCRIPTLET_NO_PRELOAD','exact ordinary rollback argv and complete actual command membership')
    C.need(transaction['before']==(installed if role=='downgrade'else middle)and transaction['after']==(middle if role=='downgrade'else base)and transaction['witness']==dict(nonce=selected['nonce'],label='rollback-'+role,targets=targets),'complete two exact transaction inventories and automatic dispatcher targets')
    ref=transaction['pacman_log'];name='phase3-rollback-'+role+'-pacman.log';C.need(ref['file']==name and C.pin(C.read(directory/name,1024**2))=={k:ref[k]for k in('bytes','sha256')},'complete original transaction log')
    if role=='downgrade':
     raw=C.read(directory/name,1024**2);C.need(b"running '20-systemd-sysusers.hook'"in raw and b"running '21-systemd-tmpfiles.hook'"in raw,'original upstream automatic Upgrade hooks')
    number=row['commands'].index(transaction['command']);err=C.read(directory/('phase3-command-%03d.stderr'%number),1024**2);C.need(b'error:'not in err and b'command failed to execute correctly'not in err,'no suppressed rollback scriptlet/hook error')
    current=graphs['phase3-'+label];proof=row['stages'][label];C.need(current['security_capabilities']==before['security_capabilities']and proof['accounts']['before']==proof['accounts']['after']==first['accounts']['after'],'all capabilities and initialized account bytes preserved')
    observed=[p['observed']for p in packages.values()];versions=[(p['transaction']['name'],p['transaction']['version'])for p in packages.values()]
    C.need(changes(core,previous_graph['nodes'],current['nodes'],observed,versions,proof['accounts'],proof['auxiliary'],proof['generated'],proof['tmpfiles'],proof['shells'])==proof['effects'],'whole recomputed typed per-boundary effects')
    originals=[packages[n+'-original']['observed']for n in core.C.REPLACED];candidates=[packages[n]['observed']for n in core.C.NAMES];backups={n for p in observed for n in p['metadata'].get('backup',[])}
    remaining=originals+([packages[n]['observed']for n in core.C.NAMES-core.C.REPLACED]+[packages[n+'-original']['observed']for n in core.C.profile()['support']]if role=='downgrade'else[])
    core.T.payload(current['nodes'],remaining,backups);core.T.configuration(current['nodes'],before['nodes'],originals,candidates,False);C.need(all(current['nodes'][n]==before['nodes'][n]for n in core.C.FIXTURES),'all user configuration remains exact at each boundary');previous_graph=current
   for name in remove:
    for path,node in packages[name if name in core.C.NAMES else name+'-original']['observed']['nodes'].items():
     if node['type']!='directory'and path not in original['nodes']:C.need(path not in previous_graph['nodes'],'removed package payload cannot survive rollback')
   C.need(row['effects']==dict(status='PASS_TWO_ORDINARY_ROLLBACK_BOUNDARIES_AND_FULL_ORIGINAL574_PAYLOAD',stages=['downgraded','restored']),'explicit restored574 result');prior_graph=previous_graph
  else:C.need(row['effects']==dict(status='EXACT_RESTORED_FIRST_BOOT_ALL_NODES_AND_CAPABILITIES'),'full original574 persistence result')
  previous=row
 return dict(status='PASS_FOUR_BOOT_AUTOMATIC_HOOK_ROLLBACK_DATA_PENDING_ROOT_DECISION',graphs=8,original_packages=574,hardware='NOT_RUN',Asahi='NOT_RUN',release='NOT_ADMITTED')

# SPDX-License-Identifier: MIT
"""Passive complete guest custody joins. Cache DATA never creates authority."""
import base64,gzip,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C,adapter,effects,boot

def graph(directory,ref):
 C.need(set(ref)=={'file','raw','compressed'}and ref['file'].endswith('-root.json.gz')and'/'not in ref['file'],'fixed full graph role');raw=C.read(Path(directory)/ref['file'],64*1024**2);C.need(C.pin(raw)==ref['compressed'],'whole retained compressed graph');data=C.inflate(raw);C.need(len(data)<=256*1024**2 and C.pin(data)==ref['raw'],'whole retained full raw graph');v=C.decode(data);C.need(v['complete']is True and type(v['nodes'])is dict and len(v['nodes'])<=500000,'complete bounded persistent graph');return v

def _install_validate(directory,source,selected,boots):
 C.selection(selected);core=adapter.core(source);directory=Path(directory);C.need(len(boots)==2,'two actual fresh boots mandatory');all_graphs={};previous=None
 expected=C.decode(C.read(C.HERE/'pid1-expected.json'));expected.update(kernel=selected['kernel']['profile']['release'],nonce=selected['nonce'],serial=C.disk_serial(selected['nonce'],'boot'))
 for phase,record in enumerate(boots,1):
  C.need(record['phase']==phase,'fixed ordered two boot case');C.command(record['qemu'],3600)
  row=C.decode(C.read(directory/('phase%d-custody.json'%phase),16*1024**2));C.need(row==record['result']['custody']and row['status']=='PASS_FULL_GRAPH_SIGNATURE_ACCOUNT_CACHE_AND_USER_PRESERVATION'and row['phase']==phase and row['public_home_retired']is True,'full source-owned custody equals actual UART frame')
  C.process(record['result']['pid1'],expected)
  C.need(row['clock']==3300 and type(row['seconds'])in(int,float)and 0<=row['seconds']<=3300 and type(row['commands'])is list and len(row['commands'])<=128,'source-owned stage command and clock envelope')
  for prefix,commands in(('phase%d'%phase,row['commands']),('phase%d-observer'%phase,record['result']['observer_commands'])):
   for number,command in enumerate(commands):
    C.command(command,90)
    for suffix in('stdout','stderr'):
     raw=C.read(directory/('%s-command-%03d.%s'%(prefix,number,suffix)),1024**2);C.need(C.pin(raw)==dict(bytes=command[suffix+'_bytes'],sha256=command[suffix+'_sha256']),'every complete foreground stream byte join')
  initial=C.decode(C.read(C.HERE/('pid1-baseline.json'if phase==1 else'pid1-expected.json')));initial.update(kernel=selected['kernel']['profile']['release'],nonce=selected['nonce'],serial=C.disk_serial(selected['nonce'],'boot'));C.process(row['initial_pid1'],initial,'initializing')
  wanted={'phase1-before','baseline-automatic','phase1-installed'}if phase==1 else{'phase2-before'};C.need(set(row['graphs'])==wanted,'all mandatory full persistent observations')
  graphs={n:graph(directory,r)for n,r in row['graphs'].items()};all_graphs.update(graphs)
  base,_,installed=core.C.states();C.need(row['inventories']==(dict(before=base,baseline=base,installed=installed)if phase==1 else dict(before=installed)),'every actual full574/589 inventory map')
  if phase==1:
   original=C.decode(C.inflate(C.read(directory/'media-source-nodes.json.gz',64*1024**2)));overlay=C.decode(C.read(directory/'media-overlay.json'));caps=C.decode(C.read(directory/'media-source-capabilities.json',4*1024**2));C.need(graphs['phase1-before']['nodes']==boot.expected_baseline(original,overlay)and all(g['security_capabilities']==caps for g in graphs.values()),'whole first boot source/overlay and all complete capability maps')
   for role in('baseline_automatic','install'):
    transaction=row[role];ref=transaction['pacman_log'];name='phase1-'+('baseline-original-reinstall'if role=='baseline_automatic'else'accepted-core7-install')+'-pacman.log';C.need(ref['file']==name,'fixed original transaction log role');raw=C.read(directory/name,1024**2);C.need(C.pin(raw)=={n:ref[n]for n in('bytes','sha256')}and b"running '20-systemd-sysusers.hook'"in raw and b"running '21-systemd-tmpfiles.hook'"in raw,'full original actual automatic-hook log');C.command(transaction['command']);C.need(transaction['normal_flags']=='NO_NOHOOKS_NO_NOSCRIPTLET_NO_PRELOAD'and transaction['witness']['nonce']==selected['nonce']and'--noscriptlet'not in transaction['command']['argv'],'actual ordinary signed dispatcher receipt')
   C.need(row['baseline_automatic']['witness']['targets']==['systemd']and set(row['install']['witness']['targets'])==core.C.NAMES,'original reinstall then all seven candidate package hook targets')
   # Source-owned signature checks and native64 authentication remain mandatory
   # at production; here replay every complete typed graph/effect predicate.
   packages=[];versions=[]
   catalog=C.decode(C.read(directory.parent/'inputs/catalog.json'))
   for p in catalog['products'].values():
    archive=core.C.P.archive(directory.parent/'inputs/packages'/p['file']);C.need(archive['metadata']['pkgname']==[p['name']]and archive['metadata']['pkgver']==[p['version']],'whole signed selected archive metadata');packages.append(archive);versions.append((p['name'],p['version']))
   before,after=graphs['phase1-before']['nodes'],graphs['phase1-installed']['nodes']
   # Shell DATA stays alongside its complete graph. Reconstruct only from the
   # source-owned raw shell receipt, never infer it from a permissive checksum.
   C.need('shells'in row,'complete shell configuration DATA required');proof=effects.changes(core,before,after,packages,versions,row['accounts'],row['auxiliary'],row['generated'],row['tmpfiles'],row['shells']);C.need(proof==row['effects'],'recomputed complete typed effects')
  else:C.need(graphs['phase2-before']['nodes']==all_graphs['phase1-installed']['nodes']and graphs['phase2-before']['security_capabilities']==all_graphs['phase1-installed']['security_capabilities'],'all persistent nodes/capabilities on genuine second boot');C.need(row['previous']==C.pin(C.encoded(previous)),'same exact first boot custody')
  previous=row
 return dict(status='PASS_FULL_SOURCE_OWNED_TWO_BOOT_DATA_PENDING_ROOT_DECISION',graphs=len(all_graphs),hardware='NOT_RUN',Asahi='NOT_RUN',release='NOT_ADMITTED')

def validate(directory,source,selected,boots):
 C.need(len(boots)==4,'explicit new four-boot automatic rollback case')
 _install_validate(directory,source,selected,boots[:2])
 import rollback
 return rollback.validate_tail(directory,adapter.core(source),selected,boots,graph)

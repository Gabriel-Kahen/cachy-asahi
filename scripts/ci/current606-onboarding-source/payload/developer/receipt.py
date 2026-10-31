# SPDX-License-Identifier: MIT
"""Finite DATA gate; source/transport/CI/full native lifecycle remain mandatory."""
import math,re
STEPS=('setup-preview','setup-apply','setup-repeat','terminal','fish-startup','zsh-startup','editor','compiler-version','compile','hello','setup-remove','fish-after-remove','zsh-after-remove')
CONFLICTS=('preview-existing','activate-preserve-existing','remove-preserve-existing')
BOUNDS=dict(fixture=420,command=20,max_nodes=256,max_bytes=8*1024**2,max_file=1024**2)
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(value):need(type(value)is dict and set(value)=={'bytes','sha256'}and type(value['bytes'])is int and 0<=value['bytes']<=BOUNDS['max_bytes']and re.fullmatch('[0-9a-f]{64}',value['sha256']or''),'exact DATA pin')
def validate(value,nonce):
 need(type(value)is dict and value['status']=='PASS_FULL606_APPS7_SETUP6_SOFTWARE_ONBOARDING_REQUIRES_REPLAY'and value['nonce']==nonce and re.fullmatch('[0-9a-f]{32}',nonce or''),'exact fresh-user receipt/nonce')
 need(value['phase']=='install-setup6'and value['versions']=={'cachy-asahi-apps':'0.1.0-7','cachy-asahi-setup':'0.1.0-6','cachy-asahi-repository-runtime':'0.1.0-1'}and value['package_count']==606,'joint exact606 installed composition')
 need(value['security']==dict(CapEff=0,CapPrm=0,CapInh=0,CapAmb=0,CapBnd=0xdb,NoNewPrivs=1)and value['uid']>0 and value['gid']>0,'actual ordinary zero-capability/NNP profile')
 rows=value['commands'];need(type(rows)is list and tuple(r['step']for r in rows)==STEPS and all(r['success']is True and r['error']is None and r['returncode']==0 for r in rows),'whole original13 journey commands')
 for row in rows:
  need(row['terminal']==('PTY, scripted command'if row['step']in('terminal','fish-startup','zsh-startup','fish-after-remove','zsh-after-remove')else'captured process'),'actual source-owned PTY command roles')
 need(value['journey']['steps']==13 and value['journey']['terminal_scope']=='software PTY and interactive shell startup, not graphical terminal integration'and value['journey']['editor_scope']=='scripted noninteractive Vim, not GUI/editor usability','original honest software scope')
 conflicts=value['existing'];need(tuple(r['step']for r in conflicts['commands'])==CONFLICTS and[r['returncode']for r in conflicts['commands']]==[2,2,0]and conflicts['config_identity_preserved']is True and conflicts['original_files']==['.config/fish/config.fish','.zshrc','user-owned.conf'],'all existing config bytes and identities held')
 need(value['direct_child_reaped']is value['group_retired']is value['ordinary_uid_absent']is True,'actual foreground retirement and no ordinary UID processes')
 start,seconds=value['clock']['started'],value['clock']['seconds'];need(type(start)in(int,float)and type(seconds)in(int,float)and math.isfinite(start)and math.isfinite(seconds)and start>=0 and 0<seconds<=420,'finite fixture original component clock')
 pin(value['evidence']);need(value['evidence']['bytes']>0 and value['evidence_path']=='container/onboarding-evidence.zip','fixed opaque safe evidence role')
 need(value['native_acceptance']=='REQUIRES_FULL_REPLAY_AND_ROOT_DECISION'and all(value[k]=='NOT_RUN'for k in('graphical_terminal','GUI','audio','hardware','independent_new_user_install'))and value['performance']=='NOT_CLAIMED'and value['release']=='NOT_ADMITTED','no software-to-hardware/installation admission')
 return value

def replay(raw,value,source):
 """Read every fixed archive member; never execute retained commands/binary."""
 import hashlib,io,json,stat,zipfile
 wanted=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest());need(wanted==value['evidence'],'whole opaque evidence pin')
 with zipfile.ZipFile(io.BytesIO(raw))as z:
  infos=z.infolist();names=[i.filename for i in infos];need(len(infos)<=BOUNDS['max_nodes']and len(set(names))==len(names)and sum(i.file_size for i in infos)<=BOUNDS['max_bytes']and z.testzip()is None,'full ZIP uniqueness/size/CRC')
  for i in infos:need(not i.flag_bits&1 and not i.is_dir()and stat.S_ISREG(i.external_attr>>16)and 0<=i.file_size<=BOUNDS['max_file']and not i.filename.startswith('/')and all(p not in('','.','..')for p in i.filename.split('/'))and all(32<=ord(c)<127 and c not in ':\\<>|?*"'for c in i.filename),'ordinary safe bounded evidence member')
  files={n:z.read(n)for n in names}
 custody=json.loads(files.pop('workspace-custody.json'));selected={n:r for n,r in custody.items()if r['file']is not None};need(set(files)==set(selected),'whole finite workspace file closure')
 for n,b in files.items():need(selected[n]['file']==dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())and'security.capability'not in selected[n]['xattrs'],'every complete workspace file pin/capability')
 need(json.loads(files['evidence/ordinary-result.json'])=={k:value[k]for k in('journey','existing','commands','security','uid','gid','nonce')},'whole ordinary receipt/stdout join')
 source=bytes(source);edited=source+b'// Disposable software onboarding edit\n';need(files['evidence/edited-hello.c']==files['fresh/workspace/examples/development/hello.c']==edited,'actual scripted Vim edit retains complete exact example')
 binary=files['evidence/hello'];need(binary==files['fresh/workspace/build/onboarding/hello']and len(binary)>=64 and binary[:6]==b'\x7fELF\x02\x01'and int.from_bytes(binary[18:20],'little')==183,'complete same native AArch64 ELF binary')
 need(value['journey']['original_source_sha256']==hashlib.sha256(source).hexdigest()and value['journey']['edited_source_sha256']==hashlib.sha256(edited).hexdigest()and value['journey']['binary_sha256']==hashlib.sha256(binary).hexdigest(),'complete source/edit/executable hashes')
 markers=dict(terminal=b'CACHY_ASAHI_TERMINAL_OK',**{'fish-startup':b'CACHY_ASAHI_FISH_OK','zsh-startup':b'CACHY_ASAHI_ZSH_OK','fish-after-remove':b'CACHY_ASAHI_FISH_REMOVED','zsh-after-remove':b'CACHY_ASAHI_ZSH_REMOVED'})
 for i,row in enumerate(value['commands']):
  prefix='journey-%02d-%s'%(i,row['step']);need(row['stdout_file']==prefix+'.stdout'and row['stderr_file']==prefix+'.stderr','fixed full command log roles');out=files['evidence/'+row['stdout_file']];err=files['evidence/'+row['stderr_file']];need(len(out)+len(err)<=128*1024 and not err,'bounded complete actual command outputs')
  if row['step']in markers:need(markers[row['step']]in out and row['expected_output']==markers[row['step']].decode(),'actual PTY/shell marker')
  if row['step']=='hello':need(out==b'Hello from cachy-asahi\n','actual compiled program exact output')
  if row['step']=='fish-startup':need(b'sentinel-onboarding'in out,'actual Fish listing fixture')
  if row['step']=='zsh-after-remove':need(row['prompt_response']['prompt']=='--- Type one of the keys in parentheses ---'and row['prompt_response']['response']=='0\n'and type(row['prompt_response']['observed_and_sent'])is bool and(row['prompt_response']['observed_and_sent']is ('--- Type one of the keys in parentheses ---'in out.decode(errors='replace'))),'actual configured Zsh startup prompt/response observation')
 need(json.loads(files['evidence/journey-commands.json'])==value['commands'],'complete original13-command file/receipt equality')
 configs={'.config/fish/config.fish':b'# original private Fish configuration\n# >>> cachy-asahi setup fish v1 >>>\n# user-owned edited block, never overwritten\n','.zshrc':b'# original private Zsh configuration\n# >>> cachy-asahi setup zsh v1 >>>\n# user-owned edited block, never overwritten\n','user-owned.conf':b'original unrelated user configuration\n'};existing=value['existing'];need(existing['before']==existing['after'],'existing config full identity before/after equality')
 for n,b in configs.items():need(files['existing/'+n]==b and existing['before'][n]['sha256']==hashlib.sha256(b).hexdigest()and custody['existing/'+n]['identity']==existing['after'][n]['identity'],'whole user-owned config bytes/inode/metadata held')
 for row in existing['commands']:
  out=files['evidence/'+row['step']+'.stdout'];err=files['evidence/'+row['step']+'.stderr'];need(hashlib.sha256(out).hexdigest()==row['stdout_sha256']and hashlib.sha256(err).hexdigest()==row['stderr_sha256']and not err,'all existing config command raw outputs joined');reply=json.loads(out);need(reply['operation']==('remove'if row['step']=='remove-preserve-existing'else'activate')and reply['mode']==('preview'if row['step']=='preview-existing'else'applied'),'actual preview/apply/remove status')
 return dict(status='COMPLETE_SOFTWARE_ONBOARDING_EVIDENCE_REPLAY_ONLY',files=len(files),bytes=sum(map(len,files.values())),actual_acceptance='NOT_GRANTED')

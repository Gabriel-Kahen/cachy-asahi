# SPDX-License-Identifier: MIT
"""Finite installed CLI exercises over synthetic reports, never hardware evidence."""
import argparse,contextlib,copy,hashlib,io,json,os,re,runpy,socket,stat,subprocess,sys,urllib.request
from pathlib import Path
from unittest.mock import patch
INSTALLED=Path('/usr/bin/cachy-asahi-doctor')
RUNNER=Path('/runner/installed_comparison.py')
PACKAGE_GROUPS={
 'platform':('asahi-meta','linux-asahi','m1n1','uboot-asahi','asahi-alarm-keyring','asahi-firmware','asahi-scripts','asahi-configs','asahi-audio','alsa-ucm-conf-asahi','speakersafetyd','mesa','mesa-asahi','libdrm'),
 'desktop':('hyprland','pipewire','pipewire-pulse','wireplumber'),
 'project':('cachy-asahi-hyprland-settings','cachy-asahi-fish-config','cachy-asahi-zsh-config','cachy-asahi-setup','cachy-asahi-update','cachy-asahi-fdk-aac','cachy-asahi-ksmctl','cachy-asahi-topmem','cachy-asahi-zsh-autosuggestions','cachy-asahi-fish-bang-bang','cachy-asahi-doctor','cachy-asahi-welcome')}
UNITS={'system':('speakersafetyd.service','asahi-audio.service','display-manager.service'),'user':('pipewire.service','pipewire-pulse.service','wireplumber.service','xdg-desktop-portal.service','xdg-desktop-portal-hyprland.service')}
TOOLS=('pacman','systemctl','Hyprland','hyprctl','wpctl','pipewire','wireplumber','cachy-asahi-setup','cachy-asahi-update')
STATES=('checked','unavailable','unknown')
LIMITATIONS=[
 'User-supplied reports are not authenticated; matching model labels do not identify the same machine.',
 'Unknown and unavailable describe missing knowledge; neither means absent or healthy.',
 'Observed changes do not establish update causation, health, regression, hardware behavior or performance.',
 'Check additions/removals describe report coverage; no new observations were collected.']
GUARD_NAMES=('collect','query','fixed_read','available','local_user_bus','audio_socket')
AUDIT_EVENTS=('subprocess.Popen','os.system','os.fork','os.posix_spawn','os.exec','socket.__new__','socket.connect','socket.getaddrinfo')
CASE_NAMES=('unchanged-json','changed-json','unchanged-human','malformed-refused','unsupported-refused','existing-output-refused','input-output-alias-refused','private-output','symlink-input-refused','guarded-unchanged','guarded-changed','guarded-malformed')

def need(ok,message):
 if not ok:raise ValueError(message)
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def row(name,state,value):return dict(check=name,state=state,value=value,note='SYNTHETIC SUPPLIED REPORT FIXTURE; not collected')
def fixture():
 checks=[row('platform','checked',dict(architecture='aarch64',kernel='synthetic-kernel',page_size_bytes=4096)),
  row('apple-model','unavailable',dict(identifier=None,observed_board=None,model=None,model_property_available=False)),
  row('session','unknown',dict(type='unknown',wayland_environment=False,hyprland_environment=False)),
  row('tools','checked',{name:False for name in TOOLS})]
 checks.extend(row('package/'+name,'checked',dict(group=group,presence='absent',version=None))for group,names in PACKAGE_GROUPS.items()for name in names)
 checks.extend(row(scope+'/'+unit,'unavailable',None)for scope,units in UNITS.items()for unit in units)
 checks.append(row('audio/default-output','unavailable',None))
 return dict(schema_version=1,tool='cachy-asahi-doctor',version='0.2.0',collected_utc='2026-10-27T00:00:00+00:00',checks=checks,
  coverage={state:sum(r['state']==state for r in checks)for state in STATES},
  limits=dict(command_seconds=2,total_query_seconds=20,command_output_bytes=65536,device_tree_bytes=4096),
  scope='local observations only',limitations=['SYNTHETIC SUPPLIED REPORT FIXTURE; no hardware or live audio observation.'])
def fixtures():
 before=fixture();unchanged=copy.deepcopy(before);unchanged['collected_utc']='2026-10-27T00:00:01+00:00';unchanged['checks'].reverse()
 for r in unchanged['checks']:r['note']='SYNTHETIC ignored note'
 changed=copy.deepcopy(before);changed['collected_utc']='2026-10-27T00:00:02+00:00'
 for r in changed['checks']:
  if r['check']=='package/linux-asahi':r['value'].update(presence='present',version='synthetic-2')
  if r['check']=='audio/default-output':r['state']='unknown'
 changed['coverage']={state:sum(r['state']==state for r in changed['checks'])for state in STATES}
 unsupported=copy.deepcopy(before);unsupported['version']='99.0'
 return before,unchanged,changed,unsupported
def expected_comparison(before,after):
 # Independent fixture oracle: only the two explicitly named supplied rows may change.
 old={r['check']:dict(state=r['state'],value=r['value'])for r in before['checks']};new={r['check']:dict(state=r['state'],value=r['value'])for r in after['checks']};changes=[]
 for name in ('audio/default-output','package/linux-asahi'):
  if old[name]!=new[name]:changes.append(dict(check=name,kind='state'if name=='audio/default-output'else'value',before=old[name],after=new[name]))
 need(all(old[name]==new[name]for name in set(old)-{'audio/default-output','package/linux-asahi'}),'fixture drift outside finite comparison')
 return dict(schema_version=1,tool='cachy-asahi-doctor-comparison',scope='supplied observations only',
  before={key:before[key]for key in ('version','collected_utc')},after={key:after[key]for key in ('version','collected_utc')},changed=bool(changes),change_count=len(changes),unchanged_count=len(old)-len(changes),
  coverage=dict(before=before['coverage'],after=after['coverage']),changes=changes,limitations=LIMITATIONS)
def identity(path):
 value=path.lstat();need(stat.S_ISREG(value.st_mode)or stat.S_ISLNK(value.st_mode),'finite fixture file/link required')
 return dict(device=value.st_dev,inode=value.st_ino,mode=value.st_mode,uid=value.st_uid,gid=value.st_gid,size=value.st_size,mtime_ns=value.st_mtime_ns,ctime_ns=value.st_ctime_ns,
  link=os.readlink(path)if stat.S_ISLNK(value.st_mode)else None,sha256=None if stat.S_ISLNK(value.st_mode)else sha(path))
def snapshot(root):
 need(root.is_absolute()and root.is_dir()and not root.is_symlink(),'ordinary comparison fixture root required')
 info=root.stat();rows={'.':dict(device=info.st_dev,inode=info.st_ino,mode=info.st_mode,uid=info.st_uid,gid=info.st_gid)}
 for path in sorted(root.iterdir()):
  need(len(rows)<16,'finite comparison fixture membership required');rows[path.name]=identity(path)
 return rows
def preserve(root,before):need(snapshot(root)==before,'comparison fixtures/reports not preserved across lifecycle')
def guarded(payload_sha,argv):
 """Run installed code with denied collection/actors, separately from direct CLI execution."""
 need(INSTALLED.is_file()and not INSTALLED.is_symlink()and sha(INSTALLED)==payload_sha,'guarded installed payload differs')
 loaded=runpy.run_path(str(INSTALLED),run_name='doctor_installed_guarded');namespace=loaded['main'].__globals__;attempts=[]
 def forbidden(*_args,**_kwargs):
  attempts.append('DENIED');raise AssertionError('installed comparison attempted collection/process/network')
 active=[False]
 def audit(event,args):
  if active[0]and event in AUDIT_EVENTS:forbidden()
 sys.addaudithook(audit);out=io.StringIO();err=io.StringIO()
 with contextlib.ExitStack()as stack:
  stack.enter_context(patch.dict(namespace,{name:forbidden for name in GUARD_NAMES}))
  for name in ('Popen','run','check_output','check_call','call'):stack.enter_context(patch.object(subprocess,name,forbidden))
  for name in ('socket','create_connection','getaddrinfo'):stack.enter_context(patch.object(socket,name,forbidden))
  stack.enter_context(patch.object(urllib.request,'urlopen',forbidden))
  for name in dir(os):
   if name in ('system','fork','forkpty','posix_spawn','posix_spawnp')or name.startswith(('exec','spawn')):
    if callable(getattr(os,name)):stack.enter_context(patch.object(os,name,forbidden))
  stack.enter_context(contextlib.redirect_stdout(out));stack.enter_context(contextlib.redirect_stderr(err));active[0]=True
  try:code=loaded['main'](argv)
  finally:active[0]=False
 need(attempts==[],'guarded collection/process/network attempted');need(len(out.getvalue().encode())+len(err.getvalue().encode())<=65536,'guarded output cap')
 return dict(status='PASS_GUARDED_INSTALLED_CODE',mode='INSTALLED_CODE_LOADER_NOT_DIRECT_EXEC',installed_path=str(INSTALLED),installed_sha256=payload_sha,
  returncode=code,stdout=out.getvalue(),stderr=err.getvalue(),forbidden_calls=0,guards=list(GUARD_NAMES),audit_events=list(AUDIT_EVENTS))
def run_comparisons(user,home,output,payload_sha,label):
 """Called by the native lifecycle after exact installed ownership/payload checks."""
 need(re.fullmatch('[a-z-]{1,40}',label)is not None,'finite lifecycle phase required')
 need(INSTALLED.is_file()and not INSTALLED.is_symlink()and sha(INSTALLED)==payload_sha,'installed comparison executable differs')
 directory=output/('comparison-'+label);directory.mkdir(mode=0o700);owner=home.stat();os.chown(directory,owner.st_uid,owner.st_gid)
 before,unchanged,changed,unsupported=fixtures();paths={}
 for name,data in [('before',before),('unchanged',unchanged),('changed',changed),('unsupported',unsupported),('malformed',None),('existing',dict(sentinel='SYNTHETIC existing private file'))]:
  path=directory/(name+'.json');path.write_text('{"SYNTHETIC PRIVATE":'if data is None else json.dumps(data,sort_keys=True)+'\n');path.chmod(0o600);os.chown(path,owner.st_uid,owner.st_gid);paths[name]=path
 paths['link']=directory/'input-link';paths['link'].symlink_to('before.json');os.chown(paths['link'],owner.st_uid,owner.st_gid,follow_symlinks=False)
 pins={name:identity(path)for name,path in paths.items()};cases=[];created=directory/'new-comparison.json';invalid=directory/'must-not-exist.json'
 def invoke(name,args,expected=0,result=None,human=False):
  raw=user(home,[str(INSTALLED),'--compare',str(paths['before']),*args],expected)
  need(len(raw.encode())<=65536,'comparison output cap')
  if result is not None:need(json.loads(raw)==result,'installed comparison JSON differs: '+name)
  elif human:need(raw=='cachy-asahi doctor — offline observation comparison\n0 changed checks; 43 unchanged.\nNo observation changes.\n'+'\n'.join(LIMITATIONS)+'\n','installed comparison text differs')
  else:need(raw=='','refused comparison leaked stdout')
  cases.append(dict(case=name,mode='DIRECT_INSTALLED_EXECUTABLE',returncode=expected,stdout_sha256=hashlib.sha256(raw.encode()).hexdigest()))
  need({key:identity(path)for key,path in paths.items()}==pins,'comparison input/existing-file preservation differs');need(not invalid.exists(),'refused comparison published output')
 same=expected_comparison(before,unchanged);diff=expected_comparison(before,changed)
 invoke('unchanged-json',[str(paths['unchanged']),'--json'],result=same)
 invoke('changed-json',[str(paths['changed']),'--json'],result=diff)
 invoke('unchanged-human',[str(paths['before'])],human=True)
 invoke('malformed-refused',[str(paths['malformed']),'--json','--output',str(invalid)],2)
 invoke('unsupported-refused',[str(paths['unsupported']),'--json','--output',str(invalid)],2)
 invoke('existing-output-refused',[str(paths['changed']),'--output',str(paths['existing'])],2)
 invoke('input-output-alias-refused',[str(paths['changed']),'--output',str(paths['before'])],2)
 invoke('private-output',[str(paths['changed']),'--json','--output',str(created)],result=diff)
 created_info=created.lstat();need(stat.S_ISREG(created_info.st_mode)and stat.S_IMODE(created_info.st_mode)==0o600 and created_info.st_uid==owner.st_uid and created_info.st_gid==owner.st_gid and json.loads(created.read_text())==diff,'installed comparison private output differs');created_pin=identity(created)
 invoke('symlink-input-refused',[str(paths['link']),'--json'],2)
 for name,key,expected,result in [('guarded-unchanged','unchanged',0,same),('guarded-changed','changed',0,diff),('guarded-malformed','malformed',2,None)]:
  raw=user(home,['/usr/bin/python3','-I','-B',str(RUNNER),'--guarded',payload_sha,'--compare',str(paths['before']),str(paths[key]),'--json'])
  guard=json.loads(raw);need(guard==dict(status='PASS_GUARDED_INSTALLED_CODE',mode='INSTALLED_CODE_LOADER_NOT_DIRECT_EXEC',installed_path=str(INSTALLED),installed_sha256=payload_sha,returncode=expected,stdout=guard.get('stdout'),stderr=guard.get('stderr'),forbidden_calls=0,guards=list(GUARD_NAMES),audit_events=list(AUDIT_EVENTS)),'closed installed guard proof differs')
  if result is None:need(guard['stdout']==''and guard['stderr']=='Comparison refused: use bounded ordinary schema-1 doctor reports from supported versions and matching known models.\n','guarded refusal differs')
  else:need(json.loads(guard['stdout'])==result and guard['stderr']=='','guarded installed JSON differs')
  cases.append(dict(case=name,mode=guard['mode'],returncode=expected,stdout_sha256=hashlib.sha256(guard['stdout'].encode()).hexdigest(),forbidden_calls=0))
 need(tuple(r['case']for r in cases)==CASE_NAMES,'finite installed comparison case sequence differs')
 need({key:identity(path)for key,path in paths.items()}==pins and identity(created)==created_pin,'comparison input/output identities changed');need(sha(INSTALLED)==payload_sha,'installed executable changed during comparison')
 return dict(phase=label,home=home.name,status='PASS_INSTALLED_COMPARISON_SYNTHETIC_REPORT_INPUTS',fixture_scope='SYNTHETIC_SUPPLIED_REPORTS_NOT_COLLECTED_OBSERVATIONS',installed_path=str(INSTALLED),installed_sha256=payload_sha,
  cases=cases,direct_executable_cases=9,guarded_installed_code_cases=3,input_existing_file_preservation=True,private_output_mode='0600',private_output_preserved=True,
  no_collection_process_network='PASS_GUARDED_INSTALLED_CODE_CASES',comparison_oracle=dict(unchanged_count=43,changed_checks=['audio/default-output','package/linux-asahi'],change_count=2),GUI='NOT_RUN',hardware='NOT_RUN',real_audio='NOT_RUN')

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--guarded',required=True);args,remainder=parser.parse_known_args()
 print(json.dumps(guarded(args.guarded,remainder),sort_keys=True))

# SPDX-License-Identifier: MIT
"""Actual installed CLI, actual module templates, private-user recovery only."""
import importlib.machinery,importlib.util,json,os,shutil,signal,subprocess,sys
from pathlib import Path
NAMES=('fresh-fish','fresh-zsh','recover-activate','recover-remove','recover-edited','recover-template','recover-state','recover-recheck')
MODULES=('fish-bang-bang','fish-autopair','fish-done','zsh-autosuggestions','zsh-syntax-highlighting','zsh-history-substring-search')
def need(ok,why):
 if not ok:raise ValueError(why)
def validate(v):
 need(set(v)=={'status','homes','cases','scope'} and v['status']=='PASS' and set(v['homes'])==set(NAMES) and set(v['cases'])==set(NAMES) and all(x['status']=='PASS'for x in v['cases'].values()),'all eight real-template extension cases required')
 need(v['scope']=='ACTUAL_CLI_SIX_INSTALLED_MODULES_PRIVATE_HOMES_TEMPLATE_DRIFT_USES_OWNED_EXACT_COPY','precise real-module scope required')
 need(all(x['preview_readonly'] and x['preserved'] for x in v['cases'].values()),'preview and private preservation required')
def exercise(cli,templates,root,H):
 loader=importlib.machinery.SourceFileLoader('_actual_setup6',str(cli));spec=importlib.util.spec_from_loader(loader.name,loader);M=importlib.util.module_from_spec(spec);loader.exec_module(M)
 need(tuple(M.MODULES)==MODULES,'all six real module identities required')
 results={};homes={}
 def expired(*_):raise TimeoutError('finite30s real-module recovery case deadline')
 previous=signal.signal(signal.SIGALRM,expired)
 try:
  for name in NAMES:
   signal.setitimer(signal.ITIMER_REAL,30)
   home=root/name;home.mkdir(mode=0o700);homes[name]=True;helper=H.SetupHomes(cli,templates,root)
   if not name.startswith('fresh-'):helper.seed(home)
   sentinel=home/'unrelated';sentinel.write_text('preserved user bytes\n');sentinel.chmod(0o640);original=H.snapshot(home)
   def invoke(op,apply=False,expected=0):
    if expected!=1:return helper.invoke(home,op,MODULES if op=='activate' else (),apply,expected)
    argv=[sys.executable,'-I','-B',str(cli),op,'--home',str(home),'--config-home',str(home/'config'),'--zdotdir',str(home),'--state-dir',str(home/'setup-state'),'--template-root',str(helper.templates)]
    if apply:argv+=['--apply']
    r=subprocess.run(argv,env=dict(PATH='/usr/bin:/bin',HOME=str(home),LANG='C.UTF-8'),cwd=home,capture_output=True,timeout=10)
    need(r.returncode==1 and not r.stdout and 0<len(r.stderr)<65536 and b'retained private edit'not in r.stderr,'bounded refusal without private content required')
    return dict(refusal_exit=1)
 
   def snapshot():return H.snapshot(home)
   def preview():
    before=snapshot();r=invoke('recover',expected=2);need(snapshot()==before,'recovery preview wrote private state');return r
   def crash(op,point):
    code='''import importlib.machinery,importlib.util,os,sys
 from pathlib import Path
 l=importlib.machinery.SourceFileLoader('_owned_setup6_child',sys.argv[1]);s=importlib.util.spec_from_loader(l.name,l);m=importlib.util.module_from_spec(s);l.exec_module(m)
 e=m.Setup(Path(sys.argv[2]),Path(sys.argv[3]),config='config',state='setup-state');old=e.fs.atomic
 point=e.journal_path if sys.argv[4]=='journal' else e.state_path if sys.argv[4]=='state' else e.targets[sys.argv[4]]
 def atomic(path,data,expected,private=False):
  old(path,data,expected,private)
  if path==point:os._exit(71)
 e.fs.atomic=atomic
 e.run(sys.argv[5],m.MODULES,True)
 '''
    code=code.replace('\n ','\n');compile(code,'<owned-interruption-child>','exec')
    env=dict(PATH='/usr/bin:/bin',HOME=str(home),LANG='C.UTF-8',LC_ALL='C.UTF-8',PYTHONDONTWRITEBYTECODE='1')
    row=subprocess.run([sys.executable,'-I','-B','-c',code,str(cli),str(home),str(helper.templates),point,op],env=env,cwd=home,capture_output=True,timeout=10)
    need(row.returncode==71 and len(row.stdout)+len(row.stderr)<65536 and (home/'setup-state/journal.json').is_file(),'owned actual atomic-write interruption required')
   if name.startswith('fresh-'):
    before=snapshot();invoke('activate');need(snapshot()==before,'fresh activation preview changed home');invoke('activate',True);state=json.loads((home/'setup-state/state.json').read_text());need(set(state['components'])==set(MODULES),'fresh all-six activation required')
    before=snapshot();invoke('activate',True);need(snapshot()==before,'fresh repeat changed state')
    shell=name.removeprefix('fresh-');target=helper.paths(home)[shell]
    script=('source '+str(target)+'; printf continued'if shell=='fish'else'source '+str(target)+'; print -n continued')
    row=subprocess.run([shutil.which(shell),*(['--no-config']if shell=='fish'else['-d','-f']),'-c',script],env=dict(PATH='/usr/bin:/bin',HOME=str(home),LANG='C.UTF-8',XDG_CONFIG_HOME=str(home/'config'),ZDOTDIR=str(home)),cwd=home,capture_output=True,timeout=5)
    need(row.returncode==0 and row.stdout==b'continued'and not row.stderr,'actual fresh generated noninteractive caller required');invoke('remove',True)
    need(not any(p.exists()for p in helper.paths(home).values()),'fresh removal must restore absent startup files')
   elif name=='recover-template':
    owned=home/'real-template-copy';owned.mkdir()
    for component in MODULES:shutil.copytree(templates/component,owned/component)
    crash('activate','journal');helper.templates=owned;before=snapshot()
    invoke('recover',expected=1);invoke('recover',True,1);need(snapshot()==before,'template drift discarded journal or user state')
   else:
    if name=='recover-remove':invoke('activate',True)
    crash('remove'if name=='recover-remove'else'activate','state'if name=='recover-state'else'journal'if name=='recover-recheck'else'fish')
    report=preview();need({a['component']for a in report['actions']}==set(MODULES),'all six recovery action identities required')
    if name in ('recover-edited','recover-recheck'):
     p=helper.paths(home)['fish'];p.parent.mkdir(parents=True,exist_ok=True);p.write_text('# retained private edit\n');before=snapshot();invoke('recover',True,1);need(snapshot()==before,'edited target/journal not preserved')
    else:
     invoke('recover',True);need(not(home/'setup-state/journal.json').exists(),'recovery journal not retired')
     if name!='recover-remove':invoke('remove',True)
   need(sentinel.read_text()=='preserved user bytes\n'and(sentinel.stat().st_mode&0o777)==0o640,'unrelated private user bytes/mode lost')
   if not name.startswith('fresh-')and name not in('recover-edited','recover-recheck','recover-template'):
    for p in helper.paths(home).values():need(p.read_text()==H.USER_CONFIG and(p.stat().st_mode&0o777)==0o640,'existing user bytes/modes lost')
   results[name]=dict(status='PASS',preview_readonly=True,preserved=True)
 finally:
  signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
 v=dict(status='PASS',scope='ACTUAL_CLI_SIX_INSTALLED_MODULES_PRIVATE_HOMES_TEMPLATE_DRIFT_USES_OWNED_EXACT_COPY',homes=homes,cases=results);validate(v);return v

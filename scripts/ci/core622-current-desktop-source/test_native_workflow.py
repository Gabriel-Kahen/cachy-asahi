#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run literal maintained preactor controls in standalone pinned source exports.

core: all 13 native workflow commands, then fresh607 source preflight.
installer-controller: required root/no-userns inherited controller, without fallback.
installer-suites: explicit local 39+11 shell only; controller remains NOT_RUN.
No native job, package actor, acquisition or hardware acceptance is performed.
"""
import argparse,ast,hashlib,importlib.util,json,os,re,selectors,shlex,signal,stat,subprocess,sys,tempfile,time
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_workflow_factory',HERE/'prepare.py')
F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
CORE_TITLE='Whole622 and original Core source controls before secrets or actors'
CORE_SCRIPT_SHA='21e3cf1f79f3178e8e352d1be74fbc8a177adf80a8cc4f59453328634150c6dc'
INSTALLER_TITLE='Run unchanged installer controls and focused604 controls without actors'
INSTALLER_SHELL_SHA='53b6b312d412510bba535564383ea920feeb2326bb25893689067621c4f0aca5'
ROLES=('expanded604-installer','expanded604-legacy','expanded604-seven','expanded604-fresh600-decisions')
ALIASES=('workflow.yml.in','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml')
EXPECTED=(
 ('core622-code/run622.py',('--source-preflight',)),
 ('core-source/scripts/ci/core-native-lifecycle/entry.py',('source','--source','$GITHUB_WORKSPACE/core-source')),
 ('core-source/scripts/ci/core-native-lifecycle/test_contract.py',()),
 ('core-source/scripts/ci/core-native-lifecycle/test_fixture.py',()),
 ('core-source/scripts/ci/core-native-lifecycle/assemble.py',('--source-only',)),
 ('core51-parent/test_case.py',()),('core51-parent/test_protocol.py',()),
 ('core51-parent/test_emission.py',()),('core51-parent/test_host.py',()),
 ('core51-parent/test_route.py',('--vm-source','$GITHUB_WORKSPACE/vm-source')),
 ('core51-parent/test_sources.py',('--core-source','$GITHUB_WORKSPACE/core-source','--vm-source','$GITHUB_WORKSPACE/vm-source','--kernel-carrier','$GITHUB_WORKSPACE/kernel-inputs')),
 ('core622-code/test_desktop622.py',()),
 ('core622-code/test_bridge622.py',('--core-source','$GITHUB_WORKSPACE/core-source','--vm-source','$GITHUB_WORKSPACE/vm-source','--fresh607-source','$GITHUB_WORKSPACE/fresh607-code')))

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def ordinary(path):
 path=Path(path).absolute();need(path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary canonical source/log path');return path
def variable(name):
 need(os.environ.get(name),'required source role '+name);return ordinary(os.environ[name])
def relative(name):
 need(type(name)is str and name and not name.startswith('/')and '\\'not in name and all(p not in('','.','..')for p in name.split('/')),'ordinary source member');return name
def profile():
 raw=F.read_state(HERE/'profile.json')[0];need(pin(raw)==F.PROFILE,'fixed maintained factory profile');return json.loads(raw)
def identity(value):
 return(value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_uid,value.st_gid,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
def namespace_state(root,wanted):
 root=ordinary(root);need(root.is_dir()and type(wanted)is dict and wanted,'ordinary nonempty complete source role');directories={''};files={};observed={}
 for name,want in wanted.items():
  relative(name);need(type(want)is dict and set(want)=={'bytes','sha256'}and type(want['bytes'])is int and want['bytes']>=0 and type(want['sha256'])is str and re.fullmatch('[a-f0-9]{64}',want['sha256']),'whole pinned source member byte bound')
  directories.update(''if str(parent)=='.'else parent.as_posix()for parent in Path(name).parents)
 for path in(root,*sorted(root.rglob('*'))):
  name=''if path==root else path.relative_to(root).as_posix();info=path.lstat();need(not stat.S_ISLNK(info.st_mode),'no source namespace aliases')
  if stat.S_ISDIR(info.st_mode):observed[name]=(identity(info),tuple(sorted(p.name for p in path.iterdir())))
  else:need(stat.S_ISREG(info.st_mode)and info.st_nlink==1,'ordinary single-link complete source member');files[name]=identity(info)
 need(set(files)==set(wanted)and set(observed)==directories,'closed complete source membership without foreign empty directories');return dict(files=files,directories=observed)
def pinned_member(path,want,before):
 path=ordinary(path);fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  info=os.fstat(fd);need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and info.st_size==want['bytes']and identity(info)==before,'exact pinned source descriptor size/identity');chunks=[];size=0
  while size<=want['bytes']:
   raw=os.read(fd,min(1024**2,want['bytes']-size+1))
   if not raw:break
   chunks.append(raw);size+=len(raw)
  need(size==want['bytes']and identity(info)==identity(os.fstat(fd))==identity(path.lstat()),'whole stable pinned source descriptor/path');value=b''.join(chunks);need(pin(value)==want,'whole pinned source bytes and SHA');return value
 finally:os.close(fd)
def tree_copy(source,target,wanted):
 # Trusted per-file pins bound reads, including the 8,884,232-byte kernel Image.
 # The factory's separate original 8MiB operand policy remains unchanged.
 before=namespace_state(source,wanted);target.mkdir(mode=0o700)
 for name,want in wanted.items():
  raw=pinned_member(source/name,want,before['files'][name])
  out=target/relative(name);out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(raw);out.chmod(0o644)
 need(namespace_state(source,wanted)==before,'late complete pinned source identity/membership check');copied=namespace_state(target,wanted)
 for name,want in wanted.items():pinned_member(target/name,want,copied['files'][name])
 need(namespace_state(target,wanted)==copied,'late complete standalone copy identity/membership check');return len(wanted)
def subset_copy(source,target,wanted):
 need(type(wanted)is dict and wanted,'nonempty closed inherited control-inputs role');target.mkdir(mode=0o700)
 for name,want in wanted.items():
  raw=F.read_state(source/relative(name))[0];need(pin(raw)==want,'exact inherited control-inputs member '+name);out=target/name;out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(raw);out.chmod(0o644)
 need({n:pin(raw)for n,raw in F.tree(target).items()}==wanted,'entire inherited projected fixture role');return len(wanted)
def block(raw,title):
 text=raw.decode();marker='      - name: '+title+'\n';need(text.count(marker)==1,'one exact source-owned workflow step');section=text.split(marker,1)[1].split('\n      - name:',1)[0];anchor='        run: |\n';need(section.count(anchor)==1,'one literal whole shell block');body=section.split(anchor,1)[1];need(all(not line or line.startswith('          ')for line in body.splitlines()),'literal unmodified step indentation');return '\n'.join(line[10:]for line in body.splitlines()if line.startswith('          '))+'\n'
def core_inventory(source):
 raw=(source/ALIASES[0]).read_bytes();need(all((source/name).read_bytes()==raw for name in ALIASES),'both native workflow aliases equal the complete template');script=block(raw,CORE_TITLE);need(pin(script.encode())['sha256']==CORE_SCRIPT_SHA,'known complete 13-command step pin');lines=script.splitlines();need(lines[0]=='set -euo pipefail'and len(lines)==14,'all and only the literal thirteen commands');inventory=[]
 for number,(line,(name,args))in enumerate(zip(lines[1:],EXPECTED)):
  tokens=shlex.split(line);prefix=[]
  while tokens and tokens[0]!='python3':prefix.append(tokens.pop(0))
  need(tokens==['python3','-I','-B','$GITHUB_WORKSPACE/'+name,*args],'exact entire native source command '+str(number+1));wanted=['CORE622_CORE_SOURCE=$GITHUB_WORKSPACE/core-source','CORE622_PARENT51=$GITHUB_WORKSPACE/core51-parent']if number==11 else [];need(prefix==wanted,'exact per-command environment operands');inventory.append(dict(number=number+1,script=name,args=list(args),environment=prefix,literal=line))
 fresh='python3 -I -B fresh607-code/implementation/run.py --source-preflight';need(raw.decode().splitlines().count('          '+fresh)==1,'one literal inherited fresh607 source-preflight command');return script,inventory,fresh,dict(template=pin(raw),step=pin(script.encode()),aliases=list(ALIASES),commands=13)
def clean_env(workspace):
 home=workspace/'home';home.mkdir(mode=0o700);tmp=workspace/'tmp';tmp.mkdir(mode=0o700);binary=workspace/'bin';binary.mkdir(mode=0o700);(binary/'python3').symlink_to(Path(sys.executable).resolve())
 return dict(PATH=str(binary)+':/usr/bin:/bin',HOME=str(home),TMPDIR=str(tmp),LANG='C',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1',PYTHONNOUSERSITE='1',GITHUB_WORKSPACE=str(workspace))
def execute(argv,workspace,env,logs,label,timeout):
 started=time.monotonic();stdout_path=logs/(label+'.stdout');stderr_path=logs/(label+'.stderr');counts={'stdout':0,'stderr':0};error=None;process=None;absent=False;limit=16*1024**2
 with stdout_path.open('xb')as out,stderr_path.open('xb')as err:
  output={'stdout':out,'stderr':err};selector=selectors.DefaultSelector()
  try:
   process=subprocess.Popen(argv,cwd=workspace,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
   for name,stream in(('stdout',process.stdout),('stderr',process.stderr)):os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,name)
   while selector.get_map():
    need(time.monotonic()-started<timeout,'whole source-control command timeout')
    for key,_ in selector.select(.1):
     raw=os.read(key.fd,65536)
     if not raw:selector.unregister(key.fileobj);continue
     counts[key.data]+=len(raw);need(sum(counts.values())<=limit,'bounded combined source-control output');output[key.data].write(raw)
   process.wait(timeout=max(.01,timeout-(time.monotonic()-started)))
  except Exception as failure:error=type(failure).__name__+': '+str(failure)
  finally:
   selector.close()
   if process is not None:
    if process.poll()is None:
     try:os.killpg(process.pid,signal.SIGTERM)
     except ProcessLookupError:pass
     try:process.wait(timeout=5)
     except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)
    try:os.killpg(process.pid,0)
    except ProcessLookupError:absent=True
    else:
     try:os.killpg(process.pid,signal.SIGKILL)
     except ProcessLookupError:pass
     error=error or 'source-control process group did not retire naturally'
    process.stdout.close();process.stderr.close()
 stdout=stdout_path.read_bytes();stderr=stderr_path.read_bytes();record=dict(argv=argv,returncode=None if process is None else process.returncode,seconds=round(time.monotonic()-started,6),seconds_limit=timeout,group_absent=absent,error=error,stdout=dict(file=stdout_path.name,**pin(stdout)),stderr=dict(file=stderr_path.name,**pin(stderr)))
 return record,stdout,stderr
def checked_run(receipt,argv,workspace,env,logs,label,timeout):
 record,out,err=execute(argv,workspace,env,logs,label,timeout);receipt['runs'].append(record);need(record['returncode']==0 and record['group_absent']and record['error']is None,'complete source-control command failed: '+label);return out,err
def core(workspace,env,logs,receipt,context):
 roots={name:variable('CORE622_'+name.upper())for name in('parent','fresh607','core_record','fresh_record')};p=profile();emitted=workspace/'core622-code';factory=F.emit(roots,emitted,context);expected=F.tree(variable('CORE622_EXPECTED'));need(F.tree(emitted)==expected,'entire emitted66 equals expected pinned current source');need(len(expected)==66,'complete current66 source');source_profile=json.loads((emitted/'profile.json').read_bytes());roles={}
 for role,source,wanted in(('core51-parent',roots['parent'],p['inputs']['parent']['files']),('fresh607-code',roots['fresh607'],p['inputs']['fresh607']['files']),('core-source',variable('CORE622_CORE_SOURCE'),source_profile['source_profiles']['core800']['files']),('vm-source',variable('CORE622_VM_SOURCE'),source_profile['source_profiles']['ksm637']['files']),('kernel-inputs',variable('CORE622_KERNEL_CARRIER'),source_profile['source_profiles']['kernel_carrier']['files'])):roles[role]=tree_copy(source,workspace/role,wanted)
 roles['core622-code']=66;script,inventory,fresh,workflow=core_inventory(emitted);receipt.update(roles=roles,factory=factory,workflow=workflow,inventory=inventory)
 # Execute the entire original literal script, including its set -euo pipefail.
 _,stderr=checked_run(receipt,['/bin/bash','--noprofile','--norc','-x','-c',script],workspace,env,logs,'core-thirteen',900)
 actual=[shlex.split(line[2:])for line in stderr.decode().splitlines()if line.startswith('+ python3 ')]
 wanted=[['python3','-I','-B',str(workspace/name),*[arg.replace('$GITHUB_WORKSPACE',str(workspace))for arg in arguments]]for name,arguments in EXPECTED]
 need(actual==wanted,'each of all13 literal commands executed exactly once in source order');receipt['executed_argv']=actual
 lines=stderr.decode().splitlines();last=max(number for number,line in enumerate(lines)if line.startswith('+ python3 '));bridge_output='\n'.join(lines[last+1:]);bridge_counts=[int(n)for n in re.findall(r'^Ran (\d+) tests?\b',bridge_output,re.M)]
 need(bridge_counts==[43],'exactly one complete Ran 43 tests summary from the final literal bridge command');receipt['bridge_tests']=43
 receipt['completed_native_workflow_commands']=13
 checked_run(receipt,['/bin/bash','--noprofile','--norc','-euo','pipefail','-c',fresh],workspace,env,logs,'fresh607-source-preflight',300)
 receipt['fresh607_source_preflight']='PASS';receipt['privileged_installer_controller']='NOT_RUN_SEPARATE_REQUIRED_SCOPE'
def installer(workspace,env,logs,receipt,scope,source_workspace):
 p=profile();fresh=variable('CORE622_FRESH607');tree_copy(fresh,workspace/'fresh607-code',p['inputs']['fresh607']['files']);implementation=workspace/'fresh607-code/implementation';text=(implementation/'source_controls.py').read_bytes();constants={}
 for node in ast.parse(text).body:
  if isinstance(node,ast.Assign)and isinstance(node.targets[0],ast.Name)and node.targets[0].id in('TITLE','SHELL','ROLES'):constants[node.targets[0].id]=ast.literal_eval(node.value)
 need(constants.get('TITLE')==INSTALLER_TITLE and constants.get('ROLES')==ROLES and pin(constants['SHELL'].encode())['sha256']==INSTALLER_SHELL_SHA,'entire held installer controller SHELL/TITLE/four roles');wanted=json.loads((implementation/'control-inputs.json').read_bytes());need(set(wanted)==set(ROLES),'all four exact inherited fixture roles');counts={}
 for role in ROLES:
  key='CORE622_CONTROL_'+role.upper().replace('-','_');source=variable(key)if os.environ.get(key)else ordinary(source_workspace)/role;counts[role]=subset_copy(source,workspace/role,wanted[role])
 inherited=(workspace/'expanded604-installer/.github/workflows/native-arm-expanded604-apps6-public-pair-installer.yml').read_bytes();need(block(inherited,INSTALLER_TITLE)==constants['SHELL'],'entire literal inherited39+11 source step');receipt.update(control_inputs=pin((implementation/'control-inputs.json').read_bytes()),controller=pin(text),shell=pin(constants['SHELL'].encode()),fixture_members=counts)
 env.update(EXPANDED600_LEGACY_ROOT=str(workspace/ROLES[1]),EXPANDED600_SEVEN_ROOT=str(workspace/ROLES[2]),CURRENT604_INSTALLER_SOURCE=str(workspace/ROLES[0]),PUBLIC_PAIR_INSTALLER_ROOT=str(workspace/ROLES[0]),PUBLIC_PAIR_COMPOSITION_ROOT=str(workspace/ROLES[0]),EXPANDED604_SOURCE=str(workspace/ROLES[0]),EXPANDED604_LEGACY_ROOT=str(workspace/ROLES[1]),EXPANDED604_FRESH600_DECISION=str(workspace/ROLES[3]/'payload/fresh600.json'))
 if scope=='installer-suites':
  need(os.environ.get('GITHUB_ACTIONS')!='true','CI requires installer-controller; explicit suites-only scope is local');receipt['privileged_installer_controller']='NOT_RUN_EXPLICIT_LOCAL_SUITE_ONLY';receipt['private_tmpfs_capacity']='NOT_ESTABLISHED'
  _,stderr=checked_run(receipt,['/bin/bash','--noprofile','--norc','-e','-o','pipefail','-c',constants['SHELL']],workspace,env,logs,'installer-suites-only',120)
 else:
  receipt['privileged_installer_controller']='NOT_PASSED';argv=[sys.executable,'-I','-B',str(implementation/'source_controls.py'),'--workspace',str(workspace)]
  if os.getuid()!=0 or os.geteuid()!=0:argv=['/usr/bin/sudo','-n','--',*argv]
  stdout,stderr=checked_run(receipt,argv,workspace,env,logs,'installer-controller',150);lines=stdout.splitlines();need(lines,'actual controller result required');value=json.loads(lines[-1]);need(value['status']=='PASS_EXACT_PRIVATE_39_AND11_SOURCE_CONTROLS'and value['capacity']=='TMPFS_128MiB_16384_INODES'and value['cleanup']=='CHILD_REAPED_PRIVATE_MOUNT_GONE_HOST_EMPTY'and value['python']==sys.version.split()[0],'entire genuine inherited controller success, selected interpreter and cleanup');receipt['privileged_installer_controller']='PASS_EXACT_INHERITED_CONTROLLER';receipt['controller_result']=value
 need([int(n)for n in re.findall(rb'Ran (\d+) tests?',stderr)]==[39,11],'all and only unchanged39+11 nonzero suites');receipt['suite_counts']=[39,11]
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--scope',choices=('core','installer-suites','installer-controller'),default='core');parser.add_argument('--context',choices=('known','null'),default='known');parser.add_argument('--output-dir',type=Path);parser.add_argument('--installer-workspace',type=Path,help='existing four pinned fixture-role directories; per-role CORE622_CONTROL_* overrides supported');args=parser.parse_args();receipt=dict(scope=args.scope,context=args.context,status='FAIL',runs=[],native='NOT_RUN',hardware='NOT_RUN',acceptance=False,acquisition='NOT_RUN')
 output=None
 if args.output_dir:
  output=ordinary(args.output_dir);need(output.parent.is_dir()and not output.exists(),'fresh ordinary receipt directory');output.mkdir(mode=0o700)
 try:
  with tempfile.TemporaryDirectory(prefix='core622-workflow-controls-',dir='/tmp')as directory:
   workspace=Path(directory);need(not any((p/'manifests/packages.toml').is_file()for p in workspace.parents),'standalone workspace outside repository');logs=output or workspace/'logs';logs.mkdir(mode=0o700,exist_ok=output is not None);env=clean_env(workspace);receipt['python']=dict(executable=sys.executable,version=sys.version);receipt['logs_retained']=output is not None
   if args.scope=='core':core(workspace,env,logs,receipt,args.context)
   else:
    source=args.installer_workspace or os.environ.get('CORE622_INSTALLER_WORKSPACE')or os.environ.get('GITHUB_WORKSPACE');need(source or all(os.environ.get('CORE622_CONTROL_'+r.upper().replace('-','_'))for r in ROLES),'explicit four-role installer fixture workspace or all per-role overrides');installer(workspace,env,logs,receipt,args.scope,source)
   receipt['status']='PASS_SOURCE_CONTROLS_ONLY'
 except Exception as error:receipt['error_type']=type(error).__name__;receipt['error']=str(error)
 if output:(output/'receipt.json').write_bytes(encoded(receipt))
 sys.stdout.buffer.write(encoded(receipt));return 0 if receipt['status']=='PASS_SOURCE_CONTROLS_ONLY'else 1

if __name__=='__main__':raise SystemExit(main())

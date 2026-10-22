# SPDX-License-Identifier: MIT
"""Counted derivatives of the complete pinned finite owner; no original files edited."""
import ast,hashlib,json,os,stat,sys,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
OLD='scripts/ci/apps-cache-native/'

def read(source,name):
 pins=json.loads((HERE/'original-pins.json').read_bytes());path=source/name;row=pins[name]
 if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('original source alias')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode)or before.st_nlink!=1 or before.st_size!=row['bytes']:raise ValueError('original source type/size')
  with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(row['bytes']+1)
  after=os.fstat(fd)
  if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('original source drift')
 finally:os.close(fd)
 if len(raw)!=row['bytes']or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise ValueError('original source hash: '+name)
 return raw.decode()

def replace(text,old,new):
 if text.count(old)!=1:raise ValueError('one exact source seam required: '+old[:100])
 return text.replace(old,new)

def function(text,name,body):
 node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name==name)
 lines=text.splitlines(keepends=True);lines[node.lineno-1:node.end_lineno]=[body];return ''.join(lines)

def text(source,name):
 raw=read(source,OLD+name)
 if name=='contract.py':
  raw=replace(raw,"ROLES={'runtime':'cachy-asahi-repository-runtime','apps':'cachy-asahi-apps','cache':'cachy-asahi-cache'}","ROLES={'runtime':'cachy-asahi-repository-runtime','apps':'cachy-asahi-apps','client':'cachy-asahi-repository-client-v2'}")
  raw=replace(raw,"LABEL='org.cachy-asahi.apps-cache-native.job'","LABEL='org.cachy-asahi.apps14-client-native.job'")
  raw=replace(raw,"root=source/'packages/tools'/name","root=recipe_directory(source,name)")
  # Two distinct uses: recipe inspection and mandatory check() source.
  for anchor,new in (("checks.recipe(source/'packages/tools'/name/'PKGBUILD')","checks.recipe(recipe_directory(source,name)/'PKGBUILD')"),("(source/'packages/tools'/name/'PKGBUILD').read_text()","(recipe_directory(source,name)/'PKGBUILD').read_text()"),("digest(source/'packages/tools'/name/original)","digest(recipe_directory(source,name)/original)")):
   raw=replace(raw,anchor,new)
  raw=replace(raw,"if name==ROLES['cache']:need(meta.get('depends')==['python>=3.11','pacman'],'final ctypes Cache dependency set differs')","if name==ROLES['client']:need(meta.get('depends')==['python>=3.11','cachy-asahi-repository-runtime=0.1.0-1'],'exact companion Runtime1 dependency required')")
  raw=replace(raw,"    return value\n\n\ndef verify_source", "    need(value.get('purpose')=='APPS14_AND_OPT_IN_CLIENT_V2_NATIVE' and {role:r['version'] for role,r in value['products'].items()}=={'runtime':'0.1.0-1','apps':'0.1.0-14','client':'0.1.0-1'},'exact distinct new product identities required')\n    return value\n\n\ndef verify_source")
  raw=replace(raw,"    return dict(status='PASS_CHECK_EXIT_NO_SKIPS',","    if name==ROLES['apps']:need(len(re.findall(r'^Ran 45 tests in [0-9.]+s$',text,re.M))==1 and len(re.findall(r'^Ran 24 tests in [0-9.]+s$',text,re.M))==1 and len(re.findall(r'^Ran 8 tests in [0-9.]+s$',text,re.M))==1 and re.findall(r'^Ran ([0-9]+) tests? in ',text,re.M)==['45','24','8'] and len(re.findall(r'^Ran [0-9]+ tests? in ',text,re.M))==3 and len(re.findall(r'^OK$',text,re.M))==3 and not re.search(r'^FAILED|^ERROR:|^FAIL:',text,re.M),'complete original45, inventory24 and optional-stage8 native suites required')\n    return dict(status='PASS_CHECK_EXIT_NO_SKIPS',")
  raw=function(raw,'validate_lifecycle',"def validate_lifecycle(value):\n from rules import validate\n from types import SimpleNamespace\n return validate(SimpleNamespace(need=need,re=re,ROLES=ROLES),value)\n")
  raw+="\ndef recipe_directory(source,name):\n need(name in NAMES,'explicit finite recipe role')\n return source/'packages/tools'/('cachy-asahi-apps14' if name==ROLES['apps'] else name)\n"
 elif name=='run.py':
  raw=replace(raw,'import contract as C\n','import contract as C\nimport adapter as A\n')
  raw=replace(raw,"shared=C.load('apps_cache_shared_builder',source/'scripts/ci/welcome-native/run.py');shared.C=C","shared=A.builder(source);shared.C=C")
  start="    def runner_context(context):\n        runner=context/'runner';runner.mkdir()\n        for name in ('contract.py','input-policy.json','installed.py','runtime_image.py','lifecycle.py'):shutil.copyfile(C.HERE/name,runner/name)\n        accepted=runner/'accepted';accepted.mkdir()\n        shutil.copyfile(source/'scripts/ci/welcome-native/lifecycle.py',accepted/'lifecycle.py')\n        shutil.copyfile(source/'scripts/ci/full-root-upgrade/root_upgrade.py',accepted/'root_upgrade.py')\n        return runner\n"
  raw=replace(raw,start,"    def runner_context(context):return A.runner(source,context)\n")
  raw=replace(raw,"for name in (C.ROLES['runtime'],C.ROLES['cache'])","for name in (C.ROLES['runtime'],)")
  raw=replace(raw,"for r in C.recipe(source,C.ROLES['apps'])['metadata'].get(k,[])","for name in (C.ROLES['apps'],C.ROLES['client']) for r in C.recipe(source,name)['metadata'].get(k,[])")
  raw=replace(raw,"products[C.ROLES['cache']]=build_pair(C.ROLES['cache'],image,base,lock,base_actors)","products[C.ROLES['client']]=build_pair(C.ROLES['client'],runtime_image,runtime_base,runtime_lock,apps_actors)")
  raw=replace(raw,"f'type=bind,src={C.HERE}/catalog_fixture.py,dst=/catalog_fixture.py,readonly'","f'type=bind,src={source}/scripts/ci/apps-cache-native/catalog_fixture.py,dst=/catalog_fixture.py,readonly'")
  raw=replace(raw,"scope='THREE_UNSELECTED_APPS_RUNTIME_CACHE_CANDIDATES'","scope='APPS14_CLIENT_V2_AND_REBUILT_RUNTIME1_NATIVE_ONLY'")
  raw=replace(raw,"report.update(status='PASS_NATIVE_APPS_RUNTIME_CACHE_PAIRS_AND_INSTALLED_LIFECYCLE',lifecycle=lifecycle,cache_cleanup='APPLIED_DISPOSABLE_FIXTURES_ONLY'","report.update(status='PASS_NATIVE_APPS14_CLIENT_V2_PAIRS_AND_INSTALLED_LIFECYCLE',lifecycle=lifecycle,cache_cleanup='NOT_RUN'")
 elif name=='lifecycle.py':
  raw=replace(raw,'import installed as I\n','import installed as I\nimport installed_checks as N\n')
  start=raw.index('            # Only this disposable user-owned conventional target');end=raw.index('            observations.append(',start)
  raw=raw[:start]+"            extra=N.observe(home,session,phase,work,user,L)\n"+raw[end:]
  start=raw.index('            observations.append(');end=raw.index('        preserve();events.append',start)
  raw=raw[:start]+"            observations.append(dict(home=home.name,apps_commands=commands,default_helpers='PASS_INSTALLED_EXACT_THREE',signed_catalog='PASS_NOT_APPLIED',inventory_collector='PASS_READONLY_OBSERVED_ALPM9',inventory_observation=collected,real_database_inventory='PASS_EXACT577_OBSERVED_METADATA_RAW_HASHES_PRESERVED',plan_inventory_source='OBSERVED_SYNTHETIC_ALPM9_FIXTURE',**extra))\n"+raw[end:]
  raw=replace(raw,"installed_default_helpers='PASS',signed_catalog='PASS_NOT_APPLIED',cache_plan_verify='PASS_NOT_APPLIED',cache_apply='PASS_REAL_ALPM16_EMPTY_TRANSACTION',","installed_default_helpers='PASS',signed_catalog='PASS_NOT_APPLIED',")
  # Reverse topological order is explicit: opt-in leaf, Apps, then shared Runtime.
  if raw.count("pacman+['-R',*selected]")!=2:raise ValueError('exact two removal transitions')
  raw=raw.replace("pacman+['-R',*selected]","pacman+['-R',*[C.ROLES[k] for k in ('client','apps','runtime')]]")
  raw=replace(raw,"status='PASS_APPS_CACHE_INSTALLED_LIFECYCLE'","status='PASS_APPS14_CLIENT_V2_INSTALLED_LIFECYCLE'")
  raw=replace(raw,"cache_cleanup='APPLIED_DISPOSABLE_FIXTURES_ONLY',cache_apply='PASS_REAL_ALPM16_EMPTY_TRANSACTION'","cache_cleanup='NOT_RUN',client_v2='PASS_INSTALLED_SIGNED_TILDE_READONLY',apps14_inventory='PASS_INSTALLED_15_CONTROLS'")
  raw=replace(raw,"architecture=os.uname().machine,page_size=os.sysconf('SC_PAGE_SIZE')","architecture=os.uname().machine,page_size=os.sysconf('SC_PAGE_SIZE'),removal_order=[C.ROLES[k] for k in ('client','apps','runtime')]")
 elif name=='job.py':
  raw=replace(raw,"    C.policy();C.verify_source(source);manifest=C.read(C.HERE/'source-manifest.json')\n","    C.policy();C.verify_source(source);manifest=C.read(C.HERE/'source-manifest.json')\n    C.need(manifest.get('workflow_path')=='.github/workflows/native-arm-build.yml' and manifest.get('workflow_ref')=='refs/heads/codex/apps14-pair-native-v1' and manifest.get('repository')=='Gabriel-Kahen/cachy-asahi','exact registered Apps14 workflow context required')\n    C.need(environment.get('GITHUB_REPOSITORY')==manifest['repository'] and environment.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and environment.get('GITHUB_REF')==manifest['workflow_ref'] and environment.get('GITHUB_WORKFLOW_REF')==manifest['repository']+'/'+manifest['workflow_path']+'@'+manifest['workflow_ref'] and environment.get('GITHUB_WORKFLOW')=='native-arm-apps14-client' and environment.get('GITHUB_JOB')=='native','registered Apps14 repository/ref/workflow/job identity required')\n    template=(C.HERE/'workflow.yml').read_text().replace('@JOB_SHA256@',C.digest(C.HERE/'job.py')).replace('@MANIFEST_SHA256@',C.digest(C.HERE/'source-manifest.json'))\n    for path in (manifest['workflow_path'],'.github/workflows/native-arm-apps14-client.yml'):C.checked(source,path,dict(bytes=len(template.encode()),sha256=hashlib.sha256(template.encode()).hexdigest()))\n")
  raw=replace(raw,"(source/'packages/tools'/name).iterdir()","C.recipe_directory(source,name).iterdir()")
  raw=replace(raw,"report['status']=='PASS_NATIVE_APPS_RUNTIME_CACHE_PAIRS_AND_INSTALLED_LIFECYCLE'","report['status']=='PASS_NATIVE_APPS14_CLIENT_V2_PAIRS_AND_INSTALLED_LIFECYCLE'")
  raw=replace(raw,"[('base-consumers',8),('apps-consumers',2)]","[('base-consumers',6),('apps-consumers',4)]")
  raw=replace(raw,"status='PASS_NATIVE_UNSELECTED_APPS_RUNTIME_CACHE_CANDIDATES',cache_cleanup='APPLIED_DISPOSABLE_FIXTURES_ONLY',cache_apply='PASS_REAL_ALPM16_EMPTY_TRANSACTION'","status='PASS_NATIVE_APPS14_AND_CLIENT_V2_CANDIDATES',cache_cleanup='NOT_RUN',client_v2='PASS_INSTALLED_SIGNED_TILDE_READONLY'")
  raw=replace(raw,"'PASS_NATIVE_UNSELECTED_APPS_RUNTIME_CACHE_CANDIDATES'","'PASS_NATIVE_APPS14_AND_CLIENT_V2_CANDIDATES'")
  # Retain the exact counted runner and fixture source derivatives as ordinary data.
  marker="    try:\n        C.verify_source(source);report=C.read(runtime/'report.json');C.validate_lifecycle(report['lifecycle'])\n"
  extra="    for name in ('contract.py','lifecycle.py','installed_checks.py','rules.py','fixture_checks.py'):\n        copy(runtime/'lifecycle-inputs/runner'/name,'emitted/'+name,2*1024**2)\n    copy(runtime/'lifecycle-inputs/runner-derivations.json','runner-derivations.json',65536)\n"
  raw=replace(raw,marker,extra+marker)
 return raw

def module(source,name):
 m=types.ModuleType('apps14_client_'+name.replace('.','_'));m.__file__=str(HERE/name);sys.modules[m.__name__]=m
 exec(compile(text(source,name),m.__file__,'exec'),m.__dict__);return m

def builder(source):
 raw=read(source,'scripts/ci/welcome-native/run.py');raw=replace(raw,"shutil.copytree(source/'packages/tools'/name,inputs)","shutil.copytree(C.recipe_directory(source,name),inputs)")
 m=types.ModuleType('apps14_client_original_builder');m.__file__=str(source/'scripts/ci/welcome-native/run.py');sys.modules[m.__name__]=m;exec(compile(raw,m.__file__,'exec'),m.__dict__);return m

def runner(source,context):
 import shutil
 runner=context/'runner';runner.mkdir();accepted=runner/'accepted';accepted.mkdir()
 for name in ('contract.py','lifecycle.py'):(runner/name).write_text(text(source,name))
 for name in ('installed.py','runtime_image.py','rules.py','installed_checks.py','fixture_checks.py','input-policy.json'):shutil.copyfile(HERE/name,runner/name)
 for name,original in [('lifecycle.py','scripts/ci/welcome-native/lifecycle.py'),('root_upgrade.py','scripts/ci/full-root-upgrade/root_upgrade.py')]:shutil.copyfile(source/original,accepted/name)
 fixtures={'apps':('packages/tools/cachy-asahi-apps14',('test_apps.py','apps.py','inventory.py','helper-pins.json','test_diagnostic_stage.py')),'client':('packages/tools/cachy-asahi-repository-client-v2',('test_client_v2.py','client_v2.py','test_runtime.py'))}
 for role,(directory,names)in fixtures.items():
  target=runner/('fixture-'+role);target.mkdir()
  for name in names:shutil.copyfile(source/directory/name,target/name)
 rows={p.relative_to(runner).as_posix():dict(bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in sorted(runner.rglob('*'))if p.is_file()}
 (context/'runner-derivations.json').write_text(json.dumps(dict(status='SOURCE_CLOSED_COUNTED_DERIVATIVES',files=rows,original_pins=json.loads((HERE/'original-pins.json').read_bytes())),sort_keys=True,indent=2)+'\n')
 return runner

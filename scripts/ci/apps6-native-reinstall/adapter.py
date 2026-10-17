# SPDX-License-Identifier: MIT
"""Exact source-pinned finite Apps6 adapters; original actors and cleanup unchanged."""
import hashlib,importlib.util,json,os,stat,sys,types
from pathlib import Path
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file())
HERE=Path(__file__).resolve().parent
ORIGINAL='scripts/ci/apps-cache-native/'
PINS={'contract.py': {'bytes': 11912, 'sha256': '16c68aa997dc018c568178f7a270938b164bec6721729be1231432ef96b280c4'}, 'run.py': {'bytes': 15349, 'sha256': 'd3cdf95b0757e1f2ebd04cb8bc56f90888ff8c17f615e9ca6e65357c4462b56e'}, 'job.py': {'bytes': 13236, 'sha256': '9a88aa45a16a5a6056d719828a1bae8b04a3cb3b32a2768b5aecb8167ef2adda'}, 'lifecycle.py': {'bytes': 16624, 'sha256': '971cd386da65cbe247e93f4fbbc6ce6a6c6f9e77aadbc6f6b1df6d39c049e45c'}, 'installed.py': {'bytes': 4441, 'sha256': '10d210905f770854ddf9ebb72b46002d414787aa0a878a498ba4b21b663d9d8e'}, 'runtime_image.py': {'bytes': 2057, 'sha256': 'a682b64a5326fc7edf0d2347c37ae50805f9b7773c2683f1fbae1769c18fa023'}, 'catalog_fixture.py': {'bytes': 3333, 'sha256': '0314733b88cc73f9813e488eff55bea8833e6b196d876d5a40fa7507e3ddc071'}}
def read(source,name):
 p=source/(ORIGINAL+name);row=PINS[name]
 if any(parent.is_symlink() for parent in p.parents):raise ValueError('original source alias refused')
 fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size!=row['bytes']:raise ValueError('original source size/type differs')
  with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(row['bytes']+1)
  after=os.fstat(fd)
  if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('original source drift')
 finally:os.close(fd)
 if len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise ValueError('Apps6 original source differs: '+name)
 return raw

def replace(text,old,new):
 if text.count(old)!=1:raise ValueError('Apps6 exact adapter anchor differs')
 return text.replace(old,new)

def original_contract(source):
 return module(source,'contract.py',adapt=False)

def text(source,name):
 raw=read(source,name).decode()
 if name=='run.py':
  read(source,'catalog_fixture.py')
  raw=replace(raw,'import contract as C\n','import contract as C\nimport adapter as A\n')
  raw=replace(raw,"f'type=bind,src={C.HERE}/catalog_fixture.py,dst=/catalog_fixture.py,readonly'","f'type=bind,src={source}/scripts/ci/apps-cache-native/catalog_fixture.py,dst=/catalog_fixture.py,readonly'")
  start="    def runner_context(context):\n        runner=context/'runner';runner.mkdir()\n        for name in ('contract.py','input-policy.json','installed.py','runtime_image.py','lifecycle.py'):shutil.copyfile(C.HERE/name,runner/name)\n        accepted=runner/'accepted';accepted.mkdir()\n        shutil.copyfile(source/'scripts/ci/welcome-native/lifecycle.py',accepted/'lifecycle.py')\n        shutil.copyfile(source/'scripts/ci/full-root-upgrade/root_upgrade.py',accepted/'root_upgrade.py')\n        return runner\n"
  raw=replace(raw,start,"    def runner_context(context):return A.runner(source,context)\n")
  raw=replace(raw,"        shutil.copytree(out/'catalog-fixture',life/'catalog-fixture',symlinks=True);public_tree(life)\n","        shutil.copytree(out/'catalog-fixture',life/'catalog-fixture',symlinks=True)\n        A.prepare_repair(source,life,out);public_tree(life)\n")
  raw=replace(raw,"report.update(status='PASS_NATIVE_APPS_RUNTIME_CACHE_PAIRS_AND_INSTALLED_LIFECYCLE'","report.update(status='PASS_NATIVE_APPS6_PAIRS_INSTALLED_AND_SIGNED_REPAIR',repair_plans_applied='APPLIED_DISPOSABLE_SYNTHETIC_COPY_ONLY',plans_applied_scope='INSTALLED_CATALOG_CLI_CASES_ONLY'")
 elif name=='lifecycle.py':
  raw=replace(raw,'import installed as I\n','import installed as I\nimport repair\n')
  raw=replace(raw,"    L.command(pacman+['-U',*archives],timeout=90);installed('install')\n","    L.command(pacman+['-U',*archives],timeout=90);installed('install')\n    repair_result=repair.run();I.payloads(L,products);preserve()\n")
  raw=replace(raw,"    C.validate_lifecycle(value);Path('/out/lifecycle.json').write_text(json.dumps(value,sort_keys=True)+'\\n')\n","    C.validate_lifecycle(value);value.update(status='PASS_APPS6_INSTALLED_LIFECYCLE_AND_SIGNED_REPAIR',repair=repair_result,plans_applied_scope='INSTALLED_CATALOG_CLI_CASES_ONLY')\n    C.validate_lifecycle(value);Path('/out/lifecycle.json').write_text(json.dumps(value,sort_keys=True)+'\\n')\n")
 elif name=='job.py':
  raw=replace(raw,"report['status']=='PASS_NATIVE_APPS_RUNTIME_CACHE_PAIRS_AND_INSTALLED_LIFECYCLE'","report['status']=='PASS_NATIVE_APPS6_PAIRS_INSTALLED_AND_SIGNED_REPAIR'")
  raw=replace(raw,"status='PASS_NATIVE_UNSELECTED_APPS_RUNTIME_CACHE_CANDIDATES'","status='PASS_NATIVE_APPS6_PAIR_AND_SIGNED_REPAIR_CANDIDATE'")
  # Raw original repair outputs are retained even when the native body fails.
  anchor="    try:\n        C.verify_source(source);report=C.read(runtime/'report.json');C.validate_lifecycle(report['lifecycle'])\n"
  extra="""    repair=runtime/'lifecycle-output/repair'
    if repair.exists():
        entries=list(repair.rglob('*'));C.need(len(entries)<=256,'bounded signed repair evidence nodes')
        links={}
        for path in sorted(entries):
            name=path.relative_to(repair).as_posix()
            if path.is_symlink():links[name]=os.readlink(path)
            elif path.is_file():copy(path,'signed-repair/'+name,16*1024**2)
            else:C.need(path.is_dir(),'repair evidence special node refused')
        raw=C.encoded(links);target=output/'signed-repair-links.json';target.write_bytes(raw)
        result['files'][target.name]=dict(bytes=len(raw),sha256=C.digest(target));result['bytes']+=len(raw)
        C.need(len(raw)<=65536 and result['bytes']<=old.MAX_TOTAL,'bounded repair links')
    copy(runtime/'lifecycle-inputs/repair-source.json','repair-source.json',65536,False)
    copy(runtime/'lifecycle-inputs/runner-derivations.json','runner-derivations.json',65536,False)
    for name in ('contract.py','run.py','job.py','lifecycle.py','installed.py','runtime_image.py'):
        copy(source/'scripts/ci/apps-cache-native'/name,'inherited/'+name,1024**2)
    for name in ('contract.py','lifecycle.py','repair.py','rules.py','installed.py','runtime_image.py'):
        copy(runtime/'lifecycle-inputs/runner'/name,'emitted/'+name,1024**2,False)
"""
  raw=replace(raw,anchor,extra+anchor)
  raw=replace(raw,"        C.need(not result['errors'],'closed evidence export incomplete');result.update(","        C.need('signed-repair/native-result.json' in result['files'] and 'runner-derivations.json' in result['files'] and 'repair-source.json' in result['files'],'complete native repair/raw/source derivation receipts required')\n        C.validate_repair(C.read(runtime/'lifecycle.json'))\n        native=C.read(repair/'native-result.json');raw=C.read(repair/'result.json')\n        C.need(native==report['lifecycle']['repair'] and native==dict(raw,native_aarch64='EXECUTED_SIGNED_SYNTHETIC_COPY_ONLY',installed_apps='0.1.0-6',input_source_sha256=C.digest(runtime/'lifecycle-inputs/repair-source.json')),'original/native/lifecycle repair receipts differ')\n        for number,transaction in enumerate(raw['transactions']):\n            C.need(C.read(repair/('worker-'+str(number)+'.stdout'))==transaction and C.digest(repair/('plan-'+str(number)+'.json'))==transaction['plan_sha256'],'original worker/plan repair joins differ')\n        C.need(not result['errors'],'closed evidence export incomplete');result.update(")
 return raw

def module(source,name,adapt=True):
 m=types.ModuleType('apps6_original_'+name.replace('.','_'));m.__file__=str(source/(ORIGINAL+name));sys.modules[m.__name__]=m
 exec(compile(text(source,name) if adapt else read(source,name).decode(),m.__file__,'exec'),m.__dict__);return m

def runner(source,context):
 import shutil
 runner=context/'runner';runner.mkdir();accepted=runner/'accepted';accepted.mkdir()
 for name in ('installed.py','runtime_image.py'):(runner/name).write_bytes(read(source,name))
 raw=read(source,'contract.py').decode()+"\nimport types as _types\nimport rules as _rules\nglobals().update(vars(_rules.bind(_types.SimpleNamespace(**globals()),HERE)))\n"
 (runner/'contract.py').write_text(raw);(runner/'lifecycle.py').write_text(text(source,'lifecycle.py'))
 for name in ('rules.py','repair.py','input-policy.json'):shutil.copyfile(HERE/name,runner/name)
 for name,original in [('lifecycle.py','scripts/ci/welcome-native/lifecycle.py'),('root_upgrade.py','scripts/ci/full-root-upgrade/root_upgrade.py')]:shutil.copyfile(source/original,accepted/name)
 values={name:dict(bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for name,p in sorted((p.relative_to(runner).as_posix(),p) for p in runner.rglob('*') if p.is_file())}
 (context/'runner-derivations.json').write_text(json.dumps(dict(originals=PINS,outputs=values,scope='EXACT_APPS6_DERIVATIVES_ORIGINAL_ACTOR_AND_CLEANUP'),sort_keys=True,indent=2)+'\n')
 return runner

def prepare_repair(source,life,out):
 spec=importlib.util.spec_from_file_location('apps6_repair_prepare',HERE/'repair.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);m.prepare(source,life,out)

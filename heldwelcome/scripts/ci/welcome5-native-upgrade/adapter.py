# SPDX-License-Identifier: MIT
"""Whole-pinned six-consumer owner; exactly two compiled version roles."""
import ast,hashlib,importlib.util,json,shutil,sys,types
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
BASE_SHA='78ee8e094f6c69ea5a1f10639888f86fc81025b7d0f0dd067dd43c3ff04ff898'
raw=(HERE/'base_adapter.py').read_bytes()
if hashlib.sha256(raw).hexdigest()!=BASE_SHA:raise ValueError('held six-consumer source adapter drift')
spec=importlib.util.spec_from_file_location('_welcome5_held_adapter',HERE/'base_adapter.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
one=B.replace;function=B.function

def text(source,name):
 raw=B.text(source,name)
 if name=='contract.py':
  raw=one(raw,"NAMES=('cachy-asahi-dns','cachy-asahi-sysctl')","NAMES=('cachy-asahi-welcome','cachy-asahi-welcome5')\nPACKAGE='cachy-asahi-welcome'")
  raw=one(raw,"LABEL='org.cachy-asahi.dns-sysctl-native.job'","LABEL='org.cachy-asahi.welcome5-upgrade-native.job'")
  raw=function(raw,'files',"def files(name):\n    return S.files(name)\n")
  raw=function(raw,'payload',"def payload(report,source,name):\n    return S.payload(report,source,name)\n")
  raw=function(raw,'check_log',"def check_log(path,name):\n    return S.check_log(path,name)\n")
  raw+='\ndef elf(data,checks):return S.elf(data,checks)\n'
 elif name=='run.py':
  raw=one(raw,"not set(C.NAMES)&base.keys()","C.PACKAGE not in base")
  raw=one(raw,"shared=C.load('accepted_tools_build',source/'scripts/ci/welcome-native/run.py');shared.C=C","shared=A.builder(source,C)")
  raw=one(raw,"payload=row['payload'],tests=row['tests']","payload=row['payload'],elf=row['elf'],tests=row['tests']")
  raw=raw.replace('DNS_SYSCTL_NATIVE_PAIRS_AND_PRIVATE_FIXTURES_ONLY','WELCOME4_TO5_NATIVE_PAIRS_AND_DISPLAYLESS_UPGRADE_ONLY').replace('PASS_NATIVE_DNS_SYSCTL_PAIRS_AND_PRIVATE_LIFECYCLE','PASS_NATIVE_WELCOME5_PAIRS_AND_SIGNED_UPGRADE')
 elif name=='job.py':
  raw=raw.replace('scripts/ci/dns-sysctl-native','scripts/ci/welcome5-native-upgrade').replace('PASS_NATIVE_DNS_SYSCTL_PAIRS_AND_PRIVATE_LIFECYCLE','PASS_NATIVE_WELCOME5_PAIRS_AND_SIGNED_UPGRADE').replace('PASS_NATIVE_DNS_SYSCTL_CANDIDATES_PRIVATE_LIFECYCLE','PASS_NATIVE_WELCOME5_CANDIDATES_SIGNED_UPGRADE')
  raw=one(raw,"basename.startswith(product+'-')","basename.startswith(C.PACKAGE+'-')")
  for before,after in [("name=product+'-'+version+'-any.pkg.tar.'+suffix","name=C.PACKAGE+'-'+version+'-aarch64.pkg.tar.'+suffix"),("expected=product+'-'+C.version(source,product)+'-any.pkg.tar.'","expected=C.PACKAGE+'-'+C.version(source,product)+'-aarch64.pkg.tar.'"),("archive=product+'-'+C.version(source,product)+'-any.pkg.tar.'","archive=C.PACKAGE+'-'+C.version(source,product)+'-aarch64.pkg.tar.'")]:raw=one(raw,before,after)
  raw=one(raw,"{r['container'] for r in ordered['consumer']['containers']}==set(owner['containers'])","[r['container'] for r in ordered['consumer']['containers']]==list(reversed(owner['containers']))")
  raw=one(raw,"        C.need(not result['errors'],'complete closed candidate evidence required')","        from rules import validate_products\n        validate_products(report)\n        C.need(not result['errors'],'complete closed candidate evidence required')")
 return raw

def module(source,name):
 m=types.ModuleType('welcome5_upgrade_'+name.replace('.','_'));m.__file__=str(HERE/name);sys.modules[m.__name__]=m;exec(compile(text(source,name),m.__file__,'exec'),m.__dict__);return m

def builder_text(source):
 raw=B.read(source,'scripts/ci/welcome-native/run.py')
 raw=one(raw,'if name==C.NAME:','if name in C.NAMES:')
 return one(raw,"=='usr/bin/'+name:","=='usr/bin/'+C.PACKAGE:")

def builder(source,contract):
 m=types.ModuleType('welcome5_compiled_builder');m.__file__=str(source/'scripts/ci/welcome-native/run.py');exec(compile(builder_text(source),m.__file__,'exec'),m.__dict__);m.C=contract;return m

def public_tree(path):return B.public_tree(path)
def runner(source,context):
 runner=context/'runner';runner.mkdir();(runner/'accepted').mkdir();(runner/'contract.py').write_text(text(source,'contract.py'))
 for n in('selection.py','rules.py','lifecycle.py','fixture_checks.py','input-policy.json'):shutil.copyfile(HERE/n,runner/n)
 for n,p in [('installed.py','scripts/ci/apps-cache-native/installed.py'),('accepted/lifecycle.py','scripts/ci/welcome-native/lifecycle.py'),('accepted/root_upgrade.py','scripts/ci/full-root-upgrade/root_upgrade.py')]:B.read(source,p);shutil.copyfile(source/p,runner/n)
 rows={p.relative_to(runner).as_posix():dict(bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in runner.rglob('*')if p.is_file()}
 (context/'runner-derivations.json').write_text(json.dumps(dict(status='SOURCE_CLOSED_COUNTED_DERIVATIVES',files=rows,builder=dict(original='scripts/ci/welcome-native/run.py',exact_replacements=2,bytes=len(builder_text(source).encode()),sha256=hashlib.sha256(builder_text(source).encode()).hexdigest())),sort_keys=True,indent=2)+'\n');return runner

# SPDX-License-Identifier: MIT
"""Lane-local exact derivatives; shared tools names/build/cleanup remain immutable."""
import hashlib,importlib.util,json,shutil,sys,types
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
BASE_SHA='78ee8e094f6c69ea5a1f10639888f86fc81025b7d0f0dd067dd43c3ff04ff898'
raw=(HERE/'base_adapter.py').read_bytes()
# Whole base pin is generated from the held DNS/sysctl lane, never an actual export.
if hashlib.sha256(raw).hexdigest()!=BASE_SHA:raise ValueError('held DNS/sysctl source adapter drift')
spec=importlib.util.spec_from_file_location('_sysctl2_held_adapter',HERE/'base_adapter.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
one=B.replace;function=B.function

def text(source,name):
 raw=B.text(source,name)
 if name=='contract.py':
  raw=one(raw,"NAMES=('cachy-asahi-dns','cachy-asahi-sysctl')","NAMES=('cachy-asahi-sysctl','cachy-asahi-sysctl2')\nPACKAGE='cachy-asahi-sysctl'")
  raw=one(raw,"LABEL='org.cachy-asahi.dns-sysctl-native.job'","LABEL='org.cachy-asahi.sysctl2-upgrade-native.job'")
 elif name=='run.py':
  raw=one(raw,"not set(C.NAMES)&base.keys()","C.PACKAGE not in base")
  raw=raw.replace('DNS_SYSCTL_NATIVE_PAIRS_AND_PRIVATE_FIXTURES_ONLY','SYSCTL1_TO2_NATIVE_PAIRS_AND_PRIVATE_UPGRADE_ONLY').replace('PASS_NATIVE_DNS_SYSCTL_PAIRS_AND_PRIVATE_LIFECYCLE','PASS_NATIVE_SYSCTL2_PAIRS_AND_SIGNED_UPGRADE')
 elif name=='job.py':
  raw=raw.replace('scripts/ci/dns-sysctl-native','scripts/ci/sysctl2-upgrade-native').replace('PASS_NATIVE_DNS_SYSCTL_PAIRS_AND_PRIVATE_LIFECYCLE','PASS_NATIVE_SYSCTL2_PAIRS_AND_SIGNED_UPGRADE').replace('PASS_NATIVE_DNS_SYSCTL_CANDIDATES_PRIVATE_LIFECYCLE','PASS_NATIVE_SYSCTL2_CANDIDATES_SIGNED_UPGRADE')
  raw=one(raw,"basename.startswith(product+'-')","basename.startswith(C.PACKAGE+'-')")
  raw=one(raw,"name=product+'-'+version+'-any.pkg.tar.'+suffix","name=C.PACKAGE+'-'+version+'-any.pkg.tar.'+suffix")
  raw=one(raw,"expected=product+'-'+C.version(source,product)+'-any.pkg.tar.'","expected=C.PACKAGE+'-'+C.version(source,product)+'-any.pkg.tar.'")
  raw=one(raw,"archive=product+'-'+C.version(source,product)+'-any.pkg.tar.'","archive=C.PACKAGE+'-'+C.version(source,product)+'-any.pkg.tar.'")
  raw=one(raw,"{r['container'] for r in ordered['consumer']['containers']}==set(owner['containers'])","[r['container'] for r in ordered['consumer']['containers']]==list(reversed(owner['containers']))")
 return raw

def module(source,name):
 m=types.ModuleType('sysctl2_upgrade_'+name.replace('.','_'));m.__file__=str(HERE/name);sys.modules[m.__name__]=m;exec(compile(text(source,name),m.__file__,'exec'),m.__dict__);return m

def public_tree(path):return B.public_tree(path)
def runner(source,context):
 runner=context/'runner';runner.mkdir();(runner/'accepted').mkdir();(runner/'contract.py').write_text(text(source,'contract.py'))
 for n in('selection.py','rules.py','lifecycle.py','fixture_checks.py','input-policy.json'):shutil.copyfile(HERE/n,runner/n)
 for n,p in [('installed.py','scripts/ci/apps-cache-native/installed.py'),('accepted/lifecycle.py','scripts/ci/welcome-native/lifecycle.py'),('accepted/root_upgrade.py','scripts/ci/full-root-upgrade/root_upgrade.py')]:B.read(source,p);shutil.copyfile(source/p,runner/n)
 rows={p.relative_to(runner).as_posix():dict(bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())for p in runner.rglob('*')if p.is_file()}
 (context/'runner-derivations.json').write_text(json.dumps(dict(status='SOURCE_CLOSED_COUNTED_DERIVATIVES',files=rows,builder='ORIGINAL_WELCOME_BUILD_BYTE_HELD'),sort_keys=True,indent=2)+'\n');return runner

# SPDX-License-Identifier: MIT
"""Exact29c2 carrier namespace adapter; no guard or credential-policy change."""
import hashlib,json,stat,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
EDITS=(("scripts/ci/llhttp-reference-native-source/","scripts/ci/libgit2-reference-native-source/",2),('ROOT_LLHTTP_REFERENCE_ADMISSION_JSON','ROOT_LIBGIT2_REFERENCE_ADMISSION_JSON',1),('ROOT_LLHTTP_REFERENCE_RUNTIME_JSON','ROOT_LIBGIT2_REFERENCE_RUNTIME_JSON',1),("cache.parent.name == 'llhttp-reference-native'","cache.parent.name == 'libgit2-reference-native'",1))
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def frozen(name):
 p=HERE/'frozen'/name;profile=json.loads((HERE/'profile.DATA.json').read_bytes());row=profile['carrier_whole_pins'].get(name)or profile['source95_public_export_helper'];need(p==p.resolve()and p.is_file()and not p.is_symlink()and p.stat().st_nlink==1,'ordinary exact frozen helper');raw=p.read_bytes();need(pin(raw)==row,'whole immutable helper/input '+name);return raw

def project(raw):
 need(pin(raw)==json.loads((HERE/'profile.DATA.json').read_bytes())['carrier_whole_pins']['carrier.py'],'whole29c2 carrier source');text=raw.decode()
 for before,after,count in EDITS:need(text.count(before)==count and after not in text,'exact carrier namespace seam');text=text.replace(before,after)
 inverse=text
 for before,after,count in reversed(EDITS):need(inverse.count(after)==count,'exact namespace inverse');inverse=inverse.replace(after,before)
 need(inverse.encode()==raw,'whole unchanged29c2 carrier inverse');return text.encode()

def runtime(binding=None):
 raw=project(frozen('carrier.py')).decode()
 for name,file in(('EXPECTED','expected-files.json'),('BINDING','binding.TEMPLATE.json'),('HOST_REFERENCE','github-host-reference.json')):
  value=json.loads(frozen(file))if name!='BINDING'or binding is None else binding
  before=name+" = json.loads((HERE/'"+file+"').read_text())";need(raw.count(before)==1,'one exact data literal binding');raw=raw.replace(before,name+' = '+repr(value))
 # New libgit2 operation only: two exact reversible held-entry changes.
 before="    new = text.replace(before, after)\n    need(new.replace(after, before).encode() == raw, 'whole-unchanged-held-entry-inverse')\n    return new.encode()"
 after="    need(text.count('len(self.rows)<160') == 1, 'one finite inner command budget seam')\n    new = text.replace(before, after).replace('len(self.rows)<160', 'len(self.rows)<512')\n    need(new.replace('len(self.rows)<512', 'len(self.rows)<160').replace(after, before).encode() == raw, 'whole-unchanged-held-entry-inverse')\n    return new.encode()"
 need(raw.count(before)==1,'one exact inner512 budget projection');raw=raw.replace(before,after)
 return raw.encode()

def module(binding=None):
 m=types.ModuleType('libgit2_exact182_carrier');m.__file__=str(HERE/'native349_carrier.py');exec(compile(runtime(binding),m.__file__,'exec'),m.__dict__);return m

def public_runtime():
 raw=frozen('public_evidence.py').decode()
 edits=(('cachy-asahi-llhttp-reference-9.3.1-1-aarch64','cachy-asahi-libgit2-reference-1.9.7-1-aarch64'),('llhttp-reference-native','libgit2-reference-native'),('LLHTTP_REFERENCE','LIBGIT2_REFERENCE'),("ROOT_FILES = ('report.json', 'cleanup.json', 'comparison.json', 'pair.json')","ROOT_FILES = ('report.json', 'cleanup.json', 'comparison.json', 'pair.json', 'project-test.json', 'project-test-inventory.lock', 'project-test-evidence.json')"),("'failure', 'packages_lock', 'pair', 'commands', 'retention_failure'}","'failure', 'packages_lock', 'pair', 'commands', 'retention_failure', 'project_test'}"),('range(160)','range(512)'))
 for before,after in edits:need(before in raw,'finite libgit2 public-export adaptation');raw=raw.replace(before,after)
 return raw.encode()

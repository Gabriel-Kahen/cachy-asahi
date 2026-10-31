# SPDX-License-Identifier: MIT
"""Fixed-five typed ALPM domains over the byte-held full native graph reader."""
import hashlib,types
from pathlib import Path
import latest_plan as plan
import latest_descriptor as query
HELD={'bytes': 18177, 'sha256': '7fa40199aedb245b9060de46995e74205dff5b88ee8ec52da4f8697b2c2cd4cf'}
ANCHOR="return name in SELECTED_FILES|SELECTED_DIRS or name == SELECTED_DB or name.startswith(SELECTED_DB+'/')"
REPLACEMENT="return name in SELECTED_FILES|SELECTED_DIRS or any(name==record or name.startswith(record+'/')for record in SELECTED_DBS)"
DB='var/lib/pacman/local'
def need(ok,why):
 if not ok:raise ValueError(why)
def paths(value):
 need(type(value)is dict and set(value)=={r[0]for r in plan.PRODUCTS},'exact five source-owned selected path roles');files={};dirs={};parents={'usr/bin','usr/share/doc','usr/share/licenses',DB}
 for role,names in value.items():
  _,package,_,_=plan.product(role);need(type(names)is dict and set(names)=={'files','directories'},'exact archive-derived selected path schema')
  need(type(names['files'])is type(names['directories'])is list and len(names['files'])<=64 and len(names['directories'])<=32,'finite plain selected path lists');files[role]=frozenset(names['files']);dirs[role]=frozenset(names['directories']);need(files[role]and not files[role]&dirs[role],'nonempty disjoint file/directory paths')
  private=('usr/lib/'+package,'usr/share/'+package,'usr/share/doc/'+package,'usr/share/licenses/'+package)
  executables={'usr/bin/'+package}|({'usr/bin/cachy-asahi-repository'}if role=='setup'else set())
  assets={'usr/share/applications/io.github.GabrielKahen.CachyAsahiWelcome.desktop','usr/share/icons/hicolor/scalable/apps/cachy-asahi-welcome.svg'}if role=='welcome'else set()
  need(all(name in executables|assets or any(name.startswith(prefix+'/')for prefix in private)for name in files[role]),'fixed product payload domain only')
  need(all(any(name==prefix or name.startswith(prefix+'/')for prefix in private)for name in dirs[role]),'only private product directories selected; common parents protected')
  need(all(any(name.startswith(directory+'/')for name in files[role])for directory in dirs[role]),'selected directory has selected payload descendants')
  for name in files[role]|dirs[role]:
   p=Path(name);need(type(name)is str and name and not p.is_absolute()and p.as_posix()==name and not{'.','..'}&set(name.split('/'))and len(p.parts)<=128,'canonical selected archive path')
   need(not name.startswith(('etc/','home/','root/','var/','dev/','proc/','sys/','boot/')),'tool package may not select user/trust/platform/device paths')
   if name.rpartition('/')[0]:parents.add(name.rpartition('/')[0])
 need(len(set.union(*(set(v)for v in files.values())))==sum(map(len,files.values())),'five selected payload closures do not overlap')
 return files,dirs,frozenset(parents)
def bind(raw,selected_paths,role=None):
 need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==HELD,'whole original native package graph source');files,dirs,parents=paths(selected_paths)
 text=raw.decode();need(text.count(ANCHOR)==1,'one exact selected DB-domain seam');text=text.replace(ANCHOR,REPLACEMENT,1);need(text.replace(REPLACEMENT,ANCHOR,1).encode()==raw,'whole original graph/security/identity function inverse')
 module=types.ModuleType('_latest_native_graph_'+str(role));exec(compile(text,'<whole-native-graph-finite-selection>','exec'),vars(module))
 chosen=tuple(r for r in plan.PRODUCTS if role is None or r[0]==role);need(bool(chosen),'fixed graph selection role');module.NAME=None if role is None else chosen[0][1];module.SELECTED_FILES=frozenset().union(*(files[r[0]]for r in chosen));module.SELECTED_DIRS=frozenset().union(*(dirs[r[0]]for r in chosen));module.SELECTED_DBS=tuple(DB+'/'+name+'-'+v for _,name,old,new in chosen for v in(old,new)if v is not None);module.INSERTION_PARENTS=parents
 module.capture=query.bind(module,raw)
 return module

def protected(scope,before,after,lock_witness):
 # The full capture uses the SAME all-five parent set every time. The selected
 # transaction still treats each of the other four tools as protected packages.
 for graph in(before,after):
  for group in graph['hardlinks']:
   marks=[scope.selected(name)for name in group['members']];need(not any(marks)or all(marks),'acted/protected hardlink group refused')
 return scope.protected(before,after,lock_witness=lock_witness)

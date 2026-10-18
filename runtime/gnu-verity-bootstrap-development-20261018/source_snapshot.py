"""Complete original read-only observer/capability maps, never a substitute map."""
import importlib,sys
from pathlib import Path
import common as C

def api():
 rows=C.source_inputs();root=C.D.parent/rows['roles']['VM226']['root'];sys.path[:0]=[str(root/'scripts/update'),str(root/'scripts/apps')]
 modules={n:importlib.import_module(n)for n in('full_root','file_capabilities','root_link_selection','aux_checkpoint')}
 for n,m in modules.items():C.need(Path(m.__file__).is_relative_to(root),'source-static original helper only: '+n)
 return modules

def raw_maps(modules,root,limits):
 F=modules['full_root'];value=F.observe(root,limits=limits,hardlinks='generic-development-internal');C.need(value['complete']is True,'complete original observation');caps,physical=modules['file_capabilities']._scan(root,value['nodes'],limits)
 return dict(observation=value,nodes=value['nodes'],capabilities=caps,physical=physical)


def observe(modules,root,limits):
 value=raw_maps(modules,root,limits);modules['root_link_selection'].check(value['observation'],limits);modules['aux_checkpoint'].checkpoint(root,value['observation'],limits);return value


def same(before,after):
 # Preserve full reports. Only fresh capacity counters may legitimately change
 # while preparing output on the same host filesystem; never rewrite raw maps.
 import copy
 a,b=copy.deepcopy(before),copy.deepcopy(after)
 for value in(a,b):
  f=value['observation']['footprint']
  for k in('filesystem_free_bytes','filesystem_free_inodes'):
   C.need(k in f and(f[k]is None or type(f[k])is int and f[k]>=0),'fresh original capacity counter');f.pop(k)
 C.need(a==b,'every original stable field/capability/physical/hardlink/rawDB map must remain equal')

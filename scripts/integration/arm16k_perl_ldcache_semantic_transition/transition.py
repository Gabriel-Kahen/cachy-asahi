# SPDX-License-Identifier: MIT
"""Derive a finite cache transition only from certified baseline/provider inputs.

The r90 observed cache is NEVER an input to derive(). Historical examples cannot
issue Root authority or replace baseline bytes, live xattrs or private guards.
"""
import importlib.util,json
from pathlib import Path
HERE=Path(__file__).resolve().parent

def module(n):
 s=importlib.util.spec_from_file_location('ldcache_'+n,HERE/(n+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
C=module('cache');P=module('providers')
BASELINE=dict(bytes=17551,sha256='0128a732a8b926232b5065374176194ea4a1f5c1628728037109bbdbb3d53215')
PROVIDER_PIN={'bytes': 180225, 'sha256': '654bfbc3adbcbc06780fe0e31c52b987eeb8ce14734297a4f0e1f319f5c76dda'}
def qualified_providers():
 body=(HERE/'providers.DATA.json').read_bytes();C.need(C.pin(body)==PROVIDER_PIN,'whole pinned package/alias projection');return json.loads(body)
EXPECTED_DB_NAMES={'libdb-5.3.so','libdb_cxx-5.3.so','libdb_stl-5.3.so'}

def derive(baseline,baseline_nodes,db_nodes,db_elf_sonames):
 C.need(C.pin(baseline)==BASELINE,'exact independently qualified baseline bytes required; hash/header alone is insufficient')
 p=qualified_providers();C.need(baseline_nodes==p['baseline_nodes']and db_nodes==p['db_nodes']and db_elf_sonames==p['db_elf_sonames'],'exact immutable provider/alias/package projection only')
 base=C.decode(baseline);joined=P.join(base['entries'],baseline_nodes)
 C.need(type(db_nodes)is dict and type(db_elf_sonames)is dict and set(db_elf_sonames)==EXPECTED_DB_NAMES,'exact3 pinned db5.3 ELF SONAMEs')
 additions=[]
 for name in sorted(EXPECTED_DB_NAMES):
  path='usr/lib/'+name;r=db_nodes.get(path);C.need(type(r)is dict and r.get('package')==dict(name='db5.3',version='5.3.28-7')and db_elf_sonames[name]==name,'db5.3 immutable package/ELF SONAME join');additions.append(C.row(name,'/'+path))
 P.join(additions,db_nodes);C.need(not set(r['name']for r in base['entries'])&EXPECTED_DB_NAMES,'dependency cache entries absent in baseline')
 expected=C.encode(base['entries']+additions);C.decode(expected)
 return dict(kind='DERIVED_DB53_PERL_LIFECYCLE_CACHE_TRANSITION_V1',baseline=BASELINE,installed=C.pin(expected),restored=BASELINE,baseline_entries=len(base['entries']),installed_entries=len(base['entries'])+3,added_entries=additions,baseline_provider_joins=joined,dependency_provider_joins=P.join(additions,db_nodes),Root_acceptance=None,lifecycle_acceptance=None,VM=None,M2=None,release=None),expected

def metadata(before,after):
 """Typed public-node predicate; called in addition to every existing private guard.

Full live xattrs are required here. r90 stat/dump omits them and cannot pass this
predicate or stand in for a mounted journal-replayed future live observation.
"""
 C.need(type(before)is dict and type(after)is dict and set(before)==set(after)=={'etc','etc/ld.so.cache'},'exact two public nodes only')
 for path in before:
  a,b=before[path],after[path];C.need(type(a)is dict and type(b)is dict and type(a.get('xattrs'))is dict and b.get('xattrs')==a['xattrs'],'unchanged fully observed live xattrs')
  for r in(a,b):C.need(all(type(r.get(k))is int for k in('mode','uid','gid','links','size','inode','mtime','mtime_ns'))and 0<r['inode']<=2**32-1 and 0<r['links']<=65535 and 0<=r['size']<=C.CAP,'typed bounded public metadata')
  fields=('type','mode','uid','gid','links','size','inode')if path=='etc'else('type','mode','uid','gid','links')
  C.need(all(a.get(k)==b.get(k)for k in fields),'stable typed parent/cache invariants')
  C.need(b['uid']==b['gid']==0 and b['mode']==(0o755 if path=='etc'else 0o644)and b['type']==('directory'if path=='etc'else'file'),'root-owned exact public metadata')
  if path!='etc':C.need(b['links']==1,'single-link regenerated cache')
  C.need(type(b.get('mtime'))is int and type(b.get('mtime_ns'))is int and 0<=b['mtime_ns']<10**9 and (b['mtime'],b['mtime_ns'])>=(a['mtime'],a['mtime_ns']),'natural nondecreasing cache/parent time, no reset')
 return True

def phase(manifest,name,body,before,after,window):
 C.need(manifest.get('kind')=='DERIVED_DB53_PERL_LIFECYCLE_CACHE_TRANSITION_V1'and name in('installed','restored'),'one declared lifecycle phase')
 C.need(C.pin(body)==manifest[name],'exact independently derived phase bytes; no learned sample allowance');C.decode(body);metadata(before,after)
 C.need(after['etc/ld.so.cache'].get('sha256')==C.pin(body)['sha256']and after['etc/ld.so.cache']['size']==len(body),'same current typed cache body')
 C.need(type(window)is tuple and len(window)==2 and all(type(v)is int and v>0 for v in window)and 0<=window[1]-window[0]<=1500*10**9,'actual finite transaction clock window')
 for r in after.values():C.need(window[0]<=r['mtime']*10**9+r['mtime_ns']<=window[1],'natural transaction cache/parent modification time; no reset')
 return dict(status='PROPOSED_PHASE_CACHE_PREDICATE_ONLY',phase=name,Root_acceptance=None,lifecycle_acceptance=None)

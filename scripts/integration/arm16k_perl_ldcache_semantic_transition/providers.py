# SPDX-License-Identifier: MIT
"""Pure cached-target join to a whole-pinned public package namespace projection."""
import base64,posixpath,re

def need(ok,why):
 if not ok:raise ValueError(why)
def public(path):
 need(type(path)is str and path.startswith('usr/lib/')and all(x not in('','..','.')for x in path.split('/')),'literal public library provider path');return path

def resolve(path,nodes):
 path=public(path);seen=set();chain=[]
 for _ in range(16):
  need(path not in seen,'provider alias cycle');seen.add(path);r=nodes.get(path);need(type(r)is dict,'cached target/alias exists in pinned namespace')
  need(r.get('uid')==r.get('gid')==0 and type(r.get('owners'))is list and len(r['owners'])==1 and type(r.get('package'))is dict,'root-owned unique immutable package provider')
  need(r['owners'][0]==r['package'].get('name')and type(r['package'].get('version'))is str and r['package']['version'],'provider inventory correspondence')
  if r.get('type')=='file':
   need(type(r.get('sha256'))is str and re.fullmatch('[0-9a-f]{64}',r['sha256'])and type(r.get('size'))is int and r['size']>0 and r['mode']in(0o644,0o755),'ordinary package shared-library provider')
   return dict(path=path,sha256=r['sha256'],bytes=r['size'],package=r['package'],aliases=chain)
  need(r.get('type')=='symlink'and r.get('mode')==0o777,'only immutable package aliases are followed')
  target=base64.b64decode(r.get('target_b64',''),validate=True).decode('ascii');need(target and '\0'not in target and not any(ord(c)<32 for c in target),'literal package alias target')
  chain.append(dict(path=path,target_b64=r['target_b64'],package=r['package']));path=public(posixpath.normpath(target.lstrip('/')if target.startswith('/')else posixpath.join(posixpath.dirname(path),target)))
 raise ValueError('finite provider alias depth')

def join(entries,nodes):
 need(type(entries)is list and type(nodes)is dict,'explicit cache entries/provider namespace')
 results=[]
 for r in entries:
  target=r['path'];need(target.startswith('/usr/lib/')and posixpath.basename(target)==r['name'],'exact public cached alias/lookup-key correspondence')
  results.append(dict(name=r['name'],cache_path=target,provider=resolve(target[1:],nodes)))
 return results

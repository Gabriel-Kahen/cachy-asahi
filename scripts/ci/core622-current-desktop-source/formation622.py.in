# SPDX-License-Identifier: MIT
"""Complete signed607 formation checks; no prefix-wide preservation waiver."""
from desktop622 import need,plan
DB='var/lib/pacman/local/'
CACHE={'etc/ld.so.cache','var/cache/ldconfig/aux-cache'}
def ungroup(row):return {k:v for k,v in row.items()if k!='hardlink_group'}

def check(value,before,after,before_caps,after_caps,payload,removed,initial_db,final_db,auxiliary):
 base,_,_=plan(value);added=set(base)-set(value['before574']);need(len(added)==34,'exact34 additions')
 need(payload['packages']==base and set(payload['ownership'])==set(base),'whole authenticated607 payload/ownership closure')
 need({r['name']:r['version']for r in initial_db}==value['before574']and {r['name']:r['version']for r in final_db}==base,'actual complete574 and607 database maps')
 olddb={r['name']:r for r in initial_db};newdb={r['name']:r for r in final_db}
 need(all(newdb[n]==r for n,r in olddb.items()if n!='libfdk-aac'),'every573 held database row/dependency/ownership unchanged')
 selected=set().union(*(set(payload['ownership'][n])for n in added));oldnodes=before['nodes'];nodes=after['nodes'];signed=payload['nodes']
 need(before['complete']is after['complete']is True and set(before['unsupported_counts'])<={'absolute-symlink','auxiliary-present'}and set(after['unsupported_counts'])<={'absolute-symlink','auxiliary-present'},'both complete non-normalized graphs')
 for n in selected:
  expected=signed[n];actual=nodes.get(n);need(actual is not None and ungroup(actual)==expected,'exact signed new payload metadata/bytes/link: '+n)
 for n in added:
  files={p for p in payload['ownership'][n]if signed[p]['type']!='directory'}
  need(set(newdb[n]['files'])==files,'complete signed installed ownership: '+n)
 # Source-derived hardlink groups must have exactly their signed membership.
 groups=sorted(sorted(r['members'])for r in after.get('hardlink_groups',{}).values())
 for group in payload['hardlinks']:
  if set(group)&selected:need(group in groups and not any(set(group)&set(g)and g!=group for g in groups),'entire signed new hardlink group')
 retired={n for n,r in removed['nodes'].items()if r['type']!='directory'and n not in signed}
 need(all(n not in nodes for n in retired),'all exclusive upstream codec payload retired')
 retired_dirs=set()
 for n,row in removed['nodes'].items():
  if row['type']=='directory'and n not in signed and n not in nodes:
   need(n in oldnodes and ungroup(oldnodes[n])==ungroup(row)and all(p in removed['nodes']for p in oldnodes if p.startswith(n+'/')),'only exact emptyable archive-owned removed directories');retired_dirs.add(n)
 need(auxiliary['status']=='FULL_FD_CHECKPOINT_AND_LIVE_AUXILIARY_LIBRARY_KEYS','source-derived ordinary cache observations required')
 dbpaths={DB+'libfdk-aac-'+value['before574']['libfdk-aac']}
 dbpaths|={DB+n+'-'+base[n]for n in added}
 # Closed ALPM database filenames, not a recursive arbitrary DB exemption.
 allowed=set(selected)|retired|retired_dirs|CACHE|dbpaths
 allowed|={d+'/'+p for d in dbpaths for p in('desc','files','mtree','install')}
 for n in set(oldnodes)|set(nodes):
  if oldnodes.get(n)==nodes.get(n):continue
  need(n in allowed,'every unrelated original node preserved: '+n)
  if n in CACHE:
   need(nodes.get(n,{}).get('type')=='file'and nodes[n]['uid']==nodes[n]['gid']==0,'ordinary observed auxiliary output')
  if n in selected and signed[n]['type']=='directory':need(ungroup(nodes[n])==signed[n],'ALPM-owned directory metadata from signed ledger')
 # No capability is silently stripped or introduced by NOHOOKS provisioning.
 need(before_caps==after_caps,'whole original capability map preserved')
 for n in selected:
  if n not in oldnodes:need(n not in after_caps,'no undeclared capability on new payload')
 return dict(status='PASS_COMPLETE607_SIGNED_PROVISIONING_GRAPH_DB_CAPS_AND_PRESERVATION',packages=607,held=573,added=34,removed={'libfdk-aac':value['before574']['libfdk-aac']},complete_graph=True,complete_capabilities=True,full_payload_and_hardlinks=True,unrelated_nodes_preserved=True,hooks='DISABLED',scriptlets='DISABLED',normal_hook_installation=False)

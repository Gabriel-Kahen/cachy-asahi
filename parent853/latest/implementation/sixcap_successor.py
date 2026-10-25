# SPDX-License-Identifier: MIT
"""One exact existing six-capability API binding; whole838 guard remains mandatory."""
import base64,importlib.util,json,sys,tempfile
from pathlib import Path
import lifecycle_cost_successor as O
pin,enc,rows,need=O.pin,O.enc,O.rows,O.need
MARKER='\n# BEGIN_EXACT_SIXCAP_SUPERVISOR_BINDING\n'
COMPONENT='latest/implementation/latest_component.py'
OLD=" N.native_scope('/',home,'/out/latest607-native.log');"
NEW=" C.scoped_load('_latest_existing_sixcap_signal_api',Path('/runner/real606/native_api.py'),{'native_contract':N});N.native_scope('/',home,'/out/latest607-native.log');"
def footer(name,want):return 'def verify():\n import sixcap_successor\n return sixcap_successor.verify(ROOT, '+repr(name)+', '+repr(want)+')\n'
def verify(root,name,want):
 root=Path(root);raw=(root/name).read_bytes();need(pin(raw)==want and not sys.flags.optimize,'whole exact sixcap source proof');p=json.loads(raw);actual=rows(root);before=p['before'];changed=set(p['before_bodies']);need(len(before)==838 and set(actual)==set(before)|set(p['added'])and {n for n in before if actual[n]!=before[n]}==changed,'whole838 inverse and finite source membership')
 need(p['publication']==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source='1e80073ffa9d50a8ac19fb67a8e9e58221a3985f',ref='codex/current607-latest-tools-v1',files=838,git_joins=838,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and p['git']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=p['publication']['source'],ref=p['publication']['ref'],files=before)and p['authorization']==before,'whole genuine838 source/Git context')
 need(all(p[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance'))and p['scope']=='EXISTING_NATIVE_0xDB_API_PRIVATE_BINDING_ONLY','NULL source authority and fixed correction scope')
 bodies={n:base64.b64decode(p['before_bodies'][n],validate=True)if n in changed else(root/n).read_bytes()for n in before};need(all(pin(bodies[n])==w for n,w in before.items()),'every original838 byte held or reconstructed');need(all(actual[n]==w for n,w in p['helpers'].items()),'exact current runtime/helper bodies')
 need((root/COMPONENT).read_text().count(NEW)==1 and (root/COMPONENT).read_text().replace(NEW,OLD,1).encode()==bodies[COMPONENT],'whole actual exercise body outside existing API binding')
 need((root/p['guard']).read_bytes()==bodies[p['guard']]+MARKER.encode()+footer(name,want).encode(),'whole original guard plus one mandatory finite guard')
 mf=json.loads((root/p['manifest']).read_bytes());need(mf['files']=={n:w for n,w in actual.items()if n not in{p['manifest'],*p['workflows']}},'whole current source manifest');oldmf=json.loads(bodies[p['manifest']]);need({k:v for k,v in mf.items()if k!='files'}=={k:v for k,v in oldmf.items()if k!='files'},'all original selection/status/NULL/clock fields held')
 for n in p['workflows']:need((root/n).read_bytes().replace(actual[p['manifest']]['sha256'].encode(),before[p['manifest']]['sha256'].encode())==bodies[n],'whole original workflow body except exact manifest stamp')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='sixcap-whole838-')as td:
   old=Path(td)/'source';old.mkdir()
   for n,b in bodies.items():q=old/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b)
   need(rows(old)==before,'complete physical838 original guard namespace')
   for q in old.rglob('*.py'):sys.modules.pop(q.stem,None)
   sys.path.insert(0,str(old/'latest/implementation'));spec=importlib.util.spec_from_file_location('_whole_original838_six_tool_guard',old/p['guard']);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);fact=m.verify();need(fact['files']==838,'whole original838/581/568 source gate')
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 return dict(fact,files=len(actual),sixcap_binding='EXACT_EXISTING_NATIVE_API_0xDB_PRIVATE_NAMESPACE',whole838=fact,actual=None)

# SPDX-License-Identifier: MIT
"""Exact raw original printer custody; complete840 predecessor guard mandatory."""
import base64,importlib.util,json,sys,tempfile
from pathlib import Path
import lifecycle_cost_successor as O
pin,enc,rows,need=O.pin,O.enc,O.rows,O.need
MARKER='\n# BEGIN_EXACT_INSTALLED_STDOUT_CODEC_SUCCESSOR\n'
def footer(name,want):return 'def verify():\n import installed_codec_successor\n return installed_codec_successor.verify(ROOT, '+repr(name)+', '+repr(want)+')\n'
def verify(root,name,want):
 root=Path(root);raw=(root/name).read_bytes();need(pin(raw)==want and not sys.flags.optimize,'whole exact installed stdout codec proof');p=json.loads(raw);before=p['before'];actual=rows(root);changed=set(p['before_bodies']);need(len(before)==840 and set(actual)==set(before)|set(p['added'])and {n for n in before if actual[n]!=before[n]}==changed,'whole840 inverse and finite842 source membership')
 pub=p['publication'];need(pub==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source='16ae35b7959ecf74b5e85cbe9243e8456ef2be6f',ref='codex/current607-sixcap-v1',files=840,git_joins=840,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and p['authorization']==before and p['git']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=pub['source'],ref=pub['ref'],files=before),'whole genuine840 publication/Git/source authority')
 need(p['scope']=='UNCHANGED_SETUP240_UNSORTED_STDOUT_RAW_CUSTODY_AND_CODEC_ONLY'and all(p[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'fixed codec-only scope and NULL new authority')
 bodies={n:base64.b64decode(p['before_bodies'][n],validate=True)if n in changed else(root/n).read_bytes()for n in before};need(all(pin(bodies[n])==w for n,w in before.items()),'every original840 byte reconstructed or held');need(all(actual[n]==w for n,w in p['helpers'].items()),'exact corrected runtime/helper/test bodies')
 for n,edits in p['edits'].items():
  text=(root/n).read_text()
  for old,new in reversed(edits):need(text.count(new)==1,'one exact stdout custody/codec seam');text=text.replace(new,old,1)
  need(text.encode()==bodies[n],'whole original body outside exact codec/custody edits')
 need((root/p['guard']).read_bytes()==bodies[p['guard']]+MARKER.encode()+footer(name,want).encode(),'whole original guard and mandatory finite appendix')
 mf=json.loads((root/p['manifest']).read_bytes());need(mf['files']=={n:w for n,w in actual.items()if n not in{p['manifest'],*p['workflows']}},'whole new842 manifest');oldmf=json.loads(bodies[p['manifest']]);need({k:v for k,v in mf.items()if k!='files'}=={k:v for k,v in oldmf.items()if k!='files'},'all original source NULL/status/clock fields held')
 for n in p['workflows']:need((root/n).read_bytes().replace(actual[p['manifest']]['sha256'].encode(),before[p['manifest']]['sha256'].encode())==bodies[n],'all original workflow bodies/clocks except exact manifest stamp')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='installed-codec-whole840-')as td:
   old=Path(td)/'source';old.mkdir()
   for n,b in bodies.items():q=old/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b)
   need(rows(old)==before,'complete physical840 namespace before old guard')
   for q in old.rglob('*.py'):sys.modules.pop(q.stem,None)
   sys.path.insert(0,str(old/'latest/implementation'));spec=importlib.util.spec_from_file_location('_whole840_installed_codec_guard',old/p['guard']);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);fact=m.verify();need(fact['files']==840,'whole original840/838/581 source guard')
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 return dict(fact,files=len(actual),installed_codec='EXACT_ORIGINAL_UNSORTED_PRINTER_AND_BOUNDED_RAW_CUSTODY',whole840=fact,actual=None)

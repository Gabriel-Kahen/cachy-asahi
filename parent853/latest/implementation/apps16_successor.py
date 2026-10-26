# SPDX-License-Identifier: MIT
"""Whole accepted842 source inverse AND Apps16-only installed composition route."""
import base64,contextlib,importlib.util,json,sys,tempfile
from pathlib import Path
import installed_codec_successor as OLD
pin,enc,rows,need=OLD.pin,OLD.enc,OLD.rows,OLD.need
MARKER='\n# BEGIN_EXACT_APPS16_SIX_TOOL_SUCCESSOR\n'
def footer(name,want):
 return "def verify():\n import apps16_successor\n return apps16_successor.verify(ROOT, "+repr(name)+', '+repr(want)+")\n\n_before_apps16_authorize=authorize\ndef authorize():\n import apps16_inputs\n apps16_inputs.qualification()\n return _before_apps16_authorize()\n"
@contextlib.contextmanager
def parent(root,p):
 bodies={n:base64.b64decode(p['before_bodies'][n],validate=True)if n in p['before_bodies']else(Path(root)/n).read_bytes()for n in p['before']};need({n:pin(b)for n,b in bodies.items()}==p['before'],'entire original842 body map reconstructed')
 with tempfile.TemporaryDirectory(prefix='apps16-composition-whole842-')as td:
  root=Path(td)/'source';root.mkdir()
  for n,b in bodies.items():q=root/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b)
  need(rows(root)==p['before'],'whole physical842 source context');yield root,bodies

def workflow(text,profiles):
 marker='      - name: Checkout exact accepted Apps8 additional product DATA\n';blocks=''
 for role,row in profiles.items():blocks+='      - name: Checkout exact Apps16 '+role+' public input DATA\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: '+row['source']+'\n          path: latest607-next-'+role+'-inputs\n          persist-credentials: false\n'
 need(text.count(marker)==1,'one held Apps8 checkout marker');text=text.replace(marker,blocks+marker,1)
 anchor='--apps10qualification-packet "$GITHUB_WORKSPACE/latest607-next-apps10qualification-inputs"';need(text.count(anchor)==2,'both original input/owner argument routes');extra=' '.join('--'+role+'-packet "$GITHUB_WORKSPACE/latest607-next-'+role+'-inputs"'for role in profiles);text=text.replace(anchor,anchor+' '+extra)
 command='LATEST607_APPS8_TEST_PACKET="$GITHUB_WORKSPACE/latest607-apps8-inputs" python3 -I -B expanded604-code/next/test_source.py';need(text.count(command)==1,'one original emitted test command');return text.replace(command,'APPS16_COMPOSITION_TEST_CARRIER="$GITHUB_WORKSPACE/latest607-next-apps16-inputs" APPS16_COMPOSITION_TEST_RECORD="$GITHUB_WORKSPACE/latest607-next-apps16qualification-inputs" APPS16_COMPOSITION_TEST_CURRENT606_RECORD="$GITHUB_WORKSPACE/latest607-next-apps16current606qualification-inputs" '+command,1)

def verify(root,name,want):
 root=Path(root);raw=(root/name).read_bytes();need(pin(raw)==want and not sys.flags.optimize,'hardpinned Apps16 successor proof');p=json.loads(raw);actual=rows(root);before=p['before'];changed=set(p['before_bodies']);added=set(p['added']);need(len(before)==842 and set(actual)==set(before)|added and{n for n in before if actual[n]!=before[n]}==changed and all(actual[n]==w for n,w in p['helpers'].items()),'whole842 finite changed/added/helper closure')
 need(all(p[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'new current actual selectors NULL')
 pub=p['publication'];need(pub['source']=='8b22845252d01e1a813ed078be60315a39a27a5f'and pub['ref']=='codex/current607-installed-codec-v1'and pub['files']==pub['git_joins']==842 and p['source_authorization']==before and p['git_authorization']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=pub['source'],ref=pub['ref'],files=before),'whole genuine accepted842 publication/Git')
 decision=p['parent_decision'];need(pin(enc(decision))==p['parent_decision_pin']and decision['status']=='ROOT_ACCEPTED_FINITE_NATIVE_SIX_TOOL_SOFTWARE_COMPOSITION'and decision['source']==pub['source']and decision['run_id']==39797561367 and decision['software_scope']['transactions']==32 and decision['software_scope']['fresh_graphs']==65 and decision['software_scope']['fresh_auxiliary_observations']==33 and decision['software_scope']['whole_real240_suites']==4,'whole accepted predecessor software scope only')
 import apps16_inputs as A16,latest_plan as PLAN
 selected=A16.profile();need(PLAN.product('apps')[3]=='0.1.0-16'and(PLAN.TRANSACTIONS,PLAN.GRAPHS,PLAN.AUXILIARY,len(PLAN.REAL_PHASES))==(32,65,33,4)and PLAN.BOUNDS==p['bounds'],'same full transaction/graph/aux/suite bounds with only Apps16 product')
 mf=json.loads((root/p['manifest']).read_bytes());need(mf['files']=={n:w for n,w in actual.items()if n not in{p['manifest'],*p['workflows']}}and all(mf[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'complete new closed source manifest and NULL actuals')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with parent(root,p)as(old,bodies):
   for n,edits in p['edits'].items():
    text=(root/n).read_text()
    for a,b in reversed(edits):need(text.count(b)==1,'one exact Apps16 runtime/source seam');text=text.replace(b,a,1)
    need(text.encode()==bodies[n],'whole original body outside explicit Apps16 changes')
   need((root/p['guard']).read_bytes()==bodies[p['guard']]+MARKER.encode()+footer(name,want).encode(),'whole original guard plus mandatory Apps16 appendix')
   oldmf=json.loads(bodies[p['manifest']]);need({k:v for k,v in mf.items()if k!='files'}=={k:v for k,v in oldmf.items()if k!='files'},'all original manifest security/NULL/status contracts held')
   for n in p['workflows']:
    text=bodies[n].replace(before[p['manifest']]['sha256'].encode(),actual[p['manifest']]['sha256'].encode()).replace(before[p['run']]['sha256'].encode(),actual[p['run']]['sha256'].encode());need(workflow(text.decode(),selected['profiles']).encode()==(root/n).read_bytes(),'entire original workflow outside exact new checkouts/operands/stamps')
   for q in old.rglob('*.py'):sys.modules.pop(q.stem,None)
   sys.path.insert(0,str(old/'latest/implementation'));s=importlib.util.spec_from_file_location('_whole_original842_composition_guard',old/p['guard']);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);fact=m.verify();need(fact['files']==842,'whole original842/840/838/581 and prior source guards executed')
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 return dict(fact,files=len(actual),profile='NATIVE607_SIX_TOOLS_APPS16_WELCOME8_SETUP6_DOCTOR2_KSM2_BOOT1',Apps16='NATIVE577_INPUT_ONLY_NEW_SIX_TOOL_COMPOSITION_NOT_QUALIFIED',Apps16_full606='UNBOUND_BEFORE_ACTORS'if selected['selection']is None else'ISSUED_SEPARATE_INPUT_ONLY_NEW_COMPOSITION_NOT_QUALIFIED',parent842=fact,actual=None)

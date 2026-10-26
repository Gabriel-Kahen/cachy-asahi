# SPDX-License-Identifier: MIT
"""Finite whole1197 inverse; exact old guard executes once in a private namespace."""
import importlib.util,json,sys,tempfile
from pathlib import Path
import common as C
PARENT_SHA='836bf00d194c7b34dd26ac2dec82e08fe49323f834b959a10566ba5cf2eea287'
ALIASES=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-fresh-installer.yml')
DOC='''\n\nExplicit generic16K TEST mode keeps the default4K six emitted bodies exact. Its kernel20 input is accepted BUILD_ONLY, never prior boot/lifecycle evidence. It uses the same607 ledger, signatures, ALPM/toolchain, namespace, post-parent root readback and retirement predicates with all old clocks. The stock rootfs kernel/modules/depmod remain unchanged; the separately pinned Image is QEMU input only. New actual/source/ref/run/Root authority and16K fit remain UNBOUND/NOT_RUN. It is not an Asahi/platform change or M2 compatibility result. See implementation/page-mode-profile.json for exact source/license/input scope.\n'''
STEP='''      - name: Checkout exact kernel20 build-only source context for explicit16K
        if: ${{ inputs.page_mode == 'generic16k' }}
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: de1aab259df6bda8ad36f959392e3fc4eb35b622
          path: fresh607-kernel20-source
          persist-credentials: false
      - name: Acquire only exact existing BUILD_ONLY kernel20 input for explicit16K
        if: ${{ inputs.page_mode == 'generic16k' }}
        timeout-minutes: 6
        shell: bash
        env:
          GITHUB_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          timeout --signal=TERM --kill-after=10s 300s python3 -I -B fresh607-code/implementation/kernel20_input.py --source "$GITHUB_WORKSPACE/fresh607-kernel20-source" --output "$RUNNER_TEMP/fresh607-kernel20-data"
'''
def one(raw,a,b):
 C.need(raw.count(a.encode())==1,'one exact page-context seam '+a[:60]);return raw.replace(a.encode(),b.encode(),1)
def with_mode(raw):
 out=one(raw,'      mode:\n',"      page_mode:\n        description: Generic software VM page mode;16K uses only fixed BUILD_ONLY kernel20\n        required: true\n        default: generic4k\n        type: choice\n        options: [generic4k, generic16k]\n      mode:\n")
 out=one(out,'      - name: Checkout issued Root accepted Six853 DATA record\n',STEP+'      - name: Checkout issued Root accepted Six853 DATA record\n')
 out=one(out,'          FRESH_SOURCE: ${{ inputs.fresh_source_revision }}\n          IMPLEMENTATION_SOURCE: ${{ inputs.source }}\n','          FRESH_SOURCE: ${{ inputs.fresh_source_revision }}\n          IMPLEMENTATION_SOURCE: ${{ inputs.source }}\n          PAGE_MODE: ${{ inputs.page_mode }}\n')
 out=one(out,'          test "$AUDIO_INPUTS_OUTCOME" = success\n','          test "$AUDIO_INPUTS_OUTCOME" = success\n          page_args=(--page-mode "$PAGE_MODE")\n          case "$PAGE_MODE" in generic4k) ;; generic16k) page_args+=(--kernel-input "$RUNNER_TEMP/fresh607-kernel20-data");; *) exit 1;; esac\n')
 out=one(out,'      - name: Run unchanged installer controls and focused604 controls without actors\n','      - name: Current generic page-mode and complete607 source controls without actors\n        shell: bash\n        env:\n          FRESH607_ACCEPTED_PUBLIC: ${{ runner.temp }}/fresh607-input-data\n        run: |\n          set -euo pipefail\n          python3 -I -B fresh607-code/implementation/test_source.py\n          python3 -I -B fresh607-code/implementation/test_page_mode.py\n      - name: Run unchanged installer controls and focused604 controls without actors\n')
 out=one(out,'      - name: Retain only bounded declared expanded604 installer reports\n        if: always()\n        timeout-minutes: 2\n        shell: bash\n', '      - name: Retain only bounded declared expanded604 installer reports\n        if: always()\n        timeout-minutes: 2\n        shell: bash\n        env:\n          PAGE_MODE: ${{ inputs.page_mode }}\n')
 out=one(out,"          rows={};total=0\n", "          mode=os.environ['PAGE_MODE'];assert type(mode)is str and mode in('generic4k','generic16k')\n          scope='generic4K fresh latest607 software installer only; no hardware or native-container P0 credit'if mode=='generic4k'else'generic16K fresh latest607 software installer only; no hardware or native-container P0 credit'\n          rows={};total=0\n")
 out=one(out,"              scope='generic4K fresh latest607 software installer only; no hardware or native-container P0 credit'",'              scope=scope')
 out=one(out,'              --tooling-inputs "$GITHUB_WORKSPACE/fresh607-tooling-inputs" \\\n','              --tooling-inputs "$GITHUB_WORKSPACE/fresh607-tooling-inputs" "${page_args[@]}" \\\n');out=with_dependency_cache_workflow(out)
 out=one(out,'          page_args=(--page-mode "$PAGE_MODE")\n','          clock_env=()\n          page_args=(--page-mode "$PAGE_MODE")\n')
 out=one(out,'generic16k) page_args+=(--kernel-input "$RUNNER_TEMP/fresh607-kernel20-data");;','generic16k) page_args+=(--kernel-input "$RUNNER_TEMP/fresh607-kernel20-data"); clock_env=(FRESH_SOURCE="$FRESH_SOURCE" GITHUB_RUN_ID="$GITHUB_RUN_ID" GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT");;')
 out=one(out,'            PYTHONDONTWRITEBYTECODE=1 \\\n','            PYTHONDONTWRITEBYTECODE=1 "${clock_env[@]}" \\\n')
 return out

def run_body(raw):
 out=one(raw,'runtime_context,tooling_inputs','runtime_context,tooling_inputs,page_mode')
 out=one(out," def __init__(self,record,public,legacy,contract,source=None,decision=None,tooling_root=None):self.tooling_root=tooling_root;", " def __init__(self,record,public,legacy,contract,source=None,decision=None,tooling_root=None,page='generic4k',kernel_input=None):page_mode.select(page,kernel_input);self.page,self.kernel_input=page,kernel_input;self.scope='GENERIC4K_LATEST607_FRESH_INSTALLER_SOFTWARE_ONLY'if page=='generic4k'else'GENERIC16K_LATEST607_FRESH_INSTALLER_SOFTWARE_ONLY';self.tooling_root=tooling_root;")
 out=one(out,' def candidate(self,path):return adapter.emit(path)'," def candidate(self,path):return adapter.emit(path)if self.page=='generic4k'else page_mode.emit(path,self.kernel_input)")
 out=one(out,"\"'GENERIC4K_LATEST607_FRESH_INSTALLER_SOFTWARE_ONLY'\"","'Y.scope'")
 out=one(out,"p.add_argument('--fresh-source-revision',required=True);", "p.add_argument('--page-mode',choices=('generic4k','generic16k'),default='generic4k');p.add_argument('--kernel-input',type=Path);p.add_argument('--fresh-source-revision',required=True);")
 out=one(out,'Integration(record,public,legacy,contract,new.fresh_source_revision,decision,tooling_root)','Integration(record,public,legacy,contract,new.fresh_source_revision,decision,tooling_root,new.page_mode,new.kernel_input)');compile(out,'<finite-page-owner>','exec');return out

def with_dependency(raw):
 p=json.loads(C.read(C.HERE/'page-parent.json'))['dependency_parent']['helper_edits'];out=raw
 for a,b in p['edits']:out=one(out,a,b)
 out+=p['append'].encode();restored=out[:-len(p['append'].encode())]
 for a,b in reversed(p['edits']):restored=one(restored,b,a)
 C.need(restored==raw,'whole original1203 producer diagnostic inverse');return out

def with_dependency_cache_workflow(raw):
 p=json.loads(C.read(C.HERE/'page-parent.json'))['dependency_cache_parent'];out=raw
 step=p['preparation_step'].encode();C.need(out.count(step)==1,'one unchanged preparation93bc checkout');out=out.replace(step,b'',1)
 anchor=b'      - name: Checkout exact retained compiler6 archive and signature inputs\n';C.need(out.count(anchor)==1,'one shared compiler6 preparation position')
 out=out.replace(anchor,step+p['incoming_step'].encode()+anchor,1)
 for a,b in p['workflow_edits']:out=one(out,a,b)
 return out

def with_dependency_cache_helper(raw):
 p=json.loads(C.read(C.HERE/'page-parent.json'))['dependency_cache_parent'];out=raw
 for a,b in p['helper_edits']:out=one(out,a,b)
 C.need(out.count(b"if __name__=='__main__':")==1,'one held compiler6 default CLI');out=out.replace(b"if __name__=='__main__':",p['helper_append'].encode()+b"\nif __name__=='__main__':",1)
 return out

def transformed(before,products,parent,guard):
 v=dict(before);v['implementation/producer_diagnostic.py']=with_dependency(v['implementation/producer_diagnostic.py']);v.update(products);v['implementation/page-parent.json']=parent;v['implementation/page_source.py']=guard;v['implementation/run.py']=run_body(v['implementation/run.py']);v['implementation/source_guard.py']=one(v['implementation/source_guard.py'],' import tooling_source\n return tooling_source.verify()',' import page_source\n return page_source.verify()');v['implementation/workflow-template.yml']=with_mode(v['implementation/workflow-template.yml'])
 old="template=__import__('tooling_source').with_tooling(__import__('compiler6_source').with_compiler6(__import__('cache_controls_context').with_cache(workflow.derive(old))));self.assertEqual";new="template=__import__('page_source').with_mode(__import__('tooling_source').with_tooling(__import__('compiler6_source').with_compiler6(__import__('cache_controls_context').with_cache(workflow.derive(old)))));self.assertEqual";v['implementation/test_source.py']=one(v['implementation/test_source.py'],old,new);v['README.md']+=DOC.encode();v['implementation/compiler6.py']=with_dependency_cache_helper(v['implementation/compiler6.py']);v['implementation/compiler6-profile.json']=C.enc(json.loads(parent)['dependency_cache_parent']['profile']);m=json.loads(v['source-manifest.json']);m['files']={n:C.pin(raw)for n,raw in v.items()if n not in('source-manifest.json',*ALIASES)};v['source-manifest.json']=C.enc(m)
 for n in ALIASES:v[n]=v['implementation/workflow-template.yml'].replace(b'@FRESH607_MANIFEST@',C.pin(v['source-manifest.json'])['sha256'].encode())
 return v

def page_binding_parent(p):
 """Reconstruct the entire immediate parent's DATA, not a second tree."""
 prior=engine_before_parent(p);binding=prior.pop('page_adapter_binding_parent');prior['guard_template']=binding['guard_template'];prior['products']['implementation/page_mode.py']=binding['product_before']
 for path,names in binding['added_before_bodies'].items():
  target=prior
  for key in path.split('.'):target=target[key]
  for name in names:target.pop(name)
 return prior

def page_binding_body(raw,p):
 for before,after in reversed(p['page_adapter_binding_parent']['mode_edits']):raw=one(raw,after,before)
 C.need(C.pin(raw)==p['page_adapter_binding_parent']['files']['implementation/page_mode.py'],'whole original page helper before body');return raw

def verify():
 raw=C.read(C.HERE/'page-parent.json');C.need(C.pin(raw)['sha256']==PARENT_SHA,'entire page parent1197 context');p=json.loads(raw);before={}
 for n,w in p['files'].items():
  b=p['before_bodies'][n].encode()if n in p['before_bodies']else C.read(C.ROOT/n);C.need(C.pin(b)==w,'complete1197 body inverse '+n);before[n]=b
 C.need(len(before)==1197 and C.pin(C.read(C.HERE/'page_source.py').replace(PARENT_SHA.encode(),b'@PARENT_'+b'SHA@'))==p['guard_template'],'whole1197/currentguard template');products={n:C.checked(C.ROOT/n,w)for n,w in p['products'].items()};expected=transformed(before,products,raw,C.read(C.HERE/'page_source.py'));actual={q.relative_to(C.ROOT).as_posix():C.pin(C.read(q))for q in C.ROOT.rglob('*')if q.is_file()and'.git'not in q.relative_to(C.ROOT).parts};C.need(actual=={n:C.pin(b)for n,b in expected.items()},'complete1203 finite source-only page selector')
 r=p['engine_failure_parent']['realtime_initialization'];C.need(r['source']=='087c70e68251ada1454ea5a8b9d7b52332dbdffa'and r['files']==r['git']['files']and r['source']==r['git']['source']==r['publication']['source'],'whole genuine087c source before realtime correction')
 C.need(r['scope']=='SOURCE_OWNED_SELECTED16K_REALTIME_CURRENT_HOST_LAUNCH_NONCE_SOURCE_RUN_WORKSPACE_NO_GPG_WAIVER'and all(r[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'closed owned guest clock scope and NULL actuals')
 restored_realtime={n:realtime_before_body(n,p)for n in r['files']};prior_realtime=realtime_before_parent(p);C.need(len(restored_realtime)==1203 and{n:C.pin(b)for n,b in restored_realtime.items()}==r['files'],'whole087c realtime-before source inverse')
 C.need(C.pin(restored_realtime['implementation/page_source.py'].replace(r['files']['implementation/page-parent.json']['sha256'].encode(),b'@PARENT_'+b'SHA@'))==prior_realtime['guard_template'],'whole original087c guard template')
 e=p['engine_failure_parent'];C.need(e['source']=='7bbdfc679712301f19da3f175ebc0275b2922138'and e['files']==e['git']['files']and e['source']==e['git']['source']==e['publication']['source'],'whole published engine diagnostic parent1203')
 C.need(e['scope']=='GENERIC16K_EXACT_NUMERIC_PLATFORM_AND_RETURNED_ENGINE_DATA_NO_ACCEPTANCE'and all(e[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'source-only engine diagnostic authority')
 restored_engine={n:engine_before_body(n,p)for n in e['files']};C.need(len(restored_engine)==1203 and{n:C.pin(b)for n,b in restored_engine.items()}==e['files'],'whole original1203 engine diagnostic before inverse')
 qraw=e['qualification']['text'].encode();C.need(C.pin(qraw)==e['qualification']['pin'],'complete original1203 SOURCE receipt');q=json.loads(qraw);C.need(q['status']=='PASS'and q['exit']==0 and q['cap']==300 and not q['timeout']and q['source']==e['files']and all(q[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'source fact only after entire1203 inverse')
 a=e['authentication_diagnostic'];C.need(a['source']==a['git']['source']==a['publication']['source']and a['files']==a['git']['files'],'whole actual numeric source417c')
 prior=realtime_before_parent(p);prior['engine_failure_parent'].pop('authentication_diagnostic');prior['guard_template']=a['guard_template']
 for k,v in a['engine_fields_before'].items():prior['engine_failure_parent'][k]=v
 for n,w in a['products_before'].items():prior['products'][n]=w
 restored_auth={}
 for n in a['files']:
  if n=='implementation/page-parent.json':body=C.enc(prior)
  elif n in a['before_bodies']:body=a['before_bodies'][n].encode()
  elif n=='implementation/page_source.py':body=one(one(realtime_before_body(n,p),r['files']['implementation/page-parent.json']['sha256'],a['files']['implementation/page-parent.json']['sha256']),a['guard_proof'],'')
  elif n=='source-manifest.json':m=json.loads(C.read(C.ROOT/n));m['files']={q:a['files'][q]for q in m['files']};body=C.enc(m)
  elif n in ALIASES:body=one(realtime_before_body(n,p),r['files']['source-manifest.json']['sha256'],a['files']['source-manifest.json']['sha256'])
  else:body=realtime_before_body(n,p)
  restored_auth[n]=body
 C.need(len(restored_auth)==1203 and {n:C.pin(b)for n,b in restored_auth.items()}==a['files'],'whole417c before authentication DATA inverse')
 binding=p['page_adapter_binding_parent'];C.need(binding['source']=='ddfc78e30552356baa94fa123f17fd33efc2aedc'and binding['files']==binding['git']['files']and binding['publication']['source']==binding['git']['source']==binding['source'],'whole genuine immediate1203 parent')
 C.need(binding['scope']=='EARLY_CURRENT607_ADAPTER_CAPTURE_ONLY_ALL_RUNTIME_BODIES_HELD'and all(binding[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'page import binding source-only authority')
 prior_parent=page_binding_parent(p);restored_binding={};helper_before=page_binding_body(engine_before_body('implementation/page_mode.py',p),p)
 for n,w in binding['files'].items():
  if n=='implementation/page-parent.json':body=C.enc(prior_parent)
  elif n=='implementation/page_mode.py':body=helper_before
  elif n=='implementation/page_source.py':
   body=engine_before_body(n,p);seal=p['engine_failure_parent']['files']['implementation/page-parent.json']['sha256'];C.need(body.count(seal.encode())==1,'one original page guard seal');body=body.replace(seal.encode(),binding['files']['implementation/page-parent.json']['sha256'].encode(),1)
   for before_edit,after_edit in reversed(binding['guard_edits']):body=one(body,after_edit,before_edit)
  elif n=='source-manifest.json':
   m=json.loads(C.read(C.ROOT/n));m['files']={name:binding['files'][name]for name in m['files']};body=C.enc(m)
  elif n in ALIASES:body=one(engine_before_body(n,p),p['engine_failure_parent']['files']['source-manifest.json']['sha256'],binding['files']['source-manifest.json']['sha256'])
  else:body=engine_before_body(n,p)
  C.need(C.pin(body)==w,'whole immediate1203 page binding before inverse '+n);restored_binding[n]=body
 C.need(len(restored_binding)==1203 and C.pin(restored_binding['implementation/page_source.py'].replace(binding['files']['implementation/page-parent.json']['sha256'].encode(),b'@PARENT_'+b'SHA@'))==prior_parent['guard_template'],'whole original1203 guard selfseal')
 qraw=binding['qualification']['text'].encode();C.need(C.pin(qraw)==binding['qualification']['pin'],'whole original1203 SOURCE receipt');q=json.loads(qraw);C.need(q['status']=='PASS'and q['exit']==0 and q['cap']==300 and not q['timeout']and q['source']==binding['files']and all(q[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'prior pure SOURCE fact only after complete before inverse')
 c=p['dependency_cache_parent'];C.need(c['source']=='15eed0d72b793117e0a44e670567acea63c2819c'and c['files']==c['git']['files']and c['git']['source']==c['publication']['source']==c['source'],'entire genuine dependency diagnostic1203 source')
 prior_parent=page_binding_parent(p);prior_parent.pop('dependency_cache_parent');prior_parent['guard_template']=c['parent_seam']['guard_template']
 for path,names in c['parent_seam']['added_before_bodies'].items():
  target=prior_parent
  for key in path.split('.'):target=target[key]
  for name in names:target.pop(name)
 restored_cache={n:(C.enc(prior_parent)if n=='implementation/page-parent.json'else c['before_bodies'][n].encode()if n in c['before_bodies']else engine_before_body(n,p))for n in c['files']}
 C.need(len(restored_cache)==1203 and{n:C.pin(b)for n,b in restored_cache.items()}==c['files'],'complete old1203 cache-before inverse, including exact old parent DATA')
 oldg=restored_cache['implementation/page_source.py'];C.need(C.pin(oldg.replace(C.pin(restored_cache['implementation/page-parent.json'])['sha256'].encode(),b'@PARENT_'+b'SHA@'))==prior_parent['guard_template'],'whole old1203 guard template held')
 qraw=c['qualification']['text'].encode();C.need(C.pin(qraw)==c['qualification']['pin'],'exact retained old1203 source-only qualification');q=json.loads(qraw);C.need(q['status']=='PASS'and q['exit']==0 and q['cap']==300 and not q['timeout']and q['source']==c['files']and q['actual_source']is q['actual_ref']is q['actual_run']is None,'old source fact only after whole before inverse')
 import compiler6
 compiler6.dependency_configuration();C.need(C.enc(compiler6.configuration())==C.enc(c['profile']),'exact selected helper/profile and all old compiler predicates held')
 d=p['dependency_parent'];C.need(d['source']=='3160eaa23a25275a9a341874b528b60b69e4f8cb'and d['files']==d['git']['files']and d['git']['source']==d['publication']['source']==d['source']and d['ref']==d['publication']['ref']==d['git']['ref'],'exact whole published1203 source context');qr=d['qualification']['text'].encode();C.need(C.pin(qr)==d['qualification']['pin'],'whole prior1203 qualification history');q=json.loads(qr);C.need(q['status']=='PASS'and q['exit']==0 and q['cap']==300 and not q['timeout']and q['current_actual']is None,'prior1203 pure source fact only')
 restored_dependency={n:(d['before_bodies'][n].encode()if n in d['before_bodies']else engine_before_body(n,p))for n in d['files']};C.need(len(restored_dependency)==1203 and{n:C.pin(b)for n,b in restored_dependency.items()}==d['files'],'entire published1203 dependency diagnostic before inverse')
 oldp=json.loads(restored_dependency['implementation/page-parent.json']);oldg=restored_dependency['implementation/page_source.py'];oldsha=C.pin(restored_dependency['implementation/page-parent.json'])['sha256'];C.need(C.pin(oldg.replace(oldsha.encode(),b'@PARENT_'+b'SHA@'))==oldp['guard_template']and oldp['files']==p['files'],'complete original1203 guard/template and1197 ancestry held')
 s=p['scope_parent'];qraw=s['qualification']['text'].encode();C.need(C.pin(qraw)==s['qualification']['pin'],'complete original1203 source qualification');q=json.loads(qraw);C.need(q['status']=='PASS'and q['exit']==0 and q['cap']==300 and 0<q['seconds']<300 and q['current_actual']is None and q['API']is False and q['native']is False,'original1203 source history only')
 restored={n:(s['before_bodies'][n].encode()if n in s['before_bodies']else engine_before_body(n,p))for n in s['files']};C.need(len(restored)==1203 and{n:C.pin(b)for n,b in restored.items()}==s['files'],'entire original1203 finite scope inverse')
 op=json.loads(restored['implementation/page-parent.json']);og=restored['implementation/page_source.py'];C.need(C.pin(og.replace(C.pin(restored['implementation/page-parent.json'])['sha256'].encode(),b'@PARENT_'+b'SHA@'))==op['guard_template']and op['files']==p['files'],'old1203 guard selfseal and complete1197 parent held');import page_mode
 for n in page_mode.edits():
  import adapter
  old=adapter.transform(before['parent604/'+n],n)[0];new=page_mode.transform(old,n);C.need(new!=old,'one explicit16K operand body')
 saved,paths=dict(sys.modules),list(sys.path)
 with tempfile.TemporaryDirectory(prefix='fresh607-whole1197-')as td:
  root=Path(td)/'source';root.mkdir(mode=0o700)
  for n,b in before.items():q=root/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b)
  try:
   for n in{q.stem for q in(root/'implementation').glob('*.py')}:sys.modules.pop(n,None)
   sys.path.insert(0,str(root/'implementation'));s=importlib.util.spec_from_file_location('source_guard',root/'implementation/source_guard.py');g=importlib.util.module_from_spec(s);sys.modules['source_guard']=g;s.loader.exec_module(g);fact=g.verify();C.need(fact['files']==1197 and fact['status']=='PASS_SOURCE_ONLY_EXACT_ORIGINAL35_TOOLING_INPUT_PREPARATION','exact full1197 guard executes once, all older gates')
  finally:
   sys.path[:]=paths
   for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
   sys.modules.update(saved)
  C.need({n:C.pin(C.read(root/n))for n in before}==p['files'],'whole1197 private source preserved')
 C.need(actual=={q.relative_to(C.ROOT).as_posix():C.pin(C.read(q))for q in C.ROOT.rglob('*')if q.is_file()and'.git'not in q.relative_to(C.ROOT).parts},'current page source unchanged');return dict(fact,status='PASS_SOURCE_ONLY_EXPLICIT_GENERIC16K_KEEP_4K_DEFAULT',files=len(actual),parent_files=1197,default='generic4k',optional='generic16k',page_size=16384,kernel_input='BUILD_ONLY_NOT_BOOT',generic16k_fit='NOT_ESTABLISHED',actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None,hardware='NOT_RUN',dependency_diagnostic='FAILURE_ONLY_EXACT180_ROLE_EXISTING_REPORT',numeric_platform_binding='EXACT_PRIVATE_RAW_SOURCE_KERNEL_PAGE_16K_DEFAULT4K_HELD')


def engine_before_parent(p):
 prior=json.loads(C.enc(p));e=prior.pop('engine_failure_parent');prior['guard_template']=e['guard_template']
 for name,row in e['products_before'].items():prior['products'][name]=row
 return prior

def engine_before_body(name,p):
 e=p['engine_failure_parent']
 if name=='implementation/page-parent.json':return C.enc(engine_before_parent(p))
 if name in e['before_bodies']:return e['before_bodies'][name].encode()
 raw=realtime_before_body(name,p)
 if name=='implementation/page_source.py':
  raw=one(raw,p['engine_failure_parent']['realtime_initialization']['files']['implementation/page-parent.json']['sha256'],e['files']['implementation/page-parent.json']['sha256'])
  C.need(raw.endswith(e['guard_append'].encode()),'exact finite guard footer inverse');raw=raw[:-len(e['guard_append'].encode())]
  for a,b in reversed(e['guard_edits']):raw=one(raw,b,a)
 elif name=='source-manifest.json':
  m=json.loads(raw);m['files']={n:e['files'][n]for n in m['files']};raw=C.enc(m)
 elif name in ALIASES:raw=one(raw,p['engine_failure_parent']['realtime_initialization']['files']['source-manifest.json']['sha256'],e['files']['source-manifest.json']['sha256'])
 return raw


def realtime_before_parent(p):
 prior=json.loads(C.enc(p));r=prior['engine_failure_parent'].pop('realtime_initialization');prior['guard_template']=r['guard_template']
 for n,w in r['products_before'].items():prior['products'][n]=w
 return prior

def realtime_before_body(name,p):
 r=p['engine_failure_parent']['realtime_initialization']
 if name=='implementation/page-parent.json':return C.enc(realtime_before_parent(p))
 raw=C.read(C.ROOT/name)
 if name in('implementation/page_mode.py','implementation/test_page_mode.py'):
  role='mode'if name.endswith('page_mode.py')and not name.endswith('test_page_mode.py')else'test';append=r[role+'_append'].encode()
  if role=='mode':C.need(raw.endswith(append)and append,'whole current16K clock helper append inverse');raw=raw[:-len(append)]
  else:raw=one(raw,append.decode()+"\nif __name__=='__main__':\n","if __name__=='__main__':\n")
  for a,b in reversed(r[role+'_edits']):raw=one(raw,b,a)
 elif name=='implementation/page_source.py':
  raw=one(raw,PARENT_SHA,r['files']['implementation/page-parent.json']['sha256']);append=r['guard_append'].encode();C.need(raw.endswith(append)and append,'whole current realtime guard append');raw=raw[:-len(append)]
  for a,b in reversed(r['guard_edits']):raw=one(raw,b,a)
 elif name=='source-manifest.json':
  m=json.loads(raw);m['files']={n:r['files'][n]for n in m['files']};raw=C.enc(m)
 elif name in('implementation/workflow-template.yml',*ALIASES):
  for a,b in reversed(r['workflow_edits']):raw=one(raw,b,a)
  if name in ALIASES:raw=one(raw,C.pin(C.read(C.ROOT/'source-manifest.json'))['sha256'],r['files']['source-manifest.json']['sha256'])
 C.need(C.pin(raw)==r['files'][name],'whole087c member before realtime correction '+name)
 return raw

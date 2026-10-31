# SPDX-License-Identifier: MIT
"""Explicit readable39→40→41 source composition; no native or graph authority."""
import ast,base64,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes':257956,'sha256':'9a7221702da6a8932664ba3c1afd7b1206d5b6a30d2ddbb7efb3acfe4b8c9c85'}
WORKFLOWS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml')
def inputs(api):
 need,pin,read,source,enc=(api[k]for k in('need','pin','read','source','encoded'));need(not sys.flags.optimize,'source checks require ordinary Python');raw=read(HERE/'tpm-acl-profile.json');need(pin(raw)==PROFILE,'whole fixed Core41 factory profile');p=json.loads(raw)
 need(p['kind']=='SOURCE_ONLY_EXPLICIT_CORE41_TYPED_TPM_ACL_FACTORY'and p['actual']is None and p['actual_acceptance']is False and p['source_after']=='29a60eeaf45fad954ffa0932c8559192a911c298','exact source-only41 identity')
 text=read(HERE/'prepare.py').decode();held={n.name:pin(ast.get_source_segment(text,n).encode())for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name in p['held_factory_functions']};need(held==p['held_factory_functions']and len(held)==25,'all25 prior factory function bodies held')
 research=source(HERE/'tpm-acl-research',p['research']);primary=json.loads(research['primary-pins.json'])
 need(all(pin(research[n])=={k:v[k]for k in('bytes','sha256')}and v['url'].startswith('https://raw.githubusercontent.com/')for n,v in primary.items()),'all pinned primary research and licensing bytes')
 need(b'BSD-2-Clause'in research['TPM-REUSE.toml']and b'Redistribution and use'in research['TPM-LICENSE'],'full TPM redistribution notices retained')
 custody=source(HERE/'tpm-acl-custody',p['custody']);freeze=json.loads(custody['author-freeze.json']);proof=json.loads(custody['Root-author-freeze-proof.json']);need(proof['freeze']==pin(custody['author-freeze.json'])and proof['source_files']==41 and proof['frozen_files']==len(freeze['files'])==156 and freeze['proposed']==p['stages']['41']['after'],'whole original author/source-control freeze Root join')
 for version in('312','314'):
  audit=json.loads(custody['audit'+version+'.json']);controls=json.loads(custody['controls'+version+'.json']);need(audit['formal_unique_tests']==64 and audit['source_files']==41 and audit['parent_files']==40 and audit['ancestor_files']==39 and audit['acceptance']is False and audit['actual']is None and controls['tests']==63 and all(r['exit']==0 for r in controls['rows'])and audit['tests'][version]['result']==pin(custody['controls'+version+'.json'])and b'Ran 2 tests in'in custody['formal'+version+'.stderr']and custody['formal'+version+'.stderr'].endswith(b'OK\n'),'whole frozen64 unique source controls, no replay or acceptance')
 q=json.loads(custody['qualification-status.json']);v=json.loads(custody['qualification-result.json']);need(q['exit']==0 and q['host_cap']==300 and q['seconds']==p['whole_source_qualification_reused_seconds']and q['actual']is None and q['Root_acceptance']=='NOT_ISSUED'and v==dict(actual=None,native='NOT_RUN',source=p['source_after'],status='PASS_FULL_ORIGINAL800_AND_CLOSED_TWO_BOOT_SOURCE_ONLY'),'exact prior whole-source qualification custody, never new native authority')
 parent,bodies=api['fresh_graph_inputs']();need({n:pin(b)for n,b in bodies.items()}==p['base']and len(bodies)==39,'whole genuine39 base before either successor')
 for number,module in [('40','xattr_diagnostic.py'),('41','acl_policy.py')]:
  stage=p['stages'][number];prior=dict(bodies);need({n:pin(b)for n,b in prior.items()}==stage['before'],'entire immediate parent before successor'+number);payload=source(HERE/'tpm-default-acl'/number,stage['payload']);bodies.update(payload)
  manifest=enc(dict(schema=1,purpose='CORE7_REAL_HOOKS_AND_ACTUAL_PID1_SOURCE_ONLY',actual=None,files={n:pin(b)for n,b in bodies.items()if n!='source-manifest.json'and not n.startswith('.github/')}));bodies['source-manifest.json']=manifest;workflow=bodies['workflow.yml.in'].replace(b'@ENTRY_SHA@',pin(bodies['entry.py'])['sha256'].encode()).replace(b'@MANIFEST_SHA@',pin(manifest)['sha256'].encode())
  for name in WORKFLOWS:bodies[name]=workflow
  need({n:pin(b)for n,b in bodies.items()}==stage['after']and len(bodies)==int(number)and {n:w for n,w in stage['before'].items()if stage['after'].get(n)==w}==stage['held'],'whole exact successor and genuinely held membership'+number)
  edits=next(ast.literal_eval(n.value)for n in ast.parse(bodies[module]).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='INVERSES'for t in n.targets))
  for name,pairs in edits.items():
   text=bodies[name].decode()
   for before,after in reversed(pairs):need(text.count(after)==1,'one counted full source inverse seam');text=text.replace(after,before,1)
   need(text.encode()==prior[name],'entire counted parent function/source body inverse')
  restored={n:b for n,b in bodies.items()if n in stage['before']}
  for name,row in stage['changed'].items():
   if row['before']is not None:restored[name]=base64.b64decode(row['before_base64'],validate=True);need(pin(restored[name])==row['before'],'whole parent before body')
  need(restored==prior,'complete immediate parent namespace and every byte restored')
 for number in('39','40','41'):
  pub=p['publication_custody'][number];need(pub['publication']['status']=='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE'and pub['git']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=pub['publication']['source'],ref=pub['publication']['ref'],files=p['base']if number=='39'else p['stages'][number]['after'])and pub['publication']['files']==pub['publication']['git_joins']==int(number),'whole genuine source publication/Git custody')
 schema=p['schema'];need(schema['old_closed_schema_held']is False and schema['typed_value_required']is True and set(schema['parent_keys'])=={'complete','nodes','security_capabilities','mounts','excluded'}and set(schema['keys'])==set(schema['parent_keys'])|{'posix_acl_defaults'}and schema['phase1_before']=='REQUIRED_EMPTY_MAP'and schema['later_stages']==['baseline-automatic','phase1-installed','phase2-before']and schema['later_required_path']=='var/lib/tpm2-tss/system/keystore'and schema['unknown_access_or_user_attrs']=='REFUSE','explicit new typed ACL positive schema AND original security predicates; old closed schema is changed')
 need(all(b"__import__('acl_policy').check_graph("in bodies[n]for n in('guest.py','validate.py')),'both live graph and passive graph require new ACL positive schema')
 return p,bodies

def result(p,unbound=False):
 if type(unbound)is not bool:raise ValueError('explicit boolean receipt mode')
 return dict(status='SOURCE_ONLY_EXACT_CORE41_TYPED_TPM_ACL_NOT_NATIVE_ACCEPTANCE',files=41,source=None if unbound else p['source_after'],ref=None if unbound else p['ref_after'],expected_fixture_source=p['source_after'],authority=p['receipt_modes']['unbound'if unbound else'known'],actual=None,run=None,acceptance=False,native='NOT_RUN',Asahi='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED',old_closed_schema_held=False)

def emit(api,output,unbound=False,authorization=None):
 need,ordinary,source,enc=(api[k]for k in('need','ordinary','source','encoded'));need(type(unbound)is bool,'explicit boolean receipt mode')
 output=ordinary(output);authorization=None if authorization is None else ordinary(authorization)
 for path in(output,*(()if authorization is None else(authorization,))):need(path==path.resolve()and path.parent.is_dir()and not os.path.lexists(path)and not path.is_relative_to(HERE)and not HERE.is_relative_to(path),'fresh canonical ordinary output/authorization outside factory')
 if authorization is not None:need(not authorization.is_relative_to(output)and not output.is_relative_to(authorization),'separate fresh authorization before any write')
 p,bodies=inputs(api);value=result(p,unbound);output.mkdir(mode=0o700)
 for name,raw in sorted(bodies.items()):
  path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 need(source(output,p['stages']['41']['after'])==bodies,'whole exact emitted41 bytes, all actuals NULL')
 if authorization is not None:
  with authorization.open('xb')as stream:stream.write(enc(value))
 return value

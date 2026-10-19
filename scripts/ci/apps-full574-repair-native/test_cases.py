# SPDX-License-Identifier: MIT
"""Finite inert case routing/data rejection and real ordinary-leaf retention."""
import ast,base64,copy,hashlib,importlib.util,json,os,stat,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
K=load('case_checks',HERE/'checks.py');P=load('case_prepare',HERE/'prepare.py')
def need(ok,why):
 if not ok:raise ValueError(why)
def case(v):
 need(type(v) is str and v in ('repair-bytes','repair-missing'),'explicit case');return v
def definition(name,path,space):
 text=path.read_text();n=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name);exec(compile(ast.get_source_segment(text,n),str(path)+':inert','exec'),space);return space[name]
def controlC():
 return types.SimpleNamespace(need=need,case=case,read=lambda p,cap:p.read_bytes(),sha=lambda raw:hashlib.sha256(raw).hexdigest(),decode=json.loads,safe=lambda p:need(not any(q.is_symlink() for q in (p,*p.parents)),'alias'))
class Cases(unittest.TestCase):
 def test_finite_choice_is_required_and_source_owned(self):
  for name in ('job.py','supervise.py'):
   text=(HERE/name).read_text();tree=ast.parse(text);m=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main');self.assertIn("add_argument('--case',choices=('repair-bytes','repair-missing'),required=True)",ast.get_source_segment(text,m))
  policy=json.loads((HERE/'policy.json').read_bytes());self.assertEqual(policy['cases'],['repair-bytes','repair-missing']);self.assertEqual(policy['status'],'UNBOUND');self.assertEqual(policy['aggregate'],'BOTH_INDEPENDENT_ROOT_CASE_DECISIONS_REQUIRED')
 def test_workflow_has_one_required_choice_and_five_joined_invocations(self):
  # Pure generated wiring from the frozen original workflow, located by source pins.
  rows=json.loads((HERE/'source-pins.json').read_bytes())['files'];source=next((q for p in HERE.parents for q in (p,p/'source') if all((q/n).is_file() and P.pin((q/n).read_bytes())==r for n,r in rows.items())),None)
  self.assertIsNotNone(source);text=P.workflow((source/'.github/workflows/native-arm-apps-full574-transaction.yml').read_text());self.assertEqual(text.count('--case "$REPAIR_CASE" --source "$GITHUB_WORKSPACE"'),5);self.assertIn('        type: choice\n        required: true\n        options:\n          - repair-bytes\n          - repair-missing',text);self.assertIn('REPAIR_CASE: ${{ inputs.repair_case }}',text)
  for bound in ('3550s','650s','2300s'):self.assertIn(bound,text)
 def test_singleton_case_loop_retains_exact_original_body(self):
  text=(HERE/'lifecycle.py').read_text();tree=ast.parse(text);main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main');loop=next(n for n in ast.walk(main) if isinstance(n,ast.For) and ast.unparse(n.target)=='(label, missing)')
  for value in ('repair-bytes','repair-missing'):
   selected=eval(compile(ast.Expression(loop.iter),'<finite-case>','eval'),{'case':value});self.assertEqual(selected,((value,value=='repair-missing'),))
  body=ast.get_source_segment(text,loop);self.assertIn('preparation=inspected(',body);self.assertIn("H.backend('inspect',workspace,owner),expected=1",body);self.assertIn('repaired(calls.call(attempts),damage_map)',body)
  self.assertIn("value['counts']==[578,575,574]",(HERE/'checks.py').read_text());self.assertIn("'wrong-plan-sha'",text);self.assertIn("'unselected-damage'",text);self.assertIn("'foreign-alpm-lock'",text)
 def test_original_owner_actor_budgets_caps_mounts_conserved(self):
  rows=json.loads((HERE/'source-pins.json').read_bytes())['files'];source=next((q for p in HERE.parents for q in (p,p/'source') if all((q/n).is_file() and P.pin((q/n).read_bytes())==r for n,r in rows.items())),None)
  text=(source/'scripts/ci/apps-full574-native/job.py').read_text();space={'C':controlC(),'ast':ast};definition('function',HERE/'job.py',space);definition('replace',HERE/'job.py',space);derived=definition('derived',HERE/'job.py',space)(text)
  original=space['function'](text,'actor');expected=original.replace(" row=reserve(report,output,role);"," C.case(report['case'])\n row=reserve(report,output,role);").replace(" argv+=['--entrypoint=/usr/bin/python3'"," if role=='lifecycle':argv+=['--env=CACHY_APPS574_REPAIR_CASE='+report['case']]\n argv+=['--entrypoint=/usr/bin/python3'")
  self.assertEqual(derived['actor'],expected);self.assertIn('3000 if role',derived['actor']);self.assertIn("'--cap-add=SETFCAP'",derived['actor']);self.assertIn("copy(args.proof.parent/'apps574-repair-handoff-diagnostic.json'",derived['retain'])
 def test_one_case_retained_inspection_rejects_cross_case_or_combined(self):
  C=controlC()
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);raw=b'{"original":"readonly"}';name='repair-bytes-inspection.json';(root/name).write_bytes(raw);pin=dict(path=name,**P.pin(raw));v=dict(case='repair-bytes',preparations={'repair-bytes':json.loads(raw)},inspection_files={'repair-bytes':pin});files={'lifecycle-public/'+name:P.pin(raw)};K.retained(C,v,root,files)
   for other in ('repair-missing','combined',None):
    with self.assertRaises(ValueError):K.retained(C,dict(v,case=other),root,files)
   bad=copy.deepcopy(v);bad['inspection_files']['repair-missing']=pin
   with self.assertRaises(ValueError):K.retained(C,bad,root,files)
 def test_real_inventory_success_publication_and_identity_conflicts(self):
  C=controlC()
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);work=root/'work';out=root/'out';work.mkdir();out.mkdir();source=work/'repair-bytes-inventory.json';raw=b'{"actual":"inventory bytes"}\n';source.write_bytes(raw);source.chmod(0o600);published=[]
   def original(path,summary):
    need(summary==P.pin(raw),'exact successful summary');target=out/path.name;fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw)
    published.append(target);return raw
   # Real local FS; chown to current caller is permitted. Production requires ordinary UID>0.
   uid,gid=os.getuid(),os.getgid();space=dict(C=C,H=types.SimpleNamespace(retain_inventory=original),WORK=work,OUT=out,os=os,stat=stat);fn=definition('publish_inventory',HERE/'lifecycle.py',space)
   env=dict(CACHY_APPS574_REPAIR_CASE='repair-bytes',OUTPUT_UID=str(uid),OUTPUT_GID=str(gid))
   if uid==0 or gid==0:self.skipTest('ordinary host caller required for ownership publication control')
   with patch.dict(os.environ,env):
    self.assertEqual(fn(source,P.pin(raw)),raw);target=published[0];info=target.lstat();self.assertEqual((info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)),(uid,gid,0o600));self.assertEqual(target.read_bytes(),raw)
    with self.assertRaises(FileExistsError):fn(source,P.pin(raw))
    for name in ('foreign-inventory.json','repair-missing-inventory.json','private.gpg'):
     with self.assertRaises(ValueError):fn(work/name,P.pin(raw))
 def test_real_private_diagnostic_write_is_fresh_bounded_and_mode0600(self):
  C=controlC();C.encoded=P.encoded;space=dict(C=C,os=os,stat=stat);fn=definition('save_diagnostic',HERE/'supervise.py',space)
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'diagnostic.json';value={'status':'DIAGNOSTIC_ONLY'};fn(p,value);self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600);self.assertEqual(json.loads(p.read_bytes()),value)
   with self.assertRaises(FileExistsError):fn(p,value)
   q=Path(td)/'oversize'
   with self.assertRaises(ValueError):fn(q,{'bounded':'x'*32768})
   self.assertFalse(q.exists())
 def test_result_requires_one_explicit_case_and_four_genuine_commits(self):
  I=load('case_readonly_fixture',HERE/'test_inspection.py');C=controlC();C.VERSIONS=json.loads((HERE/'policy.json').read_bytes())['versions'];caps='d'*64;target='usr/share/doc/cachy-asahi-apps/README.md'
  def committed(add,remove,operation):
   return dict(status='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION',dependency_checks='ORDINARY_LIBALPM',cleanup='OWNED_WORKSPACE_TEMP_AND_ALPM_HANDLE_LOCK_RELEASED',rollback='NOT_ATTEMPTED_DISPOSABLE_COPY_ONLY',commit_started=True,packages_committed=True,prepared_add=add,prepared_remove=remove,operation=operation,full574_closure=dict(status='PASS-recorded-state-preserved',main_cache='RAW_EQUAL',auxiliary_transition={'kind':'RAW_EQUAL'},auxiliary_inode_liveness='NOT_ESTABLISHED_SOURCE_SNAPSHOT_KEYS',security_capabilities='EXACT_SOURCE_MAP_PRESERVED',source_capabilities_sha256=caps))
  for selected_case in ('repair-bytes','repair-missing'):
   before=I.receipt();before.update(source_tree_sha256='e'*64,capabilities_sha256=caps,full574_binding={'source_capabilities_sha256':caps});before['damage']={target:None if selected_case=='repair-missing' else {'type':'file'}}
   repair=committed({'cachy-asahi-apps':'0.1.0-6'},{},'reinstall');repair.update(plan_sha256=before['plan_sha256'],before=before['before']);repair['full574_closure']['repair']=dict(status='SELECTED_SIGNED_ORDINARY_LEAVES_RESTORED',scope='AUTHENTICATED_SAME_VERSION_ORDINARY_FILE_BYTES_OR_MISSING_LEAF_ONLY',selected=['cachy-asahi-apps'],archives=before['archives'],plan_sha256=before['plan_sha256'],before_damage=before['damage'])
   value=dict(status='PASS_NATIVE574_AUTHENTICATED_SELECTED_REPAIR_CASE',case=selected_case,aggregate='BOTH_INDEPENDENT_ROOT_CASE_DECISIONS_REQUIRED',base_count=574,counts=[578,575,574],hardware='NOT_RUN',rollback='NOT_CLAIMED',source_preserved=True,workspaces_disposed=True,user_trust_protected_preserved=True,original_user_nodes=1,source_capabilities_sha256=caps,source_tree_sha256='e'*64,security_capabilities='EXACT_SOURCE_MAP_PRESERVED',transactions=[committed(C.VERSIONS,{},'install'),committed({},{n:v for n,v in C.VERSIONS.items() if n!='cachy-asahi-repository-runtime'},'remove'),committed({},{'cachy-asahi-repository-runtime':'0.1.0-1'},'remove')],repairs={selected_case:repair},preparations={selected_case:before},refusals={n:dict(status='FAIL',commit_started=False,packages_committed=False) for n in (selected_case+'-default-inspect','wrong-plan-sha','unselected-damage','foreign-alpm-lock')})
   self.assertIs(K.result(C,value),value)
   for mutation in (dict(case='combined'),dict(case='repair-missing' if selected_case=='repair-bytes' else 'repair-bytes'),dict(aggregate='PASS_ALL_CASES'),dict(counts=[578,574]),dict(transactions=value['transactions'][:-1])):
    with self.assertRaises(ValueError):K.result(C,dict(value,**mutation))
   bad=copy.deepcopy(value);bad['repairs'][selected_case]['packages_committed']=False
   with self.assertRaises(ValueError):K.result(C,bad)
 def test_original_unretired_handoff_is_retained_without_cleanup_authority(self):
  C=controlC();space=dict(C=C,os=os,stat=stat,base64=base64);fn=definition('diagnostic',HERE/'supervise.py',space)
  with tempfile.TemporaryDirectory() as td:
   path=Path(td)/'handoff.json';identity={'case':'repair-bytes'};value=dict(identity=identity,status='FAIL_OUTER_RETIREMENT_UNKNOWN',group_absent=False,direct_reaped=False);raw=json.dumps(value).encode();path.write_bytes(raw);path.chmod(0o600);row=fn(path,identity)
   self.assertEqual(base64.b64decode(row['raw_base64']),raw);self.assertEqual(row['raw_sha256'],C.sha(raw));self.assertFalse(row['cleanup_authority']);self.assertFalse(row['direct_reaped']);self.assertFalse(row['group_absent'])
   for mutation in (dict(identity={'case':'repair-missing'}),dict(group_absent='true')):
    path.write_text(json.dumps(dict(value,**mutation)))
    with self.assertRaises(ValueError):fn(path,identity)
   path.write_bytes(raw);path.chmod(0o644)
   with self.assertRaises(ValueError):fn(path,identity)
 def test_handoff_diagnostic_precedes_unchanged_cleanup_gate(self):
  text=(HERE/'supervise.py').read_text();self.assertLess(text.index('retained=diagnostic('),text.index('original.check('));self.assertIn("original.check(a.handoff,identity,a.job_outcome=='skipped')",text);self.assertIn('os.execv(',text)
if __name__=='__main__':unittest.main(verbosity=2)

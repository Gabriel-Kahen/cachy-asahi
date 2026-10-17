# SPDX-License-Identifier: MIT
"""Finite source/data controls; no native actor, signing or ALPM execution."""
import ast,copy,hashlib,importlib.util,json,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
def load(n,p):
 spec=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(spec);sys.modules[n]=m;spec.loader.exec_module(m);return m
P=load('inspection_source_prepare',HERE/'prepare.py');K=load('inspection_runtime_checks',HERE/'checks.py')
def need(ok,why):
 if not ok:raise ValueError(why)
def receipt():
 return dict(status='INSPECTED_AUTHENTICATED_OWNED_FULL574_REINSTALL',scope='READONLY_AUTHENTICATED_OWNED_FULL574_REINSTALL_PREPARATION',operation='reinstall',selected=['cachy-asahi-apps'],plan_sha256='a'*64,archives={'cachy-asahi-apps':'b'*64},commit_started=False,packages_committed=False,transaction='NOT_RUN',repair_authority=False,installer_authority=False,root_preserved=True,cleanup='OWNED_TEMP_REMOVED_WORKSPACE_FLOCK_RELEASED',source_preservation='LEASED_READONLY_SOURCE_REVALIDATED',before={n:'c'*64 for n in ('tree_sha256','database_sha256','packages_sha256','inventory_sha256')},damage={'usr/share/doc/cachy-asahi-apps/README.md':None},worker=dict(seconds=600,output_limit=512*1024,returncode=0,termination=None,direct_child_reaped=True,group_kill_sent=True,retirement='ORIGINAL_SUPERVISOR_SIGNALS_GROUP_BEFORE_LEADER_REAP'),auxiliary_preservation=dict(status='PASS-recorded-state-preserved',main_cache='RAW_EQUAL',auxiliary_transition={'kind':'RAW_EQUAL'}))
class Controls(unittest.TestCase):
 def test_exact_supervised_cli_source_rows_and_template_unchanged(self):
  cli=json.loads((HERE/'cli-pins.json').read_bytes())['files'];rows=json.loads((HERE/'source-pins.json').read_bytes())['files'];self.assertEqual(set(cli),{'scripts/apps/repair_inspection.py','scripts/apps/test_repair_inspection.py','scripts/apps/REPAIR_INSPECTION.md'});self.assertTrue(all(rows.get(n)==r for n,r in cli.items()));self.assertEqual(json.loads((HERE/'policy.json').read_bytes())['status'],'UNBOUND')
 def test_explicit_case_uses_genuine_cli_not_fixture_measurement(self):
  text=(HERE/'lifecycle.py').read_text();tree=ast.parse(text);main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main');loop=next(n for n in ast.walk(main) if isinstance(n,ast.For) and ast.unparse(n.target)=='(label, missing)');body=ast.get_source_segment(text,loop)
  self.assertIn('preparation=inspected(',body);self.assertNotIn('observed(',body);self.assertIn("pins=preparation['before']",body);self.assertIn("damage_map=preparation['damage']",body)
  node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='inspected');calls=[];saved={};C=types.SimpleNamespace(need=need,read=lambda p:p.read_bytes(),sha=lambda b:hashlib.sha256(b).hexdigest(),save=lambda p,v:saved.update({p.name:v}),load=lambda n,p:K)
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);planfile=root/'plan';planfile.write_bytes(b'exact caller plan');row=receipt();row['plan_sha256']=C.sha(planfile.read_bytes());names=['apps'];H=types.SimpleNamespace(common=lambda w,o:['--workspace',str(w),'--ownership-sha256',o],credentials=lambda:['--release','/inputs/release/bundle']);Runner=types.SimpleNamespace(call=lambda args:(calls.append(args) or row));space=dict(__file__=str(HERE/'lifecycle.py'),C=C,H=H,SOURCE=root,OUT=root,Path=Path,owned=lambda *a:None);exec(compile(ast.get_source_segment(text,node),'<source-only-inspected>','exec'),space);self.assertEqual(space['inspected'](None,Runner,root,'owner',planfile,{'plan':{'requested_applications':names}},'repair-missing'),row)
   self.assertEqual(calls[0][:3],['/usr/bin/python3','-I','-B']);self.assertEqual(calls[0][4],'inspect-reinstall');self.assertNotIn('--worker',calls[0]);self.assertEqual(saved,{'repair-missing-inspection.json':row})
 def test_inspection_retirement_beforepins_and_readonly_refusals(self):
  C=types.SimpleNamespace(need=need);row=receipt();K.inspection(C,row,'a'*64)
  for patching in (dict(commit_started=True),dict(root_preserved=False),dict(status='OBSERVED_OWNED_COPY'),dict(plan_sha256='d'*64),dict(before={}),dict(repair_authority=True),dict(worker=dict(row['worker'],seconds=610)),dict(worker=dict(row['worker'],termination='timeout'))):
   with self.subTest(change=patching),self.assertRaises(ValueError):K.inspection(C,dict(row,**patching),'a'*64)
 def test_original_retained_json_and_closed_export_hashes_join(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);C=types.SimpleNamespace(need=need,case=lambda v: v if v in ('repair-bytes','repair-missing') else need(False,'case'),read=lambda p,cap:p.read_bytes(),sha=lambda b:hashlib.sha256(b).hexdigest(),decode=json.loads);value=dict(case='repair-missing',preparations={},inspection_files={});files={}
   for label in ('repair-missing',):
    row=receipt();raw=json.dumps(row).encode();name=label+'-inspection.json';(root/name).write_bytes(raw);pin=dict(path=name,**P.pin(raw));value['preparations'][label]=row;value['inspection_files'][label]=pin;files['lifecycle-public/'+name]=P.pin(raw)
   K.retained(C,value,root,files);bad=copy.deepcopy(value);bad['inspection_files']['repair-missing']['path']='../different';
   with self.assertRaises(ValueError):K.retained(C,bad,root,files)
   (root/'repair-missing-inspection.json').write_bytes(b'changed original JSON')
   with self.assertRaises(ValueError):K.retained(C,value,root,files)
if __name__=='__main__':unittest.main(verbosity=2)

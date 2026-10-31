#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Trusted source fixtures, actual installed modules/CLI, temporary TEST GPG only."""
import ast,copy,hashlib,importlib.util,io,json,os,subprocess,sys,unittest
from pathlib import Path

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def command(argv,**kwargs):return subprocess.run(list(map(str,argv)),capture_output=True,text=True,timeout=60,**kwargs)

def run_suite(mode,prefix=Path('/'),fixtures=Path('/runner')):
 runtime=prefix/'usr/share/cachy-asahi/repository-runtime';stream=io.StringIO()
 if mode=='apps':
  actual=prefix/'usr/lib/cachy-asahi-apps';sys.argv=['fixture','--repository-source',str(runtime)]
  fixture=load('trusted_apps16_fixture',fixtures/'fixture-apps/test_apps.py');fixture.a=load('actual_installed_apps16',actual/'apps.py');fixture.HERE=actual
  suite=unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(getattr(fixture,n))for n in ('InventorySectionSetTests','ActualMetadataTests','InventoryTests'));expected=15
 elif mode=='apps-stage':
  actual=prefix/'usr/lib/cachy-asahi-apps';sys.argv=['fixture','--repository-source',str(runtime)]
  fixture=load('trusted_apps16_stage_fixture',fixtures/'fixture-apps/test_diagnostic_stage.py');fixture.A=load('actual_installed_apps16_stage_apps',actual/'apps.py');fixture.I=load('actual_installed_apps16_stage_inventory',actual/'inventory.py');fixture.HERE=actual
  cls=fixture.Controls;suite=unittest.TestSuite(cls(n)for n in('test_actual_isolated_cli_default_and_optin_without_stdout_schema_change','test_real_first_second_scan_mutation_and_original_deadline_refuse','test_original_failed_fsync_removes_output_preserves_failed_phase_and_error','test_stage_existing_link_ancestry_alias_parent_mode_and_foreign_edit_refuse'));expected=4
 elif mode=='client':
  v2=runtime/'scripts/client/client_v2.py';actual=load('actual_installed_client_v2',v2);fixture=load('trusted_client_v2_fixture',fixtures/'fixture-client/test_client_v2.py');fixture.c=actual
  nodes=ast.parse((fixtures/'fixture-client/test_runtime.py').read_bytes());node=next(n for n in nodes.body if isinstance(n,ast.ClassDef)and n.name=='InstalledGPGTests')
  namespace=dict(FIXTURE=fixture,C=actual,V2=v2,STAGE=prefix,sys=sys,json=json,command=command,__name__='installed_client_v2_controls',copy=copy,Path=Path)
  exec(compile(ast.Module(body=[node],type_ignores=[]),'source-pinned InstalledGPGTests','exec'),namespace)
  cls=namespace['InstalledGPGTests'];suite=unittest.TestSuite([cls('test_installed_cli_tilde_signed_lookup_export_tamper_preserves_checkpoint'),cls('test_sources_tilde_version_real_signed_lookup_export_and_tamper_refusal')]);expected=2
 else:raise ValueError('finite installed fixture mode required')
 outcome=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite);raw=stream.getvalue().encode()
 if not outcome.wasSuccessful()or outcome.testsRun!=expected or outcome.skipped or len(raw)>65536:raise ValueError('installed controls failed: '+raw[-2048:].decode(errors='replace'))
 return dict(status='PASS_INSTALLED_CONTROLS',mode=mode,tests=outcome.testsRun,failures=len(outcome.failures),errors=len(outcome.errors),skipped=len(outcome.skipped),report_bytes=len(raw),report_sha256=hashlib.sha256(raw).hexdigest(),installed_source=True)

if __name__=='__main__':
 if os.uname().machine!='aarch64'or os.getuid()==0 or len(sys.argv)!=2:raise ValueError('ordinary native ARM installed-control actor required')
 print(json.dumps(run_suite(sys.argv[1]),sort_keys=True))

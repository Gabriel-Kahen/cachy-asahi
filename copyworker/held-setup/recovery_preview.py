# SPDX-License-Identifier: MIT
"""Six real interrupted temporary-user tests against the actual installed helper."""
import argparse,hashlib,importlib.machinery,importlib.util,io,json,os,sys,tempfile,types,unittest
from pathlib import Path

def adapted_source(raw):
 old="s=importlib.util.spec_from_file_location('setup_child',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)"
 new="import importlib.machinery\nloader=importlib.machinery.SourceFileLoader('setup_child',sys.argv[1]);s=importlib.util.spec_from_loader(loader.name,loader);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)"
 if raw.count(old)!=1:raise ValueError('only extensionless installed-helper loader adaptation')
 return raw.replace(old,new,1)

def run_controls(cli,tests,scratch):
 need=lambda ok,why:None if ok else(_ for _ in()).throw(ValueError(why))
 digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest();need(digest(cli)==digest(tests/'setup.py'),'installed/canonical helper body identity');need(not scratch.exists()and scratch.parent==Path('/tmp'),'fresh private fixture root');scratch.mkdir(mode=0o700);saved=dict(sys.modules);paths=sys.path[:];prior=tempfile.tempdir
 try:
  tempfile.tempdir=str(scratch);sys.path.insert(0,str(tests));import test_setup,test_shell_modules
  need(Path(test_setup.__file__)==tests/'test_setup.py'and Path(test_shell_modules.__file__)==tests/'test_shell_modules.py','exact source-owned fixture modules');loader=importlib.machinery.SourceFileLoader('_actual_installed_setup6',str(cli));module=importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name,loader));loader.exec_module(module);test_setup.setup=test_shell_modules.setup=module
  raw=(tests/'test_recovery_preview.py').read_text();adapted=adapted_source(raw);m=types.ModuleType('_source_held_six_installed_recovery_tests');m.__file__=str(tests/'test_recovery_preview.py');exec(compile(adapted,m.__file__,'exec'),m.__dict__);suite=unittest.defaultTestLoader.loadTestsFromTestCase(m.RecoveryPreviewTests);names=sorted(t.id().split('.')[-1]for t in suite);need(len(names)==len(set(names))==6,'six exact source-owned recovery cases');output=io.StringIO();result=unittest.TextTestRunner(stream=output,verbosity=2).run(suite);need(result.testsRun==6 and result.wasSuccessful()and not result.skipped,'all actual interrupted recovery assertions required: '+output.getvalue()[:8192]);need(list(scratch.iterdir())==[],'all ordinary fixture homes retired');return dict(tests=6,cases={n:'PASS'for n in names},source_test_sha256=digest(tests/'test_recovery_preview.py'),adapter_sha256=hashlib.sha256(adapted.encode()).hexdigest(),installed_helper_sha256=digest(cli),private_fixtures_retired=True)
 finally:
  tempfile.tempdir=prior;sys.path[:]=paths
  for n in set(sys.modules)-set(saved):del sys.modules[n]
  sys.modules.update(saved)
  if scratch.exists()and not list(scratch.iterdir()):scratch.rmdir()

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--helper-sha256',required=True);a=p.parse_args();cli=Path('/usr/bin/cachy-asahi-setup');tests=Path('/inputs/setup6-tests');assert os.getuid()==os.geteuid()>0 and os.uname().machine=='aarch64'and Path('/.dockerenv').is_file()and os.environ.get('CACHY_ASAHI_SETUP6_USER')=='1';assert hashlib.sha256(cli.read_bytes()).hexdigest()==a.helper_sha256;report=run_controls(cli,tests,Path('/tmp')/('setup6-preview-'+os.urandom(16).hex()));report.update(status='PASS_ACTUAL_INSTALLED_SETUP6_INTERRUPTED_RECOVERY_PREVIEW',uid=os.getuid(),native_architecture='aarch64',actual_page_size=os.sysconf('SC_PAGE_SIZE'),installed_helper=True,system_mutation='NONE_USER_FIXTURES_ONLY',hardware='NOT_RUN');print(json.dumps(report,sort_keys=True))

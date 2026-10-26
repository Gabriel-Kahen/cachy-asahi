#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact installed helpers, ordinary private fixtures; never live KSM mutation."""
import hashlib,importlib.machinery,importlib.util,json,os,stat,subprocess,sys,unittest
from pathlib import Path
PACKAGE='cachy-asahi-ksmctl';NEW=PACKAGE+'2'
EXPERIMENT='cachy-asahi-ksm-experiment'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def load(name,path):
 loader=importlib.machinery.SourceFileLoader(name,str(path));spec=importlib.util.spec_from_loader(name,loader);m=importlib.util.module_from_spec(spec);loader.exec_module(m);return m
def suite(source,reporter,experiment=None):
 """Source-pinned tests with all behavioral calls bound to installed bytes.

 The original reporter SCRIPT remains source-relative for its four provenance
 checks. Its fourteen runtime fixtures instead use the exact installed module.
 Experiment tests use only E.Control(model=True) on real owned regular files;
 the suite includes actual SIGKILL/recovery and rejects sysfs/procfs aliases.
 """
 tests=load('_ksm_installed_reporter_tests',source/'test_ksmctl.py');tests.ksm=load('_ksm_exact_installed_reporter',reporter)
 result=unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromModule(tests))
 need(result.wasSuccessful()and result.testsRun==18 and not result.skipped,'all18 installed reporter/source-provenance controls required')
 if experiment is not None:
  tests=load('_ksm_installed_experiment_tests',source/'test_experiment.py');tests.E=load('_ksm_exact_installed_experiment',experiment)
  result=unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromModule(tests))
  need(result.wasSuccessful()and result.testsRun==26 and not result.skipped,'all26 installed experiment private controls required')
 return dict(reporting=18,experiment=26 if experiment is not None else 0,domain='PRIVATE_REGULAR_FILES_ONLY',live_kernel_write='NOT_RUN')
def installed(path,expected):
 s=path.lstat();raw=path.read_bytes()
 need(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o755 and s.st_nlink==1 and pin(raw)==expected,'exact installed root-owned executable bytes required')
 return raw
def command(argv):
 p=subprocess.run(list(map(str,argv)),stdin=subprocess.DEVNULL,capture_output=True,timeout=55,env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
 need(p.returncode==0 and len(p.stdout)+len(p.stderr)<=128*1024,'installed bounded private command refused')
 return dict(exit_code=p.returncode,stdout=pin(p.stdout),stderr=pin(p.stderr))
def main(role,work,phase):
 need(os.getuid()==os.geteuid()>0 and role in(PACKAGE,NEW)and work.is_absolute()and work.is_dir()and not work.is_symlink()and work.stat().st_uid==os.getuid(),'ordinary owned installed fixture context')
 policy=json.loads(Path('/runner/input-policy.json').read_bytes());product=policy['products'][role]
 reporter=Path('/usr/bin')/PACKAGE;installed(reporter,product['source_files'][PACKAGE]);programs=[reporter]
 if role==NEW:
  experiment=Path('/usr/bin')/EXPERIMENT;installed(experiment,product['source_files'][EXPERIMENT]);programs.append(experiment)
 else:need(not os.path.lexists('/usr/bin/'+EXPERIMENT),'old reporting package cannot expose new management helper')
 # --help/version exit in argparse before any Control()/fixed-livepath access.
 cli=[dict(program=p.name,argument=arg,**command([p,arg]))for p in programs for arg in('--help','--version')]
 source=Path('/inputs/sources')/role
 argv=['/usr/bin/python3','-I','-B',__file__,'--suite',str(source),str(reporter)]
 if role==NEW:argv.append(str(programs[1]))
 tests=command(argv)
 receipt=dict(status='PASS_INSTALLED_KSM_REPORT_AND_PRIVATE_EXPERIMENT_FIXTURES',role=role,version=product['version'],phase=phase,report_controls=18,experiment_controls=26 if role==NEW else 0,reporter_sha256=pin(reporter.read_bytes())['sha256'],helper_sha256=pin(programs[1].read_bytes())['sha256']if role==NEW else None,commands=cli,suite=tests,live_kernel_write='NOT_RUN',merge_eligibility='NOT_CHANGED',hardware='NOT_RUN')
 p=work/(phase+'-receipt.json');need(not p.exists(),'fresh installed phase receipt');p.write_text(json.dumps(receipt,sort_keys=True)+'\n');print(json.dumps(receipt,sort_keys=True))
if __name__=='__main__':
 if sys.argv[1]=='--suite':suite(Path(sys.argv[2]),Path(sys.argv[3]),None if len(sys.argv)==4 else Path(sys.argv[4]))
 else:main(sys.argv[1],Path(sys.argv[2]),sys.argv[3])

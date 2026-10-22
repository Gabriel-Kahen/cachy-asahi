#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Six fixed installed tools, ordinary private fixtures; no live platform actor."""
import hashlib,importlib.machinery,importlib.util,io,json,os,stat,subprocess,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import latest_plan as P

def load(name,path):
 loader=importlib.machinery.SourceFileLoader(name,str(path));spec=importlib.util.spec_from_loader(name,loader);module=importlib.util.module_from_spec(spec);loader.exec_module(module);return module

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def call(argv,seconds=20,code=0):
 value=subprocess.run(list(map(str,argv)),stdin=subprocess.DEVNULL,capture_output=True,timeout=seconds);P.need(value.returncode==code and len(value.stdout)+len(value.stderr)<=128*1024,'bounded actual installed readonly CLI failed');return value

def suite(tests,count):
 stream=io.StringIO();result=unittest.TextTestRunner(stream=stream,verbosity=2).run(tests);raw=stream.getvalue().encode();P.need(result.wasSuccessful()and result.testsRun==count and not result.skipped and len(raw)<=65536,'complete fixed installed private controls failed: '+raw[-2048:].decode(errors='replace'))
 return dict(tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),report=pin(raw),scope='INSTALLED_SOURCE_PRIVATE_FIXTURE_ONLY')

def doctor_report(value,version,want):
 P.need(type(value)is dict and value.get('schema_version')==1 and value.get('tool')=='cachy-asahi-doctor'and value.get('scope')=='local observations only'and value.get('version')==('0.2.0'if version=='0.2.0-1'else'0.1.0'),'actual installed Doctor version/scope')
 rows=value['checks'];P.need(type(rows)is list and len(rows)<128 and len({r['check']for r in rows})==len(rows),'bounded unique Doctor rows')
 platform=next(r for r in rows if r['check']=='platform');P.need(platform['value']==dict(architecture='aarch64',kernel=os.uname().release,page_size_bytes=os.sysconf('SC_PAGE_SIZE')),'observed generic platform, no M2 claim')
 for row in rows:
  if row['check'].startswith('package/'):
   name=row['check'][8:];v=row['value'];P.need(row['state']in('checked','unknown','unavailable'),'finite observed package state')
   if row['state']=='checked':P.need(v['presence']==('present'if name in want else'absent')and v['version']==want.get(name),'actual successful Doctor package query agrees with independent inventory')
   else:P.need(v['presence']=='unknown'and v['version']is None,'query failure never absence/health authority')
  if row['check'].startswith(('system/','user/')):P.need(row['state']in('checked','unknown','unavailable','warning'),'offline service observation only')
 audio=[r for r in rows if r['check']=='audio/default-output'];P.need(not audio if version=='0.1.0-1'else len(audio)==1 and audio[0]['state']=='unavailable'and audio[0]['value']is None,'no local PipeWire socket or live audio claim')
 return value

def doctor(work,version,want):
 program=Path('/usr/bin/cachy-asahi-doctor');call([program,'--help']);path=work/'doctor.json';value=doctor_report(json.loads(call([program,'--json','--output',path],25).stdout),version,want);raw=path.read_bytes();s=path.lstat();P.need(json.loads(raw)==value and stat.S_ISREG(s.st_mode)and s.st_uid==os.getuid()and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,'actual private complete report')
 call([program,'--output',path],25,2);P.need(path.lstat()==s and path.read_bytes()==raw,'no overwrite identity/content');outside=work/'outside';outside.write_bytes(b'owned private sentinel\n');outside.chmod(0o600);prior=outside.lstat();alias=work/'alias';alias.symlink_to('outside')
 try:call([program,'--output',alias],25,2);P.need(outside.lstat()==prior and outside.read_bytes()==b'owned private sentinel\n','symlink refusal preserves private sentinel')
 finally:alias.unlink()
 controls=None
 if version=='0.2.0-1':
  source=HERE/'doctor-tests';P.need(program.read_bytes()==(source/'cachy-asahi-doctor').read_bytes(),'installed Doctor2 exact accepted source');actual=load('_latest_installed_doctor',program);tests=unittest.TestSuite()
  for filename,key,classes in(('test_doctor.py','doctor',('Diagnostics','QueryControls','Reports')),('test_audio.py','D',('Audio','RealIPC'))):
   module=load('_latest_'+key+'_tests',source/filename);setattr(module,key,actual)
   for cls in classes:tests.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(getattr(module,cls)))
  controls=suite(tests,27)
 return dict(CLI=4,report=value,private_report=dict(**pin(raw),mode='0600',no_overwrite=True,symlink_refusal=True),controls=controls,live_audio='NOT_RUN',hardware='NOT_RUN')

def apps(work,version,want):
 call(['/usr/bin/cachy-asahi-apps','--help']);path=work/'inventory.json';receipt=json.loads(call(['/usr/bin/cachy-asahi-apps','inventory','--dbpath','/var/lib/pacman','--output',path],40).stdout);raw=path.read_bytes();s=path.lstat();P.need(receipt['applied']=='NOT_APPLIED'and receipt['sha256']==pin(raw)['sha256']and stat.S_ISREG(s.st_mode)and s.st_uid==os.getuid()and s.st_nlink==1,'actual owned Apps inventory snapshot');rows=json.loads(raw)['packages'];P.need(len(rows)==len(want)and{r['name']:r['version']for r in rows}==want,'whole actual Apps inventory equals independent full wanted606/607')
 controls=None
 if version=='0.1.0-10':
  for name in('apps.py','inventory.py'):P.need((Path('/usr/lib/cachy-asahi-apps')/name).read_bytes()==(HERE/'apps10-source'/name).read_bytes(),'actual installed accepted Apps8 helper source')
  controls=load('_latest_original_apps_controls',HERE/'apps-tests/fixture_checks.py').run_suite('apps',fixtures=HERE/'apps-tests');P.need(controls['tests']==15,'all15 original installed Apps controls')
 P.need(path.lstat()==s,'snapshot unchanged');path.unlink();return dict(CLI=2,inventory=pin(raw),inventory_count=len(want),controls=controls,applied='NOT_APPLIED')

def ksm(work,version,want):
 program=Path('/usr/bin/cachy-asahi-ksmctl');cli=[]
 for p in([program,Path('/usr/bin/cachy-asahi-ksm-experiment')]if version=='0.1.0-2'else[program]):
  for flag in('--help','--version'):value=call([p,flag]);cli.append(dict(program=p.name,flag=flag,stdout=pin(value.stdout),stderr=pin(value.stderr)))
 P.need(version=='0.1.0-2'or not Path('/usr/bin/cachy-asahi-ksm-experiment').exists(),'KSM1 exposes no experiment')
 controls=None
 if version=='0.1.0-2':controls=load('_latest_held_ksm_fixtures',HERE/'ksm-tests/fixture_checks.py').suite(HERE/'ksm-tests/source',program,Path('/usr/bin/cachy-asahi-ksm-experiment'));P.need(controls==dict(reporting=18,experiment=26,domain='PRIVATE_REGULAR_FILES_ONLY',live_kernel_write='NOT_RUN'),'exact44 private KSM controls')
 return dict(CLI=cli,controls=controls,live_kernel_write='NOT_RUN',hardware='NOT_RUN')

def welcome(work,version,want):
 program=Path('/usr/bin/cachy-asahi-welcome');value=json.loads(call([program,'--status','--json']).stdout);P.need(value['architecture']=='aarch64'and value['kernel']==os.uname().release and value['page_size']==os.sysconf('SC_PAGE_SIZE')and value['schema_version']==1 and value['hardware_compatibility']=='not-assessed'and len(value['packages'])==6,'actual generic readonly Welcome status')
 for name,row in value['packages'].items():
  P.need(row['state']in('installed','not-found','unknown'),'finite Welcome package state')
  if row['state']!='unknown':P.need(row['state']==('installed'if name in want else'not-found')and row['version']==want.get(name),'Welcome successful query agrees with independent inventory')
 controls=None
 if version=='0.1.0-8':
  before=list(sys.argv);sys.argv=['fixed-native-cli',str(program)]
  try:module=load('_latest_whole_welcome6_CLI',HERE/'welcome-tests/test_cli.py')
  finally:sys.argv=before
  controls=suite(unittest.defaultTestLoader.loadTestsFromTestCase(module.CLI),5)
 return dict(status=value,controls=controls,GUI='NOT_RUN',hardware='NOT_RUN')

def boot(work,version,want):
 api=load('_latest_exact_boot_installed_fixture',HERE/'boot-tests/installed_fixture.py');value=api.run(work,HERE/'boot-tests/boot-fixture',home=Path(os.environ['HOME']));api.F.validate(value,'77c326d908442852de51e66c660153d4c6051390b14466e48fa9c037cc1c573e');return dict(controls=value,real_journal='NOT_READ',live_pstore='NOT_READ',hardware='NOT_RUN')

def setup(work,version,want):
 program=Path('/usr/bin/cachy-asahi-setup');call([program,'--help']);previews=[]
 for operation in('activate','remove','recover'):
  argv=[program,operation,'--home',Path(os.environ['HOME'])]
  if operation!='recover':argv+=['--components','fish-bang-bang']
  raw=call(argv,25).stdout;value=json.loads(raw);P.need(value.get('mode')=='preview'and value.get('operation')==operation and not value.get('pending_transaction')and not value.get('preserved_conflicts'),'actual nonmutating Setup preview');previews.append(dict(operation=operation,value=value,raw=pin(raw)))
 return dict(CLI=4,controls=None,previews=previews,scope='READONLY_PREVIEW_ONLY_WHOLE_REAL_MODULE_SUITES_SEPARATELY_REQUIRED')

def main():
 P.need(len(sys.argv)==3 and os.getuid()==os.geteuid()>0 and os.uname().machine=='aarch64','ordinary owned ARM fixture only');work=Path(sys.argv[1]);P.need(work.is_absolute()and work.name.startswith('latest607-')and work.stat().st_uid==os.getuid()and stat.S_IMODE(work.stat().st_mode)==0o700,'fresh owned private fixture work');role=sys.argv[2];_,name,old,new=P.product(role);value=json.loads((work/'plan.json').read_bytes());P.need(set(value)=={'inventory','phase'}and type(value['inventory'])is dict and len(value['inventory'])in(606,607),'fixed actual fixture inventory');want=value['inventory'];version=want[name];P.need(version in(old,new),'installed original/latest fixture version');actual=call(['/usr/bin/pacman','-Q']).stdout;P.need(dict(r.split()for r in actual.decode().splitlines())==want,'source-owned whole pacman-Q, separate query authority')
 row=globals()[role](work,version,want);result=dict(status='PASS_ACTUAL_LATEST_TOOL_PRIVATE_FIXTURE',role=role,version=version,phase=value['phase'],home=Path(os.environ['HOME']).name,inventory_sha256=pin(P.inventory_bytes(want))['sha256'],inventory_authority='SOURCE_OWNED_FULL_PACMAN_Q_SEPARATE_TOOL_QUERY_AUTHORITY',observation=row,hardware='NOT_RUN',performance='NOT_CLAIMED',release='NOT_ADMITTED');path=work/'receipt.json';P.need(not path.exists(),'fresh private fixture receipt');path.write_text(json.dumps(result,sort_keys=True)+'\n');path.chmod(0o600)
if __name__=='__main__':main()

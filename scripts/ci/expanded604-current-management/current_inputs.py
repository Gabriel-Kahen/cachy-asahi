# SPDX-License-Identifier: MIT
"""Exact accepted Welcome4/Orphans2 input projection; GUI acceptance is separate."""
import hashlib,json,re,tarfile
from pathlib import Path
WELCOME='cachy-asahi-welcome';ORPHANS='cachy-asahi-orphans';DOCTOR='cachy-asahi-doctor'
VERSIONS={WELCOME:'0.1.0-4',ORPHANS:'0.1.0-2'}
SOURCE='3c06dad15dec0dbfe47d5f064a9c56ce76f59756';PRODUCT='0b74d8ecea4f152bda4adfbd9bee488890db4363';RUN=39002929704
STATUS='ROOT_ACCEPTED_WELCOME4_NATIVE_PAIR_AND_SIGNED_INSTALLED_CLI_ONLY'
DECISION={'bytes': 15561, 'sha256': 'd4009851806b0de4a3fa594d96d249c29073bb2e97ac2c307497ae26665ab3d0'}  # Frozen below from the existing Root-authored decision, never synthesized.
ARCHIVES={WELCOME:dict(bytes=32268,sha256='80cd962d35d8652ab7891d61f856e37502f365adb842329a680b4fa88558503d'),ORPHANS:dict(bytes=18900,sha256='2543a13b584bf974efc4ce79f4da585d9e4513c2bc3907750fe5c962d20c8c02'),DOCTOR:dict(bytes=13708,sha256='06898669fdd6c9e5bdcc9909e6b0e75e958bdbd57520a7082c0e9f5f7fac7482')}

def require(C,binding,published=True):
 C.need(binding.get('status')==STATUS and binding.get('source')==SOURCE and binding.get('candidate_source')==PRODUCT,'current Welcome4/Orphans2 native pair/CLI input identity required')
 if published:C.need(type(binding.get('carrier_source')) is str and re.fullmatch('[0-9a-f]{40}',binding['carrier_source']) and binding['carrier_source'] not in (SOURCE,PRODUCT),'current immutable published packet remains UNBOUND')
 C.ref(binding.get('index'),4*1024**2)
 return binding

def validate(C,source,root,binding,checks,bind,*,published=True,native_source=None):
 require(C,binding,published);value=C.read(C.checked(root,binding['index']))
 C.need(value.get('schema_version')==1 and value.get('kind')=='ROOT_ACCEPTED_CURRENT604_WELCOME4_ORPHANS2_INPUT_PROJECTION' and value.get('native_source')==SOURCE and value.get('candidate_source')==PRODUCT and value.get('native_run')==RUN and value.get('GUI')=='FAIL_NOT_ACCEPTED' and set(value.get('packages',{}))==set(VERSIONS),'exact current two-product projection required')
 # Use the original reference and empty-record rules. No collected code imports.
 old=C.scoped_load('current604_original_reference_reader',source/'scripts/ci/expanded604-composition/inputs.py',{'contract':C});refs=old.references(value)
 C.need(len(refs)<=256 and sum(r['bytes'] for r in refs.values())<=64*1024**2,'original packet count/byte bound')
 paths={}
 for name,row in refs.items():paths[name]=old.source_ref(root,row)
 nodes=[]
 for p in root.rglob('*'):
  nodes.append(p);C.need(len(nodes)<=512 and not p.is_symlink() and (p.is_file() or p.is_dir()),'original ordinary packet node/count bound')
 C.need({p.relative_to(root).as_posix() for p in nodes if p.is_file()}==set(refs)|{binding['index']['path']},'current packet closed reference set')
 parents={q.as_posix() for n in set(refs)|{binding['index']['path']} for q in Path(n).parents if q.as_posix()!='.'}
 C.need(all(p.is_file() or p.relative_to(root).as_posix() in parents for p in nodes),'unreferenced empty packet directory')
 approval=value['decision'];C.need({k:approval[k] for k in ('bytes','sha256')}==DECISION,'exact original Root decision bytes required');decision=C.read(paths[approval['path']])
 C.need(decision['status']==STATUS and decision['source_sha']==SOURCE and decision['run_id']==RUN and decision['attempt']==1 and decision['GUI']=='FAIL_NOT_ACCEPTED' and decision['generic16k']=='NO_NEW_CREDIT' and decision['hardware']=='NOT_RUN' and decision['release']=='NOT_ADMITTED','Root pair/CLI scope must not promote GUI or604')
 native_source=Path(native_source) if native_source is not None else source
 api=C.scoped_load('current604_native_guards',native_source/'scripts/ci/welcome-management-native/native_contract.py',{})
 C.need(api.policy()['candidate_source']==PRODUCT,'exact existing product authority');result={}
 for name,version in VERSIONS.items():
  row=value['packages'][name];C.need(row['version']==version and row['native_source']==SOURCE and row['native_run']==RUN and set(row['files'])=={'a','b'} and row['files']['a']['path']!=row['files']['b']['path'],'two distinct exact current archive rows')
  recipe=api.recipe(native_source,name);product=api.product(name);C.need(set(row['source_files'])==set(product['source_files']),'complete current source/license closure')
  for n,ref in row['source_files'].items():C.need({k:ref[k] for k in ('bytes','sha256')}==product['source_files'][n] and C.sha(paths[ref['path']])==C.sha(native_source/'packages/tools'/name/n),'current retained source differs')
  reports=[]
  for side in ('a','b'):
   ref=row['files'][side];C.need({k:ref[k] for k in ('bytes','sha256')}==ARCHIVES[name]==decision['packages'][name]['archives'][side],'Root exact current archive digest')
   path=paths[ref['path']];C.need(path.name==name+'-'+version+('-aarch64' if name==WELCOME else '-any')+'.pkg.tar.xz','fixed current archive basename');report=checks.package(path)
   C.need(not bind.bind_artifact(recipe['metadata'],report,recipe['input_sha256']['PKGBUILD']),'actual current PKGINFO/BUILDINFO binding');C.need(api.payload(report,native_source,name)==row['payload'],'actual current complete payload')
   if name==WELCOME:
    with tarfile.open(path,'r:xz') as tar:
     members=[m for m in tar if checks.clean_name(m.name)=='usr/bin/'+WELCOME];C.need(len(members)==1 and members[0].isfile() and members[0].size<=4*1024**2,'bounded actual Welcome ELF');api.elf(tar.extractfile(members[0]).read(),checks)
   C.need(api.check_log(paths[row['checks'][side]['path']],name)==decision['native_checks']['checks'][name][side],'original complete ordinary check replay');reports.append(report)
  C.need(reports[0]['members']==reports[1]['members'] and reports[0]['metadata']==reports[1]['metadata'],'current native pair byte metadata/payload equality')
  comparison=C.read(paths[row['comparison']['path']]);old.comparison(comparison);C.need(comparison==decision['packages'][name]['comparison'],'original Root comparison equality')
  result[name]=old.normalized(name,dict(row,sources=row['source_files'],metadata=recipe['metadata']),root,reports[0])
 evidence=value['evidence'];life=C.read(paths[evidence['lifecycle']['path']]);api.validate_lifecycle(life);api.validate_root_guard(life['root_guard'],paths[evidence['root_guard_tap']['path']].read_text())
 C.need(decision['lifecycle']['status']==life['status'] and decision['lifecycle']['raw_reports']==36,'Root signed CLI lifecycle scope')
 baseline=dict(line.split() for line in paths[evidence['base_lock']['path']].read_text().splitlines());C.need(len(baseline)==574 and C.sha(paths[evidence['base_lock']['path']])==api.BASE,'actual original574 installed inventory')
 count=0
 for event in life['events']:
  if event['count']!=577:continue
  for observation in event['observations']:
   prefix='runtime/public-reports/'+observation['home'].removeprefix('management-home-')+'/'+event['phase']+'/'
   for n,sha in observation['reports'].items():C.need(C.sha(paths[prefix+n])==sha,'original raw CLI observation hash');count+=1
 C.need(count==36,'all36 original CLI reports retained')
 cleanup=C.read(paths[evidence['cleanup']['path']]);cleaner=C.scoped_load('current604_cleanup',source/'scripts/ci/management-tools-generic16k/contract.py',{});cleaner.cleanup_proof(cleanup);C.need(cleanup==decision['cleanup'],'Root ordered cleanup equality')
 # Doctor stays the identical already-selected archive; new joint lifecycle used it.
 C.need(decision['packages'][DOCTOR]['version']=='0.1.0-1' and all(r==ARCHIVES[DOCTOR] for r in decision['packages'][DOCTOR]['archives'].values()),'unchanged Doctor artifact required')
 return result

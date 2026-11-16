#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Passive LLVM command-namespace successor; future actual Root selectors unissued."""
import argparse,hashlib,importlib.util,json,os,resource,struct,sys,tarfile,time,zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('llvm5_base',HERE/'base.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B);v=B.v
spec=importlib.util.spec_from_file_location('llvm5_storage',HERE/'storage.py');storage=importlib.util.module_from_spec(spec);spec.loader.exec_module(storage)
MIB,GIB=v.MIB,v.GIB
PARENT=dict(source='365a763bc515a1b3550cc804536ddbf66353aac8',ref='refs/heads/codex/llvm23-source-reference-native-v2-20261115-r2',files=256,bytes=40919517,map_sha256='22f6f8a9d3eabf4de16c853cf67183b67beca4e702e26c5b492066e94194735c',tree='f251f3b7c7e152943ce85bc012f97305934e8fd8')
COMMANDS=dict(probe=60,tools=10800,runtimes=1800,check=600,makepkg=13800,pkginfo=60,buildinfo=60,**{'tool-owners':30,'packages-unsorted':30})
PACKAGE='cachy-asahi-llvm23-source-reference-23.1.1-1-aarch64.pkg.tar.zst'


def namespace(data,result,specification):
 """Complete declared flat output, stronger than self-declared output_files alone."""
 v.need(set(specification)=={'command_receipts','command_logs','facts','fixed_output'},'exact command/fact output profile')
 receipts=specification['command_receipts'];facts=specification['facts'];logs=specification['command_logs']
 v.need(set(receipts)==set(logs)==set(COMMANDS)and set(facts)=={'runtime','tools'}and len(set(receipts.values()))==len(COMMANDS)and len(set(facts.values()))==2 and not set(receipts.values())&set(facts.values()),'separate command receipt/fact namespace')
 v.need(len(specification['fixed_output'])==len(set(specification['fixed_output'])) and len(set(logs.values()))==len(COMMANDS),'unique fixed outputs and command logs')
 for name in logs.values():v.need('/'not in v.safe_name(name) and name.endswith('.log'),'flat literal command log')
 for name in specification['fixed_output']:v.need('/'not in v.safe_name(name),'flat fixed output')
 for name in list(receipts.values())+list(facts.values()):v.need('/'not in v.safe_name(name)and name.endswith('.json'),'flat literal receipt/fact leaf')
 expected=set(specification['fixed_output'])|set(receipts.values())|set(facts.values())|set(logs.values())|{PACKAGE}
 v.need(len(expected)<=63 and set(result['output_files'])==expected and {p.name for p in data.iterdir()}==expected|{'actor-result.json'},'complete exact successful output namespace')
 total=0
 for name,row in result['output_files'].items():
  v.need(set(row)=={'bytes','sha256','mode'}and type(row['bytes'])is int and row['bytes']>=0 and v.digest(row['sha256'])and type(row['mode'])is int and not row['mode']&0o111 and row['mode']&~0o777==0,'ordinary nonexecutable output declaration')
  cap=2*GIB if name==PACKAGE else 64*MIB;got=v.hashed(data/name,cap);v.need(got=={k:row[k]for k in('bytes','sha256')},'whole complete output content');total+=got['bytes']
 v.need(total<=4*GIB,'unchanged exported aggregate cap')
 observed=v.load(data/facts['runtime']);v.need(set(observed)=={'schema','admission_sha256','operation','entry','parent'}and type(observed['schema'])is int and observed['schema']==1 and observed['operation']=='llvm23-source-reference-native-v1' and v.digest(observed['admission_sha256']),'initial actual runtime facts are not a stage command receipt');v.runtime(observed)
 tools=v.load(data/facts['tools']);v.need(set(tools)=={'schema','tools','command_receipt','expected349_sha256','scope'}and type(tools['schema'])is int and tools['schema']==1 and tools['scope']=='ACTUAL_PATH_BYTES_AND_ALPM_OWNERSHIP_ONLY_NOT_COMPILER_RUNTIME_QUALIFICATION' and tools['expected349_sha256']=='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453' and tools['command_receipt']==receipts['tool-owners'],'tool inventory independently binds its actual owner command')
 for name,maximum in COMMANDS.items():
  row=v.load(data/receipts[name]);v.natural(row['lifecycle'])
  v.need(row['success']is True and type(row['returncode'])is int and row['returncode']==row['lifecycle']['exit']==0 and 0<row['timeout_seconds']<=row['requested_seconds']==maximum and row['log']==logs[name]and v.hashed(data/row['log'],64*MIB)==row['log_pin'],'separate bounded natural command and full log hash')
  if name in('probe','tools','runtimes','check'):v.need(row['argv']==['/usr/bin/bash','/inputs/packages/port/llvm23-source-reference/build.sh',name],'exact tools/runtimes stage command')
 return dict(files=len(expected)+1,bytes=total,command_receipts=receipts,facts=facts,runtime_and_build_success_separate=True)


def inverse256_rows(rows,pins,frame,parent_source,ancestor_source):
 """Exact append-only successor→256, then held256→253→251→248 DATA inverse."""
 found=B.old.namespace_rows(rows,pins);v.need(frame['parent']==PARENT and frame['actual']==B.old.ACTUAL,'fixed previous256 lineage; no future actual declarations')
 saved_map=frame['saved_parent_map'];meta_name=frame['metadata'];replacements=frame['replacements'];v.need(set(replacements)==set(pins['correction_files']),'only exact explicitly profiled successor correction paths')
 additions={saved_map,meta_name}|{r['saved']for r in replacements.values()}
 v.need(set(frame)=={'parent','actual','saved_parent_map','metadata','metadata_value','replacements'}and additions<=set(rows)and len(additions)==len(replacements)+2,'finite distinct append-only inverse frame')
 v.need(v.decode(rows[meta_name][0])==frame['metadata_value']and rows[meta_name][1]==0o644,'whole exact successor lineage metadata')
 restored={n:r for n,r in rows.items()if n not in additions|{'source-map.json'}}
 for name,item in replacements.items():
  v.safe_name(name);v.safe_name(item['saved']);v.need(set(item)=={'saved','before','after','inverse'}and B.old.descriptor(rows[item['saved']])==item['before']and B.old.descriptor(rows[name])==item['after'],'exact old/new/saved bodies and modes')
  original=rows[item['saved']];candidate=rows[name]
  if item['inverse']['kind']=='LITERAL_SEAMS':
   transformed=original[0]
   for seam in item['inverse']['seams']:
    v.need(set(seam)=={'before','after','count'}and type(seam['count'])is int,'typed finite literal seam')
    old,new=seam['before'].encode(),seam['after'].encode();v.need(transformed.count(old)==seam['count']and seam['count']>0 and new not in transformed,'finite exact literal seam');transformed=transformed.replace(old,new)
   v.need(candidate==(transformed,original[1]),'only exact reviewed source edits')
   inverse=transformed
   for seam in reversed(item['inverse']['seams']):
    old,new=seam['before'].encode(),seam['after'].encode();v.need(inverse.count(new)==seam['count'],'exact reversible successor literal count');inverse=inverse.replace(new,old)
   v.need(inverse==original[0],'whole exact saved Source byte inverse')
  elif item['inverse']['kind']=='JSON_ACTOR_DESCRIPTOR':
   old=v.decode(original[0]);new=v.decode(candidate[0]);name_changed=item['inverse']['actor'];updated=json.loads(json.dumps(old));updated['actor_files'][name_changed]=item['inverse']['descriptor'];v.need(item['inverse']['frozen_python_actor']==dict(before=True,after=False)and old['outer_delegation']['frozen_python_actor']is True,'explicit revised native actor, no false frozen claim');updated['outer_delegation']['frozen_python_actor']=False;v.need(new==updated and candidate[1]==original[1],'only finite actor descriptor contract update')
  else:raise ValueError('unreviewed successor inverse operation')
  restored[name]=original
 restored['source-map.json']=rows[saved_map];historical=B.old.namespace_rows(restored,B.parent_pins)
 v.need(set(rows)-set(restored)==additions and set(restored)<=set(rows),'append-only finite new namespace; no dropped prior files')
 for name in set(restored)-set(replacements)-{'source-map.json'}:v.need(rows[name]==restored[name],'unchanged previous256 leaf')
 B.old.inverse253_rows(restored,B.parent_pins,historical,parent_source,ancestor_source)
 return historical


def whole_reference(row,limit=16*MIB):
 v.need(type(row)is dict and set(row)=={'path','bytes','sha256'}and type(row['bytes'])is int and 0<row['bytes']<=limit,'whole external Root DATA reference')
 raw=v.read(v.path(row['path']),limit);v.need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())=={k:row[k]for k in('bytes','sha256')},'external whole reference changed');return v.decode(raw)


def binding(value,pins):
 v.need(value['scope']=='ROOT_BOUND_LLVM23_INDEPENDENT_READER_V6','new receipt-successor Reader scope')
 actual=value['actual'];v.need(all(actual[k]is not None for k in actual),'new actual selectors remain NULL until Root')
 publication=whole_reference(value['publication'])
 v.need(publication['issuer']=='Root'and publication['status']=='PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY'and publication['source']==actual['source']and publication['ref']==actual['ref']and publication['tree']==pins['source_tree']and publication['source_map_sha256']==pins['source_map_sha256']and publication['files']==pins['source_files']and publication['bytes']==pins['source_bytes'],'actual independently retained complete successor publication')
 selected=dict(pins,source=actual['source'],ref=actual['ref']);v.check_binding(dict(value,scope='ROOT_BOUND_LLVM23_INDEPENDENT_READER_V2'),selected)
 v.need(actual['source']!=PARENT['source']and actual['ref']!=PARENT['ref'],'new successor identity, never relabel failed256');return selected


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 for name in('binding','source','previous-source','historical-source','ancestor-source','original','provider','approval','source-commit','output'):parser.add_argument('--'+name,type=Path,required=True)
 parser.add_argument('--binding-sha256',required=True);a=parser.parse_args()
 resource.setrlimit(resource.RLIMIT_AS,(256*MIB,256*MIB));resource.setrlimit(resource.RLIMIT_CORE,(0,0));v.END=time.monotonic()+1800;B.old.v.END=v.END
 v.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized Root Reader5')
 raw=v.read(v.path(a.binding));v.need(hashlib.sha256(raw).hexdigest()==a.binding_sha256,'external Root binding SHA');b=v.decode(raw);pins=v.load(HERE/'pins.json');pins=binding(b,pins);actual=b['actual']
 for name in('reader.py','base.py','storage.py','inverse-frame.json'):
  key={'reader.py':'reader_sha256','base.py':'base_sha256','storage.py':'storage_sha256','inverse-frame.json':'frame_sha256'}[name];expected=b[key]if name=='reader.py'else pins[key];v.need(v.hashed(HERE/name)['sha256']==expected,'whole exact Reader5 '+name)
 v.need(v.hashed(HERE/'pins.json')['sha256']==b['pins_sha256'],'whole exact Reader5 pins')
 source=v.path(a.source);previous=v.path(a.previous_source);historical=v.path(a.historical_source);ancestor=v.path(a.ancestor_source);output=v.path(a.output)
 v.need(output.parent.is_dir()and output.parent.stat().st_uid==os.geteuid()and not output.parent.stat().st_mode&0o022 and not output.exists(),'fresh private owned Reader output')
 v.need(all(output!=p and output not in p.parents and p not in output.parents for p in(source,previous,historical,ancestor)),'disjoint complete current/historical/Reader namespaces')
 storage_verdict=storage.check(output.parent,b['storage_profile'],v)
 v.need(v.hashed(a.original)==b['original_archive']and v.hashed(a.provider)['sha256']==b['provider_sha256']and v.hashed(a.approval)['sha256']==actual['approval']and v.hashed(a.source_commit)['sha256']==b['source_commit_sha256'],'whole actual Original/provider/admission/commit')
 B.old.admitted_provider(v.load(a.provider),v.load(a.approval),b,pins)
 commit=v.read(a.source_commit,MIB);v.need([line for line in commit.split(b'\n\n',1)[0].splitlines()if line.startswith(b'parent ')]==[('parent '+PARENT['source']).encode()],'exact sole published256 parent, no replay')
 found=v.source_tree(source,pins,commit,actual['source']);previous_found=v.source_namespace(previous,B.parent_pins);rows={n:(v.read(source/n,64*MIB),row['mode'])for n,row in found.items()}
 restored=inverse256_rows(rows,pins,v.load(HERE/'inverse-frame.json'),historical,ancestor);v.need(restored==previous_found,'same exact physically retained256 Source inverse')
 def verified_namespace(data,result):
  verdict=namespace(data,result,pins['output_namespace']);v.receipt_verdict=verdict;return verdict
 projection=B.install(pins['output_namespace'],verified_namespace);v.HERE=HERE
 output.mkdir(mode=0o700);evidence=output/'full-original';v.full_zip(a.original,evidence,b['full_original_decode']);B.old.proof_join(v.load(evidence/'source-readback.json'),found,actual,pins)
 result=v.replay(b,source,evidence,output)
 report=dict(schema=1,status='PASS_INDEPENDENT_LLVM23_ABSENT_IMAGE_STDOUT_SUCCESSOR_DATA_ONLY',binding_sha256=a.binding_sha256,actual=actual,source_files=pins['source_files'],source_tree=pins['source_tree'],verified_historical_inverse=[256,253,251,248],command_namespace=v.receipt_verdict,passive_projection=projection,storage=storage_verdict,**result,native_acceptance=False,Root_authentication=False,Root_acceptance=None,holds='native16K/M2/performance/release remain held')
 (output/'reader.json').write_bytes(v.canonical(report));print(json.dumps(report,sort_keys=True))

if __name__=='__main__':
 try:main()
 except(ValueError,KeyError,TypeError,OSError,MemoryError,RuntimeError,struct.error,zipfile.BadZipFile,tarfile.TarError)as error:print('REFUSED: '+str(error),file=sys.stderr);raise SystemExit(2)

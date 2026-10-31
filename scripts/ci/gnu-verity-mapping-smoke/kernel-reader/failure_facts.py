#!/usr/bin/env python3
"""Optional source-bound failed-build DATA. Never a kernel acceptance path."""
import argparse,io,json,stat,subprocess,zipfile
from pathlib import Path
from unittest.mock import patch
import replay as R

def failure_files(raw):
 files={};total=0
 with zipfile.ZipFile(io.BytesIO(raw))as z:
  for row in z.infolist():
   R.safe(row.filename);R.need(row.filename not in files,'duplicate failure member')
   R.need(row.filename in R.FILES|{'failure.json'}and not row.is_dir()and not row.flag_bits&1 and stat.S_IFMT(row.external_attr>>16)in(0,stat.S_IFREG),'closed ordinary failure members')
   cap=256*1024**2 if row.filename=='Image'else 16*1024**2 if row.filename.endswith(('.stdout','.stderr','.log'))else 1024**2 if row.filename=='source-manifest.json'else 262144 if row.filename in('config','baseline.config','candidate-unvalidated.config')else 65536
   total+=row.file_size;R.need(0<=row.file_size<=cap and total<=R.MAX_TOTAL and len(files)<30,'bounded failure closure');files[row.filename]=z.read(row)
 R.need('failure.json'in files and 'kernel-artifacts.json'not in files,'original failure required; no success descriptor')
 d=R.decode(files['failure.json']);R.need(set(d)=={'status','error_type','error','source','retained','cleanup'}and d['status']=='FAIL_BUILD_ONLY_NO_BOOT_AUTHORITY'and type(d['error_type'])is str and type(d['error'])is str and len(d['error'])<=512 and d['cleanup']=='UNKNOWN_WORK_RETAINED_NO_SUCCESSFUL_COMPLETE_RECEIPT_AUTHORITY','exact original nonaccepting failure descriptor')
 R.need(set(d['retained'])==set(files)-{'failure.json'}and all(R.pin(files[n])==v for n,v in d['retained'].items()),'complete original failure member pins')
 return files,d

def difference(before,after,L):
 a,b=L.config_values(before),L.config_values(after)
 rows=[dict(symbol=k,before_present=k in a,after_present=k in b,before=a.get(k),after=b.get(k))for k in sorted(set(a)|set(b))if(k in a)!=(k in b)or a.get(k)!=b.get(k)]
 raw=(json.dumps(rows,sort_keys=True,separators=(',',':'))+'\n').encode()
 try:L.delta(before,after);guard=dict(result='PASS_SOURCE_RULES_ONLY_NOT_KERNEL_ACCEPTANCE')
 except ValueError as e:guard=dict(result='REFUSED',error_type=type(e).__name__,error=str(e))
 return dict(before=R.pin(before),after=R.pin(after),changed_symbols=len(rows),rows=rows[:256],omitted_symbols=max(0,len(rows)-256),complete_diff=R.pin(raw),complete_diff_encoding='UTF8_SORTED_KEYS_COMPACT_JSON_ARRAY_PLUS_LF',guard=guard,acceptance_authority=False)

def inspect(source,archive,metadata,binding,selection):
 R.selected(binding,selection);run=R.read(metadata);R.run_identity(run,binding,success=False);R.need(run['conclusion']=='failure','failed workflow only')
 transport=R.collection_join(archive,metadata,binding);L=R.preflight(source);files,d=failure_files(R.ordinary(archive,R.MAX_ZIP))
 proof=R.decode(files['source-proof.json'])
 R.need(d['source']==proof and set(proof)=={'status','source_sha','workflow_sha','ref','run_id','run_attempt','manifest','profile'}and proof['status']=='SOURCE_PROOF_PASS_BUILD_ONLY'and proof['source_sha']==proof['workflow_sha']==R.SOURCE and proof['ref']==R.REF and proof['run_id']==R.RUN and proof['run_attempt']=='1'and proof['profile']==L.KP.PROFILE and proof['manifest']==R.pin(files['source-manifest.json']),'original failure exact source/workflow/run proof')
 R.need(files['source-manifest.json']==R.ordinary(source/R.LANE/'source-manifest.json',1024**2),'whole failed source manifest')
 result=dict(status='FAILED_BUILD_DATA_ONLY_NOT_ACCEPTED',source=R.SOURCE,ref=R.REF,run=R.RUN,original_transport=transport,artifact_members={n:R.pin(v)for n,v in files.items()},error_type=d['error_type'],error=d['error'],candidate='DIAGNOSTIC_UNAVAILABLE',cleanup='UNKNOWN_WORK_RETAINED',acceptance_authority=False,boot='NOT_RUN',limits=['NO_KERNEL_BOOT_OR_CLEANUP_ACCEPTANCE','SOURCE_RECORDED_IMAGE_HASH_NOT_FULL_IMAGE_REPLAY','CONFIG_DIFF_DATA_NOT_ALLOWLIST_WAIVER'])
 if not R.DIAGNOSTIC_FILES<=set(files):return result
 diagnostic=R.unvalidated_data(files)
 receipt=R.decode(files['candidate-unvalidated-build-receipt.json']);row=R.decode(files['candidate-controller.json'])
 work=str(Path(receipt['helper']['path']).parent.parent)
 R.need(Path(work).is_absolute()and Path(work).name=='gnu-verity-kernel-work'and not any(x in('..','.')for x in Path(work).parts)and '\n'not in work and '\r'not in work,'ordinary candidate provenance root')
 R.command(row,files,'candidate',work)
 R.need(receipt['config']['path']==work+'/helper/built/build/.config'and {k:receipt['config'][k]for k in('bytes','sha256')}==R.pin(files['candidate-unvalidated.config'])and receipt['image']['path']==work+'/helper/built/build/arch/arm64/boot/Image','original unvalidated receipt fixed config/Image join')
 if row['stdout_bytes']:
  R.need(R.decode(files['candidate-controller.stdout'])==receipt,'original candidate stdout/receipt join')
 R.need('baseline.config'in files,'actual same-job baseline required')
 baseline=R.decode(files['baseline-build-receipt.json']);R.need({k:baseline['config'][k]for k in('bytes','sha256')}==R.pin(files['baseline.config']),'actual baseline receipt pin')
 R.command(R.decode(files['baseline-controller.json']),files,'baseline',work)
 result.update(candidate='UNVALIDATED_ORIGINAL_CONFIG_HEADER_RECEIPT_DATA',diagnostic=diagnostic,configuration=difference(files['baseline.config'],files['candidate-unvalidated.config'],L),header=R.pin(files['candidate-unvalidated.Image.header']),Image_receipt_only={k:receipt['image'][k]for k in('bytes','sha256')})
 return result

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,default=R.HERE/'source')
 for n in('archive','metadata','binding','selection'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args()
 with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_PROCESS')),patch.object(subprocess,'run',side_effect=AssertionError('NO_PROCESS')):
  print(json.dumps(inspect(a.source.absolute(),a.archive.absolute(),a.metadata.absolute(),R.read(a.binding.absolute()),R.read(a.selection.absolute())),sort_keys=True))

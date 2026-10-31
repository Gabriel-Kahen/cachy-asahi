# SPDX-License-Identifier: MIT
"""Fresh fixed-artifact transfer; historical original metadata is explicit DATA."""
import argparse,json,time
from pathlib import Path
import contract as C,lane as L
NAMES=('run.json','artifacts.json','logs.zip','collection-outcome.json','bound-original.json')
MODE='ROOT_HISTORICAL_SMALL_DATA_PLUS_IDENTICAL_FIXED_ARTIFACT_TRANSFER'

def acquire(output):
 C.source(C.ROOT);p,d,decision,result=C.bound() # Before mkdir or ANY API/actors.
 owner=L.fresh(output);(output/'owner.json').write_bytes(C.encoded(dict(identity=owner,descriptor=C.pin(C.read(C.HERE/'kernel-descriptor.json')),mode=MODE)));started=time.monotonic();fetches=[]
 with C.kernel(d)as R:
  T=R.load('_boot_kernel_fixed_transfer',R.HERE/'collect.py');binding=dict(source_sha=d['source'],ref=d['ref'],run_id=d['run_id'],run_attempt='1',artifact_sha256=d['artifact']['sha256'])
  def get(name,suffix,cap,seconds):
   path=output/name;T.original_get(path,suffix,cap,seconds);request=R.read(path.with_suffix(path.suffix+'.request.json'));fetches.append(dict(name=name,request=request,stdout=C.pin(C.read(path,cap)),stderr=C.pin(C.read(path.with_suffix(path.suffix+'.stderr'),65536))))
  try:
   get('current-run.json','actions/runs/'+d['run_id'],1024**2,40);R.run_identity(R.read(output/'current-run.json'),binding)
   get('current-artifacts.json','actions/runs/'+d['run_id']+'/artifacts?per_page=100',2*1024**2,40);a=T.artifact_row(R.read(output/'current-artifacts.json'),binding)
   C.need((a['id'],a['name'],a['size_in_bytes'],a.get('digest'))==(d['artifact']['id'],d['artifact']['name'],d['artifact']['bytes'],'sha256:'+d['artifact']['sha256']),'current unexpired original source/run/ref/id/digest BEFORE artifact GET')
   originals=output/'originals';originals.mkdir(mode=0o700)
   for name in NAMES:(originals/name).write_bytes(C.read(C.HERE/'kernel-provenance'/name,8*1024**2))
   get('artifact-transfer.zip','actions/artifacts/'+str(d['artifact']['id'])+'/zip',32*1024**2,120);raw=C.read(output/'artifact-transfer.zip',32*1024**2);C.need(C.pin(raw)=={k:d['artifact'][k]for k in('bytes','sha256')},'entire fixed artifact transferred bytes');(output/'artifact-transfer.zip').rename(originals/'artifact.zip')
   files,replay=C.input_replay(originals,d,output/'strict-input-replay');(output/'input-replay.json').write_bytes(C.encoded(replay));C.need(time.monotonic()-started<=225,'bounded input transfer/replay')
   status=dict(status='ACQUIRED_EXACT_ROOT_ACCEPTED_KERNEL_INPUT_ONLY',mode=MODE,descriptor=C.pin(C.read(C.HERE/'kernel-descriptor.json')),artifact=d['artifact'],members=d['members'],Image=d['Image'],config=d['config'],historical_transport=d['historical_transport'],current_metadata=C.pin(C.read(output/'current-run.json')),current_artifacts=C.pin(C.read(output/'current-artifacts.json')),fetches=fetches,owner=owner,root=str(output),seconds=round(time.monotonic()-started,6),kernel_boot='NOT_RUN',scope=C.P.SCOPE,Root_boot_acceptance='NOT_ISSUED');(output/'input-acquisition.json').write_bytes(C.encoded(status));return status
  except BaseException as e:
   (output/'input-failure.json').write_bytes(C.encoded(dict(status='FAILED_FIXED_INPUT_TRANSFER_NO_BOOT_AUTHORITY',mode=MODE,error_type=type(e).__name__,error=str(e)[:512],fetches=fetches,owner=owner,retry=False)));raise
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(acquire(a.output.absolute()),sort_keys=True))

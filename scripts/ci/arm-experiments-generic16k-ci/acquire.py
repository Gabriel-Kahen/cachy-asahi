#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One bounded original-log fetch per experiment; no binary/source execution."""
import argparse,base64,hashlib,importlib.util,io,json,os,re,sys,tarfile,zipfile
from pathlib import Path
HERE=Path(__file__).resolve().parent

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def decode(raw,origin,entry):
 need(len(raw)<=32*1024**2,'bounded original logs ZIP transport')
 with zipfile.ZipFile(io.BytesIO(raw)) as z:
  names=z.namelist();need(len(names)==len(set(names))<=128 and names.count('0_trial.txt')==1 and sum(i.file_size for i in z.infolist())<=512*1024**2,'bounded closed original logs directory')
  for member in z.infolist():
   need(not member.filename.startswith('/') and '\\' not in member.filename and all(p not in ('','.','..') for p in member.filename.rstrip('/').split('/')) and (member.external_attr>>16)&0o170000 in (0,0o100000,0o040000),'ordinary bounded original log member path/type')
  need(not z.getinfo('0_trial.txt').is_dir() and (z.getinfo('0_trial.txt').external_attr>>16)&0o170000 in (0,0o100000),'ordinary exact aggregate log')
  with z.open('0_trial.txt') as stream:text=stream.read(64*1024**2+1)
 need(len(text)<=64*1024**2,'bounded original aggregate log');lines=[re.sub(rb'^\d{4}-\d\d-\d\dT\S+ ',b'',l.removeprefix(b'\xef\xbb\xbf')) for l in text.splitlines()];head=b'CACHY_ASAHI_EVIDENCE_BEGIN experiment-artifacts ';tail=b'CACHY_ASAHI_EVIDENCE_END experiment-artifacts';begins=[i for i,l in enumerate(lines) if l.startswith(head)];ends=[i for i,l in enumerate(lines) if l==tail];need(len(begins)==len(ends)==1 and begins[0]<ends[0],'one original artifact frame');a,b=begins[0],ends[0];expected=head+('sha256='+origin['frame']['sha256']+' bytes='+str(origin['frame']['bytes'])).encode();need(lines[a]==expected,'original exact frame header');body=lines[a+1:b];need(all(re.fullmatch(rb'[A-Za-z0-9+/=]+',l) for l in body) and sum(map(len,body))<=12*1024**2,'strict bounded base64 frame');frame=base64.b64decode(b''.join(body),validate=True);need(pin(frame)==origin['frame'],'original compressed frame hash')
 result={};wanted={'experiment-artifacts/archive-manifest.json':entry['archive_manifest'],'experiment-artifacts/'+Path(entry['bundle']['path']).name:entry['bundle']}
 with tarfile.open(fileobj=io.BytesIO(frame),mode='r:gz') as archive:
  for member in archive:
   need(member.name in wanted and member.name not in result and member.isfile() and member.size<=8*1024**2,'two bounded original regular artifact members');data=archive.extractfile(member).read(member.size+1);need(len(data)==member.size and pin(data)=={k:wanted[member.name][k] for k in ('bytes','sha256')},'exact original input object pin');result[member.name]=data
 need(set(result)==set(wanted),'complete original bundle and allowlist');return {wanted[n]['path']:data for n,data in result.items()}

def acquire(source_root,output,logs_root=None,download=False):
 origins=json.loads((HERE/'origins.json').read_bytes())['experiments'];index=json.loads((source_root/'scripts/ci/arm-experiments-generic16k/retained-inputs.json').read_bytes())['experiments'];need(set(origins)==set(index) and len(index)==4,'four exact accepted originals');need(output.is_absolute() and not output.exists() and not any(p.is_symlink() for p in output.parents),'fresh ordinary owned acquisition root');need((logs_root is None)==download,'one explicit offline or CI acquisition mode')
 if download:need(os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ARCH')=='ARM64' and os.getuid()==os.geteuid()>0,'explicit disposable native CI download only')
 output.mkdir(mode=0o700);proof={}
 for experiment,origin in origins.items():
  if logs_root is not None:
   path=logs_root/f"arm-c0{experiment[-1]}-run{origin['run']}"/'logs.zip';need(path.is_file() and not path.is_symlink() and path.stat().st_size<=32*1024**2,'retained original log input');raw=path.read_bytes()
  else:
   spec=importlib.util.spec_from_file_location('arm_input_supervisor',source_root/'scripts/ci/glibc-owned-runtime/runner.py');supervisor=importlib.util.module_from_spec(spec);spec.loader.exec_module(supervisor);endpoint=f"repos/Gabriel-Kahen/cachy-asahi/actions/runs/{origin['run']}/attempts/1/logs";environment={k:os.environ[k] for k in ('PATH','HOME','GH_TOKEN') if k in os.environ};environment.update(LANG='C',LC_ALL='C');row,raw,stderr,error=supervisor.run_command(['gh','api',endpoint],output,environment,60,32*1024**2);need(error is None and row['exit_code']==0 and row['group_absence_verified'] is True and not stderr,'original immutable attempt logs unavailable; refuse without retry')
  objects=decode(raw,origin,index[experiment]);
  for name,data in objects.items():
   need(not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')),'fixed original input destination');path=output/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
   with path.open('xb') as stream:stream.write(data)
   path.chmod(0o400)
  proof[experiment]=dict(run=origin['run'],attempt=1,source=origin['source'],logs=pin(raw),original_logs=origin['logs'],logs_equal_original_transport=(pin(raw)==origin['logs']),input_authentication='EXACT_ORIGINAL_COMPRESSED_FRAME_AND_TWO_OBJECT_PINS',frame=origin['frame'],files={n:pin(data) for n,data in objects.items()})
 value=dict(status='EXACT_ORIGINAL_EIGHT_INPUTS_ACQUIRED_NO_EXECUTION',experiments=proof,hardware='NOT_RUN',runtime='NOT_RUN');(output/'input-proof.json').write_text(json.dumps(value,indent=2,sort_keys=True)+'\n');return value
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);mode=p.add_mutually_exclusive_group(required=True);mode.add_argument('--logs-root',type=Path);mode.add_argument('--download',action='store_true');a=p.parse_args();print(json.dumps(acquire(a.source_root,a.output,a.logs_root,a.download)))

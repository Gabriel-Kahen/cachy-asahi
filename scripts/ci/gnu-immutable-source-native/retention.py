"""Existing fixed544MiB/320-file export validation; no acceptance inference."""
import argparse,re,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import deploy as D
def verify(public):
 value=D.obj(D.read(public/'retention.json',4*1024**2));files=value['files'];D.need(value['status']=='BOUNDED_SOURCE_DERIVED_METADATA_AND_LOGS_ONLY'and type(files)is dict and len(files)<=320 and value['bytes']==sum(r['bytes']for r in files.values())<=544*1024**2,'original bounded complete export')
 actual=set()
 for p in public.rglob('*'):
  D.need(not p.is_symlink()and(p.is_dir()or p.is_file()),'no exported alias')
  if p.is_file():actual.add(p.relative_to(public).as_posix())
 D.need(actual==set(files)|{'retention.json'},'whole original export file closure')
 for n,row in files.items():D.need(n and not n.startswith('/')and all(x not in('','.','..')for x in n.split('/'))and D.pin(D.read(public/n,64*1024**2))==row,'whole bounded original export pin')
 return dict(status='PASS_COMPLETE_BOUNDED_EXPORT_NOT_RUNTIME_ACCEPTANCE',files=len(files),bytes=value['bytes'],acceptance=False)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--public',type=Path,required=True);a=p.parse_args();print(D.encoded(verify(a.public)).decode(),end='')

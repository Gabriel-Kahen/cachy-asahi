#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Export only exact kernel DATA from an explicitly selected immutable checkout."""
import argparse,os,re,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import custody as Q,kernel_data
def stage(source,revision,output):
 Q.verify();source=Q.safe(source);output=Q.safe(output)
 Q.need(re.fullmatch('[0-9a-f]{40}',revision or''),'explicit immutable kernel DATA revision')
 expected=kernel_data.expected_descriptor();rows=dict(Image=expected['Image'],config=expected['config'],**{'kernel-input.json':Q.pin(Q.enc(expected))})
 Q.need(Q.rows(source)==rows,'only three exact kernel DATA files, ignoring Git metadata')
 Q.need(subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True,timeout=15).strip()==revision,'kernel DATA checkout revision')
 tree=subprocess.check_output(['git','-C',str(source),'ls-tree','-r','-z',revision],timeout=15);blobs={}
 for entry in tree.split(b'\0'):
  if not entry:continue
  fields,name=entry.split(b'\t');mode,kind,oid=fields.decode('ascii').split();name=name.decode('ascii')
  Q.need(mode=='100644'and kind=='blob'and name in rows and name not in blobs,'only the three ordinary committed DATA blobs');blobs[name]=oid
 Q.need(set(blobs)==set(rows),'complete kernel DATA Git tree')
 subprocess.run(['git','-C',str(source),'diff','--exit-code','HEAD','--','.'],check=True,capture_output=True,timeout=15)
 values={n:Q.read(source/n)for n in rows};Q.need(not os.path.lexists(output)and output.parent.is_dir()and not source.is_relative_to(output)and not output.is_relative_to(source),'fresh disjoint kernel DATA export')
 Q.need(Q.rows(source)==rows and all(Q.pin(raw)==rows[n]for n,raw in values.items()),'late complete kernel DATA identity')
 import hashlib
 Q.need(all(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==blobs[name]for name,raw in values.items()),'all original Git DATA blob bytes joined')
 output.mkdir(mode=0o700)
 for name,raw in values.items():(output/name).write_bytes(raw);(output/name).chmod(0o644)
 kernel_data.verify(output,expected)
 return dict(status='EXACT_KERNEL_DATA_EXPORTED_NOT_BOOT',source=revision,files=3,boot='NOT_RUN')
if __name__=='__main__':
 import json
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--revision',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(stage(a.source,a.revision,a.output),sort_keys=True))

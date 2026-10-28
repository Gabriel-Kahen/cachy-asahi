#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fetch exactly three hash-bound official public inputs; no source execution."""
import argparse,concurrent.futures,hashlib,json,time,urllib.request
from pathlib import Path

PINS={
 'glibc-2.43.tar.gz':(40287809,'e1e622cbd635019090fa23260e5d9ec219b12f97ae7ae02f033d4ae42cf2c004'),
 'glibc-2.43.tar.gz.sig':(1018,'bfd0c5a9924e4f084281cd2f3ba96e5c6e87a6d363113e7a0f98c5151463c9e3'),
 'gnu-keyring.gpg':(3698125,'0fe55175b96a8ea1c4b670cc3fe11d56b341e4eff81b161ea49958ae550be6ca')}

def fetch(name,output):
    size,pin=PINS[name];url='https://ftp.gnu.org/gnu/'+('' if name=='gnu-keyring.gpg' else 'glibc/')+name
    temporary=output/(name+'.partial');start=time.monotonic();digest=hashlib.sha256();total=0
    try:
        request=urllib.request.Request(url,headers={'User-Agent':'cachy-asahi-official-release/1'})
        with urllib.request.urlopen(request,timeout=30) as response,temporary.open('xb') as stream:
            if response.url!=url:raise ValueError('unexpected official source redirect')
            while True:
                if time.monotonic()-start>180:raise TimeoutError('official input deadline')
                data=response.read(min(1024**2,size-total+1))
                if not data:break
                total+=len(data)
                if total>size:raise ValueError('official input byte bound')
                stream.write(data);digest.update(data)
        if total!=size or digest.hexdigest()!=pin:raise ValueError('official input identity differs')
        temporary.rename(output/name)
        return dict(path=name,url=url,bytes=total,sha256=pin)
    except BaseException:
        if temporary.exists():temporary.unlink()
        raise


def acquire(output):
    if output.exists() or any(p.is_symlink() for p in (output,*output.parents)):raise ValueError('fresh ordinary acquisition path required')
    output.mkdir(mode=0o700)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:rows=list(pool.map(lambda name:fetch(name,output),PINS))
    result=dict(status='HASH_BOUND_OFFICIAL_INPUTS_READY_UNSELECTED',files=rows)
    (output/'acquisition.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');return result


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    print(json.dumps(acquire(args.output.absolute()),sort_keys=True))

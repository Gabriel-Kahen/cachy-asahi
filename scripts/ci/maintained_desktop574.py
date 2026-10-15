#!/usr/bin/env python3
"""Reconstruct pinned public574 context; reuse existing six-file secret seed only."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

ENV={'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8','LANG':'C.UTF-8'}
ZLIB='zlib-1:1.3.2-3-aarch64.pkg.tar.xz'
ARCHBOOT='https://archboot.com/src/release/aarch64/2026.10/'


def digest(path):
    with path.open('rb')as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def plan(inputs,context):
    rows=inputs['packages'];names={r['name']for r in rows}
    if len(rows)!=574 or len(names)!=574:raise ValueError('574 unique packages required')
    result=[]
    def add(row,target,signature=False):
        suffix='.sig'if signature else''
        name=row['filename']+suffix
        if re.fullmatch(r'[A-Za-z0-9._+@:~-]{1,255}',name)is None:raise ValueError('unsafe filename')
        result.append(dict(filename=name,target=target,url=row['url']+suffix,
                           size=row['signature_size'if signature else'size'],
                           sha256=row['signature_sha256'if signature else'sha256']))
    for row in rows:
        add(row,context/'deps'/row['filename'])
        add(row,context/'deps'/(row['filename']+'.sig'),True)
    add(inputs['rootfs'],context/'rootfs.tar.gz')
    add(inputs['rootfs'],context/'rootfs.tar.gz.sig',True)
    for row in inputs['keyring_files']:add(row,context/'keys'/row['filename'])
    if len(result)!=1153 or len({r['target']for r in result})!=1153:raise ValueError('input membership')
    return result


def seed(inputs,items,cache,helper):
    expected={r['filename']:(r['size'],r['sha256'])for r in items}
    try:
        for name,size,pin,*_ in helper.OLD_FOUR_PRIVATE_ROWS+helper.RETAINED_BUBBLEWRAP_PRIVATE_ROWS:
            if expected.get(name)!=(size,pin):raise ValueError('retained seed differs from574 inputs')
        helper.seed_current_build_cache(cache,inputs['accepted_prior_input_sha256'])
    finally:
        # Nothing inherited by downloads, Docker or package code can retain tokens.
        os.environ.clear()
        os.environ.update(dict(ENV,HOME=str(cache.parent.parent/'home')))


def fetch(item,opener=urllib.request.urlopen):
    target=item['target'];size=item['size'];pin=item['sha256']
    if os.path.lexists(target):
        info=target.lstat()
        if not stat.S_ISREG(info.st_mode)or info.st_size!=size or digest(target)!=pin:
            raise ValueError('seeded input does not match pin: '+item['filename'])
        return dict(filename=item['filename'],source='existing_exact_seed',bytes=size)
    urls=[item['url']]
    if item['filename']in(ZLIB,ZLIB+'.sig'):urls.append(ARCHBOOT+item['filename'])
    for index,url in enumerate(urls):
        parsed=urllib.parse.urlsplit(url)
        if parsed.scheme!='https'or parsed.username or parsed.password:raise ValueError('HTTPS public source required')
        partial=target.with_name(target.name+'.partial');created=False
        try:
            with opener(url,timeout=60)as response:
                if urllib.parse.urlsplit(response.url).scheme!='https':raise ValueError('non-HTTPS redirect')
                with partial.open('xb')as output:
                    created=True;hasher=hashlib.sha256();count=0
                    while True:
                        raw=response.read(1048576)
                        if not raw:break
                        count+=len(raw)
                        if count>size:raise ValueError('download exceeds pin: '+item['filename'])
                        output.write(raw);hasher.update(raw)
                    if count!=size or hasher.hexdigest()!=pin:raise ValueError('download hash/size mismatch: '+item['filename'])
                    output.flush();os.fsync(output.fileno())
            partial.rename(target)
            return dict(filename=item['filename'],source=url,bytes=size)
        except urllib.error.HTTPError as error:
            error.close()
            if not(error.code in(404,410)and index+1<len(urls)):raise
        finally:
            if created:partial.unlink(missing_ok=True)
    raise ValueError('no matching public source: '+item['filename'])


def configure(inputs,context):
    hooks=inputs['bootstrap_hook_masks']
    if any(re.fullmatch(r'[A-Za-z0-9_.@+-]+\.hook',name)is None for name in hooks):raise ValueError('unsafe hook name')
    (context/'Dockerfile').write_text(DOCKERFILE)
    (context/'pacman.conf').write_text(PACMAN)
    (context/'disabled-hooks.txt').write_text(''.join(name+'\n'for name in sorted(set(hooks))))
    lock=''.join('{} {}\n'.format(row['name'],row['version'])for row in sorted(inputs['packages'],key=lambda row:row['name']))
    (context/'expected-packages.lock').write_text(lock)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=['seed','build'])
    parser.add_argument('--inputs',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();os.umask(0o077)
    output=args.output.absolute();context=output/'context'
    if args.mode=='seed':
        output.mkdir(mode=0o700);context.mkdir(mode=0o700)
        for name in['deps','keys']:(context/name).mkdir(mode=0o700)
        (output/'home').mkdir(mode=0o700)
    inputs=json.loads(args.inputs.read_bytes());items=plan(inputs,context)
    report=dict(status='FAILED',packages=574,native_build='NOT_RUN',hardware='NOT_RUN')
    try:
        if args.mode=='seed':
            helperpath=Path(__file__).absolute().parent/'old_four_seed.py'
            spec=importlib.util.spec_from_file_location('retained_public_seed',helperpath)
            helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
            seed(inputs,items,context/'deps',helper)
            report.update(status='SIX_EXACT_EXISTING_SEED_FILES_READY',seeded_files=6)
            return 0
        os.environ.clear();os.environ.update(dict(ENV,HOME=str(output/'home')))
        if platform.system()!='Linux'or platform.machine()not in('aarch64','arm64'):raise ValueError('native Linux ARM host required')
        architecture=subprocess.check_output(['/usr/bin/docker','info','--format','{{.Architecture}}'],text=True,env=os.environ).strip()
        if architecture not in('aarch64','arm64'):raise ValueError('native ARM Docker daemon required')
        report.update(host_arch=platform.machine(),daemon_arch=architecture)
        failures=[];success=[]
        def acquire(item):
            try:return fetch(item),None
            except Exception as error:
                return None,dict(filename=item['filename'],url=item['url'],kind=type(error).__name__,http_status=getattr(error,'code',None))
        with ThreadPoolExecutor(max_workers=6)as pool:
            for result,error in pool.map(acquire,items):
                if error:failures.append(error)
                else:success.append(result)
        report.update(acquired=len(success),failures=failures)
        if failures:raise ValueError('specific input acquisition failed')
        configure(inputs,context)
        command=['/usr/bin/docker','build','--progress=plain','--network=none','--pull=false',
                 '--platform=linux/arm64','--iidfile',str(output/'image-id'),str(context)]
        completed=subprocess.run(command,env=os.environ,stdin=subprocess.DEVNULL)
        report['build_returncode']=completed.returncode
        if completed.returncode:return 1
        image=(output/'image-id').read_text().strip()
        installed=subprocess.check_output(['/usr/bin/docker','run','--rm','--pull=never','--network=none',
            '--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--entrypoint=/bin/cat',image,'/builder-packages.lock'],env=os.environ)
        (output/'installed-packages.lock').write_bytes(installed)
        if installed!=(context/'expected-packages.lock').read_bytes():raise ValueError('installed574 inventory differs')
        report.update(status='PASS_NATIVE_OFFLINE_574_TRANSACTION',native_build='PASS',image=image)
        return 0
    except Exception as error:
        report.update(error_kind=type(error).__name__)
        print('574 preparation/build failed; see bounded report below',file=sys.stderr)
        return 1
    finally:
        for name in tuple(os.environ):
            if name.startswith(('CACHY_OLD_FOUR_','CACHY_RETAINED_BUBBLEWRAP_')):os.environ.pop(name,None)
        raw=json.dumps(report,sort_keys=True,indent=2)+'\n'
        (output/('seed-report.json'if args.mode=='seed'else'report.json')).write_text(raw);print(raw)


DOCKERFILE = 'FROM scratch\nADD rootfs.tar.gz /\nCOPY keys/ /usr/share/pacman/keyrings/\nCOPY deps/ /tmp/deps/\nCOPY --chmod=0644 pacman.conf /etc/pacman.conf\nCOPY disabled-hooks.txt /tmp/disabled-hooks.txt\nCOPY expected-packages.lock /expected-packages.lock\nRUN mkdir -p /builder-disabled-hooks \\\n && while IFS= read -r hook; do ln -s /dev/null "/builder-disabled-hooks/$hook"; done < /tmp/disabled-hooks.txt \\\n && pacman-key --init && pacman-key --populate archlinuxarm \\\n && pacman -U --noconfirm --noscriptlet /tmp/deps/*.pkg.tar.xz \\\n && ldconfig \\\n && pacman -Q | LC_ALL=C sort > /builder-packages.lock \\\n && cmp /expected-packages.lock /builder-packages.lock \\\n && rm -rf /tmp/deps /var/cache/pacman/pkg/*\n'
PACMAN = '[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nHookDir = /builder-disabled-hooks\n'


if __name__=='__main__':raise SystemExit(main())

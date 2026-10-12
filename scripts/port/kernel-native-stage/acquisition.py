#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Acquire one exact kernel trial's data into NEW ignored storage; never install."""
import argparse
from contextlib import contextmanager
import ctypes
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import urllib.parse
import urllib.request

sys.path.insert(0,str(Path(__file__).resolve().parent))

from common import PREFIX, SOURCE, digest, load, module, need, regular, save

MAX_TOTAL = 1200 * 1024**2
MAX_SECONDS = 1800
CHUNK = 1024**2
PINS = {
    PREFIX+'dependencies.json':'cf4d6eaa80ab15f1b1359d161b7b07e187f37df6071e5f628e235cb9689a93d6',
    SOURCE+'candidate.json':'d26f691006a24f76db11f2f353e0ec10d93425ce2b6f8970a446b7bd34c98617',
    SOURCE+'harness.py':'f2d6fc62d28b0c189469ca7cf8293f10c574ecd0459c33c013bf1a271b8a5ebf',
    'scripts/ci/native_arm.py':'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898',
}


class Budget:
    def __init__(self, seconds=MAX_SECONDS, maximum=MAX_TOTAL):
        need(0 < seconds <= MAX_SECONDS and 0 < maximum <= MAX_TOTAL,'finite budget required')
        self.deadline = time.monotonic()+seconds; self.maximum=maximum; self.bytes=0

    def check(self):
        remaining=self.deadline-time.monotonic(); need(remaining>0,'acquisition deadline exceeded')
        return remaining

    def add(self,size):
        self.check(); self.bytes+=size; need(self.bytes<=self.maximum,'acquisition byte cap exceeded')


def canonical(path):
    path=Path(path)
    need(path.is_absolute() and '..' not in path.parts and path==path.resolve() and
         not any(p.is_symlink() for p in (path,*path.parents)),'canonical nonsymlink path required')
    return path


def record(item):
    need(set(item)=={'filename','size','sha256','url'} and
         isinstance(item['filename'],str) and re.fullmatch(r'[A-Za-z0-9@+:_.-]+',item['filename']) and
         item['filename'] not in ('.','..'),'flat bounded input name required')
    need(type(item['size']) is int and 0<=item['size']<=MAX_TOTAL and
         re.fullmatch(r'[0-9a-f]{64}',item['sha256'] or ''),'input size/hash required')
    parsed=urllib.parse.urlsplit(item['url'])
    need(parsed.scheme=='https' and not parsed.query and not parsed.fragment and not parsed.username and
         not parsed.password and parsed.hostname in {'ca.us.mirror.archlinuxarm.org','github.com','raw.githubusercontent.com'},
         'primary HTTPS input URL required')
    return item


def allowed_response(item,url):
    if url==item['url']: return True
    return item['url']=='https://github.com/AsahiLinux/linux/archive/asahi-7.1.13-3.tar.gz' and url in (
        'https://codeload.github.com/AsahiLinux/linux/tar.gz/refs/tags/asahi-7.1.13-3',
        'https://codeload.github.com/AsahiLinux/linux/tar.gz/asahi-7.1.13-3')


class ExactRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self,item): self.item=item
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        need(allowed_response(self.item,newurl),'unapproved redirect refused')
        return super().redirect_request(req,fp,code,msg,headers,newurl)


def transfer(stream,destination,item,budget):
    total=0; hashed=hashlib.sha256()
    while True:
        budget.check(); block=stream.read(CHUNK)
        if not block: break
        total+=len(block); need(total<=item['size'],'input exceeded exact size')
        budget.add(len(block)); hashed.update(block); destination.write(block)
    need(total==item['size'] and hashed.hexdigest()==item['sha256'],'input size/hash differs')



def _parent_death_guard(expected_parent):
    libc=ctypes.CDLL(None,use_errno=True)
    need(libc.prctl(1,signal.SIGKILL,0,0,0)==0,'HTTP parent-death guard failed')
    need(os.getppid()==expected_parent,'HTTP parent changed before guard')


def _http_child(item,destination,budget,send,receive,expected_parent):
    # The child owns its own group and can always be terminated even if a
    # caller masked cancellation signals. It executes only this data fetch.
    receive.close()
    _parent_death_guard(expected_parent)
    os.setsid()
    for sig in (signal.SIGTERM,signal.SIGINT): signal.signal(sig,signal.SIG_DFL)
    signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGTERM,signal.SIGINT})
    try:
        opener=urllib.request.build_opener(ExactRedirect(item))
        request=urllib.request.Request(item['url'],headers={'User-Agent':'cachy-asahi-kernel-data/1','Accept-Encoding':'identity'})
        with opener.open(request,timeout=min(30,budget.check())) as response:
            need(allowed_response(item,response.url),'unapproved final response URL')
            length=response.headers.get('Content-Length')
            need(length is None or length.isdecimal() and int(length)==item['size'],'advertised size differs')
            transfer(response,destination,item,budget)
        destination.flush();os.fsync(destination.fileno())
        send.send((True,item['size']))
    except BaseException as error:
        send.send((False,type(error).__name__+': '+str(error)[:512]))
    finally:
        send.close()


def _stop_download(process):
    if process.is_alive():
        # Only this freshly created child/group is targeted. setsid might not
        # yet have executed when cancellation arrives, so handle that race.
        try: os.killpg(process.pid,signal.SIGTERM)
        except ProcessLookupError: process.terminate()
        process.join(timeout=0.25)
    if process.is_alive():
        try: os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError: process.kill()
        process.join(timeout=1)
    need(not process.is_alive(),'HTTP child cleanup failed')
    process.close()



@contextmanager
def _masked_cancellation():
    previous=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGTERM,signal.SIGINT})
    try: yield
    finally: signal.pthread_sigmask(signal.SIG_SETMASK,previous)


@contextmanager
def _term_cancellation():
    previous=signal.getsignal(signal.SIGTERM)
    def cancel(signum,frame): raise KeyboardInterrupt('HTTP acquisition cancelled')
    if previous==signal.SIG_DFL: signal.signal(signal.SIGTERM,cancel)
    try: yield
    finally:
        if previous==signal.SIG_DFL: signal.signal(signal.SIGTERM,previous)

def http_download(item,destination,budget):
    """Enforce the aggregate deadline outside all potentially blocking I/O."""
    context=multiprocessing.get_context('fork')
    receive,send=context.Pipe(duplex=False)
    process=context.Process(target=_http_child,args=(item,destination,budget,send,receive,os.getpid()))
    with _term_cancellation():
        started=False
        try:
            budget.check()
            with _masked_cancellation():
                process.start();started=True;send.close()
            process.join(timeout=budget.check())
            need(not process.is_alive(),'acquisition deadline exceeded during HTTP read')
            budget.check()
            need(process.exitcode==0 and receive.poll(),'HTTP child failed without receipt')
            success,value=receive.recv();need(success,'HTTP acquisition failed: '+str(value))
            budget.add(value)
        finally:
            with _masked_cancellation():
                try:
                    if started: _stop_download(process)
                    else: process.close()
                finally:
                    receive.close();send.close()


def fetch(item,cache,budget,reuse=()):
    record(item);canonical(cache);need(cache.is_dir(),'owned cache required')
    target=cache/item['filename'];need(not target.exists() and not target.is_symlink(),'new cache file required')
    temporary=cache/('.'+item['filename']+'.partial')
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    reused=None
    try:
        with os.fdopen(fd,'wb') as dst:
            for candidate in reuse:
                candidate=Path(candidate)
                if not candidate.exists() and not candidate.is_symlink(): continue
                canonical(candidate);regular(candidate,MAX_TOTAL)
                need(candidate.stat().st_size==item['size'] and digest(candidate)==item['sha256'],
                     'reuse input size/hash differs')
                descriptor=os.open(candidate,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(descriptor,'rb') as src:
                    info=os.fstat(src.fileno())
                    need(stat.S_ISREG(info.st_mode) and info.st_size==item['size'],'reuse file changed')
                    transfer(src,dst,item,budget)
                need(digest(candidate)==item['sha256'],'reuse file changed after copy')
                reused=str(candidate);break
            else:
                http_download(item,dst,budget)
            dst.flush();os.fsync(dst.fileno())
        need(digest(temporary)==item['sha256'],'stored input hash differs');os.rename(temporary,target)
        return {'filename':item['filename'],'bytes':item['size'],'sha256':item['sha256'],'reused':reused}
    finally:
        temporary.unlink(missing_ok=True)


def items(dependencies,candidate):
    packages=[]
    for p in dependencies['packages']:
        need(p['url']=='https://ca.us.mirror.archlinuxarm.org/aarch64/extra/'+p['filename'],'exact official package URL required')
        packages.extend(({'filename':p['filename'],'size':p['size'],'sha256':p['sha256'],'url':p['url']},
                         {'filename':p['filename']+'.sig','size':p['signature_size'],'sha256':p['signature_sha256'],'url':p['url']+'.sig'}))
    archive={'filename':'asahi.tar.gz','size':candidate['archive']['bytes'],'sha256':candidate['archive']['sha256'],'url':candidate['archive']['url']}
    patch={'filename':'candidate.patch','size':candidate['patch']['bytes'],'sha256':candidate['patch']['sha256'],'url':candidate['patch']['url']}
    all_items=packages+[archive,patch]+dependencies['keyring_files']
    for item in all_items:record(item)
    need(len(packages)==30 and len(all_items)==35 and len({p['filename'] for p in all_items})==35 and
         sum(p['size'] for p in all_items)<=MAX_TOTAL,'exact finite acquisition set required')
    return packages,archive,patch


def signatures(root,dependencies,cache,keys,output,budget):
    native=module('kernel_acquisition_native',root/'scripts/ci/native_arm.py')
    results=[]
    with tempfile.TemporaryDirectory(prefix='public-gpg-',dir=output) as directory:
        home=Path(directory);home.chmod(0o700)
        command=['/usr/bin/gpg','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve','--no-autostart']
        imported=subprocess.run(command+['--import',str(keys/'archlinuxarm.gpg')],capture_output=True,timeout=min(60,budget.check()))
        need(imported.returncode==0,'pinned public-key import failed')
        for p in dependencies['packages']:
            verified=subprocess.run(command+['--status-fd','1','--verify',str(cache/(p['filename']+'.sig')),str(cache/p['filename'])],
                                    capture_output=True,text=True,timeout=min(60,budget.check()))
            need(verified.returncode==0 and len(verified.stdout)+len(verified.stderr)<=65536,'signature command failed')
            native.valid_signature(verified.stdout,dependencies['signer_fingerprint'])
            need(not re.search(r'^\[GNUPG:\] (FAILURE|ERROR|NODATA|BADARMOR)\b',verified.stdout,re.M),'signature failure status')
            results.append({'name':p['name'],'exit':verified.returncode,'status':verified.stdout})
    return results


def acquire(root,output,reuse_cache_paths=()):
    root=canonical(root);output=canonical(output);owned=root/'artifacts/kernel-native-stage'
    need(output.is_relative_to(owned) and output!=owned and not output.exists(),'new owned ignored output required')
    for path,pin in PINS.items():
        regular(root/path);need(digest(root/path)==pin,'frozen acquisition source differs: '+path)
    dependencies=load(root/(PREFIX+'dependencies.json'),PINS[PREFIX+'dependencies.json'])
    candidate=load(root/(SOURCE+'candidate.json'),PINS[SOURCE+'candidate.json'])
    packages,archive,patch=items(dependencies,candidate)
    config=root/(PREFIX+'embedded-config.txt');regular(config,1024**2)
    need(config.stat().st_size==candidate['config']['bytes'] and digest(config)==candidate['config']['sha256'],'embedded config pin differs')
    caches=tuple(canonical(p) for p in reuse_cache_paths)
    output.mkdir(parents=True,mode=0o700);cache=output/'packages';cache.mkdir(mode=0o700);keys=output/'keys';keys.mkdir(mode=0o700)
    budget=Budget();report={'status':'FAIL','native_execution':'NOT RUN','installation':'NOT RUN','inputs':[]}
    try:
        for item in packages:
            report['inputs'].append(fetch(item,cache,budget,[p/item['filename'] for p in caches]))
        report['inputs'].append(fetch(archive,output,budget,[p/name for p in caches for name in ('asahi.tar.gz','linux-asahi-7.1.13-3.tar.gz','source-snapshot.tar.gz')]))
        report['inputs'].append(fetch(patch,output,budget,[p/name for p in caches for name in ('candidate.patch','0d61333f6e03e8fa4620e33e1bac4c644a9412c6.patch')]))
        for item in dependencies['keyring_files']:
            report['inputs'].append(fetch(item,keys,budget,[p/item['filename'] for p in caches]))
        report['signatures']=signatures(root,dependencies,cache,keys,output,budget)
        config_copy=output/'embedded-config';budget.add(config.stat().st_size);shutil.copyfile(config,config_copy)
        need(digest(config_copy)==candidate['config']['sha256'] and digest(config)==candidate['config']['sha256'],'config copy differs')
        harness=module('kernel_acquisition_harness',root/(SOURCE+'harness.py'))
        # The held harness's output boundary becomes a nested subtree of this
        # acquisition directory. Full-source extraction is expressly disabled.
        harness.ROOT=output
        baseline=output/'artifacts/kernel-candidates/baseline';after=output/'artifacts/kernel-candidates/candidate'
        arguments={'lock':root/(SOURCE+'candidate.json'),'lock_sha256':PINS[SOURCE+'candidate.json'],
                   'archive':output/'asahi.tar.gz','config':config_copy,'patch':output/'candidate.patch','full_source':False}
        budget.check();before_report=harness.run(SimpleNamespace(**arguments,mode='baseline',output=baseline))
        budget.check();after_report=harness.run(SimpleNamespace(**arguments,mode='apply',output=after))
        need(not any(re.search(rb'(?i)offset|fuzz|reject', (after/x).read_bytes()) for x in ('dry-run.log','apply.log')),'nonexact patch output')
        report['source_slices']={'baseline':before_report,'candidate':after_report}
        result={'archive':str(output/'asahi.tar.gz'),'config':str(config_copy),'patch':str(output/'candidate.patch'),
                'bio_baseline':str(baseline/'source-slice/block/bio.c'),'bio_candidate':str(after/'source-slice/block/bio.c'),
                'package_cache':str(cache),'key_dir':str(keys)}
        need(sum(p.stat().st_size for p in output.rglob('*') if p.is_file())<=MAX_TOTAL,'final storage cap exceeded')
        budget.check();report.update(status='PASS-acquired-source-data',bytes=budget.bytes,arguments=result)
        return result
    finally:save(output/'acquisition.json',report)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);parser.add_argument('--reuse-cache',type=Path,action='append',default=[])
    args=parser.parse_args();print(json.dumps(acquire(args.root,args.output,args.reuse_cache),sort_keys=True));return 0

if __name__=='__main__':raise SystemExit(main())

# SPDX-License-Identifier: MIT
"""Two declared direct transports for the unchanged historical Asahi archive."""
import json
import hashlib
import os
from pathlib import Path
import stat
import time
import urllib.error
import urllib.request

URLS=('https://codeload.github.com/AsahiLinux/linux/tar.gz/refs/tags/asahi-7.1.13-3',
      'https://codeload.github.com/AsahiLinux/linux/tar.gz/asahi-7.1.13-3')
SIZE=262965559
SHA='874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad'
REVISION='94fb23346d522edf53722357c426a3e58030beea'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args):raise ValueError('direct archive transport must not redirect')


def opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())


def cache_key():return 'asahi-kernel-source-v1-'+SHA+'-'+str(SIZE)


def ordinary(path):
    if not path.is_absolute() or '..' in path.parts or any(c in str(path) for c in '\r\n') or any(p.is_symlink() for p in (path,*path.parents)):
        raise ValueError('ordinary absolute cache/input paths required')


def copy_exact(source,target,deadline):
    """Hash the exact bytes being copied, then publish with atomic no-clobber."""
    ordinary(source);ordinary(target)
    partial=target.with_name(target.name+'.partial');created=False;src=None;dst=None
    try:
        src=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        before=os.fstat(src)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.geteuid() or before.st_mode&0o022 or before.st_size!=SIZE:
            raise ValueError('cache/archive type ownership mode size differs')
        if target.exists() or target.is_symlink():raise ValueError('archive destination exists')
        dst=os.open(partial,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);created=True
        digest=hashlib.sha256();count=0
        with os.fdopen(dst,'wb',closefd=False) as output:
            while True:
                if time.monotonic()>=deadline:raise TimeoutError('archive validation deadline')
                raw=os.read(src,1024**2)
                if not raw:break
                count+=len(raw)
                if count>SIZE:raise ValueError('archive exceeds exact size')
                digest.update(raw);output.write(raw)
            output.flush();os.fsync(dst)
        after=os.fstat(src)
        identity=lambda row:(row.st_dev,row.st_ino,row.st_size,row.st_mtime_ns,row.st_ctime_ns)
        if count!=SIZE or digest.hexdigest()!=SHA or identity(before)!=identity(after):
            raise ValueError('copied archive size/hash/identity differs')
        os.link(partial,target,follow_symlinks=False);partial.unlink();created=False
        parent=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(parent)
        finally:os.close(parent)
        return dict(bytes=count,sha256=digest.hexdigest(),path=str(target))
    finally:
        if src is not None:os.close(src)
        if dst is not None:os.close(dst)
        if created:partial.unlink()


def cache_state(archive,hit,matched,retained_archive=None):
    ordinary(archive)
    if archive.name!='kernel.tar.gz' or archive.parent.name!=SHA or not archive.parent.is_dir():
        raise ValueError('dedicated content-addressed archive directory required')
    if hit not in ('true','false','') or not isinstance(matched,str):raise ValueError('explicit cache restore outputs required')
    names={p.name for p in archive.parent.iterdir()}
    if hit=='true':
        if matched!=cache_key() or names!={'kernel.tar.gz'}:raise ValueError('exact cache hit/key/closed archive required')
        return 'HIT'
    explicit_seed=retained_archive is not None and Path(retained_archive)==archive and names=={'kernel.tar.gz'}
    if matched or (names and not explicit_seed):raise ValueError('partial/unexpected cache restore refused')
    return 'MISS'


def acquire(fetch,item,out,manifest_sha256,receipt_path,*,cache_archive=None,cache_hit=None,cache_matched_key=None,retained_archive=None):
    if item!=fetch.EXPECTED[0] or (item['bytes'],item['sha256'],item['source_revision'])!=(SIZE,SHA,REVISION):
        raise ValueError('unchanged historical kernel pins required')
    report=dict(status='FAIL',original_input=item,historical_manifest_sha256=manifest_sha256,
        transport_policy='TWO_DIRECT_TAG_URLS_NO_REDIRECT_300S',attempts=[],total_deadline_seconds=300,
        source_revision=REVISION,bytes=SIZE,sha256=SHA,extraction='NOT_PERFORMED')
    try:
        with fetch.deadline_alarm(300):
            deadline=time.monotonic()+300
            if cache_archive is not None:
                cache_archive=Path(cache_archive)
                report['cache']=dict(key=cache_key(),action_commit='0057852bfaa89a56745cba8c7296529d2fc39830',status='VALIDATING',save_requested=False,trust='EXACT_HISTORICAL_HASH_RECHECK_NO_SIGNATURE_CREDIT',archive_path=str(cache_archive),restore_hit=str(cache_hit)[:8],restore_matched_key=str(cache_matched_key)[:512])
                state=cache_state(cache_archive,cache_hit,cache_matched_key,retained_archive);report['cache']['status']=state
                if state=='HIT':
                    restored=copy_exact(cache_archive,out/'kernel.tar.gz',deadline)
                    report.update(status='RESTORED_HASH_VERIFIED',result=restored)
                    report['cache'].update(status='HIT_HASH_VERIFIED',validation=restored)
                    return report
            if retained_archive is not None:
                retained_archive=Path(retained_archive)
                result=copy_exact(retained_archive,out/'kernel.tar.gz',deadline)
                report.update(status='RETAINED_ARCHIVE_HASH_VERIFIED',result=result,
                    retained_source=dict(kind='EXPLICIT_LOCAL_RETAINED_ARCHIVE',path=str(retained_archive),bytes=SIZE,sha256=SHA,cache_hit_credit=False))
                if cache_archive is not None:
                    prepared=result if retained_archive==cache_archive else copy_exact(out/'kernel.tar.gz',cache_archive,deadline)
                    report['cache'].update(status='MISS_RETAINED_ARCHIVE_HASH_VERIFIED',validation=prepared,save_requested=True)
                return report
            for index,url in enumerate(URLS):
                attempt=dict(requested_url=url,status='FAIL');report['attempts'].append(attempt)
                selected=dict(item,url=url,allowed_hosts=['codeload.github.com'])
                try:
                    result=fetch.fetch_one(selected,out,deadline,opener=opener())
                    if result['final_url']!=url or result['bytes']!=SIZE or result['sha256']!=SHA:
                        raise ValueError('direct final URL/content identity differs')
                    attempt['status']='PASS';report.update(status='FETCHED_HASH_VERIFIED',result=result)
                    break
                except (urllib.error.HTTPError,urllib.error.URLError,TimeoutError,OSError) as error:
                    attempt.update(error_type=type(error).__name__,reason=str(error)[:200])
                    status=error.code if isinstance(error,urllib.error.HTTPError) else None
                    attempt['http_status']=status
                    header=error.headers.get('Retry-After','') if isinstance(error,urllib.error.HTTPError) and error.headers else ''
                    if isinstance(error,urllib.error.HTTPError):error.close()
                    if status is not None and status not in (429,500,502,503,504):raise
                    if index+1==len(URLS):raise
                    # One explicit capped pause within the same total deadline.
                    pause=min(10,int(header)) if header.isdecimal() and len(header)<=6 else 2
                    if time.monotonic()+pause>=deadline:raise TimeoutError('no remaining bounded transport window')
                    attempt['pause_before_next_seconds']=pause;time.sleep(pause)
            if cache_archive is not None:
                prepared=copy_exact(out/'kernel.tar.gz',cache_archive,deadline)
                report['cache'].update(status='MISS_FETCHED_HASH_VERIFIED',validation=prepared,save_requested=True)
            return report
    except BaseException as error:
        report.update(status='FAIL',error_type=type(error).__name__,reason=str(error)[:200]);raise
    finally:
        report['partial_absent']=not (out/'kernel.tar.gz.partial').exists()
        if cache_archive is not None:report['cache_partial_absent']=not Path(str(cache_archive)+'.partial').exists()
        raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
        if len(raw)>16384:raise ValueError('acquisition receipt bound')
        with receipt_path.open('xb') as stream:stream.write(raw)
        print(raw.decode(),flush=True)

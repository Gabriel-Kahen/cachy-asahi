# SPDX-License-Identifier: MIT
"""Two declared direct transports for the unchanged historical Asahi archive."""
import json
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


def acquire(fetch,item,out,manifest_sha256,receipt_path):
    if item!=fetch.EXPECTED[0] or (item['bytes'],item['sha256'],item['source_revision'])!=(SIZE,SHA,REVISION):
        raise ValueError('unchanged historical kernel pins required')
    report=dict(status='FAIL',original_input=item,historical_manifest_sha256=manifest_sha256,
        transport_policy='TWO_DIRECT_TAG_URLS_NO_REDIRECT_300S',attempts=[],total_deadline_seconds=300,
        source_revision=REVISION,bytes=SIZE,sha256=SHA,extraction='NOT_PERFORMED')
    try:
        with fetch.deadline_alarm(300):
            deadline=time.monotonic()+300
            for index,url in enumerate(URLS):
                attempt=dict(requested_url=url,status='FAIL');report['attempts'].append(attempt)
                selected=dict(item,url=url,allowed_hosts=['codeload.github.com'])
                try:
                    result=fetch.fetch_one(selected,out,deadline,opener=opener())
                    if result['final_url']!=url or result['bytes']!=SIZE or result['sha256']!=SHA:
                        raise ValueError('direct final URL/content identity differs')
                    attempt['status']='PASS';report.update(status='FETCHED_HASH_VERIFIED',result=result)
                    return report
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
    except BaseException as error:
        report.update(error_type=type(error).__name__,reason=str(error)[:200]);raise
    finally:
        report['partial_absent']=not (out/'kernel.tar.gz.partial').exists()
        raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
        if len(raw)>16384:raise ValueError('acquisition receipt bound')
        with receipt_path.open('xb') as stream:stream.write(raw)
        print(raw.decode(),flush=True)

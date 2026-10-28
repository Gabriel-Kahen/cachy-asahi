#!/usr/bin/env python3
"""Read-only, bounded HTTPS availability probe for the original 501 input pins."""
import argparse
import concurrent.futures
from datetime import datetime, timezone
import json
from pathlib import Path
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ci'))
import native_arm as native
import preview

ORIGINAL_PIN='7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41'
MIRRORS=('fl.us.mirror.archlinuxarm.org','de3.mirror.archlinuxarm.org',
         'nj.us.mirror.archlinuxarm.org','mirror.archlinuxarm.org')
PRIVATE=Path('/home/gabe/.local/share/cachy-asahi/private-inputs/cachy-asahi-native-arm-audit')


def items(lock):
    result=lock['keyring_files']+[lock['rootfs'],native.signature_item(lock['rootfs'])]
    for package in lock['packages']:
        result.extend([package,native.signature_item(package)])
    preview.need(len(result)==501 and len({i['filename'] for i in result})==501,'exact unique 501 input set required')
    for item in result:
        native.check_pin(item['sha256'])
        url=urllib.parse.urlsplit(item['url'])
        preview.need(Path(item['filename']).name==item['filename'] and url.scheme=='https' and
                     not url.query and not url.fragment and not url.username and
                     url.hostname in ('raw.githubusercontent.com','ca.us.mirror.archlinuxarm.org'), 'original URL boundary refused')
        preview.need(isinstance(item['size'],int) and 0<=item['size']<=2**31,'input size refused')
    return result


def probe(url, expected_size, opener=urllib.request.urlopen):
    """HEAD body never read; fallback one-byte Range GET only on 405/501."""
    parsed=urllib.parse.urlsplit(url)
    preview.need(parsed.scheme=='https' and parsed.hostname in
                 ('raw.githubusercontent.com','ca.us.mirror.archlinuxarm.org')+MIRRORS and
                 not parsed.query and not parsed.fragment and not parsed.username,'nonofficial probe refused')
    result={'url':url,'method':'HEAD','expected_bytes':expected_size,'authentication':'NOT RUN',
            'TLS_verification':'required; not relaxed','body_bytes_read':0}
    try:
        try:
            response=opener(urllib.request.Request(url,method='HEAD'),timeout=15)
        except urllib.error.HTTPError as e:
            if e.code not in (405,501):
                raise
            e.close()
            result['head_status']=e.code
            result['method']='GET Range bytes=0-0; close after at most one byte'
            response=opener(urllib.request.Request(url,headers={'Range':'bytes=0-0'},method='GET'),timeout=15)
        with response:
            actual=urllib.parse.urlsplit(response.url)
            preview.need(actual.scheme=='https' and actual.hostname in
                         ('raw.githubusercontent.com','ca.us.mirror.archlinuxarm.org')+MIRRORS and
                         not actual.query and not actual.fragment and not actual.username,'nonofficial/insecure redirect refused')
            result.update({'http_status':response.status,'effective_url':response.url,
                           'content_length':response.headers.get('Content-Length'),
                           'content_range':response.headers.get('Content-Range')})
            if result['method']!='HEAD':
                result['body_bytes_read']=len(response.read(1))
                result['availability']='HTTP-success; one-byte probe only, no full-size authentication'
            else:
                length=response.headers.get('Content-Length')
                result['availability']='HTTP-success-size-match' if length is not None and length.isdigit() and int(length)==expected_size else 'HTTP-success-length-unconfirmed-or-mismatch'
            return result
    except urllib.error.HTTPError as e:
        result.update({'http_status':e.code,'failure_kind':'HTTPError','diagnostic':str(e),'availability':'unavailable'})
        e.close()
    except (urllib.error.URLError,ssl.SSLError,OSError,ValueError) as e:
        result.update({'http_status':None,'failure_kind':type(e).__name__,'diagnostic':str(e), 'availability':'unavailable'})
    return result


def audit(lock, output, probe_fn=probe):
    frozen=items(lock)
    receipt={'schema':1,'scope':'original-501-input-availability; not authentication','source_sha256':native.sha(Path(__file__)),
             'input_lock_sha256':ORIGINAL_PIN,'observed_start_utc':datetime.now(timezone.utc).isoformat(),
             'runner_failure':'38199269315 HTTP404 before native build','parallel_workers':4,'inputs':[],
             'unavailable':[],'alternate_mirrors':[],'native_build':'NOT RUN','hardware':'NOT RUN',
             'published_archive_bytes':False,'source_versions_changed':False}
    def check(item):
        return {'filename':item['filename'],'sha256':item['sha256'],'expected_bytes':item['size']} | probe_fn(item['url'],item['size'])
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        receipt['inputs']=list(pool.map(check,frozen))
    receipt['unavailable']=[r for r in receipt['inputs'] if r['availability']=='unavailable']
    alternatives=[]
    for failed in receipt['unavailable']:
        url=urllib.parse.urlsplit(failed['url'])
        if url.hostname=='ca.us.mirror.archlinuxarm.org':
            for host in MIRRORS:
                alternatives.append({'filename':failed['filename'],'sha256':failed['sha256'],'url':'https://'+host+url.path,'size':failed['expected_bytes']})
    def alternate(item):
        return {'filename':item['filename'],'pinned_sha256':item['sha256']} | probe_fn(item['url'],item['size'])
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        receipt['alternate_mirrors']=list(pool.map(alternate,alternatives))
    retained=[]
    for item in frozen:
        path=PRIVATE/item['filename']
        present=path.is_file() and not path.is_symlink()
        match=present and path.stat().st_size==item['size'] and native.sha(path)==item['sha256']
        retained.append({'filename':item['filename'],'sha256':item['sha256'],'bytes':item['size'],'retained_pin_match':bool(match),
                         'signature_authentication':'prior evidence only; not repeated by this availability probe'})
    receipt.update({'retained_inputs':retained,'retained_pin_match_count':sum(r['retained_pin_match'] for r in retained),
                    'unavailable_count':len(receipt['unavailable']), 'observed_end_utc':datetime.now(timezone.utc).isoformat(),
                    'status':'unavailable-original-inputs' if receipt['unavailable'] else 'all-original-URLs-HTTP-accessible-not-authenticated'})
    native.save(output,receipt)
    return receipt


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input-lock',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    try:
        lock=preview.load(a.input_lock,ORIGINAL_PIN)
        preview.need(not a.output.exists() and not a.output.is_symlink(),'new output required')
        r=audit(lock,a.output)
        print(f'{r["status"]}: {r["unavailable_count"]} unavailable; {r["retained_pin_match_count"]}/501 retained hashes match')
        return 0 if not r['unavailable'] else 1
    except (ValueError,OSError,KeyError):
        print('REFUSED original input pin/boundary or output prerequisite')
        return 2


if __name__=='__main__':raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite exact Xvfb recovery: known mirrors/archive metadata, no version fallback."""
import argparse,hashlib,importlib.util,json,os,re,resource,signal,sys,tempfile,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('held_six_intake',HERE.parent/'six_pair_intake/intake.py');I=importlib.util.module_from_spec(spec);spec.loader.exec_module(I)
P=I.P
EXTRA={'archlinuxarm.org','tardis.tiny-vps.com'}
I.HOSTS.update(EXTRA)
NAME='xorg-server-xvfb-21.1.25-1-aarch64.pkg.tar.xz'
SHA='9799e250607b6ebe1b143138fe7cf64366fc94127bb5fbaea6c456c68c2bf715'
SIG='62b1b083753f451ae512b37ee0478e47db63ef9f6dc10c5ef3e722d0f8ad4958'

def metadata(url,budget,entry):
    I.official(url);budget.remaining();budget.gets+=1
    if budget.gets>12:raise ValueError('twelve total request cap')
    redirects=I.Redirect();entry.update(url=url,initial_get_number=budget.gets,redirects=redirects.redirects)
    try:
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),redirects)
        with opener.open(urllib.request.Request(url,headers={'Accept-Encoding':'identity'}),timeout=min(12,budget.remaining()))as response:
            entry.update(http_status=response.status,effective_url=response.url)
            body=response.read(65537);budget.consume(len(body))
            if len(body)>65536:raise ValueError('metadata exceeds 64KiB')
            entry.update(bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),status='READ_ONLY_METADATA')
            return body.decode('utf-8')
    except urllib.error.HTTPError as error:entry.update(status='HOLD_HTTP',http_status=error.code);error.close();raise ValueError('HTTP '+str(error.code))from None

def archive_paths(html,base):
    # Follow only bounded directory metadata, never arbitrary discovered payloads.
    return [urllib.parse.urljoin(base,href)for href in re.findall(r'href=["\']([^"\']+)["\']',html)if href.startswith(('repos/','packages/'))and not any(c in href for c in ['?','#','..'])][:2]

def run(output):
    budget=I.Budget();output.mkdir(mode=0o700,exist_ok=False);(output/'archives').mkdir(mode=0o700)
    contract=json.loads((HERE.parent/'six_pair_intake/inputs.json').read_text());item=next(p for p in contract['pairs']if p['name']=='xorg-server-xvfb');pin=item['archive']
    assert pin['filename']==NAME and pin['bytes']==705376 and pin['sha256']==SHA and pin['signature_bytes']==566 and pin['signature_sha256']==SIG
    original=Path('/tmp/cachy-asahi-arm16k-ui-six-pair-intake-20261115/receipt.json');old=json.loads(original.read_text());preserved={str(original):P.sha(original)}
    for pair in old['pairs']:
        if pair['status'].startswith('PASS'):
            for obj in pair['objects']:preserved[obj['path']]=P.sha(Path(obj['path']))
    report={'schema_version':1,'status':'HOLD_EXACT_XVFB_UNAVAILABLE','identity':item,'original_six_receipt':{'path':str(original),'sha256':preserved[str(original)]},'requests':[],'local_search':{'roots':['/home/gabe/Documents/ChatGPT','/home/gabe/.cache','/home/gabe/.local/share/cachy-asahi','/tmp','/dev/shm'],'method':'filename enumeration excluding .git; bounded JSON/index search, no archive payload rescan','exact_filename_found':False,'unrelated_x86_64':'21.1.25-2 retained; not substituted','carrier_indexes':['scripts/ci/retained-build-inputs/carrier-profile.json','scripts/ci/core-native-lifecycle-source/payload/retained/carrier-profile.json'],'carrier_Xvfb_members':0},'no_package_execution_install_guest':True}
    def save():
        report.update(initial_requests=budget.gets,response_body_bytes=budget.body,seconds=time.monotonic()-budget.started)
        (output/'receipt.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    def try_pair(url):
        if budget.gets>=11:return False
        receipt={'kind':'exact-archive','url':url};report['requests'].append(receipt);save()
        try:
            file=output/'archives'/NAME
            I.fetch(url,{'bytes':705376,'sha256':SHA},file,budget,receipt)
            receipt['path']=str(file);sig=output/'archives'/(NAME+'.sig');s={'kind':'exact-signature'};report['requests'].append(s)
            I.fetch(url+'.sig',{'bytes':566,'sha256':SIG},sig,budget,s);s['path']=str(sig)
            with tempfile.TemporaryDirectory(prefix='xvfb-public-gpg-',dir=output)as home:
                P.bound(contract['binary_public_key']);report['signature']=I.verify(file,sig,Path(contract['binary_public_key']['path']),Path(home),budget)
            report['metadata']=I.metadata(file,item);report['status']='PASS_EXACT_XVFB_ARCHIVE_SIGNATURE_METADATA_DATA_ONLY';return True
        except Exception as error:receipt.update(category=type(error).__name__,reason=str(error)[:256]);return False
        finally:save()
    try:
        if I.shutil.disk_usage(output).free<2*1024**3+I.CAP:raise ValueError('free reserve refused')
        for host in ['fl.us.mirror.archlinuxarm.org','de3.mirror.archlinuxarm.org','nj.us.mirror.archlinuxarm.org','mirror.archlinuxarm.org']:
            if try_pair('https://'+host+'/aarch64/extra/'+NAME):break
        if not report['status'].startswith('PASS'):
            # Known ALARM archive metadata; saved only as DATA, no imported code.
            for url in ['https://archlinuxarm.org/about/mirrors','https://tardis.tiny-vps.com/aarm/']:
                entry={'kind':'metadata'};report['requests'].append(entry)
                try:
                    html=metadata(url,budget,entry);(output/('metadata-'+str(budget.gets)+'.html')).write_text(html)
                    if 'tardis.tiny-vps.com'in url:report['archive_directory_links']=archive_paths(html,url)
                except Exception as error:entry.update(category=type(error).__name__,reason=str(error)[:256])
                save()
    except Exception as error:report.update(category=type(error).__name__,reason=str(error)[:256])
    finally:
        report['five_pairs_and_original_receipt_unchanged']=all(P.sha(Path(p))==h for p,h in preserved.items());report['preserved_input_hashes']=preserved;save()
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--recover-exact-only',action='store_true',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if not __debug__:p.error('assertions required')
    resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(TimeoutError('180 second outer deadline')));signal.alarm(180)
    report=run(a.output);signal.alarm(0);print(json.dumps({k:report[k]for k in ['status','initial_requests','response_body_bytes','seconds','five_pairs_and_original_receipt_unchanged']}));return 0 if report['status'].startswith('PASS')else 2
if __name__=='__main__':raise SystemExit(main())

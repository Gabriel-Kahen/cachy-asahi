#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit separately discovered current official ARM Xvfb DATA candidate."""
import argparse,hashlib,importlib.util,json,resource,signal,tempfile,time,urllib.parse,urllib.request,re
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('current_Xvfb_intake',HERE.parent/'six_pair_intake/intake.py');I=importlib.util.module_from_spec(spec);spec.loader.exec_module(I)
def discover(root):
    root.mkdir(mode=0o700,exist_ok=False);assert I.shutil.disk_usage(root).free>=2*1024**3+I.CAP;I.HOSTS.add('archlinuxarm.org');started=time.time();url='https://archlinuxarm.org/packages/aarch64/xorg-server-xvfb';redirect=I.Redirect();op=urllib.request.build_opener(urllib.request.ProxyHandler({}),redirect)
    with op.open(url,timeout=12)as response:
        I.official(response.url);raw=response.read(65537);assert len(raw)<=65536;record={'url':url,'method':'GET','initial_request':1,'started_wall':started,'http_status':response.status,'effective_url':response.url,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'redirects':redirect.redirects,'seconds':time.time()-started}
    (root/'package-page.html').write_bytes(raw);(root/'discovery.json').write_text(json.dumps(record,indent=2,sort_keys=True)+'\n')

def run(root):
    discovery=json.loads((root/'discovery.json').read_text());assert discovery['http_status']==200 and discovery['url']=='https://archlinuxarm.org/packages/aarch64/xorg-server-xvfb'
    page=(root/'package-page.html').read_bytes();assert len(page)==discovery['bytes']and hashlib.sha256(page).hexdigest()==discovery['sha256']
    versions=re.findall(rb'<h1>xorg-server-xvfb ([^< ]+)</h1>',page);assert len(versions)==1;version=versions[0].decode();assert re.fullmatch(r'[0-9.]+-[0-9]+',version)
    filename='xorg-server-xvfb-'+version+'-aarch64.pkg.tar.xz';assert ('http://mirror.archlinuxarm.org/aarch64/extra/'+filename).encode()in page
    budget=I.Budget();budget.started-=time.time()-discovery['started_wall'];budget.gets=1;budget.body=len(page)
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(TimeoutError('180s discovery+intake deadline')));signal.alarm(max(1,int(budget.remaining())))
    report={'status':'HOLD_CURRENT_CANDIDATE_INPUT','scope':'separate current official ARM Xvfb for proposed disposable VM only; oldpin remains HOLD','discovery':discovery,'version':version,'objects':[]}
    try:
        (root/'archives').mkdir(mode=0o700)
        for name,cap in [(filename,2*1024**2),(filename+'.sig',65536)]:
            url='https://ca.us.mirror.archlinuxarm.org/aarch64/extra/'+name;I.official(url);budget.gets+=1;assert budget.gets<=8;redirect=I.Redirect();entry={'url':url,'redirects':redirect.redirects};report['objects'].append(entry)
            op=urllib.request.build_opener(urllib.request.ProxyHandler({}),redirect)
            with op.open(urllib.request.Request(url,headers={'Accept-Encoding':'identity'}),timeout=min(12,budget.remaining()))as response:
                I.official(response.url);entry.update(http_status=response.status,effective_url=response.url)
                raw=response.read(cap+1);budget.consume(len(raw));assert len(raw)<=cap
            p=root/'archives'/name;p.write_bytes(raw);entry.update(path=str(p),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        key=json.loads((HERE.parent/'inputs.json').read_text())['public_key_material'][0];I.P.bound(key)
        binary=Path(key['path']+'.binary');assert binary.stat().st_size==2228 and I.P.sha(binary)=='9403f923eed777ba0896a0b225e1522d3a7625234694c753ae26b27c29672aae'
        with tempfile.TemporaryDirectory(prefix='current-Xvfb-public-gpg-',dir=root)as home:report['signature']=I.verify(root/'archives'/filename,root/'archives'/(filename+'.sig'),binary,Path(home),budget)
        meta,pin=I.P.package_metadata(root/'archives'/filename);assert meta['pkgname']==['xorg-server-xvfb']and meta['pkgver']==[version]and meta['arch']==['aarch64'];report.update(metadata=meta,metadata_pin=pin,status='PASS_CURRENT_ARCHIVE_SIGNATURE_IDENTITY_DATA_ONLY')
    except Exception as error:report.update(category=type(error).__name__,reason=str(error)[:512])
    finally:
        signal.alarm(0);report.update(initial_GETs=budget.gets,response_body_bytes=budget.body,seconds=time.monotonic()-budget.started);(root/'acquisition.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:report[k]for k in ['status','version','initial_GETs','response_body_bytes','seconds']}));return 0 if report['status'].startswith('PASS')else 2
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--discovered-root',type=Path,required=True);p.add_argument('--discover-current',action='store_true');a=p.parse_args();
    if not __debug__:p.error('assertions must remain enabled')
    resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2));resource.setrlimit(resource.RLIMIT_CORE,(0,0));
    if a.discover_current:discover(a.discovered_root)
    raise SystemExit(run(a.discovered_root))

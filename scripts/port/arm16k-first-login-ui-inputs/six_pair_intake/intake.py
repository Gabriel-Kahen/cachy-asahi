#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit exact-six DATA intake. No package execution, installation or guest."""
import argparse,base64,hashlib,importlib.util,json,os,resource,shutil,signal,subprocess,sys,tempfile,time,urllib.error,urllib.parse,urllib.request
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent));import plan as P
SIGNER='68B3537F39A313B3E574D06777193F152BDBE6A6'
HOSTS={'ca.us.mirror.archlinuxarm.org','fl.us.mirror.archlinuxarm.org','de3.mirror.archlinuxarm.org','nj.us.mirror.archlinuxarm.org','mirror.archlinuxarm.org'}
CAP=8*1024**2

def official(url):
    p=urllib.parse.urlsplit(url)
    if not(p.scheme=='https'and p.hostname in HOSTS and not p.username and not p.password and p.port in (None,443)and not p.query and not p.fragment):raise ValueError('official HTTPS boundary refused')
    return url

class Redirect(urllib.request.HTTPRedirectHandler):
    def __init__(self):self.redirects=[]
    def redirect_request(self,request,response,code,message,headers,newurl):
        official(newurl)
        if len(self.redirects)>=3:raise ValueError('three redirect cap exceeded')
        if urllib.parse.urlsplit(newurl).path!=urllib.parse.urlsplit(request.full_url).path:raise ValueError('redirect changed exact package path')
        self.redirects.append({'status':code,'url':newurl})
        return super().redirect_request(request,response,code,message,headers,newurl)

class Budget:
    def __init__(self):self.started=time.monotonic();self.gets=0;self.body=0
    def remaining(self):
        seconds=180-(time.monotonic()-self.started)
        if seconds<=0:raise TimeoutError('180 second intake deadline')
        return seconds
    def consume(self,size):
        self.body+=size
        if self.body>CAP:raise ValueError('eight MiB response-body cap')

def checked(path,pin):
    if path.is_symlink()or not path.is_file()or path.stat().st_size!=pin['bytes']or P.sha(path)!=pin['sha256']:raise ValueError('exact retained byte pin mismatch')
    return path

def fetch(url,pin,path,budget,receipt):
    official(url);budget.remaining();budget.gets+=1
    if budget.gets>12:raise ValueError('twelve initial GET cap')
    redirect=Redirect();receipt.update(url=url,initial_get_number=budget.gets,redirects=redirect.redirects)
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),redirect)
    request=urllib.request.Request(url,headers={'User-Agent':'cachy-asahi-six-pair-data-intake/1','Accept-Encoding':'identity'})
    try:
        with opener.open(request,timeout=min(12,budget.remaining()))as response:
            official(response.url);receipt.update(http_status=response.status,effective_url=response.url)
            length=response.headers.get('Content-Length')
            if length is not None and int(length)!=pin['bytes']:raise ValueError('HTTP length differs from exact pin')
            with path.open('xb')as target:
                while True:
                    budget.remaining();data=response.read(min(65536,pin['bytes']+1-target.tell()))
                    if not data:break
                    budget.consume(len(data));target.write(data)
                    if target.tell()>pin['bytes']:raise ValueError('response exceeds exact object size')
        checked(path,pin);receipt.update(status='PASS_EXACT_SIZE_SHA256',bytes=pin['bytes'],sha256=pin['sha256']);return path
    except urllib.error.HTTPError as error:
        # No error body is needed, retained or displayed.
        receipt.update(status='HOLD_HTTP',http_status=error.code);error.close();raise ValueError('HTTP '+str(error.code))from None

def metadata(path,item):
    meta,evidence=P.package_metadata(path)
    for field,expected in item['expected'].items():
        if sorted(meta.get(field,[]))!=sorted(expected):raise ValueError('PKGINFO/catalog mismatch: '+field)
    if meta['arch']!=['aarch64']:raise ValueError('actual ARM architecture required')
    return {**evidence,'identity_arch_relations_licenses':'PASS_EXACT_CATALOG','metadata':meta,'source_license_correspondence':'HOLD; no source acceptance'}

def verify(path,sig,key,home,budget):
    result=subprocess.run(['/usr/bin/gpgv','--homedir',str(home),'--keyring',str(key),'--status-fd','1',str(sig),str(path)],capture_output=True,text=True,timeout=min(5,budget.remaining()),env={'PATH':'/usr/bin','HOME':str(home),'LC_ALL':'C'})
    if len(result.stdout)+len(result.stderr)>65536:raise ValueError('gpgv diagnostic bound')
    status=result.stdout
    rows=[line.split()[1:]for line in status.splitlines()if line.startswith('[GNUPG:] ')]
    bad={'EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','FAILURE','ERROR','NODATA','BADARMOR'}
    valid=[row for row in rows if row and row[0]=='VALIDSIG']
    if result.returncode or any(row and row[0]in bad for row in rows)or len(valid)!=1 or len(valid[0])!=11 or valid[0][1]!=SIGNER or valid[0][-1]!=SIGNER:raise ValueError('gpgv exact primary signature refusal')
    return {'exit':result.returncode,'signer_primary':valid[0][1],'signature_date':valid[0][2],'signature_timestamp':valid[0][3],'status_sha256':hashlib.sha256(status.encode()).hexdigest(),'stderr_bytes':len(result.stderr.encode()),'stderr_sha256':hashlib.sha256(result.stderr.encode()).hexdigest(),'scope':'mathematical signature against pinned retained official key; external freshness/trust acceptance HOLD'}

def run(contract,output):
    budget=Budget();output.mkdir(mode=0o700,exist_ok=False);(output/'archives').mkdir(mode=0o700)
    report={'schema_version':1,'scope':contract['scope'],'status':'HOLD_INCOMPLETE','pairs':[],'network_initial_GET_cap':12,'redirect_cap_each':3,'response_body_cap_bytes':CAP,'whole_deadline_seconds':180,'installation_guest_package_execution':False,'other139_authentication':'NOT RUN','key_freshness_external_trust_native_M2_release':'HOLD'}
    def save():
        report.update(initial_GETs=budget.gets,response_body_bytes=budget.body,seconds=time.monotonic()-budget.started)
        (output/'receipt.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    try:
        if contract['scope']!='exact-six-ARM111-UI-pairs-DATA-intake'or contract['signer']!=SIGNER or len(contract['pairs'])!=6:raise ValueError('finite contract refused')
        P.bound(contract['catalog']);P.bound(contract['plan_report'])
        armored=P.bound(contract['armored_public_key']);binary=P.bound(contract['binary_public_key'])
        encoded=b''.join(line for line in armored.splitlines()[2:]if line and not line.startswith((b'=',b'-----')))
        if base64.b64decode(encoded,validate=True)!=binary:raise ValueError('retained armored/binary public key disagreement')
        report['public_key']=contract['binary_public_key'];report['gpgv']={'path':'/usr/bin/gpgv','bytes':Path('/usr/bin/gpgv').stat().st_size,'sha256':P.sha(Path('/usr/bin/gpgv'))}
        if shutil.disk_usage(output).free<2*1024**3+CAP:raise ValueError('two GiB free reserve refused')
        with tempfile.TemporaryDirectory(prefix='six-pair-public-gpg-',dir=output)as home:
            for item in contract['pairs']:
                entry={'name':item['name'],'version':item['version'],'archive':item['archive'],'objects':[],'status':'HOLD'};report['pairs'].append(entry);save()
                try:
                    pin=item['archive'];filename=pin['filename']
                    if filename!=item['name']+'-'+item['version']+'-aarch64.pkg.tar.xz'or item['repo']!='extra':raise ValueError('exact filename/repository refused')
                    if item['url']!='https://ca.us.mirror.archlinuxarm.org/aarch64/extra/'+filename:raise ValueError('frozen official URL refused')
                    files=[]
                    for name,expected,url in [(filename,{'bytes':pin['bytes'],'sha256':pin['sha256']},item['url']),(filename+'.sig',{'bytes':pin['signature_bytes'],'sha256':pin['signature_sha256']},item['url']+'.sig')]:
                        obj={'filename':name};entry['objects'].append(obj);save()
                        existing=next((Path(root)/name for root in contract['cache_directories']if(Path(root)/name).exists()),None)
                        if existing is not None:files.append(checked(existing,expected));obj.update(status='PASS_REUSED_EXACT_BYTES',path=str(existing),**expected)
                        else:
                            target=output/'archives'/name;files.append(fetch(url,expected,target,budget,obj));obj['path']=str(target)
                        save()
                    entry['metadata']=metadata(files[0],item);entry['signature']=verify(*files,Path(contract['binary_public_key']['path']),Path(home),budget);entry['status']='PASS_EXACT_SIX_SCOPE_ARCHIVE_AND_SIGNATURE'
                except Exception as error:entry.update(status='HOLD',category=type(error).__name__,reason=str(error)[:256])
                save()
        report['status']='PASS_SIX_ARCHIVES_SIGNATURES_DATA_ONLY'if all(p['status'].startswith('PASS_')for p in report['pairs'])else'HOLD_UNAVAILABLE_OR_REFUSED_EXACT_INPUTS'
    except Exception as error:report.update(status='HOLD_INPUT_RESOURCE_REFUSAL',category=type(error).__name__,reason=str(error)[:256])
    finally:save()
    return report

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--acquire-exact-six',action='store_true',required=True);parser.add_argument('--output',required=True,type=Path);args=parser.parse_args()
    if not __debug__:parser.error('assertions must remain enabled')
    resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in()).throw(TimeoutError('180 second outer deadline')));signal.alarm(180)
    result=run(json.loads((HERE/'inputs.json').read_text()),args.output);signal.alarm(0)
    print(json.dumps({k:result[k]for k in ['status','initial_GETs','response_body_bytes','seconds']}));return 0 if result['status'].startswith('PASS_')else 2
if __name__=='__main__':raise SystemExit(main())

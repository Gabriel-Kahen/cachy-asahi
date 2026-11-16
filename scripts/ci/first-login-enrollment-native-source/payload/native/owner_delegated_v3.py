# SPDX-License-Identifier: MIT
"""Explicit delegated private-stage owner; no operational work on import.

Program observations never become Root image qualifications or final acceptance.
Only the external Root boundary authenticates the selected delegation hash.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time
from types import SimpleNamespace

API='CURRENT_ONBOARDING_DELEGATED_OWNER_V3'
OP='first-login-enrollment-ui-current-v2'
ISSUER='DELEGATED_CURRENT_OWNER_V3'
FAMILY='scripts/ci/first-login-enrollment-native-source'
HERE=Path(__file__).resolve()
ROOT=HERE.parents[5]
LABEL='org.cachy-asahi.current-private'
COUNTS={'backend':350,'ui':374,'lifecycle':372}
FINAL=dict(Root_final_acceptance=None,independent_component_acceptance=False,hardware_acceptance=False,release_acceptance=False)
HELD={
 FAMILY+'/successor_v2/profile.json':'8ad3641649e395b1202363e3368f713f65252a743b12e3a8d69430e4f82bc171',
 FAMILY+'/successor_v2/native.py':'cde384acd8574ddfcb07f7316ad4d24349f5b958ac6b2cea48a3a6aff480c827',
 FAMILY+'/payload/native/build_tools_tools_v2.py':'eb1ff0ee8aefc2c0e32b38520e1bf0dabcbb9308081a24e2f9c378366a3cab13',
 FAMILY+'/payload/native/build_tools_alpm_v2.py':'d4197495e0281aecfd590e76ed908cd1fcf46b1934bc02709e47a7dac49abb73'}
NATIVE_PIN=dict(bytes=13703,sha256=HELD[FAMILY+'/successor_v2/native.py'])
_INSIDE=None


def need(ok,why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def decode(raw):
    def pairs(rows):
        result={}
        for key,value in rows:need(key not in result,'duplicate JSON key');result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite JSON'))
    encoded(value);return value


def raw(path,cap=16*1024**2):
    path=Path(path);need(path.is_absolute() and path==path.resolve() and not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute nonaliased DATA')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap and not before.st_mode&0o022,'bounded single-link non-writable DATA')
        chunks=[];size=0
        while block:=os.read(fd,min(65536,cap+1-size)):
            size+=len(block);need(size<=cap,'DATA cap');chunks.append(block)
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        identity=lambda s:tuple(getattr(s,k)for k in fields)
        need(size==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'DATA changed during whole read')
        return b''.join(chunks)
    finally:os.close(fd)


def save(path,value):
    with Path(path).open('xb')as stream:os.fchmod(stream.fileno(),0o600);stream.write(encoded(value))


def relative(member):
    need(type(member)is str and re.fullmatch('[A-Za-z0-9._+/-]{1,240}',member) and not member.startswith('/') and
         all(p not in ('','.','..')for p in member.split('/')),'closed Source-relative name');return member


def load(root,row,name):
    member=relative(row['member']);path=Path(root)/member;body=raw(path,128*1024)
    need(pin(body)=={k:row[k]for k in ('bytes','sha256')},'whole reviewed Source program')
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;exec(compile(body,str(path),'exec'),module.__dict__);return module


def scope(body,sha256):
    need(type(body)is bytes and len(body)<=1024**2 and pin(body)['sha256']==sha256,'external Root-selected whole delegation SHA')
    d=decode(body)
    need(type(d)is dict and body==encoded(d) and (d.get('schema'),d.get('kind'))in ((3,'ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3'),(4,'ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4')) and
         d.get('issuer')=='Root' and d.get('approved')is True and d.get('scope')=='CURRENT_PRIVATE_STAGE_ONLY', 'new explicit conditional private delegation, never old direct grant')
    need(d['stage']in COUNTS and re.fullmatch('[0-9a-f]{64}',d['nonce']) and d['image_ids']==dict.fromkeys(COUNTS) and
         d['binding']['run']is d['binding']['job']is None,'future IDs remain genuinely unobserved')
    need(all(d.get(k)==v and type(d.get(k))is type(v)for k,v in FINAL.items()),'no delegated final acceptance')
    return d


def material(H,d,source,role):
    need(type(role)is str and role in d['materials'],'explicit closed material role')
    row=d['materials'][role];member=relative(row['member']);path=Path(source)/member
    body=raw(path);need(pin(body)=={k:row[k]for k in ('bytes','sha256')},'closed material whole pin')
    return dict(path=str(path),**pin(body))


def strict_signature(status,fingerprint):
    need(type(status)is bytes and re.fullmatch('[0-9A-F]{40}',fingerprint or ''),'explicit TEST primary')
    rows=[line.split()[1:]for line in status.decode().splitlines()if line.startswith('[GNUPG:] ')]
    bad={'EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','FAILURE','NODATA','TRUST_NEVER','TRUST_UNDEFINED','BADARMOR'}
    valid=[r for r in rows if r and r[0]=='VALIDSIG']
    need(not any(r and r[0]in bad for r in rows) and len(valid)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==fingerprint and
         any(r and r[0]=='TRUST_ULTIMATE'for r in rows),'strict current trusted TEST signature')


def natural(row,expected=0):
    need(row['reaped']is True and row['ownership']=='REAPED' and row['group_census']=='EMPTY_TWICE' and row['output_complete']is True and
         row['timeout']is False and row['signals']==[] and row['error']is None and not any(row.get(k)for k in ('forced_cleanup','ownership_lost','emergency_retirement')) and type(row['exit'])is int and row['exit']==expected,'natural complete command retirement')


class Runner:
    def __init__(self,executor,directory,capability,deadline):
        self.executor,self.directory,self.capability,self.deadline=executor,Path(directory),capability,deadline
        self.directory.mkdir(mode=0o700);self.records=[];self.outputs={};self.stderr_outputs={};self.cleaning=False
        self.index()
    def index(self):
        pending=self.directory/'.commands.json.pending';save(pending,self.records);pending.replace(self.directory/'commands.json')
    def run(self,step,argv,timeout_seconds=180,expected=0):
        need(type(step)is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',step) and step not in self.outputs and
             len(self.records)<self.capability['command_rows'],'unique finite receipt step')
        need(type(argv)is list and argv and all(type(v)is str and '\0'not in v for v in argv) and Path(argv[0]).is_absolute(),'literal executable argv')
        seconds=min(timeout_seconds,self.capability['max_command_seconds'],self.deadline-time.monotonic())
        need(math.isfinite(seconds) and seconds>1,'common finite stage deadline')
        need(self.cleaning or time.time()<=getattr(self,'expires_epoch',float('inf')),'delegation expired before new work')
        result=self.executor.run(step,argv,seconds,expected=expected);out=result['stdout'];row=result['receipt']
        need(type(out)is bytes and len(out)<=1024**2 and row['step']==step and row['argv']==argv and row['expected']==expected and
             type(row['exit'])is int and row['exit']==expected and row['output_pin']==pin(out),'exact genuine executor receipt/output')
        natural(row['supervision'],expected)
        original=decode(encoded(row));row=dict(row,success=True,log_pin=pin(out),executor_receipt=original,channels='stdout with separately pinned stderr')
        self.records.append(row);self.outputs[step]=out;(self.directory/(step+'.stdout')).write_bytes(out)
        if 'stderr'in result:
            need(type(result['stderr'])is bytes and pin(result['stderr'])==original['stderr_pin'],'actual separate stderr pin')
            (self.directory/(step+'.stderr')).write_bytes(result['stderr']);self.stderr_outputs[step]=result['stderr']
        save(self.directory/(step+'.json'),row);self.index();return out


def labels(c):return {LABEL:c['nonce'],LABEL+'.source':c['binding']['source'],LABEL+'.stage':c['stage'],LABEL+'.scope':'DELEGATED_PRIVATE_TEST_ONLY'}


def container(row,intent,c):
    need(row['Name']=='/'+intent['name'] and re.fullmatch('[0-9a-f]{64}',row['Id']) and row['Image']==intent['image'],'actual full CID/name/image')
    conf,host=row['Config'],row['HostConfig']
    need(conf['User']==intent['user'] and conf['Entrypoint']==intent['entrypoint'] and conf['Cmd']==intent['cmd'] and (not intent.get('hostname')or conf['Hostname']==intent['hostname']) and
         all(conf['Labels'].get(k)==v for k,v in labels(c).items()),'actual exact user/entry/nonce/source/private scope')
    need(host['NetworkMode']=='none' and host['Privileged']is False and host['ReadonlyRootfs']is intent['readonly'] and
         host['CapDrop']==['ALL'] and (host.get('CapAdd')or[])==intent.get('capadd',[]) and host['SecurityOpt']in (['no-new-privileges'],['no-new-privileges=true']) and
         not host['Devices'] and not host.get('DeviceRequests') and not host.get('VolumesFrom') and host.get('Tmpfs',{})==intent.get('tmpfs',{}) and
         host['Memory']==host['MemorySwap']==4*1024**3 and host['NanoCpus']==4*10**9 and host['PidsLimit']==512 and
         host.get('Init')in(None,False) and not host.get('AutoRemove') and host.get('PidMode','')=='' and host.get('UTSMode','')=='' and host.get('IpcMode','private')=='private','actual bounded isolated native actor')
    binds=[]
    for m in row['Mounts']:
        if m['Type']=='tmpfs':need(m['Destination']in intent.get('tmpfs',{}) and m['RW']is True,'only declared private tmpfs');continue
        need(m['Type']=='bind','no foreign/image-induced volumes');binds.append((m['Destination'],m['Source'],m['RW']))
    need(sorted(binds)==sorted(tuple(x)for x in intent['mounts']),'actual exact bind set');return row['Id']


def intent(c,image,name,user,cmd,mounts,*,readonly=True,capadd=(),tmpfs=None):
    need(re.fullmatch('sha256:[0-9a-f]{64}',image) and re.fullmatch('[a-z0-9-]{1,128}',name),'immutable image and exact bounded name')
    return dict(name=name,image=image,user=user,entrypoint=['/bin/bash'],cmd=cmd,mounts=mounts,labels=labels(c),readonly=readonly,capadd=list(capadd),tmpfs={}if tmpfs is None else tmpfs)


def create_argv(endpoint,row,env=()):
    need(type(endpoint)is str and endpoint.startswith('unix:///') and endpoint not in ('unix:///var/run/docker.sock','unix:///run/docker.sock'),'explicit private endpoint')
    argv=['/usr/bin/docker','--host='+endpoint,'container','create','--name',row['name'],'--pull=never','--platform=linux/arm64','--user',row['user'],
        '--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=4g','--memory-swap=4g','--cpus=4','--pids-limit=512','--init=false']
    if row.get('hostname'):argv+=['--hostname='+row['hostname']]
    if row['readonly']:argv+=['--read-only']
    for cap in row['capadd']:argv+=['--cap-add='+cap]
    for path,options in row['tmpfs'].items():argv+=['--tmpfs',path+':'+options]
    for key,value in row['labels'].items():argv+=['--label',key+'='+value]
    for value in env:argv+=['--env',value]
    for dst,src,rw in row['mounts']:
        need(all(Path(p).is_absolute() and ','not in p and '\n'not in p for p in (dst,src)),'literal exact bind operand')
        argv+=['--mount','type=bind,src='+src+',dst='+dst+(''if rw else',readonly')]
    return argv+['--entrypoint=/bin/bash',row['image'],*row['cmd']]


def image_data(report,d,c,inventory_raw):
    need(report.get('issuer')!='Root' and not report.get('independent_component_acceptance') and report['status']=='PROVISIONAL_CURRENT_IMAGE_CONSTRUCTED_DATA_ONLY' and report['operation']==OP and report['stage']==d['stage'] and
         report['binding']==c['binding'] and report['delegation_pin']==c['delegation_pin'] and report['owner_executor_facts']['nonce']==c['nonce'] and
         report['Root_final_acceptance']is None and report['independent_image_qualification']is None,'genuine provisional image observations; never Root qualification')
    packages=report['packages'];expected=''.join(n+' '+v+'\n'for n,v in sorted(packages.items())).encode()
    need(type(packages)is dict and len(packages)==COUNTS[c['stage']] and inventory_raw==expected and
         {k:report['inventory_pin'][k]for k in ('bytes','sha256')}==pin(expected) and re.fullmatch('sha256:[0-9a-f]{64}',report['image_id']),'whole typed provisional inventory')
    return dict(id=report['image_id'],packages=packages,inventory_pin=report['inventory_pin'])


def modules(source):
    source=Path(source);bodies={n:raw(source/n,128*1024)for n in HELD}
    need(all(pin(body)['sha256']==HELD[n]for n,body in bodies.items()),'whole held helper/profile closure')
    def body_module(name,path,body,extra=None):
        spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec)
        if extra:m.__dict__.update(extra)
        sys.modules[name]=m;exec(compile(body,str(path),'exec'),m.__dict__);return m
    N=body_module('delegated_current_native',source/(FAMILY+'/successor_v2/native.py'),bodies[FAMILY+'/successor_v2/native.py'])
    T=body_module('delegated_current_tools',source/(FAMILY+'/payload/native/build_tools_tools_v2.py'),bodies[FAMILY+'/payload/native/build_tools_tools_v2.py'])
    a=bodies[FAMILY+'/payload/native/build_tools_alpm_v2.py'];seam=b'import build_tools_tools_v2 as T';replacement=b'T=__held_tools'
    need(a.count(seam)==1 and replacement not in a,'one held private tools import seam');projected=a.replace(seam,replacement)
    need(projected.replace(replacement,seam)==a,'exact held private tools inverse')
    A=body_module('delegated_current_alpm',source/(FAMILY+'/payload/native/build_tools_alpm_v2.py'),projected,{'__held_tools':T})
    profile=decode(bodies[FAMILY+'/successor_v2/profile.json']);N.policy(profile)
    return N,T,A,profile


def source_request(body,sha,context,source):
    preview=scope(body,sha);source=Path(source)
    H=load(source,preview['programs']['context'],'private_current_context')
    d=H.validate_delegation(body,sha);c=H.validate_context(d,context);root,rows=H.source(d,source)
    need(root==source and c['source_root']==str(source) and c['stage']==d['stage'],'same actual delegated Source/context/stage')
    own=raw(Path(__file__).resolve(),128*1024);need(pin(own)==H.descriptor(d['programs']['owner']) and
         Path(__file__).resolve()==source/d['programs']['owner']['member'],'executing whole reviewed delegated owner')
    policy=H.decode(H.read(source/d['policy']['member'],1024**2)[0]);return d,c,policy,H


def request(body,sha,context,source,inputs,image_report,executor):
    d,c,p,H=source_request(body,sha,context,source)
    I=load(source,d['programs']['image'],'private_current_image')
    observed=I.admit(body,sha,context,Path(source),executor,H)
    need(observed[:3]==(d,c,p),'same independently validated actual private executor domains')
    need(type(inputs['source_date_epoch'])is int and inputs['source_date_epoch']>=0,'explicit private Source epoch')
    native,tools,alpm,profile=modules(source)
    lock=raw(Path(source)/('inputs/stages/'+c['stage']+'.expected.lock'),1024**2)
    image=image_data(image_report,d,c,lock)
    need(image_report['owner_executor_facts']==executor.facts and not image_report.get('failure') and not image_report.get('cleanup_or_protected_failure') and
         image_report['protected_before']==image_report['protected_after'] and image_report['cleanup']['errors']==[] and
         image_report['cleanup']['retained_target_image_unqualified']==image['id'],'observed provisional image custody and preservation')
    return dict(d=d,c=c,policy=p,H=H,image=image,native=native,tools=tools,alpm=alpm,profile=profile,inventory=lock,protected_fn=getattr(I,'protected_state',None))


def test_policy(plan,inputs):
    d,p,H=plan['d'],plan['policy'],plan['H'];selected=p['private_stage']['test']
    need(set(selected)=={'fingerprint','public_key_role'} and selected['public_key_role']in d['materials'] and
         re.fullmatch('[0-9A-F]{40}',selected['fingerprint']),'explicit Root-reviewed current public TEST policy')
    key=material(H,d,plan['source'],selected['public_key_role']);body=raw(key['path'],65536)
    need(b'PRIVATE KEY'not in body,'public TEST certificate only')
    return key,selected['fingerprint']


def decision(body,verification,archive,signature,public_key,fingerprint,name,version):
    d,p=decode(body),decode(verification);key=dict({k:public_key[k]for k in ('bytes','sha256')},fingerprint=fingerprint,trust_scope='TEST_ONLY')
    status='ACCEPTED_PRIVATE_SETUP8_PACKAGE_TEST_ONLY'if name=='cachy-asahi-setup'else'ACCEPTED_PRIVATE_CURRENT_ONBOARDING_PACKAGE_TEST_ONLY'
    need(d['schema']==1 and d['issuer']=='Root' and d['accepted']is True and d['holds_preserved']is True and d['status']==status and d['trust_scope']=='TEST_ONLY' and
         d['archive']==dict(pin(archive),package=name,version=version,arch='any') and d['signature']==pin(signature) and d['public_test_key']==key and
         d['verification_proof_sha256']==pin(verification)['sha256'],'genuine exact Root batch-sign decision, never producer fabricated authority')
    need(p['schema']==1 and p['Root_issuer']=='Root' and p['status']=='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE' and p['verified']is True and p['trust_scope']=='TEST_ONLY' and
         p['archive']==pin(archive) and p['signature']==pin(signature) and p['public_test_key']==key,'actual Root public verification joins signed bytes')
    # Historical absolute filename fields are retained provenance, never opened.
    return dict(Root_decision_pin=pin(body),Root_verification_pin=pin(verification))


class Session:
    def __init__(self,plan,source,output,inputs,image_report,executor):
        self.plan,self.source,self.output,self.inputs,self.executor=plan,Path(source),Path(output),inputs,executor
        self.plan['source']=self.source
        self.d,self.c,self.policy=plan['d'],plan['c'],plan['policy'];self.image=plan['image'];self.profile=plan['profile']
        self.native,self.tools,self.alpm=plan['native'],plan['tools'],plan['alpm'];self.native_pin=NATIVE_PIN;self.cleanup=None;self.actors=[]
        self.endpoint=executor.facts['docker_endpoint'];self.start=time.monotonic();self.end=min(self.start+self.d['capability']['total_seconds'],getattr(executor,'deadline',float('inf')))
        self.runner=Runner(executor,self.output/'commands',self.d['capability'],self.end-90);self.runner.expires_epoch=self.d['expires_epoch']
        self.runner.expires_epoch=self.d['expires_epoch'];self.records=self.runner.records;self.signature_receipts={};self.state=self.output/'owner';self.state.mkdir(mode=0o700)
    def run(self,step,argv):return self.runner.run(step,argv,min(180,self.d['capability']['max_command_seconds']))
    def docker(self,step,args,seconds=15):return self.runner.run(step,['/usr/bin/docker','--host='+self.endpoint,*args],seconds)
    def inspect(self,cid,row,step):
        rows=decode(b'{"rows":'+self.docker(step,['container','inspect',cid])+b'}')['rows'];need(len(rows)==1,'one actual actor inspection')
        need(container(rows[0],row,self.c)==cid,'same full CID');return rows[0]
    def retire(self,state):
        row=state['intent'];prefix='retire-'+str(len(self.records));query=['container','ls','--all','--no-trunc','--filter','name=^/'+row['name']+'$','--format','{{.ID}} {{.Names}}']
        found=self.docker(prefix+'-query',query).decode().splitlines();need(len(found)<=1,'exact actor discovery')
        if not found:
            need(state.get('terminal')is not None,'uncertain create cannot become successful retirement')
            return dict(status='ABSENT_BEFORE_REMOVAL_HOLD',name=row['name'])
        cid=found[0].split(' ')[0];need(re.fullmatch('[0-9a-f]{64}',cid),'actual discovered full CID')
        inspected=self.inspect(cid,row,prefix+'-inspect');nonnatural=inspected['State']['Running']is True
        self.docker(prefix+'-remove',['container','rm',*(['--force']if nonnatural else[]),cid])
        for i in range(2):need(not self.docker(prefix+'-after-'+str(i),query).strip(),'actual actor absence twice')
        return dict(status='REMOVED_AND_ABSENT'if not nonnatural else'FORCED_REMOVAL_HOLD',cid=cid,name=row['name'],inspection=inspected)
    def actor(self,row,label,seconds=180,env=()):
        before=len(self.records)
        query=['container','ls','--all','--no-trunc','--filter','name=^/'+row['name']+'$','--format','{{.ID}} {{.Names}}']
        need(not self.docker(label+'-fresh',query).strip(),'fresh exact actor name; no collision deletion')
        state=dict(intent=row,submitted=True);self.actors.append(state);save(self.state/(label+'-intent.json'),row)
        cid=self.runner.run(label+'-create',create_argv(self.endpoint,row,env),15).decode().strip();need(re.fullmatch('[0-9a-f]{64}',cid),'actual created full CID');state['cid']=cid
        state['created']=self.inspect(cid,row,label+'-created');state['attach_step']=label+'-attach';out=self.docker(label+'-attach',['container','start','--attach',cid],seconds)
        state['terminal']=self.inspect(cid,row,label+'-terminal');terminal=state['terminal']['State']
        need(terminal['Running']is False and terminal['ExitCode']==0 and terminal['OOMKilled']is False,'natural zero-exit actor, never forced retirement success')
        state['retirement']=self.retire(state);need(state['retirement']['status']=='REMOVED_AND_ABSENT','full natural exact-CID retirement')
        state['retired']=True;state['command_receipts']=list(self.records[before:]);save(self.state/(label+'-receipt.json'),state);return out,state
    def trust(self):
        self.public_key,self.fingerprint=test_policy(self.plan,self.inputs)
        self.private=Path(tempfile.mkdtemp(prefix='build-tools-test-private-',dir='/tmp'));self.private.chmod(0o700)
        self.homes=[self.private/'trust']
        for home in self.homes:home.mkdir(mode=0o700)
        self.verifier=['/usr/bin/gpg','--homedir',str(self.homes[0]),'--batch','--no-auto-key-retrieve','--auto-key-locate','clear']
        key=self.private/'public.asc';key.write_bytes(raw(self.public_key['path'],65536))
        self.runner.run('private-test-import',self.verifier+['--import',str(key)],60)
        listing=self.runner.run('private-test-primary',self.verifier+['--with-colons','--list-keys'],60).decode()
        need([line.split(':')[9]for line in listing.splitlines()if line.startswith('fpr:')]==[self.fingerprint],'one Root-selected TEST primary')
        ownertrust=self.private/'ownertrust';ownertrust.write_text(self.fingerprint+':6:\n')
        self.runner.run('private-test-ownertrust',self.verifier+['--import-ownertrust',str(ownertrust)],60)
    def verify(self,key,archive,signature):
        status=self.runner.run('private-signature-'+key,self.verifier+['--status-fd=1','--verify',str(signature),str(archive)],60)
        strict_signature(status,self.fingerprint);self.signature_receipts[key]=dict(archive=pin(raw(archive)),signature=pin(raw(signature)),fingerprint=self.fingerprint,
            status=status.decode(),command=self.records[-1],trust_scope='TEST_ONLY')
    def setup(self):
        row=self.inputs['setup8'];H=self.plan['H'];roles={k:material(H,self.d,self.source,row[k+'_role'])for k in ('archive','signature','decision','verification')}
        archive=raw(roles['archive']['path']);sig=raw(roles['signature']['path'])
        need(pin(archive)==self.profile['setup8']['archive_pin'],'genuine accepted unchanged Setup8 archive')
        decision(raw(roles['decision']['path']),raw(roles['verification']['path']),archive,sig,self.public_key,self.fingerprint,'cachy-asahi-setup','0.3.0-1')
        self.verify('setup8',roles['archive']['path'],roles['signature']['path']);return roles
    def product(self,kind,product):
        if self.d['capability'].get('allow_selected_pair_adoption',False):return self.selected_product(kind,product)
        need(self.d['capability']['allow_pair_adoption']is True,'explicit actual product adoption capability')
        H=self.plan['H'];producer=H.validate_delegation(product['producer_delegation_raw'],pin(product['producer_delegation_raw'])['sha256'])
        H.validate_context(producer,product['producer_context']);pair=decode(product['pair_raw'])
        need(self.d['capability']['allow_pair_adoption']is True,'explicit private pair adoption capability')
        selected=self.d['private_stage_producers'][producer['stage']]
        need(pin(product['producer_delegation_raw'])==selected and (producer['stage']!='backend' or selected==self.d['pair_policy']['producer_delegation_pin']),'explicit Root-selected actual producer delegation')
        for key in ('source','ref','run','attempt','source_lock'):need(product['producer_context']['binding'][key]==self.c['binding'][key],'same actual source/run product provenance')
        recipe=self.profile['packages'][kind];expected_stage='ui'if kind=='ui'else'backend'
        need(producer['stage']==expected_stage and pair['schema']==product['producer_context']['schema'] and pair['schema']in(3,4) and pair['kind']=='DELEGATED_CURRENT_ONBOARDING_PAIR_V'+str(pair['schema']) and pair['issuer']=='DELEGATED_CURRENT_OWNER_V'+str(pair['schema']) and
             pair['binding']==product['producer_context']['binding'] and pair['nonce']==producer['nonce'] and pair['program_pin']==H.descriptor(producer['programs']['owner']) and
             pair['policy_pin']==H.descriptor(producer['policy']) and pair['package']==recipe['name'] and pair['version']==recipe['version'] and pair['matching_pair']is True and
             all(pair.get(k)==v and type(pair.get(k))is type(v)for k,v in FINAL.items()),'actual observed producing pair; no Root acceptance claim')
        archives=product['archives'];need(type(archives)is list and len(archives)==2 and all(type(b)is bytes and 0<len(b)<=16*1024**2 for b in archives) and
             archives[0]==archives[1] and pair['archives']==[pin(b)for b in archives],'genuine complete matching compressed pair bodies')
        signature=product['signature'];need(type(signature)is bytes and 0<len(signature)<=65536,'actual detached Root signature bytes after build')
        decision(product['Root_decision_raw'],product['Root_verification_raw'],archives[0],signature,self.public_key,self.fingerprint,recipe['name'],recipe['version'])
        directory=self.output/'adopted';directory.mkdir(mode=0o700,exist_ok=True);archive=directory/(kind+'.archive');sig=directory/(kind+'.archive.sig')
        with archive.open('xb')as stream:stream.write(archives[0])
        with sig.open('xb')as stream:stream.write(signature)
        self.verify(kind,archive,sig)
        md=self.runner.run('adopted-pkginfo-'+kind,['/usr/bin/bsdtar','-xOf',str(archive),'.PKGINFO'],60);parsed=self.tools._metadata(md)
        need(parsed.get('pkgname')==[recipe['name']] and parsed.get('pkgver')==[recipe['version']] and parsed.get('arch')==['any'],'actual signed candidate package identity')
        save(directory/(kind+'-producer-pair.json'),pair);return dict(recipe,archive=str(archive),signature=str(sig),archive_pin=pin(archives[0]),signature_pin=pin(signature))
    def selected_product(self,kind,product):
        H=self.plan['H'];need(getattr(H,'ISSUER',None)=='DELEGATED_CONTEXT_PROGRAM_V4' and callable(getattr(H,'adopt_selected_pair',None)), 'explicit pinned completed-producer context API')
        recipe=self.profile['packages'][kind];selection_role=product.get('selection_role')
        if 'pair_selections'in self.d:
            need(type(selection_role)is str and selection_role in self.d['pair_selections'],'explicit selected component role')
            selection=self.d['pair_selections'][selection_role]
        else:selection=self.d['pair_selection']
        need(selection['component']==dict(name=recipe['name'],version=recipe['version'],architecture='any') and selection['test_fingerprint']==self.fingerprint and
             selection['public_test_key_pin']=={k:self.public_key[k]for k in ('bytes','sha256')},'exact Root-selected completed component and current TEST policy')
        signatures=product['signatures'];archives=product['archives']
        adoption=H.adopt_selected_pair(self.d,self.c,producer_delegation_raw=product['producer_delegation_raw'],producer_context=product['producer_context'],
            completion_raw=product['completion_raw'],pair_raw=product['pair_raw'],root_component_raw=product['root_component_raw'],root_test_raw=product['root_test_raw'],
            archive_bodies=archives,signature_bodies=signatures,public_test_key_raw=raw(self.public_key['path'],65536),selection_role=selection_role)
        need(adoption['kind']=='DELEGATED_CURRENT_ONBOARDING_SELECTED_PAIR_ADOPTION_V4' and adoption['current_stage_gpg_required']is True and
             all(adoption.get(k)==v and type(adoption.get(k))is type(v)for k,v in FINAL.items()), 'genuine selected completed producer; never relabel its run or claim final acceptance')
        directory=self.output/'adopted';directory.mkdir(mode=0o700,exist_ok=True);pairs=[]
        for i,(archive_body,signature_body)in enumerate(zip(archives,signatures)):
            archive=directory/(kind+'-'+str(i)+'.archive');sig=directory/(kind+'-'+str(i)+'.archive.sig')
            with archive.open('xb')as stream:stream.write(archive_body)
            with sig.open('xb')as stream:stream.write(signature_body)
            self.verify(kind+'-selected-'+str(i),archive,sig);pairs.append((archive,sig))
        need(len(pairs)==2 and archives[0]==archives[1],'both actual Root-selected pair signatures verified')
        archive,sig=pairs[0];metadata=self.tools._metadata(self.runner.run('adopted-pkginfo-'+kind,['/usr/bin/bsdtar','-xOf',str(archive),'.PKGINFO'],60))
        need(metadata.get('pkgname')==[recipe['name']] and metadata.get('pkgver')==[recipe['version']] and metadata.get('arch')==['any'],'actual selected signed package identity')
        for field,suffix in (('root_component_raw','Root-component.json'),('root_test_raw','Root-TEST.json'),('completion_raw','completion.json'),('pair_raw','producer-pair.json')):
            with (directory/(kind+'-'+suffix)).open('xb')as stream:stream.write(product[field])
        save(directory/(kind+'-selected-adoption.json'),adoption)
        return dict(recipe,archive=str(archive),signature=str(sig),archive_pin=pin(archives[0]),signature_pin=pin(signatures[0]))
    def retire_trust(self):
        if not hasattr(self,'private'):return
        for i,home in enumerate(self.homes):
            self.runner.run('private-retire-'+str(i),['/usr/bin/gpgconf','--homedir',str(home),'--kill','all'],15)
            step='no-agent-private-'+str(i)
            out=self.runner.run(step,['/usr/bin/gpg-connect-agent','--homedir',str(home),'--no-autostart','/bye'],15,expected=2)
            diagnostic=b'gpg-connect-agent: no gpg-agent running in this session\n'
            need(out==b'' and self.runner.stderr_outputs.get(step)==diagnostic and
                 not any(stat.S_ISSOCK(p.lstat().st_mode)for p in home.rglob('*')),'exact no-agent and no private sockets')
        shutil.rmtree(self.private);need(not os.path.lexists(self.private),'private TEST directory absent')
    def __enter__(self):
        need(self.c['stage']in('backend','ui'),'host build callbacks only; lifecycle requires outer launcher')
        self.plan['source']=self.source
        need(callable(self.plan['protected_fn']),'selected public-image preservation API')
        self.before=self.plan['protected_fn'](self.tools)
        try:
            self.trust();self.setup()
            if self.c['stage']=='ui':self.product('first-login',self.inputs['products']['first-login'])
            info=decode(self.docker('private-daemon',['info','--format','{{json .}}']))
            need(info['ID']==self.executor.facts['engine_id'] and info['OSType']=='linux' and info['Architecture']in('aarch64','arm64') and info['CgroupVersion']=='2','actual same native private engine')
            rows=decode(b'{"rows":'+self.docker('private-image',['image','inspect',self.image['id']])+b'}')['rows']
            need(len(rows)==1 and rows[0]['Id']==self.image['id'] and rows[0]['Architecture']=='arm64' and rows[0]['Os']=='linux' and
                 rows[0]['Config']['Labels'].get('org.cachy-asahi.current-image.nonce')==self.c['nonce'],'actual same provisional image on admitted engine')
            probe=intent(self.c,self.image['id'],'cachy-private-'+self.c['nonce'][:32]+'-probe',str(self.executor.facts['uid'])+':'+str(self.executor.facts['gid']),['-c','/usr/bin/pacman -Q | LC_ALL=C sort'],[])
            lock,state=self.actor(probe,'private-probe');need(lock==self.plan['inventory'],'fresh actual complete stage inventory')
            inventory=self.output/'builder-inventory.lock';inventory.write_bytes(lock)
            self.build_inputs=dict(source_date_epoch=self.inputs['source_date_epoch'],capacity=dict(build_seconds=min(180,self.d['capability']['max_command_seconds']),builder_cpus=4,builder_memory_bytes=4*1024**3,builder_pids=512),
                builder_inventory=dict(path=str(inventory),**pin(lock),packages=self.image['packages']))
            self.facts=dict(operation=OP,stage=self.c['stage'],binding=self.c['binding'],nonce=self.c['nonce'],delegation_pin=self.c['delegation_pin'],context_pin=pin(encoded(self.c)),context_program_pin=self.plan['H'].descriptor(self.d['programs']['context']),context_issuer=self.c['issuer'],context_kind=self.c['kind'],
                image=self.image['id'],architecture=os.uname().machine,page_size=os.sysconf('SC_PAGE_SIZE'),scope='DELEGATED_PRIVATE_ONLY',**FINAL)
            return self
        except BaseException as error:
            self.runner.deadline=self.end;self.runner.cleaning=True
            failures=self.retire_submitted()
            try:self.retire_trust()
            except BaseException as later:failures.append(dict(step='private-trust',error=type(later).__name__))
            save(self.state/'entry-failure.json',dict(status='HOLD',failure=type(error).__name__,retirement_failures=failures,**FINAL));raise
    def build(self,kind,label):
        need(kind in (('ui',)if self.c['stage']=='ui'else('enrollment','first-login')) and label in('a','b'),'exact current build slot')
        recipe=self.profile['packages'][kind];slot=self.output/'builds'/(kind+'-'+label);slot.mkdir(mode=0o700,parents=True,exist_ok=False)
        snapshot=slot/'inputs';snapshot.mkdir(mode=0o755)
        for name,row in recipe['files'].items():
            body=raw(self.source/recipe['path']/name);need(pin(body)=={k:row[k]for k in ('bytes','sha256')},'whole immutable actual recipe input')
            target=snapshot/name;target.write_bytes(body);target.chmod(row['mode'])
        artifacts=slot/'artifacts';artifacts.mkdir(mode=0o755);expected=slot/'expected-packages.lock';expected.write_bytes(self.plan['inventory'])
        uid,gid=self.executor.facts['uid'],self.executor.facts['gid'];name='cachy-private-'+self.c['nonce'][:32]+'-'+kind+'-'+label
        actor=intent(self.c,self.image['id'],name,f'{uid}:{gid}',['/builder-entry.sh'],[
            ('/inputs',str(snapshot),False),('/out',str(artifacts),True),('/builder-entry.sh',str(self.source/'scripts/build/container-entry.sh'),False),('/expected-packages.lock',str(expected),False)],
            tmpfs={'/tmp':'rw,nosuid,nodev,exec,size=4g'})
        epoch=self.inputs['source_date_epoch'];out,state=self.actor(actor,'build-'+kind+'-'+label,180,['CACHY_ASAHI_CONTAINER=1','SOURCE_DATE_EPOCH='+str(epoch)])
        need(state['attach_step']in self.runner.stderr_outputs,'complete actual build stderr is required')
        errors=self.runner.stderr_outputs[state['attach_step']];build_log=out+errors
        save(slot/'build-log-components.json',dict(stdout=pin(out),stderr=pin(errors),composition='stdout followed by stderr; no cross-channel ordering claim'))
        (slot/'build.log').write_bytes(build_log);self.native.check_log(build_log,kind,self.profile)
        validator=self.d['programs']['build_validator'];load(self.source,validator,'private_current_validator_pin_only')
        argv=['/usr/bin/python3','-I','-B',str(self.source/validator['member']),'--source-root',str(self.source),'--kind',kind,'--build-directory',str(slot),
            '--expected-inventory',str(expected),'--source-date-epoch',str(epoch)]
        static=decode(self.runner.run('validate-'+kind+'-'+label,argv,180));need(static['status']=='PASS_DELEGATED_BUILD_STATIC_VALIDATION','actual held static predicates pass')
        evidence=dict(schema_version=1,status='built-package-static-pass',hardware_status='NOT RUN',mode='native',image=self.image['id'],image_id=self.image['id'],
            source_date_epoch=epoch,network='none',builder_host_arch='aarch64',exit_code=0,clean_environment_id=name,command=create_argv(self.endpoint,actor,['CACHY_ASAHI_CONTAINER=1','SOURCE_DATE_EPOCH='+str(epoch)]),
            expected_packages_sha256=pin(self.plan['inventory'])['sha256'],recipe_inputs=static['recipe_inputs'],recipe_metadata=static['recipe_metadata'],entry_script_sha256=static['entry_script_sha256'],artifacts=static['artifacts'])
        evidence['files']={str(p.relative_to(slot)):pin(raw(p))['sha256']for p in artifacts.iterdir()if p.is_file()}
        for n in ('expected-packages.lock','build.log','build-log-components.json','validation.json'):evidence['files'][n]=pin(raw(slot/n))['sha256']
        save(slot/'provenance.json',evidence);return evidence
    def compare(self,kind):
        out=self.runner.run('current-'+kind+'-compare',['/usr/bin/python3','-I','-B',str(self.source/'scripts/build/compare.py'),
            str(self.output/'builds'/(kind+'-a')),str(self.output/'builds'/(kind+'-b')),'--require-bytes'],180)
        comparison=decode(out);recipe=self.profile['packages'][kind]
        need(comparison['status']=='contents-reproduced' and comparison['errors']==[],'actual pair comparator passed')
        archives=[pin(raw(self.output/'builds'/(kind+'-'+label)/'artifacts'/recipe['archive']))for label in ('a','b')]
        need(archives[0]==archives[1],'actual complete compressed pair equality')
        version=self.c['schema'];need(type(version)is int and version in(3,4),'actual selected producer context format')
        pair=dict(schema=version,kind='DELEGATED_CURRENT_ONBOARDING_PAIR_V'+str(version),issuer='DELEGATED_CURRENT_OWNER_V'+str(version),binding=self.c['binding'],nonce=self.c['nonce'],
            program_pin=self.plan['H'].descriptor(self.d['programs']['owner']),policy_pin=self.c['policy_pin'],package=recipe['name'],version=recipe['version'],component=dict(name=recipe['name'],version=recipe['version'],architecture='any'),
            archives=archives,matching_pair=True,comparison_receipt=self.records[-1],**FINAL)
        save(self.output/(kind+'-pair.json'),pair);return out
    def retire_submitted(self):
        self.runner.deadline=self.end;self.runner.cleaning=True;failures=[]
        for state in self.actors:
            if not state.get('retired'):
                try:
                    state['retirement']=self.retire(state);state['retired']=True
                    if state['retirement']['status']!='REMOVED_AND_ABSENT':failures.append(dict(step='nonnatural',name=state['intent']['name']))
                except BaseException as error:failures.append(dict(step='actor-retirement',name=state['intent']['name'],error=type(error).__name__))
        return failures
    def __exit__(self,kind,error,tb):
        failures=self.retire_submitted();retired=[s.get('retirement')for s in self.actors];after=None
        try:self.retire_trust()
        except BaseException as later:failures.append(str(later)[:1024])
        try:after=self.plan['protected_fn'](self.tools)
        except BaseException as later:failures.append(str(later)[:1024])
        okay=error is None and not failures and self.before==after
        save(self.output/'owner-cleanup.json',dict(operation=OP,stage=self.c['stage'],binding=self.c['binding'],nonce=self.c['nonce'],
            protected_before=self.before,protected_after=after,retired=retired,failures=failures,signature_verifications=self.signature_receipts,**FINAL))
        self.cleanup=dict(status='PASS_DELEGATED_CURRENT_STAGE_RETIREMENT'if okay else'HOLD_DELEGATED_CURRENT_STAGE_RETIREMENT',operation=OP,stage=self.c['stage'],
            binding=self.c['binding'],nonce=self.c['nonce'],natural_retirement=okay,owned_container_absence_verified=not failures,protected_state_unchanged=self.before==after,**FINAL)
        if not okay and error is None:raise ValueError('delegated host cleanup or preservation held')


def open_delegated_session(*,delegation_raw,delegation_sha256,context,image_report,executor,source_root,output,inputs):
    source=Path(source_root);d,c,p,H=source_request(delegation_raw,delegation_sha256,context,source)
    if c['stage']=='lifecycle':
        need(_INSIDE is not None,'lifecycle requires actual outer-owned namespace launcher')
        return LocalSession(d,c,p,H,source,Path(output),inputs,image_report)
    plan=request(delegation_raw,delegation_sha256,context,source,inputs,image_report,executor)
    plan['source']=source
    return Session(plan,source,output,inputs,image_report,executor)


class ObservedTools:
    def __init__(self,held):self.held=held
    def __getattr__(self,name):return getattr(self.held,name)
    def check_payload(self,recipe,run,pacman,label):
        result=self.held.check_payload(recipe,run,pacman,label)
        for i,(name,row)in enumerate(sorted(recipe['payload_files'].items())):
            path='/'+name
            need(run(label+'-stat-'+str(i),['/usr/bin/stat','-c','%u:%g:%a:%s:%h:%F','--',path])==
                ('0:0:%o:%d:1:regular file\n'%(row['mode'],row['bytes'])).encode(),'actual local installed identity/mode/size')
            need(run(label+'-sha256-'+str(i),['/usr/bin/sha256sum','--',path])==(row['sha256']+'  '+path+'\n').encode(),'actual whole installed source bytes')
        return result


def local_domain(manifest):
    need(_INSIDE is manifest and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and os.getpid()>1 and os.getppid()==1 and
         Path('/proc/1/comm').read_bytes()==b'bash\n' and os.uname().nodename==manifest['hostname'],'actual native local root direct child of owned Bash PID1')
    group=Path('/sys/fs/cgroup');values={k:(group/k).read_text().strip()for k in ('memory.max','memory.swap.max','pids.max','cpu.max')}
    quota,period=values['cpu.max'].split()
    need(values['memory.max']==str(4*1024**3) and values['memory.swap.max']=='0' and values['pids.max']=='512' and quota.isdecimal() and period.isdecimal() and
         int(period)>0 and int(quota)==4*int(period),'actual finite signed-image kernel limits, no host executor impersonation')
    return values


def observed_local_workflow(held):
    """Versioned invocation facts around the unchanged held Commands.run body."""
    class Commands(held.Commands):
        def run(self,step,argv,cwd,expected=0):
            need(type(step)is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',step) and
                 type(argv)is list and argv and all(type(v)is str for v in argv) and Path(argv[0]).is_absolute() and
                 type(expected)is int and expected in(0,2),'explicit finite local invocation')
            need(expected==0 or(re.fullmatch('no-agent-private-[0-9]+',step) and len(argv)==5 and
                 argv[0]=='/usr/bin/gpg-connect-agent' and argv[1]=='--homedir' and argv[3:]==['--no-autostart','/bye']),'exact expected local nonzero invocation')
            requested=dict(schema=1,kind='DELEGATED_LOCAL_COMMAND_INVOCATION_REQUEST_V1',step=step,argv_pin=pin(encoded(argv)),
                timeout_seconds=self.timeout,deadline_monotonic=self.deadline,max_output_bytes=self.max_output)
            need(all(type(requested[k])in(int,float) and math.isfinite(requested[k]) for k in('timeout_seconds','deadline_monotonic')) and
                 2<=self.timeout<=600 and type(self.max_output)is int and 0<=self.max_output<=1024**2,'actual local invocation instance bounds')
            save(self.output/(step+'.invocation-request.json'),requested)
            original_core=self.core;observed=[];before=len(self.records)
            class Core:
                def __getattr__(inner,name):return getattr(original_core,name)
                def supervise(inner,child,**arguments):
                    need(not observed and set(arguments)=={'cap','retirement','grace','max_output'},'one actual held supervisor invocation')
                    need(all(type(arguments[k])in(int,float) and math.isfinite(arguments[k])for k in('cap','retirement','grace')) and
                         1.1<arguments['cap']<=requested['timeout_seconds'] and arguments['retirement']==1 and arguments['grace']==.2 and
                         arguments['max_output']==requested['max_output_bytes'],'exact actual held supervision arguments')
                    selected=dict(schema=1,kind='DELEGATED_LOCAL_SUPERVISION_REQUEST_V1',step=step,request_pin=pin(encoded(requested)),
                        cap_seconds=arguments['cap'],retirement_seconds=arguments['retirement'],grace_seconds=arguments['grace'],max_output_bytes=arguments['max_output'])
                    save(self.output/(step+'.supervision-request.json'),selected)
                    # Persist actual arguments before delegating the actual wait owner.
                    result=original_core.supervise(child,**arguments)
                    need(type(result)is dict and type(result.get('output'))is bytes,'actual complete held supervisor result')
                    observed.append((selected,decode(encoded({k:v for k,v in result.items()if k!='output'})),pin(result['output'])))
                    return result
            self.core=Core()
            try:out=super().run(step,argv,cwd,expected)
            finally:self.core=original_core
            need(len(observed)==1 and len(self.records)==before+1,'one original local receipt and supervision')
            selected,result,output_pin=observed[0];row=self.records[-1];original=decode(encoded(row))
            need(raw(self.output/(step+'.invocation-request.json'),16384)==encoded(requested) and
                 raw(self.output/(step+'.supervision-request.json'),16384)==encoded(selected),'whole actual invocation requests unchanged')
            need(decode(raw(self.output/'commands.json'))==self.records,'whole genuine held command index unchanged')
            need(row['step']==step and row['argv']==argv and row['cwd']==str(cwd) and row['expected']==expected and row['success']is True and
                 row['supervision']==result and row['log_pin']==output_pin==pin(out) and row['channels']=='stdout+stderr combined in pipe order','genuine local invocation/result/receipt join')
            natural(result,expected)
            need(type(result.get('passed'))is bool and type(result['seconds'])in(int,float) and math.isfinite(result['seconds']) and
                 0<=result['seconds']<selected['cap_seconds'],'actual local supervisor outcome and duration below actual cap')
            row.update(timeout_seconds=requested['timeout_seconds'],supervision_cap_seconds=selected['cap_seconds'],
                retirement_seconds=selected['retirement_seconds'],grace_seconds=selected['grace_seconds'],max_output_bytes=selected['max_output_bytes'],
                held_receipt=original,local_invocation_v1=dict(schema=1,kind='DELEGATED_LOCAL_COMMAND_INVOCATION_V1',request=requested,
                    request_pin=pin(encoded(requested)),supervision_request=selected,supervision_request_pin=pin(encoded(selected)),
                    held_receipt_pin=pin(encoded(original)),supervision_result_pin=pin(encoded(result))))
            held.save(self.output/'commands.json',self.records);return out
    return SimpleNamespace(Commands=Commands)


class LocalRunner:
    def __init__(self,commands,maximum=180):self.commands=commands;self.maximum=maximum
    def run(self,step,argv,timeout_seconds=180,expected=0):
        need(expected==0,'exact local expected exit')
        need(self.commands.timeout<=self.maximum and self.commands.deadline<=_INSIDE['deadline'],'local callbacks remain within actual delegated command/total deadline')
        raw=self.commands.run(step,argv,self.commands.output.parent,expected)
        natural(self.commands.records[-1]['supervision']);return raw


def local_retire_trust(local,callbacks):
    """Preserve the held combined channel and actual no-agent exit, per instance."""
    if not hasattr(local,'work'):return None
    def run(step,argv):
        expected=0
        if argv and argv[0]=='/usr/bin/gpg-connect-agent':
            match=re.fullmatch('no-agent-private-([0-9]+)',step)
            need(match is not None and int(match[1])<len(local.homes) and argv==[
                '/usr/bin/gpg-connect-agent','--homedir',str(local.homes[int(match[1])]),'--no-autostart','/bye'],'exact local no-agent operand')
            expected=2
        out=callbacks.command(local.admin,step,argv,expected=expected);row=local.admin.records[-1]
        need(row['step']==step and row['argv']==argv and type(row['expected'])is int and row['expected']==expected and
             row['success']is True and row['log_pin']==pin(out) and row['channels']=='stdout+stderr combined in pipe order','actual held local retirement receipt')
        natural(row['supervision'],expected);return out
    result=local.deps[1].retire_private(run,local.work,local.homes)
    need(result['homes_retired'] and result['no_sockets'] and result['private_directory_absent'] and not result['failures'],'all actual local private TEST homes retired')
    return result


class LocalSession:
    """Reuse only reviewed local callbacks, never bc47942's Root admission gate."""
    def __init__(self,d,c,policy,H,source,output,inputs,image_report):
        self.d,self.c,self.policy,self.source,self.output,self.inputs=d,c,policy,source,output,inputs
        self.native,T,A,self.profile=modules(source);self.native_pin=NATIVE_PIN;self.tools=ObservedTools(T)
        self.plan=dict(H=H,source=source);self.cleanup=None;self.signature_receipts={}
        self.image=image_data(image_report,d,c,raw(source/'inputs/stages/lifecycle.expected.lock',1024**2))
    def __enter__(self):
        kernel=local_domain(_INSIDE);H=self.plan['H'];self.public_key,self.fingerprint=test_policy(self.plan|dict(d=self.d,policy=self.policy),self.inputs)
        callback=self.d['programs']['local_callbacks'];need(callback['sha256']=='f1a91dee080f76eff88409dd1fe893dc45a2084338017f367ec9874a462a612d','whole reviewed local callback body')
        BC=load(self.source,callback,'delegated_local_callbacks');deps=BC.dependencies();deps=(observed_local_workflow(deps[0]),*deps[1:]);BC._INSIDE=_INSIDE
        # This is local callback configuration, not an old Root grant: it has no
        # issuer, approval, Root qualification or admission selector fields.
        config=dict(stage='lifecycle',binding=self.c['binding'],resources=dict(total_seconds=min(600,self.d['capability']['total_seconds']),build_seconds=min(180,self.d['capability']['max_command_seconds'])),
            owner=dict(test_public_key=self.public_key,test_fingerprint=self.fingerprint),images={'lifecycle':dict(id=self.image['id'],inventory_pin=dict(path=str(self.source/'inputs/stages/lifecycle.expected.lock'),**pin(raw(self.source/'inputs/stages/lifecycle.expected.lock'))))})
        class SignedCallbacks(BC.SignedSession):
            def retire_trust(local):return local_retire_trust(local,BC)
        self.local=SignedCallbacks(config,self.source,self.output,deps)
        self.local.__enter__();self.local.commands.timeout=min(self.local.commands.timeout,self.d['capability']['max_command_seconds']);self.local.commands.deadline=min(self.local.commands.deadline,_INSIDE['deadline'])
        self.runner=LocalRunner(self.local.commands,min(180,self.d['capability']['max_command_seconds']));self.records=self.local.commands.records
        self.verifier,self.fingerprint,self.pacman=self.local.verifier,self.local.fingerprint,self.local.pacman
        try:
            roles={k:material(H,self.d,self.source,self.inputs['setup8'][k+'_role'])for k in ('archive','signature','decision','verification')}
            archive=raw(roles['archive']['path']);signature=raw(roles['signature']['path'])
            need(pin(archive)==self.profile['setup8']['archive_pin'],'authentic unchanged Setup8 dependency')
            decision(raw(roles['decision']['path']),raw(roles['verification']['path']),archive,signature,self.public_key,self.fingerprint,'cachy-asahi-setup','0.3.0-1')
            directory=self.output/'adopted';directory.mkdir(mode=0o700,exist_ok=True);package=directory/'setup8.archive';detached=directory/'setup8.archive.sig'
            package.write_bytes(archive);detached.write_bytes(signature)
            self.signed={'setup8':dict(self.profile['setup8'],archive=str(package),signature=str(detached),archive_pin=pin(archive),signature_pin=pin(signature))}
            need(set(self.inputs['products'])=={'enrollment','first-login','ui'},'actual four-package lifecycle material set after builds/signing')
            for kind in ('enrollment','first-login','ui'):self.signed[kind]=Session.product(self,kind,self.inputs['products'][kind])
            self.protected_before=self.local.protected_before
            self.facts=dict(operation=OP,stage='lifecycle',binding=self.c['binding'],nonce=self.c['nonce'],delegation_pin=self.c['delegation_pin'],context_pin=pin(encoded(self.c)),context_program_pin=H.descriptor(self.d['programs']['context']),context_issuer=self.c['issuer'],context_kind=self.c['kind'],image=self.image['id'],
                architecture='aarch64',page_size=os.sysconf('SC_PAGE_SIZE'),execution_domain='DELEGATED_OWNED_SIGNED_IMAGE_LOCAL',kernel_limits=kernel,**FINAL)
            return self
        except BaseException as error:
            self.local.__exit__(type(error),error,error.__traceback__);raise
    verify=Session.verify
    selected_product=Session.selected_product
    def run(self,step,argv):return self.runner.run(step,argv)
    def verify_state(self):return self.local.verify_state()
    def protected_after(self):return self.local.protected_after()
    def __exit__(self,kind,error,tb):
        try:return self.local.__exit__(kind,error,tb)
        finally:
            old=self.local.cleanup;okay=old is not None and old['natural_retirement']is True and old['protected_state_unchanged']is True
            self.cleanup=dict(status='PENDING_OUTER_CONTAINER_RETIREMENT',operation=OP,stage='lifecycle',binding=self.c['binding'],nonce=self.c['nonce'],
                natural_retirement=okay,owned_container_absence_verified=False,protected_state_unchanged=okay,**FINAL)


def products_to_data(value,directory,rows):
    """Bounded generated observations, not unreviewed host-path references."""
    if type(value)is bytes:
        need(0<len(value)<=16*1024**2,'bounded actual generated product body');name='body-%04d.bin'%len(rows)
        need(len(rows)<64 and sum(r['bytes']for r in rows.values())+len(value)<=128*1024**2,'finite generated product set/aggregate bytes');path=directory/name
        with path.open('xb')as stream:os.fchmod(stream.fileno(),0o600);stream.write(value)
        rows[name]=pin(value);return {'generated_body':name,'pin':pin(value)}
    if type(value)is dict:return {k:products_to_data(v,directory,rows)for k,v in value.items()}
    if type(value)is list:return [products_to_data(v,directory,rows)for v in value]
    need(type(value)in(str,int,float,bool,type(None)),'JSON or actual generated bytes only');return value


def products_from_data(value,directory,rows):
    if type(value)is dict and set(value)=={'generated_body','pin'}:
        name=relative(value['generated_body']);need('/'not in name and rows.get(name)==value['pin'],'closed generated observation descriptor')
        body=raw(directory/name);need(pin(body)==value['pin'],'whole actual generated product body');return body
    if type(value)is dict:return {k:products_from_data(v,directory,rows)for k,v in value.items()}
    if type(value)is list:return [products_from_data(v,directory,rows)for v in value]
    return value


def finalize_delegated(report,receipt,d,c,*,expected_intent):
    need(report['kind']=='DELEGATED_CURRENT_PRIVATE_STAGE_REPORT_V4' and report['stage']=='lifecycle' and report['status']=='PENDING_OUTER_CURRENT_STAGE_RETIREMENT' and
         report['binding']==c['binding'] and report['nonce']==d['nonce'] and report['delegation_pin']==c['delegation_pin'] and
         all(report.get(k)==v and type(report.get(k))is type(v)for k,v in FINAL.items()),'genuine same-stage pending inner result with no acceptance')
    need(receipt['intent']==expected_intent,'exact independently selected outer launch intent')
    commands=receipt['command_receipts'];need(type(commands)is list and len(commands)>=8,'complete actual outer command receipts')
    for command in commands:
        natural(command['supervision']);actual=command['executor_receipt'];natural(actual['supervision'])
        need(command['success']is True and type(command['expected'])is int and command['expected']==0 and type(actual['expected'])is int and actual['expected']==0 and
             actual['step']==command['step'] and actual['argv']==command['argv'] and type(actual['exit'])is int and actual['exit']==0 and
             actual['output_pin']==command['log_pin'] and actual['supervision']==command['supervision'],'genuine exact natural outer executor receipt/output join')
    row=receipt['intent'];created,terminal=receipt['created'],receipt['terminal'];cid=container(created,row,c)
    need(container(terminal,row,c)==cid and terminal['State']['Running']is False and terminal['State']['ExitCode']==0 and terminal['State']['OOMKilled']is False and
         receipt['retired']is True and receipt['retirement']['status']=='REMOVED_AND_ABSENT' and receipt['retirement']['cid']==cid,'actual natural same-CID terminal/removal/absence')
    need(row['user']=='0:0' and row['entrypoint']==['/bin/bash'] and row['cmd'][0:3]==['-c','/usr/bin/python3 -I -B "$@"; status=$?; exit "$status"','current-private'] and
         row['readonly']is False and row['capadd']==['CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID'],'exact signed local root/Bash-PID1 intent')
    cleanup=report['owner_cleanup'];need(cleanup['status']=='PENDING_OUTER_CONTAINER_RETIREMENT' and cleanup['natural_retirement']is True and
         cleanup['owned_container_absence_verified']is False and cleanup['protected_state_unchanged']is True,'genuine local restoration, absence only observed outer')
    result=dict(report);result['status']='PROVISIONAL_CURRENT_LIFECYCLE_DATA_ONLY';result['outer_retirement']=receipt
    result['owner_cleanup']=dict(cleanup,status='PASS_DELEGATED_CURRENT_STAGE_RETIREMENT',owned_container_absence_verified=True)
    return result


def launch_delegated_lifecycle(*,delegation_raw,delegation_sha256,context,image_report,executor,source_root,output,inputs):
    source=Path(source_root);output=Path(output);plan=request(delegation_raw,delegation_sha256,context,source,inputs,image_report,executor)
    need(plan['c']['stage']=='lifecycle' and not output.exists() and output.parent.is_dir() and output.parent.stat().st_uid==os.getuid() and
         stat.S_IMODE(output.parent.stat().st_mode)==0o700 and not list(output.parent.iterdir()),'fresh empty owned lifecycle output parent')
    control=Path(executor.work)/('private-lifecycle-'+plan['c']['nonce']);control.mkdir(mode=0o700)
    s=Session(plan,source,control,inputs,image_report,executor);generated=control/'generated';generated.mkdir(mode=0o700);rows={}
    encoded_inputs=products_to_data(inputs,generated,rows);hostname='current-private-'+plan['c']['nonce'][:32]
    manifest=dict(delegation=decode(delegation_raw),delegation_sha256=delegation_sha256,context=context,image_report=image_report,source_root=str(source),output=str(output),
        inputs=encoded_inputs,generated=rows,hostname=hostname,deadline=s.end,host_uid=os.getuid(),host_gid=os.getgid())
    path=control/'inside.json';save(path,manifest);owner=source/plan['d']['programs']['owner']['member']
    cmd=['-c','/usr/bin/python3 -I -B "$@"; status=$?; exit "$status"','current-private',str(owner),'--inside',str(path),'--manifest-sha256',pin(raw(path))['sha256']]
    actor=intent(s.c,s.image['id'],'cachy-private-'+s.c['nonce'][:32]+'-lifecycle','0:0',cmd,[
        (str(source),str(source),False),(str(control),str(control),False),(str(output.parent),str(output.parent),True)],readonly=False,capadd=['CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID'])
    actor['hostname']=hostname
    # Pass the fixed hostname through the explicit inspected create vector.
    try:out,state=s.actor(actor,'private-lifecycle',min(600,s.d['capability']['max_command_seconds']))
    except BaseException as error:
        failures=s.retire_submitted()
        save(control/'launch-failure.json',dict(status='HOLD',failure=type(error).__name__,retirement_failures=failures,actors=s.actors,commands=s.records,**FINAL));raise
    report=decode(raw(output/'route.json',4*1024**2));result=finalize_delegated(report,state,s.d,s.c,expected_intent=actor)
    save(control/'outer-final.json',dict(report=result,commands=s.records,**FINAL));shutil.copytree(control,output/'outer-owner')
    need(raw(control/'outer-final.json')==raw(output/'outer-owner/outer-final.json'),'whole retained outer evidence')
    shutil.rmtree(control);need(not control.exists(),'private outer directory absent before final publication')
    temporary=output/'route.final.json';save(temporary,result);os.replace(temporary,output/'route.json');return result


def inside(path,sha):
    global _INSIDE
    body=raw(path,4*1024**2);need(pin(body)['sha256']==sha,'actual outer-selected whole inside manifest')
    m=decode(body);_INSIDE=m;local_domain(m);source=Path(m['source_root']);raw_d=encoded(m['delegation'])
    d,c,p,H=source_request(raw_d,m['delegation_sha256'],m['context'],source)
    need(d['stage']=='lifecycle' and time.monotonic()<m['deadline'] and type(m['host_uid'])is int and m['host_uid']>0 and type(m['host_gid'])is int and m['host_gid']>0,'finite actual local stage/export operands')
    inputs=products_from_data(m['inputs'],path.parent/'generated',m['generated']);R=load(source,d['programs']['route'],'private_current_route')
    profile=decode(raw(source/(FAMILY+'/successor_v2/profile.json')));output=Path(m['output'])
    try:return R.run_registered(stage='lifecycle',source=source,profile=profile,inputs=inputs,delegation_raw=raw_d,delegation_sha256=m['delegation_sha256'],
        context=c,image=m['image_report'],executor=None,output=output,open_session=open_delegated_session)
    finally:
        if output.is_dir():
            paths=[output,*output.rglob('*')];need(len(paths)<=4096,'finite public actor output tree')
            for target in paths:
                info=target.lstat();need(not target.is_symlink() and(stat.S_ISREG(info.st_mode)or stat.S_ISDIR(info.st_mode)),'ordinary public actor output only')
                os.chown(target,m['host_uid'],m['host_gid'])


def run_owned_current_v3(*,delegation_raw,delegation_sha256,context,source_root,inputs,executor,output,public_output):
    """Executor callback: actual image, private stage, then selected public retention.

    The assembler's single semantic validator selects all public references.
    New retention must explicitly support this v4 report; old schema projection
    or manufactured Root image/admission fields are deliberately unavailable.
    """
    source=Path(source_root);output=Path(output);public_output=Path(public_output)
    d,c,p,H=source_request(delegation_raw,delegation_sha256,context,source)
    validator=load(source,d['programs']['inputs_assembler'],'private_current_inputs_assembler')
    validation=validator.validate_owner_inputs_v3(inputs=inputs,delegation=d,source_root=source)
    need(type(validation)is dict and validation['valid']is True and type(validation['required_refs'])is list,'shared authoritative public-input validation')
    stage_inputs=validator.stage_inputs(inputs);image_inputs=inputs['image_inputs']
    image_program=load(source,d['programs']['image'],'private_current_image_entry')
    retention=load(source,d['programs']['retention'],'private_current_retention')
    retain=getattr(retention,'retain_delegated_stage',None)
    need(callable(retain),'selected retention must explicitly accept delegated v4; no old Root-schema projection')
    need(output.is_absolute() and output==output.resolve() and output.is_dir() and not list(output.iterdir()) and
         stat.S_IMODE(output.stat().st_mode)==0o700 and output.stat().st_uid==os.getuid(),'fresh executor-owned empty stage root')
    try:
        image=image_program.build_stage(delegation_raw=delegation_raw,delegation_sha256=delegation_sha256,context=c,
            source_root=source,inputs=image_inputs,executor=executor,output=output/'image',context_program=H)
        route=load(source,d['programs']['route'],'private_current_stage_route');profile=decode(raw(source/(FAMILY+'/successor_v2/profile.json')))
        if c['stage']=='lifecycle':
            parent=output/'lifecycle-output';parent.mkdir(mode=0o700);stage_output=parent/'stage'
            report=launch_delegated_lifecycle(delegation_raw=delegation_raw,delegation_sha256=delegation_sha256,context=c,image_report=image,
                executor=executor,source_root=source,output=stage_output,inputs=stage_inputs)
        else:
            stage_output=output/'stage'
            report=route.run_registered(stage=c['stage'],source=source,profile=profile,inputs=stage_inputs,delegation_raw=delegation_raw,
                delegation_sha256=delegation_sha256,context=c,image=image,executor=executor,output=stage_output,open_session=open_delegated_session)
        need(report['status']=='PROVISIONAL_CURRENT_'+c['stage'].upper()+'_DATA_ONLY' and all(report.get(k)==v and type(report.get(k))is type(v)for k,v in FINAL.items()),'actual private stage completed with no final acceptance')
        # The selected retention program owns privacy projections and its encoder.
        # No raw work/home/launch tree is copied or emitted by this adapter.
        retained=retain(stage=c['stage'],output=stage_output,destination=public_output,source_root=source,delegation=d,context=c,
            image_report=image,stage_report=report,profile=profile,inputs=inputs,executor=executor)
        need(type(retained)is dict and retained['evidence_state']=='COMPLETE' and retained['Root_final_acceptance']is None and
             not retained.get('independent_component_acceptance') and not retained.get('hardware_acceptance') and not retained.get('release_acceptance'),'complete selected public retention, never component acceptance')
        result=dict(completed=True,status='DELEGATED_PRIVATE_STAGE_AND_PUBLIC_RETENTION_COMPLETE',binding=c['binding'],stage=c['stage'],nonce=c['nonce'],
            stage_report_pin=pin(encoded(report)),retention=dict(evidence_state=retained['evidence_state'],capsule_pin=retained['capsule_pin'],manifest_pin=pin(encoded(retained['manifest']))),**FINAL)
        save(output/'completion.json',result);return result
    except BaseException as error:
        save(output/'failure.json',dict(completed=False,status='HOLD',binding=c['binding'],stage=c['stage'],failure_type=type(error).__name__,**FINAL));raise


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--inside',type=Path,required=True);p.add_argument('--manifest-sha256',required=True);a=p.parse_args()
    need(sys.flags.isolated and sys.dont_write_bytecode and __debug__,'isolated unoptimized internal signed-image entry')
    inside(a.inside,a.manifest_sha256)


if __name__=='__main__':main()

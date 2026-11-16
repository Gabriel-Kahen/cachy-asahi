# SPDX-License-Identifier: MIT
"""Finite retained-DATA Reader for the current three-package owned route.

Never imports producer/Source code or invokes an actor, decoder command, ALPM,
GPG, Docker, network, or lease operation. Root authenticates external evidence.
"""
import argparse
import datetime
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import tarfile

OP='first-login-enrollment-ui-current-v2'
STAGES=('backend','ui','lifecycle')
KINDS=('enrollment','first-login','ui')
VERSIONS={'enrollment':('cachy-asahi-repository-enrollment','0.4.0-1'),
          'first-login':('cachy-asahi-first-login','0.1.0-3'),
          'ui':('cachy-asahi-first-login-ui','0.2.0-2')}
COUNTS={'backend':350,'ui':374,'lifecycle':372}
PROFILE_PIN={'bytes':21679,'sha256':'8ad3641649e395b1202363e3368f713f65252a743b12e3a8d69430e4f82bc171'}
FAMILY='scripts/ci/first-login-enrollment-native-source'
MAX_FILE=16*1024**2
MAX_TOTAL=512*1024**2
API='CURRENT_ONBOARDING_OWNED_CALLBACKS_V2'
LABEL='org.cachy-asahi.current-onboarding'
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']
CAPABILITIES=['CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID']
OWNER=FAMILY+'/payload/native/owner_current_v2.py'
ROUTE=FAMILY+'/successor_v2/owned_route.py'
PREFIX=FAMILY+'/successor_v3'
# Independently reviewed bc47942 runtime closure, never imported as code.
CODE={
 'scripts/workflows/developer_workflow.py':dict(bytes=29699,mode=420,sha256='531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba'),
 'scripts/virtual/owned_process.py':dict(bytes=25140,mode=493,sha256='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'),
 FAMILY+'/payload/native/build_tools_tools_v2.py':dict(bytes=34468,mode=420,sha256='eb1ff0ee8aefc2c0e32b38520e1bf0dabcbb9308081a24e2f9c378366a3cab13'),
 FAMILY+'/payload/native/build_tools_alpm_v2.py':dict(bytes=27087,mode=420,sha256='d4197495e0281aecfd590e76ed908cd1fcf46b1934bc02709e47a7dac49abb73'),
 ROUTE:dict(bytes=26320,mode=420,sha256='43db41de72822cb8f4d875b6c1d17ffd5062770616ed303f63e299c13478dd86'),
 FAMILY+'/successor_v2/native.py':dict(bytes=13703,mode=420,sha256='cde384acd8574ddfcb07f7316ad4d24349f5b958ac6b2cea48a3a6aff480c827'),
 FAMILY+'/successor_v2/profile.json':dict(mode=420,**PROFILE_PIN),
 OWNER:dict(bytes=46298,mode=420,sha256='f1a91dee080f76eff88409dd1fe893dc45a2084338017f367ec9874a462a612d')}



def need(ok,message):
    if not ok:raise ValueError(message)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def decode(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate JSON key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def relative(value):
    need(type(value) is str and 0<len(value.encode())<=4096 and not value.startswith('/') and
         not any(ord(c)<32 or ord(c)==127 or c=='\\' for c in value) and
         all(p not in ('','.','..') for p in value.split('/')),'literal relative DATA path')
    return value


def absolute(value):
    p=Path(value);need(p.is_absolute() and '..' not in p.parts and
        not any(q.is_symlink() for q in (p,*p.parents)),'ordinary absolute no-alias DATA path')
    return p


class Reads:
    def __init__(self):self.total=0
    def read(self,path,cap=MAX_FILE):
        p=absolute(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded single-link DATA')
            data=bytearray()
            while block:=os.read(fd,min(65536,cap+1-len(data))):
                data.extend(block);need(len(data)<=cap,'DATA byte cap')
            after=os.fstat(fd)
            identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            need(len(data)==before.st_size and identity(before)==identity(after)==identity(p.lstat()),'DATA changed during read')
            self.total+=len(data);need(self.total<=MAX_TOTAL,'aggregate DATA read cap')
            return bytes(data)
        finally:os.close(fd)
    def reference(self,row,cap=MAX_FILE):
        need(type(row) is dict and set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int and
             0<=row['bytes']<=cap and re.fullmatch('[0-9a-f]{64}',row['sha256'] or ''),'exact nonnull DATA reference')
        raw=self.read(row['path'],cap);need(pin(raw)=={k:row[k] for k in ('bytes','sha256')},'whole reference mismatch');return raw


def metadata(raw):
    need(type(raw) is bytes and len(raw)<=256*1024,'metadata cap')
    result={}
    for line in raw.decode('utf-8').split('\n'):
        if not line or line.startswith('#'):continue
        key,sep,value=line.partition(' = ')
        need(sep and re.fullmatch('[a-z][a-z0-9_]*',key) and len(value)<=8192 and '\r' not in value,'canonical package metadata')
        result.setdefault(key,[]).append(value)
    return result


def inventory(raw):
    need(type(raw) is bytes and 0<len(raw)<=1024**2 and raw.endswith(b'\n'),'complete inventory bytes')
    result={}
    for line in raw.decode('ascii').split('\n')[:-1]:
        name,sep,version=line.partition(' ')
        need(sep and re.fullmatch('[a-z0-9@._+-]+',name) and re.fullmatch(r'[A-Za-z0-9.+_:~\-]+',version) and name not in result,'unique literal inventory row')
        result[name]=version
    return result


def inventory_bytes(rows):return ''.join(n+' '+v+'\n' for n,v in sorted(rows.items())).encode()


def check_log(raw,kind,profile):
    need(type(raw) is bytes and 0<len(raw)<=1024**2 and raw.count(b'Starting check()')==1,'one bounded recipe check invocation')
    text=raw.decode('utf-8');need(not re.search(r'FAILED|ERROR:|\bskipped\b|expected failure',text,re.I),'failed/skipped checks refused')
    if kind=='enrollment':
        values=[]
        for line in text.split('\n'):
            if line.startswith('{'):
                try:values.append(decode(line.encode()))
                except ValueError:pass
        need(values==[profile['enrollment_check_report']],'exact current Enrollment04 check report')
    else:
        wanted=profile['packages'][kind]['check_counts']
        need(wanted==([14,6] if kind=='first-login' else [38,6]),'current check suite counts')
        need(re.findall(r'^Ran ([0-9]+) tests in [0-9.]+s$',text,re.M)==list(map(str,wanted)) and
             text.splitlines().count('OK')==2,'complete ordered native check suites')


def strict_signature(raw,fingerprint):
    need(re.fullmatch('[0-9A-F]{40}',fingerprint or ''),'explicit TEST primary fingerprint')
    rows=[line.split()[1:] for line in raw.decode().splitlines() if line.startswith('[GNUPG:] ')]
    bad={'EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','FAILURE','NODATA','TRUST_NEVER','TRUST_UNDEFINED'}
    need(not any(row and row[0] in bad for row in rows),'bad TEST signature/key state')
    valid=[r for r in rows if r and r[0]=='VALIDSIG']
    need(len(valid)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==fingerprint and
         any(r and r[0]=='TRUST_ULTIMATE' for r in rows),'one exact trusted TEST primary')


def archive_tar(raw,recipe,packages,epoch=None):
    need(type(raw) is bytes and 0<len(raw)<=MAX_FILE and len(raw)%512==0,'bounded decoded package DATA')
    expected=recipe['payload_files'];parents={str(p) for n in expected for p in Path(n).parents if str(p)!='.'}
    seen=set();dirs=set();payload={};meta={};cursor=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for item in archive:
            name=item.name[:-1] if item.name.endswith('/') else item.name;relative(name)
            need(name not in seen and item.offset==cursor and item.offset_data==cursor+512 and not item.pax_headers and
                 item.uid==item.gid==0 and item.type in (tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE),'closed single-header package framing')
            seen.add(name);end=item.offset_data+item.size;cursor=item.offset_data+(item.size+511)//512*512
            need(0<=item.size<=1024**2 and cursor<=len(raw) and not any(raw[end:cursor]),'package member/padding bound')
            if item.isdir():
                need(name in parents and item.mode==0o755 and item.size==0,'package directory namespace/mode');dirs.add(name);continue
            body=raw[item.offset_data:end]
            if name in ('.PKGINFO','.BUILDINFO','.MTREE'):
                need(item.mode==0o644,'package metadata mode');meta[name]=body
            else:
                need(name in expected and dict(mode=item.mode,**pin(body))==expected[name],'source-bound package payload')
                payload[name]=expected[name]
    need(dirs==parents and set(payload)==set(expected) and set(meta)=={'.PKGINFO','.BUILDINFO','.MTREE'} and
         len(raw)-cursor>=1024 and not any(raw[cursor:]),'complete package payload/metadata/trailer')
    pkg,build=metadata(meta['.PKGINFO']),metadata(meta['.BUILDINFO'])
    for key,value in (('pkgname',recipe['name']),('pkgbase',recipe['name']),('pkgver',recipe['version']),('arch','any')):
        need(pkg.get(key)==[value],'exact current PKGINFO identity')
    for key,field in (('depend','depends'),('makedepend','makedepends'),('checkdepend','checkdepends'),('optdepend','optdepends')):
        need(sorted(pkg.get(key,[]))==sorted(recipe.get(field,[])),'exact source dependency metadata')
    need(pkg.get('license')==['MIT'] and not any(k in pkg for k in ('provides','replaces','conflict','install','backup')),'private package metadata policy')
    for key,value in (('format','2'),('pkgname',recipe['name']),('pkgbase',recipe['name']),('pkgver',recipe['version']),('pkgarch','any'),('pkgbuild_sha256sum',recipe['files']['PKGBUILD']['sha256'])):
        need(build.get(key)==[value],'exact source BUILDINFO identity/recipe')
    need('check' in build.get('buildenv',[]) and '!check' not in build['buildenv'],'BUILDINFO checks enabled')
    labels={n+'-'+v:n for n,v in packages.items()};need(len(labels)==len(packages),'unambiguous installed labels')
    installed=build.get('installed',[]);need(len(installed)==len(set(installed))==len(packages),'complete builder installed inventory')
    names=set()
    for value in installed:
        label,sep,arch=value.rpartition('-');need(sep and arch in ('aarch64','any') and label in labels,'exact installed name/version; architecture syntax')
        names.add(labels[label])
    need(names==set(packages),'exact installed package membership')
    if epoch is not None:need(pkg.get('builddate')==build.get('builddate')==[str(epoch)],'stable source epoch metadata')
    return {'payload':payload,'metadata':meta}


def package(raw,recipe,packages,epoch=None):
    need(0<len(raw)<=MAX_FILE,'compressed package cap')
    if raw.startswith(b'\xfd7zXZ\0'):
        import lzma
        stream=lzma.LZMADecompressor(memlimit=64*1024**2);body=stream.decompress(raw,max_length=MAX_FILE+1)
        need(stream.eof and not stream.unused_data,'complete one XZ package frame')
    else:
        need(raw.startswith(b'\x28\xb5\x2f\xfd'),'exact zstd/XZ package framing')
        try:from compression import zstd
        except ImportError:raise ValueError('Python3.14 stdlib zstd required; no external decoder')
        with zstd.ZstdFile(io.BytesIO(raw),'rb') as stream:
            body=stream.read(MAX_FILE+1);need(stream.read(1)==b'','decoded package cap')
    return archive_tar(body,recipe,packages,epoch)


def source_tree(source,reads):
    source=absolute(source);raw=reads.read(source/'source.lock.json',1024**2);lock=decode(raw)
    need(lock.get('schema')==1 and lock.get('operation')==OP and lock.get('kind')=='CURRENT_ONBOARDING_CLOSED_SOURCE_V3' and type(lock.get('files')) is dict and 58<=len(lock['files'])<=254 and
         set(lock['actual'])=={'source','ref','run','job','artifact','Root_trust','Root_resources','Root_runtime','Root_signing','actual_images','dispatch_grant','publication'} and all(v is None for v in lock['actual'].values()),'closed current-v3 Source declaration')
    need(reads.read(source/'source-map.json',1024**2)==raw,'identical source map and lock')
    found={};expected_dirs={str(p) for n in lock['files'] for p in Path(n).parents if str(p)!='.'}
    for current,dirs,files in os.walk(source,followlinks=False):
        for name in dirs:
            q=Path(current)/name;need(not q.is_symlink() and q.relative_to(source).as_posix() in expected_dirs,'Source directory alias/extra directory')
        for name in files:
            p=Path(current)/name;key=p.relative_to(source).as_posix();relative(key)
            need(key in ('source.lock.json','source-map.json') or key in lock['files'],'extra Source member')
            if key in ('source.lock.json','source-map.json'):continue
            row=lock['files'][key];body=reads.read(p,32*1024**2 if key=='inputs/public-carrier.tar' else MAX_FILE)
            need(pin(body)=={k:row[k] for k in ('bytes','sha256')} and stat.S_IMODE(p.lstat().st_mode)==row['mode'],'Source bytes/mode')
            found[key]=body
    need(set(found)==set(lock['files']),'complete Source membership')
    return pin(raw),found


def command_index(rows,output,reads,resources,log_root=None,argv_cap=128):
    need(type(rows) is list and 0<len(rows)<=resources['command_rows']<=512,'finite complete command index')
    result={};total=0.0
    for i,row in enumerate(rows):
        step=row.get('step');need(type(step) is str and re.fullmatch('[A-Za-z0-9._+-]{1,96}',step) and step not in result,'unique command step')
        need(set(row)=={'step','argv','cwd','expected','success','log','log_pin','supervision','channels'} and
             row['log']=='%03d-%s.log'%(i,step) and row['channels']=='stdout+stderr combined in pipe order','exact owned Commands receipt')
        need(type(row['argv']) is list and 0<len(row['argv'])<=argv_cap and all(type(a) is str and len(a)<=16384 and '\0' not in a for a in row['argv']) and
             Path(row['argv'][0]).is_absolute() and Path(row['cwd']).is_absolute(),'literal finite command argv/cwd')
        s=row['supervision'];need(type(s) is dict and row['success'] is True and type(row['expected']) is int and row['expected']==0 and
            s.get('reaped') is True and s.get('ownership')=='REAPED' and s.get('group_census')=='EMPTY_TWICE' and
            s.get('output_complete') is True and s.get('timeout') is False and s.get('signals')==[] and
            s.get('error') is None and s.get('passed',True) is True and not any(s.get(k) for k in ('forced_cleanup','ownership_lost','emergency_retirement')) and type(s.get('exit')) is int and s['exit']==0,'natural complete zero-exit command')
        seconds=s.get('seconds');need(type(seconds) in (int,float) and math.isfinite(seconds) and 0<=seconds<resources['build_seconds'],'finite command duration')
        total+=seconds;raw=reads.read((output/'commands' if log_root is None else log_root)/row['log'],1024**2)
        need(pin(raw)==row['log_pin'],'complete original command log pin');result[step]=(i,row,raw)
    need(total<resources['total_seconds'],'finite aggregate owned operation')
    return result



def labels(ad):
    return {LABEL:token_for(ad),LABEL+'.operation':OP,LABEL+'.stage':ad['stage'],LABEL+'.source':ad['binding']['source']}


def source_program(source,files,ad,reads):
    prefix=FAMILY+'/successor_v3';program=decode(files[prefix+'/owner-program.json']);closure=decode(files['provenance/owner-closure.json'])
    need(program['schema']==1 and program['kind']=='CURRENT_ONBOARDING_COMMITTED_OWNER_PROGRAM_V3' and program['operation']==OP and
         program['api']==API and program['entrypoint']=='open_current_session' and program['closure']==CODE and
         all(v is None for v in program['actual'].values()),'complete unissued committed owner program')
    need(closure['schema']==1 and closure['kind']=='CURRENT_ONBOARDING_COMMITTED_OWNER_ROUTE_CLOSURE_V3' and closure['api']==API and
         closure['operation']==OP and closure['owner']==OWNER and closure['route']==ROUTE and closure['files']==CODE and
         closure['commit']==program['closure_commit'] and re.fullmatch('[0-9a-f]{40}',closure['commit']),'whole externally carried committed owner closure')
    for name,row in CODE.items():
        need(pin(files[name])=={k:row[k] for k in ('bytes','sha256')} and stat.S_IMODE((source/name).lstat().st_mode)==row['mode'],'known whole owner/route/runtime code DATA and mode')
    need(program['owner']==dict(path=OWNER,**pin(files[OWNER])) and program['route']==dict(path=ROUTE,**pin(files[ROUTE])) and
         ad['owner']['api']==API and ad['owner']['code']==dict(path=str(source/OWNER),**pin(files[OWNER])), 'same admitted maintained owner API/code')
    registry=decode(files[prefix+'/operation-registry.json']);entry=registry['operations'][OP]
    need(registry['schema']==3 and registry['actual_Root_admission'] is None and set(registry['operations'])=={OP} and
         entry['api']==API and entry['owner']==program['owner'] and entry['route']==program['route'] and entry['entry']==program['registry'] and
         program['registry']==dict(path=prefix+'/dispatch.py',**pin(files[prefix+'/dispatch.py'])), 'current closed operation registry')
    for stage,count in COUNTS.items():
        raw=files['inputs/stages/'+stage+'.expected.lock'];row=program['expected_inventories'][stage]
        need(row==dict(packages=count,**pin(raw)) and len(inventory(raw))==count,'all typed source inventory declarations')
    need(files['inputs/stages/'+ad['stage']+'.expected.lock']==reads.reference(ad['images'][ad['stage']]['inventory_pin']), 'actual stage qualification joins typed Source lock')
    return dict(commit=closure['commit'],code_files=len(CODE))


def container(row,intent,ad):
    need(row['Name']=='/'+intent['name'] and re.fullmatch('[0-9a-f]{64}',row['Id']) and row['Image']==ad['images'][ad['stage']]['id']==intent['image'], 'same exact owned CID/name/image')
    c,h=row['Config'],row['HostConfig']
    need(c['User']==intent['user'] and c['Entrypoint']==intent['entrypoint'] and c['Cmd']==intent['cmd'] and
         all(c['Labels'].get(k)==v for k,v in labels(ad).items()), 'actual actor config/source/stage labels')
    need(h['NetworkMode']=='none' and h['ReadonlyRootfs'] is intent['readonly'] and h['Privileged'] is False and h['CapDrop']==['ALL'] and
         (h['CapAdd'] or [])==intent.get('capadd',[]) and h['SecurityOpt']==['no-new-privileges'] and not h.get('VolumesFrom') and
         h.get('Tmpfs',{})==intent.get('tmpfs',{}) and h.get('PidMode','')=='' and h.get('IpcMode','private')=='private' and h.get('UTSMode','')=='' and
         not h['Devices'] and not h['DeviceRequests'] and h['Memory']==h['MemorySwap']==4*1024**3 and h['NanoCpus']==4*10**9 and
         h['PidsLimit']==512 and h.get('Init') in (None,False) and not h.get('AutoRemove',False), 'actual exact finite owned namespace isolation')
    mounts=[]
    for m in row['Mounts']:
        if m['Type']=='tmpfs':need(m['Destination'] in intent.get('tmpfs',{}) and m['RW'] is True,'only declared private tmpfs');continue
        need(m['Type']=='bind','no image-induced/foreign volume');mounts.append((m['Destination'],m['Source'],m['RW']))
    need(sorted(mounts)==sorted(tuple(v) for v in intent['mounts']),'actual exact inspected mount set')
    return row['Id']


def observed_daemon(index,ad):
    _,row,raw=index['native-daemon'];need(row['argv']==DOCKER+['info','--format','{{json .}}'],'exact selected daemon endpoint')
    info=decode(raw);need(info['OSType']=='linux' and info['Architecture'] in ('arm64','aarch64') and info['CgroupVersion']=='2' and
         all(info[k] is True for k in ('MemoryLimit','SwapLimit','CpuCfsQuota','PidsLimit')) and
         not any('rootless' in x or 'userns' in x for x in info['SecurityOptions']), 'actual native rootful cgroup-v2 enforcement observation')
    _,row,raw=index['fresh-owner-label'];need(row['argv']==DOCKER+['ps','-aq','--filter','label='+LABEL+'='+token_for(ad)] and not raw.strip(),'actual fresh stage namespace')


def retirement(index,prefix,intent,ad,receipt,created,terminal):
    cid=container(created,intent,ad);need(container(terminal,intent,ad)==cid,'same actor before/after attach')
    need(terminal['State']['Running'] is False and type(terminal['State']['ExitCode']) is int and terminal['State']['ExitCode']==0 and
         terminal['State']['OOMKilled'] is False,'natural successful container exit')
    expected={'create':intent['create_argv'],'inspect-created':DOCKER+['container','inspect',cid],
        'start-attached':DOCKER+['container','start','--attach',cid], 'inspect-terminal':DOCKER+['container','inspect',cid],
        prefix+'-query':DOCKER+['container','ls','--all','--no-trunc','--filter','name=^/'+intent['name']+'$','--format','{{.ID}} {{.Names}}'],
        prefix+'-inspect':DOCKER+['container','inspect',intent['name']], prefix+'-remove':DOCKER+['container','rm','--force',cid],
        prefix+'-after':DOCKER+['container','ls','--all','--no-trunc','--filter','name=^/'+intent['name']+'$','--format','{{.ID}} {{.Names}}']}
    for step,argv in expected.items():need(index[step][1]['argv']==argv,'exact observed owned actor command '+step)
    need(index['create'][2].decode().strip()==cid and decode(index['inspect-created'][2])==[created] and decode(index['inspect-terminal'][2])==[terminal], 'raw created/terminal receipt bodies')
    need(receipt['status']=='REMOVED_AND_ABSENT' and receipt['cid']==cid and receipt['name']==intent['name'] and
         container(receipt['inspection'],intent,ad)==cid and decode(index[prefix+'-inspect'][2])==[receipt['inspection']] and
         index[prefix+'-query'][2].decode().strip()==cid+' '+intent['name'] and index[prefix+'-remove'][2].decode().strip()==cid and
         not index[prefix+'-after'][2].strip(), 'raw exact-CID removal and successful absence observations')
    steps=list(expected);need([index[k][0] for k in steps]==sorted(index[k][0] for k in steps), 'natural create/inspect/attach/terminal/remove/absence order')


def token_for(ad):return hashlib.sha256(encoded(dict(binding=ad['binding'],selector=ad['selector'],stage=ad['stage']))).hexdigest()[:24]


def references(value):
    if type(value) is dict:
        if set(value)=={'path','bytes','sha256'}:yield value
        else:
            for item in value.values():yield from references(item)
    elif type(value) is list:
        for item in value:yield from references(item)


def outer_lifecycle(output,source,inputs,ad,report,reads):
    receipt=report['outer_retirement'];root=output/'outer-owner'
    need(receipt==decode(reads.read(root/'receipt.final.json',4*1024**2)) and receipt['status']=='PASS_OWNED_CURRENT_LIFECYCLE_RETIREMENT' and
         receipt['operation']==OP and receipt['stage']=='lifecycle' and receipt['binding']==ad['binding'] and not receipt.get('failure') and not receipt.get('retirement_error'), 'actual retained successful outer lifecycle receipt')
    local=decode(reads.read(output/'owner-local.json',65536));need(local['operation']==OP and local['stage']=='lifecycle' and local['binding']==ad['binding'] and
         local['status']=='PASS_LOCAL_STAGE_PENDING_OUTER_RETIREMENT' and local['body_success'] is True and local['protected_state_unchanged'] is True and local['failures']==[], 'genuine local result pending outer retirement')
    private=local['private_retirement'];need(private['homes_retired'] is True and private['no_sockets'] is True and private['private_directory_absent'] is True and
         private['registered']==private['retired']==2 and private['failures']==[], 'all actual private TEST homes retired')
    intent=receipt['intent'];need(intent==decode(reads.read(root/'intent.json',65536)), 'retained original lifecycle intent')
    owner=ad['owner'];manifest_path=Path(owner['launch_manifest']);state=manifest_path.parent
    need(manifest_path.name=='inside.json' and state.parent==Path('/tmp') and re.fullmatch('current-onboarding-owner-[A-Za-z0-9_-]{8,64}',state.name) and
         owner['lifecycle_capabilities']==CAPABILITIES and owner['input_references']==list(references(inputs)), 'exact Root launch/carrier policy')
    code=receipt['code_refs'];destinations=[str(source/name) for name in CODE];need(set(code)=={*destinations,str(manifest_path)},'closed executable carrier')
    mounts={str(source):(str(source),False),str(output.parent):(str(output.parent),True), owner['admission_path']:(owner['admission_path'],False),owner['inputs']['path']:(owner['inputs']['path'],False)}
    def add(dst,src,rw=False):
        need(type(dst) is str and type(src) is str and all(Path(v).is_absolute() and '..' not in Path(v).parts and ',' not in v and '\n' not in v for v in (dst,src)), 'literal lifecycle mount')
        need(dst not in mounts or mounts[dst]==(src,rw),'consistent unique lifecycle mount');mounts[dst]=(src,rw)
    for row in references(ad):add(row['path'],row['path'])
    for i,name in enumerate(CODE):
        dst=str(source/name);row=code[dst];body=reads.read(root/('code-'+str(i)),128*1024)
        need(row==dict(path=str(state/('code-'+str(i))),**pin(body)) and pin(body)=={k:CODE[name][k] for k in ('bytes','sha256')}, 'retained whole maintained executable carrier')
        mounts.pop(dst,None);add(dst,row['path'])
    manifest_raw=reads.read(root/'inside.json',1024**2);manifest=decode(manifest_raw)
    need(code[str(manifest_path)]==dict(path=str(manifest_path),**pin(manifest_raw)) and manifest['admission']==dict(path=owner['admission_path'],**pin(reads.read(owner['admission_path'],4*1024**2))) and
         manifest['inputs']==owner['inputs'] and manifest['grant_sha256']==pin(encoded(ad))['sha256'] and type(manifest['host_uid']) is int and manifest['host_uid']>0 and
         type(manifest['host_gid']) is int and manifest['host_gid']>=0 and type(manifest['deadline']) in (int,float) and math.isfinite(manifest['deadline']), 'actual bound inner manifest without reading vanished actor paths')
    mounts.pop(str(manifest_path),None);add(str(manifest_path),str(manifest_path))
    for row in ad['signed'].values():
        for field in ('archive','signature'):add(row[field],row[field])
    for row in owner['input_references']:add(row['path'],row['path'])
    need(len(mounts)<=128,'finite mount closure')
    for dst,(src,rw) in mounts.items():
        need(not (Path(dst).is_relative_to(output.parent) and dst!=str(output.parent)) and not (Path(src).is_relative_to(output.parent) and dst!=str(output.parent)) and
             dst not in ('/','/proc','/sys','/dev','/var/run/docker.sock','/run/docker.sock') and
             not any(Path(dst).is_relative_to(p) for p in ('/etc','/var/lib/pacman','/root','/home/alarm')), 'no writable code alias/protected host state/socket')
    name='cachy-asahi-current-'+token_for(ad)+'-lifecycle';image=ad['images']['lifecycle']['id']
    cmd=['-c','/usr/bin/python3 -I -B "$@"; status=$?; exit "$status"','current-onboarding',owner['code']['path'],'--inside-lifecycle',str(manifest_path)]
    argv=DOCKER+['create','--name',name,'--pull=never','--platform','linux/arm64','--user','0:0','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--pids-limit','512','--memory','4g','--memory-swap=4g','--cpus','4','--network','none','--init=false']
    for capability in CAPABILITIES:argv+=['--cap-add',capability]
    for key,value in labels(ad).items():argv+=['--label',key+'='+value]
    for dst,(src,rw) in sorted(mounts.items()):argv+=['--mount','type=bind,src='+src+',dst='+dst+('' if rw else ',readonly')]
    argv+=['--entrypoint','/bin/bash',image,*cmd]
    expected=dict(name=name,image=image,user='0:0',mounts=[[d,s,rw] for d,(s,rw) in sorted(mounts.items())],entrypoint=['/bin/bash'],cmd=cmd,
                  labels=labels(ad),readonly=False,capadd=CAPABILITIES,tmpfs={},create_argv=argv)
    need(intent==expected,'independently reconstructed exact Bash PID1/native child launch')
    index=admin_index(output,'outer-owner/commands',ad,reads,argv_cap=512)
    need(receipt['commands']==[v[1] for v in index.values()], 'complete outer original command stream')
    need(list(index)==['fresh-owner-label','native-daemon','fresh-name','create','inspect-created','start-attached','inspect-terminal',
                      'retire-query','retire-inspect','retire-remove','retire-after'], 'exact outer lifecycle command order')
    observed_daemon(index,ad);need(not index['fresh-name'][2].strip() and index['fresh-name'][1]['argv']==DOCKER+['container','ls','--all','--no-trunc','--filter','name=^/'+name+'$','--format','{{.ID}} {{.Names}}'],'fresh actual lifecycle name')
    retirement(index,'retire',intent,ad,receipt['retirement'],receipt['created'],receipt['terminal'])
    return dict(actual_owned_cid=receipt['created']['Id'],natural_retirement=True,retained_absence_observation=True,private_homes=2)


def check(output,source,profile,inputs,admission,binding,*,_dependency=False,_reads=None,_source_data=None):
    """Check one externally pinned Root stage; paths select retained DATA only."""
    need(type(binding) is dict and binding.get('issuer')=='Root' and binding.get('approved') is True and
         binding.get('operation')==OP and binding.get('stage') in STAGES and binding.get('Root_acceptance') is None,'unissued matching Reader binding')
    need(not _dependency or binding['stage'] in ('backend','ui'),'only finite prior build stages may be dependency Readers')
    reads=Reads() if _reads is None else _reads;output=absolute(output);source=absolute(source)
    need(binding['output']==str(output),'exact bound output')
    for key,path in (('profile',profile),('inputs',inputs),('admission',admission)):
        need(binding[key]['path']==str(absolute(path)),'exact external input path')
    p=decode(reads.reference(binding['profile']));need(pin(encoded(p))==PROFILE_PIN,'whole maintained current profile')
    inp=decode(reads.reference(binding['inputs']));ad=decode(reads.reference(binding['admission']))
    need(binding['reader']['path']==str(Path(__file__).resolve()) and pin(reads.reference(binding['reader']))==pin(Path(__file__).read_bytes()),'exact matching Reader code')
    lock,files=source_tree(source,reads) if _source_data is None else _source_data
    need(binding['source_lock']==dict(path=str(source/'source.lock.json'),**lock),'external Source lock')
    stage=binding['stage'];actual=ad['binding']
    need(ad['source_root']==str(source) and ad['output']==str(output),'exact Root-bound current source/output operands')
    need(ad.get('schema')==1 and ad.get('issuer')=='Root' and ad.get('approved') is True and ad.get('operation')==OP and ad.get('stage')==stage and
         ad['profile_pin']==pin(encoded(p)) and ad['inputs_pin']==pin(encoded(inp)) and actual['source_lock']==lock and inp['source']==actual,'same Root Source/profile/inputs admission')
    need(set(actual)=={'source','ref','run','job','attempt','source_lock'} and re.fullmatch('[0-9a-f]{40}',actual['source']) and
         re.fullmatch('refs/heads/codex/[A-Za-z0-9._/-]+',actual['ref']) and all(type(actual[k]) is str and re.fullmatch('[1-9][0-9]*',actual[k]) for k in ('run','job')) and
         type(actual['attempt']) is int and actual['attempt']==1,'complete actual Source/run/job/attempt binding')
    need(inp['Root_admission']==ad['selector'] and inp['matching_Reader']==ad['matching_Reader'] and ad['matching_Reader']['selector'] and
         ad['matching_Reader']['operation']==OP and ad['matching_Reader']['sha256']==binding['reader']['sha256'],'new matching Reader/owner selectors')
    cap=ad['resources'];need(cap==inp['Root_capacity'] and all(type(cap.get(k)) is int for k in ('build_seconds','builder_cpus','builder_memory_bytes','builder_pids','total_seconds','command_rows')) and 2<=cap['build_seconds']<=180 and
         cap['builder_cpus']==4 and cap['builder_memory_bytes']==4*1024**3 and cap['builder_pids']==512 and
         type(cap['total_seconds']) is int and 2<=cap['total_seconds']<=1800 and type(cap['command_rows']) is int and 1<=cap['command_rows']<=512,'exact admitted finite resources')
    start,end=ad['issued_at_unix'],ad['expires_at_unix'];need(all(type(v) in (int,float) and math.isfinite(v) for v in (start,end)) and start<=end<=start+300,'historical admission validity window')
    need(p['operation']==OP and set(p['packages'])==set(KINDS) and all(p['packages'][k]['name']==v[0] and p['packages'][k]['version']==v[1] and len(p['packages'][k]['payload_files'])==n for k,v,n in ((k,VERSIONS[k],n) for k,n in zip(KINDS,(16,6,8)))),'exact current package identities/payload counts')
    for kind,recipe in p['packages'].items():
        for name,row in recipe['files'].items():need(pin(files[recipe['path']+'/'+name])=={k:row[k] for k in ('bytes','sha256')},'recipe Source binding')
    for name,row in p['helpers'].items():need(pin(files[name])=={k:row[k] for k in ('bytes','sha256')},'maintained helper Source pin')
    for name,row in p['prior_factory'].items():need(pin(files[FAMILY+'/'+name])=={k:row[k] for k in ('bytes','sha256')},'held Source constructor pin')
    need(files[FAMILY+'/successor_v2/profile.json']==encoded(p),'profile in closed Source')
    image=ad['images'][stage];packages=image['packages'];need(re.fullmatch('sha256:[0-9a-f]{64}',image['id']) and len(packages)==COUNTS[stage] and
         reads.reference(image['inventory_pin'])==inventory_bytes(packages),'complete qualified stage inventory')
    qualification=decode(reads.reference(image['Root_qualification']))
    reads.reference(ad['runtime'])
    need(binding.get('runtime')==ad['runtime'] and qualification['runtime']==ad['runtime'],'same separately Root-bound whole runtime input')
    need(qualification['issuer']=='Root' and qualification['status']=='ROOT_REVIEWED_CURRENT_ONBOARDING_IMAGE_V2' and
         qualification['operation']==OP and qualification['stage']==stage and qualification['binding']==actual and qualification['image']==image['id'] and
         qualification['inventory_pin']==image['inventory_pin'] and qualification['observed_architecture']=='aarch64' and
         qualification['owned_runner'] is True and qualification['image_build_policy_admitted'] is True and
         inp['image_namespace_qualification']==image['Root_qualification'],'independently retained actual native image/owner proof')
    project={'cachy-asahi-setup':'0.3.0-1',**{name:version for name,version in VERSIONS.values()}}
    wanted={'cachy-asahi-setup'} if stage=='backend' else {'cachy-asahi-setup','cachy-asahi-first-login'} if stage=='ui' else set()
    need(set(packages)&set(project)==wanted and all(packages[n]==project[n] for n in wanted),'exact dependency/project-free stage')
    program=source_program(source,files,ad,reads)
    need(ad['owner']['inputs']==binding['inputs'] and type(inp['source_date_epoch']) is int and inp['source_date_epoch']>=0 and
         type(ad['source_date_epoch']) is int and ad['source_date_epoch']==inp['source_date_epoch'],'same owner input file/epoch')
    signature_inputs(inp['setup8'],p['setup8'],ad,reads)
    if stage=='ui':
        backend=inp['first_login_backend'];pair=decode(reads.reference(backend['native_pair']))
        need(pair['issuer']=='Root' and pair['status']=='ROOT_REVIEWED_CURRENT_FIRST_LOGIN_PAIR_V2' and pair['binding']==actual and
             pair['name']=='cachy-asahi-first-login' and pair['version']=='0.1.0-3' and pair['archive']==pin(reads.reference(backend['archive'])),'fresh current CLI03 native pair input')
        signature_inputs(backend,None,ad,reads)
    if stage in ('ui','lifecycle'):
        official=inp['official_ui_dependencies'];proof=decode(reads.reference(official['verification']))
        need(official['required']==['gtk4','python-gobject'] and {'gtk4','python-gobject'}<=set(packages) and
             proof['issuer']=='Root' and proof['status']=='ROOT_REVIEWED_OFFICIAL_ONBOARDING_CLOSURE_V2' and
             proof['catalog']==pin(reads.reference(official['exact_closure'])) and proof['archive_signature_inputs']==pin(reads.reference(official['archive_signature_inputs'])) and
             (proof['base_packages'],proof['selected_packages'],proof['qualified_packages'])==(349,23,372),'exact independently verified official closure input')
    report=decode(reads.read(output/'route.json',4*1024**2))
    need(report['schema']==1 and report['operation']==OP and report['stage']==stage and report['status']=='PASS_CURRENT_ONBOARDING_OWNED_STAGE_DATA_ONLY' and
         report['binding']==actual and report['profile_pin']==ad['profile_pin'] and report['inputs_pin']==ad['inputs_pin'] and report['source_lock']==lock and
         report.get('Root_acceptance') is None and report.get('native16K')=='UNQUALIFIED' and report.get('M2')=='NOT_RUN' and report.get('performance')=='NOT_MEASURED' and report.get('release')=='NOT_ADMITTED' and not report.get('failure'),'complete successful same-stage route report')
    facts=report['owner_facts'];need(facts['operation']==OP and facts['stage']==stage and facts['binding']==actual and facts['image']==image['id'] and
         facts['architecture']=='aarch64' and type(facts['page_size']) is int and facts['page_size'] in (4096,16384),'same actual owner facts')
    need(report['owner_cleanup']==dict(status='PASS_OWNED_CURRENT_STAGE_RETIREMENT',operation=OP,stage=stage,binding=actual,natural_retirement=True,
         owned_container_absence_verified=True,protected_state_unchanged=True),'complete owner cleanup/retirement')
    verification=stage_verification(output,inp,ad,report,reads,stage)
    commands=command_index(report['commands'],output,reads,cap)
    if stage in ('backend','ui'):
        verdict=builds(output,source,p,inp,image,report,commands,reads,stage)
        verdict['owner_retirement']=build_retirement(output,source,inp,ad,report,commands,reads,stage)
    else:
        verdict=lifecycle(output,p,inp,ad,report,commands,reads,packages)
        verdict['outer_retirement']=outer_lifecycle(output,source,inp,ad,report,reads)
        verdict['native_pairs']=prior_pairs(source,binding,report,reads,(lock,files))
    return dict(status='PASS_CURRENT_ONBOARDING_RETAINED_STAGE_DATA_ONLY',operation=OP,stage=stage,binding=actual,verified=verdict,
        command_rows=len(commands),owner_program=program,stage_verification=verification,Root_authentication=False,Root_acceptance=None,native16K='UNQUALIFIED',GUI='NOT_RUN',M2='NOT_RUN',performance='NOT_MEASURED',release='NOT_ADMITTED',
        limitations=['Root authenticates the external admission/proofs and their historical freshness; no fresh signature/actor operation occurs here',
                     'Dependency BUILDINFO architecture suffixes are syntax-checked; the admitted package map independently binds names/versions',
                     'A stage result is not a combined native-ready/GUI/hardware/release acceptance'])


def prior_pairs(source,binding,report,reads,source_data):
    """Independently read both completed build stages only at lifecycle time."""
    selected=binding['build_stage_bindings'];need(type(selected) is dict and set(selected)=={'backend','ui'}, 'lifecycle requires actual backend/UI Reader bindings after their builds')
    found={}
    for stage,kinds in (('backend',('enrollment','first-login')),('ui',('ui',))):
        previous=decode(reads.reference(selected[stage],65536))
        need(previous.get('stage')==stage and previous.get('operation')==OP,'exact prior build stage, no recursive lifecycle dependency')
        result=check(Path(previous['output']),source,Path(previous['profile']['path']),Path(previous['inputs']['path']),Path(previous['admission']['path']),previous,
            _dependency=True,_reads=reads,_source_data=source_data)
        need(result['binding']==report['binding'],'same Source/run/job/attempt for every prior actual pair')
        for kind in kinds:
            observed=result['verified'][kind]['archive'];need(observed==report['signed'][kind]['archive_pin'], 'lifecycle signed archive is the independently checked actual pair: '+kind)
            found[kind]=observed
    return found


def signature_inputs(value,recipe,ad,reads):
    archive=pin(reads.reference(value['archive']));signature=pin(reads.reference(value['signature']))
    selected=value['current_TEST_signature_verification']
    need(type(selected) is dict and set(selected)=={'Root_decision','Root_verification'},'explicit retained Root signature decision/proof')
    decision=decode(reads.reference(selected['Root_decision']));proof_raw=reads.reference(selected['Root_verification']);proof=decode(proof_raw)
    package=decision['archive'];project={'cachy-asahi-setup':'0.3.0-1',**dict(VERSIONS.values())}
    need(decision['schema']==1 and decision['issuer']=='Root' and decision['accepted'] is True and decision['holds_preserved'] is True and
         decision['trust_scope']=='TEST_ONLY' and package['package'] in project and package['version']==project[package['package']] and package['arch']=='any' and
         decision['status']==('ACCEPTED_PRIVATE_SETUP8_PACKAGE_TEST_ONLY' if package['package']=='cachy-asahi-setup' else 'ACCEPTED_PRIVATE_CURRENT_ONBOARDING_PACKAGE_TEST_ONLY'),
         'package-specific actual Root TEST decision')
    need({k:package[k] for k in ('bytes','sha256')}==archive and decision['signature']==signature and
         decision['signature_file']==value['signature']['path'] and decision['verification_proof_sha256']==pin(proof_raw)['sha256'], 'Root decision exact body/signature/proof')
    key=decision['public_test_key'];fingerprint=key['fingerprint']
    need(proof['schema']==1 and proof['Root_issuer']=='Root' and proof['status']=='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE' and proof['verified'] is True and
         proof['trust_scope']=='TEST_ONLY' and proof['archive']==archive and proof['signature']==signature and proof['public_test_key']==key and
         key['trust_scope']=='TEST_ONLY' and re.fullmatch('[0-9A-F]{40}',fingerprint or ''),'same public Root TEST verification')
    public_key=dict(path=decision['public_test_key_file'],**{k:key[k] for k in ('bytes','sha256')});reads.reference(public_key,65536)
    verified=datetime.datetime.fromisoformat(proof['actual_verified_utc']);issued=datetime.datetime.fromisoformat(decision['issued_at'])
    need(verified.tzinfo is not None and issued.tzinfo is not None and verified.timestamp()<=issued.timestamp()<=ad['issued_at_unix'],
         'historical Root proof precedes this admission; no invented current Root observation')
    need(ad['owner']['test_fingerprint']==fingerprint and ad['owner']['test_public_key']==public_key,'independently admitted public TEST policy')
    if recipe is not None:need(archive==recipe['archive_pin'],'authentic accepted Setup8 archive')
    return dict(kind='ROOT_RETAINED_TEST_SIGNATURE_DECISION',archive=value['archive'],signature=value['signature'],public_key=public_key,
                fingerprint=fingerprint,package=package['package'],Root_decision=selected['Root_decision'],Root_verification=selected['Root_verification'],trust_scope='TEST_ONLY')


def admin_index(output,directory,ad,reads,argv_cap=128):
    root=output/directory;rows=decode(reads.read(root/'commands.json',4*1024**2))
    cap=dict(ad['resources']);cap['build_seconds']=max(30,cap['build_seconds']);cap['total_seconds']=min(600,cap['total_seconds'])
    return command_index(rows,output,reads,cap,log_root=root,argv_cap=argv_cap)


def stage_verification(output,inputs,ad,report,reads,stage):
    receipt=report['stage_signature_verification'];binding=ad['binding']
    need(receipt['status']=='PASS_OWNED_CURRENT_STAGE_TEST_VERIFICATION' and receipt['operation']==OP and receipt['stage']==stage and
         receipt['binding']==binding and receipt['scope']=='DELEGATED_CURRENT_OWNER_GPG_NOT_ROOT_OBSERVATION','delegated owner verification scope')
    admin=admin_index(output,'owner-admin/commands' if stage=='lifecycle' else 'owner-state/admission',ad,reads)
    keys=('setup8','first_login_backend') if stage=='ui' else ('setup8',)
    need(set(receipt['verified'])==set(keys),'exact stage signature inputs')
    home=None;last=-1
    for key in keys:
        selected=signature_inputs(inputs[key],None,ad,reads)
        need(selected['package']==('cachy-asahi-setup' if key=='setup8' else 'cachy-asahi-first-login'),'Root decision names this exact stage dependency')
        row=receipt['verified'][key];step='owner-current-signature-'+key
        index,command,raw=admin[step];argv=command['argv'];trust=Path(argv[2])
        need(trust.is_absolute() and trust.name=='trust' and trust.parent.parent==Path('/tmp') and
             re.fullmatch('build-tools-test-[A-Za-z0-9_+-]+',trust.parent.name),'private current trust path')
        need(home is None or home==trust,'one TEST trust home');home=trust
        verifier=['/usr/bin/gpg','--homedir',str(trust),'--batch','--no-auto-key-retrieve','--auto-key-locate','clear']
        need(argv==verifier+['--status-fd=1','--verify',selected['signature']['path'],selected['archive']['path']] and row['command']==command and
             row['archive']=={k:selected['archive'][k] for k in ('bytes','sha256')} and row['signature']=={k:selected['signature'][k] for k in ('bytes','sha256')} and
             row['public_test_key']=={k:selected['public_key'][k] for k in ('bytes','sha256')} and row['fingerprint']==selected['fingerprint'] and
             row['status_text'].encode()==raw and index>last,'actual original stage GPG receipt/log/body/order')
        strict_signature(raw,selected['fingerprint']);last=index
    verifier=['/usr/bin/gpg','--homedir',str(home),'--batch','--no-auto-key-retrieve','--auto-key-locate','clear'];work=home.parent
    imported,_,_=admin['import-root-test-public'];primary,_,listing=admin['current-primary'];trusted,_,_=admin['trust-current-test-primary']
    need(admin['import-root-test-public'][1]['argv']==verifier+['--import',str(work/'public.asc')] and
         admin['current-primary'][1]['argv']==verifier+['--with-colons','--list-keys'] and
         admin['trust-current-test-primary'][1]['argv']==verifier+['--import-ownertrust',str(work/'ownertrust')] and
         imported<primary<trusted<admin['owner-current-signature-'+keys[0]][0],'explicit isolated trust prepared before current signature checks')
    fingerprints=[line.split(':')[9] for line in listing.decode().splitlines() if line.startswith('fpr:')]
    need(fingerprints==[ad['owner']['test_fingerprint']],'only exact admitted current TEST primary')
    for i,path in enumerate((home,work/'home')):
        kill,kr,_=admin['retire-private-'+str(i)];absent,ar,raw=admin['no-agent-private-'+str(i)]
        need(kr['argv']==['/usr/bin/gpgconf','--homedir',str(path),'--kill','all'] and
             ar['argv']==['/usr/bin/gpg-connect-agent','--homedir',str(path),'--no-autostart','/bye'] and
             raw==b'gpg-connect-agent: no gpg-agent running in this session\n' and last<kill<absent,'actual private TEST home retirement receipts')
        last=absent
    common=['import-root-test-public','current-primary','trust-current-test-primary']
    if stage=='lifecycle':common+=['baseline-inventory','before-e','before-d']
    wanted=common+['owner-current-signature-'+key for key in keys]
    if stage=='lifecycle':wanted+=['restored-inventory','after-e','after-d']
    wanted+=['retire-private-0','no-agent-private-0','retire-private-1','no-agent-private-1']
    if stage!='lifecycle':wanted=['fresh-owner-label','native-daemon']+wanted
    need(list(admin)==wanted,'complete exact owner administrative stream')
    if stage=='lifecycle':
        base=reads.reference(ad['images']['lifecycle']['inventory_pin'])
        for step in ('baseline-inventory','restored-inventory'):
            need(admin[step][1]['argv']==['/usr/bin/pacman','-Q'] and b''.join(sorted(admin[step][2].splitlines(keepends=True)))==base,
                 'same actual restored project-free372 inventory')
        for flag in ('e','d'):
            before=admin['before-'+flag];after=admin['after-'+flag]
            need(before[1]['argv']==after[1]['argv']==['/usr/bin/pacman','-Qq'+flag] and before[2]==after[2], 'preserved actual ALPM installation reasons')
    return dict(fingerprint=ad['owner']['test_fingerprint'],verified_inputs=list(keys),private_homes=2,trust_home=str(home),command_rows=len(admin))


def build_retirement(output,source,inputs,ad,report,commands,reads,stage):
    root=output/'owner-state';token=token_for(ad);expected={};results={}
    kinds=('ui',) if stage=='ui' else ('enrollment','first-login')
    for kind in kinds:
        for label in ('a','b'):
            slot=output/'builds'/(kind+'-'+label);provenance=decode(reads.read(slot/'provenance.json',1024**2));declared=provenance['command'];name=provenance['clean_environment_id']
            target=root/'intents'/(name+'.json');intent=decode(reads.read(target,65536));result=decode(reads.read(target.with_suffix('.result'),1024**2))
            labels={LABEL:token,LABEL+'.operation':OP,LABEL+'.stage':stage,LABEL+'.source':ad['binding']['source']}
            create=DOCKER+['create',*declared[3:-4],'--memory-swap=4g']
            for key,value in labels.items():create+=['--label',key+'='+value]
            create+=declared[-4:]
            mounts=[['/inputs',str(slot/'inputs'),False],['/out',str(slot/'artifacts'),True],
                ['/builder-entry.sh',str(source/'scripts/build/container-entry.sh'),False],['/expected-packages.lock',str(slot/'expected-packages.lock'),False]]
            exact=dict(name=name,image=ad['images'][stage]['id'],user=declared[declared.index('--user')+1],mounts=mounts,entrypoint=['/bin/bash'],cmd=['/builder-entry.sh'],
                labels=labels,readonly=True,create_argv=create,declared_argv=declared,slot=str(slot),capadd=[],tmpfs={'/tmp':'rw,nosuid,nodev,exec,size=4g'})
            need(intent==exact and result['status']=='PASS_OWNED_GENERIC_BUILD_PROXY' and result['name']==name and
                 not result.get('failure') and not result.get('retirement_error'),'exact original generic intent and genuine proxy completion')
            expected[name]=intent;results[name]=result
    found={q.stem for q in (root/'intents').iterdir() if q.suffix=='.json'}
    need(found==set(expected) and {q.name for q in (root/'intents').iterdir()}=={n+suffix for n in expected for suffix in ('.json','.result')},'complete exact current generic intent/result namespace')
    observed=set();inspections=0;architectures=0
    directories=sorted(root.glob('proxy-*'));need(len(directories)==3*len(expected),'one image query, native query and actual container proxy per build')
    for directory in directories:
        need(directory.is_dir() and not directory.is_symlink() and re.fullmatch('proxy-[A-Za-z0-9_-]+',directory.name),'ordinary bounded proxy directory')
        index=admin_index(output,str(directory.relative_to(output)/'commands'),ad,reads)
        if list(index)==['image-inspect']:
            _,row,raw=index['image-inspect'];rows=decode(raw);image=ad['images'][stage]['id']
            need(row['argv']==DOCKER+['image','inspect',image] and type(rows) is list and len(rows)==1 and rows[0]['Id']==image and
                 rows[0]['Architecture']=='arm64' and rows[0]['Os']=='linux','actual exact selected native image inspection');inspections+=1
        elif list(index)==['native-architecture']:
            _,row,raw=index['native-architecture'];need(row['argv']==DOCKER+['info','--format','{{.Architecture}}'] and raw.strip() in (b'arm64',b'aarch64'),'actual native daemon query');architectures+=1
        else:
            need(list(index)==['fresh-name','create','inspect-created','start-attached','inspect-terminal','proxy-final-query','proxy-final-inspect','proxy-final-remove','proxy-final-after'], 'complete exact native-build proxy stream')
            rows=decode(index['inspect-created'][2]);need(type(rows) is list and len(rows)==1,'one original created build actor')
            name=rows[0]['Name'][1:];need(name in expected and name not in observed,'one proxy per declared build identity');observed.add(name)
            intent=expected[name];result=results[name]
            need(rows[0]==result['created'] and not index['fresh-name'][2].strip() and index['fresh-name'][1]['argv']==DOCKER+['container','ls','--all','--no-trunc','--filter','name=^/'+name+'$','--format','{{.ID}} {{.Names}}'], 'actual fresh generic name')
            retirement(index,'proxy-final',intent,ad,result['retirement'],result['created'],result['terminal'])
    need(observed==set(expected) and inspections==architectures==len(expected),'all declared builds actually inspected, completed and retired')
    cleanup=decode(reads.read(root/'cleanup.json',65536));need(cleanup['stage']==stage and cleanup['binding']==ad['binding'] and cleanup['failures']==[] and
         cleanup['retired']==[dict(status='ABSENT',name=n) for n in sorted(expected)], 'owner rechecked exact completed generic identities')
    index=admin_index(output,'owner-state/retirement',ad,reads)
    need(list(index)==['retire-'+str(i)+'-query' for i in range(len(expected))]+['final-owner-label'],'complete final native build absence stream')
    for i,name in enumerate(sorted(expected)):
        _,row,raw=index['retire-'+str(i)+'-query'];need(not raw.strip() and row['argv']==DOCKER+['container','ls','--all','--no-trunc','--filter','name=^/'+name+'$','--format','{{.ID}} {{.Names}}'],'successful final exact-name absence query')
    _,row,raw=index['final-owner-label'];need(not raw.strip() and row['argv']==DOCKER+['ps','-aq','--filter','label='+LABEL+'='+token],'actual final owned namespace absence')
    admin=admin_index(output,'owner-state/admission',ad,reads);observed_daemon(admin,ad)
    manifest=decode(reads.read(root/'proxy.json',4*1024**2));need(manifest['grant']==ad and manifest['source']==str(source) and manifest['output']==str(output) and
         type(manifest['uid']) is int and type(manifest['gid']) is int and manifest['uid']>0 and manifest['gid']>0 and
         all(i['user']==str(manifest['uid'])+':'+str(manifest['gid']) for i in expected.values()) and
         type(manifest['deadline']) in (int,float) and math.isfinite(manifest['deadline']),'same Root-admitted proxy source/output/user/deadline')
    return dict(owned_build_containers=len(expected),actual_created_terminal_inspections=True,retained_exact_absence_queries=True,
        host_protected_state='OWNER_CHECKED_DECLARATION_NO_RAW_HOST_SNAPSHOTS_RETAINED')


def builds(output,source,p,inputs,image,report,commands,reads,stage):
    kinds=('ui',) if stage=='ui' else ('enrollment','first-login');expected_steps=[];clean=set();result={}
    inventory_ref=inputs['ui_builder_inventory' if stage=='ui' else 'builder_inventory']
    need(inputs['ui_builder_image' if stage=='ui' else 'builder_image']==image['id'] and inventory_ref['packages']==image['packages'] and
         {k:inventory_ref[k] for k in ('path','bytes','sha256')}==image['inventory_pin'],'exact builder operands')
    need(set(report['artifacts'])==set(kinds) and report['builds']['status']=='PASS_CURRENT_BUILD_PAIR_DATA_ONLY' and set(report['builds']['pairs'])==set(kinds),'complete current kind comparisons')
    for kind in kinds:
        recipe=p['packages'][kind];archives=[];parsed=[];provenances=[]
        for label in ('a','b'):
            step='current-'+kind+'-'+label;expected_steps.append(step);_,row,_=commands[step];directory=output/'builds'/(kind+'-'+label)
            expected=['/usr/bin/python3','-I','-B',str(source/'scripts/build/build.py'),str(source/recipe['path']),'--image',image['id'],'--output',str(directory),'--mode','native','--source-date-epoch',str(inputs['source_date_epoch']),'--network','none','--timeout',str(inputs['Root_capacity']['build_seconds']),'--expected-packages',image['inventory_pin']['path'],'--reviewed-inputs',str(source/'reviewed'/(kind+'.json'))]
            need(row['argv']==expected,'exact dependency/check-enabled generic builder argv')
            provenance=decode(reads.read(directory/'provenance.json',1024**2));provenances.append(provenance)
            need(provenance['status']=='built-package-static-pass' and provenance['mode']=='native' and provenance['network']=='none' and provenance['image']==provenance['image_id']==image['id'] and
                 provenance['builder_host_arch'] in ('aarch64','arm64') and provenance['source_date_epoch']==inputs['source_date_epoch'] and provenance['exit_code']==0 and
                 provenance['expected_packages_sha256']==image['inventory_pin']['sha256'],'actual builder provenance/image/inventory/epoch')
            identity=provenance['clean_environment_id'];need(type(identity) is str and re.fullmatch('cachy-asahi-[0-9a-f]{16}',identity) and identity not in clean,'six distinct clean build identities');clean.add(identity)
            command=provenance['command'];need(type(command) is list and '--user' in command,'retained generic builder Docker command')
            user=command[command.index('--user')+1];need(re.fullmatch('[1-9][0-9]*:[1-9][0-9]*',user),'ordinary builder user/group')
            expected_docker=['docker','run','--rm','--name',identity,'--pull=never','--platform','linux/arm64','--user',user,'--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--pids-limit','512','--memory','4g','--cpus','4','--network','none','--tmpfs','/tmp:rw,nosuid,nodev,exec,size=4g','--env','CACHY_ASAHI_CONTAINER=1','--env','SOURCE_DATE_EPOCH='+str(inputs['source_date_epoch']),'--mount','type=bind,src='+str(directory/'inputs')+',dst=/inputs,readonly','--mount','type=bind,src='+str(directory/'artifacts')+',dst=/out','--mount','type=bind,src='+str(source/'scripts/build/container-entry.sh')+',dst=/builder-entry.sh,readonly','--mount','type=bind,src='+str(directory/'expected-packages.lock')+',dst=/expected-packages.lock,readonly','--entrypoint','/bin/bash',image['id'],'/builder-entry.sh']
            need(command==expected_docker,'exact qualified builder Docker identity/security/resources/env/mounts')
            need(provenance['recipe_inputs']==decode(reads.read(source/'reviewed'/(kind+'.json'),1024**2)),'complete independently reviewed recipe input map')
            need({q.name for q in (directory/'inputs').iterdir()}==set(recipe['files']),'complete clean recipe snapshot namespace')
            for name,row in recipe['files'].items():need(pin(reads.read(directory/'inputs'/name))=={k:row[k] for k in ('bytes','sha256')},'whole clean recipe Source leaves')
            for name,sha in provenance['files'].items():relative(name);need(hashlib.sha256(reads.read(directory/name)).hexdigest()==sha,'every actual provenance output pin')
            need({'build.log','validation.json','expected-packages.lock','artifacts/packages.lock','artifacts/generated.SRCINFO','artifacts/environment.txt','artifacts/config.sha256','artifacts/makepkg.conf','artifacts/pacman.conf'}<=set(provenance['files']),'complete builder provenance files')
            need(reads.read(directory/'artifacts/packages.lock')==reads.reference(image['inventory_pin'])==reads.read(directory/'expected-packages.lock'),'actual builder complete inventory')
            check_log(reads.read(directory/'build.log',1024**2),kind,p)
            for name,sha in provenance['recipe_inputs'].items():relative(name);need(hashlib.sha256(reads.read(directory/'inputs'/name)).hexdigest()==sha and
                sha==recipe['files'][name]['sha256'],'actual clean recipe input/source snapshot')
            need(provenance['recipe_inputs']['PKGBUILD']==recipe['files']['PKGBUILD']['sha256'] and
                 provenance['entry_script_sha256']==hashlib.sha256(reads.read(source/'scripts/build/container-entry.sh')).hexdigest(),'builder entry and recipe pin')
            validation=decode(reads.read(directory/'validation.json',1024**2));need(validation['errors']==[],'complete builder validation pass')
            raw=reads.read(directory/'artifacts'/recipe['archive']);need(provenance['artifacts']=={recipe['archive']:pin(raw)['sha256']},'one exact compressed archive')
            archives.append(raw);parsed.append(package(raw,recipe,image['packages'],inputs['source_date_epoch']))
        step='current-'+kind+'-compare';expected_steps.append(step);_,row,raw=commands[step]
        need(row['argv']==['/usr/bin/python3','-I','-B',str(source/'scripts/build/compare.py'),str(output/'builds'/(kind+'-a')),str(output/'builds'/(kind+'-b')),'--require-bytes'],'exact pair comparison argv')
        comparison=decode(raw);need(comparison==report['builds']['pairs'][kind] and comparison['status']=='contents-reproduced' and comparison['errors']==[] and
            comparison['packages']=={recipe['archive']:dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)} and
            archives[0]==archives[1] and parsed[0]==parsed[1],'independent whole compressed/metadata/payload pair equality')
        for key in ('image','image_id','mode','source_date_epoch','recipe_inputs','recipe_metadata','expected_packages_sha256','entry_script_sha256'):
            need(provenances[0][key]==provenances[1][key],'same exact pair inputs')
        need(report['artifacts'][kind]==dict(a=pin(archives[0]),b=pin(archives[1])),'route compressed pair pins')
        result[kind]=dict(archive=pin(archives[0]),payload_files=len(recipe['payload_files']),distinct_recorded_clean_ids=True)
    need(list(commands)==expected_steps,'complete exact build/compare command order')
    return result


def lifecycle(output,p,inputs,ad,report,commands,reads,base):
    facts=report['owner_facts'];need(facts.get('execution_domain')=='OWNED_SIGNED_IMAGE_LOCAL','actual local signed-image domain')
    protected=report['protected_before']
    need(type(protected) is dict and set(protected)=={'alpm_db','alarm_home','root_home','global_trust','global_config','package_cache'} and
         protected==report['protected_after'],'all six protected-state restoration maps')
    for row in protected.values():
        need(type(row) is dict and set(row)=={'files','bytes','sha256'} and type(row['files']) is int and 0<=row['files']<=100000 and
             type(row['bytes']) is int and 0<=row['bytes']<=128*1024**2 and re.fullmatch('[0-9a-f]{64}',row['sha256'] or ''),'whole bounded protected-tree snapshot receipt')
    life=report['lifecycle'];need(life['status']=='PASS_CURRENT_THREE_SIGNED_ALPM_DATA_ONLY' and life['Root_acceptance'] is None and
        life['native16K']==life['GUI']==life['M2']=='NOT_RUN','exact lifecycle data scope')
    signed=report['signed'];need(signed==ad['signed'] and set(signed)=={'setup8',*KINDS},'four exact signed project inputs')
    used=set();last=-1
    def entry(step,argv=None):
        need(step in commands and step not in used,'required unique lifecycle command '+step);used.add(step)
        index,row,raw=commands[step]
        if argv is not None:need(row['argv']==argv,'exact lifecycle command '+step)
        return index,row,raw
    for key in ('setup8',*KINDS):
        recipe=p['setup8'] if key=='setup8' else p['packages'][key];row=signed[key]
        need((row['name'],row['version'])==(recipe['name'],recipe['version']) and row['payload_files']==recipe['payload_files'],'exact signed payload binding')
        need(pin(reads.read(output/'signed'/(key+'.archive')))==row['archive_pin'] and pin(reads.read(output/'signed'/(key+'.signature')))==row['signature_pin'],'whole signed archive/signature bytes')
        if key=='setup8':need(row['archive_pin']==recipe['archive_pin'],'authentic Setup8 lifecycle bytes')
        else:
            builder=inputs['ui_builder_inventory' if key=='ui' else 'builder_inventory'];need(reads.reference({k:builder[k] for k in ('path','bytes','sha256')})==inventory_bytes(builder['packages']) and len(builder['packages'])==(374 if key=='ui' else 350),'retained candidate build inventory')
            package(reads.read(output/'signed'/(key+'.archive')),recipe,builder['packages'],inputs['source_date_epoch'])
    baseline_index,_,raw=entry('current-baseline',['/usr/bin/pacman','-Q']);need(inventory(raw)==base,'actual project-free372 baseline')
    # The owner-created isolated config is visible in each real pacman argv.
    install=commands['current-install-setup8'][1]['argv'];need(install[:2]==['/usr/bin/pacman','--config'],'private pacman config argv')
    config_path=install[2];config_raw=reads.read(output/'signature-config.txt',4096);need(pin(config_raw)==report['signature_config_pin'],'retained original signature config pin');config=config_raw.decode()
    match=re.fullmatch(r'\[options\]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = (/tmp/build-tools-test-[A-Za-z0-9_+-]+/trust)\nHookDir = /builder-disabled-hooks\nLogFile = (/tmp/build-tools-test-[A-Za-z0-9_+-]+/pacman.log)\n',config)
    need(match is not None and config_path==str(Path(match[1]).parent/'pacman.conf') and match[2]==str(Path(match[1]).parent/'pacman.log'),'closed private local-only signature config')
    pacman=['/usr/bin/pacman','--config',config_path];verifier=['/usr/bin/gpg','--homedir',match[1],'--batch','--no-auto-key-retrieve','--auto-key-locate','clear']
    signer=ad['owner']['test_fingerprint'];verified=[]
    need(signed['setup8']['archive_pin']==pin(reads.reference(inputs['setup8']['archive'])) and signed['setup8']['signature_pin']==pin(reads.reference(inputs['setup8']['signature'])),'same currently verified Setup8 signature bytes')
    for key,row in signed.items():
        index,_,raw=entry('current-signature-'+key,[*verifier,'--status-fd=1','--verify',row['signature'],row['archive']])
        candidates=[line.split()[2] for line in raw.decode().splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
        need(candidates==[signer],'same externally selected current TEST fingerprint');strict_signature(raw,signer)
        md_index,_,md=entry('current-pkginfo-'+key,['/usr/bin/bsdtar','-xOf',row['archive'],'.PKGINFO']);data=metadata(md)
        need(data.get('pkgname')==[row['name']] and data.get('pkgver')==[row['version']] and data.get('arch')==['any'] and baseline_index<index<md_index,'signed current metadata/order')
        verified.append(md_index)
    added={'cachy-asahi-setup':'0.3.0-1'}
    def inv(step,versions):
        index,_,raw=entry(step,['/usr/bin/pacman','-Q']);need(raw==inventory_bytes(base|versions) and life['inventories'][step]==pin(raw),'complete exact lifecycle inventory');return index
    def payload(key,label,after):
        prior=set(used)
        recipe=p['setup8'] if key=='setup8' else p['packages'][key]
        _,_,raw=entry(label+'-file-list',pacman+['-Qlq',recipe['name']])
        leaves=[line.lstrip('/') for line in raw.decode().splitlines() if not line.endswith('/')]
        need(len(leaves)==len(set(leaves)) and set(leaves)==set(recipe['payload_files']),'exact ALPM file list')
        for i,(name,row) in enumerate(sorted(recipe['payload_files'].items())):
            path='/'+name;_,_,raw=entry(label+'-owner-'+str(i),pacman+['-Qqo',path]);need(raw.decode().strip()==recipe['name'],'actual ALPM owner')
            _,_,raw=entry(label+'-stat-'+str(i),['/usr/bin/stat','-c','%u:%g:%a:%s:%h:%F','--',path]);need(raw==('0:0:%o:%d:1:regular file\n'%(row['mode'],row['bytes'])).encode(),'actual installed file mode/uid/gid/size/link/type')
            _,_,raw=entry(label+'-sha256-'+str(i),['/usr/bin/sha256sum','--',path]);need(raw==(row['sha256']+'  '+path+'\n').encode(),'actual installed source bytes')
        indexes=[commands[s][0] for s in used-prior];need(min(indexes)>after,'payload observations after installation inventory');return max(indexes)
    def absent(label,keys,after):
        names=sorted({name for key in keys for name in signed[key]['payload_files']})
        for i,name in enumerate(names):
            for flag in ('-e','-L'):
                index,_,_=entry(label+'-'+str(i)+flag,['/usr/bin/test','!',flag,'/'+name]);need(index>after,'absence observed after removal inventory')
    index,_,_=entry('current-install-setup8',pacman+['--noconfirm','--asdeps','-U',signed['setup8']['archive']]);need(index>max(verified),'all signatures verified before install')
    observed=inv('current-dependency-inventory',added);need(observed>index,'setup inventory order');payload('setup8','current-setup8',observed)
    need(life['payloads']['setup8']==dict(verified=True,files=p['setup8']['payload_files']),'Setup8 payload report')
    for cycle in ('install','reinstall'):
        index,_,_=entry('current-'+cycle,pacman+['--noconfirm','-U',*[signed[k]['archive'] for k in KINDS]])
        need(index>max(commands[s][0] for s in used if s!='current-'+cycle),'ordered current install cycle')
        observed=inv('current-'+cycle+'-inventory',added|dict(VERSIONS.values()));need(observed>index,'candidate inventory order')
        last_payload=max(payload(kind,'current-'+cycle+'-'+kind,observed) for kind in KINDS)
        need(life['payloads'][cycle]=={k:dict(verified=True,files=p['packages'][k]['payload_files']) for k in KINDS},'all payload reports')
        for kind in KINDS:
            help_index,_,_=entry('current-'+cycle+'-help-'+kind,['/usr/bin/runuser','-u','alarm','--','/usr/bin/'+VERSIONS[kind][0],'--help']);need(help_index>last_payload,'help observed after installed payloads')
        removed,_,_=entry('current-remove-'+cycle,pacman+['--noconfirm','-R',*[VERSIONS[k][0] for k in reversed(KINDS)]])
        need(removed>max(commands[s][0] for s in used if s!='current-remove-'+cycle),'help/payload before removal')
        observed=inv('current-after-remove-'+cycle,added);need(observed>removed,'removal inventory order');absent('current-absent-'+cycle,KINDS,observed)
    index,_,_=entry('current-remove-setup8',pacman+['--noconfirm','-R','cachy-asahi-setup']);need(index>max(commands[s][0] for s in used if s!='current-remove-setup8'),'final dependency removal order')
    observed=inv('current-final-inventory',{});need(observed>index,'baseline restoration order');absent('current-absent-setup8',('setup8',),observed)
    need(used==set(commands),'no unexplained or omitted lifecycle commands')
    return dict(packages=3,signed_inputs=4,baseline_packages=372,inventory_sizes=[372,373,376,373,376,373,372],payload_leaves=[16,6,8],protected_state_unchanged=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('binding','output','source','profile','inputs','admission'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--binding-sha256',required=True);parser.add_argument('--execute-reader',action='store_true');args=parser.parse_args()
    need(args.execute_reader,'explicit separately Root-bound passive Reader entry required')
    reads=Reads();raw=reads.read(args.binding,65536);need(pin(raw)['sha256']==args.binding_sha256,'external binding SHA')
    result=check(args.output,args.source,args.profile,args.inputs,args.admission,decode(raw));print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()

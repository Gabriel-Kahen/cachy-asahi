# SPDX-License-Identifier: MIT
"""Independent signed349 DATA wrapper around the immutable Perl pair Reader."""
import hashlib
from contextlib import contextmanager
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import sys

MIB=1024**2
COMPONENT_MAP='3f238d649cb649ba2aff45e7930e49b28e3a7d8891860a1a17ead850719d5dee'
ORIGINAL_MAP='0c37bef7218caa6cb0f0e6d1b22ed5053b10a228f53e15076f5803d2fcf86b3e'
EXPECTED349='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
SIGNER='68B3537F39A313B3E574D06777193F152BDBE6A6'
DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']
ACTUAL=dict(source=None,ref=None,run=None,job=None,reader=None,authority=None,approval=None,artifact=None,image=None)


def need(value,why):
    if not value:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def digest(value,length=64):return type(value) is str and re.fullmatch('[0-9a-f]{'+str(length)+'}',value) is not None


def native_path(value):
    need(type(value) is str and 1<len(value)<=4096 and re.fullmatch('/[A-Za-z0-9._+/-]+',value) and
         all(part not in ('','.','..') for part in value.split('/')[1:]),'one canonical bounded absolute native path')
    return Path(value)


def decode(raw):
    def pairs(rows):
        out={}
        for key,value in rows:need(key not in out,'duplicate JSON key');out[key]=value
        return out
    def number(value):
        result=float(value);need(math.isfinite(result),'finite DATA number');return result
    def invalid(value):raise ValueError('nonfinite DATA')
    try:value=json.loads(raw,object_pairs_hook=pairs,parse_float=number,parse_constant=invalid)
    except RecursionError as error:raise ValueError('DATA depth') from error
    pending=[(value,0)];count=0
    while pending:
        item,depth=pending.pop();count+=1;need(depth<=32 and count<=200000,'DATA structure bound')
        if type(item) is dict:pending.extend((v,depth+1) for v in item.values())
        elif type(item) is list:pending.extend((v,depth+1) for v in item)
    return value


def read(root,name,cap=8*MIB):
    need(type(name) is str and 0<len(name)<=4096 and not name.startswith('/') and all(x not in ('','.','..') for x in name.split('/')),'relative DATA leaf')
    root=Path(root);need(root.is_absolute() and root==root.resolve() and not any(p.is_symlink() for p in (root,*root.parents)),'ordinary absolute DATA root')
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        parts=name.split('/')
        for part in parts[:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
        leaf=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        try:
            before=os.fstat(leaf);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded ordinary single-link DATA')
            chunks=[];size=0
            while block:=os.read(leaf,min(65536,cap+1-size)):
                size+=len(block);need(size<=cap,'DATA byte cap');chunks.append(block)
            key=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
            need(size==before.st_size and key(before)==key(os.fstat(leaf))==key(os.stat(parts[-1],dir_fd=fd,follow_symlinks=False)),'whole stable DATA read')
            return b''.join(chunks)
        finally:os.close(leaf)
    finally:os.close(fd)


def source_data(root,b):
    need(type(b) is dict and set(b)=={'source','ref','run','job','approval','source_map_sha256','component_map_sha256','operation'} and
         digest(b['source'],40) and digest(b['approval']) and digest(b['source_map_sha256']) and digest(b['component_map_sha256']) and
         type(b['ref']) is str and re.fullmatch('refs/heads/codex/[A-Za-z0-9._/-]+',b['ref']) and
         all(type(b[k]) is str and re.fullmatch('[1-9][0-9]{0,19}',b[k]) for k in ('run','job')) and
         b['operation']=='perl5423-native-pair-v2' and b['component_map_sha256']==COMPONENT_MAP,'external actual Root Source/once binding required')
    raw=read(root,'source-map.json',MIB);need(pin(raw)['sha256']==b['source_map_sha256'],'Root-authenticated whole Source map')
    m=decode(raw);need(type(m['schema']) is int and m['schema']==1 and m['actual']==ACTUAL,'unpublished hosted Source selectors remain NULL')
    rows=m['files'];need(type(rows) is dict and 1<=len(rows)<=320,'finite complete Source')
    nodes=[]
    for directory,dirs,files in os.walk(root,followlinks=False):
        base=Path(directory)
        for name in tuple(dirs):
            need(not (base/name).is_symlink(),'Source directory alias')
            if base==Path(root) and name=='.git':dirs.remove(name)
            else:nodes.append(base/name)
        nodes.extend(base/name for name in files);need(len(nodes)<=1024,'finite Source node bound')
    need(len(nodes)<=1024 and all(not p.is_symlink() and (p.is_dir() or p.is_file()) for p in nodes),'ordinary finite Source nodes')
    need({p.relative_to(root).as_posix() for p in nodes if p.is_file()}==set(rows)|{'source-map.json'},'complete Source membership')
    expected_dirs={str(parent) for name in set(rows)|{'source-map.json'} for parent in Path(name).parents if str(parent)!='.'}
    need({p.relative_to(root).as_posix() for p in nodes if p.is_dir()}==expected_dirs,'complete Source directory membership')
    total=0
    for name,want in rows.items():
        body=read(root,name,64*MIB);total+=len(body)
        need(dict(**pin(body),mode=stat.S_IMODE((Path(root)/name).stat().st_mode))==want,'whole Source byte/mode pin')
    need(total<=96*MIB,'whole Source byte bound')
    for prefix,map_name,want in [('original','native/source-map.json',ORIGINAL_MAP),('perl','source-map.json',b['component_map_sha256'])]:
        held=read(root,prefix+'/'+map_name,MIB);need(pin(held)['sha256']==want,'immutable held Source map')
        leaves=decode(held)['files']
        need({name[len(prefix)+1:] for name in rows if name.startswith(prefix+'/')}==set(leaves)|{map_name},'complete held Source subtree')
        need(all(rows[prefix+'/'+name]==row for name,row in leaves.items()),'held Source bytes/modes preserved')
    return m


def natural(row):
    need(type(row) is dict and row.get('natural_exit') is True and row.get('forced_cleanup') is False and
         row.get('retirement')=='REAPED' and row.get('group_absent') is True and row.get('leader_held_until_group_inspection') is True and
         row.get('ownership_lost') is False and row.get('exit_observed_via_waitpid') is True and not row.get('cleanup_error') and
         type(row.get('pid')) is int and row['pid']>0 and type(row.get('exit')) is int,'natural direct owned bootstrap retirement')
    seconds=row.get('elapsed_seconds');need(type(seconds) in (int,float) and math.isfinite(seconds) and 0<seconds<=1800,'bounded bootstrap actor clock')
    return row['exit']


def signed(status):
    need(type(status) is str and len(status)<=65536,'bounded complete GPG status')
    rows=[line.split()[1:] for line in status.splitlines() if line.startswith('[GNUPG:] ')]
    need(not any(not row or row[0] in ('EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','FAILURE','ERROR') for row in rows),'unexpired unrevoked signature status required')
    valid=[row for row in rows if row[0]=='VALIDSIG']
    need(len(valid)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==SIGNER,'exact pinned primary signature fingerprint')


def filesystem_data(value):
    need(type(value) is dict and set(value)=={'path','canonical','accessible','device','available_bytes','total_inodes','available_inodes'} and
         value['canonical'] is value['accessible'] is True,'complete canonical accessible filesystem observation')
    native_path(value['path'])
    need(all(type(value[k]) is int and 0<=value[k]<2**64 for k in ('device','available_bytes','total_inodes','available_inodes')) and
         value['available_bytes']>=8*1024*MIB and 120000<=value['available_inodes']<=value['total_inodes'],
         'fixed observed filesystem bytes/inode reserve required')


def daemon_data(value):
    need(value['schema']==1 and value['status']=='OBSERVED_ROOTFUL_NATIVE_LOCAL_DAEMON_PRECONDITIONS' and value['native_acceptance'] is False,'actual local daemon observation')
    info,version,host,socket,storage=(value[k] for k in ('info','version','host','socket','storage'))
    need(host['system']=='Linux' and host['machine']=='aarch64' and host['uid']==host['gid']==1001 and
         version['Server']['Os']=='linux' and version['Server']['Arch'] in ('arm64','aarch64') and info['OSType']=='linux' and
         info['Architecture'] in ('arm64','aarch64'),'actual native coordinator and daemon')
    need(socket==dict(path='/var/run/docker.sock',uid=0,socket=True,stable=True) and
         type(info['SecurityOptions']) is list and all(type(v) is str and 'rootless' not in v and 'userns' not in v for v in info['SecurityOptions']) and
         info['CgroupVersion']=='2' and all(info[k] is True for k in ('CpuCfsQuota','MemoryLimit','SwapLimit','PidsLimit')),'actual rootful local cgroup/socket profile')
    need(type(info['ID']) is str and info['ID'] and storage['path']==info['DockerRootDir'] and storage['canonical'] is storage['accessible'] is True and
         all(type(storage[k]) is int for k in ('available_bytes','total_inodes','available_inodes')) and
         120000<=storage['available_inodes']<=storage['total_inodes'] and storage['available_bytes']>=8*1024*MIB and
         type(host['MemAvailable_bytes']) is int and host['MemAvailable_bytes']>=8*1024*MIB,'actual visible fixed-pool storage/RAM admission')
    work=storage['work_filesystems'];need(type(work) is list and len(work)==4,'four actual work/cache/carrier/temp filesystem observations')
    for row in work:filesystem_data(row)
    temp=native_path(work[0]['path'])
    need([row['path'] for row in work]==[str(temp),str(temp/'perl-hosted'),str(temp/'alarm-cache'),str(temp/'pgo-hosted-retained')],
         'exact actual temp/work/cache/carrier paths; per-device observations are not additive')


def provenance_data(get,source_root,h,b,source_map):
    readback_raw,daemon_raw=get('source-readback.json'),get('daemon.json')
    need(pin(readback_raw)['sha256']==h['source_readback_sha256'] and pin(daemon_raw)['sha256']==h['daemon_identity_sha256'],'actual retained Source readback and daemon hashes')
    proof=decode(readback_raw)
    need(proof['schema']==1 and proof['status']=='PASS_EXACT_HOSTED_SOURCE_READBACK' and proof['binding']=={k:v for k,v in b.items() if k!='job'},'actual same-Source pre-job readback')
    expected=dict(source_map['files']);expected['source-map.json']=dict(**pin(read(source_root,'source-map.json',MIB)),mode=0o644)
    need(type(proof['files']) is dict and set(proof['files'])==set(expected),'complete actual Source readback membership')
    for name,row in proof['files'].items():
        need(set(row)=={'bytes','sha256','mode','blob'} and {k:row[k] for k in ('bytes','sha256','mode')}==expected[name] and digest(row['blob'],40),'actual Source readback byte/mode joins')
        body=read(source_root,name,64*MIB)
        need(hashlib.sha1(b'blob '+str(len(body)).encode()+b'\0'+body).hexdigest()==row['blob'],'actual Source Git blob/body join')
    actors=proof['actors'];need(type(actors) is list and len(actors)==2,'two actual read-only Source proof actors')
    observed=actors[0]['argv'];need(type(observed) is list and len(observed)>3 and type(observed[3]) is str and observed[3].startswith('--work-tree='),'observed native Source work-tree')
    native_source=native_path(observed[3][len('--work-tree='):])
    filesystem_data(proof['storage_before_inputs'])
    temp=native_path(proof['storage_before_inputs']['path'])
    need(not temp.is_relative_to(native_source) and not native_source.is_relative_to(temp),'initial temp storage disjoint from native Source')
    git=['/usr/bin/git','--no-replace-objects','--git-dir='+str(native_source/'.git'),'--work-tree='+str(native_source),'-c','protocol.allow=never','-c','core.fsmonitor=false']
    for row,argv in zip(actors,[git+['rev-parse','--verify','HEAD'],git+['ls-tree','-rz','--full-tree',b['source']]]):
        need(row['argv']==argv and natural(row['lifecycle'])==row['returncode']==0 and
             pin(get(row['stdout']))==row['stdout_pin'] and pin(get(row['stderr']))==row['stderr_pin'] and not get(row['stderr']),'actual naturally retired same-Source Git proof streams')
    need(get(actors[0]['stdout']).strip()==b['source'].encode(),'actual published Source HEAD')
    found={}
    for raw in get(actors[1]['stdout']).split(b'\0'):
        if not raw:continue
        head,name=raw.split(b'\t',1);mode,kind,oid=head.decode().split();name=name.decode()
        need(name in expected and name not in found and kind=='blob' and mode in ('100644','100755'),'actual ordinary complete Git tree')
        found[name]=dict(mode=int(mode[-3:],8),blob=oid)
    need(found=={name:{k:row[k] for k in ('mode','blob')} for name,row in proof['files'].items()},'actual readback tree/blob table join')
    daemon=decode(daemon_raw);daemon_data(daemon)
    need(daemon['storage']['work_filesystems'][0]['path']==str(temp),'initial before-input and native temp storage path continuity')


def bootstrap_data(get,source_root,h,b):
    original=decode(read(source_root,'original/bootstrap/scripts/ci/inputs.lock.json',MIB))
    extras=decode(read(source_root,'original/native/input-profile.json',MIB))['additions']['rows']
    combined=dict(original,packages=original['packages']+extras)
    need(len(original['packages'])==248 and len(extras)==8 and original['signer_fingerprint']==SIGNER,'held original256 signed archive inputs')
    need(decode(get('bootstrap/inputs.lock.json'))==combined,'exact combined original+fixed8 input lock')
    def signature(row):return dict(filename=row['filename']+'.sig',url=row['url']+'.sig',size=row['signature_size'],sha256=row['signature_sha256'])
    payloads=[combined['rootfs'],*combined['packages']]
    inputs=combined['keyring_files']+[row for item in payloads for row in (item,signature(item))]
    need(len(inputs)==517 and len({row['filename'] for row in inputs})==517,'complete517 input membership')
    acquisition_raw=get('bootstrap/acquisition.json');acquisition=decode(acquisition_raw)
    need(pin(acquisition_raw)['sha256']==h['bootstrap']['acquisition_sha256'] and acquisition['schema_version']==1 and
         acquisition['acquisition']=='PASS' and acquisition['signature_authentication']=='NOT RUN' and
         acquisition['counts']=={'total':517,'pass':517,'fail':0,'pending':0} and
         all(type(x) is int for x in acquisition['counts'].values()) and set(acquisition['inputs'])=={row['filename'] for row in inputs},'actual whole PASS517 transport records')
    for row in inputs:
        need(acquisition['inputs'][row['filename']]==dict(status='PASS',expected_sha256=row['sha256'],expected_bytes=row['size']),'every acquired exact byte/hash/size pin')
    signature_raw=get('bootstrap/signatures.json');signatures=decode(signature_raw)
    need(pin(signature_raw)['sha256']==h['bootstrap']['signatures_sha256'] and set(signatures)=={row['filename'] for row in payloads},'all257 actual signature results')
    for item in payloads:
        row=signatures[item['filename']];need(type(row['exit_code']) is int and row['exit_code']==0,'actual zero-exit GPG verification')
        signed(row['status']);argv=row['command']
        need(type(argv) is list and len(argv)==11 and argv[:4]==['gpg','--batch','--no-options','--homedir'] and argv[5:9]==['--no-auto-key-retrieve','--status-fd','1','--verify'] and
             Path(argv[-2]).name==item['filename']+'.sig' and Path(argv[-1]).name==item['filename'],'exact upstream signature verify command')
    lock=get('bootstrap/packages.lock');need(pin(lock)['sha256']==EXPECTED349==h['bootstrap']['expected349_sha256'] and
         lock==read(source_root,'original/native/expected349.lock',MIB),'actual full349 package inventory')
    record=decode(get('bootstrap/bootstrap.json'))
    need(record['status']=='image-provisioned' and record['image_id']==h['bootstrap']['image'] and
         record['packages_lock_sha256']==EXPECTED349,'actual immutable bootstrap image and inventory')
    operations_raw=get('bootstrap/operations.json');need(pin(operations_raw)['sha256']==h['bootstrap']['operations_sha256'],'whole bootstrap operation index')
    operations=decode(operations_raw);need(type(operations) is list and 1<=len(operations)<=600,'finite actual bootstrap operations')
    captured=[];seconds=0
    for index,row in enumerate(operations):
        need(set(row)=={'argv','stdout','stderr','stdout_pin','stderr_pin','lifecycle','returncode'} and
             all(row[key]=='bootstrap/operations/'+str(index).zfill(3)+'.'+key for key in ('stdout','stderr')) and
             natural(row['lifecycle'])==row['returncode'] and type(row['argv']) is list and 0<len(row['argv'])<=64 and
             all(type(v) is str and 0<len(v)<=4096 for v in row['argv']), 'exact naturally completed bootstrap operation index')
        out,err=get(row['stdout']),get(row['stderr'])
        need(pin(out)==row['stdout_pin'] and pin(err)==row['stderr_pin'],'whole actual stdout/stderr pins')
        need(row['returncode']==(1 if index==len(operations)-1 else 0),'only final exact image absence may be nonzero')
        captured.append((row['argv'],out,err));seconds+=row['lifecycle']['elapsed_seconds']
    need(seconds<=4740,'finite bootstrap plus cleanup actor clock')
    daemon=decode(get('daemon.json'));daemon_data(daemon)
    for (argv,out,err),command,key in zip(captured[:2],['info','version'],['info','version']):
        need(argv==DOCKER+[command,'--format','{{json .}}'] and not err.strip() and decode(out)==daemon[key],
             'actual daemon observation must join native command streams')
    for item in payloads:
        sig=signatures[item['filename']];matches=[(out,err) for argv,out,err in captured if argv==sig['command']]
        need(len(matches)==1 and matches[0]==(sig['status'].encode(),sig['diagnostic'].encode()), 'GPG result must join actual naturally retired raw command streams')
    homes={row['command'][4] for row in signatures.values()}
    need(len(homes)==1,'all signatures must use one actual private GPG home')
    gpg_home=next(iter(homes))
    need(type(gpg_home) is str and Path(gpg_home).is_absolute() and '..' not in Path(gpg_home).parts and
         gpg_home.endswith('/bootstrap/gpg'),'fixed actual bootstrap GPG home')
    image=h['bootstrap']['image'];token=hashlib.sha256((b['source']+':'+b['ref']+':'+b['run']).encode()).hexdigest()[:24]
    tag='perl-native-base:'+token;label='cachy-asahi.hosted-perl'
    build_indexes=[i for i,(argv,_,_) in enumerate(captured) if argv[:3]==DOCKER+['build']]
    need(len(build_indexes)==1,'one source-owned signed349 bootstrap build')
    build_index=build_indexes[0];argv=captured[build_index][0]
    def option(name):
        positions=[i for i,v in enumerate(argv) if v==name]
        need(len(positions)==1 and positions[0]+1<len(argv), 'one explicit bootstrap option '+name)
        return argv[positions[0]+1]
    need('--network=none' in argv and '--pull=false' in argv and '--platform=linux/arm64' in argv and
         argv.count('--no-cache')==1 and option('--tag')==tag and option('--iidfile').endswith('/bootstrap/image-id') and
         argv[-1]==str(Path(option('--iidfile')).parent/'context'), 'actual offline no-pull native bootstrap build')
    labels=[argv[i+1] for i,v in enumerate(argv[:-1]) if v=='--label']
    need(sorted(labels)==sorted([label+'='+token,label+'.source='+b['source']]),'actual unique Source-owned bootstrap labels')
    for selector in ('reference='+tag,'label='+label+'='+token):
        required=DOCKER+['image','ls','--no-trunc','-q','--filter',selector]
        matches=[i for i,(args,out,err) in enumerate(captured) if args==required and not out.strip() and not err.strip()]
        need(len(matches)==1 and matches[0]<build_index,'actual empty owned image baseline before build')
    probe='perl-bootstrap-inventory-'+token
    probe_absence=DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+probe+'$']
    agent_retirement=['gpgconf','--homedir',gpg_home,'--kill','gpg-agent']
    need(len(captured)>=5 and captured[-5][0]==agent_retirement and
         len([argv for argv,_,_ in captured if argv[:1]==['gpgconf']])==1,
         'one naturally completed exact bootstrap GPG-agent retirement before other cleanup')
    need(len(captured)>=4 and captured[-4][0]==probe_absence and not captured[-4][1].strip() and not captured[-4][2].strip(),
         'actual named inventory probe final absence')
    inventory=[]
    for index,(args,out,err) in enumerate(captured):
        if args[:2]!=DOCKER:continue
        command=args[2:]
        need(command and command[0] in ('image','info','version','context','container','run','build'),'unrelated Docker mutation refused')
        if command[:2]==['image','rm']:need(index==len(captured)-2 and command==['image','rm',image],'only exact final owned image removal permitted')
        elif command[:2]==['image','inspect']:need(command==['image','inspect',image],'only exact created image inspection')
        elif command[:2]==['image','ls']:
            need(command[:6]==['image','ls','--no-trunc','-q','--filter',command[-1]] and len(command)==6 and
                 command[-1] in ('reference='+tag,'label='+label+'='+token),'only owned alias baseline list')
        elif command[0]=='image':raise ValueError('unrelated image mutation refused')
        elif command[0]=='container':need(args==probe_absence and index==len(captured)-4,'only exact final inventory probe absence query')
        elif command[0]=='run':
            expected=['--name',probe,'--label',label+'='+token,'--label',label+'.source='+b['source'],
                      '--cpus=1','--memory=128m','--memory-swap=128m','--pids-limit=32',
                      '--rm','--pull=never','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges',
                      '--read-only','--entrypoint=/bin/cat',image,'/builder-packages.lock']
            need(command[1:]==expected and out==lock and not err.strip(),'exact bounded named inventory cat probe')
            inventory.append(index)
    need(len(inventory)==1 and build_index<inventory[0]<len(captured)-4,'one actual post-build inventory probe')
    need(len(captured)>=3 and captured[-3][0]==DOCKER+['image','inspect',image] and captured[-2][0]==DOCKER+['image','rm',image] and
         captured[-1][0]==DOCKER+['image','inspect',image], 'exact owned-image cleanup operation tail')
    inspected=decode(captured[-3][1]);need(type(inspected) is list and len(inspected)==1,'actual sole cleanup image inspection')
    actual=inspected[0]
    need(actual['Id']==image and actual['Architecture']=='arm64' and actual['Os']=='linux' and actual['RepoTags']==[tag] and not actual['Config'].get('Volumes') and
         actual['Config']['Labels'].get(label)==token and actual['Config']['Labels'].get(label+'.source')==b['source'], 'cleanup may remove only exact freshly owned native image')
    need(not captured[-3][2].strip() and not captured[-2][2].strip() and
         ('Deleted: '+image).encode() in captured[-2][1].splitlines() and all(line.startswith((b'Deleted: ',b'Untagged: ')) for line in captured[-2][1].splitlines()) and
         captured[-1][1].strip() in (b'',b'[]') and captured[-1][2].decode().strip()=='Error response from daemon: No such image: '+image,
         'actual no-force image removal and exact final absence diagnostics')
    cleanup=h['cleanup'];need(cleanup['image']==image and cleanup['gpg_agent_absent'] is True and cleanup['probe_absent'] is True and cleanup['image_removed'] is True and cleanup['image_absent'] is True and cleanup['error'] is None,'cleanup receipt joins GPG socket absence and exact raw owned image retirement')
    return dict(image=image,input_files=517,signed_payloads=257,packages=349,operations=len(operations),image_absence_verified=True)


@contextmanager
def pair_transport(reader,logical,physical):
    """Two reviewed read-only root routers; preserve every held check unchanged."""
    original_read,original_namespace=reader.read,reader.export_namespace
    def routed_read(root,*args,**kwargs):
        return original_read(physical if Path(root)==logical else root,*args,**kwargs)
    def routed_namespace(root,*args,**kwargs):
        return original_namespace(physical if Path(root)==logical else root,*args,**kwargs)
    reader.read,reader.export_namespace=routed_read,routed_namespace
    try:yield
    finally:reader.read,reader.export_namespace=original_read,original_namespace


def relocated_pair(reader,evidence,source_root,c,a,q):
    physical=Path(evidence)/'pair'
    need(physical.is_absolute() and physical==physical.resolve(),'canonical passive pair evidence root')
    report=decode(read(physical,'report.json',MIB));inputs=native_path(report['inputs']);logical=inputs.parent
    need(str(inputs)==str(logical/'inputs') and inputs.name=='inputs' and logical!=Path('/'),'exact logical native pair input relationship')
    for root in (logical,physical):
        need(not source_root.is_relative_to(root) and not root.is_relative_to(source_root),'Source outside both native and passive pair roots')
    need(logical==physical or not(logical.is_relative_to(physical) or physical.is_relative_to(logical)), 'pair transport roots disjoint or identical')
    with pair_transport(reader,logical,physical):result=reader.validate_pair(logical,c,a,q)
    return result,dict(kind='REVIEWED_READ_ONLY_PAIR_TRANSPORT_VIEW',logical_pair_root=str(logical),physical_pair_root=str(physical),
                       routed_boundaries=['read','export_namespace'],artifact_bytes_changed=False,held_decision_checks_changed=False)


def pair_data(evidence,source_root,a,q,source_map):
    path=source_root/'perl/reader.py';body=read(source_root,'perl/reader.py',MIB)
    need(pin(body)=={k:source_map['files']['perl/reader.py'][k] for k in ('bytes','sha256')},'immediately pinned immutable pair Reader')
    spec=importlib.util.spec_from_file_location('held_perl_hosted_passive_reader',path);reader=importlib.util.module_from_spec(spec)
    exec(compile(body,str(path),'exec'),reader.__dict__)
    return relocated_pair(reader,evidence,source_root,decode(read(source_root,'perl/contract.json',MIB)),a,q)


def validate(evidence,source_root,binding):
    """Root authenticates Source/once-role/daemon/image authority before invocation."""
    need(sys.version_info>=(3,14),'actual Reader requires Python3.14 zstd runtime')
    source_root=Path(source_root);source_map=source_data(source_root,binding)
    evidence=Path(evidence)
    def get(name):return read(evidence,name,16*MIB)
    h=decode(get('hosted.json'))
    need(h['schema']==1 and h['status']=='PAIR_COMPLETED' and h['binding']==binding and type(h['pair_exit']) is int and h['pair_exit']==0 and
         digest(h['source_readback_sha256']) and digest(h['daemon_identity_sha256']) and
         re.fullmatch('sha256:[0-9a-f]{64}',h['bootstrap']['image']),'actual completed hosted binding')
    provenance_data(get,source_root,h,binding,source_map)
    bootstrap=bootstrap_data(get,source_root,h,binding)
    a_raw,q_raw=get('adapter-admission.json'),get('adapter-qualification.json');a,q=decode(a_raw),decode(q_raw)
    need(a_raw==encoded(a) and q_raw==encoded(q) and a['source']=={'sha':binding['source'],'ref':binding['ref'].removeprefix('refs/heads/')} and
         all(a[key]==binding[key] for key in ('operation','run','job','approval')) and a['source_map_sha256']==binding['component_map_sha256'] and
         a['image']==bootstrap['image'] and q['source_readback_sha256']==h['source_readback_sha256'] and
         q['native_daemon_identity_sha256']==h['daemon_identity_sha256'] and a['input_signature_audit_sha256']==q['input_signature_audit_sha256']==h['bootstrap']['signatures_sha256'],
         'exact Root Source/native daemon/image/signature to pair precondition join')
    result,transport=pair_data(evidence,source_root,a,q,source_map)
    need(result['status']=='PASS_NATIVE_PAIR_DATA' and result['native_acceptance'] is False,'held pair Reader must produce bounded PASS DATA')
    return dict(schema=1,status='PASS_HOSTED_PERL_PAIR_DATA',binding=binding,bootstrap=bootstrap,pair=result,transport_view=transport,
                native_acceptance=False,authority='ROOT_AUTHENTICATION_REQUIRED',physical_M2='NOT_QUALIFIED',release='NOT_ADMITTED')

# SPDX-License-Identifier: MIT
"""Job-local TEST key custody. No global agent/keyring operations or key export."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import socket
import stat
import struct
import subprocess
import time
import sys
from types import SimpleNamespace

FISH_MANIFEST = 'a27a13ba1938d2ec27d1ef9159b95a8d2263c06b143bfc9b694e5d3cccd14f5c'

def bind(profile, base):
    if type(profile) is not str or profile not in ('topmem-v1', 'fish-history-v1'):
        raise ValueError('service-profile-unselected')
    PROFILE = profile
    ROOT = Path(base)
    ADDON = ROOT/'addon'
    if profile == 'topmem-v1':
        NAME, ADDON_SCOPE, SIGNING, KEY_REF = 'cachy-asahi-topmem', 'topmem-addon', 'topmem-signing', 'topmem_key_owner'
        PURPOSE = 'TOPMEM_DISPOSABLE_TEST_TOOLCHAIN_INTERNAL_REPOSITORY_V2'
        PRODUCER = 'TOPMEM_SINGLE_PACKAGE_PACMAN_DATABASE_V1'
        MANIFEST = '4eb3b51f8eb7dcd0bc1ec01dd4b911326d7f0faef0d810517e42b5a9d6272cd7'
        SOURCE_MEMBERS, REPO, SIGNER_ENV = 18, 'topmem', 'TOPMEM_SIGNER_FP'
        ENTRY, PROBE = '/topmem-lifecycle.sh', '/topmem-smoke.py'
        RECIPE_FILES = ('.SRCINFO','LICENSE','NOTICE','PKGBUILD','README.md','cachy-asahi-topmem','test_topmem.py')
    else:
        NAME, ADDON_SCOPE, SIGNING, KEY_REF = 'cachy-asahi-fish-bang-bang', 'fish-history-addon', 'fish-history-signing', 'fish_history_key_owner'
        PURPOSE = 'FISH_HISTORY_DISPOSABLE_TEST_TOOLCHAIN_INTERNAL_REPOSITORY_V2'
        PRODUCER = 'FISH_HISTORY_SINGLE_PACKAGE_PACMAN_DATABASE_V1'
        MANIFEST = FISH_MANIFEST
        SOURCE_MEMBERS, REPO, SIGNER_ENV = 24, 'fish-history', 'FISH_SIGNER_FP'
        ENTRY, PROBE = '/fish-history-lifecycle.sh', '/fish-history-probe.py'
        RECIPE_FILES = ('.SRCINFO','PKGBUILD','__history_previous_command.fish','__history_previous_command_arguments.fish','opt-in.fish','usage.md','NOTICE','LICENSE.upstream','LICENSE.project')
    LABEL = 'org.cachy-asahi.'+ADDON_SCOPE+'.nonce'
    TOOLS = {'/usr/bin/gpg', '/usr/bin/gpg-agent'}
    SCOPE = 'DISPOSABLE TEST ONLY'
    _PROCESSES, _SOCKETS, _SPAWNS = {}, {}, {}

    def need(value, reason):
        if not value: raise ValueError(reason)


    def live(end):
        need(type(end) in (int,float) and math.isfinite(end) and time.monotonic() < end, 'signer-deadline')


    def directory(path):
        path=Path(path);info=path.lstat()
        need(path.is_absolute() and path==path.resolve() and stat.S_ISDIR(info.st_mode)
            and info.st_uid==os.getuid()>0 and info.st_gid==os.getgid()>0
            and stat.S_IMODE(info.st_mode)==0o700,'signer-directory')
        return [info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode]


    def bound(path, identity):
        need(directory(path)==identity,'signer-directory-drift')


    def write(c,path,value,mode=0o600):
        raw=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
        need(len(raw)<=65536,'signer-journal-bound')
        parent=Path(path).parent;identity=directory(parent)
        temporary=parent/('.signer-'+os.urandom(16).hex())
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
        try:
            view=memoryview(raw)
            while view:
                count=os.write(fd,view);need(count>0,'signer-write');view=view[count:]
            os.fsync(fd);bound(parent,identity);os.replace(temporary,path)
            rootfd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(rootfd)
            finally:os.close(rootfd)
            bound(parent,identity)
        finally:
            try:os.close(fd)
            finally:temporary.unlink(missing_ok=True)


    def file(c,path,row,end,executable=False):
        live(end);path=Path(path);before=path.lstat()
        need(path.is_absolute() and path==path.resolve() and stat.S_ISREG(before.st_mode)
            and before.st_uid==before.st_gid==0 and before.st_nlink==1 and stat.S_IMODE(before.st_mode)==row['mode']
            and type(row['mode']) is int and row['mode'] in (0o644,0o755) and (not executable or row['mode']==0o755)
            and type(row['bytes']) is int and before.st_size==row['bytes'] and 0<row['bytes']<=64*1024**2
            and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']), 'signer-tool-type')
        raw=c.read(path,64*1024**2,deadline=end);after=path.lstat()
        need(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'] and
            all(getattr(before,k)==getattr(after,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid',
                'st_nlink','st_size','st_mtime_ns','st_ctime_ns')),'signer-tool-pin')
        return raw


    def elf_dependencies(raw):
        """Finite ELF64 linkage declarations; dynamic search overrides are refused."""
        need(raw[:6]==b'\x7fELF\x02\x01' and len(raw)>=64,'signer-tool-elf')
        header=struct.unpack_from('<HHIQQQIHHHHHH',raw,16)
        need(header[1]==183 and header[8]==56 and 0<header[9]<=128,'signer-tool-elf')
        loads=[];dynamic=None;interpreter=None
        for i in range(header[9]):
            offset=header[4]+i*56;need(offset+56<=len(raw),'signer-tool-elf')
            kind,flags,pos,address,physical,size,memory,align=struct.unpack_from('<IIQQQQQQ',raw,offset)
            need(pos+size<=len(raw),'signer-tool-elf')
            if kind==1:loads.append((address,pos,size))
            if kind==2:dynamic=(pos,size)
            if kind==3:
                body=raw[pos:pos+size];need(body.endswith(b'\0') and b'\0' not in body[:-1],'signer-tool-elf')
                interpreter=body[:-1].decode('ascii')
        wanted=[];table=None;length=None
        if dynamic:
            need(dynamic[1]<=65536 and dynamic[1]%16==0,'signer-tool-elf')
            for pos in range(dynamic[0],dynamic[0]+dynamic[1],16):
                tag,value=struct.unpack_from('<qQ',raw,pos)
                if tag==0:break
                if tag==1:wanted.append(value)
                elif tag==5:table=value
                elif tag==10:length=value
                elif tag in (15,29):raise ValueError('signer-tool-search-override')
            need(len(wanted)<=32 and table is not None and length is not None and length<=1024**2,'signer-tool-elf')
        names=[]
        if wanted:
            matches=[pos+table-address for address,pos,size in loads if address<=table and table+length<=address+size]
            need(len(matches)==1,'signer-tool-elf');start=matches[0]
            for index in wanted:
                need(index<length,'signer-tool-elf');body=raw[start+index:start+length].split(b'\0',1)[0]
                name=body.decode('ascii');need(re.fullmatch('[A-Za-z0-9_.+-]{1,128}',name),'signer-tool-elf');names.append(name)
        return interpreter,names


    def policy(c,path,pin,config,end):
        path=Path(path);info=path.lstat()
        need(path.is_absolute() and path==path.resolve() and path.is_relative_to(Path(config['jobroot']))
            and stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_gid==os.getgid() and info.st_nlink==1
            and stat.S_IMODE(info.st_mode)==0o600,'signer-policy-custody')
        raw=c.pinned(path,pin,deadline=end);value=c.decode(raw)
        need(set(value)=={'schema_version','purpose','tools','helpers','producer'} and type(value['schema_version']) is int
            and value['schema_version']==2 and value['purpose']==PURPOSE and type(value['tools']) is dict
            and set(value['tools'])==TOOLS and type(value['helpers']) is dict and len(value['helpers'])<=128
            and not set(value['helpers']) & TOOLS,'signer-policy')
        producer=value['producer']
        need(type(producer) is dict and set(producer)=={'kind','sha256','bytes'} and producer['kind']==PRODUCER
            and type(producer['sha256']) is str and re.fullmatch('[0-9a-f]{64}',producer['sha256'])
            and producer['sha256']==config['repository_producer_sha256']
            and type(producer['bytes']) is int and 0<producer['bytes']<=2*1024**2,'signer-producer-policy')
        selected_manifest=manifest(c,config,value,end);producerrow=selected_manifest['files']['producer.py']
        need(producerrow=={'sha256':producer['sha256'],'bytes':producer['bytes'],'mode':0o644},'signer-producer-manifest')
        producerpath=Path(config['caller_source'])/'producer.py';before=producerpath.lstat()
        need(producerpath==producerpath.resolve() and stat.S_ISREG(before.st_mode) and before.st_nlink==1
            and before.st_uid==os.getuid() and before.st_gid==os.getgid() and before.st_size==producer['bytes']
            and stat.S_IMODE(before.st_mode)==0o644,'signer-producer-custody')
        body=c.pinned(producerpath,producer['sha256'],deadline=end);after=producerpath.lstat()
        need(len(body)==producer['bytes'] and all(getattr(before,k)==getattr(after,k) for k in
            ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')),'signer-producer-source')
        rows={**value['tools'],**value['helpers']};bodies={};total=0
        for name,row in rows.items():
            need(type(name) is str and (name in TOOLS or name.startswith(('/usr/bin/','/usr/lib/','/usr/share/gnupg/','/usr/share/makepkg/')))
                and type(row) is dict and set(row)=={'sha256','bytes','mode'},'signer-policy-row')
            bodies[name]=file(c,name,row,end,executable=name in TOOLS);total+=len(bodies[name])
            need(total<=256*1024**2,'signer-policy-bound')
        for name,body in bodies.items():
            if not body.startswith(b'\x7fELF'):
                # Selected GPG tools require ELF linkage. No shell tool substitution
                # or generic script permit follows from the internal producer grant.
                need(name not in TOOLS,'signer-script-closure-unselected');continue
            interpreter,needed=elf_dependencies(body)
            if interpreter:
                target=str(Path(interpreter).resolve());need(target in rows,'signer-loader-unselected')
            for soname in needed:
                candidates={str((Path(n)/soname).resolve()) for n in ('/usr/lib/aarch64-linux-gnu','/usr/lib','/lib/aarch64-linux-gnu','/lib')
                    if (Path(n)/soname).exists()}
                need(len(candidates)==1 and candidates.pop() in value['helpers'],'signer-library-unselected')
        return value


    def process(pid):
        """Kernel-observed identity. No PID alone grants signalling authority."""
        need(type(pid) is int and pid>0,'signer-process')
        path=Path('/proc')/str(pid)
        try:
            raw=(path/'stat').read_bytes();need(len(raw)<=4096,'signer-process-bound')
            rest=raw.decode('ascii').rsplit(')',1)[1].split()
            state=rest[0];start=int(rest[19]);parent=int(rest[1]);group=int(rest[2]);session=int(rest[3])
            status=(path/'status').read_bytes();need(len(status)<=65536,'signer-process-bound')
            fields={line.split(':',1)[0]:line.split(':',1)[1].strip().split() for line in status.decode('ascii').splitlines() if ':' in line}
            uid=list(map(int,fields['Uid']));gid=list(map(int,fields['Gid']))
            if state=='Z':
                return {'pid':pid,'start':start,'ppid':parent,'group':group,'session':session,'uid':uid,'gid':gid,'state':'Z'}
            executable=os.readlink(path/'exe');info=(path/'exe').stat()
            argv=(path/'cmdline').read_bytes();need(len(argv)<=65536,'signer-process-bound')
            return {'pid':pid,'start':start,'ppid':parent,'group':group,'session':session,'uid':uid,'gid':gid,
                    'exe':executable,'exe_dev':info.st_dev,'exe_ino':info.st_ino,
                    'argv':[part.decode('utf-8') for part in argv.split(b'\0')[:-1]],'state':state}
        except FileNotFoundError:
            need(not path.exists(),'signer-process-unobserved')
            return None


    def identity(row):
        return {key:value for key,value in row.items() if key not in ('state','ppid')}


    def agent_matches(row,record,config,argv):
        need(row is not None and row['uid']==[os.getuid()]*4 and row['gid']==[os.getgid()]*4
            and row['exe']=='/usr/bin/gpg-agent' and row['group']==row['session']==row['pid']
            and row['argv']==argv,'signer-agent-identity')
        if record is not None:need(identity(row)==record,'signer-agent-drift')


    def caller_state(c,config,end):
        path=Path(config['jobroot'])/'caller-state.json';descriptor=config['caller_state'];info=path.lstat()
        raw=c.read(path,65536,deadline=end)
        need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_gid==os.getgid() and info.st_nlink==1
            and stat.S_IMODE(info.st_mode)==0o600 and descriptor=={'sha256':hashlib.sha256(raw).hexdigest(),
                'bytes':len(raw),'dev':info.st_dev,'ino':info.st_ino},'signer-caller-state')
        value=c.decode(raw)
        need(set(value)=={'schema_version','baseline_attempted','addon_attempted','signing_attempted'}
            and type(value['schema_version']) is int and value['schema_version']==1
            and all(type(value[k]) is bool for k in ('baseline_attempted','addon_attempted','signing_attempted')),'signer-caller-state')
        return value


    def argv(home):
        return ['/usr/bin/gpg-agent','--no-options','--homedir',str(home),'--supervised',
                '--disable-scdaemon','--extra-socket','none','--browser-socket','none','--allow-loopback-pinentry',
                '--no-allow-external-cache']


    def manifest(c,config,selected,end):
        value=c.decode(c.pinned(Path(config['caller_source'])/'manifest.json',config['caller_manifest_sha256'],deadline=end))
        need(type(value) is dict and set(value)=={'schema_version','addon_profile','baseline_packet_sha256','addon_manifest_sha256','files','tools'}
            and type(value['schema_version']) is int and value['schema_version']==2
            and value['addon_profile']==config['addon_profile']==PROFILE
            and value['addon_manifest_sha256']==MANIFEST
            and value['baseline_packet_sha256']==config['packet_sha256']
            and type(value['addon_manifest_sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['addon_manifest_sha256'])
            and type(value['files']) is dict and set(value['files'])=={'caller.py','signing.py','recovery.py','agent_entry.py','producer.py','repository_adapter.py'}
            and type(value['tools']) is dict and set(value['tools'])=={'/usr/bin/git','/usr/bin/python3.12','/usr/bin/docker'},'signer-caller-manifest')
        for row in [*value['files'].values(),*value['tools'].values()]:
            need(type(row) is dict and set(row)=={'sha256','bytes','mode'} and type(row['bytes']) is int
                and 0<row['bytes']<=64*1024**2 and type(row['mode']) is int and row['mode'] in (0o644,0o755)
                and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'signer-caller-manifest')
        python='/usr/bin/python3.12'
        need(str(Path(sys.executable).resolve())==python and python in selected['helpers']
            and value['tools'][python]==selected['helpers'][python],'signer-python-unselected')
        return value


    def journal_record(c,path,config,end,pin=None):
        info=path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_gid==os.getgid()
            and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'signer-journal-custody')
        raw=c.pinned(path,pin,deadline=end) if pin else c.read(path,65536,deadline=end)
        need(len(raw)<=65536,'signer-journal-bound');value=c.decode(raw)
        fields={'schema_version','scope','source_commit','nonce','policy_path','policy_sha256','nodes','phase','parent',
            'agent','agent_argv','key_owner','certificate_sha256','sticky_uncertain','launch_attempted','socket'}
        need(type(value) is dict and set(value)==fields and type(value['schema_version']) is int and value['schema_version']==1
            and value['scope']==SCOPE and value['source_commit']==config['source_commit'] and value['nonce']==config['nonce']
            and value['phase'] in {'reserved','create-attempted','bound','generating','prepared','failed','disposed'}
            and type(value['sticky_uncertain']) is bool and type(value['launch_attempted']) is bool
            and type(value['nodes']) is dict and set(value['nodes'])=={'root','keyhome','public','runtime'}
            and value['policy_path']==config['tool_policy'] and value['policy_sha256']==config['tool_policy_sha256'], 'signer-journal-binding')
        for node in value['nodes'].values():
            need(type(node) is list and len(node)==5 and all(type(x) is int for x in node),'signer-journal-node')
        if value['socket'] is not None:
            row=value['socket'];need(type(row) is dict and set(row)=={'path','identity'}
                and row['path']==str(path.parent/'keyhome/S.gpg-agent') and type(row['identity']) is list
                and len(row['identity'])==5 and all(type(x) is int for x in row['identity']),'signer-journal-socket')
        if value['key_owner'] is not None:
            row=value['key_owner'];need(type(row) is dict and set(row)=={'path','sha256'}
                and row['path']==str(path.parent/'key-owner.json') and type(row['sha256']) is str
                and re.fullmatch('[0-9a-f]{64}',row['sha256']),'signer-journal-owner')
        return value


    def check_policy(worker,config,policy_path,policy_sha):
        with worker.graph(config,config['work_deadline']) as (c,producer,load):
            selected=policy(c,policy_path,policy_sha,config,config['work_deadline'])
            manifest(c,config,selected,config['work_deadline'])
            return {'status':'SOURCE TOOL POLICY CHECKED','scope':SCOPE,'policy_sha256':policy_sha,
                    'tool_count':len(selected['tools']),'helper_count':len(selected['helpers']),
                    'producer_kind':PRODUCER,'producer_sha256':selected['producer']['sha256']}


    def start(worker,config,parent_owned_runner):
        end=config['work_deadline'];live(end)
        with worker.graph(config,end) as (c,producer,load):
            need(caller_state(c,config,end)['signing_attempted'],'signer-attempt-not-reserved')
            policy_path,policy_sha=config['tool_policy'],config['tool_policy_sha256']
            selected=policy(c,policy_path,policy_sha,config,end)
            selected_manifest=manifest(c,config,selected,end);python='/usr/bin/python3.12'
            entry=Path(config['caller_source'])/'agent_entry.py';entryrow=selected_manifest['files']['agent_entry.py']
            entryraw=c.pinned(entry,entryrow['sha256'],deadline=end)
            need(len(entryraw)==entryrow['bytes'],'signer-entry-source')
            root=Path(config['jobroot']);directory(root);keyroot=root/SIGNING
            need(not keyroot.exists() and not keyroot.is_symlink(),'signer-root-not-fresh')
            keyroot.mkdir(mode=0o700);home=keyroot/'keyhome';public=keyroot/'public';runtime=keyroot/'runtime'
            for path in (home,public,runtime):path.mkdir(mode=0o700)
            need(len(os.fsencode(home/'S.gpg-agent'))<=100,'signer-socket-path-bound')
            nodes={name:directory(path) for name,path in (('root',keyroot),('keyhome',home),('public',public),('runtime',runtime))}
            journal=keyroot/'owner-journal.json'
            record={'schema_version':1,'scope':SCOPE,'source_commit':config['source_commit'],'nonce':config['nonce'],
                'policy_path':str(policy_path),'policy_sha256':policy_sha,'nodes':nodes,'phase':'reserved','parent':process(os.getpid()),
                'agent':None,'agent_argv':argv(home),'key_owner':None,'certificate_sha256':None,'sticky_uncertain':False,
                'launch_attempted':False,'socket':None}
            write(c,journal,record)
            env={'PATH':'/usr/bin:/bin','HOME':os.environ['HOME'],'LANG':'C.UTF-8','LC_ALL':'C',
                 'GNUPGHOME':str(home),'XDG_RUNTIME_DIR':str(runtime)}
            running=None;logfd=None;listener=None
            try:
                with producer.jr.defer_signals() as events:
                    listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                    listener.bind(str(home/'S.gpg-agent'));os.chmod(home/'S.gpg-agent',0o600);listener.listen(16)
                    socket_info=(home/'S.gpg-agent').lstat()
                    socket_identity=[socket_info.st_dev,socket_info.st_ino,socket_info.st_uid,socket_info.st_gid,stat.S_IMODE(socket_info.st_mode)]
                    record['socket']={'path':str(home/'S.gpg-agent'),'identity':socket_identity}
                    _SOCKETS[str(journal)]=(listener,parent_owned_runner,False)
                    write(c,journal,record)
                    parent_owned_runner.register_socket(home/'S.gpg-agent',socket_identity)
                    _SOCKETS[str(journal)]=(listener,parent_owned_runner,True)
                    logfd=os.open(keyroot/'agent.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    parent=os.getpid();mask=signal.pthread_sigmask(signal.SIG_BLOCK,set())
                    def setup():
                        producer.jr._child_setup(parent,mask,max(.01,end-time.monotonic()))
                        resource.setrlimit(resource.RLIMIT_FSIZE,(8*1024**2,8*1024**2))
                    record.update(phase='create-attempted',launch_attempted=True);write(c,journal,record)
                    program='__file__='+repr(str(entry))+';exec(compile(bytes.fromhex('+repr(entryraw.hex())+'),__file__,"exec"))'
                    launch=[python,'-I','-B','-S','-c',program,'--listener-fd',str(listener.fileno()),
                        '--agent-sha256',selected['tools']['/usr/bin/gpg-agent']['sha256'],'--keyhome',str(home),'--deadline-at',str(end)]
                    live(end)
                    running=subprocess.Popen(launch,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                        stderr=logfd,env=env,close_fds=True,start_new_session=True,preexec_fn=setup,pass_fds=(listener.fileno(),))
                    _PROCESSES[str(journal)]=running
                    observed=None
                    for unused in range(200):
                        live(end);observed=process(running.pid)
                        if observed:
                            need(observed['uid']==[os.getuid()]*4 and observed['gid']==[os.getgid()]*4
                                and observed['ppid']==parent and observed['group']==observed['session']==running.pid
                                and observed.get('exe') in (python,'/usr/bin/gpg-agent'),'signer-spawn-identity')
                            _SPAWNS[str(journal)]={k:observed[k] for k in ('pid','start','group','session','uid','gid')}
                        if observed and observed.get('exe')=='/usr/bin/gpg-agent':break
                        need(running.poll() is None,'signer-agent-exit');time.sleep(.01)
                    agent_matches(observed,None,config,record['agent_argv'])
                    record['agent']=identity(observed);record['phase']='bound';write(c,journal,record)
                if events:raise producer.jr.Cancelled(events[0])
                return {'path':str(journal),'sha256':hashlib.sha256(c.read(journal,65536,deadline=end)).hexdigest(),
                        'socket':record['socket'],'scope':SCOPE}
            except BaseException:
                record['phase']='failed'
                try:write(c,journal,record)
                except BaseException:pass
                raise
            finally:
                if listener is not None and str(journal) not in _SOCKETS:
                    failed=sys.exc_info()[0] is not None
                    try:listener.close()
                    except BaseException:
                        if not failed:raise
                if logfd is not None:
                    failed=sys.exc_info()[0] is not None
                    try:os.close(logfd)
                    except BaseException:
                        if not failed:raise


    def prepare(worker,config,policy_path,policy_sha):
        end=config['work_deadline'];live(end)
        with worker.graph(config,end) as (c,producer,load):
            selected=policy(c,policy_path,policy_sha,config,end)
            need(caller_state(c,config,end)['signing_attempted'],'signer-attempt-not-reserved')
            root=Path(config['jobroot']);keyroot=root/SIGNING;journal=keyroot/'owner-journal.json'
            handoff=config['agent_handoff']
            need(handoff['path']==str(journal) and handoff['scope']==SCOPE,'signer-agent-handoff')
            record=journal_record(c,journal,config,end,handoff['sha256'])
            need(record['phase']=='bound' and record['source_commit']==config['source_commit'] and record['nonce']==config['nonce']
                and record['policy_sha256']==policy_sha and record['socket']==handoff['socket'],'signer-agent-handoff')
            nodes=record['nodes'];home=keyroot/'keyhome';public=keyroot/'public'
            for name,path in (('root',keyroot),('keyhome',home),('public',public),('runtime',keyroot/'runtime')):bound(path,nodes[name])
            socket_info=(home/'S.gpg-agent').lstat()
            need(stat.S_ISSOCK(socket_info.st_mode) and [socket_info.st_dev,socket_info.st_ino,socket_info.st_uid,
                socket_info.st_gid,stat.S_IMODE(socket_info.st_mode)]==record['socket']['identity'],'signer-agent-socket')
            agent_matches(process(record['agent']['pid']),record['agent'],config,record['agent_argv'])
            env={'PATH':'/usr/bin:/bin','HOME':os.environ['HOME'],'LANG':'C.UTF-8','LC_ALL':'C',
                 'GNUPGHOME':str(home),'XDG_RUNTIME_DIR':str(keyroot/'runtime')}
            try:
                toolrunner=producer.jr.Runner(min(7200,end-time.monotonic()),env,keyroot/'tool-logs')
                toolrunner.deadline=min(toolrunner.deadline,end)
                prefix=['/usr/bin/gpg','--no-autostart','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve']
                def command(args):
                    live(end);bound(keyroot,nodes['root']);bound(home,nodes['keyhome'])
                    policy(c,policy_path,policy_sha,config,end)
                    agent_matches(process(record['agent']['pid']),record['agent'],config,record['agent_argv'])
                    result=toolrunner.run(prefix+args,timeout=min(120,end-time.monotonic()),limit=65536,separate_stderr=True)
                    live(end);need(type(result.returncode) is int and result.returncode==0,'signer-command-failed')
                    need(type(result.stdout) is bytes and len(result.stdout)<=65536 and b'PRIVATE KEY' not in result.stdout,'signer-output')
                    agent_matches(process(record['agent']['pid']),record['agent'],config,record['agent_argv']);bound(home,nodes['keyhome'])
                    return result.stdout
                record['phase']='generating';write(c,journal,record)
                uid=NAME+'-TEST-'+config['nonce']+' <'+config['nonce']+'@invalid>'
                created=command(['--status-fd','1','--pinentry-mode','loopback','--passphrase','','--quick-generate-key',uid,'rsa2048','sign','1d'])
                keys=[line.split()[-1] for line in created.decode('ascii').splitlines() if line.startswith('[GNUPG:] KEY_CREATED P ')]
                need(len(keys)==1 and re.fullmatch('[A-F0-9]{40}',keys[0]),'signer-created-fingerprint');fingerprint=keys[0]
                listing=command(['--with-colons','--fingerprint','--list-secret-keys']).decode('ascii').splitlines()
                primary=[];pending=False
                for line in listing:
                    fields=line.split(':')
                    if fields[0]=='sec':need(len(fields)>9 and fields[1] not in ('r','e'),'signer-key-state');pending=True
                    elif fields[0]=='fpr' and pending:need(len(fields)>9,'signer-key-list');primary.append(fields[9]);pending=False
                    elif fields[0]=='ssb':raise ValueError('signer-unselected-subkey')
                need(primary==[fingerprint],'signer-key-list')
                exported=command(['--armor','--export',fingerprint])
                need(exported.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----') and b'PRIVATE KEY' not in exported,'signer-public-certificate')
                cert=public/'public-key.asc'
                with cert.open('xb') as stream:os.fchmod(stream.fileno(),0o644);stream.write(exported);stream.flush();os.fsync(stream.fileno())
                bound(public,nodes['public'])
                owner={'schema_version':1,'owner':'TEST-'+config['nonce'],'fingerprint':fingerprint,'certificate':str(cert),
                    'certificate_sha256':hashlib.sha256(exported).hexdigest(),'keyhome':str(home),
                    'gpg_sha256':selected['tools']['/usr/bin/gpg']['sha256'],# Explicit V2 legacy-field meaning: pinned internal producer source, never a host executable.
                    'repo_add_sha256':selected['producer']['sha256']}
                ownerpath=keyroot/'key-owner.json';write(c,ownerpath,owner)
                ownerpin=hashlib.sha256(c.read(ownerpath,65536,deadline=end)).hexdigest()
                record.update(phase='prepared',certificate_sha256=owner['certificate_sha256'],key_owner={'path':str(ownerpath),'sha256':ownerpin})
                write(c,journal,record);live(end)
                return {'key_owner_path':str(ownerpath),'key_owner_sha':ownerpin,'proof':{'scope':SCOPE,'status':'PREPARED',
                    'agent_bound':True,'source_commit':config['source_commit'],'policy_sha256':policy_sha,'private_key_exported':False}}
            except BaseException:
                record['phase']='failed'
                try:write(c,journal,record)
                except BaseException:pass
                raise


    def remove_home(path,known,end):
        bound(path,known);count=[0]
        def node(info):return [info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode]
        def walk(directory_path,fd,identity,depth):
            live(end);need(depth<=8,'signer-disposal-depth')
            need(node(os.fstat(fd))==identity and directory(directory_path)==identity,'signer-disposal-directory-drift')
            with os.scandir(fd) as entries:
                for entry in entries:
                    live(end);count[0]+=1;need(count[0]<=512,'signer-disposal-count')
                    info=os.stat(entry.name,dir_fd=fd,follow_symlinks=False)
                    need(info.st_uid==os.getuid() and info.st_gid==os.getgid() and info.st_dev==known[0],'signer-disposal-owner')
                    if stat.S_ISDIR(info.st_mode):
                        need(stat.S_IMODE(info.st_mode)==0o700,'signer-disposal-mode')
                        childfd=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                        try:walk(directory_path/entry.name,childfd,node(info),depth+1)
                        finally:os.close(childfd)
                        need(node(os.stat(entry.name,dir_fd=fd,follow_symlinks=False))==node(info),'signer-disposal-directory-drift')
                        os.rmdir(entry.name,dir_fd=fd)
                    else:
                        need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=8*1024**2
                            and stat.S_IMODE(info.st_mode) in (0o600,0o644),'signer-disposal-type')
                        after=os.stat(entry.name,dir_fd=fd,follow_symlinks=False)
                        need(node(after)==node(info) and after.st_nlink==1,'signer-disposal-file-drift')
                        os.unlink(entry.name,dir_fd=fd)
                    need(node(os.fstat(fd))==identity and directory(directory_path)==identity,'signer-disposal-directory-drift')
            live(end);need(node(os.fstat(fd))==identity and directory(directory_path)==identity,'signer-disposal-directory-drift')
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:walk(path,fd,known,0)
        finally:os.close(fd)
        bound(path,known);path.rmdir();need(not path.exists() and not path.is_symlink(),'signer-keyhome-absence')


    def release_listener(journal,record,end):
        """Dispose retained parent FD independently; named objects need exact binding."""
        held=_SOCKETS.get(str(journal))
        if held is None:return
        live(end);held[0].close()
        name=Path(journal).parent/'keyhome/S.gpg-agent'
        bound(name.parent,record['nodes']['keyhome'])
        row=record['socket'];need(row is not None and row['path']==str(name),'signer-agent-socket')
        try:info=name.lstat()
        except FileNotFoundError:pass
        else:
            need(stat.S_ISSOCK(info.st_mode) and [info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)]==row['identity'],'signer-agent-socket')
            name.unlink()
        if held[2]:held[1].unregister_socket(name)
        _SOCKETS.pop(str(journal),None)


    def recover(worker,config,cleanup_end):
        end=min(cleanup_end,config['cleanup_deadline']);live(end)
        result={'status':'FAIL','agent_absent':False,'keyhome_absent':False,'cancelled':False,'reason':'unobserved','key_owner':None}
        with worker.graph(config,end) as (c,producer,load):
            record=None;journal=None
            try:
                root=Path(config['jobroot'])/SIGNING;journal=root/'owner-journal.json'
                state=caller_state(c,config,end)
                if not state['signing_attempted'] and not root.exists():
                    return {**result,'status':'NOT STARTED','agent_absent':True,'keyhome_absent':True,'reason':'not-started'}
                record=journal_record(c,journal,config,end);bound(root,record['nodes']['root'])
                selected=policy(c,record['policy_path'],record['policy_sha256'],config,end)
                home=root/'keyhome';need(record['agent_argv']==argv(home),'signer-journal-command')
                unknown=record['agent'] is None and record['launch_attempted']
                if unknown:
                    record['sticky_uncertain']=True;write(c,journal,record)
                expected=record['agent'] or _SPAWNS.get(str(journal));observed=process(expected['pid']) if expected else None
                need(not unknown or expected is not None,'signer-unbound-agent')
                if observed is not None and observed['state']=='Z':
                    need(all(observed[k]==expected[k] for k in ('pid','start','group','session','uid','gid')), 'signer-agent-drift')
                elif observed is not None:
                    if unknown:
                        need(all(observed[k]==expected[k] for k in expected) and observed.get('exe') in ('/usr/bin/python3.12','/usr/bin/gpg-agent'), 'signer-spawn-drift')
                    else:agent_matches(observed,expected,config,record['agent_argv'])
                    need(hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'),'signer-pidfd-required')
                    pidfd=os.pidfd_open(expected['pid'],0)
                    try:
                        again=process(expected['pid'])
                        if unknown:need(again is not None and all(again[k]==expected[k] for k in expected), 'signer-spawn-drift')
                        else:agent_matches(again,expected,config,record['agent_argv'])
                        with selectors.DefaultSelector() as selector:
                            selector.register(pidfd,selectors.EVENT_READ)
                            for signum in (signal.SIGTERM,signal.SIGKILL):
                                live(end);signal.pidfd_send_signal(pidfd,signum)
                                if selector.select(min(2,end-time.monotonic())):break
                            else:raise ValueError('signer-agent-removal-uncertain')
                    finally:os.close(pidfd)
                result['agent_absent']=True
                running=_PROCESSES.get(str(journal))
                if running is not None:
                    running.wait(timeout=min(1,end-time.monotonic()));_PROCESSES.pop(str(journal),None)
                _SPAWNS.pop(str(journal),None)
                held=_SOCKETS.get(str(journal))
                if held is not None:release_listener(journal,record,end)
                if record['socket'] is not None:
                    name=home/'S.gpg-agent';bound(home,record['nodes']['keyhome'])
                    try:socket_info=name.lstat()
                    except FileNotFoundError:pass
                    else:
                        need(stat.S_ISSOCK(socket_info.st_mode) and [socket_info.st_dev,socket_info.st_ino,socket_info.st_uid,
                            socket_info.st_gid,stat.S_IMODE(socket_info.st_mode)]==record['socket']['identity'],'signer-agent-socket')
                        name.unlink()

                ownerref=record['key_owner']
                if ownerref is not None:
                    need(ownerref['path']==str(root/'key-owner.json'),'signer-owner-path')
                    ownerinfo=Path(ownerref['path']).lstat()
                    need(stat.S_ISREG(ownerinfo.st_mode) and ownerinfo.st_uid==os.getuid() and ownerinfo.st_gid==os.getgid() and ownerinfo.st_nlink==1
                        and stat.S_IMODE(ownerinfo.st_mode)==0o600,'signer-owner-custody')
                    owner=c.decode(c.pinned(Path(ownerref['path']),ownerref['sha256'],deadline=end))
                    cert=root/'public/public-key.asc';bound(cert.parent,record['nodes']['public']);certinfo=cert.lstat()
                    need(stat.S_ISREG(certinfo.st_mode) and certinfo.st_uid==os.getuid() and certinfo.st_gid==os.getgid()
                        and certinfo.st_nlink==1 and stat.S_IMODE(certinfo.st_mode)==0o644,'signer-certificate-custody')
                    certbody=c.read(cert,65536,deadline=end)
                    need(certbody.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----') and b'PRIVATE KEY' not in certbody,'signer-public-certificate')
                    need(set(owner)=={'schema_version','owner','fingerprint','certificate','certificate_sha256','keyhome','gpg_sha256','repo_add_sha256'}
                        and type(owner['schema_version']) is int and owner['schema_version']==1
                        and owner['owner']=='TEST-'+config['nonce'] and type(owner['fingerprint']) is str
                        and re.fullmatch('[A-F0-9]{40}',owner['fingerprint'])
                        and owner['certificate']==str(cert) and owner['keyhome']==str(home)
                        and owner['gpg_sha256']==selected['tools']['/usr/bin/gpg']['sha256']
                        and owner['repo_add_sha256']==selected['producer']['sha256']
                        and owner['certificate_sha256']==record['certificate_sha256']
                        and hashlib.sha256(certbody).hexdigest()==record['certificate_sha256'], 'signer-owner-certificate')
                if home.exists():remove_home(home,record['nodes']['keyhome'],end)
                need(not home.exists() and not home.is_symlink(),'signer-keyhome-absence')
                result['keyhome_absent']=True
                if (root/'runtime').exists():remove_home(root/'runtime',record['nodes']['runtime'],end)
                record['phase']='disposed';write(c,journal,record);live(end)
                need(record['sticky_uncertain'] is False,'signer-sticky-uncertainty')
                result.update(status='PASS',reason='disposed',key_owner=ownerref)
            except BaseException as error:
                result['cancelled']=isinstance(error,(producer.jr.Cancelled,KeyboardInterrupt))
                result['reason']='cancelled' if result['cancelled'] else 'refused'
            finally:
                if record is not None and journal is not None and str(journal) in _SOCKETS:
                    try:release_listener(journal,record,end)
                    except BaseException:result.update(status='FAIL',reason='refused',key_owner=None)
        return result

    def prepared_custody(c, config, end):
        """Validate prepared custody each poll using the existing guards, no new clock."""
        live(end)
        root=Path(config['jobroot'])/SIGNING
        record=journal_record(c,root/'owner-journal.json',config,end)
        need(type(config.get('addon_profile')) is str and config['addon_profile']==PROFILE
             and type(config.get(KEY_REF)) is dict
             and record['phase']=='prepared' and record['sticky_uncertain'] is False
             and record['launch_attempted'] is True and record['key_owner']==config.get(KEY_REF),
             'signer-prepared-custody')
        for name,path in (('root',root),('keyhome',root/'keyhome'),('public',root/'public'),('runtime',root/'runtime')):
            bound(path,record['nodes'][name])
        home=root/'keyhome';name=home/'S.gpg-agent';row=record['socket']
        need(row is not None and row['path']==str(name) and record['agent_argv']==argv(home), 'signer-agent-socket')
        info=name.lstat()
        observed=[info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)]
        need(stat.S_ISSOCK(info.st_mode) and observed==row['identity'],'signer-agent-socket')
        need(type(record['agent']) is dict and type(record['agent'].get('pid')) is int,'signer-agent-identity')
        agent_matches(process(record['agent']['pid']),record['agent'],config,record['agent_argv'])
        live(end)
        return name,tuple(observed)

    return SimpleNamespace(need=need,live=live,directory=directory,bound=bound,write=write,file=file,elf_dependencies=elf_dependencies,policy=policy,process=process,identity=identity,agent_matches=agent_matches,caller_state=caller_state,argv=argv,manifest=manifest,journal_record=journal_record,check_policy=check_policy,start=start,prepare=prepare,remove_home=remove_home,release_listener=release_listener,recover=recover,prepared_custody=prepared_custody,ROOT=ROOT,ADDON=ADDON,PROFILE=PROFILE,PURPOSE=PURPOSE,PRODUCER=PRODUCER,SCOPE=SCOPE,SIGNING=SIGNING,KEY_REF=KEY_REF,NAME=NAME,ADDON_SCOPE=ADDON_SCOPE,MANIFEST=MANIFEST,TOOLS=frozenset(TOOLS),_PROCESSES=_PROCESSES,_SOCKETS=_SOCKETS,_SPAWNS=_SPAWNS)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root controller for two exclusively owned finite hosted domains; opt-in only."""
import argparse
import grp
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import resource
import select
import shutil
import signal
import stat
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('llhttp-reference_v2_data',HERE/'data.py');D=importlib.util.module_from_spec(s);s.loader.exec_module(D)
s=importlib.util.spec_from_file_location('llhttp-reference_v2_host_tools',HERE/'host_tools.py');H=importlib.util.module_from_spec(s);s.loader.exec_module(H)
s=importlib.util.spec_from_file_location('llhttp_go_cli_va_v2',HERE/'go_cli_va.py');V=importlib.util.module_from_spec(s);s.loader.exec_module(V)
s=importlib.util.spec_from_file_location('llhttp_failed_retirement_v3',HERE/'failed_retirement.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)
s=importlib.util.spec_from_file_location('llhttp_source_readonly_v6',HERE/'source_readonly.py');Q=importlib.util.module_from_spec(s);s.loader.exec_module(Q)
s=importlib.util.spec_from_file_location('llhttp_public_evidence_v6',HERE/'public_evidence.py');E=importlib.util.module_from_spec(s);s.loader.exec_module(E)
s=importlib.util.spec_from_file_location('native349_public_carrier',HERE/'native349_carrier.py');N=importlib.util.module_from_spec(s);s.loader.exec_module(N)
LIMIT_FILES=('memory.max','memory.swap.max','pids.max','cpu.max')


def write(path,value,uid=None,gid=None):
    raw=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw)
    if uid is not None:os.chown(path,uid,gid)


def proc(pid):
    fields=Path('/proc/'+str(pid)+'/stat').read_text().rpartition(')')[2].split()
    return int(fields[19]),Path('/proc/'+str(pid)+'/cgroup').read_text().strip()[3:]


class Controller:
    def __init__(self,root,out,policy,nonce,uid,gid):
        self.root,self.out,self.policy,self.nonce,self.uid,self.gid=root,out,policy,nonce,uid,gid
        self.started=time.monotonic();self.end=self.started+policy['controller_work_seconds'];self.cleanup_end=self.end+policy['cleanup_seconds']
        self.cleaning=False;self.commands=[];self.units={};self.pidfds={};self.loop=None;self.mounted=False
        self.host_facts={};self.tools={};self.host_policy={}
        path=root/'held-source'/D.BASE_PREFIX/'runtime/owned_process.py'
        spec=importlib.util.spec_from_file_location('llhttp-reference_v2_owned_process',path);self.O=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.O);self.O.prepare()

    def run(self,args,seconds=30,check=True):
        D.need(args and any(row['path']==args[0] for row in self.tools.values()),'qualified absolute controller executable')
        for row in self.tools.values():
            if row['path']==args[0]:H.checked(row)
        D.need(len(self.commands)<512,'finite controller command count')
        cap=min(seconds,(self.cleanup_end if self.cleaning else self.end)-time.monotonic())
        D.need(cap>1,'whole owner deadline expired')
        D.need(resource.getrlimit(resource.RLIMIT_AS)==V.controller_limit(self.policy),'same finite controller soft/hard VA ceiling before launch')
        address_space=V.child_plan(args,self.tools,self.policy)
        child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=V.child_limits(address_space),
                               env={'PATH':'/usr/bin:/bin','HOME':str(self.out),'LC_ALL':'C','DOCKER_BUILDKIT':'0'},start_new_session=True)
        row=self.O.supervise(child,cap=cap,retirement=.5,grace=.1,max_output=1024**2)
        body=row.pop('output');self.commands.append(dict(argv=args,address_space=address_space,retirement=row,output=D.pin(body)))
        (self.out/('command-%03d.bin'%len(self.commands))).write_bytes(body)
        write(self.out/('command-%03d.json'%len(self.commands)),self.commands[-1])
        D.need(row['reaped'] is True and row['ownership']=='REAPED' and row['group_census']=='EMPTY_TWICE'
               and row['output_complete'] is True and not row['signals'] and not row['timeout'] and row['error'] is None
               and type(row['exit']) is int and (row['exit']==0 if check else row['exit']>=0),
               'natural complete controller child retirement')
        return row['exit'],body

    def record_host_policy(self,value):
        path=self.out/'host-policy.json';temporary=self.out/'host-policy.partial'
        raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode();D.need(len(raw)<=1024**2,'bounded complete existing-host policy receipt')
        if path.exists():
            info=path.lstat();D.need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600,'same own host-policy receipt')
        fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'wb')as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,path)
        finally:
            if temporary.exists():temporary.unlink() # Only this invocation's fixed exclusive temporary.

    def capacity(self):
        p=self.policy;available=int(next(s.split()[1]for s in Path('/proc/meminfo').read_text().splitlines()if s.startswith('MemAvailable:')))*1024
        D.need(available>=p['minimum_available_bytes']and shutil.disk_usage(self.out).free>=p['minimum_disk_bytes'],'fresh complete controller/pair memory/disk admission')
        return available

    def tool(self,name):
        D.need(name in self.tools,'observed required host tool: '+name)
        return H.checked(self.tools[name])

    def preflight(self):
        self.host_facts=H.probe_all()
        self.tools={name:row['selected'] for name,row in self.host_facts['tools'].items() if row['selected'] is not None}
        facts=self.host_facts
        facts['observed_epoch']=int(time.time())
        facts['systemd']={"minimum_version":254,"version":None,"minimum_met":False}
        if 'systemctl' in self.tools:
            try:
                code,raw=self.run([self.tool('systemctl'),'--version'],10,check=False)
                match=re.match(rb'systemd ([0-9]+)\b',raw)
                version=int(match[1]) if match and code==0 else None
                facts['systemd'].update(exit=code,output=D.pin(raw),text=raw[:4096].decode('utf-8','replace'),
                                         version=version,minimum_met=version is not None and version>=254)
            except Exception as error:
                facts['systemd']['error']=dict(type=type(error).__name__,message=str(error)[:240])
        capabilities={}
        for name,path in (('cgroup_controllers',Path('/sys/fs/cgroup/cgroup.controllers')),
                          ('effective_capabilities',Path('/proc/self/status'))):
            try:
                # procfs/sysfs report synthetic sizes; bound the read itself.
                with path.open('rb') as stream:raw=stream.read(65537)
                D.need(len(raw)<=65536,'bounded kernel capability facts')
                capabilities[name]=raw.decode().split() if name=='cgroup_controllers' else next(line for line in raw.decode().splitlines() if line.startswith('CapEff:'))
            except Exception as error:capabilities[name]=dict(error=type(error).__name__)
        capabilities['systemd_runtime_directory']=Path('/run/systemd/system').is_dir()
        try:
            info=Path('/dev/loop-control').stat()
            capabilities['loop_control']=dict(present=True,character_device=stat.S_ISCHR(info.st_mode),uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode))
        except OSError as error:capabilities['loop_control']=dict(present=False,error=type(error).__name__)
        facts['capabilities']=capabilities
        write(self.out/'host-tools.json',facts)
        D.need(not facts['missing_or_invalid'],'existing required host tools missing/invalid: '+','.join(facts['missing_or_invalid']))
        D.need(facts['systemd']['minimum_met'],'actual systemd254+ required for DelegateSubgroup')
        D.need(type(capabilities['cgroup_controllers']) is list and {'cpu','memory','pids'}<=set(capabilities['cgroup_controllers']),
               'unified kernel controllers required')
        D.need(capabilities['systemd_runtime_directory'],'actual systemd runtime directory required')
        D.need(capabilities['loop_control'].get('character_device') is True,'existing loop-control character device required')

    def show(self,kind):
        _,raw=self.run([self.tool('systemctl'),'show',D.unit(self.nonce,kind),'--no-pager',
                        '--property=LoadState,ActiveState,SubState,Result,MainPID,ControlGroup,ExecMainCode,ExecMainStatus,Description'],check=False)
        result=dict(line.split('=',1) for line in raw.decode().splitlines() if '=' in line)
        return result

    def start(self,kind,command,uid=None,gid=None):
        prior=self.show(kind);D.need(prior.get('LoadState')=='not-found','fresh exclusive unit name')
        D.need(any(row['path']==command[0] for row in self.tools.values()),'qualified observed service executable')
        for row in self.tools.values():
            if row['path']==command[0]:H.checked(row)
        argv=D.service_args(self.nonce,kind,self.policy[kind],command,self.out/'volume'/(kind+'.log'),uid,gid)
        argv[0]=self.tool('systemd-run')
        argv.insert(3,'--description=cachy-llhttp-reference-owned-'+self.nonce+'-'+kind)
        launcher=H.checked(self.tools['python3']) if kind=='daemon' else None
        argv=Q.project_service(argv,self.root,self.out,self.nonce,kind,launcher=launcher)
        # Preserve uncertain submission in cleanup, even when systemd-run itself fails.
        self.units[kind]=dict(submitted=True,cgroup=None)
        self.run(argv)
        until=min(self.end,time.monotonic()+30)
        expected='/system.slice/'+D.unit(self.nonce,kind)
        final_group=expected+'/daemon' if kind=='daemon' else expected
        observed=None
        while time.monotonic()<until:
            row=self.show(kind)
            if row.get('MainPID','0')!='0' and row.get('ActiveState')=='active':
                pid=int(row['MainPID'])
                D.need(row['Description']=='cachy-llhttp-reference-owned-'+self.nonce+'-'+kind and row['ControlGroup']==expected
                       and (observed is None or pid==observed[0]),'same exact owned service/cgroup')
                if observed is None:
                    fd=os.pidfd_open(pid,0)
                    self.pidfds[kind]=fd
                    self.units[kind].update(cgroup=expected,original_pidfd=fd,original_pidfd_identity=F.pidfd_identity(fd))
                else:
                    fd=self.pidfds[kind]
                poll=select.poll();poll.register(fd,select.POLLIN)
                D.need(not poll.poll(0),'same live newly started service PID')
                start,cgroup=proc(pid)
                D.need(observed is None or observed==(pid,start),'same original service MainPID and starttime across exec')
                observed=(pid,start)
                executable=Path('/proc/'+str(pid)+'/exe').resolve()
                if kind=='daemon' and executable==Path(launcher):
                    D.need(cgroup in (expected,final_group),'same exact owned delegated launcher cgroup')
                    time.sleep(min(.1,max(0.0,until-time.monotonic())))
                    continue
                D.need(executable==Path(self.tool('dockerd' if kind=='daemon' else 'python3'))
                       and (cgroup==final_group or kind=='daemon' and cgroup==expected and proc(pid)==(start,final_group))
                       and not poll.poll(0),'exact observed service executable and final cgroup')
                limits={k:(Path('/sys/fs/cgroup'+expected)/k).read_text().strip() for k in LIMIT_FILES}
                D.domain(limits,self.policy[kind])
                actual=dict(pid=pid,starttime=start,cgroup=expected,limits=limits)
                self.units[kind].update(actual)
                return actual
            D.need(row.get('ActiveState') not in ('failed','inactive'),'service failed before observed admission')
            time.sleep(min(1.0,max(0.0,until-time.monotonic())))
        raise TimeoutError('owned service startup deadline')

    def docker(self,*args,check=True):
        return self.run([self.tool('docker'),'--host=unix://'+str(self.out/'volume/docker.sock'),*args],30,check)

    def setup(self):
        self.capacity()
        self.end=min(self.end,time.monotonic()+self.policy['pair_seconds']);self.cleanup_end=self.end+self.policy['cleanup_seconds']
        self.preflight() # Existing12 tools only; no package manager/tool acquisition.
        self.host_policy=dict(status='PASS_EXISTING_HOST_TOOLS_ONLY',declaration=self.policy['host_tools'],commands=[],package_manager_invocations=0,host_package_mutations=0,tools=sorted(self.tools))
        D.existing_host(self.host_policy,self.policy)
        self.record_host_policy(self.host_policy)
        p=self.policy;available=self.capacity()
        D.need(available>=p['minimum_available_bytes'] and shutil.disk_usage(self.out).free>=p['minimum_disk_bytes'],
               'new separately reviewed aggregate memory/storage admission')
        D.need(p['minimum_available_bytes']>=p['owner']['memory_bytes']+p['daemon']['memory_bytes']+p['host_reserve_bytes']
               and p['minimum_disk_bytes']>=p['storage_bytes']+p['host_reserve_bytes'],'aggregate policy inequality')
        image=self.out/'storage.img';fd=os.open(image,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        self.run([self.tool('fallocate'),'--length',str(p['storage_bytes']),'--',str(image)],60)
        D.need(image.stat().st_size==p['storage_bytes'] and image.stat().st_blocks*512>=p['storage_bytes'],'physically allocated fixed storage reservation')
        _,raw=self.run([self.tool('losetup'),'--find','--show','--nooverlap',str(image)])
        device=raw.decode().strip();D.need(re.fullmatch('/dev/loop[0-9]+',device),'owned loop device')
        self.loop=device;self.loop_identity()
        self.run([self.tool('mkfs.ext4'),'-t','ext4','-q','-m','0',device],60)
        volume=self.out/'volume';volume.mkdir(mode=0o755)
        self.run([self.tool('mount'),'-t','ext4','-o','nodev,nosuid',device,str(volume)]);self.mounted=True
        # Work and daemon storage share the same finite filesystem; no sparse quota claim.
        for name in ('work','data','exec'):(volume/name).mkdir(mode=0o700)
        os.chown(volume/'work',self.uid,self.gid)
        (volume/'work/tmp').mkdir(mode=0o700);os.chown(volume/'work/tmp',self.uid,self.gid)
        (volume/'exec/tmp').mkdir(mode=0o700)
        write(volume/'daemon.json',{})
        cg='/system.slice/'+D.unit(self.nonce,'daemon')+'/containers'
        argv=[self.tool('dockerd'),'--config-file='+str(volume/'daemon.json'),'--host=unix://'+str(volume/'docker.sock'),
              '--data-root='+str(volume/'data'),'--exec-root='+str(volume/'exec'),'--pidfile='+str(volume/'docker.pid'),
              '--group='+grp.getgrgid(self.gid).gr_name,'--storage-driver=overlay2','--exec-opt=native.cgroupdriver=cgroupfs',
              '--cgroup-parent='+cg,'--default-cgroupns-mode=private','--bridge=none','--iptables=false',
              '--ip6tables=false','--ip-forward=false','--ip-masq=false','--userland-proxy=false']
        host_shim=Q.managed_shim_host()
        daemon=self.start('daemon',argv)
        parent=Path('/sys/fs/cgroup'+daemon['cgroup'])
        for group in (parent,parent/'containers'):
            D.need(Q.CGROUP_CONTROLLERS<=set(Q.managed_read(group/'cgroup.subtree_control',4096).split()),
                   'same exact host-coordinate controllers enabled before daemon exec')
        D.need(bool(Q.managed_read(parent/'daemon/memory.swap.max',32).strip()),
               'daemon host-coordinate leaf has its actual swap control')
        until=min(self.end,time.monotonic()+30)
        while not (volume/'docker.sock').exists():
            D.need(time.monotonic()<until,'scoped daemon socket startup');time.sleep(.1)
        socket=(volume/'docker.sock').stat()
        D.need(stat.S_ISSOCK(socket.st_mode) and socket.st_uid==0 and socket.st_gid==self.gid
               and stat.S_IMODE(socket.st_mode)==0o660,'exact private socket ownership/mode')
        _,raw=self.docker('info','--format','{{json .}}');info=D.decode(raw)
        D.need(info['DockerRootDir']==str(volume/'data') and info['CgroupDriver']=='cgroupfs'
               and info['Driver']=='overlay2' and info['MemoryLimit'] is True and info['SwapLimit'] is True
               and info['PidsLimit'] is True and info['CpuCfsQuota'] is True,
               'actual dedicated daemon endpoint/storage/driver and inner resource support')
        daemon['managed_containerd']=Q.observe_managed_containerd(volume,daemon['pid'],daemon['starttime'],daemon['cgroup']+'/daemon')
        D.need(Q.managed_shim_host()==host_shim,'same host shim mount point outside private daemon namespace')
        daemon['engine_id']=info['ID'];return daemon,available,shutil.disk_usage(volume).free

    def loop_identity(self):
        _,raw=self.run([self.tool('losetup'),'--json','--list','--output','NAME,BACK-FILE',self.loop])
        devices=D.decode(raw)['loopdevices']
        D.need(len(devices)==1 and devices[0]['name']==self.loop and devices[0]['back-file']==str(self.out/'storage.img'),
               'same exact owned loop backing file')

    def stop(self,kind):
        if kind not in self.units:return dict(submitted=False)
        row=self.show(kind);owned=self.units[kind]
        if row.get('LoadState')!='not-found':
            D.need(row.get('Description')=='cachy-llhttp-reference-owned-'+self.nonce+'-'+kind,'owned unit before stop')
            if owned.get('cgroup'):D.need(row.get('ControlGroup') in ('',owned['cgroup']),'same unit cgroup before stop')
            self.run([self.tool('systemctl'),'stop',D.unit(self.nonce,kind)],20)
        censuses=[]
        for _ in range(2):
            current=self.show(kind)
            D.need(current.get('ActiveState') in ('inactive','failed') or current.get('LoadState')=='not-found','owned service absent')
            cgroup=owned.get('cgroup') or '/system.slice/'+D.unit(self.nonce,kind)
            snapshot=F.empty_snapshot(Path('/sys/fs/cgroup'+cgroup));exited=False
            if kind in self.pidfds:
                exited=F.pidfd_exited(self.pidfds[kind],owned.get('original_pidfd_identity'))
                D.need(exited,'original service PIDFD exited')
            censuses.append(dict(cgroup=cgroup,pidfd_exited=exited,**snapshot));time.sleep(.05)
        if current.get('Result')not in(None,'success')and current.get('LoadState')!='not-found':
            return F.retire_failed(kind,self.nonce,owned,row,current,self.pidfds.get(kind),censuses)
        D.need(current.get('Result') in (None,'success') or current.get('LoadState')=='not-found','no forced/timeout service retirement')
        return dict(unit=D.unit(self.nonce,kind),empty_twice=True,pidfd_exited=kind in self.pidfds,
                    state=current.get('ActiveState'),result=current.get('Result'))

    def cleanup(self):
        self.cleaning=True;self.cleanup_end=min(self.cleanup_end,time.monotonic()+90);rows={};errors=[]
        for kind in ('owner','daemon'):
            try:rows[kind]=self.stop(kind)
            except BaseException as error:errors.append(dict(step=kind,error=type(error).__name__))
        # Bounded complete logs after both services stop, before their quota filesystem disappears.
        for kind in ('owner','daemon'):
            path=self.out/'volume'/(kind+'.log')
            if self.mounted and path.exists():
                try:(self.out/(kind+'.log')).write_bytes(D.read(path,16*1024**2,empty=True))
                except BaseException as error:errors.append(dict(step=kind+'-log',error=type(error).__name__))
        # Never unmount/detach uncertain live service storage.
        if not errors:
            try:
                image=self.out/'storage.img'
                if image.exists():
                    _,raw=self.run([self.tool('losetup'),'--json','--list','--associated',str(image),'--output','NAME,BACK-FILE'])
                    found=D.decode(raw)['loopdevices'];D.need(len(found)<=1,'at most one exclusively owned loop association')
                    if found:
                        D.need(found[0]['back-file']==str(image) and re.fullmatch('/dev/loop[0-9]+',found[0]['name']),'same associated loop backing file')
                        self.loop=found[0]['name']
                volume=self.out/'volume'
                self.mounted=volume.exists() and os.path.ismount(volume)
                if self.mounted:
                    D.need(self.loop is not None and volume.stat().st_dev==Path(self.loop).stat().st_rdev,'same exact owned mounted block device')
                    self.run([self.tool('umount'),str(self.out/'volume')],20);self.mounted=False
                if self.loop:
                    self.loop_identity();self.run([self.tool('losetup'),'--detach',self.loop]);self.loop=None
                    _,raw=self.run([self.tool('losetup'),'--json','--list','--associated',str(image),'--output','NAME,BACK-FILE'])
                    D.need(not D.decode(raw)['loopdevices'],'owned loop backing association absent after detach')
                image=self.out/'storage.img'
                if image.exists():image.unlink()
            except BaseException as error:errors.append(dict(step='owned-storage',error=type(error).__name__))
        for fd in self.pidfds.values():os.close(fd)
        return dict(services=rows,errors=errors,host_package_mutations=0,owned_storage_absent=not self.mounted and self.loop is None and not (self.out/'storage.img').exists())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('root','output','carrier-root'):parser.add_argument('--'+name,type=Path,required=True)
    for name in ('source-map-sha256','admission-sha256','runtime-sha256'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--runner-uid',type=int,required=True);parser.add_argument('--runner-gid',type=int,required=True);a=parser.parse_args()
    D.need(sys.flags.isolated and __debug__ and os.getuid()==os.geteuid()==0 and platform.machine() in ('aarch64','arm64'),
           'isolated root controller on genuine native ARM required')
    D.need(a.runner_uid>0 and a.runner_gid>0 and re.fullmatch(r'/[A-Za-z0-9_./-]+',str(a.output)) and re.fullmatch(r'/[A-Za-z0-9_./-]+',str(a.root)) and a.root==a.root.resolve() and a.output==a.output.resolve()
           and not a.output.exists() and not a.output.is_relative_to(a.root),'fresh disjoint exact operation output')
    admission_raw=os.environ.pop('ROOT_LLHTTP_REFERENCE_ADMISSION_JSON','').encode();runtime_raw=os.environ.pop('ROOT_LLHTTP_REFERENCE_RUNTIME_JSON','').encode()
    actual,runtime=D.admission(a.root,a.source_map_sha256,admission_raw,runtime_raw,a.admission_sha256,a.runtime_sha256,os.environ,int(time.time()))
    policy=D.decode(D.read(HERE/'policy.json'))
    resource.setrlimit(resource.RLIMIT_AS,V.controller_limit(policy));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    controller_group='/system.slice/cachy-llhttp-reference-controller-'+os.environ['GITHUB_RUN_ID']+'-1.scope'
    controller_start,actual_group=proc(os.getpid())
    D.need(actual_group==controller_group,'external finite controller scope required')
    controller_limits={k:(Path('/sys/fs/cgroup'+actual_group)/k).read_text().strip() for k in LIMIT_FILES}
    D.domain(controller_limits,policy['controller'])
    os.umask(0o077);a.output.mkdir(mode=0o711);os.chmod(a.output,0o711)
    owner=Controller(a.root,a.output,policy,actual['nonce'],a.runner_uid,a.runner_gid)
    report=dict(status='HOLD',source=actual['source'],ref=actual['ref'],source_map_sha256=a.source_map_sha256,
                admission=D.pin(admission_raw),runtime=D.pin(runtime_raw),policy=D.pin(D.read(HERE/'policy.json')),
                run=os.environ['GITHUB_RUN_ID'],attempt=1,job=os.environ['GITHUB_JOB'],Root_acceptance=None,native_pair='NOT RUN',
                controller=dict(pid=os.getpid(),starttime=controller_start,cgroup=actual_group,limits=controller_limits))
    def cancelled(signum,frame):raise TimeoutError('external whole operation deadline/cancellation')
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM):signal.signal(sig,cancelled)
    signal.setitimer(signal.ITIMER_REAL,policy['controller_work_seconds'])
    try:
        daemon,available,disk=owner.setup();volume=a.output/'volume';work=volume/'work';marker=work/'actual-owner.json'
        report['pinned_input_carrier']=N.stage(a.carrier_root,work/'native349-pinned-inputs',a.runner_uid,a.runner_gid)
        allowed={k:v for k,v in os.environ.items() if k.startswith(('GITHUB_','CACHY_RETAINED_','CACHY_OLD_FOUR_'))
                 or k in ('PATH','ImageOS','ImageVersion','RUNNER_OS','RUNNER_ARCH')}
        allowed.update(PATH='/usr/bin:/bin',HOME=str(work),RUNNER_TEMP=str(work),TMPDIR=str(work/'tmp'))
        config=dict(source_root=str(a.root),source_map_sha256=a.source_map_sha256,admission_raw=admission_raw.decode(),runtime_raw=runtime_raw.decode(),
                    admission_sha256=a.admission_sha256,runtime_sha256=a.runtime_sha256,environment=allowed,
                    marker=str(marker),output=str(work/'llhttp-reference-native'),pinned_inputs=str(work/'native349-pinned-inputs'))
        launch=work/'launch.json';write(launch,config,a.runner_uid,a.runner_gid)
        payload=owner.start('owner',[owner.tool('python3'),'-I','-B',str(HERE/'payload.py'),str(launch)],a.runner_uid,a.runner_gid)
        observed=dict(kind='LLHTTP_REFERENCE_ACTUAL_HOSTED_DOMAINS_V2',source=actual['source'],ref=actual['ref'],nonce=actual['nonce'],
                      source_map_sha256=a.source_map_sha256,run=os.environ['GITHUB_RUN_ID'],attempt=1,job=os.environ['GITHUB_JOB'],
                      owner=payload,daemon=daemon,host_policy=dict(owner.host_policy,receipt=D.pin(D.read(a.output/'host-policy.json'))),endpoint='unix://'+str(volume/'docker.sock'),storage_bytes=policy['storage_bytes'],
                      available_memory=available,available_storage=disk,backend=policy['bootstrap_backend'])
        write(a.output/'actual-domains.json',observed);write(marker,observed,a.runner_uid,a.runner_gid)
        while True:
            D.need(time.monotonic()<owner.end,'external whole owner/acquisition deadline')
            row=owner.show('owner')
            if row.get('SubState')=='exited' or row.get('ActiveState') in ('inactive','failed') or row.get('LoadState')=='not-found':
                D.need(row.get('Result')=='success' and row.get('ExecMainCode')=='1' and row.get('ExecMainStatus')=='0','ordinary payload natural success required')
                break
            time.sleep(min(10.0,max(0.0,owner.end-time.monotonic())))
        evidence=work/'llhttp-reference-native/evidence';D.need(evidence.is_dir(),'complete inherited pair evidence required')
        inherited=D.decode(D.read(evidence/'report.json'))
        D.need(inherited['status']=='PASS_CURRENT_MD4C053_REFERENCE_NATIVE_PAIR_ONLY' and inherited['source']==actual['source']
               and inherited['source_map_sha256']==a.source_map_sha256,'same actual pair Source/report')
        _,containers=owner.docker('ps','--all','--quiet');D.need(not containers.strip(),'owned daemon has no remaining containers')
        # Strict finite public outputs are exported in finally before storage cleanup.
        report.update(status='PAIR_PASSED_PENDING_EXTERNAL_CLEANUP',native_pair=inherited['status'])
    except BaseException as error:report['failure']=dict(type=type(error).__name__,message=str(error)[:500])
    finally:
        E.preserve(report,a.output/'volume/work/llhttp-reference-native',a.output/'evidence',
                   dict(source=actual['source'],ref=actual['ref'],source_map_sha256=a.source_map_sha256,
                        run=os.environ['GITHUB_RUN_ID'],attempt=1,job=os.environ['GITHUB_JOB'],nonce=actual['nonce']),a.runner_uid)
        report['host_preflight']=owner.host_facts
        report['host_policy']=owner.host_policy
        if owner.host_policy:
            try:owner.record_host_policy(owner.host_policy)
            except BaseException:report['host_policy_report_failure']=True
        signal.setitimer(signal.ITIMER_REAL,90)
        try:report['cleanup']=owner.cleanup()
        except BaseException as error:report['cleanup']=dict(errors=[dict(type=type(error).__name__)])
        signal.setitimer(signal.ITIMER_REAL,0)
        if report['status']=='PAIR_PASSED_PENDING_EXTERNAL_CLEANUP' and not report['cleanup']['errors'] and report['cleanup']['owned_storage_absent']:
            report['status']='PASS_CURRENT_MD4C053_REFERENCE_NATIVE_PAIR_EXTERNAL_DOMAINS_ONLY'
        else:report['status']='HOLD'
        write(a.output/'owner-report.json',report)
        # Publish only bounded, selected receipts. Failed mounted storage stays root-owned/private.
        selected=[p for p in a.output.iterdir() if p.is_file() and p.name!='storage.img']
        public=a.output/'evidence'
        if public.exists():selected.extend(p for p in public.rglob('*') if p.is_file())
        D.need(len(selected)<4096,'finite selected public receipt namespace')
        for path in selected:
            D.need(not path.is_symlink(),'ordinary selected controller receipt')
            os.chown(path,a.runner_uid,a.runner_gid);path.chmod(0o600)
        if public.exists():
            for path in sorted([p for p in public.rglob('*') if p.is_dir()],reverse=True):
                os.chown(path,a.runner_uid,a.runner_gid);path.chmod(0o700)
            os.chown(public,a.runner_uid,a.runner_gid);public.chmod(0o700)
        os.chown(a.output,a.runner_uid,a.runner_gid);a.output.chmod(0o700)
    print(json.dumps(dict(status=report['status'],Root_acceptance=None)),flush=True)
    return 0 if report['status']=='PASS_CURRENT_MD4C053_REFERENCE_NATIVE_PAIR_EXTERNAL_DOMAINS_ONLY' else 1


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as error:print('HOLD_OWNER: '+type(error).__name__,file=sys.stderr);raise SystemExit(2)

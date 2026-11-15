# SPDX-License-Identifier: MIT
"""Independent passive namespace DATA classifier; importing it executes no role."""
import hashlib
import json
import math
from pathlib import Path
import re

DOMAIN='PERL_ARM_CAP0_NNP_RO_CONTAINER_V1'
DOMAIN_SHA='6c6bdc29acf59e8ea911167f08d4d66a993777c121b2399211cec030e2a5b804'
OLD_SOURCE='3937d8b9f3210f4e9868bf19f01dfa22de64ddfe'
CASES=('bwrap-user-mount-net','unshare-mapped-root')
OPERATION='perl5423-native-namespace-v1'
FRAME=b'PERL_NATIVE_NAMESPACE_V1 '
LIMITS={'cpu.max':'200000 100000','memory.max':'4294967296','memory.swap.max':'0','pids.max':'256'}
TMPFS={'/run':'rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001','/tmp':'rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001'}


def need(ok,why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()


def digest(value,size=64):return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',value) is not None


def decode(raw,cap=1024**2):
    need(type(raw) is bytes and len(raw)<=cap,'bounded raw DATA')
    def unique(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate JSON key');result[key]=value
        return result
    def number(value):
        result=float(value);need(math.isfinite(result),'finite number');return result
    def invalid(value):raise ValueError('nonfinite number')
    try:value=json.loads(raw,object_pairs_hook=unique,parse_float=number,parse_constant=invalid)
    except RecursionError as error:raise ValueError('DATA depth') from error
    pending=[(value,0)];count=0
    while pending:
        item,depth=pending.pop();count+=1;need(depth<=24 and count<=20000,'DATA structure bound')
        if type(item) is dict:pending.extend((v,depth+1) for v in item.values())
        elif type(item) is list:pending.extend((v,depth+1) for v in item)
    return value


def natural(row):
    need(type(row) is dict and row.get('natural_exit') is True and row.get('forced_cleanup') is False
        and row.get('retirement')=='REAPED' and row.get('group_absent') is True
        and row.get('leader_held_until_group_inspection') is True and row.get('ownership_lost') is False
        and row.get('exit_observed_via_waitpid') is True and type(row.get('exit')) is int,'natural direct owned retirement required')
    need(type(row.get('pid')) is int and 1<row['pid']<2**31,'owned leader PID')
    seconds=row.get('elapsed_seconds');need(type(seconds) in (int,float) and math.isfinite(seconds) and 0<=seconds<=28,'finite diagnostic command')
    return row['exit']


def maps(rows):
    need(type(rows) is list and 0<len(rows)<=8,'bounded complete namespace map')
    for row in rows:
        need(type(row) is list and len(row)==3 and all(type(x) is int and 0<=x<2**32 for x in row)
            and row[2]>0 and row[0]+row[2]<=2**32 and row[1]+row[2]<=2**32,'nonoverflowing map row')
    for index in (0,1):
        ordered=sorted(rows,key=lambda r:r[index])
        need(all(left[index]+left[2]<=right[index] for left,right in zip(ordered,ordered[1:])),'nonoverlapping namespace map')
    return rows


def admission(value):
    keys={'schema','operation','source','run','job','image','approval','source_map_sha256','domain_sha256','token','container','volume','inputs'}
    need(type(value) is dict and set(value)==keys and type(value['schema']) is int and value['schema']==1 and value['operation']==OPERATION,'exact Root diagnostic admission')
    need(digest(value['source'],40) and value['source']!=OLD_SOURCE,'separate actual qualification Source required')
    for name in ('run','job'):need(type(value[name]) is str and re.fullmatch('[1-9][0-9]{0,19}',value[name]),'actual run/job')
    need(type(value['image']) is str and re.fullmatch('sha256:[0-9a-f]{64}',value['image']),'immutable native image')
    need(all(digest(value[k]) for k in ('approval','source_map_sha256')) and value['domain_sha256']==DOMAIN_SHA and digest(value['token'],24),'Root source/domain/approval bindings')
    need(value['container']=='perl-namespace-'+value['run']+'-'+value['token'][:12] and value['volume']==value['container']+'-work','fixed owned resource names')
    path=value['inputs'];need(type(path) is str and re.fullmatch('/[A-Za-z0-9._+/-]{1,240}',path) and all(x not in ('','.','..') for x in path.split('/')[1:]),'canonical absolute host input path')
    return pin(encode(value))['sha256']


def create_argv(a):
    return ['/usr/bin/docker','--host=unix:///var/run/docker.sock','create','--name',a['container'],
        '--label','cachy-asahi.operation='+OPERATION,'--cpus=2','--memory=4g','--memory-swap=4g','--pids-limit=256',
        '--init','--read-only','--network=none','--hostname=perl5423-native','--cap-drop=ALL','--security-opt=no-new-privileges',
        '--user=1001:1001','--ulimit=nofile=1024:1024','--ulimit=core=0:0',
        *['--tmpfs='+name+':'+value for name,value in TMPFS.items()],
        '--mount','type=volume,src='+a['volume']+',dst=/work',
        '--mount','type=bind,src='+a['inputs']+',dst=/inputs,readonly',
        '--env','ADAPTER_ADMISSION_SHA256='+pin(encode(a))['sha256'],
        '--entrypoint=/usr/bin/bash',a['image'],'--noprofile','--norc','/inputs/entry.sh']


def host_data(host,a,sha):
    need(type(host) is dict and set(host)=={'binding_sha256','image_inspect','container_inspect','create_argv'} and host['binding_sha256']==sha,'Root authenticated host binding')
    need(host['create_argv']==create_argv(a),'exact adapter-domain create argv')
    image=host['image_inspect'];need(image['Id']==a['image'] and image['Architecture']=='arm64' and image['Os']=='linux' and not image.get('Config',{}).get('Volumes'),'native image/no anonymous volumes')
    row=host['container_inspect'];h=row['HostConfig'];c=row['Config']
    need(row['Name']=='/'+a['container'] and row['Image']==a['image'] and c['User']=='1001:1001' and c['Hostname']=='perl5423-native','actual same container/image/identity')
    need(c['Entrypoint']==['/usr/bin/bash'] and c['Cmd']==['--noprofile','--norc','/inputs/entry.sh'],'actual runtime entry')
    env=c['Env'];need(type(env) is list and [v for v in env if v.startswith('ADAPTER_ADMISSION_SHA256=')]==['ADAPTER_ADMISSION_SHA256='+sha],'actual operand environment')
    need(h['NanoCpus']==2000000000 and h['Memory']==h['MemorySwap']==4294967296 and h['PidsLimit']==256,'actual resource domain')
    need(h['NetworkMode']=='none' and h['ReadonlyRootfs'] is True and h['Init'] is True and h['CapDrop']==['ALL'] and not h.get('CapAdd') and h['SecurityOpt']==['no-new-privileges'] and h['Privileged'] is False and not h.get('Devices') and not h.get('DeviceRequests'),'actual capability/network/rootfs domain')
    need(h['Tmpfs']==TMPFS,'actual bounded tmpfs declarations')
    mount_list=row['Mounts'];need(type(mount_list) is list and len(mount_list)==2,'two actual explicit mounts')
    mounts={v['Destination']:v for v in mount_list};need(set(mounts)=={'/inputs','/work'},'exact mounted namespaces')
    need(mounts['/inputs']['Type']=='bind' and mounts['/inputs']['RW'] is False and mounts['/inputs']['Source']==a['inputs'],'actual readonly inputs bind')
    need(mounts['/work']['Type']=='volume' and mounts['/work']['RW'] is True and mounts['/work']['Name']==a['volume'],'actual private work volume')


def host_domain(host,a):host_data(host,a,admission(a))


def mount_data(raw):
    need(type(raw) is str and 0<len(raw.encode())<=128*1024,'bounded complete mountinfo')
    selected={}
    for line in raw.splitlines():
        sides=line.split(' - ');need(len(sides)==2,'literal mountinfo separator')
        left,right=sides[0].split(),sides[1].split();need(len(left)>=6 and len(right)==3,'literal mountinfo fields')
        target=left[4]
        if target not in ('/','/inputs','/work','/tmp','/run'):continue
        need(target not in selected,'unique observed required mount')
        selected[target]=(set(left[5].split(',')),right[0],set(right[2].split(',')))
    need(set(selected)=={'/','/inputs','/work','/tmp','/run'},'all actual required mounts')
    for name in ('/','/inputs'):need('ro' in selected[name][0] and 'rw' not in selected[name][0],'actual readonly mount')
    need('rw' in selected['/work'][0] and 'ro' not in selected['/work'][0],'actual writable work mount')
    for name,size in [('/tmp',64*1024**2),('/run',8*1024**2)]:
        opts,kind,sup=selected[name];need(kind=='tmpfs' and {'rw','noexec','nosuid','nodev'}<=opts and 'ro' not in opts,'actual bounded safe tmpfs')
        need({'uid=1001','gid=1001'}<=sup,'actual tmpfs ownership')
        values=[x[5:] for x in sup if x.startswith('size=')];need(len(values)==1,'actual tmpfs byte size')
        match=re.fullmatch('([1-9][0-9]*)([kKmMgG]?)',values[0]);need(match,'numeric tmpfs size')
        need(int(match[1])*{'':1,'k':1024,'m':1024**2,'g':1024**3}[match[2].lower()]==size,'actual exact tmpfs size')


def context(value,*,baseline=False):
    keys={'pid','ppid','pgrp','session','starttime','uid','euid','gid','egid','groups','architecture','page_bytes','cwd','exe','cmdline','namespaces','uid_map','gid_map','status','limits','cgroup','mountinfo','interfaces','hostname'}
    need(type(value) is dict and set(value)==keys,'exact observed process context')
    for key in ('pid','ppid','pgrp','session','uid','euid','gid','egid'):
        need(type(value[key]) is int and 0<=value[key]<2**31,'numeric process identity')
    need(value['pid']>0 and value['pgrp']>0 and value['session']>0,'live positive process identity')
    need(type(value['starttime']) is int and 0<value['starttime']<2**64,'positive actual process starttime')
    need(value['architecture']=='aarch64' and type(value['page_bytes']) is int and value['page_bytes'] in (4096,16384,65536),'actual native ARM/page observation')
    groups=value['groups'];need(type(groups) is list and len(groups)<=32 and all(type(x) is int and 0<=x<2**32 for x in groups) and len(groups)==len(set(groups)),'complete bounded groups')
    for key in ('cwd','exe'):need(type(value[key]) is str and value[key].startswith('/') and len(value[key])<=4096,'literal process path')
    cmd=value['cmdline'];need(type(cmd) is list and 0<len(cmd)<=32 and all(type(x) is str and '\0' not in x for x in cmd) and sum(len(x.encode())+1 for x in cmd)<=8192,'complete bounded process argv')
    need(type(value['namespaces']) is dict and set(value['namespaces'])=={'user','mnt','net','pid'},'complete namespace links')
    for key,item in value['namespaces'].items():need(type(item) is str and re.fullmatch(key+r':\[[1-9][0-9]{0,19}\]',item),'literal actual namespace identity')
    maps(value['uid_map']);maps(value['gid_map'])
    status=value['status'];need(type(status) is dict and set(status)=={'CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs','Seccomp','Seccomp_filters'},'complete process security status')
    for key in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'):need(type(status[key]) is str and re.fullmatch('[0-9a-f]{1,16}',status[key]),'literal capability observation')
    need(status['NoNewPrivs']=='1' and status['Seccomp'] in ('0','1','2') and type(status['Seccomp_filters']) is str and re.fullmatch('[0-9]{1,4}',status['Seccomp_filters']),'actual NNP and observed seccomp fields')
    need(value['limits']==LIMITS and type(value['cgroup']) is str and 0<len(value['cgroup'])<=4096,'actual resource limits/cgroup observation')
    need(type(value['mountinfo']) is str and len(value['mountinfo'].encode())<=128*1024,'bounded mount observation')
    need(type(value['interfaces']) is list and len(value['interfaces'])<=32 and all(type(x) is str and re.fullmatch('[A-Za-z0-9_.:-]{1,32}',x) for x in value['interfaces']),'bounded interface observation')
    need(type(value['hostname']) is str and 0<len(value['hostname'])<=255,'hostname observation')
    if baseline:
        need(all(value[k]==1001 for k in ('uid','euid','gid','egid')) and all(int(status[k],16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')),'actual alarm1001/cap0 baseline')
        need(value['interfaces']==['lo'] and value['hostname']=='perl5423-native','actual network/hostname domain')
        mount_data(value['mountinfo'])
    return value


def probe_argv(case,a,sha,mode):
    inner=['/usr/bin/python3','-I','-B','/inputs/probe.py',mode,'--case',case,'--admission-sha256',sha,'--source-map-sha256',a['source_map_sha256'],'--token',a['token']]
    if mode=='--exec-probe':return inner
    if case==CASES[0]:return ['/usr/bin/bwrap','--die-with-parent','--unshare-net','--ro-bind','/','/','--proc','/proc','--dev','/dev','--tmpfs','/home','--tmpfs','/var/lib/pacman','--chdir','/tmp','--',*inner]
    return ['/usr/bin/unshare','--user','--map-root-user','--',*inner]


def subset(value):return {k:value[k] for k in ('uid','gid','namespaces','uid_map','gid_map')}


def python_process(value):need(re.fullmatch(r'/usr/bin/python3(?:\.[0-9]{1,2})?',value['exe']),'actual system Python runtime')


def baseline(entry,parent):
    context(entry,baseline=True);context(parent,baseline=True);python_process(entry)
    need(entry['pid']>1 and entry['ppid']==parent['pid']==1 and entry['cwd']=='/work/recipe' and entry['cmdline']==['/usr/bin/python3','-I','-B','/inputs/entry.py'],'entry directly parented by actual init')
    need(parent['starttime']<=entry['starttime'],'parent/entry chronological identity')
    need(Path(parent['exe']).name in ('docker-init','tini') and parent['cmdline'][-5:]==['--','/usr/bin/bash','--noprofile','--norc','/inputs/entry.sh'],'actual injected init entry tail')
    for key in ('namespaces','uid_map','gid_map','groups','cgroup'):need(entry[key]==parent[key],'entry/init actual runtime continuity')


def outcome(raw,row,a,sha,entry):
    need(type(raw) is bytes and 0<len(raw)<=512*1024,'bounded complete command log')
    case=row['case'];code=natural(row['lifecycle']);need(code==row['returncode'] and -255<=code<=255,'actual direct exit result')
    need(row['argv']==probe_argv(case,a,sha,'--exec-probe'),'fixed outer diagnostic argv')
    frames=[];tail=[]
    for index,line in enumerate(raw.splitlines(keepends=True)):
        if not line.startswith(FRAME):tail.append(line);continue
        need(len(line)<=256*1024 and line.endswith(b'\n'),'bounded complete frame')
        value=decode(line[len(FRAME):],256*1024);need(encode(value)==line[len(FRAME):],'canonical frame DATA')
        need(type(value) is dict and value.get('schema')==1 and type(value['schema']) is int and value.get('operation')==OPERATION and value.get('case')==case and value.get('admission_sha256')==sha and value.get('source_map_sha256')==a['source_map_sha256'] and value.get('token')==a['token'],'same-source/run framed diagnostic')
        need(len(frames)<2 and (frames or index==0),'ordered finite frames');frames.append(value)
    common={'schema','operation','case','phase','admission_sha256','source_map_sha256','token'}
    need(frames and set(frames[0])==common|{'context','argv','executable'} and frames[0]['phase']=='exec','first exact exec frame')
    first=frames[0];before=context(first['context'],baseline=True);python_process(before)
    need(before['pid']==row['lifecycle']['pid'] and before['ppid']==entry['pid'] and before['pgrp']==before['session']==before['pid'],'actual direct owned wrapper lineage')
    need(entry['starttime']<=before['starttime'],'entry/wrapper chronological identity')
    need(before['cwd']=='/work/recipe' and before['cmdline']==row['argv'],'actual wrapper argv/cwd')
    for key in ('namespaces','uid_map','gid_map','groups','cgroup'):need(before[key]==entry[key],'entry-to-wrapper runtime continuity')
    need(first['argv']==probe_argv(case,a,sha,'--inner'),'fixed exec-boundary tool argv')
    executable=first['executable'];need(type(executable) is dict and set(executable)=={'bytes','sha256','mode','uid','gid'} and type(executable['bytes']) is int and 0<executable['bytes']<=4*1024**2 and digest(executable['sha256']) and all(type(executable[k]) is int for k in ('mode','uid','gid')) and executable['mode']==0o755 and executable['uid']==executable['gid']==0,'actual ordinary root-owned diagnostic binary')
    result=dict(exit_code=code,outcome='UNKNOWN',before=subset(before),after=None,retirement=row['lifecycle'],reason='NO_COMPLETE_SUCCESSFUL_EFFECTS',output=pin(raw),namespace_errno='UNKNOWN',policy_cause='UNKNOWN')
    if len(frames)==2 and frames[1].get('phase')=='exec-error':
        need(set(frames[1])==common|{'errno'} and type(frames[1]['errno']) is int and 0<frames[1]['errno']<4096 and code==126,'actual exec failure only')
        result['reason']='EXEC_FAILURE_NOT_NAMESPACE_ERRNO';return result
    if len(frames)==1 and code!=0:
        denied=code>0 and any(text in b''.join(tail) for text in (b'No permissions to create a new namespace',b'unshare failed: Operation not permitted',b'Creating new namespace failed: Operation not permitted'))
        result.update(outcome='DENIED' if denied else 'UNKNOWN',reason='TOOL_REPORTED_DENIAL_CAUSE_UNKNOWN' if denied else 'NONZERO_RESULT_CAUSE_UNKNOWN');return result
    if len(frames)!=2 or code!=0 or tail:return result
    second=frames[1];need(set(second)==common|{'context'} and second['phase']=='inner','exact inner frame')
    after=context(second['context']);python_process(after);result['after']=subset(after)
    need(after['pgrp']==before['pgrp'] and after['session']==before['session'],'inner remains in supervised process group/session')
    need(after['cmdline']==probe_argv(case,a,sha,'--inner')[probe_argv(case,a,sha,'--inner').index('/usr/bin/python3'):],'actual inner runtime argv')
    ns0,ns1=before['namespaces'],after['namespaces'];changed={k for k in ns0 if ns0[k]!=ns1[k]}
    supported=after['cgroup']==before['cgroup'] and after['page_bytes']==before['page_bytes'] and before['starttime']<=after['starttime']
    if case==CASES[0]:
        supported=supported and changed=={'user','mnt','net'} and after['cwd']=='/tmp' and all(after[k]==1001 for k in ('uid','euid','gid','egid'))
        for key in ('uid_map','gid_map'):
            supported=supported and [outside+1001-inside for inside,outside,count in after[key] if inside<=1001<inside+count]==[1001]
    else:
        supported=supported and changed=={'user'} and after['cwd']=='/work/recipe' and all(after[k]==0 for k in ('uid','euid','gid','egid')) and after['uid_map']==after['gid_map']==[[0,1001,1]] and after['pid']==before['pid'] and after['starttime']==before['starttime'] and after['ppid']==entry['pid']
    result.update(outcome='SUPPORTED' if supported else 'UNKNOWN',reason='EXACT_OBSERVED_EFFECTS' if supported else 'OBSERVED_EFFECTS_DO_NOT_ESTABLISH_REQUEST')
    return result


def classify(report,logs,host,a):
    """Root must authenticate Source, operands and outer actor lifetime separately."""
    sha=admission(a);host_data(host,a,sha)
    keys={'schema','operation','status','native_acceptance','admission_sha256','source_map_sha256','domain_sha256','host_sha256','token','entry','parent','commands','failure'}
    need(type(report) is dict and set(report)==keys and type(report['schema']) is int and report['schema']==1 and report['operation']==OPERATION and report['native_acceptance'] is False,'closed diagnostic report')
    need(report['admission_sha256']==sha and report['source_map_sha256']==a['source_map_sha256'] and report['domain_sha256']==DOMAIN_SHA and report['host_sha256']==pin(encode(host))['sha256'] and report['token']==a['token'],'exact bound raw host/runtime observations')
    need(report['status'] in ('OBSERVED_NAMESPACE_DATA','FAIL_NAMESPACE_DATA') and (report['failure'] is None or type(report['failure']) is str and len(report['failure'])<=4096),'bounded diagnostic completion')
    entry,parent=report['entry'],report['parent'];baseline(entry,parent)
    commands=report['commands'];need(type(commands) is list and len(commands)<=2,'finite diagnostic command count')
    need(type(logs) is dict and set(logs)=={row['log'] for row in commands},'complete exact raw logs')
    results={};seconds=0
    for case,row in zip(CASES,commands):
        need(type(row) is dict and set(row)=={'case','argv','log','log_pin','returncode','lifecycle'} and row['case']==case and row['log']==case+'.log','ordered exact diagnostic command index')
        raw=logs[row['log']];need(pin(raw)==row['log_pin'],'whole raw log pin')
        results[case]=outcome(raw,row,a,sha,entry);seconds+=row['lifecycle']['elapsed_seconds']
    need(seconds<60,'aggregate diagnostic deadline')
    complete=report['status']=='OBSERVED_NAMESPACE_DATA' and report['failure'] is None and len(results)==2
    success=complete and all(row['outcome']=='SUPPORTED' for row in results.values())
    return dict(schema=1,status='PASS_NAMESPACE_EFFECTS' if success else 'OBSERVED_NAMESPACE_NO_QUALIFICATION',source=a['source'],run=a['run'],job=a['job'],image=a['image'],domain_sha256=DOMAIN_SHA,reader_sha256=pin(Path(__file__).read_bytes())['sha256'],cases=results,native_acceptance=False,policy_cause='UNKNOWN',authority='ROOT_AUTHENTICATION_AND_OUTER_LIFETIME_REQUIRED')

# SPDX-License-Identifier: MIT
"""Independent, passive XS evidence joins. Never invoke an actor or load XS."""
import hashlib
import json
from pathlib import PurePosixPath
import re

MIB=1024**2
ARCH='usr/lib/perl5/5.42/core_perl';PURE='usr/share/perl5/core_perl';CORE=ARCH+'/CORE'
ROOT='/inputs/prefix';STAGE='/xs-work/xs-stage'
EXT='blib/arch/auto/CachyAsahi/Perl5423/Consumer/Consumer.so'
PACKAGE='perl-5.42.3-1.3-aarch64.pkg.tar.zst'
PACKAGE_PIN=dict(bytes=22071176,sha256='647c5f1d2c6965ec2e26b37e75d29c819fafa344f16002153493e9fc62121c22')
DECISION_PIN=dict(bytes=5804,sha256='27803c99064198f8688abe2e4d91910eef93df5ad337ebfc7f2d8798afbf41e1')
INVENTORY='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
PAIR=dict(kind='native',source='25dc3e65bdb6137c87a9409067fe9b2cf6e9763f',run='43692477455',job='132745843566')
CANDIDATE=dict(commit='c8e9baea97f83f652763e701143d6dec5b679f31',recipe_sha256='cf0df8990ac83f48a4c29978c932922108f0e01cb6d052209934da5b01af4068',source_sha256='16b23f32e34df12709fc5fa0a7028d3df3c3cfceca21e38faada6a025edff725')
FIXTURE={'Makefile.PL':'5706dab03e22e73ad8d91a7e75430263603a2a6560bc01559c2d56121addac0e','Consumer.xs':'bcf502b93bb8b6e8196b977a328c5242c56b1c8adb02062e1037c396b8cee5ee','lib/CachyAsahi/Perl5423/Consumer.pm':'9b422015bde54964a1b73f35691192f2a036466ed3904c639dbd7952780df64f','t/roundtrip.t':'fad9c6668f28f0a584e8b9c56d583d5d763869b8b9dbebbe3e1829435f0fc1ab','provenance.pl':'ae9b547198fdb2313defa89a83589d98f7228c3418b5031c3f9c6fd5088b87eb'}
RUNNER='bf2903fd1f72fe5c33a71bd00a15f71e7a4ae153d13522682af4f71d660e580e'
LIMITS={'cpu.max':'200000 100000','memory.max':'4294967296','memory.swap.max':'0','pids.max':'256'}
GENERATED=('Makefile','consumer.d','Consumer.c','Consumer.o',EXT,'xs-configure-provenance.json','xs-runtime-provenance.json')


def encode(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()
def selected(name):return name=='usr/bin/perl' or any(name==p or name.startswith(p+'/') for p in (ARCH,PURE))


def fields(raw,need):
    rows={}
    for line in raw.decode().splitlines():
        if not line or line.startswith('#'):continue
        need(' = ' in line,'literal package metadata');key,value=line.split(' = ',1);rows.setdefault(key,[]).append(value)
    return rows


def harness(raw,need):
    text=raw.decode();need(len(re.findall(r'^All tests successful\.$',text,re.M))==1 and
        len(re.findall(r'^t/roundtrip\.t[.\s]+ok\s*$',text,re.M))==1 and
        len(re.findall(r'^Files=1,\s*Tests=21(?:,|\s).*$',text,re.M))==1 and
        len(re.findall(r'^Result: PASS\s*$',text,re.M))==1 and
        not re.search(r'^\s*(?:not ok|Bail out!|Failed\s+[1-9])|^Result: (?!PASS\s*$)',text,re.M),
        'actual exact roundtrip one-file21-assertion harness PASS')
    labels=['loaded fixture version','actual compiled headers and Perl API']+['XS scalar/string roundtrip','XS UTF8 flag preserved']*6+['native signed IV roundtrip']*4+['XS array roundtrip','array UTF8 flag preserved','actual loaded XS object']
    tap=re.findall(r'^ok\s+(\d+)\s+-\s+([^\n]+)$',text,re.M)
    if tap:need(tap==[(str(i),label) for i,label in enumerate(labels,1)] and re.search(r'^1\.\.21\s*$',text,re.M),'complete exact successful TAP labels when present')
    return dict(files=1,assertions=21,raw_TAP_present=bool(tap),scope='SOURCE_BOUND_HARNESS_ASSERTIONS; NO_PER_VALUE_OUTPUT_WHEN_TAP_SUPPRESSED')


def mounts(raw,need):
    found={}
    for line in raw.splitlines():
        left,sep,right=line.partition(' - ');a,b=left.split(),right.split();need(sep and len(a)>=6 and len(b)==3,'complete mount observation')
        if a[4] in ('/','/inputs','/work','/tmp','/run','/xs-work','/sys/fs/cgroup'):
            need(a[4] not in found,'unique actual mount');found[a[4]]=(set(a[5].split(',')),b[0],set(b[2].split(',')))
    need(set(found)=={'/','/inputs','/work','/tmp','/run','/xs-work','/sys/fs/cgroup'},'complete native smoke mount scope')
    for name in ('/','/inputs','/sys/fs/cgroup'):need('ro' in found[name][0] and 'rw' not in found[name][0],'actual readonly boundary')
    need('rw' in found['/work'][0] and 'ro' not in found['/work'][0],'actual writable work volume')
    for name,size in (('/tmp',64*MIB),('/run',8*MIB),('/xs-work',256*MIB)):
        flags,kind,options=found[name];need(kind=='tmpfs' and {'rw','nosuid','nodev'}<=flags and 'ro' not in flags and
            {'uid=1001','gid=1001'}<=options and (('noexec' not in flags) if name=='/xs-work' else ('noexec' in flags)),'actual owned bounded tmpfs execution policy')
        values=[x[5:] for x in options if x.startswith('size=')];need(len(values)==1,'unique tmpfs size')
        match=re.fullmatch(r'([1-9][0-9]*)([kKmMgG]?)',values[0]);need(match and int(match[1])*{'':1,'k':1024,'m':MIB,'g':1024*MIB}[match[2].lower()]==size,'exact tmpfs capacity')


def runtime(observation,sandbox,operation_sha,need):
    entry,parent=observation['entry'],observation['parent']
    need(observation['schema']==1 and observation['operation_sha256']==operation_sha and observation['sandbox']==sandbox and
         observation['native_acceptance'] is False and observation['XS_acceptance'] is False,'actual runtime observation joins')
    for row in (entry,parent):
        need(all(type(row[k]) is int and row[k]==1001 for k in ('uid','euid','gid','egid')) and row['architecture']=='aarch64' and
             row['page_bytes'] in (4096,16384) and row['limits']==LIMITS and row['interfaces']==['lo'] and row['hostname']=='perl5423-native','actual native1001 finite runtime')
        need(all(int(row['status'][k],16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')) and row['status']['NoNewPrivs']=='1' and row['status']['Seccomp']=='2','actual cap0/NNP/seccomp runtime')
        need(set(row['namespaces'])=={'user','mnt','net','pid'} and all(re.fullmatch(k+r':\[[1-9][0-9]*\]',v) for k,v in row['namespaces'].items()),'literal actual namespaces')
        need(all(row[k]==[[0,0,4294967295]] for k in ('uid_map','gid_map')) and row['cgroup']=='0::/\n','unremapped private unified cgroup runtime')
        mounts(row['mountinfo'],need)
    argv=['/usr/bin/python3','-I','-B','/inputs/consumer/native_adapter/native.py','actor','--admission-sha256',operation_sha]
    need(type(entry['pid']) is int and entry['pid']>1 and entry['ppid']==parent['pid']==1 and 0<parent['starttime']<=entry['starttime'] and
         entry['cmdline']==argv and re.fullmatch(r'/usr/bin/python3(?:\.[0-9]{1,2})?',entry['exe']) and entry['cwd']=='/work' and
         PurePosixPath(parent['exe']).name in ('docker-init','tini') and parent['cmdline'][-len(argv)-1:]==['--']+argv and
         all(entry[k]==parent[k] for k in ('groups','namespaces','uid_map','gid_map','cgroup')),'actual direct init/entry lineage')
    need(sandbox['schema']==1 and sandbox['authorization']=='ROOT_ADMITTED_FOUR_COMMAND_XS_SMOKE' and sandbox['exclusive_scope'] is True and
         sandbox['uid']==sandbox['gid']==1001 and sandbox['target_arch']=='aarch64' and sandbox['workspace']=='/xs-work' and
         sandbox['workspace_identity']['owner_uid']==1001 and sandbox['workspace_identity']['inode']>0 and
         sandbox['cgroup_membership']=='0::/\n' and sandbox['cgroup_directory']=='/sys/fs/cgroup' and
         len(sandbox['cgroup_identity'])==2 and all(type(x) is int and x>=0 for x in sandbox['cgroup_identity']) and
         set(sandbox['namespaces'])=={'user','mnt','net','pid','cgroup'} and
         all(sandbox['namespaces'][k]==v for k,v in entry['namespaces'].items()) and
         re.fullmatch(r'cgroup:\[[1-9][0-9]*\]',sandbox['namespaces']['cgroup']),'runtime-generated bounded exclusive sandbox')


def provenance(value,phase,a,inputs,admission_pin,input_pin,generated,need):
    arch,pure,core=(ROOT+'/'+x for x in (ARCH,PURE,CORE));expected_extension=STAGE+'/'+EXT
    need(value['schema']==1 and value['phase']==phase and value['native_acceptance'] is False and
         value['admission_sha256']==admission_pin['sha256'] and value['inputs_sha256']==input_pin['sha256'] and
         all(value[k]==a[k] for k in ('archive','artifact','inventory','root')) and value['perl']==ROOT+'/usr/bin/perl' and
         (value['arch'],value['pure'],value['core'])==(arch,pure,core) and value['version']=='v5.42.3' and
         str(value['make_maker'])=='7.76' and value['tools']==a['toolchain'],'actual provenance operand/configuration joins')
    config=value['config'];need(config['cf_time']=='Sun Aug  2 00:00:00 UTC 2026' and config['useshrplib']=='true' and
         config['useithreads']=='define' and str(config['ivsize'])=='8' and config['archname'].startswith('aarch64-') and config['libperl']=='libperl.so','shared threaded IV64 candidate Config')
    rows=inputs['files'];required=['usr/bin/perl',ARCH+'/Config.pm']+[CORE+'/'+x for x in ('perl.h','EXTERN.h','XSUB.h','config.h','patchlevel.h','libperl.so')]
    need(value['runtime_files']=={k:rows[k] for k in required} and value['libperl_maps']==[core+'/libperl.so'],'actual executable/headers/Config/libperl file joins')
    modules=value['loaded_modules'];need(type(modules) is dict and modules.get('Config.pm')==arch+'/Config.pm' and modules.get('ExtUtils/MakeMaker.pm')==pure+'/ExtUtils/MakeMaker.pm','actual loaded candidate Config/MakeMaker')
    allowed={ROOT+'/'+x for x in rows}|{STAGE+'/provenance.pl'}
    if phase=='runtime':allowed.add(STAGE+'/blib/lib/CachyAsahi/Perl5423/Consumer.pm')
    need(all(type(k) is str and type(v) is str and v in allowed for k,v in modules.items()),'no substituted loaded module path')
    objects=value['dynamic_objects'];need(type(objects) is list and len(objects)<=256 and all(x in {ROOT+'/'+k for k in rows}|({expected_extension} if phase=='runtime' else set()) for x in objects),'no substituted dynamic object path')
    if phase=='runtime':
        need(expected_extension in objects and value['extension']==expected_extension and value['extension_sha256']==digest(generated[EXT]) and
             value['dependencies_sha256']==digest(generated['consumer.d']) and value['api']==dict(perl='5.42.3',api='5.42.0',iv_bytes=8),'actual loaded compiled XS/API/dependency proof')
    else:need(value['extension'] is None and value['extension_sha256'] is None and value['dependencies_sha256'] is None,'configure precedes extension load')


def validate(get,source_root,binding,context,io):
    need=io.need;io.tick()
    source=lambda name,cap=16*MIB:io.read(source_root,name,cap)
    exported=io.export(get('xs/output.tar',256*MIB));names=set(exported)
    need(io.names('xs/exported')==names,'retained export closed namespace')
    for name,(body,mode) in exported.items():need(get('xs/exported/'+name,64*MIB)==body,'whole raw tar/retained export bytes')
    logical=io.decode(exported['evidence-map.json'][0]);need(type(logical) is dict and 1<=len(logical)<=50,'finite logical evidence map')
    required={'receipt.json','plan.json','sandbox.json','admission.json','inputs.json'}|{str(i)+'.'+s for i in range(1,5) for s in ('stdout','stderr')}|{'generated/'+x for x in GENERATED}
    need(set(logical)==required,'complete exact successful runner evidence namespace')
    fixed={'evidence-map.json','actor-result.json','runtime-observation.json','actual-packages.txt','operation.json','accepted-reader.json'};flat=set();data={}
    for name,row in logical.items():
        io.tick();need(set(row)=={'file','bytes','sha256'} and re.fullmatch(r'evidence-[0-9]{3}\.data',row['file']) and row['file'] not in flat,'unique canonical flat evidence mapping')
        flat.add(row['file']);body=exported[row['file']][0];need(io.pin(body)=={k:row[k] for k in ('bytes','sha256')},'whole logical evidence leaf pin');data[name]=body
    need(names==fixed|flat,'complete raw export namespace')
    actor=io.decode(exported['actor-result.json'][0]);need(actor==context['actor_result'] and actor['status']=='RUNNER_COMPLETED' and
         actor['runner_status']=='FOUR_SMOKE_COMMANDS_COMPLETED' and actor['failure'] is None and actor['native_acceptance'] is False and actor['XS_acceptance'] is False and
         actor['qualification']=='NOT_GRANTED' and actor['nested_invocation']=='NOT_INVOKED' and actor['nested_qualification']=='NOT_QUALIFIED','same scoped successful actor result DATA')
    operation=context['operation'];operation_raw=get('xs/operation.json');need(exported['operation.json'][0]==operation_raw==get('bundle/operation.json') and io.decode(operation_raw)==operation,'same raw outer operation')
    op_sha=digest(operation_raw)
    need(actor['operation_sha256']==op_sha,'actor exact operation hash')
    need(operation['source']==dict(sha=binding['source'],ref=binding['ref'].removeprefix('refs/heads/')) and all(operation[k]==binding[k] for k in ('run','job','approval')) and
         operation['image']==context['image'] and operation['operation']==binding['operation']=='perl5423-native-xs-v1' and operation['pair']=={k:PAIR[k] for k in ('source','run','job')},'external same Source/run/job/image/accepted-pair binding')
    for name,key in (('admission.json','xs_admission_sha256'),('inputs.json','inputs_sha256'),('plan.json','plan_sha256')):
        need(digest(data[name])==operation[key] and data[name]==get('bundle/xs-'+name),'raw runner/bundle operand pins')
    a,inputs,plan,sandbox,receipt=(io.decode(data[k]) for k in ('admission.json','inputs.json','plan.json','sandbox.json','receipt.json'))
    admission_pin,input_pin=io.pin(data['admission.json']),io.pin(data['inputs.json'])
    arc=source('accepted/'+PACKAGE,64*MIB);decision=source('accepted/Root-decision.json')
    need(io.pin(arc)==PACKAGE_PIN and io.pin(decision)==DECISION_PIN and exported['accepted-reader.json'][0]==decision and
         operation['accepted_reader_receipt']==dict(path='/inputs/accepted-reader.json',**DECISION_PIN),'exact Root accepted archive/decision DATA')
    accepted=io.decode(decision);need(accepted['accepted'] is True and accepted['status']=='ACCEPTED_EXACT_PERL5423_NATIVE_ARM4K_BUILD_PAIR_ONLY' and accepted['archive']==PACKAGE_PIN and accepted['page_bytes']==4096,'fixed scoped Root pair decision')
    parsed=io.package(arc);need(parsed['identity']==PACKAGE_PIN,'independently parsed accepted package')
    rows={}
    for name,row in parsed['nodes'].items():
        if selected(name):
            need(row['type'] in ('directory','file'),'selected runtime aliases/specials refused')
            if row['type']=='file':rows[name]={k:row[k] for k in ('bytes','sha256','mode')}
    need(inputs==dict(schema=1,archive_sha256=PACKAGE_PIN['sha256'],candidate_recipe_sha256=CANDIDATE['recipe_sha256'],files=rows) and
         len(rows)<=5000 and sum(x['bytes'] for x in rows.values())<=128*MIB,'complete archive-derived ordinary runtime map')
    need(a['schema']==1 and a['candidate']==CANDIDATE and a['target_arch']=='aarch64' and a['artifact']==PAIR and a['inputs_sha256']==input_pin['sha256'] and
         a['archive']==dict(name=PACKAGE,path='/inputs/'+PACKAGE,**PACKAGE_PIN) and a['root']['path']==ROOT and a['root']['kind']=='extracted' and
         a['root']['owner_uid']==1001 and all(type(a['root'][k]) is int and a['root'][k]>0 for k in ('device','inode')),'exact candidate/admitted extracted prefix identity')
    for key,name,control in (('pkginfo','PKGINFO','.PKGINFO'),('buildinfo','BUILDINFO','.BUILDINFO')):
        body=source('accepted/'+name);need(body==parsed['controls'][control] and a['metadata'][key]==dict(path='/inputs/'+name,**io.pin(body)),'exact embedded package metadata sidecar')
    pkg,build=(fields(parsed['controls'][name],need) for name in ('.PKGINFO','.BUILDINFO'))
    need(all(pkg.get(k)==[v] for k,v in (('pkgname','perl'),('pkgver','5.42.3-1.3'),('arch','aarch64'))) and
         all(build.get(k)==[v] for k,v in (('pkgver','5.42.3-1.3'),('pkgarch','aarch64'),('pkgbuild_sha256sum',CANDIDATE['recipe_sha256']))),'exact package/build candidate metadata')
    need(all(parsed['elfs'][name]['machine']=='AArch64' and parsed['elfs'][name]['type'] in (2,3) for name in ('usr/bin/perl',CORE+'/libperl.so')),'actual archived AArch64 executable and libperl')
    inventory=source('accepted/packages.txt');need(digest(inventory)==INVENTORY and exported['actual-packages.txt'][0]==inventory and a['inventory']==dict(path='/inputs/packages.txt',**io.pin(inventory)) and operation['expected349_sha256']==INVENTORY,'actual signed349 image inventory join')
    preparation_raw=get('bundle/preparation.json');preparation=io.decode(preparation_raw)
    need(preparation['files']==rows and preparation['root']==a['root'] and preparation['inputs']==input_pin and
         preparation['admission']==admission_pin and preparation['plan']==io.pin(data['plan.json']) and
         preparation['planning_stage_removed'] is True,'complete prepared prefix map and operand identities')
    expected_bundle={'consumer/'+name:io.pin(source('consumer/'+name)) for name in (
        *FIXTURE,'preflight.py','runner/run.py','runner/helpers/owned_child.py','native_adapter/native.py',
        'native_adapter/operation.TEMPLATE.json','native_adapter/support/common.py','native_adapter/support/runtime.py','native_adapter/support/data_export.py')}
    expected_bundle.update({'prefix/'+name:{k:row[k] for k in ('bytes','sha256')} for name,row in rows.items()})
    expected_bundle.update({PACKAGE:PACKAGE_PIN,'accepted-reader.json':DECISION_PIN,
        'PKGINFO':io.pin(parsed['controls']['.PKGINFO']),'BUILDINFO':io.pin(parsed['controls']['.BUILDINFO']),
        'packages.txt':io.pin(inventory),'daemon.json':io.pin(get('daemon.json')),
        'xs-admission.json':admission_pin,'xs-inputs.json':input_pin,'xs-plan.json':io.pin(data['plan.json']),
        'preparation.json':io.pin(preparation_raw)})
    bundle_raw=get('bundle/bundle-map.json')
    need(digest(bundle_raw)==operation['bundle_map_sha256'] and io.decode(bundle_raw)==dict(schema=1,files=expected_bundle),
         'complete Source/archive/prefix/metadata/operand bundle map; no unknown or omitted leaf')
    tools=a['toolchain'];need(set(tools)=={'cc','ld','make'} and tools['cc']==tools['ld'],'explicit compiler/linker-driver/make pins')
    for row in tools.values():need(set(row)=={'path','bytes','sha256'} and re.fullmatch('/usr/bin/[A-Za-z0-9._+-]+',row['path']) and type(row['bytes']) is int and 0<row['bytes']<=16*MIB and re.fullmatch('[0-9a-f]{64}',row['sha256']),'finite immutable-image tool binary descriptors')
    arch,pure,core=(ROOT+'/'+x for x in (ARCH,PURE,CORE));perl=ROOT+'/usr/bin/perl'
    env=dict(PATH='/usr/bin',HOME=STAGE,LC_ALL='C',TZ='UTC',LD_LIBRARY_PATH=core,PERL_DL_NONLAZY='1',CACHY_XS_ROOT=ROOT,CACHY_XS_PERL=perl,CACHY_XS_CORE=core,
        CACHY_XS_ADMISSION='/inputs/xs-admission.json',CACHY_XS_ADMISSION_SHA256=admission_pin['sha256'],CACHY_XS_INPUTS='/inputs/xs-inputs.json',CACHY_XS_INPUTS_SHA256=input_pin['sha256'])
    env.update({'CACHY_XS_'+k.upper():v['path'] for k,v in tools.items()});argv=[perl,'-I'+arch,'-I'+pure]
    commands=[argv+['Makefile.PL'],[tools['make']['path'],'-j2'],[tools['make']['path'],'test'],argv+['provenance.pl']]
    expected=dict(status='PREFLIGHT_DATA_ONLY_XS_NOT_RUN',native_acceptance=False,cwd=STAGE,environment_policy='REPLACE_ENTIRE_ENVIRONMENT_WITH_THIS_EXACT_MAP',environment=env,commands=commands,archive=a['archive'],root=a['root'],artifact=PAIR)
    need(plan==expected and data['plan.json']==encode(expected),'independent exact four argv/environment plan')
    source_pins={}
    for name,sha in FIXTURE.items():
        body=source('consumer/'+name);need(digest(body)==sha,'frozen fixture source pin');source_pins[name]=io.pin(body)
    need(digest(source('consumer/runner/run.py'))==RUNNER==sandbox['runner_sha256']==operation['runner_sha256'] and sandbox['plan_sha256']==digest(data['plan.json']) and
         sandbox['accepted_reader_receipt']==operation['accepted_reader_receipt'],'frozen runner/plan/sandbox receipt binding')
    observation=io.decode(exported['runtime-observation.json'][0]);need(observation==context['runtime_observation'] and observation['generator_sha256']==operation['runtime_identity_generator_sha256']==digest(source('consumer/native_adapter/native.py')),'actual pinned observation generator')
    runtime(observation,sandbox,op_sha,need)
    need(receipt['schema']==1 and receipt['status']=='FOUR_SMOKE_COMMANDS_COMPLETED' and receipt['native_acceptance'] is False and receipt['XS_acceptance'] is False and receipt['qualification']=='NOT_GRANTED' and
         receipt['plan_sha256']==digest(data['plan.json']) and receipt['sandbox_sha256']==digest(data['sandbox.json']) and len(receipt['commands'])==4 and
         type(receipt['elapsed_seconds']) in (int,float) and 0<receipt['elapsed_seconds']<240 and 'error' not in receipt,'complete finite runner receipt')
    for i,(command,timeout) in enumerate(zip(receipt['commands'],(30,90,30,30)),1):
        need(command['number']==i and command['argv']==commands[i-1] and command['environment_sha256']==digest(encode(env)) and command['launched'] is True,'exact launched command scope')
        io.natural(command['lifecycle'],max_seconds=timeout+3)
        for stream in ('stdout','stderr'):
            body=data[str(i)+'.'+stream];need(len(body)<=4*MIB and command[stream]==dict(path=str(i)+'.'+stream,**io.pin(body)),'whole bounded command stdout/stderr')
    for key in ('cgroup.procs','cgroup.threads','memory.events','pids.events'):need(receipt['resource_initial'][key]==receipt['resource_final'][key],'exclusive actor/resource retirement continuity')
    need(receipt['resource_initial']['cgroup.procs']==sorted([1,observation['entry']['pid']]),'only init and entry remain in the actual cgroup')
    for label in ('resource_initial','resource_final'):
        for event,keys in (('memory.events',('max','oom','oom_kill')),('pids.events',('max',))):
            events=dict(line.split() for line in receipt[label][event].splitlines());need(all(events.get(k)=='0' for k in keys),'no memory/PID limit or OOM event')
    need(receipt['cleanup']==dict(removed=True,stage_identity=receipt['cleanup']['stage_identity']) and receipt['cleanup']['stage_identity']['owner_uid']==1001 and
         receipt['stage_final']['entries']<=512 and receipt['stage_final']['regular_bytes']<=64*MIB,'owned finite stage naturally retired and removed')
    generated={name:data['generated/'+name] for name in GENERATED};need(set(receipt['artifacts'])==set(GENERATED),'complete generated artifact namespace')
    for name,body in generated.items():need(receipt['artifacts'][name]==dict(path='generated/'+name,**io.pin(body)),'whole generated artifact pin')
    obj,extension=io.elf(generated['Consumer.o']),io.elf(generated[EXT]);needed_libperl=parsed['elfs'][CORE+'/libperl.so'].get('soname') or core+'/libperl.so'
    need(obj and obj['type']==1 and extension and extension['type']==3 and extension['machine']=='AArch64' and needed_libperl in extension['needed'],
         'actual AArch64 object/shared extension linked to candidate libperl')
    deps=generated['consumer.d'].decode();need(all(core+'/'+h in deps.split() for h in ('EXTERN.h','perl.h','XSUB.h','config.h','patchlevel.h')) and
         all(not ('/CORE/' in x) or x.startswith(core+'/') for x in deps.replace('\\\n',' ').split()),'actual admitted CORE dependency selection')
    c=generated['Consumer.c'];need(all(x.encode() in c for x in ('#include "EXTERN.h"','#include "perl.h"','#include "XSUB.h"','PERL_SUBVERSION != 3','XS_CachyAsahi__Perl5423__Consumer_scalar_roundtrip','XS_CachyAsahi__Perl5423__Consumer_iv_roundtrip','XS_CachyAsahi__Perl5423__Consumer_array_roundtrip','XS_CachyAsahi__Perl5423__Consumer_native_info')),'generated C retains fixture API/guards')
    conf=io.decode(generated['xs-configure-provenance.json']);run=io.decode(generated['xs-runtime-provenance.json']);standalone=io.decode(data['4.stdout'])
    for value,phase in ((conf,'configure'),(run,'runtime'),(standalone,'runtime')):provenance(value,phase,a,inputs,admission_pin,input_pin,generated,need)
    # The harness also loads Test::More; each actual module/object closure is checked above.
    invariant=lambda value:{k:v for k,v in value.items() if k not in ('assertions','loaded_modules','dynamic_objects')}
    need(run['assertions']=='SCALAR_NUL_UTF8_ARRAY_IV64' and invariant(run)==invariant(standalone) and receipt['provenance']==dict(configure=conf,runtime=run,standalone=standalone),'three actual provenance receipts agree on candidate facts')
    mm=conf['makefile'];expected_mm=dict(PERL='"'+perl+'" -I'+arch+' -I'+pure,FULLPERL=' '.join(argv),PERL_INC=core,PERL_LIB=pure,PERL_ARCHLIB=arch,CC=tools['cc']['path'],LD=tools['ld']['path'],MAKE=tools['make']['path'],MYEXTLIB=core+'/libperl.so')
    need(set(mm)==set(expected_mm)|{'CCFLAGS'} and all(mm[k]==v for k,v in expected_mm.items()) and '-MMD -MF consumer.d' in mm['CCFLAGS'],'MakeMaker exact admitted interpreter/header/library/tools')
    makefile=generated['Makefile'].decode().replace('\\\n',' ')
    for key,value in expected_mm.items():
        lines=re.findall(r'^'+key+r'\s*=\s*(.*?)\s*$',makefile,re.M)
        if key=='MAKE' and not lines:continue  # MM facts and actual command argv bind make even when no assignment is emitted.
        need(len(lines)==1 and lines[0].replace('"','')==value.replace('"',''),'actual Makefile binding '+key)
    checked=harness(data['3.stdout'],need)
    io.tick()
    return dict(schema=1,status='PASS_PASSIVE_NATIVE_XS_CONSUMER_DATA',source=binding['source'],run=binding['run'],job=binding['job'],archive=PACKAGE_PIN,
        fixture=source_pins,commands=4,test_harness=checked,extension=io.pin(generated[EXT]),assertions='SCALAR_NUL_UTF8_ARRAY_IV64',
        tool_binary_proof='EXTERNALLY_ROOT_ADMITTED_IMAGE_AND_PINNED_RUNTIME_GUARD; BINARY_BODIES_NOT_EXPORTED',
        staged_fixture_proof='FROZEN_RUNNER_SOURCE_AND_SUCCESSFUL_SOURCE_PIN_CHECK; STAGE_REMOVED',native_acceptance=False,XS_acceptance=False,authority=None)

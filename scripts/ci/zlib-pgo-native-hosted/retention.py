# SPDX-License-Identifier: MIT
"""Bounded complete PGO-hosted DATA retention; no native replay or acquisition."""
import ast,hashlib,importlib.util,io,json,math,os,re,shlex,stat,tarfile
from pathlib import Path,PurePosixPath

SOURCE_SHA='bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'
RECIPE='packages/experiments/cachy-asahi-zlib-pgo-v1'
PROFILE_NAMES=tuple('#tmp#build#'+n+'.gcda'for n in sorted('adler32 crc32 deflate infback inffast inflate inftrees trees zutil compress uncompr gzclose gzlib gzread gzwrite example minigzip'.split()))
PAYLOAD=('libz.a','minigzip','example','probe','strict-gzip','zlib.h','zconf.h','LICENSE')
MAX_FILE=16*1024**2;MAX_LARGE=64*1024**2;MAX_PUBLIC=512*1024**2;MAX_LEAVES=20000
BOOT={'inputs.lock.json','runner.json','bootstrap.json','bootstrap.log','packages.lock','image-id','image-inspect.json','signatures.json','rootfs-inventory.json','rootfs-hooks.json','package-audit.json','cache-checksums.json','acquisition.json','key-import.log','retained-preparation.json','build-started.json','context/Dockerfile','context/disabled-hooks.txt','context/pacman.conf'}
WORK_FILES={'input-transport-owner.json','input-transport.stdout','input-transport.stderr','input-transport.exit-code','bootstrap-owner.json','pairs-owner.json','pair-cleanup-owner.json','cleanup-owner.json','producer-binding.json','producer-binding-1.json','producer-binding-2.json','producer-inspect.json','producer-inspect-1.json','producer-inspect-2.json','comparison.json','build-intent-1.json','build-intent-2.json'}
PHASES=('input-transport','bootstrap','pairs','pair-cleanup','cleanup')
PHASE_ROLES={'input-transport':'RETAINED_INPUT_TRANSPORT_DATA','bootstrap':'FRESH_ORIGINAL341_PRODUCER',
    'pairs':'TWO_INDEPENDENT_PGO_CONSUMERS','pair-cleanup':'CONSUMER_RETIREMENT',
    'cleanup':'PRODUCER_RETIREMENT_AFTER_CONSUMERS'}
CARRIER_SOURCE='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
CARRIER_PROFILE='4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'
TRANSPORT_STREAMS=('input-transport.stdout','input-transport.stderr','input-transport.exit-code')


def need(ok,message):
    if not ok:raise ValueError(message)


def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return dict(bytes=len(raw),sha256=sha(raw))
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()


def decode(raw):
    def pairs(rows):
        result={}
        for key,value in rows:need(key not in result,'duplicate evidence JSON key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in()).throw(ValueError('nonfinite evidence JSON')))


def relative(name):
    p=PurePosixPath(name);need(type(name)is str and str(p)==name and not p.is_absolute()and'..'not in p.parts and '\\'not in name,'ordinary relative retention path');return name


def read(path,cap=MAX_FILE):
    path=Path(path);need(not any(p.is_symlink()for p in(path,*path.parents)),'retention aliases refused')
    info=path.stat();need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and 0<=info.st_size<=cap,'bounded ordinary single-link retained leaf')
    raw=path.read_bytes();need(len(raw)==info.st_size,'retained leaf changed size');return raw


def j(path):return decode(read(path))


def cap(name):return MAX_LARGE if PurePosixPath(name).name=='libz.a'or re.search(r'\.pkg\.tar\.(?:xz|zst|gz)$',name)else MAX_FILE


def tree(directory,allowed=None,limit=8192):
    directory=Path(directory);need(directory.is_dir()and not directory.is_symlink(),'ordinary evidence directory')
    result={};size=0
    for path in sorted(directory.rglob('*')):
        need(not path.is_symlink(),'evidence alias refused')
        info=path.stat();need(stat.S_ISDIR(info.st_mode)or stat.S_ISREG(info.st_mode),'special evidence node refused')
        if path.is_dir():continue
        name=relative(path.relative_to(directory).as_posix());need(allowed is None or allowed(name),'unexpected evidence leaf: '+name)
        raw=read(path,cap(name));result[name]=pin(raw);size+=len(raw)
        need(len(result)<=limit and size<=MAX_PUBLIC,'complete evidence tree bound')
    return result


def inner_leaf(name):
    parts=name.split('/')
    if len(parts)==1:return name in {'train.gz','train.decoded','gun.decoded','example.gz','training-results.json','profile-seal.json','result.json','receipt.json','failed-profile-inventory.json','tool-identity-observations.json','tool-identity-error.json'}
    if parts[0]=='commands':return len(parts)==2 and(parts[1]=='commands.json'or re.fullmatch(r'[0-9]{4}-[a-zA-Z0-9.-]+\.log',parts[1])is not None)
    if parts[0]in('profiles','decoded-profiles'):return len(parts)==2 and parts[1]in PROFILE_NAMES
    if parts[0]=='failed-profiles':return len(parts)==2 and re.fullmatch(r'[A-Za-z0-9_.#-]+',parts[1])is not None
    if parts[0]=='instrumented':return len(parts)==2 and parts[1]in('libz.a','example','minigzip','gun','gun.o','Makefile','configure.log')
    return len(parts)==2 and parts[0]in('optimized-1','optimized-2')and parts[1]in(*PAYLOAD,'Makefile.txt','configure.log.txt')


def attempt_leaf(name,source_inputs):
    parts=name.split('/');top=parts[0]
    if len(parts)==1:return top in {'source-plan.json','reviewed-inputs.json','expected-packages.lock','native-command.json','source-cache-before.json','source-cache-after.json'}
    if top=='seed-cache':return name in {'seed-cache/FORMAT','seed-cache/objects/'+SOURCE_SHA,'seed-cache/receipts/50979bf81eda4d1f5b23fbe05aec5fabd7827b270fe3edda22b7189944004c43-zlib-1.3.2.json'}
    if top=='source-material':return name in {'source-material/srcdest/zlib-1.3.2.tar.gz','source-material/receipts/zlib-1.3.2.json','source-material/notices/e32ff4e00d9d94930537635291da39e7e612703334bf6fde8c7f1686fe8a45a2','source-material/source-plan.json','source-material/source-catalog.json','source-material/selection.json'}
    if top!='native-build':return False
    if len(parts)==2:return parts[1]in('provenance.json','validation.json','expected-packages.lock','build.log')
    if parts[1]=='inputs':return '/'.join(parts[2:])in source_inputs
    if parts[1]=='source-material':return attempt_leaf('/'.join(parts[1:]),source_inputs)
    if parts[1]!='artifacts':return False
    if len(parts)>3 and parts[2]=='pgo-v1-evidence':return inner_leaf('/'.join(parts[3:]))
    if len(parts)!=3:return False
    return parts[2]in('environment.txt','packages.lock','config.sha256','makepkg.conf','pacman.conf','generated.SRCINFO')or re.fullmatch(r'cachy-asahi-zlib-pgo-v1-1\.3\.2-1-aarch64(?:-[a-z]+\.log|\.pkg\.tar\.(?:zst|xz|gz))',parts[2])is not None


def labels():
    tc=['tool-target',*['tool-'+n for n in('gcc','gcc-ar','gcc-ranlib','ld','gcov-tool','make','as')],*['tool-path-'+n for n in('cc1','collect2','libgcov-a')]]
    result=[*tc,'build-instrumented-configure','build-instrumented-static','build-training-gun-compile','build-training-gun-link','train-encode','train-decode','train-example','train-gun','build-training-profile-decode']
    for attempt in(1,2):
        prefix='build-optimized-'+str(attempt)
        result += [*tc,prefix+'-configure',prefix+'-static',prefix+'-upstream-test',prefix+'-probe-compile',prefix+'-probe-link',prefix+'-strict-gzip-compile',prefix+'-strict-gzip-link',prefix+'-symbols','elf-optimized-'+str(attempt),*tc]
    for number in(0,1):
        result.append('validate-probe-'+str(number))
        for index in range(8):
            for level in(1,6,9):
                prefix=f'validate-{number}-{index}-{level}';result += [prefix+'-encode',prefix+'-decode-0',prefix+'-decode-1']
    result += [f'validate-{n}-reject-{i}'for n in(0,1)for i in range(3)]
    need(len(result)==234,'finite source command label model');return result


def owned_status(row,expected=None):
    need(row.get('exit_observed_via_waitpid')is True and row.get('ownership_lost')is False
         and row.get('retirement')=='REAPED'and row.get('natural_exit')is True
         and row.get('forced_cleanup')is False and row.get('group_absent')is True
         and row.get('leader_held_until_group_inspection')is True
         and type(row.get('exit'))is int and(expected is None or row['exit']==expected),
         'direct owned waitpid status and unreaped-leader retirement required')


def commands(directory):
    directory=Path(directory);rows=j(directory/'commands.json');expected=labels()
    need(type(rows)is list and len(rows)==len(expected),'complete234 native pipeline commands')
    for index,(row,label)in enumerate(zip(rows,expected)):
        owned_status(row,2 if '-reject-'in label else 0)
        need(row['label']==label and row['log']==f'{index:04d}-'+label+'.log'and row['status']=='PASS','complete native command order/index')
        need(row['exit']==(2 if '-reject-'in label else 0)and row['group_absent']is True and row['leader_held_until_group_inspection']is True and'cleanup_error'not in row,'finite command success and held leader cleanup')
        need(type(row['argv'])is list and row['argv']and all(type(v)is str for v in row['argv']),'native argv observation')
        uids=row['cleanup_member_uids'];need(type(uids)is list and uids==sorted(set(uids))and all(type(v)is int and v>0 for v in uids),'ordinary original-group credentials')
        need(type(row['elapsed_seconds'])in(int,float)and math.isfinite(row['elapsed_seconds'])and 0<=row['elapsed_seconds']<=1200,'bounded native command elapsed')
        read(directory/row['log'])
    need(set(tree(directory))=={'commands.json',*(r['log']for r in rows)},'all and only command diagnostic leaves')
    decoder=next(r for r in rows if r['label']=='build-training-profile-decode');body=read(directory/decoder['log']).decode()
    need(not re.search(r'not a gcov|corrupt|malformed|\b(?:warning|error)\b|cannot open|cannot access directory|is not a directory|incorrect gcov version|mismatch|skipping|counter overflow|read error',body,re.I),'native decoder diagnostics refused')
    names=re.findall(r'reading file:[ \t]+(?:\./)?([^\r\n]*?)[ \t]*$',body,re.M)
    need(len(names)==34 and set(names)==set(PROFILE_NAMES)and all(names.count(n)==2 for n in PROFILE_NAMES),'native decoder exact17 twice transcript')
    return rows


def correctness_commands(rows,resultdir,cases):
    by_label={row['label']:row for row in rows}
    def check(label,argv,stdout):
        row=by_label[label];need(row['argv']==argv,'source-fixed correctness command argv')
        if stdout is not None:need(dict(bytes=row['stdout_bytes'],sha256=row['stdout_sha256'])==pin(stdout),'whole correctness/probe/refusal stdout observation')
    probe=dict(status='PASS',variant='pgo-v1',prefix='/usr/lib/cachy-asahi/experiments/zlib-pgo-v1',zlib='1.3.2',source_sha256=SOURCE_SHA,roundtrips=21,negative_checks=42)
    expected=(json.dumps(probe,separators=(',',':'))+'\n').encode()
    for number in(0,1):
        root=resultdir/('optimized-'+str(number+1));check('validate-probe-'+str(number),[str(root/'probe'),'--build-check'],expected)
        for index,plain in enumerate(cases):
            for level in(1,6,9):
                prefix=f'validate-{number}-{index}-{level}';check(prefix+'-encode',[str(root/'minigzip'),'-'+str(level)],None)
                for consumer in(0,1):check(prefix+'-decode-'+str(consumer),[str(resultdir/('optimized-'+str(consumer+1))/'strict-gzip')],plain)
        for index in range(3):check(f'validate-{number}-reject-{index}',[str(root/'strict-gzip')],cases[2])


def upstream(root):
    archive=Path(root)/'pgo-source/inputs/cache-seed/objects'/SOURCE_SHA;raw=read(archive);need(sha(raw)==SOURCE_SHA,'real upstream archive pin')
    result={};seen=set();total=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz')as stream:
        for m in stream:
            path=PurePosixPath(m.name);need(not path.is_absolute()and'..'not in path.parts and path.parts[0]=='zlib-1.3.2'and m.name not in seen and len(seen)<2048 and(m.isdir()or m.isfile()),'safe finite source archive members')
            seen.add(m.name);total+=m.size;need(m.size<=8*1024**2 and total<=64*1024**2,'source map data bound')
            if m.isfile():result['upstream/'+'/'.join(path.parts[1:])]=pin(stream.extractfile(m).read())
    return result


def constant(path,name):
    node=next(n.value for n in ast.parse(read(path).decode()).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id==name for t in n.targets))
    return ast.literal_eval(node)


def configured(directory,source):
    keys=('CC','AR','RANLIB','CFLAGS','LDFLAGS');values=[]
    for name in('Makefile.txt','configure.log.txt'):
        record={};text=read(directory/name).decode()
        for key in keys:
            found=re.findall(r'^'+key+r'[ \t]*=[ \t]*([^\n]*)$',text,re.M);need(len(found)==1,'one observed configured assignment')
            record[key]=' '.join(shlex.split(found[0]))
        values.append(record)
    baseline=constant(source/'pipeline.py','BASE');link=constant(source/'pipeline.py','LINK');use=constant(source/'pipeline.py','USE');features=constant(source/'arm_c01.py','FEATURE_FLAGS')
    actual,probe=values;need(all(actual[k]==probe[k]==v for k,v in [('CC','gcc'),('AR','gcc-ar'),('RANLIB','gcc-ranlib')]),'exact effective compiler/archive tools')
    head=shlex.split(baseline);probe_flags=shlex.split(probe['CFLAGS']);suffix=probe_flags[len(head):]
    need(probe_flags[:len(head)]==head and suffix and suffix[0]=='-fPIC'and len(suffix)==len(set(suffix))and all(v in features for v in suffix),'unprofiled configure probes and fixed feature suffix')
    need(probe['LDFLAGS']==link and actual['LDFLAGS']==link+use and shlex.split(actual['CFLAGS'])==shlex.split(baseline+use)+suffix,'exact profile-use flags; missing profile and mismatch remain fatal')
    return dict(**actual,configure_probe=probe)


def inner(directory,root):
    directory=Path(directory);root=Path(root);actual=tree(directory,inner_leaf,4097);receipt=j(directory/'receipt.json');body={k:v for k,v in actual.items()if k!='receipt.json'}
    need(set(receipt)=={'schema','status','files','acceptance','performance','hardware'}and receipt['schema']==1 and receipt['files']==body and receipt['acceptance']is False,'whole nested native PGO receipt closure')
    report=j(directory/'result.json');status='PASS_FINITE_PGO_CONSTRUCTION_AND_NATIVE_CORRECTNESS_ONLY'
    need(receipt['status']==report['status']==status and report['source_sha256']==SOURCE_SHA and report['training_attempts']==1 and report['optimized_clean_builds']==2 and report['profile_use']=='SAME_SEALED_PROFILE_BOTH_BUILDS_NO_FALLBACK'and report['profile_decode']=='GCC_NATIVE_DECODER_TRANSCRIPT_MATCHED','complete genuine finite pipeline report')
    need(report['hardware']==report['physical16k']=='NOT RUN'and report['performance']=='NOT MEASURED'and report['release']=='NOT_ADMITTED'and report['optimization_acceptance']=='NOT RUN','no performance or physical admission')
    source=root/'pgo-source'/RECIPE;policy=j(source/'recipe-policy.json');need(report['recipe_policy']==pin(read(source/'recipe-policy.json')),'frozen recipe policy identity')
    binding=report['binding'];need(binding['source_files']=={**upstream(root),**{'local/'+name:value for name,value in policy['local_files'].items()}},'whole original upstream/local source identity')
    need(binding['training']['corpus']==policy['training']and binding['training']['heldout']==policy['validation'],'separate frozen training/heldout identities')
    need(binding['training']['results_sha256']==sha(read(directory/'training-results.json')),'whole training results binding')
    training=j(directory/'training-results.json');plan=training['plan'];need(len(plan)==4,'finite training plan')
    resultdir=PurePosixPath(plan[2]['argv'][1]).parent;need(resultdir.is_absolute()and resultdir.name=='pgo-result'and'..'not in resultdir.parts,'ordinary observed in-container training output')
    expected=[dict(label='train-encode',argv=['/tmp/build/minigzip','-6'],input='training.bin',output='train.gz'),dict(label='train-decode',argv=['/tmp/build/minigzip','-d'],input='train.gz',output='train.decoded'),dict(label='train-example',argv=['/tmp/build/example',str(resultdir/'example.gz')],input=None,output=None),dict(label='train-gun',argv=['/tmp/build/gun'],input='train.gz',output='gun.decoded')]
    pretty=lambda x:(json.dumps(x,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
    need(plan==expected and binding['training']['command_plan_sha256']==sha(pretty(plan)),'exact deterministic training-only argv/plan seal')
    for name in('train.decoded','gun.decoded'):need(read(directory/name)==read(source/'training.bin'),'retained training roundtrip bytes')
    native=commands(directory/'commands')
    rows={r['label']:r for r in native}
    need([r['label']for r in training['results']]==[r['label']for r in plan],'complete four training result pins')
    for row in training['results']:
        command=rows[row['label']];need(command['argv']==next(p['argv']for p in plan if p['label']==row['label'])and row['stdout']==dict(bytes=command['stdout_bytes'],sha256=command['stdout_sha256']),'exact training argv/stdout command join')
    for row,name in [('train-encode','train.gz'),('train-decode','train.decoded'),('train-gun','gun.decoded')]:need(pin(read(directory/name))==dict(bytes=rows[row]['stdout_bytes'],sha256=rows[row]['stdout_sha256']),'retained whole training stdout')
    need(training['instrumented']=={p.name:pin(read(p,cap(p.name)))for p in(directory/'instrumented').iterdir()},'whole instrumented program/config pins')
    module_path=source/'profile_seal.py';need(pin(read(module_path))==policy['local_files']['profile_seal.py'],'frozen passive profile validator')
    spec=importlib.util.spec_from_file_location('_host_retained_profile_seal',module_path);validator=importlib.util.module_from_spec(spec);spec.loader.exec_module(validator)
    seal=validator.verify(directory/'profiles',binding,directory/'profile-seal.json',expected_sha256=report['profile_seal_sha256'])
    profile_rows=[dict(name=name,**value)for name,value in sorted(tree(directory/'profiles').items())]
    need(training['profiles']==profile_rows,'all raw profiles match native-decoder input snapshot')
    need(set(tree(directory/'decoded-profiles'))==set(PROFILE_NAMES),'all native-decoded profile leaves')
    for name in PROFILE_NAMES:need(read(directory/'decoded-profiles'/name)[:8]==read(directory/'profiles'/name)[:8],'native decoder profile magic/version identity')
    outputs=[]
    for number in(1,2):outputs.append({name:pin(read(directory/f'optimized-{number}'/name,cap(name)))for name in PAYLOAD})
    need(report['outputs']==outputs and outputs[0]==outputs[1],'same-seal two clean optimized payloads identical')
    need(report['effective_flags']==[configured(directory/f'optimized-{n}',source)for n in(1,2)],'actual effective profile-use flags join')
    correctness=report['correctness'];need(all(correctness[k]==v for k,v in dict(encodes=48,cross_decodes=96,strict_rejections=6,probes=2).items())and correctness['includes_page_boundaries']==[16383,16384,16385]and correctness['physical16k']=='NOT RUN','complete finite native correctness and separate16K scope')
    cases=[b'',b'x',b'cachy-asahi public workload\n'*4096,bytes(range(256))*1024]+[bytes((i*13+i//257)&255 for i in range(n))for n in(16383,16384,16385)]+[read(source/'validation.bin')]
    need(correctness['input_pins']==[pin(d)for d in cases],'complete correctness/page-boundary and independent heldout input pins')
    correctness_commands(native,resultdir,cases)
    return dict(status='MATCHED_SOURCE_BOUND_FINITE_PGO_CONSTRUCTION_DATA',files=len(actual),profiles=17,commands=234,inner_clean_builds=2,seal_sha256=report['profile_seal_sha256'],outputs=outputs[0],hardware='NOT RUN',generic16k='NOT RUN',performance='NOT GRANTED')


def transport_record(work,root,own,owner,*,runtime_temp=None):
    """Match transport DATA and full proof; historical paths are DATA, not probes."""
    work=Path(work);root=Path(root);row=j(work/'input-transport-owner.json')
    def original_path(value):
        need(type(value)is str,'recorded original absolute path required')
        path=PurePosixPath(value)
        need(path.is_absolute()and str(path)==value and'..'not in path.parts and'\\'not in value,
             'normalized original POSIX path required')
        return path
    temp=original_path(row['runtime_temp']);source=original_path(row['source_root'])
    carrier=original_path(row['carrier_path'])
    need(carrier==temp/'pgo-hosted-retained'and not temp.is_relative_to(source)
         and not source.is_relative_to(temp),'original runtime DATA and source paths must be disjoint')
    if runtime_temp is not None:
        need(temp==original_path(str(runtime_temp)),'trusted original runner temp binding differs')
    need(row['status']=='PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY'and row['identity']==own
         and row['manifest_sha256']==sha(read(root/owner.MAP))
         and row['role']==PHASE_ROLES['input-transport']
         and row['carrier_source']==row['carrier_head']==CARRIER_SOURCE
         and row['profile_sha256']==CARRIER_PROFILE
         and type(row['expected_carrier_files'])is int and row['expected_carrier_files']==1154
         and type(row['expected_carrier_bytes'])is int and row['expected_carrier_bytes']==1046432165
         and type(row['budget_seconds'])is int and row['budget_seconds']==480
         and row['retry']is False and row['acceptance']is False and row['native']=='NOT_RUN',
         'same-owner complete bounded retained input transport DATA required')
    profile=read(root/'scripts/ci/setup6-retained-helpers/carrier-profile.json')
    need(sha(profile)==CARRIER_PROFILE,'held whole carrier profile source required')
    selected=decode(profile)
    need(selected['source']==CARRIER_SOURCE and len(selected['files'])==1154
         and sum(v['bytes']for v in selected['files'].values())==1046432165,
         'complete original retained profile volume required')
    streams={name:pin(read(work/name))for name in TRANSPORT_STREAMS}
    need(read(work/'input-transport.exit-code')==b'0\n','complete successful outer transport phase required')
    rows=j(work/'input-transport-actors/actors.json')
    need(type(rows)is list and len(rows)==5,'complete five-command one-fetch transport required')
    git=['git','-c','credential.helper=','-c','http.extraHeader=','-c','http.sslVerify=true',
         '-c','core.hooksPath=/dev/null','-c','protocol.allow=never','-c','protocol.https.allow=always']
    expected_argv=[[*git,'init','--template=',str(carrier)],
        [*git,'-C',str(carrier),'-c','http.lowSpeedLimit=65536','-c','http.lowSpeedTime=60',
         'fetch','--depth=1','--no-tags','--no-recurse-submodules',
         'https://github.com/Gabriel-Kahen/cachy-asahi.git',CARRIER_SOURCE],
        [*git,'-C',str(carrier),'rev-parse','--verify','FETCH_HEAD'],
        [*git,'-C',str(carrier),'checkout','--detach',CARRIER_SOURCE],
        [*git,'-C',str(carrier),'rev-parse','--verify','HEAD']]
    elapsed=0
    for index,actor in enumerate(rows):
        need(actor.get('status')=='PASS'and'cleanup_error'not in actor,'complete unforced transport actor')
        owned_status(actor,0)
        need(type(actor.get('elapsed_seconds'))in(int,float)and math.isfinite(actor['elapsed_seconds'])
             and 0<=actor['elapsed_seconds']<=482,'bounded transport actor elapsed')
        elapsed+=actor['elapsed_seconds']
        read(work/'input-transport-actors'/f'{index:04d}.log')
        need(original_path(actor['log'])==temp/'pgo-hosted-work/input-transport-actors'/f'{index:04d}.log',
             'same original runtime transport actor log path')
        argv=actor['argv'];need(type(argv)is list and argv and argv[0]=='git'
            and all(type(value)is str for value in argv),'source-owned transport Git argv')
        need(argv==expected_argv[index],'exact source-owned transport argv, qualifiers and target required')
    need(set(tree(work/'input-transport-actors'))=={'actors.json',*(f'{n:04d}.log'for n in range(5))},
         'complete and only retained transport actor streams')
    need(elapsed<=482,'shared480-second transport deadline plus final retirement allowance required')
    prepared=j(work/'bootstrap/retained-preparation.json')
    need(prepared['status']=='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY'
         and prepared['source']==prepared['carrier']['source']==CARRIER_SOURCE
         and prepared['carrier']['files']==prepared['carrier']['blob_joins']==1154
         and prepared['mode']=='native248'and prepared['actual']is None,
         'unchanged full1154 Git/blob preparation required after transport DATA')
    return dict(status='MATCHED_RETAINED_INPUT_DATA_AND_COMPLETE1154_PREPARATION',role=PHASE_ROLES['input-transport'],
        source=CARRIER_SOURCE,profile_sha256=CARRIER_PROFILE,carrier_files=1154,carrier_bytes=1046432165,
        original_runtime_temp=str(temp),original_source_root=str(source),actors=5,fetches=1,elapsed_seconds=elapsed,streams=streams,
        native='NOT_RUN',native_cleanup='NOT_ESTABLISHED',acceptance=False)


def producer(work,root,own,owner):
    work=Path(work);base=j(work/'bootstrap-owner.json');lock=read(work/'bootstrap/packages.lock');expected=read(Path(root)/owner.LANE/'expected-packages.lock')
    need(lock==expected and len(lock.decode().splitlines())==341,'genuine complete original341 producer inventory')
    need(base['identity']==own and base['status']=='PASS_FRESH_SIGNED_ORIGINAL341_BOOTSTRAP'and base['package_count']==341,'fresh current producer receipt')
    image=base['image'];need(re.fullmatch(r'sha256:[0-9a-f]{64}',image or''),'concrete producer image')
    for suffix in('','-1','-2'):
        row=j(work/('producer-binding'+suffix+'.json'));inspection=work/('producer-inspect'+suffix+'.json')
        need(set(row)=={'schema','status','identity','image','packages','package_count','bootstrap_owner','inspection'}and row['schema']==1 and row['status']=='PASS_FRESH_OWNED_RUNTIME_IMAGE_AND_FULL341_LOCK'and row['identity']==own and row['image']==image and row['package_count']==341,'same-run live producer identity/lock receipt')
        need(row['packages']==pin(lock)and row['bootstrap_owner']==pin(read(work/'bootstrap-owner.json'))and row['inspection']==pin(read(inspection)),'full producer receipt byte joins')
        need(owner.require_image(j(inspection),own)==image,'same owned daemon producer image')
    return base,lock


def qualify(work,root,own,owner,*,runtime_temp=None):
    work=Path(work);root=Path(root);transport=transport_record(work,root,own,owner,runtime_temp=runtime_temp)
    base,lock=producer(work,root,own,owner);image=base['image']
    pair=j(work/'pairs-owner.json');consumers=j(work/'pair-cleanup-owner.json');cleanup=j(work/'cleanup-owner.json')
    need(all(row['identity']==own for row in(pair,consumers,cleanup)),'same source/run complete phase identities')
    need(pair['status']=='PASS_TWO_INDEPENDENT_NATIVE_PGO_BUILDS_PENDING_CLEANUP'and pair['image']==image and pair['source_cache_unchanged']is True,'complete two independent candidate builds')
    names=pair['clean_environment_ids'];need(type(names)is list and len(names)==len(set(names))==2,'two distinct actual builder environments')
    need(consumers['status']=='PASS_ACTUAL_BUILD_CONSUMERS_ABSENT_BEFORE_IMAGE'and set(consumers['observed_absent'])==set(names),'all actual build consumers absent before producer')
    need(cleanup['status']=='PASS_ORDERED_OWNED_CONSUMER_THEN_IMAGE_ABSENCE'and cleanup['consumer_absence_verified']is True and cleanup['image_absence_verified']is True and cleanup['removed_images']==[image],'independent ordered consumer then producer absence')
    for phase in PHASES:
        rows=j(work/(phase+'-actors/actors.json'));need(type(rows)is list and rows and all(r['status']=='PASS'and r['natural_exit']is True and r['group_absent']is True and r['leader_held_until_group_inspection']is True for r in rows),'naturally completed held host actors: '+phase)
        for row in rows:owned_status(row)
    outputs=[work/f'attempt-{n}/native-build'for n in(1,2)];records=owner.validate_pair_records(outputs,image,own);owner.validate_observations(work,records,own)
    recipe=root/'pgo-source'/RECIPE;approved={p.relative_to(recipe).as_posix():pin(read(p))for p in recipe.rglob('*')if p.is_file()}
    result=[]
    for number,output in enumerate(outputs,1):
        preparation=output.parent;record=records[number-1]
        need(read(preparation/'expected-packages.lock')==read(output/'expected-packages.lock')==read(output/'artifacts/packages.lock')==lock,'full runtime producer lock fed to preparation/builder/actual consumer')
        need(j(preparation/'native-command.json')['expected_packages']==pin(lock),'runtime native-plan lock receipt')
        need(j(preparation/'source-cache-before.json')==j(preparation/'source-cache-after.json'),'each independent source cache unchanged')
        need(tree(output/'inputs')==approved,'complete actual source recipe snapshot')
        need(record['image']==record['image_id']==image,'same producer image in native versioned builder')
        result.append(inner(output/'artifacts/pgo-v1-evidence',root))
    return dict(status='COMPLETE_TWO_INDEPENDENT_SOURCE_BOUND_PGO_DATA_PENDING_ROOT_REVIEW',image=image,packages=pin(lock),outer_builders=names,
        candidate_attempts=result,independent_payload_equality={name:result[0]['outputs'][name]==result[1]['outputs'][name]for name in PAYLOAD},
        input_transport=transport,phase_roles=PHASE_ROLES,
        raw_archive_equality='OBSERVATION_ONLY_INDEPENDENT_TRAINING_SEALS_AND_PROVENANCE_CAN_DIFFER',cleanup='MATCHED_CONSUMERS_ABSENT_BEFORE_PRODUCER_IMAGE',acceptance=False,
        installed='NOT RUN',hardware='NOT RUN',generic16k='NOT RUN',performance='NOT GRANTED',release='NOT_ADMITTED')


def candidate_diagnostics(work,own,manifest_sha256):
    """Derive partial candidate DATA only; absence of binding2 is never sufficient."""
    work=Path(work);owner_report={};owner_error=None
    try:
        if (work/'pairs-owner.json').exists():owner_report=j(work/'pairs-owner.json')
    except Exception as error:owner_error=type(error).__name__
    matched_owner=(type(owner_report)is dict and owner_report.get('identity')==own
        and owner_report.get('manifest_sha256')==manifest_sha256)
    declared=owner_report.get('candidate_states',[])if matched_owner else []
    matched_states=(type(declared)is list and len(declared)==2
        and all(type(row)is dict and type(row.get('attempt'))is int and row.get('attempt')==n for n,row in enumerate(declared,1)))
    result=[]
    for number in(1,2):
        prefix=f'attempt-{number}/native-build'
        names=[f'build-intent-{number}.json',f'producer-binding-{number}.json',f'build-observations/{number}.json',
            prefix+'/provenance.json',prefix+'/artifacts/pgo-v1-evidence/result.json',
            prefix+'/artifacts/pgo-v1-evidence/receipt.json',
            prefix+'/artifacts/pgo-v1-evidence/tool-identity-observations.json',
            prefix+'/artifacts/pgo-v1-evidence/tool-identity-error.json']
        evidence={};records={};errors=[]
        for name in names:
            if not os.path.lexists(work/name):continue
            try:
                raw=read(work/name);evidence[name]=pin(raw);records[name]=decode(raw)
            except Exception as error:errors.append(dict(path=name,error_type=type(error).__name__))
        present=os.path.lexists(work/f'attempt-{number}')
        owner_state=declared[number-1]if matched_states else None
        row=dict(attempt=number,state='NO_RETAINED_EVIDENCE',owner_state=owner_state,
            attempt_directory_present=present,evidence=evidence,errors=errors,acceptance=False)
        pipeline=records.get(prefix+'/artifacts/pgo-v1-evidence/result.json',{})
        provenance=records.get(prefix+'/provenance.json',{})
        observed=records.get(f'build-observations/{number}.json',{})
        intent=records.get(f'build-intent-{number}.json',{})
        matched_intent=type(intent)is dict and intent.get('identity')==own
        pipeline_failed=type(pipeline)is dict and pipeline.get('status')=='FAIL'and pipeline.get('source_sha256')==SOURCE_SHA
        native_failed=type(provenance)is dict and provenance.get('status')=='failed'and provenance.get('mode')=='native'
        driver=observed.get('driver_execution',{})if type(observed)is dict else {}
        driver_failed=(type(driver)is dict and driver.get('status')=='FAILED_OR_INTERRUPTED'
            and observed.get('source_sha')==own.get('source_sha'))
        reached=present or any(os.path.lexists(work/name)for name in names)
        if pipeline_failed:
            row.update(state='FAILED',failure=dict(basis='INNER_PIPELINE_RESULT',error_type=pipeline.get('error_type'),error=str(pipeline.get('error',''))[:4096]))
        elif driver_failed or native_failed and(matched_intent or owner_state is not None):
            row.update(state='FAILED',failure=dict(basis='DRIVER_EXECUTION'if driver_failed else'NATIVE_BUILDER_PROVENANCE',error_type=driver.get('error_type'),error=str(driver.get('error',provenance.get('error','')))[:4096]))
        elif owner_state is not None and owner_state.get('state')=='FAILED_OR_INTERRUPTED':
            row.update(state='FAILED_OR_REFUSED',failure=dict(basis='MATCHED_OWNER_CONTROL_FLOW',error_type=owner_state.get('error_type')))
        elif owner_state is not None and owner_state.get('state')=='NOT_REACHED'and not reached:
            row['state']='NOT_REACHED'
        elif reached:
            row['state']='REACHED_NOT_QUALIFIED'
        elif owner_state is not None and owner_state.get('state')!='NOT_REACHED':
            row['state']='DECLARED_REACHED_WITHOUT_RETAINED_ATTEMPT_DATA'
        if owner_state is not None and owner_state.get('state')=='NOT_REACHED'and reached:
            row['errors'].append(dict(path='pairs-owner.json',error_type='NOT_REACHED_CONTRADICTS_RETAINED_ATTEMPT_DATA'))
        result.append(row)
    return dict(schema=1,role='PARTIAL_CANDIDATE_DIAGNOSTIC_DATA_ONLY',candidates=result,
        owner_report_matched=matched_owner,owner_report_error=owner_error,acceptance=False,cleanup_credit='NONE',qualification='NOT_ESTABLISHED')


def retain(args,owner):
    """Export permitted partial DATA before the unchanged mandatory qualifier."""
    manifest,own=owner.binding(args,feature_required=False);root=Path(owner.ROOT);work=Path(args.work);public=owner.fresh(args.public);copied={};total=0;export_errors=[]
    receipt=dict(schema=1,status='PARTIAL_OR_FAILED_PGO_HOSTED_DATA',identity=own,manifest_sha256=args.manifest_sha256,files=copied,acceptance=False,
        phase_roles=PHASE_ROLES,construction='NOT QUALIFIED',installed='NOT RUN',generic16k='NOT RUN',hardware='NOT RUN',performance='NOT GRANTED',release='NOT_ADMITTED',
        limits=dict(public_bytes=MAX_PUBLIC,total_leaves=MAX_LEAVES,attempt_leaves=8192,ordinary_leaf_bytes=MAX_FILE,libz_or_archive_bytes=MAX_LARGE),
        limitations=['Public receipts require trusted Root ingress; local JSON is not GitHub attestation.','No native codec/profile/compiler/package or runtime replay is performed by retention.','Profile header/hash and native decoder transcript joins do not create a second independent native decoder execution.','No LIVE original-group members does not establish zombie/global absence; final consumer/producer retirement is separate.','Independent outer archives may differ in training seals/runtime provenance; their byte equality is observational.','External retained-input transport is DATA only; complete zero-exit streams, owned transport actors and the unchanged full1154 Git/blob preparation are mandatory before construction.','No candidate16K, physical Asahi/M2, performance, energy/thermal, final-system or release admission follows.'],
        export_errors=export_errors)
    def error(name,error):
        if len(export_errors)<256:export_errors.append(dict(path=str(name),type=type(error).__name__,message=str(error)[:1024]))
        else:receipt['export_errors_truncated']=True
    def copy(path,name):
        nonlocal total
        relative(name);need(name not in copied,'duplicate public retention name');data=read(path,cap(name))
        need(total+len(data)<=MAX_PUBLIC and len(copied)<MAX_LEAVES,'whole public retention bounds')
        target=public/name;target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb')as stream:stream.write(data)
        copied[name]=dict(**pin(data),mode=stat.S_IMODE(Path(path).stat().st_mode));total+=len(data)
    def attempt_copy(path,name):
        try:copy(path,name)
        except Exception as failure:error(name,failure)
    def export_tree(directory,prefix,allowed,limit=8192):
        directory=Path(directory)
        try:
            need(directory.is_dir()and not directory.is_symlink(),'ordinary export directory')
            leaves=0
            for index,path in enumerate(directory.rglob('*')):
                if index>=2*limit:error(prefix,ValueError('bounded export node count'));break
                try:
                    need(not path.is_symlink(),'export aliases refused');info=path.stat()
                    need(stat.S_ISDIR(info.st_mode)or stat.S_ISREG(info.st_mode),'special export node refused')
                    if path.is_dir():continue
                    leaves+=1;need(leaves<=limit,'bounded export leaf count')
                    name=relative(path.relative_to(directory).as_posix());need(allowed(name),'unexpected diagnostic leaf: '+name)
                    attempt_copy(path,prefix+'/'+name)
                except Exception as failure:error(prefix+'/'+path.relative_to(directory).as_posix(),failure)
                if leaves>limit:break
        except Exception as failure:error(prefix,failure)
    try:
        attempt_copy(args.proof,'presecret-source-proof.json')
        for name in[*manifest['files'],owner.MAP,*owner.ALIASES]:attempt_copy(root/name,'source/'+name)
        for name in sorted(WORK_FILES):
            if os.path.lexists(work/name):attempt_copy(work/name,name)
        for name in sorted(BOOT):
            if os.path.lexists(work/'bootstrap'/name):attempt_copy(work/'bootstrap'/name,'bootstrap/'+name)
        for directory in(*[phase+'-actors'for phase in PHASES],'build-observations'):
            if not os.path.lexists(work/directory):continue
            def permitted(name):return '/'not in name and(name=='actors.json'or re.fullmatch(r'[0-9]{4}\.log',name)is not None or directory=='build-observations'and name in('1.json','2.json'))
            export_tree(work/directory,directory,permitted)
        source=root/'pgo-source'/RECIPE;source_inputs={p.relative_to(source).as_posix()for p in source.rglob('*')if p.is_file()}
        for number in(1,2):
            path=work/f'attempt-{number}'
            if os.path.lexists(path):export_tree(path,f'attempt-{number}',lambda n:attempt_leaf(n,source_inputs))
        receipt['candidate_diagnostics']=candidate_diagnostics(work,own,args.manifest_sha256)
        need(not export_errors,'bounded diagnostic export errors prevent qualification')
        report=qualify(work,root,own,owner,runtime_temp=os.environ.get('RUNNER_TEMP'));receipt.update(status=report['status'],construction='FINITE_DATA_AWAITING_ROOT_REVIEW',actual=report)
    except(Exception,KeyboardInterrupt)as failure:
        receipt['error']=dict(type=type(failure).__name__,message=str(failure)[:4096]);receipt['cleanup_credit']='NONE'
    finally:
        if 'candidate_diagnostics'not in receipt:receipt['candidate_diagnostics']=candidate_diagnostics(work,own,args.manifest_sha256)
        receipt['retained_bytes']=total;receipt['retained_leaves']=len(copied)
        owner.save(public/'receipt.json',receipt)
    return 0 if receipt['status']=='COMPLETE_TWO_INDEPENDENT_SOURCE_BOUND_PGO_DATA_PENDING_ROOT_REVIEW'else 1

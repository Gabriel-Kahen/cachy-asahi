# SPDX-License-Identifier: MIT
"""Explicit public current-stage evidence selection; no actors or directory capture."""
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

OP = 'first-login-enrollment-ui-current-v2'
SCHEMAS = dict(backend='CURRENT_BACKEND_RETENTION_V3', ui='CURRENT_UI_RETENTION_V3',
               lifecycle='CURRENT_LIFECYCLE_RETENTION_V3')
MAX_FILE, MAX_TOTAL, MAX_MEMBERS, MAX_COMPRESSED = 8*1024**2, 16*1024**2, 512, 8*1024**2
PUBLIC = {'context','domain','inventory','public_test_key','image_qualification','runtime','admission'}
KINDS = dict(backend=('enrollment','first-login'), ui=('ui',), lifecycle=())
BUILD_FILES = {'build.log','validation.json','expected-packages.lock','artifacts/packages.lock',
               'artifacts/generated.SRCINFO','artifacts/environment.txt','artifacts/config.sha256',
               'artifacts/makepkg.conf','artifacts/pacman.conf'}
PRIVATE_PARTS = {'.git','.gnupg','.ssh','.aws','private-keys-v1.d','openpgp-revocs.d',
                 '.cache','.config','.local','.docker','.kube','.password-store','.netrc',
                 'gpg','gnupg','keyring','keyrings','cache','storage','mounted-storage','credentials','trust'}
PRIVATE_FILES = {'inside.json','proxy.json','signature-config.txt','ownertrust','pacman.log'}
PUBLIC_DOTFILES={'.SRCINFO','.PKGINFO','.BUILDINFO','.MTREE'}
COMMAND_KEYS = {'step','argv','cwd','expected','success','log','log_pin','supervision','channels'}
COUNTS = dict(backend=350, ui=374, lifecycle=372)


def need(value, why):
    if not value:
        raise ValueError(why)


def encode(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def credential_field(key):
    """Credential-shaped receipt fields are invalid, even when nested or empty."""
    name=re.sub('[^a-z0-9]','',key.casefold())
    return (name in {'authorization','proxyauthorization','apikey','xapikey','awsaccesskeyid'}
            or name.endswith(('token','password','passwd','secret','privatekey','secretkey'))
            or any(word in name for word in ('credential','password','privatekey','secretaccesskey')))


def decode(raw,*,object_required=True):
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate receipt key')
            need(not credential_field(key),'credential-shaped public receipt field refused')
            result[key]=value
        return result
    def invalid(_):
        raise ValueError('nonfinite receipt number')
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=invalid)
    need(type(value) is dict if object_required else type(value) is list,'typed receipt required')
    return value


def relative(value):
    need(type(value) is str and 0<len(value)<=512 and '\\' not in value,'literal relative evidence path')
    path=PurePosixPath(value)
    need(not path.is_absolute() and path.as_posix()==value and len(path.parts)<=16 and
         all(re.fullmatch('[A-Za-z0-9._+@:-]+',p) and p not in ('.','..') for p in path.parts),
         'unsafe evidence path')
    need(not any(p.lower() in PRIVATE_PARTS or p.startswith(('build-tools-test-','current-onboarding-owner-'))
                 for p in path.parts) and path.name not in PRIVATE_FILES and
         not any(p in ('home','trust','bin') for p in path.parts) and
         not any(p.startswith('.') and p not in PUBLIC_DOTFILES for p in path.parts), 'private evidence path refused')
    return path


def absolute(value):
    need(type(value) in (str,Path) or isinstance(value,Path),'literal absolute file path')
    path=Path(value)
    need(path.is_absolute() and '..' not in path.parts and '\x00' not in str(path),'ordinary absolute file path')
    # /home itself may hold the public checkout; hidden key/credential trees may not.
    need(not any(p.lower() in PRIVATE_PARTS or p.startswith(('build-tools-test-','current-onboarding-owner-'))
                 for p in path.parts) and path.name not in PRIVATE_FILES,'private file refused before open')
    need('home' not in path.parts[2:], 'nested private home refused')
    need(not any(p.startswith('.') and p not in PUBLIC_DOTFILES for p in path.parts[1:]),'hidden/private path refused')
    return path


def identity(info):
    # atime changes during ordinary reads; every other stable identity field is bound.
    return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid',
                                         'st_size','st_mtime_ns','st_ctime_ns'))


def _open(path):
    parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
            os.close(parent);parent=child
        return os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
    finally:
        os.close(parent)


def directory_fd(path):
    path=absolute(path);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        return fd
    except BaseException:
        os.close(fd);raise


def read_file(value,cap=MAX_FILE):
    path=absolute(value);fd=_open(path)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap,
             'bounded ordinary single-link public file required')
        chunks=[];total=0
        while block:=os.read(fd,min(65536,cap+1-total)):
            total+=len(block);need(total<=cap,'public file cap');chunks.append(block)
        need(total==before.st_size and identity(before)==identity(os.fstat(fd)),'public file changed during read')
        check=_open(path)
        try:need(identity(before)==identity(os.fstat(check)),'public path identity changed')
        finally:os.close(check)
        raw=b''.join(chunks)
        need(not re.search(br'-----BEGIN (?:PGP PRIVATE KEY BLOCK|[A-Z0-9 ]*PRIVATE KEY)-----|(?im:^)(?:Authorization:|AWS_SECRET_ACCESS_KEY=|GITHUB_TOKEN=)',raw),
             'private/credential material refused')
        return raw
    finally:
        os.close(fd)


def reference(row,cap=MAX_FILE):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int
         and 0<=row['bytes']<=cap and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
         'whole public reference required')
    raw=read_file(row['path'],cap)
    need(pin(raw)=={k:row[k] for k in ('bytes','sha256')},'whole public reference mismatch')
    return raw


def public_command(row):
    need(type(row) is dict and COMMAND_KEYS<=set(row)<=COMMAND_KEYS|{'launch_error'},'exact owned command receipt')
    # Raw command arguments/cwd can name private homes and launch configuration.
    value={k:row[k] for k in ('step','expected','success','log','log_pin','channels')}
    supervision=row['supervision']
    need(supervision is None or type(supervision) is dict,'typed or explicitly unknown supervision receipt')
    fields={'reaped','ownership','group_census','output_complete','timeout','signals','exit','seconds',
            'passed','forced_cleanup','ownership_lost','emergency_retirement'}
    value['supervision']={k:v for k,v in supervision.items() if k in fields} if supervision is not None else {'ownership':'UNKNOWN'}
    value['supervision']['error']=None if supervision is not None and supervision.get('error') is None else 'PRESENT_REDACTED'
    if row.get('launch_error'):value['launch_error']='PRESENT_REDACTED'
    return value


def public_tree(value):
    """Remove configuration/credentials/free-form failures from receipt projections."""
    excluded={'Config','HostConfig','Mounts','GraphDriver','StorageOpt','Env','argv','cwd','command',
              'create_argv','declared_argv','launch_manifest','credentials','password','token','secret',
              'private_key','inspection','created','terminal','failure','retirement_error'}
    excluded={k.lower() for k in excluded}
    if isinstance(value,dict):
        return {k:public_tree(v) for k,v in value.items() if k.lower() not in excluded}
    if isinstance(value,list):return [public_tree(v) for v in value]
    return value


def route_projection(route):
    common={'schema','operation','stage','status','binding','profile_pin','inputs_pin','source_lock',
            'Root_acceptance','native16K','M2','performance','release','owner_facts','owner_cleanup',
            'builds','artifacts','lifecycle','protected_before','protected_after','signature_config_pin'}
    value={k:v for k,v in route.items() if k in common}
    value['commands']=[public_command(row) for row in route['commands']]
    verification=route['stage_signature_verification']
    value['stage_signature_verification']={k:v for k,v in verification.items() if k!='verified'}
    value['stage_signature_verification']['verified']={}
    for key,row in verification['verified'].items():
        value['stage_signature_verification']['verified'][key]={k:v for k,v in row.items() if k!='command'}
        value['stage_signature_verification']['verified'][key]['command']=public_command(row['command'])
    for key in ('failure','prior_failure'):
        if key in route:value[key]={'type':route[key]['type']}
    value['owner_facts']={k:v for k,v in value.get('owner_facts',{}).items() if k in
        ('operation','stage','binding','image','architecture','page_size','execution_domain')}
    value['owner_cleanup']={k:v for k,v in value.get('owner_cleanup',{}).items() if k in
        ('status','operation','stage','binding','natural_retirement','owned_container_absence_verified','protected_state_unchanged')}
    for key in ('protected_before','protected_after'):
        if key in value:
            need(type(value[key]) is dict and set(value[key])=={'alpm_db','alarm_home','root_home','global_trust','global_config','package_cache'},'exact preservation summary roles')
            for row in value[key].values():
                need(type(row) is dict and set(row)=={'files','bytes','sha256'} and type(row['files']) is int
                     and type(row['bytes']) is int and row['files']>=0 and row['bytes']>=0
                     and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
                     'public preservation hashes/counts only; never source tree contents')
    return public_tree(value)


def retain_stage(stage,output,destination,*,binding,profile,inputs,public,public_roots,streams,encoder):
    """Return a bounded capsule and public manifest, never stage acceptance.

    streams are explicit command-index references supplied by the owning executor;
    public context/domain receipts replace private launch/configuration bodies.
    The trusted existing log_evidence.bundle callable receives only fresh public DATA.
    """
    need(stage in SCHEMAS and type(binding) is dict and set(binding)==
         {'source','ref','run','job','attempt','source_lock'},'known exact stage/binding')
    need(type(binding['source']) is str and re.fullmatch('[0-9a-f]{40}',binding['source'])
         and type(binding['ref']) is str and re.fullmatch('refs/heads/codex/[A-Za-z0-9._/-]+',binding['ref'])
         and all(type(binding[k]) is str and re.fullmatch('[1-9][0-9]{0,19}',binding[k]) for k in ('run','job'))
         and type(binding['attempt']) is int and binding['attempt']==1 and type(binding['source_lock']) is dict
         and set(binding['source_lock'])=={'bytes','sha256'} and type(binding['source_lock']['bytes']) is int
         and 0<binding['source_lock']['bytes']<=MAX_FILE and type(binding['source_lock']['sha256']) is str
         and re.fullmatch('[0-9a-f]{64}',binding['source_lock']['sha256']),'typed whole current binding')
    output=absolute(output);destination=absolute(destination)
    need(not destination.is_relative_to(output)
         and not output.is_relative_to(destination),'fresh disjoint retention destination')
    check=directory_fd(output);os.close(check)
    check=directory_fd(destination.parent)
    try:
        try:os.stat(destination.name,dir_fd=check,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise ValueError('fresh retention destination required')
    finally:os.close(check)
    need(type(public_roots) in (tuple,list) and 0<len(public_roots)<=16,'explicit approved public roots')
    roots=[]
    for value in public_roots:
        root=absolute(value);need(len(root.parts)>=3,'overbroad public root')
        fd=directory_fd(root);os.close(fd);roots.append(root)
    def public_reference(row,cap=MAX_FILE):
        path=absolute(row['path'])
        need(any(path.is_relative_to(root) for root in roots),'reference outside approved public roots')
        return reference(row,cap)
    expected=PUBLIC|({'prior_backend','prior_ui'} if stage=='lifecycle' else set())
    need(type(public) is dict and set(public)==expected,'complete exact stage public roles')
    need(type(streams) is dict and set(streams)==({'administrative','outer'} if stage=='lifecycle'
         else {'admission','retirement','proxies'}),'complete exact stage stream roles')
    bodies={};sources={};holds=[]
    def add(name,raw,origin=None):
        relative(name)
        need(name not in bodies and type(raw) is bytes and len(raw)<=MAX_FILE,'unique bounded public member')
        need(len(bodies)<MAX_MEMBERS and sum(map(len,bodies.values()))+len(raw)<=MAX_TOTAL,'public namespace cap')
        bodies[name]=raw
        if origin is not None:sources[name]=origin
    def file(name,path,expected_pin=None,cap=MAX_FILE):
        relative(name)
        need(absolute(path).is_relative_to(output),'selected output body outside stage root')
        raw=read_file(path,cap)
        if expected_pin is not None:need(pin(raw)==expected_pin,'selected body pin mismatch: '+name)
        add(name,raw,dict(path=str(path),**pin(raw)));return raw
    route_raw=read_file(output/'route.json',4*1024**2);route=decode(route_raw)
    need(route['schema']==1 and route['operation']==OP and route['stage']==stage and route['binding']==binding
         and route['Root_acceptance'] is None,'same unaccepted current route')
    facts=route['owner_facts']
    need(facts['architecture']=='aarch64' and type(facts['page_size']) is int and facts['page_size'] in (4096,16384)
         and type(facts['image']) is str and re.fullmatch('sha256:[0-9a-f]{64}',facts['image']),
         'typed actual public owner facts')
    allowed_status={'PASS_CURRENT_ONBOARDING_OWNED_STAGE_DATA_ONLY','HOLD','PENDING_OUTER_CURRENT_STAGE_RETIREMENT'}
    need(route['status'] in allowed_status,'unknown route status')
    cleanup=route.get('owner_cleanup')
    need(type(cleanup) is dict and cleanup['stage']==stage and cleanup['binding']==binding,'actual owner cleanup receipt required')
    need(all(type(cleanup.get(k)) is bool for k in
         ('natural_retirement','owned_container_absence_verified','protected_state_unchanged')),'typed owner cleanup facts')
    if route['status']!='PASS_CURRENT_ONBOARDING_OWNED_STAGE_DATA_ONLY' or any(cleanup.get(k) is not True
            for k in ('natural_retirement','owned_container_absence_verified','protected_state_unchanged')):
        holds.append('UNCERTAIN_OR_PENDING_OWNED_RETIREMENT')
    need(type(route.get('commands')) is list and route['commands'],'actual stage command index required')
    add('route.public.json',encode(route_projection(route)),dict(path=str(output/'route.json'),**pin(route_raw)))
    def command_stream(label,ref,path_pattern=None,rows=None):
        path=absolute(ref['path']);rel=path.relative_to(output).as_posix()
        need(path_pattern is None or re.fullmatch(path_pattern,rel),'wrong stage command-index location')
        raw=reference(ref,1024**2);index=decode(raw,object_required=False)
        need(type(index) is list and 0<len(index)<=512,'finite actual command index')
        if rows is not None:need(index==rows,'route and retained command index differ')
        steps=[row['step'] for row in index]
        if label=='stage':
            if stage!='lifecycle':
                need(steps==['current-'+kind+'-'+suffix for kind in KINDS[stage] for suffix in ('a','b','compare')],
                     'complete exact clean-build and comparison roles')
            else:
                grammar=r'current-(baseline|signature-(setup8|enrollment|first-login|ui)|pkginfo-(setup8|enrollment|first-login|ui)|install-setup8|dependency-inventory|(install|reinstall)(-inventory|-help-(enrollment|first-login|ui))?|after-remove-(install|reinstall)|remove-(setup8|install|reinstall)|final-inventory|absent-(setup8|install|reinstall)-[0-9]+-(e|L)|(setup8|(install|reinstall)-(enrollment|first-login|ui))-(file-list|(owner|stat|sha256)-[0-9]+))'
                need(all(re.fullmatch(grammar,step) for step in steps),'unknown lifecycle public command role')
        elif label in ('admission','administrative'):
            wanted=['import-root-test-public','current-primary','trust-current-test-primary']
            if stage=='lifecycle':wanted+=['baseline-inventory','before-e','before-d']
            wanted+=['owner-current-signature-'+key for key in (('setup8','first_login_backend') if stage=='ui' else ('setup8',))]
            if stage=='lifecycle':wanted+=['restored-inventory','after-e','after-d']
            wanted+=['retire-private-0','no-agent-private-0','retire-private-1','no-agent-private-1']
            if stage!='lifecycle':wanted=['fresh-owner-label','native-daemon']+wanted
            need(steps==wanted,'complete actual public trust and private-retirement receipt roles')
        elif label=='retirement':
            need(steps==['retire-'+str(i)+'-query' for i in range(2*len(KINDS[stage]))]+['final-owner-label'],
                 'complete final owned absence query roles')
        elif label.startswith('proxy-'):
            groups=[['image-inspect'],['native-architecture'],['fresh-name','create','inspect-created','start-attached',
                'inspect-terminal','proxy-final-query','proxy-final-inspect','proxy-final-remove','proxy-final-after']]
            need(steps in groups,'unknown or missing proxy public command roles')
        elif label=='outer':
            need(steps==['fresh-owner-label','native-daemon','fresh-name','create','inspect-created','start-attached',
                'inspect-terminal','retire-query','retire-inspect','retire-remove','retire-after'],
                 'complete final outer owned retirement command roles')
        selected=[];seen=set()
        for i,row in enumerate(index):
            public_row=public_command(row);step=row['step']
            need(type(step) is str and re.fullmatch('[A-Za-z0-9._+-]{1,96}',step) and step not in seen
                 and row['log']=='%03d-%s.log'%(i,step),'exact unique indexed command log')
            seen.add(step)
            # Inspection/launch stdout can carry private Docker configuration.
            if any(word in step for word in ('inspect','create','start-attached','native-daemon')):
                # Public domain observations are required separately, never a producer PASS substitute.
                public_row['private_launch_body_excluded']=True
            else:
                body=read_file(path.parent/row['log'],1024**2)
                need(pin(body)==row['log_pin'],'whole original command log')
                add('streams/'+label+'/'+row['log'],body,dict(path=str(path.parent/row['log']),**pin(body)))
            supervision=row['supervision']
            if row['success'] is not True or type(supervision) is not dict or type(supervision.get('exit')) is not int or any(supervision.get(k)!=v for k,v in
                    dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,timeout=False,signals=[],error=None,exit=0).items()) or (
                    type(supervision) is dict and (supervision.get('passed',True) is not True or any(supervision.get(k)
                        for k in ('forced_cleanup','ownership_lost','emergency_retirement')))):
                holds.append('NON_NATURAL_OR_UNCERTAIN_COMMAND')
            selected.append(public_row)
        add('streams/'+label+'/commands.public.json',encode(selected),dict(path=str(path),**pin(raw)))
        return index
    command_ref=dict(path=str(output/'commands/commands.json'),**pin(read_file(output/'commands/commands.json',1024**2)))
    stage_commands=command_stream('stage',command_ref,r'commands/commands\.json',route['commands'])
    for role,row in public.items():
        raw=public_reference(row)
        if role in ('context','domain'):
            value=decode(raw)
            need(set(value)=={'schema','kind','operation','stage','binding','facts'} and value['schema']==1
                 and value['kind']=='CURRENT_ONBOARDING_PUBLIC_'+role.upper()+'_V3' and value['operation']==OP
                 and value['stage']==stage and value['binding']==binding and type(value['facts']) is dict and value['facts'],
                 'explicit public '+role+' receipt schema')
            forbidden={'Config','HostConfig','Mounts','GraphDriver','StorageOpt','Env','argv','cwd','launch_manifest','private_key','credentials','inside'}
            forbidden={key.lower() for key in forbidden}
            def safe(value):
                if isinstance(value,dict):
                    need(not any(key.lower() in forbidden or any(word in key.lower() for word in
                             ('password','credential','private_key','secret','token')) for key in value),
                         'private domain/context fields')
                    for v in value.values():safe(v)
                elif isinstance(value,list):
                    for v in value:safe(v)
            safe(value)
            facts=value['facts']
            if role=='context':
                need(set(facts)<={'architecture','page_size','image','execution_domain'} and facts.get('architecture')=='aarch64' and type(facts.get('page_size')) is int
                     and facts['page_size'] in (4096,16384) and facts.get('image')==route['owner_facts']['image'],
                     'actual public context observations required')
            else:
                observations=facts.get('observations')
                need(set(facts)<={'execution_domain','observations','signature_policy'} and type(facts.get('execution_domain')) is str and type(observations) is list
                     and 0<len(observations)<=64,'actual public domain observation bodies required')
                if stage=='lifecycle':
                    policy=facts.get('signature_policy')
                    need(type(policy) is dict and set(policy)=={'architecture','SigLevel','LocalFileSigLevel',
                         'offline_verifier','public_TEST_only','private_home_retired','signature_config_pin'}
                         and policy['architecture']=='aarch64' and policy['SigLevel']==policy['LocalFileSigLevel']=='Required'
                         and policy['offline_verifier'] is policy['public_TEST_only'] is True
                         and policy['signature_config_pin']==route.get('signature_config_pin'),
                         'actual public required-signature policy projection required')
                    if policy['private_home_retired'] is not True:holds.append('UNCERTAIN_SIGNATURE_POLICY_RETIREMENT')
                else:need('signature_policy' not in facts,'unknown build-stage signature-config role')
                containers=set();retired=set()
                for item in observations:
                    need(type(item) is dict and set(item)=={'kind','body','source_pin'}
                         and item['kind'] in ('container','image','native_daemon','retirement','signature_policy')
                         and type(item['body']) is dict and item['body'] and set(item['body'])!={'status'}
                         and type(item['source_pin']) is dict and set(item['source_pin'])=={'bytes','sha256'}
                         and type(item['source_pin']['bytes']) is int and 0<item['source_pin']['bytes']<=MAX_FILE
                         and re.fullmatch('[0-9a-f]{64}',item['source_pin']['sha256']),
                         'whole-pinned public domain observations, not producer PASS')
                    body=item['body']
                    if item['kind']=='container':
                        need(set(body)=={'cid','name','image','state'} and type(body['state']) is dict
                             and re.fullmatch('[0-9a-f]{64}',body['cid']) and type(body['name']) is str
                             and re.fullmatch('[A-Za-z0-9._-]{1,128}',body['name'])
                             and body['image']==route['owner_facts']['image']
                             and {'Running','ExitCode'}<=set(body['state'])<=
                                 {'Status','Running','ExitCode','OOMKilled','Dead','Pid'}
                             and type(body['state']['Running']) is bool and type(body['state']['ExitCode']) is int,
                             'actual public container identity/state body')
                        if body['state']['Running'] or body['state']['ExitCode']!=0 or body['state'].get('OOMKilled') is True:
                            holds.append('NON_NATURAL_PUBLIC_CONTAINER_STATE')
                        containers.add(body['cid'])
                    if item['kind']=='retirement':
                        need(set(body)=={'cid','status','absence_verified'} and body['status'] in
                             ('REMOVED_AND_ABSENT','ABSENT','HOLD','UNKNOWN'), 'actual public retirement body')
                        if body['status'] not in ('REMOVED_AND_ABSENT','ABSENT') or body['absence_verified'] is not True:
                            holds.append('UNCERTAIN_PUBLIC_DOMAIN_RETIREMENT')
                        else:
                            need(type(body['cid']) is str and re.fullmatch('[0-9a-f]{64}',body['cid']),
                                 'exact actual public retired CID')
                            retired.add(body['cid'])
                    if item['kind'] not in ('container','retirement'):
                        need(set(body)<={'architecture','image','status','absence_verified','signature_config_pin',
                             'SigLevel','LocalFileSigLevel','offline_verifier','public_TEST_only','private_home_retired'},
                             'closed public observation body keys')
                need({'container','retirement'}<={item['kind'] for item in observations},
                     'public container and retirement observation bodies required')
                if containers!=retired:holds.append('UNMATCHED_PUBLIC_RETIREMENT_IDENTITIES')
        elif role=='inventory':
            rows=raw.decode('ascii').splitlines();names=[]
            for line in rows:
                parts=line.split(' ');need(len(parts)==2 and all(parts),'typed complete inventory row');names.append(parts[0])
            need(len(rows)==COUNTS[stage] and len(set(names))==len(names),'exact typed stage inventory count')
        elif role=='public_test_key':
            need(raw.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----') and b'PRIVATE KEY' not in raw,'public TEST key only')
        elif role in ('runtime','image_qualification','admission'):
            value=decode(raw)
            add('public/'+role+'.data',encode(public_tree(value)),row)
            continue
        add('public/'+role+'.data',raw,row)
    verification=route['stage_signature_verification'];keys=('setup8','first_login_backend') if stage=='ui' else ('setup8',)
    need(set(verification['verified'])==set(keys) and verification['stage']==stage and verification['binding']==binding,'complete actual stage GPG receipt')
    for key in keys:
        data=inputs[key];item=verification['verified'][key]
        need(set(item)=={'archive','signature','public_test_key','fingerprint','status_text','command'}
             and type(item['status_text']) is str and 0<len(item['status_text'].encode())<=1024**2
             and type(item['fingerprint']) is str and re.fullmatch('[0-9A-F]{40}',item['fingerprint']),
             'closed current public signature receipt')
        for field in ('archive','signature'):
            raw=public_reference(data[field]);need(pin(raw)==item[field],'signature input body join')
            add('public/'+key+'.'+field,raw,data[field])
        for field in ('Root_decision','Root_verification'):
            row=data['current_TEST_signature_verification'][field]
            add('public/'+key+'.'+field+'.json',public_reference(row),row)
        status=item['status_text'].encode();need(pin(status)==item['command']['log_pin'],'current public GPG status bytes')
        need(item['public_test_key']==pin(bodies['public/public_test_key.data']),'same whole public TEST key')
        add('public/'+key+'.gpg-status.txt',status)
    def trust_stream(label,row,pattern):
        index=command_stream(label,row,pattern)
        by_step={item['step']:item for item in index}
        for key in keys:
            item=verification['verified'][key];actual=by_step['owner-current-signature-'+key]
            need(actual==item['command'] and bodies['streams/'+label+'/'+actual['log']]==item['status_text'].encode(),
                 'raw current GPG status must join original owned command receipt')
        for i in (0,1):
            row=by_step['no-agent-private-'+str(i)]
            if bodies['streams/'+label+'/'+row['log']]!=b'gpg-connect-agent: no gpg-agent running in this session\n':
                holds.append('UNCERTAIN_PRIVATE_AGENT_ABSENCE')
        return index
    if stage in ('backend','ui'):
        need(set(route['artifacts'])==set(KINDS[stage]) and set(route['builds']['pairs'])==set(KINDS[stage]),'exact current pair roles')
        for kind in KINDS[stage]:
            recipe=profile['packages'][kind]
            need(relative(recipe['archive']).name==recipe['archive'],'literal package archive basename')
            for label in ('a','b'):
                prefix='builds/'+kind+'-'+label;root=output/prefix
                provenance_raw=read_file(root/'provenance.json',1024**2);provenance=decode(provenance_raw)
                fields={'status','mode','network','image','image_id','builder_host_arch','source_date_epoch',
                        'exit_code','expected_packages_sha256','clean_environment_id','recipe_inputs','files',
                        'artifacts','entry_script_sha256','recipe_metadata'}
                add(prefix+'/provenance.public.json',encode(public_tree({k:v for k,v in provenance.items() if k in fields})),
                    dict(path=str(root/'provenance.json'),**pin(provenance_raw)))
                need(set(provenance['recipe_inputs'])==set(recipe['files']),'complete recipe input roles')
                allowed=BUILD_FILES|{'artifacts/'+recipe['archive']}
                need(BUILD_FILES<=set(provenance['files'])<=allowed,'unknown/missing provenance output roles')
                for name,sha in provenance['files'].items():
                    relative(name);raw=read_file(root/name)
                    need(pin(raw)['sha256']==sha,'whole provenance output body')
                    add(prefix+'/'+name,raw,dict(path=str(root/name),**pin(raw)))
                archive_name=prefix+'/artifacts/'+recipe['archive']
                if archive_name not in bodies:file(archive_name,root/'artifacts'/recipe['archive'],route['artifacts'][kind][label])
                need(pin(bodies[archive_name])==route['artifacts'][kind][label],'actual compressed archive body required')
                log=bodies[prefix+'/build.log'];need(log.count(b'Starting check()')==1 and not re.search(br'FAILED|ERROR:|\bskipped\b',log,re.I),'actual non-skipped check log required')
                for name,row in recipe['files'].items():
                    relative(name);need(provenance['recipe_inputs'][name]==row['sha256'],'whole recipe snapshot pin')
                    file(prefix+'/inputs/'+name,root/'inputs'/name,{k:row[k] for k in ('bytes','sha256')})
                clean=provenance['clean_environment_id'];need(re.fullmatch('cachy-asahi-[0-9a-f]{16}',clean),'exact clean identity')
                for suffix in ('.json','.result'):
                    name='owner-state/intents/'+clean+suffix
                    # Retain typed result/retirement facts, never raw create argv or mounts.
                    original=read_file(output/name,1024**2);value=decode(original)
                    keep={k:v for k,v in value.items() if k in ('status','name','retirement')}
                    for field in ('failure','retirement_error'):
                        if value.get(field):keep[field]='PRESENT_REDACTED'
                    if suffix=='.json':keep={'name':value['name'],'image':value['image'],'readonly':value['readonly']}
                    else:
                        if value.get('status')!='PASS_OWNED_GENERIC_BUILD_PROXY' or value.get('failure') or value.get('retirement_error'):holds.append('UNCERTAIN_PROXY_RETIREMENT')
                        if isinstance(keep.get('retirement'),dict):keep['retirement']={k:v for k,v in keep['retirement'].items() if k in ('status','cid','name')}
                    add(name+'.public.json',encode(keep),dict(path=str(output/name),**pin(original)))
            a=bodies['builds/'+kind+'-a/artifacts/'+recipe['archive']];b=bodies['builds/'+kind+'-b/artifacts/'+recipe['archive']]
            need(a==b,'both actual compressed pair bodies must match')
            step='current-'+kind+'-compare';matches=[r for r in stage_commands if r['step']==step]
            need(len(matches)==1,'actual strict comparison log missing')
            comparison=decode(bodies['streams/stage/'+matches[0]['log']])
            need(comparison==route['builds']['pairs'][kind] and comparison['status']=='contents-reproduced' and comparison['errors']==[]
                 and comparison['packages']=={recipe['archive']:dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)},'strict whole pair comparison receipt')
        trust_stream('admission',streams['admission'],r'owner-state/admission/commands\.json')
        command_stream('retirement',streams['retirement'],r'owner-state/retirement/commands\.json')
        proxies=streams['proxies'];need(type(proxies) is list and len(proxies)==6*len(KINDS[stage]),'all three proxy streams per clean build')
        seen=set()
        for i,row in enumerate(proxies):
            need(row['path'] not in seen,'duplicate proxy stream');seen.add(row['path'])
            command_stream('proxy-'+str(i),row,r'owner-state/proxy-[A-Za-z0-9_-]+/commands/commands\.json')
        cleanup_raw=read_file(output/'owner-state/cleanup.json',65536)
        value=decode(cleanup_raw);need(value['stage']==stage and value['binding']==binding,'same build cleanup')
        cleanup_public=dict(stage=stage,binding=binding,failures=['PRESENT_REDACTED']*len(value['failures']),
            retired=[{k:v for k,v in row.items() if k in ('status','name','cid')} for row in value['retired']])
        add('owner-cleanup.json',encode(cleanup_public),dict(path=str(output/'owner-state/cleanup.json'),**pin(cleanup_raw)))
        if value['failures']:holds.append('UNCERTAIN_OWNER_CLEANUP')
    else:
        for key in ('setup8','enrollment','first-login','ui'):
            signed=route['signed'][key]
            for field in ('archive','signature'):
                name='signed/'+key+'.'+field;file(name,output/name,signed[field+'_pin'])
        trust_stream('administrative',streams['administrative'],r'owner-admin/commands/commands\.json')
        command_stream('outer',streams['outer'],r'outer-owner/commands/commands\.json')
        local_raw=read_file(output/'owner-local.json',65536);local=decode(local_raw)
        need(local['operation']==OP and local['stage']==stage and local['binding']==binding,'same lifecycle restoration receipt')
        safe_local={k:local[k] for k in ('status','operation','stage','binding','body_success','protected_state_unchanged')}
        retirement=local.get('private_retirement')
        need(retirement is None or type(retirement) is dict,'typed or explicitly unknown private retirement receipt')
        safe_local['private_retirement']={k:retirement.get(k) if retirement is not None and type(retirement.get(k)) is bool
            else None for k in ('homes_retired','no_sockets','private_directory_absent')}
        if local['status']!='PASS_LOCAL_STAGE_PENDING_OUTER_RETIREMENT' or local.get('failures') or not all(safe_local['private_retirement'].values()):holds.append('UNCERTAIN_PRIVATE_OR_LOCAL_RETIREMENT')
        add('owner-local.public.json',encode(safe_local),dict(path=str(output/'owner-local.json'),**pin(local_raw)))
        final_raw=read_file(output/'outer-owner/receipt.final.json',4*1024**2);final=decode(final_raw)
        need(final['operation']==OP and final['stage']==stage and final['binding']==binding,'same final outer retirement receipt')
        if final['status']!='PASS_OWNED_CURRENT_LIFECYCLE_RETIREMENT' or final.get('failure') or final.get('retirement_error'):holds.append('UNCERTAIN_OUTER_RETIREMENT')
        if route.get('outer_retirement')!=final:holds.append('UNJOINED_OUTER_RETIREMENT')
        add('outer-retirement.public.json',encode({k:final[k] for k in ('status','operation','stage','binding')}),
            dict(path=str(output/'outer-owner/receipt.final.json'),**pin(final_raw)))
        if route['protected_before']!=route['protected_after']:holds.append('PROTECTED_STATE_DRIFT')
        need(set(route['protected_before'])=={'alpm_db','alarm_home','root_home','global_trust','global_config','package_cache'},'complete preservation summaries')
        life=route['lifecycle'];inventory_steps=['current-baseline','current-dependency-inventory','current-install-inventory',
            'current-after-remove-install','current-reinstall-inventory','current-after-remove-reinstall','current-final-inventory']
        need(set(life['inventories'])==set(inventory_steps[1:]),'complete lifecycle inventory receipt roles')
        by_step={row['step']:row for row in stage_commands}
        for step,count in zip(inventory_steps,(372,373,376,373,376,373,372)):
            need(step in by_step,'missing lifecycle inventory body')
            raw=bodies['streams/stage/'+by_step[step]['log']];rows=raw.decode('ascii').splitlines()
            need(raw.endswith(b'\n') and len(rows)==count and len({row.split(' ')[0] for row in rows})==count
                 and all(len(row.split(' '))==2 for row in rows),'actual typed lifecycle inventory body')
            if step!='current-baseline':need(life['inventories'][step]==pin(raw),'whole lifecycle inventory pin')
        need(set(life['payloads'])=={'setup8','install','reinstall'},'complete lifecycle payload receipt roles')
        payloads=[('current-setup8',life['payloads']['setup8'],profile['setup8'])]
        for cycle in ('install','reinstall'):
            need(set(life['payloads'][cycle])=={'enrollment','first-login','ui'},'complete lifecycle payload kinds')
            payloads += [('current-'+cycle+'-'+kind,life['payloads'][cycle][kind],profile['packages'][kind])
                         for kind in ('enrollment','first-login','ui')]
        for label,receipt,recipe in payloads:
            need(set(receipt)=={'verified','files'} and receipt['files']==recipe['payload_files'],
                 'whole typed lifecycle payload source/ownership receipt')
            if receipt['verified'] is not True:holds.append('UNCERTAIN_PAYLOAD_OWNERSHIP')
            wanted=[label+'-file-list']+[label+'-'+field+'-'+str(i) for field in ('owner','stat','sha256')
                                           for i in range(len(recipe['payload_files']))]
            need(set(wanted)<=set(by_step),'actual lifecycle installed-file ownership/stat/hash bodies required')
    # The independent Reader consumes these projections plus explicit public domain/context receipts.
    # The private v2 inside/proxy/config files are intentionally never opened.
    manifest=dict(schema=3,kind=SCHEMAS[stage],operation=OP,stage=stage,binding=binding,
        evidence_state='HOLD' if holds else 'COMPLETE',holds=sorted(set(holds)),
        Root_acceptance=None,component_acceptance=None,hardware_acceptance=None,release_acceptance=None,
        files={name:pin(raw) for name,raw in sorted(bodies.items())},sources=sources,
        legacy_private_launch_replay=False,public_domain_context_required=True)
    add('retention-manifest.json',encode(manifest))
    root=destination/('current-'+stage+'-public-v3')
    parent=directory_fd(destination.parent);rootfd=None
    try:
        os.mkdir(destination.name,0o700,dir_fd=parent)
        child=os.open(destination.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        try:
            os.mkdir(root.name,0o700,dir_fd=child)
            rootfd=os.open(root.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=child)
        finally:os.close(child)
        root_identity=(os.fstat(rootfd).st_dev,os.fstat(rootfd).st_ino)
        for name,raw in sorted(bodies.items()):
            parts=relative(name).parts;node=os.dup(rootfd)
            try:
                for part in parts[:-1]:
                    try:os.mkdir(part,0o700,dir_fd=node)
                    except FileExistsError:pass
                    child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=node)
                    os.close(node);node=child
                fd=os.open(parts[-1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444,dir_fd=node)
                with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
            finally:os.close(node)
    finally:
        if rootfd is not None:os.close(rootfd)
        os.close(parent)
    def validate_staging():
        # Walk only the newly generated, closed public staging tree, never output/private state.
        fd=directory_fd(root)
        try:need((os.fstat(fd).st_dev,os.fstat(fd).st_ino)==root_identity,'staging root identity changed')
        finally:os.close(fd)
        found=set();directories=set()
        for parent,dirs,names in os.walk(root,followlinks=False):
            need(not any((Path(parent)/n).is_symlink() for n in dirs),'staging directory alias')
            directories.update((Path(parent)/name).relative_to(root).as_posix() for name in dirs)
            for name in names:
                path=Path(parent)/name;rel=path.relative_to(root).as_posix();found.add(rel)
                need(rel in bodies and read_file(path)==bodies[rel],'closed stable staging namespace')
        wanted={str(parent) for name in bodies for parent in PurePosixPath(name).parents if str(parent)!='.'}
        need(found==set(bodies) and directories==wanted,'missing/extra staged public evidence')
    validate_staging();capsule=encoder(root)
    need(type(capsule) is bytes and 0<len(capsule)<=MAX_COMPRESSED,'bounded existing evidence encoder output')
    validate_staging()
    return dict(directory=str(root),manifest=manifest,capsule=capsule,capsule_pin=pin(capsule),
                evidence_state=manifest['evidence_state'],Root_acceptance=None)


def emit(result,stream):
    """Existing log_evidence.py CLI envelope, after retain_stage validation."""
    name=Path(result['directory']).name
    need(re.fullmatch('current-(backend|ui|lifecycle)-public-v3',name),'fixed safe evidence marker')
    raw=result['capsule'];need(pin(raw)==result['capsule_pin'],'whole encoded capsule changed')
    stream.write('CACHY_ASAHI_EVIDENCE_BEGIN %s sha256=%s bytes=%d\n'%(name,pin(raw)['sha256'],len(raw)))
    stream.write(base64.encodebytes(raw).decode())
    stream.write('CACHY_ASAHI_EVIDENCE_END '+name+'\n')

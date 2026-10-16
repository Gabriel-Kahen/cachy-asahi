# SPDX-License-Identifier: MIT
"""Actual ordinary 16K CLI execution, explicit physical temporary fixtures only."""
import base64,re,ctypes,hashlib,importlib.machinery,importlib.util,io,json,os,shutil,stat,sys,tarfile,time
from pathlib import Path

def need(ok,why):
    if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(name,path):
    loader=importlib.machinery.SourceFileLoader(name,str(path));spec=importlib.util.spec_from_loader(name,loader);module=importlib.util.module_from_spec(spec);loader.exec_module(module);return module

def startup_clock(raw,nonce,manifest):
    """Initialize only this marked VM's real clock from an observed runner UTC."""
    need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and os.sysconf('SC_PAGE_SIZE')==16384 and
        'management16k=1' in Path('/proc/cmdline').read_text().split(),'marked root management16K clock startup required')
    need(len(raw)<=4096,'clock seed bound');seed=json.loads(raw)
    fields={'schema_version','purpose','source_commit','job_token','nonce','payload_manifest_sha256','host_realtime_ns','host_monotonic_ns'}
    need(set(seed)==fields and type(seed['schema_version']) is int and seed['schema_version']==1 and seed['purpose']=='MANAGEMENT16K_OBSERVED_RUNNER_UTC_STARTUP' and
        seed['source_commit']==manifest['source_commit'] and seed['nonce']==nonce and seed['payload_manifest_sha256']==sha((json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode()) and
        re.fullmatch('[0-9a-f]{16}',seed['job_token']) and all(type(seed[n]) is int and 0<seed[n]<2**63 for n in ('host_realtime_ns','host_monotonic_ns')),'exact source/nonce/payload/clock seed required')
    before=dict(realtime_ns=time.time_ns(),monotonic_ns=time.monotonic_ns())
    time.clock_settime_ns(time.CLOCK_REALTIME,seed['host_realtime_ns'])
    after=dict(realtime_ns=time.time_ns(),monotonic_ns=time.monotonic_ns())
    elapsed=after['monotonic_ns']-before['monotonic_ns']
    need(0<=elapsed<=5*10**9 and seed['host_realtime_ns']<=after['realtime_ns']<=seed['host_realtime_ns']+elapsed+10**9,'VM real clock initialization/readback failed')
    return dict(status='SET_VM_REALTIME_FROM_OBSERVED_RUNNER_UTC',seed=seed,seed_sha256=sha(raw),before=before,after=after,
        uid=0,authority='RECORDED_STARTUP_ANCHOR_NOT_CONTINUOUS_UTC_SYNCHRONIZATION')

def fixture(raw,target):
    """Extract only the finite public signing fixture; no hardlinks/authority."""
    need(len(raw)<=2*1024**2 and not target.exists(),'fresh bounded public fixture required');target.mkdir(mode=0o700);nodes=set();total=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for member in archive:
            name=member.name;need(name and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')) and
                name.split('/')[0] in ('bundle','catalog.json','catalog.json.sig','public.gpg','control.json') and name not in nodes and len(nodes)<128 and member.uid==member.gid==0,'fixture path/count/ownership differs');nodes.add(name)
            path=target/name;need(not any(p.is_symlink() for p in (path,*path.parents)),'fixture ancestor alias refused');path.parent.mkdir(parents=True,exist_ok=True)
            if member.isdir():path.mkdir(exist_ok=True);path.chmod(0o755)
            elif member.isfile():
                total+=member.size;need(0<=member.size<=262144 and total<=1024**2 and member.mode==0o644,'fixture byte/mode bound')
                raw=archive.extractfile(member).read();need(len(raw)==member.size,'fixture truncated');path.write_bytes(raw);path.chmod(0o644)
            elif member.issym():
                need('/' not in member.linkname and member.linkname not in ('','.','..') and name.startswith('bundle/repo/'),'fixture symlink refused');path.symlink_to(member.linkname)
            else:raise ValueError('fixture special/hardlink refused')
    need({'bundle/release.json','bundle/release.json.sig','catalog.json','catalog.json.sig','public.gpg','control.json'}<=nodes,'complete public signed fixture required')

def records(db,rows):
    local=db/'local';local.mkdir(parents=True,mode=0o700);(local/'ALPM_DB_VERSION').write_text('9\n')
    for row in rows:
        path=local/(row['name']+'-'+row['version']);path.mkdir(mode=0o700)
        fields={'NAME':[row['name']],'VERSION':[row['version']],'ARCH':[row.get('arch','any')],'REASON':[str(row.get('reason',1))]}
        fields.update({key:row.get(source,[]) for key,source in [('DEPENDS','depend'),('OPTDEPENDS','optional'),('PROVIDES','provides'),('CONFLICTS','conflict'),('REPLACES','replaces')]})
        (path/'desc').write_text(''.join('%'+key+'%\n'+'\n'.join(values)+'\n\n' for key,values in fields.items() if values))
        files=row.get('files',[]);(path/'files').write_text('%FILES%\n'+'\n'.join(files)+'\n\n' if files else '')

def readonly_db(db):
    for path in sorted(db.rglob('*'),reverse=True):path.chmod(0o555 if path.is_dir() else 0o444)
    db.chmod(0o555);need(not os.access(db,os.W_OK),'ordinary fixture DB must be physically readonly')

def state(root,owned_lock=None):
    value={}
    for path in sorted(root.rglob('*')):
        info=path.lstat();need(len(value)<512 and (path.is_file() or path.is_dir()) and not path.is_symlink(),'bounded fixture state')
        if path.is_file():
            if path==owned_lock:
                need(info.st_size==0 and stat.S_IMODE(info.st_mode)==0,'exact ALPM mode0000 empty lock metadata required');content='NOT_READ_ALPM_LOCK_METADATA_ONLY'
            else:content=sha(path.read_bytes())
            value[str(path.relative_to(root))]=dict(ino=info.st_ino,mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,sha256=content)
    return value

def apps(work,call):
    root=work/'apps';root.mkdir();public=root/'public';fixture(Path('/fixtures/catalog.tar').read_bytes(),public)
    signed=json.loads((public/'control.json').read_bytes());before=json.loads((public/'bundle/base.json').read_bytes())['packages']
    after=before+json.loads((public/'bundle/release.json').read_bytes())['packages']
    cli=['/usr/bin/cachy-asahi-apps','--release',str(public/'bundle'),'--release-sha256',signed['release_sha256'],'--catalog',str(public/'catalog.json'),
        '--catalog-sha256',signed['catalog_sha256'],'--catalog-signature',str(public/'catalog.json.sig'),'--keyring',str(public/'public.gpg'),'--signer',signed['signer']]
    observed=[]
    for operation,rows in (('install',before),('remove',after)):
        db=root/operation/'var/lib/pacman';records(db,rows);readonly_db(db);prior=state(db);snapshot=root/(operation+'.json')
        receipt=call('apps-inventory-'+operation,['/usr/bin/cachy-asahi-apps','inventory','--dbpath',str(db),'--output',str(snapshot)])
        need(receipt['applied']=='NOT_APPLIED' and receipt['sha256']==sha(snapshot.read_bytes()) and stat.S_IMODE(snapshot.stat().st_mode)==0o600,'actual readonly observed inventory differs')
        plan=call('apps-plan-'+operation,cli+['--installed',str(snapshot),'--installed-sha256',receipt['sha256'],'plan',operation,'fixture'])
        need(plan['status']=='PLANNED' and plan['applied']=='NOT_APPLIED' and plan['synthetic'] is True and plan['installer_authority'] is False and
            [v['name'] for v in plan['plan']['additions' if operation=='install' else 'removals']]==['fixture'] and
            plan['plan']['installed_inventory']=='OBSERVED_LOCAL_DB_METADATA_NOT_PAYLOAD_OR_HARDWARE_ATTESTATION' and state(db)==prior,'actual signed observed plan or DB preservation differs')
        observed.append(dict(operation=operation,inventory_sha256=receipt['sha256'],database_sha256=receipt['database_sha256'],not_applied=True,db_preserved=True,inventory=json.loads(snapshot.read_bytes())))
    for verb in (['list'],['search','synthetic'],['show','fixture']):
        result=call('apps-'+verb[0],cli+verb);need(result['synthetic'] is True and result['applied']=='NOT_APPLIED' and result['applications'][0]['id']=='fixture','actual default-prefix signed catalog lookup differs')
    return dict(default_prefix=True,repository_override=False,Git_checkout=False,observed_plans=observed,signer=signed['signer'],production_trust='NOT_ESTABLISHED')

def cache(work,call):
    root=work/'cache-target';cache=root/'var/cache/pacman/pkg';cache.mkdir(parents=True);db=root/'var/lib/pacman';records(db,[])
    keep='held-1-1-any.pkg.tar.xz';drop='selected-1-1-any.pkg.tar.xz';other='unselected-1-1-any.pkg.tar.xz'
    for name in (keep,drop,other):
        (cache/name).write_bytes((name+' fixture archive\n').encode());(cache/(name+'.sig')).write_bytes(b'associated TEST cache signature fixture\n')
    (cache/'unrelated.txt').write_bytes(b'preserve unrelated\n');policy=work/'cache-policy.json'
    pin=lambda name:dict(bytes=(cache/name).stat().st_size,sha256=sha((cache/name).read_bytes()))
    policy.write_text(json.dumps(dict(schema_version=1,cache=str(cache),protected={keep:dict(**pin(keep),signature=pin(keep+'.sig'))})));policy.chmod(0o600)
    plan=work/'cache-plan.json';prior=state(root)
    result=call('cache-plan',['/usr/bin/cachy-asahi-cache','plan','--root',str(root),'--cache',str(cache),'--dbpath',str(db),'--protect',str(policy),'--select',drop,'--output',str(plan)])
    verified=call('cache-verify',['/usr/bin/cachy-asahi-cache','verify',str(plan)]);need(result['status']==verified['status']=='NOT_APPLIED' and state(root)==prior,'cache plan mutated fixtures')
    product=load('management16k_actual_cache','/usr/bin/cachy-asahi-cache');held=product.AlpmLock(root,db);held.acquire()
    try:
        need((db/'db.lck').is_file(),'real libalpm exclusion absent');lock=(db/'db.lck').stat()
        failed=call('cache-concurrent-refusal',['/usr/bin/cachy-asahi-cache','apply',str(plan),'--confirm','REMOVE_SELECTED_CACHE_ARCHIVES','--plan-sha256',result['plan_sha256'],'--quarantine',str(work/'concurrent-quarantine')],expected=1)
        held.check();during=state(root,db/'db.lck')
        need(failed['status']=='REFUSED_OR_INTERRUPTED' and (db/'db.lck').stat().st_ino==lock.st_ino and during=={**prior,'var/lib/pacman/db.lck':during['var/lib/pacman/db.lck']},'concurrent refusal changed data or foreign lock')
    finally:held.release()
    need(state(root)==prior and not (db/'db.lck').exists(),'owned counterpart lock release differs')
    applied=call('cache-apply',['/usr/bin/cachy-asahi-cache','apply',str(plan),'--confirm','REMOVE_SELECTED_CACHE_ARCHIVES','--plan-sha256',result['plan_sha256'],'--quarantine',str(work/'applied-quarantine')])
    removed=sorted([drop,drop+'.sig']);need(applied['status']=='APPLIED' and applied['lock']=='OWN_LOCK_RELEASED' and applied['removed_objects']==removed and applied['reclaimed_bytes'] is None and applied['disk_space']=='NOT_MEASURED','actual selected cache cleanup differs')
    remaining={k:v for k,v in prior.items() if not k.startswith('var/cache/pacman/pkg/'+drop)}
    need(state(root)==remaining and not (db/'db.lck').exists(),'cache cleanup changed protected/unselected/database files')
    journal=json.loads((work/'applied-quarantine/journal.json').read_bytes());need(journal['phase']=='APPLIED' and journal['lock_release']=='OWN_LOCK_RELEASED' and journal['alpm']['version'].startswith('16.') and sorted(journal['purged'])==removed,'durable ALPM cleanup journal differs')
    return dict(real_ALPM_version=journal['alpm']['version'],concurrent_refusal=True,protected_unselected_database_preserved=True,removed_objects=removed,lock_released=True,disk_space='NOT_MEASURED',journal=journal)

def orphans(work,call):
    root=work/'orphans-target';db=root/'var/lib/pacman'
    rows=[dict(name='sample-leaf',version='1-1'),dict(name='sample-provider',version='3-1',provides=['sample-virtual=2']),
        dict(name='sample-oldprovider',version='1-1',provides=['sample-virtual=1']),dict(name='sample-helper',version='2-1'),
        dict(name='sample-consumer',version='1-1',reason=0,depend=['sample-virtual>=2'],optional=['sample-helper>=2: retained feature']),
        dict(name='linux-asahi',version='1-1'),dict(name='custom-important',version='1-1'),dict(name='sample-manual',version='1-1',reason=0)]
    records(db,rows);readonly_db(db);prior=state(db);assessment=work/'orphans-assessment.json';plan=work/'orphans-plan.json'
    call('orphans-assess',['/usr/bin/cachy-asahi-orphans','assess','--root',str(root),'--dbpath',str(db),'--protect','custom-important','--output',str(assessment)])
    value=json.loads(assessment.read_bytes());need(value['candidates']==['sample-leaf','sample-oldprovider'] and not value['broken_dependencies'] and value['libalpm'].startswith('16.') and
        value['packages']['sample-provider']['required_by']==['sample-consumer'] and value['packages']['sample-helper']['optional_required_by']==['sample-consumer'] and value['packages']['linux-asahi']['protected'] is True,'real required/provided/optional/protected assessment differs')
    call('orphans-plan',['/usr/bin/cachy-asahi-orphans','plan',str(assessment),'--select','sample-leaf','--select','sample-oldprovider','--output',str(plan)])
    verified=call('orphans-verify',['/usr/bin/cachy-asahi-orphans','verify',str(plan)]);need(verified['status']=='NOT_APPLIED' and verified['apply_supported'] is False and verified['verification']=='PASS_CURRENT_METADATA_ONLY','orphan plan verify differs')
    for name in ('sample-provider','sample-helper','linux-asahi','custom-important','sample-manual'):
        result=call('orphans-refuse-'+name,['/usr/bin/cachy-asahi-orphans','plan',str(assessment),'--select',name,'--output',str(work/('refused-'+name+'.json'))],expected=1)
        need(result['status']=='NOT_APPLIED' and result['verification']=='REFUSED','protected/needed/explicit orphan selection allowed')
    need(state(db)==prior and not (db/'db.lck').exists(),'readonly orphan assessment altered metadata')
    return dict(required_provided_optional_protected=True,explicit_selected=['sample-leaf','sample-oldprovider'],not_applied=True,database_preserved=True,libalpm=value['libalpm'],assessment=value,plan=json.loads(plan.read_bytes()))

def exercise(nonce,release):
    need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and os.uname().release==release and os.sysconf('SC_PAGE_SIZE')==16384 and
        'management16k=1' in Path('/proc/cmdline').read_text().split(),'marked actual generic16384 guest required')
    original=load('management16k_original_guest','/original_guest.py');raw=Path('/payload.json').read_bytes();manifest=json.loads(raw);original.payload_identity(manifest)
    clock_path=Path('/clock-seed.json');clock_info=clock_path.lstat()
    need(stat.S_ISREG(clock_info.st_mode) and clock_info.st_uid==clock_info.st_gid==0 and clock_info.st_nlink==1 and stat.S_IMODE(clock_info.st_mode)==0o444 and clock_info.st_size<=4096,'root-owned readonly startup clock seed required')
    clock_setup=startup_clock(clock_path.read_bytes(),nonce,manifest)
    for name in manifest['files']:
        info=(Path('/')/name).lstat();need(info.st_uid==info.st_gid==0 and info.st_nlink==1 and not info.st_mode&0o022,'root-owned readonly captured payload required')
    work=Path('/tmp/management16k');work.mkdir(mode=0o700);os.chown(work,23001,23001)
    need(ctypes.CDLL(None).prctl(38,1,0,0,0)==0,'guest no-new-privileges failed');os.setgroups([]);os.setgid(23001);os.setuid(23001)
    status=Path('/proc/self/status').read_text()
    need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==23001 and os.getgroups()==[] and re.search(r'^NoNewPrivs:\s*1$',status,re.M) and
        all(re.search(r'^'+name+r':\s*0+$',status,re.M) for name in ('CapEff','CapPrm','CapAmb')),'ordinary UID/groups/NNP/capability contract differs')
    original.owned_absent();home=work/'home';home.mkdir(mode=0o700)
    for name in ('config','cache','data','state','runtime'):
        directory=home/name;directory.mkdir(mode=0o700);(directory/'sentinel').write_bytes(b'preserve caller settings\n')
    before=original.snapshot(home);temporary=work/'temporary';temporary.mkdir(mode=0o700)
    env=dict(PATH='/usr/bin:/bin',HOME=str(home),TMPDIR=str(temporary),LC_ALL='C',LANG='C',TZ='UTC',PYTHONDONTWRITEBYTECODE='1',
        XDG_CONFIG_HOME=str(home/'config'),XDG_CACHE_HOME=str(home/'cache'),XDG_DATA_HOME=str(home/'data'),XDG_STATE_HOME=str(home/'state'),XDG_RUNTIME_DIR=str(home/'runtime'),
        DISPLAY='',WAYLAND_DISPLAY='',DBUS_SESSION_BUS_ADDRESS='unix:path=/no-session')
    commands=[]
    def call(name,argv,expected=0):
        try:row,out=original.command(argv,env,expected,30)
        except original.CommandFailure as error:
            print('MANAGEMENT16K_COMMAND_FAILURE '+nonce+' '+json.dumps(dict(case=name,command=error.row,stdout_base64=base64.b64encode(error.stdout).decode(),stderr_base64=base64.b64encode(error.stderr).decode()),sort_keys=True,separators=(',',':')),flush=True)
            if name=='apps-plan-install':
                try:
                    observer=load('management16k_signature_observer','/signature_observer.py');diagnostic=observer.observe(original,work,env,error)
                    print('MANAGEMENT16K_SIGNATURE_FAILURE '+nonce+' '+json.dumps(diagnostic,sort_keys=True,separators=(',',':')),flush=True)
                except BaseException as failure:print('MANAGEMENT16K_SIGNATURE_UNAVAILABLE '+nonce+' '+json.dumps(dict(error_type=type(failure).__name__,reason=str(failure)[:160],acceptance_credit=False),sort_keys=True,separators=(',',':')),flush=True)
            raise
        row.update(case=name,owned_processes_absent=original.owned_absent());commands.append(row)
        print('MANAGEMENT16K_COMMAND '+nonce+' '+json.dumps(dict(case=name,command=row,stdout_base64=base64.b64encode(out).decode()),sort_keys=True,separators=(',',':')),flush=True)
        return json.loads(out)
    try:
        results=dict(apps=apps(work,call),cache=cache(work,call),orphans=orphans(work,call))
        need(original.snapshot(home)==before,'caller configuration changed');original.payload_identity(manifest);original.owned_absent()
        need(len(commands)==19,'finite nineteen-command set differs')
        result=dict(status='PASS_GENERIC16K_MANAGEMENT_CLI_PRIVATE_FIXTURES_ONLY',nonce=nonce,kernel=release,architecture='aarch64',page_size=16384,
            uid=23001,gid=23001,groups=[],NNP=True,capabilities_zero=True,commands=commands,results=results,payload_manifest_sha256=sha(raw),payload_preserved=True,
            user_config_preserved=True,owned_processes_absent=True,fixture_archive_sha256=manifest['fixture_archive_sha256'],clock_setup=clock_setup,
            package_registration='DATA_STAGED_PRIVATE_ROOT_NOT_ALPM_INSTALLATION',GUI='NOT_RUN',hardware='NOT_RUN',native_ALPM_lifecycle='SEPARATE_INPUT_EVIDENCE',release_admission=False)
    finally:
        original.owned_absent()
        need(not any(path.name=='db.lck' for path in work.rglob('*')),'unreleased private ALPM lock; retain fixture until VM retirement')
        # Only after preservation proof, restore our own fixture directory modes
        # so readonly metadata can be retired. Never touch captured /usr paths.
        for path in work.rglob('*'):
            if path.is_dir() and not path.is_symlink():
                need(path.stat().st_uid==os.getuid(),'foreign fixture cleanup refused');path.chmod(0o700)
        shutil.rmtree(work)
    need(not work.exists(),'owned guest fixtures remain');result['private_fixtures_removed']=True;return result

if __name__=='__main__':
    try:
        need(len(sys.argv)==3 and len(sys.argv[1])==32,'guest argument identity required');result=exercise(sys.argv[1],sys.argv[2]);text=json.dumps(result,sort_keys=True,separators=(',',':'))
        need(len(text.encode())<=65536,'guest report byte bound');print('MANAGEMENT16K_REPORT '+text,flush=True)
    except BaseException as error:print('MANAGEMENT16K_ERROR '+type(error).__name__+': '+str(error)[:160],flush=True);raise

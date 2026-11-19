"""Scoped Topmem journal recovery before the caller removes the base image."""
import hashlib
import math
import os
from pathlib import Path
import re
import stat
import time
from types import ModuleType

BASE_PACKET = '16498f24649b981e99d803682e87e632bbba289e4bb6d3169d7608d7cecdc617'
ERRORS = frozenset({'recovery-deadline', 'recovery-state', 'recovery-source', 'recovery-root',
 'recovery-missing-journal', 'recovery-unexpected-journal', 'recovery-build-policy', 'recovery-lifecycle-policy',
 'recovery-key-owner', 'recovery-query', 'recovery-inspect', 'recovery-remove', 'recovery-absence',
 'recovery-attempt-uncertain', 'recovery-cancelled', 'recovery-os-error', 'recovery-policy-refused', 'recovery-close'})

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

    def need(value, reason):
        if not value: raise ValueError(reason)


    def live(end):
        need(type(end) in (int, float) and math.isfinite(end) and time.monotonic() < end, 'recovery-deadline')


    def result():
        return {'status': 'FAIL', 'absence_verified': False, 'cancelled': False,
                'errors': [], 'disposition': 'UNKNOWN', 'containers': 0}


    def fail(row, error, producer=None):
        cancelled = isinstance(error, KeyboardInterrupt) or (producer is not None and isinstance(error, producer.jr.Cancelled))
        row['cancelled'] |= cancelled
        reason = ('recovery-cancelled' if cancelled else error.args[0] if type(error) is ValueError
                  and len(error.args) == 1 and type(error.args[0]) is str and error.args[0] in ERRORS
                  else 'recovery-os-error' if isinstance(error, OSError) else 'recovery-policy-refused')
        row['status'] = 'FAIL'
        if reason not in row['errors'] and len(row['errors']) < 16: row['errors'].append(reason)


    def read(c, path, end, limit=65536):
        live(end); info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
             and info.st_gid == os.getgid() and stat.S_IMODE(info.st_mode) == 0o600, 'recovery-state')
        raw = c.read(path, limit, deadline=end); after = path.lstat()
        fields = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(all(getattr(info,k) == getattr(after,k) for k in fields), 'recovery-state')
        return raw, info


    def state(c, config, end):
        root = Path(config['jobroot']); ref = config.get('caller_state')
        need(type(ref) is dict and set(ref) == {'sha256','bytes','dev','ino'}
             and type(ref['sha256']) is str and re.fullmatch('[0-9a-f]{64}', ref['sha256'])
             and all(type(ref[k]) is int and ref[k] >= 0 for k in ('bytes','dev','ino')), 'recovery-state')
        raw, info = read(c, root / 'caller-state.json', end)
        need(len(raw) == ref['bytes'] and hashlib.sha256(raw).hexdigest() == ref['sha256']
             and (info.st_dev,info.st_ino) == (ref['dev'],ref['ino']), 'recovery-state')
        value = c.decode(raw)
        need(set(value) == {'schema_version','baseline_attempted','addon_attempted','signing_attempted'}
             and type(value['schema_version']) is int and value['schema_version'] == 1
             and all(type(value[k]) is bool for k in ('baseline_attempted','addon_attempted','signing_attempted'))
             and (not value['addon_attempted'] or value['baseline_attempted']), 'recovery-state')
        return value


    def addon(c, config, end):
        need(config['packet_sha256'] == BASE_PACKET, 'recovery-source')
        manifest = c.decode(c.pinned(ADDON / 'source-manifest.json', MANIFEST, deadline=end))
        expected={'addon.py','lifecycle-entry.sh','smoke.py','recipes.lock.json'}|{'recipes/'+v+'/'+n for v in ('current','upgrade-fixture') for n in RECIPE_FILES}
        if PROFILE == 'fish-history-v1':expected|={'engine.py','original-config.fish'}
        need(type(manifest) is dict and set(manifest)=={'schema_version','files','recipes_sha256','parent_packet_sha256'}
             and type(manifest['schema_version']) is int and manifest['schema_version']==1
             and manifest['parent_packet_sha256']==BASE_PACKET and type(manifest['files']) is dict
             and set(manifest['files'])==expected and len(expected)==SOURCE_MEMBERS,'recovery-source')
        buffers = {}
        for name, row in manifest['files'].items():
            need(type(name) is str and '..' not in Path(name).parts and not Path(name).is_absolute(), 'recovery-source')
            path = ADDON / name; raw = c.pinned(path, row['sha256'], deadline=end)
            need(len(raw) == row['bytes'] and stat.S_IMODE(path.lstat().st_mode) == row['mode'], 'recovery-source')
            buffers[name] = raw
        if PROFILE == 'fish-history-v1':
            engine=ModuleType('captured_fish_recovery_engine');engine.__file__=str(ADDON/'engine.py')
            exec(compile(buffers['engine.py'],engine.__file__,'exec'),engine.__dict__)
            entry=ModuleType('captured_fish_recovery_entry');entry.__file__=str(ADDON/'addon.py')
            exec(compile(buffers['addon.py'],entry.__file__,'exec'),entry.__dict__)
            return entry.bind(engine)
        value = ModuleType('captured_topmem_recovery_policy'); value.__file__ = str(ADDON / 'addon.py')
        exec(compile(buffers['addon.py'], value.__file__, 'exec'), value.__dict__)
        return value


    def retry(action, row, producer, end):
        for attempt in range(2):
            live(end)
            try: return action()
            except (producer.jr.Cancelled, KeyboardInterrupt) as error:
                fail(row, error, producer)
                if attempt: raise


    def close(broker, row, producer):
        seen = set()
        for runner in (getattr(broker,'runner',None), getattr(broker,'cleanup_runner',None)):
            if runner is None or id(runner) in seen: continue
            seen.add(id(runner)); action = getattr(runner,'close',None)
            if callable(action):
                try: action()
                except BaseException as error:
                    if isinstance(error,(producer.jr.Cancelled,KeyboardInterrupt)): fail(row,error,producer)
                    else: fail(row,ValueError('recovery-close'))


    def build(worker, config, c, producer, end, row):
        path = Path(config['jobroot']) / (ADDON_SCOPE+'/build-containers.json')
        need(path.exists() and not path.is_symlink(), 'recovery-missing-journal')
        data = c.decode(read(c,path,end)[0]); rows = data.get('containers'); out = path.parent
        need(type(rows) is list and len(rows) <= 4, 'recovery-build-policy')
        expected = [{'/inputs': str(out/(v+'-'+str(n))/'inputs'), '/out': str(out/(v+'-'+str(n))/'artifacts'),
                     '/builder-entry.sh': str(Path(config['snapshot'])/'scripts/build/container-entry.sh'),
                     '/expected-packages.lock': str(out/(v+'-'+str(n))/'expected-packages.lock')}
                    for v in ('current','upgrade-fixture') for n in (1,2)]
        selected = []
        for item in rows:
            need(type(item) is dict and item.get('mounts') in expected and item['mounts'] not in selected
                 and item.get('env') == {'CACHY_ASAHI_CONTAINER':'1','SOURCE_DATE_EPOCH':'1791748800'}
                 and item.get('cmd') == ['/builder-entry.sh'] and type(item.get('name')) is str
                 and re.fullmatch('cachy-asahi-[0-9a-f]{16}', item['name']), 'recovery-build-policy')
            selected.append(item['mounts'])
        broker = None
        try:
            broker = worker.owner(config,producer,end); broker.journal_path = path
            retry(lambda: broker.initialize(data['identity']['daemon']),row,producer,end)
            # The captured broker binds endpoint/daemon/UID/tools/image/nonce/local pins.
            broker._journal()
            raw = retry(lambda: broker.cleanup(remove_image=False),row,producer,end)
            need(type(raw) is dict and type(raw.get('absence_verified')) is bool and type(raw.get('cancelled')) is bool
                 and raw.get('status') in ('PASS','FAIL') and type(raw.get('errors')) is list, 'recovery-build-policy')
            row['containers'] = len(rows); row['absence_verified'] = raw['absence_verified']; row['cancelled'] |= raw['cancelled']
            if raw['status'] != 'PASS' or raw['errors']: fail(row,ValueError('recovery-absence'))
            row['disposition'] = 'ABSENT' if row['absence_verified'] else 'UNKNOWN'
            if row['absence_verified'] and not row['errors'] and not row['cancelled']: row['status'] = 'PASS'
        finally:
            if broker is not None: close(broker,row,producer)


    def key_owner(c, config, end):
        ref = config.get(KEY_REF); root = Path(config['jobroot'])
        need(type(ref) is dict and set(ref) == {'path','sha256'} and type(ref['path']) is str, 'recovery-key-owner')
        path = Path(ref['path'])
        need(path.is_absolute() and path == path.resolve() and path.is_relative_to(root) and '..' not in path.parts,
             'recovery-key-owner')
        raw, _ = read(c,path,end); need(hashlib.sha256(raw).hexdigest() == ref['sha256'], 'recovery-key-owner')
        value = c.decode(raw)
        need(type(value.get('fingerprint')) is str and re.fullmatch('[A-F0-9]{40}',value['fingerprint'])
             and type(value.get('certificate_sha256')) is str and re.fullmatch('[0-9a-f]{64}',value['certificate_sha256']), 'recovery-key-owner')
        return value


    def query(broker, args, row, producer, end):
        value = retry(lambda: broker._operation(args,cleanup=True,timeout=min(30,end-time.monotonic())),row,producer,end)
        need(type(value.returncode) is int and value.returncode == 0 and type(value.stdout) is bytes, 'recovery-query')
        return value.stdout


    def find(broker, name, nonce, row, producer, end, identifier=None):
        selectors = [['name=^/'+name+'$'], ['label='+LABEL+'='+nonce,'ancestor='+broker.image]]
        if identifier is not None: selectors.insert(0,['id='+identifier])
        found = set()
        for selectors_row in selectors:
            argv = ['container','ls','--all','--no-trunc','--format','{{json .}}']
            for selector in selectors_row: argv += ['--filter',selector]
            raw = query(broker,argv,row,producer,end); records = [broker.accepted.decode(line) for line in raw.splitlines() if line]
            need(len(records) <= 1 and all(type(item) is dict and item.get('Names') == name and type(item.get('ID')) is str
                 and re.fullmatch('[0-9a-f]{64}',item['ID']) and (identifier is None or item['ID'] == identifier) for item in records), 'recovery-query')
            found.update(item['ID'] for item in records)
        need(len(found) <= 1,'recovery-query')
        return next(iter(found)) if found else None


    def inspect(broker, identifier, reservation, fp, repo, row, producer, end):
        records = broker.accepted.decode(query(broker,['container','inspect',identifier],row,producer,end))
        need(type(records) is list and len(records) == 1 and type(records[0]) is dict,'recovery-inspect')
        item = records[0]; config = item['Config']; host = item['HostConfig']
        labels = dict(broker.image_config.get('Labels') or {}); labels[LABEL] = reservation['nonce']
        env = dict(entry.split('=',1) for entry in broker.image_config.get('Env',[]))
        env.update({'CACHY_ASAHI_CONTAINER':'1',SIGNER_ENV:fp}); actual_env = config.get('Env') or []
        expected_cmd = [ENTRY] if PROFILE == 'topmem-v1' else [ENTRY,'--deadline',str(reservation['work_deadline']),'--nonce',reservation['nonce']]
        resources = {'AutoRemove':True,'Privileged':False,'ReadonlyRootfs':False,'NetworkMode':'none','IpcMode':'private',
            'PidMode':'','Memory':1024**3,'MemorySwap':1024**3,'NanoCpus':2*10**9,'PidsLimit':256,
            'CapDrop':['ALL'],'SecurityOpt':['no-new-privileges'],'Tmpfs':{'/tmp':'rw,nosuid,nodev,exec,size=256m'}}
        need(item.get('Id') == identifier and item.get('Name') == '/'+reservation['name'] and item.get('Image') == broker.image
             and config.get('User') == '0:0' and config.get('Labels') == labels
             and config.get('Entrypoint') == ['/bin/bash'] and config.get('Cmd') == expected_cmd
             and len({value.split('=',1)[0] for value in actual_env}) == len(actual_env)
             and dict(value.split('=',1) for value in actual_env) == env
             and all(type(host.get(k)) is type(v) and host[k] == v for k,v in resources.items())
             and type(host.get('CapAdd')) is list and sorted(host['CapAdd']) == ['CHOWN','SETGID','SETUID']
             and not any(host.get(k) for k in ('Devices','DeviceRequests','Binds','VolumesFrom','Links','PortBindings','GroupAdd')), 'recovery-inspect')
        mounts = item.get('Mounts')
        expected = {'/repo':str(repo),ENTRY:str(ADDON/'lifecycle-entry.sh'),PROBE:str(ADDON/'smoke.py')}
        if PROFILE == 'fish-history-v1':expected['/fish-original-config.fish']=str(ADDON/'original-config.fish')
        need(type(mounts) is list and len(mounts) <= (4 if PROFILE == 'topmem-v1' else 5) and all(m.get('Type') in ('bind','tmpfs') for m in mounts), 'recovery-inspect')
        bind = [m for m in mounts if m['Type'] == 'bind']
        need(len(bind) == (3 if PROFILE == 'topmem-v1' else 4) and {m['Destination']:(m['Source'],m['RW']) for m in bind} == {k:(v,False) for k,v in expected.items()}, 'recovery-inspect')


    def repository_names(repo, end):
        """Bound the old policy's recursive custody walk to its exact flat21 files."""
        def entries(path, maximum):
            found = []
            with os.scandir(path) as rows:
                for entry in rows:
                    live(end); need(len(found) < maximum, 'recovery-lifecycle-policy')
                    found.append((entry.name, entry.stat(follow_symlinks=False)))
            return found
        top = entries(repo,3)
        need({name for name,_ in top} == {'v1','v2','public-key.asc'}, 'recovery-lifecycle-policy')
        need(all(stat.S_ISDIR(info.st_mode) if name in ('v1','v2') else stat.S_ISREG(info.st_mode)
                 for name,info in top), 'recovery-lifecycle-policy')
        package_names = []
        for version,release in (('v1','1'),('v2','2')):
            rows = entries(repo/version,10)
            names = [name for name,_ in rows if re.fullmatch(re.escape(NAME)+r'-0\.1\.0-'+release+r'-any\.pkg\.tar\.(xz|gz|zst)',name)]
            need(len(names) == 1 and all(stat.S_ISREG(info.st_mode) for _,info in rows), 'recovery-lifecycle-policy')
            expected = {names[0],names[0]+'.sig',REPO+'.db.tar.gz',REPO+'.db.tar.gz.sig',
                        REPO+'.files.tar.gz',REPO+'.files.tar.gz.sig',REPO+'.db',REPO+'.db.sig',REPO+'.files',REPO+'.files.sig'}
            need({name for name,_ in rows} == expected, 'recovery-lifecycle-policy')
            package_names += names
        return package_names


    def lifecycle(worker, config, c, producer, policy, end, row):
        root = Path(config['jobroot']); path = root/(ADDON_SCOPE+'/lifecycle-container.json')
        need(path.exists() and not path.is_symlink(), 'recovery-missing-journal')
        reservation = c.decode(read(c,path,end)[0]); key = key_owner(c,config,end); fp = key['fingerprint']
        required={'scope','image','daemon','nonce','name','argv','attempted','result','cleanup'}
        allowed={'natural','evidence_sha256'} if PROFILE == 'fish-history-v1' else set()
        need(type(reservation) is dict and required <= set(reservation) <= required|allowed
             and reservation['scope'] == ADDON_SCOPE+'-lifecycle' and reservation['nonce'] == config['nonce']
             and reservation['name'] == NAME+'-'+config['nonce'] and reservation['attempted'] is True
             and reservation['result'] in ('UNKNOWN','provisional-zero') and reservation['cleanup'] == 'PARENT RECOVERY REQUIRED', 'recovery-lifecycle-policy')
        if PROFILE == 'fish-history-v1' and reservation['result']=='provisional-zero':
            need(set(reservation)==required|allowed and type(reservation['evidence_sha256']) is str
                 and re.fullmatch('[0-9a-f]{64}',reservation['evidence_sha256']), 'recovery-lifecycle-policy')
            policy.natural(reservation['natural'])
            evidence=read(c,path.parent/'lifecycle-evidence.json',end,1024**2)[0]
            need(hashlib.sha256(evidence).hexdigest()==reservation['evidence_sha256'],'recovery-lifecycle-policy')
        if PROFILE == 'fish-history-v1':
            reservation=dict(reservation,work_deadline=config['work_deadline'])
        broker = None
        try:
            broker = worker.owner(config,producer,end)
            retry(lambda: broker.initialize(reservation['daemon']),row,producer,end)
            need(reservation['image'] == broker.image and reservation['daemon'] == broker.daemon, 'recovery-lifecycle-policy')
            repo = root/(ADDON_SCOPE+'/repo'); package_names = repository_names(repo,end)
            need(reservation['argv'] == policy.lifecycle_argv(config,broker.image,fp), 'recovery-lifecycle-policy')
            with policy.repository_custody(repo,root,package_names,key['certificate_sha256'],end) as check:
                identifier = find(broker,reservation['name'],config['nonce'],row,producer,end)
                if identifier is not None:
                    inspect(broker,identifier,reservation,fp,repo,row,producer,end); check()
                    value = retry(lambda:broker._operation(['container','rm','--force',identifier],cleanup=True,
                        timeout=min(30,end-time.monotonic())),row,producer,end)
                    if type(value.returncode) is not int or value.returncode != 0: fail(row,ValueError('recovery-remove'))
                    row['containers'] = 1
                need(find(broker,reservation['name'],config['nonce'],row,producer,end,identifier) is None,'recovery-absence')
                check(); row['absence_verified'] = True; row['disposition'] = 'REMOVED' if identifier else 'ABSENT'
            process = config.get('addon_process')
            completed = type(process) is dict and process.get('reaping') == 'COMPLETED' and all(
                type(process.get(k)) is int and process[k] == 0 for k in ('natural_poll_code','runner_return_code'))
            if reservation['result'] == 'UNKNOWN' or not completed:
                if identifier is None: row.update(absence_verified=False,disposition='UNKNOWN')
                fail(row,ValueError('recovery-attempt-uncertain'))
            if row['absence_verified'] and not row['errors'] and not row['cancelled']: row['status'] = 'PASS'
        finally:
            if broker is not None: close(broker,row,producer)


    def recover(worker, config, cleanup_end):
        output = {'schema_version':1,'status':'FAIL','absence_verified':False,'cancelled':False,
                  'deadline_at':None,'build':result(),'lifecycle':result(),'errors':[]}
        producer = None
        try:
            live(cleanup_end); live(config['cleanup_deadline'])
            end = min(cleanup_end,config['cleanup_deadline'],time.monotonic()+180)
            live(end); output['deadline_at'] = end
            root = Path(config['jobroot']); info = root.lstat()
            need(root.is_absolute() and root == root.resolve() and stat.S_ISDIR(info.st_mode)
                 and info.st_uid == os.getuid() and info.st_gid == os.getgid() and stat.S_IMODE(info.st_mode) == 0o700,'recovery-root')
            with worker.graph(config,end) as (c,producer,load):
                state_value = state(c,config,end)
                if not state_value['addon_attempted']:
                    need(all(not (root/ADDON_SCOPE/name).exists() and not (root/ADDON_SCOPE/name).is_symlink()
                         for name in ('build-containers.json','lifecycle-container.json')),'recovery-unexpected-journal')
                    for name in ('build','lifecycle'): output[name].update(status='PASS',absence_verified=True,disposition='NOT_ATTEMPTED')
                else:
                    policy = addon(c,config,end)
                    for name,action in (('build',build),('lifecycle',lifecycle)):
                        try:
                            if name == 'build': action(worker,config,c,producer,end,output[name])
                            else: action(worker,config,c,producer,policy,end,output[name])
                            live(end)
                        except BaseException as error: fail(output[name],error,producer)
                live(end)
        except BaseException as error:
            for name in ('build','lifecycle'): fail(output[name],error,producer)
        output['absence_verified'] = all(output[n]['absence_verified'] for n in ('build','lifecycle'))
        output['cancelled'] = any(output[n]['cancelled'] for n in ('build','lifecycle'))
        output['errors'] = list(dict.fromkeys(error for n in ('build','lifecycle') for error in output[n]['errors']))[:16]
        if all(output[n]['status'] == 'PASS' for n in ('build','lifecycle')) and not output['cancelled'] and not output['errors']:
            output['status'] = 'PASS'
        return output

    return SimpleNamespace(need=need,live=live,result=result,fail=fail,read=read,state=state,addon=addon,retry=retry,close=close,build=build,key_owner=key_owner,query=query,find=find,inspect=inspect,repository_names=repository_names,lifecycle=lifecycle,recover=recover,ROOT=ROOT,ADDON=ADDON,PROFILE=PROFILE,NAME=NAME,ADDON_SCOPE=ADDON_SCOPE,SIGNING=SIGNING,KEY_REF=KEY_REF,PURPOSE=PURPOSE,PRODUCER=PRODUCER,MANIFEST=MANIFEST,LABEL=LABEL,REPO=REPO,ENTRY=ENTRY,PROBE=PROBE,SIGNER_ENV=SIGNER_ENV,SOURCE_MEMBERS=SOURCE_MEMBERS,BASE_PACKET=BASE_PACKET,ERRORS=ERRORS)

# SPDX-License-Identifier: MIT
"""Passive bounded recovery evidence verification. No process or filesystem actor."""
import base64
import copy
import hashlib
import json
import re
from security_recovery_state import (NAME, NEW, OLD, PROTOCOL, RecoveryPolicy,
    classify_recovery, verify_recovered, snapshot_sha256, encoded)
from security_recovery_metadata import MetadataReference, normalize_desc, window

OP = 'security-alpm-interrupted-recovery-v1'
PREFIX = '/opt/native-security-v1/recovery/'
PHASES = ('CREATED','BASELINE_RECORDED','REFERENCE_READY','BASELINE_RESTORED',
 'NORMAL_EPISODE_PASSED','RECOVERY_BASELINE_RESTORED','PRIOR_INSTALLED',
 'INTERRUPT_INTENT','CHECKPOINT_VERIFIED','INTERRUPTED_RETIRED','CLEANUP_INTENT',
 'CLEANUP_COMPLETED','RECOVERY_INSTALL_INTENT','RECOVERY_INSTALLED','RECOVERY_VERIFIED','FINALIZED')


def need(ok, reason):
    if not ok: raise ValueError(reason)


def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def pairs(items):
    out = {}
    for k,v in items:
        need(k not in out,'duplicate recovery JSON field'); out[k]=v
    return out


def parse(raw, cap):
    need(type(raw) is bytes and 0 < len(raw) <= cap,'bounded recovery JSON bytes')
    return json.loads(raw,object_pairs_hook=pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite recovery JSON')))


def decode(value, cap):
    need(type(value) is str and len(value) <= 4*((cap+2)//3),'bounded base64 DATA')
    raw=base64.b64decode(value,validate=True)
    need(len(raw)<=cap and base64.b64encode(raw).decode('ascii')==value,'canonical base64 DATA')
    return raw


def content(row):
    return None if row is None else {k:v for k,v in row.items() if k not in ('dev','ino','nlink')}


def natural(row, seconds):
    need(type(row) is dict and type(row.get('exit')) is int and row['exit']==0
        and row.get('error') is None and row.get('timeout') is row.get('forced_retirement') is False
        and all(row.get(k) is True for k in ('passed','reaped','group_absent','descendants_absent',
            'pid_reserved_until_retirement','natural_exit','leader_held_until_group_inspection','exit_observed_via_waitpid'))
        and row.get('ownership_lost') is row.get('forced_cleanup') is False
        and row.get('cleanup_member_uids')==[] and row.get('retirement')=='REAPED'
        and row.get('method')=='OWNED_NATURAL_COMMAND','natural reserved owned command')
    need(type(row.get('wall_started')) is int and type(row.get('wall_finished')) is int
        and 0<row['wall_started']<=row['wall_finished']<=row['wall_started']+seconds+15,
        'bounded owned UTC interval')
    need(type(row.get('pid')) is int and row['pid']>1 and type(row.get('starttime')) is int
        and row['starttime']>0,'original owned process identity')


def signature(status, signer):
    need(type(status) is str and len(status)<=65536 and status.isascii(),'bounded signature status')
    rows=[]
    for line in status.splitlines():
        need(line.startswith('[GNUPG:] '),'machine signature status only')
        row=line[9:].split();need(row and row[0] in ('NEWSIG','KEY_CONSIDERED','SIG_ID','GOODSIG','VALIDSIG'),
            'closed valid nonexpired signature status');rows.append(row)
    valid=[r for r in rows if r[0]=='VALIDSIG']
    need(len(valid)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==signer
        and sum(r[0]=='GOODSIG' for r in rows)==1,'one exact TEST primary signer')


def key_listing(status, signer, interval):
    need(type(status) is str and len(status)<=65536,'bounded public TEST listing')
    rows=[r.split(':') for r in status.splitlines()]
    pubs=[r for r in rows if r[0]=='pub'];fprs=[r for r in rows if r[0]=='fpr'];uids=[r for r in rows if r[0]=='uid']
    need(len(pubs)==len(fprs)==len(uids)==1 and not any(r[0] in ('sub','sec','ssb') for r in rows),'one public TEST key')
    p=pubs[0]
    need(len(p)>11 and p[1] not in ('r','e','d','i') and 's' in p[11].lower()
        and re.fullmatch('[1-9][0-9]{0,18}',p[5]) and re.fullmatch('[1-9][0-9]{0,18}',p[6]),'usable TEST signing key')
    created,expires=int(p[5]),int(p[6])
    need(expires-created==86400 and created<=interval['wall_started']<=interval['wall_finished']<expires
        and len(fprs[0])>9 and fprs[0][9]==signer and len(uids[0])>9
        and uids[0][9]=='TEST ONLY security-maintenance <security@test.invalid>','fresh scoped one-day TEST authority')
    return created,expires


def journal_data(raw, binding):
    """Validate exported journal DATA without importing its writer or load()."""
    need(type(raw) is str and raw.isascii() and 0<len(raw)<=1048576 and raw.endswith('\n'),'whole bounded journal')
    previous='0'*64;phase=-1;pending=None;records=[];phases={};commands=[]
    for i,line in enumerate(raw.encode('ascii').splitlines()):
        need(i<256 and len(line)+1<=65536,'finite journal records')
        row=parse(line,65536)
        need(type(row) is dict and set(row)=={'schema','sequence','binding','previous','event','data','sha256'}
            and type(row['schema']) is int and row['schema']==1 and type(row['sequence']) is int and row['sequence']==i
            and row['binding']==binding and row['previous']==previous and encoded(row)==line,'canonical bound journal row')
        payload={k:v for k,v in row.items() if k!='sha256'}
        need(pin(encoded(payload))['sha256']==row['sha256'] and type(row['data']) is dict,'journal hashchain')
        event,data=row['event'],row['data'];need(phase<len(PHASES)-1,'terminal journal')
        if event=='COMMAND_INTENT':
            need(phase>=0 and pending is None,'one pending command');pending=data
        elif event=='COMMAND_COMPLETED':
            need(pending is not None and data.get('step')==pending.get('step'),'paired command completion')
            commands.append((PHASES[phase],pending,data));pending=None
        else:
            need(pending is None and event==PHASES[phase+1],'exact forward phase; failed or resumed journals refused')
            phase+=1;phases[event]=data
        records.append(row);previous=row['sha256']
    need(phase==len(PHASES)-1 and pending is None,'complete finalized journal; no resume')
    return dict(phases=phases,commands=commands,pin=pin(raw.encode('ascii')),resume_allowed=False)


def validate_commands(rows,binding,signer):
    steps=('inspect-test-key','verify-signature','signed-candidate-install','remove-reference-candidate',
        'remove-reference-candidate','inspect-test-key','verify-prior-signature','prior-required-install',
        'inspect-test-key','verify-signature','signed-candidate-install','verify-recovered')
    need(type(rows) is list and tuple(r.get('step') for r in rows)==steps,'exact finite native recovery command roles')
    archive=PREFIX+NAME+'-0.1.0-2-any.pkg.tar.zst';prior=PREFIX+NAME+'-0.1.0-1-any.pkg.tar.zst'
    config=PREFIX+'pacman.conf';trust=PREFIX+'trust';keyring=PREFIX+'test-public.gpg'
    pacman=['/usr/bin/pacman','--config',config]
    key=['/usr/bin/gpg','--batch','--no-options','--no-autostart','--homedir',trust,'--no-auto-key-retrieve','--with-colons','--list-keys']
    authority=None;installs=[]
    for row in rows:
        step=row['step'];extra={'status_ascii'} if step in ('inspect-test-key','verify-signature','verify-prior-signature') else set()
        need(set(row)=={'step','argv','seconds','output_cap','stdout','stderr','retirement','binding'}|extra
            and row['binding']==binding,'closed owned command and binding')
        if step=='inspect-test-key':argv,seconds,cap=key,10,65536
        elif step.startswith('verify-') and step!='verify-recovered':
            name=prior if step=='verify-prior-signature' else archive
            argv,seconds,cap=['/usr/bin/gpgv','--status-fd=1','--keyring',keyring,name+'.sig',name],30,65536
        elif step in ('signed-candidate-install','prior-required-install'):
            argv,seconds,cap=pacman+['--noconfirm','--noscriptlet','-U',prior if step=='prior-required-install' else archive],180,1048576
        elif step=='remove-reference-candidate':argv,seconds,cap=pacman+['--noconfirm','--noscriptlet','-R',NAME],180,1048576
        else:argv,seconds,cap=pacman+['-Q'],30,1048576
        need(row['argv']==argv and type(row['seconds']) is int and 1<=row['seconds']<=seconds
            and row['output_cap']==cap,'fixed command with closed bounds')
        natural(row['retirement'],seconds)
        for channel in ('stdout','stderr'):
            p=row[channel];need(type(p) is dict and set(p)=={'bytes','sha256'} and type(p['bytes']) is int
                and 0<=p['bytes']<=cap and type(p['sha256']) is str and re.fullmatch('[0-9a-f]{64}',p['sha256']),'bounded channel pin')
        if 'status_ascii' in row:need(pin(row['status_ascii'].encode('ascii'))==row['stdout'],'retained machine status joins original output')
        if step=='inspect-test-key':authority=key_listing(row['status_ascii'],signer,row['retirement'])
        if step in ('verify-signature','verify-prior-signature'):signature(row['status_ascii'],signer)
        if step in ('signed-candidate-install','prior-required-install'):
            need(authority is not None and row['retirement']['wall_finished']<authority[1],'unexpired signer throughout install')
        if step=='signed-candidate-install':installs.append(dict(started_epoch=row['retirement']['wall_started'],finished_epoch=row['retirement']['wall_finished']))
    return installs


def validate_baseline_inventory(baseline,inventory):
    """Join package-directory identities; retain DB-format files in snapshots."""
    need(type(inventory) is bytes and 0<len(inventory)<=1048576
        and len(inventory.splitlines())==349,'bounded retained349 inventory')
    roots={n for n,row in baseline['db'].items() if '/' not in n and row['kind']=='dir'}
    expected={line.decode('ascii').replace(' ','-',1) for line in inventory.splitlines()}
    need(len(roots)==len(expected)==349 and roots==expected,'baseline package directories match retained349 inventory')
    return roots


def validate_recovery_sidecar(raw,guest,binding,map_hash,contract,provenance_validator,receipt,runner,baseline_inventory):
    """Called only after retained outer ownership/transport/image/consumer validation."""
    refpin=guest.get('recovery');need(type(refpin) is dict and set(refpin)=={'schema','protocol','path','pin'}
        and type(refpin['schema']) is int and refpin['schema']==1 and refpin['protocol']==PROTOCOL
        and refpin['path']=='recovery-evidence.json' and refpin['pin']==pin(raw),'public sidecar pin')
    value=parse(raw,8*1024**2)
    keys={'schema','protocol','binding','baseline','interrupted','evidence','interrupt_receipt','observation','raw_ascii',
        'observer_provenance','compiler_owned_retirement','reference','actual_db_raw','result','normal_episode',
        'command_records','journal_ascii','scope','upstream_source_binary_correspondence','physical_M2','release','private_cleanup'}
    actual=dict(binding,map_sha256=map_hash)
    need(type(value) is dict and set(value)==keys and type(value['schema']) is int and value['schema']==1
        and value['protocol']==PROTOCOL and value['binding']==actual
        and contract['operation']==OP and contract['recovery']['operation']==OP,'new operation and exact actual Source/map/run/attempt/token')
    need(value['scope']==dict(protocol='security-recovery-native-scope-v1',binding=actual,caller_verified_source=True,disposable_native_image=True),
        'owner-staged scope joined to actual outer receipt')
    need(runner['commit']==binding['source'] and runner['run_id']==binding['run']
        and runner['kernel']['machine'] in ('aarch64','arm64') and runner['docker_server_arch'] in ('aarch64','arm64')
        and receipt['binding']==binding and receipt['source_map_sha256']==map_hash
        and re.fullmatch('sha256:[0-9a-f]{64}',receipt['consumer']['image']), 'actual inherited native engine and image binding')
    need(value['upstream_source_binary_correspondence']=='OPEN' and value['physical_M2']=='NOT_RUN'
        and value['release']=='NOT_ADMITTED','bounded evidence only scope')
    names=tuple(sorted(set(contract['payload_files'])|set(contract['upgrade']['prior_payload_files'])))
    policy=RecoveryPolicy(binding['source'],binding['ref'],binding['run'],names)
    baseline,interrupted,evidence=value['baseline'],value['interrupted'],value['evidence']
    validate_baseline_inventory(baseline,baseline_inventory)
    plan=classify_recovery(baseline,interrupted,policy,evidence)
    reference=value['reference'];need(type(reference) is dict and set(reference)=={'snapshot','candidate_db','candidate_payload','install_window','metadata'},'closed warm reference')
    metadata=MetadataReference.from_record(reference['metadata']);authority=metadata.authority
    signer=guest['test_authority']['fingerprint']
    need(authority['binding']==actual and authority['signer']==signer and authority['archive']==guest['pair']['one']
        and authority['signature']==pin(decode(guest['test_authority']['signature_base64'],1048576)), 'same previously verified signed candidate authority')
    options=dict(Architecture='aarch64',RootDir='/',DBPath='/var/lib/pacman',SigLevel='Required',LocalFileSigLevel='Required',GPGDir=PREFIX+'trust',HookDir=PREFIX+'empty-hooks',CacheDir=PREFIX+'cache',LogFile=PREFIX+'pacman.log')
    config=('[options]\n'+''.join(k+' = '+v+'\n' for k,v in options.items())).encode('ascii')
    armor=guest['test_authority']['public_key'].splitlines()
    need(armor[0]=='-----BEGIN PGP PUBLIC KEY BLOCK-----' and armor[-1]=='-----END PGP PUBLIC KEY BLOCK-----','same retained TEST public armor')
    split=armor.index('');need(all(x.startswith(('Version: ','Comment: ')) for x in armor[1:split]) and armor[-2].startswith('='),'closed public armor')
    public=base64.b64decode(''.join(armor[split+1:-2]),validate=True)
    crc=0xB704CE
    for byte in public:
        crc^=byte<<16
        for _ in range(8):
            crc<<=1
            if crc&0x1000000:crc^=0x1864CFB
    need(base64.b64decode(armor[-2][1:],validate=True)==(crc&0xFFFFFF).to_bytes(3,'big') and authority['keyring']==pin(public)
        and authority['config']==pin(config),'fixed Required/Required private config and same public TEST keyring bytes')
    expected_payload={n:dict(kind='file',uid=0,gid=0,**contract['payload_files'][n]) if n in contract['payload_files'] else None for n in names}
    need(reference['candidate_db']==metadata.expected_db and reference['candidate_payload']==expected_payload
        and reference['install_window']==metadata.install_window,'independent full DB and declared payload reference')
    verify_recovered(baseline,reference['snapshot'],policy,metadata.expected_db,expected_payload)
    installs=validate_commands(value['command_records'],actual,signer)
    need(installs[0]==reference['install_window'],'warm successful install owns reference timestamp')
    result=value['result'];need(type(result) is dict and result['status']=='VERIFIED_RECOVERY_SEQUENCE_WITH_CALLER_OWNED_ADAPTER'
        and result['completed']==['verify-signature','orphan-cleanup','signed-candidate-install','verify-recovered']
        and result['binding']==policy.binding() and result['retry'] is False and result['native_acceptance'] is None,'complete fixed recovery sequence')
    signature(result['signature_status_ascii'],signer)
    need(result['signature_status_ascii']==value['command_records'][-3]['status_ascii'],'signature result joins recorded verifier')
    updated=copy.deepcopy(metadata.expected_db);files=value['actual_db_raw'];normal=result['normalization'];file_evidence={}
    need(type(files) is dict and set(files)==set(metadata.raw_files),'complete raw recovered local DB namespace')
    for name,original in metadata.raw_files.items():
        body=decode(files[name],1048576)
        need(pin(body)=={k:result['recovered_snapshot']['db'][name][k] for k in ('bytes','sha256')},'recovered raw DB and snapshot join')
        if name==NEW+'/desc':
            before,first=normalize_desc(original,installs[0]);after,last=normalize_desc(body,installs[1])
            need(before==after,'only INSTALLDATE raw decimal may vary');updated[name].update(pin(body))
            file_evidence[name]=dict(reference=pin(original),actual=pin(body),normalized=pin(after),reference_installdate=first,actual_installdate=last)
        else:need(body==original,'all non-desc generated metadata byte-identical')
    need(normal==dict(field='INSTALLDATE',reference_window=installs[0],recovered_window=installs[1],file_evidence=file_evidence,authority=authority),
        'exact independently recomputed timestamp normalization evidence')
    verified=verify_recovered(baseline,result['recovered_snapshot'],policy,updated,expected_payload)
    need(result['snapshot_sha256']==verified.snapshot_sha256,'actual recovered snapshot pin')
    need(type(baseline_inventory) is bytes and pin(baseline_inventory)==guest['packages'] and len(baseline_inventory.splitlines())==349,'retained original baseline inventory')
    wanted=b''.join(sorted(baseline_inventory.splitlines(keepends=True)+[NAME.encode()+b' 0.1.0-2\n']))
    need(result['inventory_ascii'].encode('ascii')==wanted and value['command_records'][-1]['stdout']==pin(wanted),'exact recovered350 inventory joins actual query')
    normal_episode=value['normal_episode'];count=normal_episode['records_count']
    need(type(count) is int and 0<count<len(guest['commands']) and guest['commands'][count-1]['step']=='repeated-owner'
        and normal_episode==dict(observation=pin(encoded(guest['upgrade']['observation'])),upgraded=guest['upgrade']['inventories']['upgraded'],
            repeated=guest['upgrade']['inventories']['repeated'],records=pin(encoded(guest['commands'][:count])),records_count=count),
        'entire retained normal episode completed before recovery')
    observation=value['observation'];rows=[parse(line.encode('ascii'),16384) for line in value['raw_ascii'].splitlines()]
    need(len(rows)==1 and value['raw_ascii'].endswith('\n') and rows==observation['records'],'genuine single blocked FIRST record; no invented END')
    point=rows[0];cp=evidence['checkpoint']
    need(point['type']==cp['type'] and point['pid']==cp['pid'] and point['ppid']==cp['ppid']
        and all(type(point[k]) is int and point[k]==v for k,v in dict(event=1,percent=0,howmany=1,current=1,
            old_only_errno=2,new_only_errno=2,old_desc_errno=2,new_desc_errno=2,symbol_object_verified=1).items())
        and point['lock']==dict(dev=cp['lock']['dev'],ino=cp['lock']['ino'],mode=0o100000,uid=0,gid=0,nlink=1,bytes=0),'first0 and absent old/new payload/desc with actual lock')
    for label in ('pacman','libalpm'):
        need(point[label+'_inode']==observation['runtime'][label]['inode'],'actual runtime inode join')
    policy_observer=contract['recovery']['observation']
    need(observation['runtime']['libalpm']['sha256']==policy_observer['libalpm_sha256'],'retained ALPM binary')
    provenance=value['observer_provenance'];provenance_validator(provenance,observation,policy_observer,baseline_inventory,[provenance['compile_record']])
    natural(value['compiler_owned_retirement'],180)
    need(provenance['compiler_retirement']=={k:value['compiler_owned_retirement'][k] for k in provenance['compiler_retirement']},'truthful compiler receipt projection')
    interrupted_receipt=value['interrupt_receipt'];full=interrupted_receipt['retirement'];channel=interrupted_receipt['channel']
    need(evidence['retirement']=={k:full[k] for k in evidence['retirement']} and full['exit']==-9 and full['passed'] is True
        and full['natural_exit'] is False and full['error'] is None and full['timeout'] is full['forced_retirement'] is False,
        'intentional original pidfd SIGKILL and certain retirement')
    need(channel['protocol']=='RECOVERY_BLOCK_V1' and re.fullmatch('[0-9a-f]{32}',channel['nonce'])
        and channel['sender']==dict(pid=cp['pid'],uid=0,gid=0) and channel['record']==pin(value['raw_ascii'].encode('ascii'))
        and interrupted_receipt['verified']==dict(snapshot_sha256=plan.interrupted_sha256,checkpoint=cp),'credentialed nonce and frozen blocked checkpoint')
    j=journal_data(value['journal_ascii'],actual);p=j['phases']
    need(p['BASELINE_RECORDED']==p['BASELINE_RESTORED']==p['RECOVERY_BASELINE_RESTORED']==dict(snapshot_sha256=snapshot_sha256(baseline))
        and p['REFERENCE_READY']==dict(reference=pin(encoded(reference['metadata'])),snapshot_sha256=snapshot_sha256(reference['snapshot']),install_window=installs[0])
        and p['NORMAL_EPISODE_PASSED']==normal_episode,'journal binds reference and both baseline restores around normal episode')
    need(p['CHECKPOINT_VERIFIED']==dict(snapshot_sha256=plan.interrupted_sha256,checkpoint=cp,observation_sha256=pin(encoded(observation))['sha256'])
        and p['INTERRUPTED_RETIRED']==dict(retirement=full,evidence_sha256=pin(encoded(evidence))['sha256'],receipt=pin(encoded(interrupted_receipt)))
        and p['INTERRUPT_INTENT']['nonce_sha256']==pin(channel['nonce'].encode())['sha256'],'durable checkpoint and intentional retirement proof bindings')
    need(p['CLEANUP_INTENT']==dict(snapshot_sha256=plan.interrupted_sha256)
        and p['CLEANUP_COMPLETED']==dict(snapshot_sha256=plan.after_unlock_sha256)
        and p['RECOVERY_INSTALL_INTENT']==dict(archive_sha256=authority['archive']['sha256'])
        and p['RECOVERY_INSTALLED']==dict(window=installs[1])
        and p['RECOVERY_VERIFIED']==p['FINALIZED']==dict(snapshot_sha256=verified.snapshot_sha256),'journal exact cleanup/install/verify/finalize order')
    for phase,intent,data in j['commands']:
        need(all(data.get(k)==v for k,v in intent.items()) if intent['step']!='recovery-compile-observer' else True,'journal command intent joins actual completion')
    adapter_phases=[phase for phase,intent,data in j['commands'] if intent['step']!='recovery-compile-observer']
    need(adapter_phases==['BASELINE_RECORDED']*3+['REFERENCE_READY','NORMAL_EPISODE_PASSED']+['RECOVERY_BASELINE_RESTORED']*3+['INTERRUPTED_RETIRED']*2+['RECOVERY_INSTALL_INTENT','RECOVERY_INSTALLED'],'native command phases preserve exact warm/normal/prior/recovery order')
    need(p['INTERRUPT_INTENT']['argv']==value['command_records'][2]['argv'],'interruption uses exact same signed candidate command')
    need(result['cleanup']==dict(status='EXACT_EMPTY_DB_DIRECTORY_AND_STALE_LOCK_REMOVED',before_sha256=plan.interrupted_sha256,after_directory=dict(db=baseline['db'],payload=baseline['payload'],lock=interrupted['lock']),after_directory_sha256=plan.after_directory_sha256,after_unlock=baseline,after_unlock_sha256=plan.after_unlock_sha256,mutations=[dict(operation='rmdir',path='var/lib/pacman/local/'+NEW),dict(operation='unlink',path='var/lib/pacman/db.lck')],retry=False),'exact two filesystem mutations restore frozen baseline')
    adapter_completions=[data for phase,intent,data in j['commands'] if intent['step']!='recovery-compile-observer']
    need(adapter_completions==value['command_records'],'every fixed native command joins durable journal')
    compiles=[(phase,intent,data) for phase,intent,data in j['commands'] if intent['step']=='recovery-compile-observer']
    need(len(compiles)==1 and compiles[0][0]=='PRIOR_INSTALLED' and compiles[0][1]['argv']==provenance['manifest']['recipe']['argv']
        and compiles[0][1]['env']==provenance['manifest']['recipe']['env'] and compiles[0][1]['cwd']==provenance['manifest']['recipe']['cwd']
        and compiles[0][2]['retirement']==value['compiler_owned_retirement'],'one actual owned compile in durable order')
    cleanup=value['private_cleanup'];need(set(cleanup)=={'path','before','removed','absence_errno','no_live_sockets'}
        and cleanup['path']==PREFIX[:-1] and cleanup['removed'] is cleanup['no_live_sockets'] is True and cleanup['absence_errno']==2
        and cleanup['before']['mode']==0o700 and cleanup['before']['uid']==cleanup['before']['gid']==0,
        'private public-only trust/config/compiler/journal prefix retired before export')
    return dict(status='VALIDATED_INTERRUPTED_RECOVERY_EVIDENCE_ONLY',binding=actual,image=receipt['consumer']['image'],
        engine=runner['docker_endpoint'],snapshot_sha256=verified.snapshot_sha256,journal=j['pin'],
        normalization='INSTALLDATE_ONLY',native='EVIDENCE_ONLY_NOT_ADMISSION',physical_M2='NOT_RUN',release='NOT_ADMITTED')

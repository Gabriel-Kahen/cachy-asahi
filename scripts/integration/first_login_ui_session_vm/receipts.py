# SPDX-License-Identifier: MIT
"""Fixture-local durable sanitized receipts and the fail-closed login gate."""
import hashlib, json, os, re, stat
from pathlib import Path
DIRECTORY=Path('/var/lib/cachy-asahi-ui-session-reference')
STAGES={'starting','baseline-check','public-trust','archive-input-check','trusted-install','installed-check','installed','waiting-user','session-check','trusted-remove','restored-check','restored','failed'}
COMMANDS={'baseline','public-import','TEST-public-ownertrust','no-secret-keys','trusted-install','installed-inventory','installed-dependencies','installed-ownership','package-files','trusted-remove','restored-inventory','restored-dependencies','sync-post-install','sync-post-remove','sync-terminal-pass','sync-terminal-hold'}
ERRORS={'command-failed','command-timeout','command-not-found','signature-refusal','dependency-refusal','permission-refusal','output-bound-refusal','state-refusal','unexpected-error','syncfs-refusal','ownership-refusal'}

def inventory_sha256(versions):
    return hashlib.sha256(json.dumps(versions,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def _directory(path,owner,mode=0o700):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    s=os.fstat(fd)
    if not(stat.S_ISDIR(s.st_mode) and (s.st_uid,s.st_gid)==owner and stat.S_IMODE(s.st_mode)==mode):
        os.close(fd);raise ValueError('foreign-receipt-directory')
    return fd

def _identity(s):
    return s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns

def _pairs(rows):
    result={}
    for key,value in rows:
        if key in result:raise ValueError('duplicate-receipt-field')
        result[key]=value
    return result

def read(path,name,owner=(0,0),public=False):
    assert name in {'installed.json','failure.json','stage.json'}
    try:directory=_directory(path,owner,0o755 if public else 0o700)
    except FileNotFoundError:return None
    try:
        try:fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        except FileNotFoundError:return None
        try:
            before=os.fstat(fd)
            if not(stat.S_ISREG(before.st_mode) and (before.st_uid,before.st_gid)==owner and stat.S_IMODE(before.st_mode)==(0o644 if public else 0o600) and before.st_nlink==1 and 0<before.st_size<=4096):raise ValueError('foreign-receipt-file')
            data=os.read(fd,4097);after=os.fstat(fd)
            if len(data)!=before.st_size or _identity(before)!=_identity(after):raise ValueError('changed-receipt-file')
            value=json.loads(data,object_pairs_hook=_pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonstandard-receipt-number')))
            if not isinstance(value,dict):raise ValueError('invalid-receipt-object')
            return value
        finally:os.close(fd)
    finally:os.close(directory)

def installed_gate(path,nonce,inputs_sha256,expected_inventory,project_files,owner=(0,0),signals=Path('/run/ui-session')):
    failure=read(path,'failure.json',owner)
    if failure is not None:
        validate('failure.json',failure,nonce)
        if failure.get('nonce')!=nonce:raise ValueError('stale-root-failure')
        if failure.get('stage')not in STAGES or failure.get('error_label')not in ERRORS:raise ValueError('invalid-root-failure')
        signal=read(signals,'failure.json',owner,public=True)
        if signal is None:return None
        validate('failure.json',signal,nonce)
        if signal!=failure:raise ValueError('stale-root-failure-signal')
        raise RuntimeError('root-fixture-'+failure['stage']+'-'+failure['error_label'])
    stage=read(path,'stage.json',owner)
    if stage is not None:validate('stage.json',stage,nonce)
    value=read(path,'installed.json',owner)
    if value is None:return None
    validate('installed.json',value,nonce)
    expected={'schema_version':1,'nonce':nonce,'stage':'installed','inputs_sha256':inputs_sha256,'inventory_sha256':inventory_sha256(expected_inventory),'baseline_count':164,'installed_count':292,'archive_count':128,'project_file_count':project_files,'trusted_ALPM_completed':True,'exact_inventory':True,'dependencies':True,'ownership':True,'project_hashes':True,'original_policy':True,'unrelated_user_file':True,'filesystem_synced':True}
    if value!=expected or type(value.get('schema_version'))is not int or any(type(value.get(k)) is not bool for k in ['trusted_ALPM_completed','exact_inventory','dependencies','ownership','project_hashes','original_policy','unrelated_user_file','filesystem_synced']):raise ValueError('stale-or-incomplete-installed-receipt')
    # Visibility of the private rename alone is insufficient: this second,
    # root-owned signal is created only AFTER private file+directory fsync.
    signal=read(signals,'installed.json',owner,public=True)
    if signal is None:return None
    validate('installed.json',signal,nonce)
    if signal!=value:raise ValueError('foreign-or-stale-installed-signal')
    return value

def validate(name,value,nonce):
    base={'schema_version','nonce','stage'}
    if value.get('nonce')!=nonce or value.get('schema_version')!=1 or type(value.get('schema_version'))is not int or value.get('stage')not in STAGES:raise ValueError('invalid-receipt-header')
    if name=='stage.json':keys=base
    elif name=='failure.json':
        keys=base|{'error_label','status'}
        if value.get('error_label')not in ERRORS or value.get('status')!='HOLD':raise ValueError('invalid-failure-label')
    elif name.startswith('command-'):
        keys=base|{'sequence','command_label','status','exit','error_label'}
        if value.get('command_label')not in COMMANDS or value.get('status')not in {'started','passed','failed'} or value.get('error_label')not in ERRORS|{None}:raise ValueError('invalid-command-label')
        if type(value.get('sequence'))is not int or not 1<=value['sequence']<=256:raise ValueError('invalid-command-sequence')
        if value.get('exit')is not None and (type(value['exit'])is not int or not -128<=value['exit']<=255):raise ValueError('invalid-command-exit')
    elif name=='installed.json':
        flags={'trusted_ALPM_completed','exact_inventory','dependencies','ownership','project_hashes','original_policy','unrelated_user_file','filesystem_synced'}
        keys=base|flags|{'inputs_sha256','inventory_sha256','baseline_count','installed_count','archive_count','project_file_count'}
        if value['stage']!='installed' or any(value.get(k)is not True for k in flags):raise ValueError('incomplete-installed-checks')
        for key,number in [('baseline_count',164),('installed_count',292),('archive_count',128)]:
            if type(value.get(key))is not int or value[key]!=number:raise ValueError('invalid-installed-count')
        if type(value.get('project_file_count'))is not int or not 0<value['project_file_count']<=128:raise ValueError('invalid-project-count')
        if any(not isinstance(value.get(k),str)or re.fullmatch('[0-9a-f]{64}',value[k])is None for k in ['inputs_sha256','inventory_sha256']):raise ValueError('invalid-installed-pin')
    elif name.startswith('ownership-'):
        validate_ownership(name,value,base);return
    elif name=='restored.json':
        flags={'inventory_restored','dependencies','package_owned_paths_absent','original_policy','user_files_preserved'};keys=base|flags|{'baseline_count'}
        if value['stage']!='restored' or value.get('baseline_count')!=164 or any(value.get(k)is not True for k in flags):raise ValueError('invalid-restored-checks')
    else:raise ValueError('unknown-receipt-name')
    if set(value)!=keys:raise ValueError('non-whitelisted-receipt-fields')

def validate_ownership(name,value,base):
    labels={'type-mismatch','uid-mismatch','gid-mismatch','mode-mismatch','link-mismatch','mtime-mismatch','size-mismatch','sha256-mismatch','md5-mismatch','missing-path','permission-refusal','missing-mtree'}
    def digest(v):return isinstance(v,str)and re.fullmatch('[0-9a-f]{64}',v)is not None
    if name=='ownership-summary.json':
        fields={'exit','warning_count','unknown_count','summary_count','altered_file_count','truncated_warning_count','truncated_unknown_count','HOLD'}
        if set(value)!=base|fields or type(value['HOLD'])is not bool:raise ValueError('ownership-summary-schema')
        if any(type(value[k])is not int or not -128<=value[k]<=2**31 for k in fields-{'HOLD'}):raise ValueError('ownership-summary-count')
    elif name.startswith('ownership-unknown-'):
        if set(value)!=base|{'stream','bytes','sha256'}or value['stream']not in {'stdout','stderr'}or type(value['bytes'])is not int or not 0<=value['bytes']<=1024**2 or not digest(value['sha256']):raise ValueError('ownership-unknown-schema')
    elif name.startswith('ownership-warning-'):
        if set(value)!=base|{'package','path','category','expected_archive','expected_mtree','actual'}or value['category']not in labels:raise ValueError('ownership-warning-schema')
        if not re.fullmatch('[a-zA-Z0-9@+_.-]+',value['package'])or not value['path'].startswith(('/usr/','/etc/','/var/','/opt/'))or len(value['path'])>1024 or '..'in Path(value['path']).parts or any(ord(c)<32 for c in value['path']):raise ValueError('ownership-warning-path')
        path=value['path']
        if path in {'/etc/shadow','/etc/gshadow'}or path.startswith(('/etc/ssh/','/usr/share/pacman/keyrings/'))or any(v in Path(path).parts for v in ['gnupg','private-keys-v1.d'])or path.endswith(('.key','.pem','.gpg','.asc')):raise ValueError('ownership-sensitive-path')
        keys={'type','uid','gid','mode','size','mtime_ns','sha256','link_target_sha256','state','hashed_bytes'}
        for name in ['expected_archive','expected_mtree','actual']:
            row=value[name]
            if row is None and name=='expected_mtree':continue
            if not isinstance(row,dict)or not set(row)<=keys:raise ValueError('ownership-observation-schema')
            for key,field in row.items():
                if key in {'sha256','link_target_sha256'}and not digest(field):raise ValueError('ownership-observation-digest')
                if key in {'uid','gid','mode','size','mtime_ns','hashed_bytes'}and(type(field)is not int or field<0):raise ValueError('ownership-observation-number')
                if key=='type'and field not in {'file','dir','link','other'}:raise ValueError('ownership-observation-type')
                if key=='state'and field not in {'read-refusal','observed','missing-path','hash-time-bound','hash-byte-bound','changed-file'}:raise ValueError('ownership-observation-state')
    else:raise ValueError('ownership-receipt-name')

class Writer:
    def __init__(self,path,nonce,owner=(0,0)):
        assert re.fullmatch('[0-9a-f]{32}',nonce)
        self.path=Path(path);self.nonce=nonce;self.owner=owner;self.sequence=0;self.stage='starting'
        self.path.mkdir(mode=0o700,exist_ok=False)
        # Persist the directory creation itself before any stage can be signaled.
        fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
        self.phase('starting')
    def write(self,name,value):
        assert re.fullmatch(r'(stage|installed|failure|restored|command-[0-9]{3}|ownership-summary|ownership-(warning|unknown)-[0-9]{3})\.json',name)
        validate(name,value,self.nonce)
        assert len(json.dumps(value))<=4096
        directory=_directory(self.path,self.owner);temporary='.'+name+'.pending'
        try:
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
            try:
                raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode();view=memoryview(raw)
                while view:
                    count=os.write(fd,view)
                    if count<=0:raise OSError('receipt short write')
                    view=view[count:]
                os.fsync(fd)
            finally:os.close(fd)
            os.replace(temporary,name,src_dir_fd=directory,dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:os.unlink(temporary,dir_fd=directory)
            except FileNotFoundError:pass
            os.close(directory)
    def phase(self,stage):
        assert stage in STAGES;self.stage=stage
        self.write('stage.json',{'schema_version':1,'nonce':self.nonce,'stage':stage})
    def command(self,label,status,exit=None,error=None):
        assert label in COMMANDS and status in {'started','passed','failed'} and (error is None or error in ERRORS)
        if status=='started':self.sequence+=1
        assert 1<=self.sequence<=256 and (exit is None or type(exit)is int and -128<=exit<=255)
        self.write('command-'+str(self.sequence).zfill(3)+'.json',{'schema_version':1,'nonce':self.nonce,'stage':self.stage,'sequence':self.sequence,'command_label':label,'status':status,'exit':exit,'error_label':error})
    def failure(self,error):
        assert error in ERRORS
        value={'schema_version':1,'nonce':self.nonce,'stage':self.stage,'error_label':error,'status':'HOLD'}
        self.write('failure.json',value);return value

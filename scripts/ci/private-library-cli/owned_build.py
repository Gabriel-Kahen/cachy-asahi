# SPDX-License-Identifier: MIT
"""Fixed private-library container actor. No CLI actor runs during import.

All process custody and actual stdout limits belong to selected parent_bridge
OwnedRunner. This body never launches build.main, docker run/build, or zstd.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

BUILDS=('jbigkit-1','jbigkit-2','libtiff-1','libtiff-2')
PROBES=tuple('probe-'+role+'-'+str(n) for role in BUILDS for n in (1,2))
CONTAINERS=(*BUILDS,*PROBES,'layer-provision','layer-lock','layer-dependencies')
ROLES=(*CONTAINERS,'layer-image')
CID=re.compile(r'[0-9a-f]{64}\Z')
IMAGE=re.compile(r'sha256:[0-9a-f]{64}\Z')
PIN=re.compile(r'[0-9a-f]{64}\Z')
NONCE=re.compile(r'[0-9a-f]{32}\Z')
LABEL='org.cachy.library-cli.'
OLD_ENTRY_SHA256='89723f0a0b2ef80391160f451e877f15fb1e0c4d9a4fec6dbbb8e0d66d8d0f24'
OLD_BUILD_SHA256='e520b37e5dfc285914203cfab99daecc80543505fef7ded6704b3fb06f001d45'
PACKAGE_CHECKS_SHA256='e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8'
COMMAND_IDS=frozenset(('container-create','container-inspect','container-start-attach','container-wait',
    'container-remove','container-absence','image-commit','image-inspect','image-remove','image-absence'))
LOG_LIMIT=4*1024**2


def need(ok,reason):
    if not ok:raise ValueError(reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def first_failure(error):
    message=str(error);detail=message.encode('utf-8',errors='backslashreplace')
    return {'exception_type':type(error).__name__,'message':message if len(detail)<=65536 else None,
            'detail_sha256':sha(detail),'detail_bytes':len(detail)}


def read_regular(path,limit=8*1024**2):
    path=Path(path)
    need(path.is_absolute() and '..' not in path.parts and all(not p.is_symlink() for p in (path,*path.parents)), 'OWNED_FILE_PATH')
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
    first=None
    try:
        row=os.fstat(fd);need(stat.S_ISREG(row.st_mode) and row.st_nlink==1 and 0<=row.st_size<=limit,'OWNED_FILE_TYPE_CAP')
        chunks=[];size=0
        while True:
            block=os.read(fd,min(65536,limit+1-size))
            if not block:break
            size+=len(block);need(size<=limit,'OWNED_FILE_CAP');chunks.append(block)
        current=os.fstat(fd);named=path.lstat()
        identity=lambda r:(r.st_dev,r.st_ino,r.st_mode,r.st_nlink,r.st_size,r.st_mtime_ns,r.st_ctime_ns)
        need(size==row.st_size and identity(row)==identity(current)==identity(named),'OWNED_FILE_CHANGED')
        return b''.join(chunks)
    except BaseException as error:
        first=error;raise
    finally:
        try:os.close(fd)
        except BaseException as closed:
            if first is None:raise
            first.add_note('owned read close uncertainty: '+type(closed).__name__)


def save(path,value):
    """Private fixed-size receipt, written/fsynced before returning to the actor."""
    raw=encoded(value);need(len(raw)<=1024**2,'OWNED_RECEIPT_CAP')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    first=None
    try:
        offset=0
        while offset<len(raw):
            written=os.write(fd,raw[offset:]);need(written>0,'OWNED_RECEIPT_WRITE');offset+=written
        os.fsync(fd)
    except BaseException as error:
        first=error;raise
    finally:
        try:os.close(fd)
        except BaseException as closed:
            if first is None:raise
            first.add_note('owned receipt close uncertainty: '+type(closed).__name__)
    return sha(raw)


def path_field(value):
    need(type(value)is str and Path(value).is_absolute() and '..' not in Path(value).parts and
         not any(c in value for c in (',','\n','\r','\0')),'CONTAINER_PATH')
    return value


def command(record,command_id,fields):
    """Closed generated Docker grammar; no externally selected argv/entrypoint."""
    need(command_id in COMMAND_IDS and type(fields)is dict,'OWNED_COMMAND_ID')
    need(record['runtime']['docker']['path']=='/usr/bin/docker','PINNED_DOCKER_PATH')
    prefix=['/usr/bin/docker','--host','unix:///run/docker.sock']
    role=fields.get('role');need(role in ROLES,'OWNED_ROLE')
    if command_id=='container-create':
        common={'role','name','image','nonce','kind'}
        kind=fields.get('kind')
        extras={'build':{'inputs','artifacts','entry','lock','epoch','uid','gid'},
            'probe':{'archive','member'},'provision':{'packages'},'lock':set(),'dependencies':set()}
        need(kind in extras and set(fields)==common|extras[kind],'OWNED_CREATE_FIELDS')
        need(role in CONTAINERS and IMAGE.fullmatch(fields['image']) and NONCE.fullmatch(fields['nonce']) and fields['nonce']==record['nonce'] and
             fields['name']=='cachy-library-cli-'+fields['nonce']+'-'+role,'OWNED_CREATE_IDENTITY')
        need((kind=='build' and role in BUILDS) or (kind=='probe' and role in PROBES) or
             (kind=='provision' and role=='layer-provision') or (kind=='lock' and role=='layer-lock') or
             (kind=='dependencies' and role=='layer-dependencies'),'OWNED_KIND_ROLE')
        args=prefix+['container','create','--name',fields['name'],'--pull=never','--platform','linux/arm64',
            '--network','none','--cap-drop=ALL','--security-opt=no-new-privileges','--log-driver=none',
            '--pids-limit','512' if kind in ('build','provision') else '64','--memory','4g' if kind in ('build','provision') else '512m',
            '--cpus','4' if kind in ('build','provision') else '1',
            '--label',LABEL+'nonce='+fields['nonce'],'--label',LABEL+'role='+role]
        if kind!='provision':args+=['--read-only']
        if kind=='build':
            need(all(type(fields[k])is int and fields[k]>=0 for k in ('epoch','uid','gid')) and fields['uid']>0,'BUILD_UID_EPOCH')
            args+=['--user',str(fields['uid'])+':'+str(fields['gid']),'--tmpfs','/tmp:rw,nosuid,nodev,exec,size=4g',
                '--env','CACHY_ASAHI_CONTAINER=1','--env','SOURCE_DATE_EPOCH='+str(fields['epoch'])]
            for source,target,ro in (('inputs','/inputs',True),('artifacts','/out',False),('entry','/builder-entry.sh',True),('lock','/expected-packages.lock',True)):
                args+=['--mount','type=bind,src='+path_field(fields[source])+',dst='+target+(',readonly' if ro else '')]
            return args+['--entrypoint','/bin/bash',fields['image'],'/builder-entry.sh']
        if kind=='probe':
            member=fields['member'];need(re.fullmatch(r'usr/lib/[A-Za-z0-9+_.-]+',member),'PROBE_MEMBER')
            script='set -euo pipefail; bsdtar -xOf /artifact '+member+' > /tmp/library.so; sha256sum /tmp/library.so; readelf --wide --dynamic /tmp/library.so'
            return args+['--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=32m','--mount','type=bind,src='+path_field(fields['archive'])+',dst=/artifact,readonly',
                '--entrypoint','/bin/bash',fields['image'],'-c',script]
        if kind=='provision':
            for cap in ('CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID'):args+=['--cap-add='+cap]
            # Six exact verified inputs supplied by the fixed Operations adapter.
            inputs=' '.join('/private/input-'+str(n)+'.pkg.tar' for n in range(6))
            script='set -euo pipefail; pacman --noconfirm -Rdd jbigkit; pacman --noconfirm -U '+inputs
            return args+['--mount','type=bind,src='+path_field(fields['packages'])+',dst=/private,readonly',
                '--entrypoint','/bin/bash',fields['image'],'-c',script]
        return args+['--entrypoint','/usr/bin/pacman',fields['image'],'-Q' if kind=='lock' else '-Dk']
    if command_id=='image-commit':
        need(set(fields)=={'role','identifier','tag','nonce','base'} and role=='layer-image' and CID.fullmatch(fields['identifier']) and
             IMAGE.fullmatch(fields['base']) and fields['base']==record['baseline']['image_id'] and NONCE.fullmatch(fields['nonce']) and fields['nonce']==record['nonce'] and
             fields['tag']=='cachy-library-cli-'+fields['nonce']+'-layer-image','OWNED_COMMIT_FIELDS')
        return prefix+['container','commit','--pause=true','--change','LABEL '+LABEL+'nonce='+fields['nonce'],
            '--change','LABEL '+LABEL+'role=layer-image','--change','LABEL '+LABEL+'base='+fields['base'],
            fields['identifier'],fields['tag']+':latest']
    need(set(fields)=={'role','identifier'},'OWNED_ID_FIELDS')
    identifier=fields['identifier']
    image=command_id.startswith('image-')
    need((IMAGE if image else CID).fullmatch(identifier) and (role=='layer-image' if image else role in CONTAINERS),'OWNED_FULL_ID_REQUIRED')
    if image:need(identifier!=record['baseline']['image_id'],'BORROWED_IMAGE_REMOVAL_REFUSED')
    if command_id.endswith('inspect'):return prefix+['image' if image else 'container','inspect','--format','{{json .}}',identifier]
    if command_id=='container-start-attach':return prefix+['container','start','--attach',identifier]
    if command_id=='container-wait':return prefix+['container','wait',identifier]
    if command_id.endswith('remove'):return prefix+(['image','rm',identifier] if image else ['container','rm','--force',identifier])
    if image:return prefix+['image','ls','--all','--no-trunc','--quiet','--filter','label='+LABEL+'nonce='+record['nonce'],'--filter','label='+LABEL+'role=layer-image']
    return prefix+['container','ls','--all','--no-trunc','--format','{{.ID}}','--filter','id='+identifier]


@dataclass(frozen=True)
class ContainerSpec:
    role:str
    image:str
    kind:str
    values:dict


@dataclass(frozen=True)
class BuildSpec:
    role:str
    recipe:Path
    output:Path
    image:str
    lock:Path
    inputs:dict
    epoch:int
    uid:int
    gid:int
    original_entry:Path


def selected_entry(raw):
    """New explicit derived entry, omitting all file-backed makepkg log capture."""
    need(sha(raw)==OLD_ENTRY_SHA256,'PINNED_ENTRY_PREIMAGE')
    old=b'makepkg --cleanbuild --clean --force --log --noconfirm'
    tail=b'logs=(*.log)\nif [[ ${#logs[@]} -gt 0 ]]; then cp -- "${logs[@]}" /out/; fi\n'
    need(raw.count(old)==1 and raw.count(tail)==1,'ENTRY_TRANSFORM_PREIMAGE')
    return raw.replace(old,b'makepkg --cleanbuild --clean --force --noconfirm').replace(tail,b'')


class OwnedBuild:
    """Fixed actor over selected runner + boundary ResourceLedger; no callbacks."""
    def __init__(self,record,boundary,ledger,runner,output):
        self.record,self.boundary,self.ledger,self.runner=record,boundary,ledger,runner
        self.output=Path(output);need(self.output.is_absolute() and self.output.is_dir() and not self.output.is_symlink(),'OWNED_OUTPUT')
        self.nonce=record['nonce'];need(NONCE.fullmatch(self.nonce),'OWNED_NONCE')
        self.baseline=record['baseline']['image_id'];need(IMAGE.fullmatch(self.baseline),'BORROWED_BASELINE_ID')
        self.containers={};self.image=None;self.receipts=0;self.first=None;self.cleanup_errors=[]

    def _call(self,identifier,fields,timeout=120,cleanup=False):
        self.boundary.check(cleanup=cleanup)
        result=self.runner.run(identifier,fields,timeout=timeout,cleanup=cleanup)
        need(type(result)is dict and type(result.get('log'))is bytes and len(result['log'])<=LOG_LIMIT,'RUNNER_RECEIPT_LOG')
        self.receipts+=1
        raw=result['log'];need(result.get('sha256')==sha(raw) and result.get('bytes')==len(raw),'RUNNER_LOG_PIN')
        private={k:result.get(k) for k in ('exit_code','log_path','sha256','bytes','natural_exit','reaped','birth',
            'pidfd_owned','uncertainty','first_failure')}
        private.update(command_id=identifier,fields=fields,log_sha256=sha(raw),log_bytes=len(raw))
        pin=save(self.output/('actor-command-'+str(self.receipts)+'.json'),private)
        result=dict(result,receipt_sha256=pin)
        birth=result.get('birth',{})
        accepted=(type(result.get('exit_code'))is int and result.get('exit_code')==0 and result.get('natural_exit')is True and result.get('reaped')is True and
            result.get('pidfd_owned')is True and result.get('uncertainty')==[] and result.get('first_failure')is None and
            type(birth)is dict and all(type(birth.get(k))is int and birth[k]>0 for k in ('pid','start_ticks','sid','ppid')) and
            birth['pid']==birth['sid'] and birth['ppid']==os.getpid())
        if not accepted:
            error=ValueError('OWNED_COMMAND_FAILED')
            if self.first is None:self.first=error
            self.boundary.fail(error,cleanup=cleanup,cancel=result.get('first_failure',{}).get('kind')=='KeyboardInterrupt' if type(result.get('first_failure'))is dict else False)
            error.receipt=result
            raise error
        self.boundary.check(cleanup=cleanup)
        return result

    def _inspect(self,row,cleanup=False):
        result=self._call('container-inspect',{'role':row['role'],'identifier':row['id']},cleanup=cleanup)
        need(len(result['log'])<=65536,'INSPECT_CAP');value=json.loads(result['log'])
        labels=value.get('Config',{}).get('Labels') or {}
        need(value.get('Id')==row['id'] and value.get('Name')=='/'+row['name'] and value.get('Image')==row['image'] and
             labels.get(LABEL+'nonce')==self.nonce and labels.get(LABEL+'role')==row['role'],'CONTAINER_POSITIVE_OWNERSHIP')
        row['last_inspect']=result['receipt_sha256'];return value,result

    def _ambiguity(self,role,reason,first):
        if self.first is None:self.first=first
        self.boundary.fail(first,cancel=isinstance(first,KeyboardInterrupt))
        try:self.ledger.ambiguous(role,reason)
        except BaseException as retained:
            self.cleanup_errors.append(type(retained).__name__)
            self.boundary.fail(retained,cleanup=True,cancel=isinstance(retained,KeyboardInterrupt))
            first.add_note('owned ambiguity journal uncertainty: '+type(retained).__name__)

    def create(self,spec):
        need(type(spec)is ContainerSpec and spec.role not in self.containers,'FIXED_CONTAINER_SPEC')
        name='cachy-library-cli-'+self.nonce+'-'+spec.role
        fields={'role':spec.role,'name':name,'image':spec.image,'nonce':self.nonce,'kind':spec.kind,**spec.values}
        command(self.record,'container-create',fields)  # Refuse malformed work before reservation.
        reservation=self.ledger.reserve(spec.role,spec.image)
        need(type(reservation)is dict and reservation.get('name')==name,'LEDGER_RESERVED_NAME')
        row={'role':spec.role,'image':spec.image,'name':name,'id':None,'creation_completed':False,'retired':False,'wait_exit':None}
        self.containers[spec.role]=row
        self.ledger.submit(spec.role)
        try:
            result=self._call('container-create',fields)
            identifier=result['log'].decode('ascii').strip();need(CID.fullmatch(identifier),'CREATE_FULL_CID')
            row.update(id=identifier,creation_completed=True)
            _,inspection=self._inspect(row)
            self.ledger.observe(spec.role,identifier=identifier,name=name,image=spec.image,nonce=self.nonce,
                creation_completed=True,receipt_sha256=inspection['receipt_sha256'])
            return row
        except BaseException as error:
            self._ambiguity(spec.role,'CREATE_UNRETURNED' if not row['creation_completed'] else 'INSPECT_UNCERTAIN',error)
            raise

    def start_wait(self,row,*,timeout=1200,build_log=None):
        def verify_log(receipt):
            need(Path(receipt['log_path'])==Path(build_log),'ACTUAL_BUILD_LOG_STORAGE_NOT_SELECTED')
            need(read_regular(Path(build_log),LOG_LIMIT)==receipt['log'],'ACTUAL_BUILD_LOG_CHANGED')
        try:result=self._call('container-start-attach',{'role':row['role'],'identifier':row['id']},timeout)
        except BaseException as error:
            receipt=getattr(error,'receipt',None)
            if build_log is not None and type(receipt)is dict:
                try:verify_log(receipt)
                except BaseException as retained:
                    error.add_note('actual build log retention uncertainty: '+type(retained).__name__)
                    self.cleanup_errors.append(type(retained).__name__);self.boundary.fail(retained,cleanup=True)
            raise
        if build_log is not None:verify_log(result)
        waited=self._call('container-wait',{'role':row['role'],'identifier':row['id']})
        text=waited['log'].decode('ascii').strip();need(re.fullmatch('[0-9]{1,3}',text),'CONTAINER_WAIT_FORMAT')
        row['wait_exit']=int(text);need(row['wait_exit']==0,'CONTAINER_NONZERO_EXIT')
        return result['log']

    def retire_container(self,row):
        if row['retired']:return
        need(row['id'] is not None and row['creation_completed'],'UNACKNOWLEDGED_CREATE_UNCERTAINTY')
        value,inspection=self._inspect(row,cleanup=True)
        if row['wait_exit']==0:
            state=value.get('State',{})
            need(state.get('Status')=='exited' and state.get('Running')is False and state.get('ExitCode')==0 and
                 state.get('Dead')is False and state.get('Error')=='','CONTAINER_NATURAL_EXIT_STATE')
        self.ledger.observe(row['role'],identifier=row['id'],name=row['name'],image=row['image'],nonce=self.nonce,
            creation_completed=True,receipt_sha256=inspection['receipt_sha256'])
        identifier=self.ledger.removal_target(row['role']);need(identifier==row['id'],'LEDGER_TARGET_CHANGED')
        self._call('container-remove',{'role':row['role'],'identifier':identifier},cleanup=True)
        result=self._call('container-absence',{'role':row['role'],'identifier':identifier},cleanup=True)
        need(result['log'].strip()==b'','CONTAINER_ABSENCE_UNCERTAIN')
        self.ledger.retire(row['role'],identifier=identifier,remove_completed=True,absent=True,receipt_sha256=result['receipt_sha256'])
        row['retired']=True

    def container(self,spec,*,timeout=1200,build_log=None):
        row=self.create(spec);first=None
        try:return self.start_wait(row,timeout=timeout,build_log=build_log)
        except BaseException as error:
            first=error
            if self.first is None:self.first=error
            self.boundary.fail(error,cancel=isinstance(error,KeyboardInterrupt))
            raise
        finally:
            try:self.retire_container(row)
            except BaseException as error:
                self.cleanup_errors.append(type(error).__name__);self.boundary.fail(error,cleanup=True)
                if self.first is None:self.first=error
                if first is None:raise
                first.add_note('owned container cleanup uncertainty: '+type(error).__name__)

    def provision_layer(self,packages):
        need(self.image is None,'ONE_DERIVED_IMAGE')
        row=self.create(ContainerSpec('layer-provision',self.baseline,'provision',{'packages':str(packages)}))
        first=None
        try:
            self.start_wait(row,timeout=600)
            reservation=self.ledger.reserve('layer-image',self.baseline);tag=reservation['name']
            self.image={'name':tag,'base':self.baseline,'id':None,'creation_completed':False,'retired':False}
            self.ledger.submit('layer-image')
            result=self._call('image-commit',{'role':'layer-image','identifier':row['id'],'tag':tag,'nonce':self.nonce,'base':self.baseline},timeout=120)
            identifier=result['log'].decode('ascii').strip();need(IMAGE.fullmatch(identifier) and identifier!=self.baseline,'COMMIT_IMAGE_ID')
            self.image.update(id=identifier,creation_completed=True)
            self.inspect_image()
            return identifier
        except BaseException as error:
            first=error
            if self.first is None:self.first=error
            self.boundary.fail(error,cancel=isinstance(error,KeyboardInterrupt))
            if self.image is not None:self._ambiguity('layer-image','CREATE_UNRETURNED' if not self.image['creation_completed'] else 'INSPECT_UNCERTAIN',error)
            raise
        finally:
            try:self.retire_container(row)
            except BaseException as error:
                self.cleanup_errors.append(type(error).__name__);self.boundary.fail(error,cleanup=True)
                if first is None:raise
                first.add_note('owned provision cleanup uncertainty: '+type(error).__name__)

    def inspect_image(self,cleanup=False):
        need(self.image is not None and self.image['id']!=self.baseline,'BORROWED_IMAGE_REMOVAL_REFUSED')
        result=self._call('image-inspect',{'role':'layer-image','identifier':self.image['id']},cleanup=cleanup)
        need(len(result['log'])<=65536,'IMAGE_INSPECT_CAP');value=json.loads(result['log'])
        labels=value.get('Config',{}).get('Labels') or {}
        need(value.get('Id')==self.image['id'] and value.get('Parent')==self.baseline and value.get('Os')=='linux' and value.get('Architecture')=='arm64' and
             self.image['name']+':latest' in (value.get('RepoTags') or []) and labels.get(LABEL+'nonce')==self.nonce and
             labels.get(LABEL+'role')=='layer-image' and labels.get(LABEL+'base')==self.baseline,'IMAGE_POSITIVE_OWNERSHIP')
        self.ledger.observe('layer-image',identifier=self.image['id'],name=self.image['name'],image=self.baseline,nonce=self.nonce,
            creation_completed=True,receipt_sha256=result['receipt_sha256'])
        return value

    def cleanup(self):
        for row in reversed(tuple(self.containers.values())):
            try:self.retire_container(row)
            except BaseException as error:
                self.cleanup_errors.append(type(error).__name__);self.boundary.fail(error,cleanup=True)
        if self.image is not None and not self.image['retired']:
            try:
                need(self.image['creation_completed'],'UNACKNOWLEDGED_IMAGE_UNCERTAINTY');self.inspect_image(cleanup=True)
                identifier=self.ledger.removal_target('layer-image');need(identifier==self.image['id'] and identifier!=self.baseline,'BORROWED_IMAGE_REMOVAL_REFUSED')
                self._call('image-remove',{'role':'layer-image','identifier':identifier},cleanup=True)
                result=self._call('image-absence',{'role':'layer-image','identifier':identifier},cleanup=True)
                need(not result['log'].strip(),'IMAGE_ABSENCE_UNCERTAIN')
                self.ledger.retire('layer-image',identifier=identifier,remove_completed=True,absent=True,receipt_sha256=result['receipt_sha256'])
                self.image['retired']=True
            except BaseException as error:
                self.cleanup_errors.append(type(error).__name__);self.boundary.fail(error,cleanup=True)
        return {'status':'FAIL' if self.cleanup_errors else 'PASS','uncertainties':len(self.cleanup_errors),'borrowed_baseline_removed':False}

    def build_attempt(self,spec,oracles):
        """New snapshot actor; only selected pure build/package oracles are reused."""
        need(type(spec)is BuildSpec and spec.role in BUILDS and spec.output.is_absolute() and not spec.output.exists(),'FRESH_BUILD_SPEC')
        need(spec.output.is_relative_to(self.output) and not spec.output.is_relative_to(spec.recipe),'BUILD_OUTPUT_SCOPE')
        oracles.verify_pins({'scripts/build/build.py':OLD_BUILD_SHA256,'scripts/checks/package_checks.py':PACKAGE_CHECKS_SHA256})
        report=oracles.recipe(spec.recipe/'PKGBUILD')
        need(report['errors']==[] and report['input_sha256']==spec.inputs,'REVIEWED_RECIPE_INPUTS')
        spec.output.mkdir(mode=0o700);inputs=spec.output/'inputs';inputs.mkdir(mode=0o700)
        need({p.name for p in spec.recipe.iterdir()}==set(spec.inputs),'EXACT_RECIPE_COPYSET')
        for name,pin in spec.inputs.items():
            need('/' not in name and PIN.fullmatch(pin),'RECIPE_LEAF_PIN');raw=read_regular(spec.recipe/name)
            need(sha(raw)==pin,'RECIPE_INPUT_CHANGED');(inputs/name).write_bytes(raw)
        need(oracles.recipe(inputs/'PKGBUILD')['input_sha256']==spec.inputs,'SNAPSHOT_INPUTS_CHANGED')
        lock=read_regular(spec.lock);need(lock and lock.decode()==''.join(sorted(lock.decode().splitlines(keepends=True))),'SORTED_LOCK_REQUIRED')
        expected=spec.output/'expected-packages.lock';expected.write_bytes(lock)
        entry=spec.output/'owned-container-entry.sh';old=read_regular(spec.original_entry);entry.write_bytes(selected_entry(old))
        artifacts=spec.output/'artifacts';artifacts.mkdir(mode=0o700)
        evidence={'schema_version':1,'actor':'new-owned-build','status':'BUILDING','mode':'native','image':spec.image,'image_id':spec.image,
            'source_date_epoch':spec.epoch,'network':'none','recipe_inputs':spec.inputs,'recipe_metadata':report['metadata'],
            'expected_packages_sha256':sha(lock),'entry_source_sha256':sha(old),'entry_script_sha256':sha(entry.read_bytes()),'hardware_status':'NOT RUN'}
        first=None
        try:
            self.container(ContainerSpec(spec.role,spec.image,'build',{'inputs':str(inputs),'artifacts':str(artifacts),'entry':str(entry),
                'lock':str(expected),'epoch':spec.epoch,'uid':spec.uid,'gid':spec.gid}),build_log=spec.output/'build.log')
            row=self.containers[spec.role];evidence['clean_environment_id']=row['id'];evidence['container_name']=row['name']
            required=('environment.txt','packages.lock','config.sha256','makepkg.conf','pacman.conf','generated.SRCINFO')
            for name in required:read_regular(artifacts/name)
            need(read_regular(artifacts/'packages.lock')==lock,'ACTUAL_BUILD_LOCK_DIFFERS')
            oracles.bind_generated(report['metadata'],oracles.metadata(read_regular(artifacts/'generated.SRCINFO').decode()))
            entries=list(artifacts.iterdir());need(len(entries)<=64 and all(p.is_file() and not p.is_symlink() for p in entries) and
                sum(p.stat().st_size for p in entries)<=512*1024**2,'BOUNDED_REGULAR_BUILD_OUTPUTS')
            paths=sorted(artifacts.glob('*.pkg.tar.*'));need(len(paths)==1,'ONE_PACKAGE_REQUIRED')
            need(not paths[0].name.endswith('.zst'),'ZSTD_REQUIRES_OWNED_DECOMPRESSOR')
            need(paths[0].name.endswith(('.pkg.tar.xz','.pkg.tar.gz')),'PACKAGE_FORMAT_NOT_SELECTED')
            package=oracles.package(paths[0]);errors=oracles.conflicts([package])+package['errors']
            errors+=oracles.bind_artifact(report['metadata'],package,spec.inputs['PKGBUILD'])
            save(spec.output/'validation.json',{'artifacts':[package],'errors':errors});need(not errors,'PACKAGE_ORACLE_FAILED')
            evidence['artifacts']={paths[0].name:oracles.digest(paths[0])}
            files={str(p.relative_to(spec.output)):oracles.digest(p) for p in sorted(artifacts.iterdir()) if p.is_file() and not p.is_symlink()}
            for name in ('expected-packages.lock','build.log','validation.json'):files[name]=sha(read_regular(spec.output/name))
            evidence.update(status='built-package-static-pass',files=files)
            return evidence
        except BaseException as error:
            first=error
            evidence.update(status='failed',error_code='OWNED_BUILD_FAILED',first_failure=first_failure(error))
            if self.first is None:self.first=error
            self.boundary.fail(error,cancel=isinstance(error,KeyboardInterrupt));raise
        finally:
            try:save(spec.output/'provenance.json',evidence)
            except BaseException as retained:
                self.cleanup_errors.append(type(retained).__name__)
                self.boundary.fail(retained,cleanup=True,cancel=isinstance(retained,KeyboardInterrupt))
                if self.first is None:self.first=retained
                if first is None:raise
                first.add_note('owned provenance persistence uncertainty: '+type(retained).__name__)


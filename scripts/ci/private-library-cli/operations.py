# SPDX-License-Identifier: MIT
"""Fixed child business schedule and pure oracles over a live parent lease.

No actor runs on import. Parent adapters require the selected in-memory Lease;
serialized baseline claims cannot authorize preflight or terminal acceptance.
"""
import hashlib
import importlib
import json
from pathlib import Path
import sys
import os
from types import SimpleNamespace

import boundary
import owned_build

CONTRACT='manifests/reviewed/project-private-libraries.json'
PLAN='scripts/ci/development/project_library_sources/materialization-plan.json'
INPUT_MAPS={'jbigkit':'manifests/reviewed/project-jbigkit-inputs.json','libtiff':'manifests/reviewed/project-libtiff-inputs.json'}
HELPERS={'common':'scripts/ci/development/common.py','base_stages':'scripts/ci/development/base_stages.py',
    'project_libraries':'scripts/ci/development/project_libraries.py',
    'prepare_project_library_sources':'scripts/ci/development/prepare_project_library_sources.py',
    'package_checks':'scripts/checks/package_checks.py','build':'scripts/build/build.py','compare':'scripts/build/compare.py'}
COMPARISON_GATES=('bytes_equal','installed_contents_equal','pkginfo_equal','buildinfo_equal')
PARENT_COMMANDS=frozenset(('baseline-info','baseline-inspect','parent-container-absence','parent-image-absence'))
NORMAL_COMMANDS=122


def need(value,reason):
    if not value:raise ValueError(reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def read_json(path):return boundary.decode(owned_build.read_regular(Path(path)))


def selected_json(record,path,pin):
    row=record['sources']['files'].get(path)
    need(type(row)is dict and row['sha256']==pin,'SELECTED_INPUT_ROW')
    raw=owned_build.read_regular(Path(record['sources']['root'])/path)
    need(sha(raw)==pin,'SELECTED_INPUT_CHANGED')
    return boundary.decode(raw)


def command(record,command_id,fields):
    """Only fixed Docker/GPG commands; paths are owned output or borrowed lock."""
    need(type(fields)is dict,'COMMAND_FIELDS')
    docker=['/usr/bin/docker','--host','unix:///run/docker.sock']
    need(record['runtime']['docker']['path']=='/usr/bin/docker','SELECTED_DOCKER_PATH')
    if command_id in owned_build.COMMAND_IDS:
        if command_id=='container-create':
            root=Path(record['output']['path'])
            for key in ('inputs','artifacts','entry','archive','packages'):
                if key in fields:need(Path(fields[key]).is_relative_to(root),'OWNED_MOUNT_SCOPE')
            if 'lock' in fields:
                lock=Path(fields['lock']);need(lock.is_relative_to(root) or str(lock)==record['baseline']['packages_lock']['path'],'LOCK_MOUNT_SCOPE')
        return owned_build.command(record,command_id,fields)
    if command_id in PARENT_COMMANDS:
        need(fields=={},'FIXED_PARENT_FIELDS')
        if command_id=='baseline-info':return docker+['info','--format','{{json .}}']
        if command_id=='baseline-inspect':return docker+['image','inspect','--format','{{json .}}',record['baseline']['image_id']]
        label=owned_build.LABEL+'nonce='+record['nonce']
        if command_id=='parent-container-absence':return docker+['container','ls','--all','--no-trunc','--quiet','--filter','label='+label]
        return docker+['image','ls','--all','--no-trunc','--quiet','--filter','label='+label]
    need(command_id=='extension-signature' and set(fields)=={'extension'} and type(fields['extension'])is int and 0<=fields['extension']<5,'FIXED_COMMAND_ID')
    contract=selected_json(record,CONTRACT,record['inputs']['contract_sha256'])
    extensions=contract['builder_extensions'];need(len(extensions)==5,'FIVE_EXTENSIONS')
    row=extensions[fields['extension']];out=Path(record['output']['path'])
    tool=record['runtime']['gpgv']['path'];need(tool=='/usr/bin/gpgv','FIXED_GPGV_PATH')
    # Exact filenames originate only in the pinned contract, never request fields.
    return [tool,'--homedir',str(out/'private-gpgv-home'),'--keyring',str(out/'private-public-keyring.gpg'),
        '--status-fd','1',str(out/('private-input-'+row['signature']['filename'])),str(out/('private-input-'+row['archive']['filename']))]


def resource_schedule():
    """Every normal launch: actor lifecycle110 +other selected launches12."""
    rows=[dict(phase='parent-preflight',command='baseline-info'),dict(phase='parent-preflight',command='baseline-inspect'),
          dict(phase='parent',command='child-launch')]
    rows.extend(dict(phase='extension-signature',command='extension-signature',extension=n) for n in range(5))
    def container(role):
        return [dict(phase=role,role=role,command=cmd,cleanup=cleanup) for cmd,cleanup in
            (('container-create',False),('container-inspect',False),('container-start-attach',False),('container-wait',False),
             ('container-inspect',True),('container-remove',True),('container-absence',True))]
    for role in boundary.BUILDS[:2]:
        rows.extend(container(role))
        for number in (1,2):rows.extend(container('probe-'+role+'-'+str(number)))
    provision=container('layer-provision');rows.extend(provision[:4])
    rows.extend((dict(phase='layer-image',role='layer-image',command='image-commit',cleanup=False),
                 dict(phase='layer-image',role='layer-image',command='image-inspect',cleanup=False)))
    rows.extend(provision[4:]);rows.extend(container('layer-lock'));rows.extend(container('layer-dependencies'))
    for role in boundary.BUILDS[2:]:
        rows.extend(container(role))
        for number in (1,2):rows.extend(container('probe-'+role+'-'+str(number)))
    rows.extend(dict(phase='layer-image-cleanup',role='layer-image',command=cmd,cleanup=True) for cmd in ('image-inspect','image-remove','image-absence'))
    rows.extend(dict(phase='parent-terminal',command=cmd,cleanup=True) for cmd in
        ('parent-container-absence','parent-image-absence','baseline-info','baseline-inspect'))
    need(len(rows)==NORMAL_COMMANDS and len({r['role'] for r in rows if 'role'in r})==16,'EXACT_RESOURCE_SCHEDULE')
    return rows


class SelectedOracles:
    """Ordinary imports from held private Source; no callback or heap-proof API."""
    def __init__(self,record,*,producer_root=None):
        self.record=record;self.root=Path(record['sources']['root'])
        directories=[str(self.root/'scripts/ci/development'),str(self.root/'scripts/checks'),str(self.root/'scripts/build')]
        for path in reversed(directories):
            if path not in sys.path:sys.path.insert(0,path)
        self.modules={}
        for name,path in HELPERS.items():
            self.verify_pins({path:record['sources']['files'][path]['sha256']})
            module=importlib.import_module(name)
            origin=Path(module.__file__)
            allowed={self.root/path}
            if producer_root is not None:
                parent=Path(producer_root);need(parent.is_absolute() and '..'not in parent.parts,'REGISTERED_PRODUCER_ROOT')
                allowed.add(parent/path)
            need(origin in allowed,'SELECTED_MODULE_ORIGIN')
            need(sha(owned_build.read_regular(origin))==record['sources']['files'][path]['sha256'],'SELECTED_MODULE_BYTES')
            self.modules[name]=module
        checks=self.modules['package_checks'];build=self.modules['build']
        for name in ('recipe','metadata','conflicts','digest'):setattr(self,name,getattr(checks,name))
        self.bind_generated=build.bind_generated;self.bind_artifact=build.bind_artifact

    def verify_pins(self,expected):
        for path,pin in expected.items():
            need(self.record['sources']['files'][path]['sha256']==pin and sha(owned_build.read_regular(self.root/path))==pin,'PURE_ORACLE_PIN')

    def package(self,path):
        need(not str(path).endswith('.zst'),'ZSTD_REQUIRES_OWNED_DECOMPRESSOR')
        need(str(path).endswith(('.pkg.tar.xz','.pkg.tar.gz')),'SELECTED_ARCHIVE_FORMAT')
        return self.modules['package_checks'].package(path)


class Operations:
    """Selected business adapter. Actor/helper methods are fixed, never input callbacks."""
    def __init__(self,record,runner,state,ledger,custody):
        self.record=record;self.runner=runner;self.state=state;self.ledger=ledger;self.custody=custody
        self.root=Path(record['sources']['root']);self.output=Path(record['output']['path']);self.cache=self.output/'baseline-cache'
        self.deadline=record['cutoff_monotonic'];self.materialized=None
        need(state.fetches==0 and state.fetch_total==0,'FRESH_CHILD_FETCH_SUFFIX')
        self.accepted_extensions={};self.signature_index=0;self.probes={};self.comparisons={};self.attempts={};self.derived=None
        self.guard();self.oracles=SelectedOracles(record);self.library=self.oracles.modules['project_libraries']
        self.actor=owned_build.OwnedBuild(record,state,ledger,runner,self.output)
        self.trusted_gpgv=record['runtime']['gpgv']

    def copy_keyring(self):
        """Copy only the live lease's selected public certificate, never ambient cache."""
        self.guard();row=self.record['baseline']['cache']['archlinuxarm_keyring'];boundary.file_ref(row)
        source=Path(row['path']);info=source.lstat()
        need([getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')]==row['identity'],
            'BORROWED_KEYRING_IDENTITY')
        raw=owned_build.read_regular(source,3098)
        need(len(raw)==row['bytes']==3098 and sha(raw)==row['sha256']=='6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f',
            'BORROWED_KEYRING_PIN')
        self.library.dearmor(raw)
        self.cache.mkdir(mode=0o700);path=self.cache/'archlinuxarm.gpg';path.write_bytes(raw);path.chmod(0o600)
        self.guard()

    @property
    def fetch_count(self):return self.state.fetches

    @fetch_count.setter
    def fetch_count(self,value):
        boundary.integer(value,0,boundary.FETCH_LIMIT)
        need(value>=self.state.fetches,'FETCH_COUNTER_CANNOT_RESET');self.state.fetches=value

    @property
    def fetch_bytes(self):return self.state.fetch_total

    @fetch_bytes.setter
    def fetch_bytes(self,value):
        boundary.integer(value,0,boundary.FETCH_TOTAL)
        need(value>=self.state.fetch_total,'FETCH_BYTES_CANNOT_RESET');self.state.fetch_total=value

    def guard(self,cleanup=False):
        import parent_bridge
        parent_bridge.recheck(self.record,self.custody,cleanup=cleanup)
        return None

    def run(self,args,label,timeout=120,cleanup=False):
        # Existing prepare's five GPG calls are matched to the fixed indexed grammar.
        need(label=='extension-signature' and self.signature_index<5 and not cleanup,'SELECTED_SIGNATURE_CALL')
        fields={'extension':self.signature_index};need(args==command(self.record,label,fields),'SIGNATURE_ARGV_DIFFERS')
        result=self.runner.run(label,fields,timeout=timeout,cleanup=False);self.signature_index+=1
        need(result['exit_code']==0 and result['natural_exit'] and result['reaped'] and result.get('pidfd_owned') is True and result.get('first_failure') is None and not result['uncertainty'],'SIGNATURE_PROCESS_FAILED')
        need(type(result['log'])is bytes and len(result['log'])<=65536 and sha(result['log'])==result['sha256'] and len(result['log'])==result['bytes'], 'SIGNATURE_LOG_PIN')
        need(owned_build.read_regular(Path(result['log_path']),65536)==result['log'],'SIGNATURE_ACTUAL_LOG')
        owned_build.save(self.output/('signature-process-'+str(fields['extension'])+'.json'),
            {k:result[k] for k in ('exit_code','natural_exit','reaped','pidfd_owned','first_failure','uncertainty','birth','log_path','sha256','bytes')})
        self.guard();return Path(result['log_path'])

    def fetch(self,item,name):
        # Exact selected Source retains redirect/body/count/pin/close handling.
        value=self.library.Operations.fetch(self,item,name)
        need(self.fetch_count<=14 and self.fetch_bytes<=boundary.FETCH_TOTAL,'FETCH_BUDGET')
        return value

    def prepare(self,contract,phases=None):
        need(all(row['archive']['filename'].endswith(('.pkg.tar.xz','.pkg.tar.gz')) for row in contract['builder_extensions']),
            'EXTENSION_FORMAT_NOT_SELECTED')
        self.copy_keyring()
        materializer=self.oracles.modules['prepare_project_library_sources']
        if phases is None:phases={name:'NOT RUN' for name in self.library.PHASES}
        self.library.Operations.prepare(self,contract,materializer,phases)
        need(self.fetch_count==14 and self.signature_index==5,'EXACT_PREPARE_COUNTS')
        return phases

    def build(self,key,number,spec,image,lock):
        self.guard();role=key+'-'+str(number)
        need(role in boundary.BUILDS and self.materialized is not None,'FIXED_BUILD_ROLE')
        recipe=self.materialized/key;need({p.name for p in recipe.iterdir()}==set(spec['inputs']),'EXACT_RECIPE_COPYSET')
        attempt=self.output/(key+'-attempt-'+str(number))
        build=owned_build.BuildSpec(role,recipe,attempt,image,Path(lock),spec['inputs'],spec['epoch'],
            self.record['credentials']['uid'],self.record['credentials']['gid'],self.root/'scripts/build/container-entry.sh')
        self.actor.build_attempt(build,self.oracles)
        result=self.library.Operations.inspect(self,key,number,spec,image,lock,attempt)
        self.attempts[role]=result;return result

    def probe(self,archive,member,pin,soname,image):
        self.guard();attempt=Path(archive).parent.parent.name
        key,_,number=attempt.partition('-attempt-');role=key+'-'+number
        need(role in boundary.BUILDS,'PROBE_BUILD_ROLE');index=self.probes.get(role,0)+1;need(index<=2,'TWO_PROBES_PER_BUILD')
        self.probes[role]=index
        log=self.actor.container(owned_build.ContainerSpec('probe-'+role+'-'+str(index),image,'probe',{'archive':str(archive),'member':member}),timeout=120)
        return self.library.dynamic_report(log.decode('utf-8'),pin,soname)

    def compare(self,key,left,right):
        self.guard();self.library.checked_pair(left,right)
        # Fail before the existing comparator can call a hidden zstd subprocess.
        need(all(not row['filename'].endswith('.zst') for row in (left,right)),'ZSTD_REQUIRES_OWNED_DECOMPRESSOR')
        value=self.oracles.modules['compare'].compare(self.output/(key+'-attempt-1'),self.output/(key+'-attempt-2'))
        row=value.get('packages',{}).get(left['filename'],{})
        need(value.get('status')=='contents-reproduced' and value.get('errors')==[] and all(row.get(k)is True for k in COMPARISON_GATES),'FULL_PAIR_COMPARISON')
        self.comparisons[key]={k:row[k] for k in COMPARISON_GATES}
        owned_build.save(self.output/(key+'-comparison.json'),value)

    def extension_inputs(self,extensions):return self.library.Operations.extension_inputs(self,extensions)

    def layer_image(self,jbig,baseline,extensions):
        self.guard();lock=owned_build.read_regular(Path(baseline['packages_lock'])).decode()
        wanted=self.library.expected_layer_lock(lock,extensions)
        need(len(wanted.splitlines())==346 and sha(wanted.encode())==boundary.DERIVED_LOCK,'EXACT_DERIVED_346')
        packages=self.output/'private-layer-context';packages.mkdir(mode=0o700)
        for n,path in enumerate([Path(jbig['archive']),*self.extension_inputs(extensions)]):
            self.library.copy_regular(path,packages/('input-'+str(n)+'.pkg.tar'),64*1024**2,deadline=self.deadline)
        image=self.actor.provision_layer(packages)
        actual=self.actor.container(owned_build.ContainerSpec('layer-lock',image,'lock',{}),timeout=120).decode()
        need(''.join(sorted(actual.splitlines(keepends=True)))==wanted,'ACTUAL_DERIVED_346_LOCK')
        self.actor.container(owned_build.ContainerSpec('layer-dependencies',image,'dependencies',{}),timeout=120)
        path=self.output/'private-layer-packages.lock';path.write_text(wanted)
        self.derived={'image_id':image,'packages':346,'lock_sha256':sha(wanted.encode()),'dependency_check':True}
        return image,path

    def cleanup(self):return self.actor.cleanup()


def parent_preflight(record,custody,lease):
    import baseline_bridge
    need(type(lease)is baseline_bridge.Lease,'LIVE_BASELINE_LEASE_REQUIRED')
    return lease.preflight(record,custody)


def parent_terminal(record,child_terminal,process_receipt,custody,lease):
    import baseline_bridge
    need(type(lease)is baseline_bridge.Lease,'LIVE_BASELINE_LEASE_REQUIRED')
    return lease.terminal(record,child_terminal,process_receipt,custody)


def verify_business(record,custody,child,*,producer_root=None):
    import evidence
    return evidence.verify_business(record,custody,child,producer_root=producer_root)


def run_cli(record,runner,boundary_state,custody):
    """Fixed child business schedule; no JSON-selected callback or subprocess."""
    import evidence
    resource_schedule()
    ledger=ops=None;first=None;phases={}
    try:
        ledger=boundary.ResourceLedger(Path(record['output']['path'])/'resource-ledger.jsonl',boundary_state)
        ops=Operations(record,runner,boundary_state,ledger,custody)
        contract=evidence.contract_inputs(record)
        phases={name:'NOT RUN' for name in ops.library.PHASES};phases['preflight']='PASS'
        phases['runtime-inputs']='RUNNING'
        ops.prepare(contract,phases);phases['runtime-inputs']=phases['materialize']='PASS'
        ops.library.execute(ops,contract,{'packages_lock':record['baseline']['packages_lock']['path']},
            SimpleNamespace(image=record['baseline']['image_id']),phases)
    except BaseException as error:
        first=error;boundary_state.fail(error,cancel=isinstance(error,KeyboardInterrupt))
    finally:
        if ops is not None:
            try:
                phases['cleanup']='RUNNING'
                result=ops.cleanup();need(result['status']=='PASS' and result['uncertainties']==0,'OWNED_CLEANUP_UNCERTAIN')
                phases['cleanup']='PASS'
            except BaseException as error:
                boundary_state.fail(error,cleanup=True,cancel=isinstance(error,KeyboardInterrupt))
                if first is None:first=error
        if ledger is not None:
            try:ledger.close()
            except BaseException as error:
                boundary_state.fail(error,cleanup=True,cancel=isinstance(error,KeyboardInterrupt))
                if first is None:first=error
    def persist_phases():
        if phases:
            observed={key:('FAIL' if value=='RUNNING' else value) for key,value in phases.items()}
            owned_build.save(Path(record['output']['path'])/'private-phases.json',dict(
                schema_version=1,purpose='project-library-phase-observations',phases=observed))
    if first is not None or boundary_state.first_cause is not None or boundary_state.cleanup_errors or boundary_state.cancelled:
        try:persist_phases()
        except BaseException as error:boundary_state.fail(error,cleanup=True)
        return boundary_state.terminal(ledger=ledger,status='FAIL')
    try:
        phases['private-postbuild-association']='RUNNING'
        need(all(value=='PASS' for key,value in phases.items() if key!='private-postbuild-association'),'ALL_FIXED_PHASES_REQUIRED')
        values=evidence.assemble(record,custody)
        birth=runner.host.birth(os.getpid())
        need(birth['pid']==birth['sid']==os.getpid() and birth['ppid']>0 and birth['start_ticks']>0,'CHILD_SELF_BIRTH')
        child={'pid':birth['pid'],'session_id':birth['sid'],'start_time_ticks':birth['start_ticks'],
            'pidfd_held':False,'reaped':False,'exit_code':None,'natural':False}
        phases['private-postbuild-association']='PASS'
        persist_phases()
        return boundary_state.terminal(ledger=ledger,child=child,private_checks={k:True for k in boundary.PRIVATE_CHECKS},
            status='CHILD_COMPLETE',**values)
    except BaseException as error:
        boundary_state.fail(error,cancel=isinstance(error,KeyboardInterrupt))
        if not (Path(record['output']['path'])/'private-phases.json').exists():
            try:persist_phases()
            except BaseException as closed:boundary_state.fail(closed,cleanup=True)
        return boundary_state.terminal(ledger=ledger,status='FAIL')

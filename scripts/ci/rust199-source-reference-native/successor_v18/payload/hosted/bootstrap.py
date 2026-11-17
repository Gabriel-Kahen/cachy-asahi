# SPDX-License-Identifier: MIT
"""Source-owned signed349 bootstrap and normal TEST-signed private LLVM install."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import stat
import sys
import tarfile
import time
from types import SimpleNamespace

DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock']
FROZEN_SHA='27e17683ba185d6959307b081ab86be4c7740ef5dbb8dff9c850670eda2ec008'
BASELINE_SHA='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
PACKAGE='cachy-asahi-llvm23-source-reference-23.1.1-1-aarch64.pkg.tar.zst'
PREFIX='opt/cachy-asahi/llvm23-source-reference'
LABEL='cachy-asahi.rust199-bootstrap'


def need(value,why):
    if not value:raise ValueError(why)


def encode(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def sha(path,tick=lambda:None):
    h=hashlib.sha256()
    with Path(path).open('rb') as source:
        while True:
            tick();block=source.read(1024**2)
            if not block:break
            h.update(block)
    return h.hexdigest()


def copy_data(source,target,tick=lambda:None):
    with source.open('rb') as src,target.open('xb') as out:
        while True:
            tick();block=src.read(1024**2)
            if not block:break
            out.write(block)
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m


def read(path,cap=4*1024**2):
    path=Path(path);need(path.is_absolute() and all(not p.is_symlink() for p in (path,*path.parents)),'ordinary absolute bootstrap DATA')
    with path.open('rb') as source:
        before=os.fstat(source.fileno());need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded ordinary bootstrap DATA')
        raw=source.read(cap+1);after=os.fstat(source.fileno())
    key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    need(len(raw)==before.st_size and key(before)==key(after)==key(path.lstat()),'bootstrap DATA changed');return raw


def provider_source(provider):
    need(provider['schema']==4 and provider['status']=='ACTUAL_PROVIDER_BINDING_ONLY' and provider['phase']=='bootstrap' and provider['run_attempt']==1 and provider['manual_dispatch'] is True,'actual bootstrap provider binding before images')
    source=provider['source'];return dict(source=source['sha'],ref=source['ref'],run=source['run'],job=source['job'],source_map_sha256=source['map_sha256'],approval=source['approval'])


def owner(binding):
    need(re.fullmatch('[0-9a-f]{40}',binding['source']) and all(re.fullmatch('[1-9][0-9]{0,19}',binding[k]) for k in ('run','job')),'actual provider-bound image owner')
    token=hashlib.sha256(encode(binding)).hexdigest()[:24]
    return dict(source=binding['source'],run=binding['run'],job=binding['job'],token=token,base_tag='rust199-base:'+token,tag='rust199-qualified:'+token)


def inventory(raw,baseline=None):
    rows={}
    for line in raw.decode().splitlines():
        fields=line.split(' ');need(len(fields)==2 and re.fullmatch('[A-Za-z0-9@._+-]+',fields[0]) and fields[0] not in rows,'finite unique ALPM inventory')
        rows[fields[0]]=fields[1]
    need(raw==''.join(k+' '+v+'\n' for k,v in sorted(rows.items())).encode(),'canonical ALPM inventory')
    if baseline is None:need(len(rows)==349 and hashlib.sha256(raw).hexdigest()==BASELINE_SHA,'exact signed349 baseline')
    else:need(350<=len(rows)<=600 and all(rows.get(k)==v for k,v in baseline.items()) and rows.get('cachy-asahi-llvm23-source-reference')=='23.1.1-1','normal private LLVM ALPM join without baseline drift')
    return rows


def fingerprint(raw):
    primary=[];pending=False
    for line in raw.decode().splitlines():
        fields=line.split(':')
        if fields[0]=='pub':pending=True
        elif fields[0]=='fpr' and pending:primary.append(fields[9]);pending=False
    need(len(primary)==1 and re.fullmatch('(?:[0-9A-F]{40}|[0-9A-F]{64})',primary[0]),'one public TEST primary key only');return primary[0]


def signature_status(raw,expected):
    rows=[line.split() for line in raw.decode().splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
    need(len(rows)==1 and expected in (rows[0][2],rows[0][-1]) and not any(x in raw.decode() for x in ('BADSIG','ERRSIG','NO_PUBKEY','EXPSIG','EXPKEYSIG','REVKEYSIG')),'exact accepted public TEST signature mathematics')


def normal_dockerfile(base_tag,key_fingerprint):
    need(re.fullmatch('rust199-base:[0-9a-f]{24}',base_tag) and re.fullmatch('(?:[0-9A-F]{40}|[0-9A-F]{64})',key_fingerprint),'fixed normal install operands')
    return f'''FROM {base_tag}
USER root
COPY {PACKAGE} /tmp/private-llvm/{PACKAGE}
COPY {PACKAGE}.sig /tmp/private-llvm/{PACKAGE}.sig
COPY public-test-key.asc /tmp/public-test-key.asc
RUN mkdir -m 700 /tmp/private-test-keyring && gpg --batch --homedir /tmp/private-test-keyring --import /tmp/public-test-key.asc && printf '%s:6:\\n' '{key_fingerprint}' | gpg --batch --homedir /tmp/private-test-keyring --import-ownertrust && pacman --gpgdir /tmp/private-test-keyring --config /etc/pacman.conf -U --noconfirm --noscriptlet /tmp/private-llvm/{PACKAGE} && gpgconf --homedir /tmp/private-test-keyring --kill gpg-agent && test ! -e /tmp/private-test-keyring/S.gpg-agent && test ! -L /tmp/private-test-keyring/S.gpg-agent && test ! -e /tmp/private-test-keyring/S.gpg-agent.browser && test ! -L /tmp/private-test-keyring/S.gpg-agent.browser && test ! -e /tmp/private-test-keyring/S.gpg-agent.extra && test ! -L /tmp/private-test-keyring/S.gpg-agent.extra && test ! -e /tmp/private-test-keyring/S.gpg-agent.ssh && test ! -L /tmp/private-test-keyring/S.gpg-agent.ssh && ldconfig && test -d /{PREFIX} && test ! -L /{PREFIX} && mkdir -p /work /stage0 /inputs /source /materials && pacman -Q | LC_ALL=C sort > /builder-qualified.lock && rm -rf /tmp/private-llvm /tmp/private-test-keyring /tmp/public-test-key.asc
USER alarm
WORKDIR /tmp
'''.encode()


@contextmanager
def source_facade(root,binding):
    entry=load('rust_bootstrap_source_guards',root/'hosted/entry.py')
    # Original349 code receives a Source-specific closed-map verifier, not LLVM aliases.
    yield SimpleNamespace(load=load,read=read,encode=encode,decode=json.loads,pin=lambda b:dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest()),verify_source=entry.source_gate)


def build_base(root,work,binding,command,deadline):
    raw=read(root/'frozen/bootstrap349.py',128*1024);need(hashlib.sha256(raw).hexdigest()==FROZEN_SHA,'exact proven signed349 helper')
    frozen=load('rust_frozen_bootstrap349',root/'frozen/bootstrap349.py');frozen.LABEL=LABEL
    own=owner(binding);frozen_owner=dict(token=own['token'],tag=own['base_tag'],source=binding['source'])
    out=work/'bootstrap';out.mkdir(mode=0o700);temp=Path(os.environ['RUNNER_TEMP']);cache=temp/'alarm-cache';carrier=temp/'pgo-hosted-retained'
    need(cache.is_dir() and carrier.is_dir() and (carrier/'.git').is_dir(),'actual finite retained DATA and seeded original cache required')
    with source_facade(root,binding) as common,frozen.held_modules(root,common) as held:
        common.verify_source(root,binding['source_map_sha256'])
        profile,original,expected=held.common.input_contract(root/'original');combined=frozen.combined_inputs(original,profile,expected)
        (out/'inputs.lock.json').write_bytes(encode(combined))
        with frozen.seed_commands(held.pgo,command):receipt=held.seed.prepare(carrier,cache,'native248',root/'original/bootstrap/scripts/ci/inputs.lock.json',min(deadline,time.monotonic()+2250),carrier/'.git')
        (out/'input-data-preparation.json').write_bytes(encode(receipt));frozen.seed_additions(profile,carrier,cache,out,deadline,held.provision,common)
        previous=held.native.fetch;held.native.fetch=held.fetch.bind_fetch(original,profile['additions']['rows'],cache,lambda row,selected:frozen.cache_only(row,selected,deadline,held.cache.cache_file),previous)
        try:
            def bounded_command(argv,**kwargs):
                if argv[:3]==DOCKER+['build']:
                    argv=list(argv);need(all(not arg.startswith(('--network','--pull')) or arg in ('--network=none','--pull=false') for arg in argv[3:]) and all(argv.count(flag)<=1 for flag in ('--network=none','--pull=false')),'offline local-only signed349 build')
                    argv[3:3]=[arg for arg in ('--network=none','--pull=false') if arg not in argv]
                kwargs.setdefault('check',False) # Preserve subprocess.run audit diagnostics on invalid signatures.
                return command(argv,**kwargs)
            with frozen.native_commands(held.native,bounded_command,deadline,frozen_owner) as (invoke,builds):
                need(held.native.audit(combined,cache,out)==256,'all original signed dependency observations required')
                for selector in ('reference='+own['base_tag'],'label='+LABEL+'='+own['token']):
                    need(not invoke(DOCKER+['image','ls','--no-trunc','-q','--filter',selector],capture_output=True,text=True,check=True).stdout.strip(),'fresh labeled base image namespace')
                image=held.native.build(combined,cache,out,{})
                need(len(builds)==1 and re.fullmatch('sha256:[0-9a-f]{64}',image),'one actual immutable signed349 image')
        finally:held.native.fetch=previous
    raw=read(out/'packages.lock');inventory(raw);need(raw==read(root/'expected349.lock'),'complete Source349 byte inventory')
    return image,dict(path=str(out/'packages.lock'),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),count=349)


def bounded_info(max_headers,tick=lambda:None):
    state={'headers':0,'ended':False}
    class Info(tarfile.TarInfo):
        @classmethod
        def fromtarfile(cls,archive):return cls._fromtarfile(archive)
        @classmethod
        def _fromtarfile(cls,archive,*,dircheck=True):
            tick()
            block=archive.fileobj.read(512)
            if block==bytes(512):state['ended']=True
            else:
                state['headers']+=1;need(state['headers']<=max_headers,'tar raw header count cap')
            item=(cls._frombuf(block,archive.encoding,archive.errors,dircheck=dircheck) if hasattr(cls,'_frombuf') else cls.frombuf(block,archive.encoding,archive.errors))
            item.offset=archive.fileobj.tell()-512;return item._proc_member(archive)
        def _proc_pax(self,archive):
            need(0<=self.size<=65536,'tar PAX metadata cap');return super()._proc_pax(archive)
        def _proc_gnulong(self,archive):
            need(0<=self.size<=65536,'tar GNU long-name cap');return super()._proc_gnulong(archive)
        def _proc_sparse(self,*args):raise ValueError('sparse tar refused')
        _proc_gnusparse_00=_proc_sparse;_proc_gnusparse_01=_proc_sparse;_proc_gnusparse_10=_proc_sparse
    return Info,state


def end_tar(archive,state,tick=lambda:None):
    tail=0
    while True:
        tick();block=archive.fileobj.read(65536)
        if not block:break
        tail+=len(block);need(not any(block) and tail<=16*1024**2,'bounded zero-only tar tail')
    need(state['ended'] and tail>=512 and archive.fileobj.tell()%512==0,'complete tar termination required')


def extract_rootfs(archive,destination,deadline,tick=lambda:None):
    """Materialize exact export DATA modes without executing or following symlinks."""
    def check():
        need(time.monotonic()<deadline,'rootfs DATA deadline');tick()
    check();need(not destination.exists(),'fresh private rootfs DATA tree');destination.mkdir(mode=0o700)
    seen=set();directories=[];links=[];logical=0;modes={}
    info,state=bounded_info(600000,check)
    with tarfile.open(archive,mode='r|',tarinfo=info) as stream:
        for member in stream:
            check();need(not member.sparse and not any(k.startswith('GNU.sparse') for k in member.pax_headers),'sparse rootfs export refused');name=PurePosixPath(member.name)
            if str(name)=='.':continue
            need(not name.is_absolute() and '..' not in name.parts and str(name) not in seen and len(name.parts)<80,'ordinary unique rootfs member')
            seen.add(str(name));need(len(seen)<=600000 and member.mode<=0o7777,'rootfs member/mode bounds');logical+=member.size;need(logical<=16*1024**3,'rootfs logical byte bound')
            target=destination.joinpath(*name.parts)
            for parent in reversed(target.parents):
                check()
                if parent==destination or destination in parent.parents:
                    if parent.exists():need(parent.is_dir() and not parent.is_symlink(),'rootfs parent cannot be an alias')
                    else:parent.mkdir(mode=0o700)
            if member.isdir():
                if not target.exists():target.mkdir(mode=0o700)
                need(target.is_dir() and not target.is_symlink(),'ordinary rootfs directory');directories.append((target,member.mode));modes[str(name)]=member.mode
            elif member.isfile():
                with stream.extractfile(member) as source,target.open('xb') as out:
                    while True:
                        check();block=source.read(1024**2)
                        if not block:break
                        out.write(block)
                modes[str(name)]=member.mode
            elif member.issym() or member.islnk():links.append((target,member.linkname,member.issym(),member.mode))
            else:raise ValueError('special rootfs export node refused')
            stream.members.clear()
        end_tar(stream,state,check)
    for target,link,symbolic,mode in links:
        check()
        need(not any(p.is_symlink() for p in target.parents),'rootfs link parent cannot alias outside DATA')
        if symbolic:target.symlink_to(link)
        else:
            relative=PurePosixPath(link);need(not relative.is_absolute() and '..' not in relative.parts,'rootfs hardlink escape');source=destination.joinpath(*relative.parts)
            need(source.is_file() and not any(p.is_symlink() for p in (source,*source.parents)),'rootfs hardlink must name an ordinary internal regular file');logical+=source.stat().st_size;need(logical<=16*1024**3,'rootfs materialized byte bound');copy_data(source,target,check);modes[target.relative_to(destination).as_posix()]=mode
    # Only this fresh private host DATA staging tree stays readable. Image bytes,
    # permissions and actor policy are never changed. Hash before final modes.
    observed={};digest=tree_digest(destination,check,modes,observed)
    def identity(info):return tuple(getattr(info,k)for k in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
    # Detect changed/extra staging nodes before restrictive parent modes are set.
    current={p.relative_to(destination).as_posix():identity(p.lstat())for p in destination.rglob('*')}
    need(current==observed,'rootfs DATA changed before exact mode finalization')
    for name,mode in sorted(modes.items(),key=lambda row:(-len(PurePosixPath(row[0]).parts),row[0])):
        check();path=destination/name;before=path.lstat()
        need(identity(before)==observed[name] and before.st_uid==os.getuid() and
             (stat.S_ISREG(before.st_mode)or stat.S_ISDIR(before.st_mode)) and
             not any(p.is_symlink()for p in path.parents),'same owned ordinary DATA node before final mode')
        fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            need(identity(os.fstat(fd))==identity(before),'same finalization descriptor')
            os.fchmod(fd,mode);after=os.fstat(fd)
            need(identity(after)==identity(path.lstat()) and stat.S_IMODE(after.st_mode)==mode and
                 all(getattr(before,k)==getattr(after,k)for k in ('st_dev','st_ino','st_nlink','st_uid','st_gid','st_size','st_mtime_ns')),
                 'exact final DATA mode/identity; no postmode content rehash claimed')
        finally:os.close(fd)
    return dict(files=len(seen),logical_bytes=logical,rootfs_tree_sha256=digest,
                digest_timing='PRIVATE_READABLE_STAGING_BEFORE_EXACT_MODE_FINALIZATION',final_modes_verified=True)


def tree_digest(root,tick=lambda:None,modes=None,observed=None):
    h=hashlib.sha256()
    for current,dirs,files in os.walk(root,followlinks=False):
        tick()
        dirs.sort()
        for name in sorted(dirs+files):
            tick()
            p=Path(current)/name;s=p.lstat()
            if stat.S_ISLNK(s.st_mode):kind,content='link',os.readlink(p)
            elif stat.S_ISDIR(s.st_mode):kind,content='dir',''
            elif stat.S_ISREG(s.st_mode):kind,content='file',sha(p,tick)
            else:raise ValueError('special rootfs DATA node')
            name=p.relative_to(root).as_posix()
            key=lambda info:tuple(getattr(info,k)for k in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
            need(key(s)==key(p.lstat()),'rootfs DATA changed while hashing')
            if observed is not None:observed[name]=key(s)
            mode=stat.S_IMODE(s.st_mode)if modes is None else modes.get(name,stat.S_IMODE(s.st_mode))
            h.update((json.dumps([name,kind,mode,content],separators=(',',':'))+'\n').encode())
    return h.hexdigest()


def inspect_image(value,image,own):
    need(value['Id']==image and value['Os']=='linux' and value['Architecture']=='arm64' and not value['Config'].get('Volumes') and value['Config']['Labels'].get(LABEL)==own['token'] and value['Config']['Labels'].get(LABEL+'.source')==own['source'],'exact owned immutable native image with no anonymous volumes')


def run(root,work,binding,plan,delivered,command):
    provider=binding;binding=provider_source(provider)
    root,work=Path(root),Path(work);own=owner(binding);out=work/'normal-image';out.mkdir(mode=0o700)
    dependencies=load('rust_bootstrap_build_dependencies',root/'hosted/build_dependencies.py');dependency_policy=dependencies.policy(root)
    gate=load('rust_bootstrap_material_gate',root/'admission.py');llvm=gate.validate_llvm_material(plan['llvm'],delivered['files'])
    files=delivered['files'];archive=Path(files['llvm_archive']['local_path']);signature=Path(files['llvm_signature']['local_path']);key=Path(files['public_test_key']['local_path'])
    fingerprint_expected=llvm['public_test_key']['fingerprint'];home=out/'gpg';home.mkdir(mode=0o700)
    base=None;image=None;exporter=None;report=dict(schema=1,status='FAIL',binding=binding,owner=own,resources=[],errors=[],native_acceptance=False)
    (out/'bootstrap.json').write_bytes(encode(report))
    phase_deadline=command.deadline;cleaning=False
    def tick():
        need(time.monotonic()<min(phase_deadline,command.deadline),'normal image aggregate2100s/global deadline')
        need(not command.cancelled[0],'normal image cancellation')
        if command.on_tick is not None:command.on_tick()
    def call(argv,timeout=60,check=True,**kw):
        if not cleaning:tick()
        cap=min(timeout,command.deadline-time.monotonic(),timeout if cleaning else phase_deadline-time.monotonic());need(cap>0,'finite normal image command')
        return command(argv,timeout=cap,check=check,**kw)
    def inspect(argv):
        values=json.loads(call(argv).stdout);need(type(values)is list and len(values)==1,'one exact daemon observation');return values[0]
    try:
        report['base_intent']=True;(out/'bootstrap.json').write_bytes(encode(report))
        base,baseline=build_base(root,work,binding,command,min(command.deadline,time.monotonic()+4500));report['base_image']=base;(out/'bootstrap.json').write_bytes(encode(report))
        phase_deadline=min(command.deadline,time.monotonic()+2100);report['normal_phase_deadline']=phase_deadline;tick()
        call(['/usr/bin/gpg','--no-options','--no-auto-key-retrieve','--batch','--homedir',str(home),'--import',str(key)],timeout=30)
        observed=call(['/usr/bin/gpg','--no-options','--no-auto-key-retrieve','--batch','--homedir',str(home),'--with-colons','--fingerprint','--list-keys'],timeout=30).stdout
        need(fingerprint(observed)==fingerprint_expected,'public TEST fingerprint differs')
        verified=call(['/usr/bin/gpg','--no-options','--no-auto-key-retrieve','--batch','--homedir',str(home),'--status-fd=1','--verify',str(signature),str(archive)],timeout=120).stdout;signature_status(verified,fingerprint_expected)
        (out/'public-TEST-verification.json').write_bytes(encode(dict(status='PASS_EXACT_TEST_SIGNATURE',fingerprint=fingerprint_expected,archive_sha256=sha(archive,tick),signature_sha256=sha(signature,tick),public_key_sha256=sha(key,tick),status_sha256=hashlib.sha256(verified).hexdigest())))
        actual=inspect(DOCKER+['image','inspect',base]);inspect_image(actual,base,own);need(own['base_tag'] in actual['RepoTags'],'exact owned base tag')
        context=out/'context';context.mkdir(mode=0o700)
        for source,name in ((archive,PACKAGE),(signature,PACKAGE+'.sig'),(key,'public-test-key.asc')):copy_data(source,context/name,tick);need(sha(context/name,tick)==sha(source,tick),'normal context bytes changed')
        dependency_audit=dependencies.prepare_context(root,context,out,Path(os.environ['RUNNER_TEMP'])/'alarm-cache',dependency_policy,call,tick)
        dockerfile=dependencies.extend_dockerfile(normal_dockerfile(own['base_tag'],fingerprint_expected),dependency_policy);(context/'Dockerfile').write_bytes(dockerfile)
        need(not call(DOCKER+['image','ls','--no-trunc','-q','--filter','reference='+own['tag']]).stdout.strip(),'fresh normal image tag')
        report['normal_intent']=True;(out/'bootstrap.json').write_bytes(encode(report))
        call(DOCKER+['build','--network=none','--pull=false','--no-cache','--platform=linux/arm64','--tag',own['tag'],'--label',LABEL+'='+own['token'],'--label',LABEL+'.source='+own['source'],'--iidfile',str(out/'image-id'),str(context)],timeout=min(900,phase_deadline-time.monotonic()))
        image=read(out/'image-id').decode().strip();report['image']=image;(out/'bootstrap.json').write_bytes(encode(report));actual=inspect(DOCKER+['image','inspect',image]);inspect_image(actual,image,own);need(own['tag'] in actual['RepoTags'],'exact owned normal image tag')
        exporter='rust199-rootfs-'+own['token'];need(not call(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+exporter+'$']).stdout.strip(),'fresh rootfs DATA exporter')
        report['exporter_intent']=exporter;(out/'bootstrap.json').write_bytes(encode(report))
        call(DOCKER+['create','--name',exporter,'--label',LABEL+'='+own['token'],'--label',LABEL+'.source='+own['source'],'--read-only','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--user=1001:1001','--entrypoint=/usr/bin/true',image])
        row=inspect(DOCKER+['container','inspect',exporter]);need(row['Image']==image and row['State']['Status']=='created' and row['Config']['Labels'][LABEL]==own['token'] and not row['Mounts'],'exact unstarted image DATA exporter')
        report['exporter_id']=row['Id'];(out/'bootstrap.json').write_bytes(encode(report));archive_rootfs=out/'rootfs.tar'
        # Supervised CLI writes a bounded file; the caller tick enforces disk reserves.
        previous_limit=resource.getrlimit(resource.RLIMIT_FSIZE);cap=min([16*1024**3]+[n for n in previous_limit if n!=resource.RLIM_INFINITY]);need(cap==16*1024**3,'inherited file limit cannot be relaxed for rootfs export')
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE,(cap,previous_limit[1]))
            call(DOCKER+['export','--output',str(archive_rootfs),exporter],timeout=min(600,phase_deadline-time.monotonic()))
        finally:resource.setrlimit(resource.RLIMIT_FSIZE,previous_limit)
        need(0<archive_rootfs.stat().st_size<=16*1024**3,'finite normal rootfs export')
        rootfs=out/'rootfs';report['extraction']=extract_rootfs(archive_rootfs,rootfs,min(phase_deadline,time.monotonic()+600),tick)
        need((rootfs/PREFIX).is_dir() and not (rootfs/PREFIX).is_symlink(),'normal installed LLVM prefix must be real')
        qualified_raw=read(rootfs/'builder-qualified.lock',1024**2);qualified=inventory(qualified_raw,inventory(read(Path(baseline['path']))));qualified_path=out/'qualified-inventory.lock';qualified_path.write_bytes(qualified_raw)
        dependency_observation=dependencies.observe(rootfs,root,dependency_policy,tick);dependencies.validate_observation(dependency_observation,root,dependency_policy,native=False)
        need(dependency_observation['inventory']==dict(bytes=len(qualified_raw),sha256=hashlib.sha256(qualified_raw).hexdigest()),'same exact actual qualified dependency inventory')
        report['build_dependencies']=dict(policy=dependencies.POLICY_PIN,audit=dict(bytes=len(encode(dependency_audit)),sha256=hashlib.sha256(encode(dependency_audit)).hexdigest()),observation=dependency_observation)
        report.update(status='PASS_NORMAL_SIGNED_LLVM_IMAGE_DATA',image=image,baseline_inventory=baseline,qualified_inventory=dict(path=str(qualified_path),bytes=len(qualified_raw),sha256=hashlib.sha256(qualified_raw).hexdigest(),count=len(qualified)),rootfs_root=str(rootfs),rootfs_tree_sha256=report['extraction']['rootfs_tree_sha256'],llvm_archive_sha256=sha(archive,tick),dockerfile_sha256=hashlib.sha256(dockerfile).hexdigest())
        report['provider_binding']=provider
    except BaseException as error:report['errors'].append(type(error).__name__+': '+str(error)[:1500]);raise
    finally:
        cleaning=True
        cleanup=[]
        if exporter:
            try:
                row=inspect(DOCKER+['container','inspect',exporter]);need(row['Id']==report.get('exporter_id') and row['Image']==image and row['Config']['Labels'].get(LABEL)==own['token'] and row['State']['Status']=='created','only exact unstarted rootfs exporter retirement');call(DOCKER+['container','rm',row['Id']]);need(not call(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+exporter+'$']).stdout.strip(),'rootfs exporter absence');cleanup.append('rootfs_exporter_absent')
            except BaseException as error:report['errors'].append('exporter retirement: '+str(error))
        try:
            call(['/usr/bin/gpgconf','--homedir',str(home),'--kill','gpg-agent'],timeout=30);need(not tuple(home.glob('S.gpg-agent*')),'owned TEST verification GPG sockets absent');cleanup.append('gpg_agent_absent')
        except BaseException as error:report['errors'].append('gpg retirement: '+str(error))
        report['cleanup']=cleanup;(out/'bootstrap.json').write_bytes(encode(report))
        if report['errors'] and report.get('status')=='PASS_NORMAL_SIGNED_LLVM_IMAGE_DATA':raise ValueError('normal image cleanup failed')
    def filepin(path):return dict(local_path=str(path),bytes=path.stat().st_size,sha256=sha(path,tick))
    files=dict(bootstrap_evidence=filepin(out/'bootstrap.json'),baseline_inventory=filepin(Path(report['baseline_inventory']['path'])),qualified_inventory=filepin(Path(report['qualified_inventory']['path'])),public_test_verification=filepin(out/'public-TEST-verification.json'))
    files['signed_build_dependencies']=filepin(out/'build-dependency-audit.json')
    for name in ('inputs.lock.json','acquisition.json','signatures.json','bootstrap.json','package-audit.json','input-data-preparation.json','fixed-eight-cache.json'):
        path=work/'bootstrap'/name
        if path.is_file():files['signed349_'+name]=filepin(path)
    return dict(report,evidence=str(out/'bootstrap.json'),files=files)


def retire(root,work,binding,boot,command):
    """Caller finally retires only this phase's exact images after export/qualification."""
    binding=provider_source(binding);own=owner(binding);errors=[];removed=[]
    if boot is None:
        path=Path(work)/'normal-image/bootstrap.json';boot=json.loads(read(path)) if path.exists() else {}
        for key,path in (('image',Path(work)/'normal-image/image-id'),('base_image',Path(work)/'bootstrap/image-id')):
            if not boot.get(key) and path.is_file():boot[key]=read(path).decode().strip()
    for key,tag in (('image',own['tag']),('base_image',own['base_tag'])):
        if not boot.get(key) and (boot.get('base_intent') or boot.get('normal_intent') or boot.get('image') or boot.get('base_image')):
            try:
                found=command(DOCKER+['image','ls','--no-trunc','--quiet','--filter','reference='+tag],timeout=30).stdout.decode().splitlines()
                identifiers=sorted(set(found));need(len(identifiers)<=1,'at most one exact owned image tag')
                if identifiers:
                    rows=json.loads(command(DOCKER+['image','inspect',identifiers[0]],timeout=30).stdout);need(len(rows)==1,'one recovery image');inspect_image(rows[0],identifiers[0],own);need(rows[0].get('RepoTags')==[tag],'only exact private image recovery tag');boot[key]=identifiers[0]
            except BaseException as error:errors.append(str(error))
    for directory in (Path(work)/'bootstrap/gpg',Path(work)/'normal-image/gpg'):
        if directory.is_dir():
            try:
                need(not any(p.is_symlink() for p in (directory,*directory.parents)) and directory.stat().st_uid==os.getuid(),'exact owned bootstrap GPG home')
                command(['/usr/bin/gpgconf','--homedir',str(directory),'--kill','gpg-agent'],timeout=30);need(not tuple(directory.glob('S.gpg-agent*')),'owned GPG agent socket absence')
            except BaseException as error:errors.append(str(error))
    for probe,image_key,exporter in (('llvm23-bootstrap-inventory-'+own['token'],'base_image',False),('rust199-rootfs-'+own['token'],'image',True)):
        try:
            present=command(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+probe+'$'],timeout=30).stdout.decode().splitlines()
            if present:
                need(present==[probe],'exact bootstrap container name');rows=json.loads(command(DOCKER+['container','inspect',probe],timeout=30).stdout);need(len(rows)==1,'one exact bootstrap container');row=rows[0]
                need(row['Image']==boot.get(image_key) and row['Config']['Labels'].get(LABEL)==own['token'] and row['Config']['Labels'].get(LABEL+'.source')==own['source'],'owned bootstrap container only')
                if exporter:need(not row['Mounts'] and (not boot.get('exporter_id') or row['Id']==boot['exporter_id']),'exact unmounted DATA exporter identity')
                live=row['State']['Status']not in ('created','exited')
                if live or (exporter and row['State']['Status']!='created'):errors.append('bootstrap container required abnormal retirement')
                command(DOCKER+['container','rm']+(['--force']if live else[])+[row['Id']],timeout=30)
            need(not command(DOCKER+['container','ls','--all','--format','{{.Names}}','--filter','name=^'+probe+'$'],timeout=30).stdout.strip(),'actual bootstrap container absence')
        except BaseException as error:errors.append(str(error))
    for image,tag in ((boot.get('image'),own['tag']),(boot.get('base_image'),own['base_tag'])):
        if not image:continue
        try:
            rows=json.loads(command(DOCKER+['image','inspect',image],timeout=30).stdout);need(len(rows)==1,'one owned image retirement');inspect_image(rows[0],image,own);need(rows[0].get('RepoTags')==[tag],'exact sole owned image tag retirement')
            command(DOCKER+['image','rm',image],timeout=60);missing=command(DOCKER+['image','inspect',image],timeout=30,check=False);need(missing.returncode==1 and missing.stderr.decode().strip()=='Error response from daemon: No such image: '+image,'actual image absence after retirement');removed.append(image)
        except BaseException as error:errors.append(str(error))
    try:
        remaining=command(DOCKER+['image','ls','--no-trunc','--quiet','--filter','label='+LABEL+'='+own['token'],'--filter','label='+LABEL+'.source='+own['source']],timeout=30).stdout.strip();need(not remaining,'actual labeled bootstrap image namespace empty')
    except BaseException as error:errors.append(str(error))
    report=dict(status='PASS_RETIRED' if not errors else 'FAIL_RETIREMENT',images=removed,errors=errors);(Path(work)/'image-retirement.json').write_bytes(encode(report));need(not errors,'owned bootstrap images not retired');return report

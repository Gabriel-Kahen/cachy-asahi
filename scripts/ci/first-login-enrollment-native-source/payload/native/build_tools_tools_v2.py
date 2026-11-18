# SPDX-License-Identifier: MIT
"""Finite FirstLogin/Enrollment pair policy and owned-runner adapters; no actors on import."""
import ast,base64,hashlib,importlib.util,io,json,os,re,shutil,stat,sys,tarfile,tempfile
from datetime import datetime,timedelta,timezone
from pathlib import Path
OPERATION='first-login-enrollment-alpm-v1'
PREFIX=Path('/opt/native-first-login-enrollment-alpm-v1')
SOURCE=PREFIX/'source'
STORE=PREFIX/'evidence'
MAX_FILE=16*1024**2
MAX_TOTAL=128*1024**2
MAX_NODES=100000
KINDS=('first-login','enrollment')
STAGES=('signing','dependency','first-login-a','first-login-b','first-login-compare','enrollment-a','enrollment-b','enrollment-compare','sign-candidates','install','commands','remove','reinstall','commands-reinstalled','remove-again','dependency-remove','restore','cleanup')

def need(value, message):
    if not value:
        raise ValueError(message)

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def data_pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def ordinary(path, maximum=2 * 1024**2):
    path = Path(path)
    need(not any(part.is_symlink() for part in (path, *path.parents)), 'ordinary nonaliased path required')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
             'bounded ordinary source required')
        pieces, size = [], 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - size))
            if not block:
                break
            pieces.append(block); size += len(block)
            need(size <= maximum, 'ordinary byte cap exceeded')
        after = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_gid')
        need(all(getattr(before, key) == getattr(after, key) for key in keys) and size == after.st_size,
             'ordinary file changed while reading')
        return b''.join(pieces)
    finally:
        os.close(fd)

def pin(path):
    return data_pin(ordinary(path, MAX_FILE))

def expected_installed(root):
    """Derive all349 version AND architecture rows from the genuine held inputs."""
    root = Path(root)
    original = json.loads(ordinary(root / 'bootstrap/scripts/ci/inputs.lock.json'))
    additions = json.loads(ordinary(root / 'native/input-profile.json'))['additions']['rows']
    versions = {}
    for row in original['rootfs_packages']:
        need(all(type(row[key]) is list and len(row[key]) == 1 for key in ('name', 'version', 'arch')),
             'exact rootfs package metadata')
        versions[row['name'][0]] = (row['version'][0], row['arch'][0])
    for row in original['packages'] + additions:
        versions[row['name']] = (row['version'], row['arch'])
    need(len(versions) == 349 and all(arch in ('any', 'aarch64') for _, arch in versions.values()),
         'complete genuine349 architecture metadata')
    lock = ordinary(root / 'native/expected349.lock')
    need(lock == ''.join(name + ' ' + version + '\n' for name, (version, _) in sorted(versions.items())).encode(),
         'derived full349 version/architecture inventory differs')
    return sorted(name + '-' + version + '-' + arch for name, (version, arch) in versions.items())

def load_workflow(root, policy):
    row = policy['original_workflow']
    path = Path(root) / row['path']; raw = ordinary(path)
    need(data_pin(raw) == {key: row[key] for key in ('bytes', 'sha256')}, 'genuine owned Commands source bytes')
    spec = importlib.util.spec_from_file_location('_build_tools_owned_workflow_v1', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module

def snapshot(root):
    """Bounded quiescent tree bytes/modes/ownership; never follow symlink nodes."""
    root = Path(root)
    need(not any(path.is_symlink() for path in root.parents), 'snapshot ancestry alias refused')
    if not os.path.lexists(root):
        return {}
    need(not root.is_symlink(), 'snapshot root alias refused')
    result, total, count = {}, 0, 0
    def visit(path, name, depth):
        nonlocal total, count
        count += 1
        need(count <= MAX_NODES and depth <= 64, 'snapshot node/depth budget exceeded')
        info = path.lstat()
        item = dict(mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)
        if stat.S_ISDIR(info.st_mode):
            item['kind'] = 'directory'; result[name] = item
            for child in sorted(path.iterdir()):
                visit(child, str(child.relative_to(root)), depth + 1)
        elif stat.S_ISREG(info.st_mode):
            raw = ordinary(path, min(MAX_FILE, MAX_TOTAL - total))
            total += len(raw); item.update(kind='file', **data_pin(raw)); result[name] = item
        elif stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            need(len(target.encode()) <= 4096, 'snapshot link byte cap')
            item.update(kind='symlink', target=target); result[name] = item
        else:
            raise ValueError('snapshot special file refused: ' + name)
    visit(root, '.', 0)
    return result

def snapshot_receipt(root):
    value = snapshot(root)
    return dict(files=len(value), **data_pin(encoded(value)))

def _metadata(raw):
    need(len(raw) <= 256 * 1024, 'metadata byte cap')
    rows = {}
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        need(' = ' in line, 'canonical makepkg metadata field')
        key, value = line.split(' = ', 1)
        need(re.fullmatch('[a-z][a-z0-9_]*', key) and len(value) <= 8192, 'bounded makepkg metadata field')
        rows.setdefault(key, []).append(value)
    return rows

def _own_tree(root, uid, gid):
    root = Path(root)
    for path in (root, *sorted(root.rglob('*'))):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'fixture aliases/special nodes refused')
        os.chown(path, uid, gid, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):path.chmod(0o700)


def source_policy(root):
    root=Path(root);policy=json.loads(ordinary(root/'native/build-tools-contract-v2.json'))
    need(policy['schema']==1 and policy['operation']==OPERATION and
         policy['actual']==dict(source=None,ref=None,run=None,job=None,artifact=None), 'new unbound pair contract')
    need(set(policy['recipes'])==set(KINDS) and policy['buildinfo_installed']==
         sorted(expected_installed(root)+['cachy-asahi-setup-0.3.0-1-any']), 'exact350 with real Setup8 dependency')
    base=ordinary(root/'native/expected349.lock')
    need(data_pin(base)==policy['baseline'] and len(base.splitlines())==349, 'exact held349 baseline')
    need(policy['dependency']['version']=='0.3.0-1' and policy['dependency']['archive_pin']==
         dict(bytes=33900,sha256='8de3bd0cf2d9333b41925fecdef5cbfe2ec6d40c3424d90746182142e0c7dc47'), 'accepted Setup8 exact archive')
    need(policy['recipes']['first-login']['version']=='0.1.0-2' and
         policy['recipes']['enrollment']['version']=='0.3.0-1', 'current exact package versions')
    need(len(policy['recipes']['first-login']['payload_files'])==6 and
         len(policy['recipes']['enrollment']['payload_files'])==15, 'finite6 and15 package payloads')
    need(not set(policy['recipes']['first-login']['payload_files']) &
         set(policy['recipes']['enrollment']['payload_files']), 'disjoint package ownership')
    config=ordinary(root/policy['makepkg_config']['path'])
    need(data_pin(config)=={key:policy['makepkg_config'][key] for key in ('bytes','sha256')} and
         b'check' in config and b'!check' not in config, 'unchanged checks-enabled makepkg configuration')
    return policy,base


def recipe_members(root,policy):
    raw=ordinary(Path(root)/policy['recipe_bundle']['path'],1024**2)
    need(data_pin(raw)==policy['recipe_bundle']['pin'], 'exact finite recipe/dependency carrier')
    result={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for member in archive:
            need(member.isfile() and not member.pax_headers and member.mode==0o644 and
                 member.uid==member.gid==member.mtime==0 and member.name not in result and
                 member.name==Path(member.name).as_posix() and '..' not in Path(member.name).parts and
                 not member.name.startswith('/') and member.size<=512*1024, 'ordinary finite recipe carrier')
            result[member.name]=archive.extractfile(member).read()
    wanted={'recipes/'+kind+'/'+name:row for kind,recipe in policy['recipes'].items()
            for name,row in recipe['source_files'].items()}
    wanted.update(policy['helpers'])
    wanted[policy['dependency']['carrier_member']]=dict(mode=420,**policy['dependency']['archive_pin'])
    need(set(result)==set(wanted), 'exact complete two recipes plus Setup8 carrier')
    for name,raw in result.items():
        need(dict(mode=420,**data_pin(raw))==wanted[name], 'source carrier body/mode pin')
    return result


def extract_recipes(root,destination,policy):
    members=recipe_members(root,policy);destination=Path(destination);destination.mkdir(mode=0o755)
    for kind in KINDS:
        for label in ('a','b'):
            target=destination/(kind+'-'+label);target.mkdir(mode=0o755)
            for name,row in policy['recipes'][kind]['source_files'].items():
                path=target/name;path.write_bytes(members['recipes/'+kind+'/'+name]);path.chmod(row['mode'])
    dependency=destination/policy['dependency']['archive']
    dependency.write_bytes(members[policy['dependency']['carrier_member']])
    need(pin(dependency)==policy['dependency']['archive_pin'],'exact authentic dependency staged')
    return dependency


def check_result(raw,kind,policy):
    need(type(raw) is bytes and 0<len(raw)<=1024**2 and raw.count(b'Starting check()')==1,
         'one actual makepkg check() per clean build')
    text=raw.decode();recipe=policy['recipes'][kind]
    need(not any(token in text for token in ('FAILED (','ERROR:','skipped=','expected failures=')),
         'package check failures/skips refused')
    if kind=='first-login':
        names=re.findall(r'^(test_[A-Za-z0-9_]+) \(__main__\.[A-Za-z]+Tests\.[A-Za-z0-9_]+\) \.\.\. ok$',text,re.M)
        need(sorted(names)==sorted(recipe['check_names']) and len(names)==len(set(names))==14 and
             re.findall(r'^Ran ([0-9]+) tests in [0-9.]+s$',text,re.M)==['11','3'] and
             text.splitlines().count('OK')==2, 'all actual FirstLogin11 plus delivery3 checks')
        return dict(status='PASS_ACTUAL_FIRST_LOGIN_CHECKS',tests=14,names=names)
    reports=[]
    for line in text.splitlines():
        if line.startswith('{'):
            try:reports.append(json.loads(line))
            except ValueError:pass
    need(len(reports)==1 and reports[0]==recipe['check_report'], 'actual full relocated signed/zstd/bwrap check report')
    return dict(status='PASS_ACTUAL_ENROLLMENT_PACKAGE_WORKFLOW',report=reports[0])


def archive_data(raw,recipe,installed):
    need(type(raw) is bytes and 0<len(raw)<=2*1024**2 and len(raw)%512==0, 'finite complete decoded package')
    expected=recipe['payload_files'];ancestors={str(p) for n in expected for p in Path(n).parents if str(p)!='.'}
    seen=set();directories=set();payload={};metadata={};cursor=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for member in archive:
            name=member.name.rstrip('/');need(name not in seen and member.offset==cursor and
                member.offset_data==cursor+512 and not member.pax_headers and member.uid==member.gid==0 and
                member.type in (tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE) and
                name==Path(name).as_posix() and '..' not in Path(name).parts,'canonical single-header package framing')
            seen.add(name);end=member.offset_data+member.size;padded=member.offset_data+((member.size+511)//512)*512
            need(0<=member.size<=1024**2 and padded<=len(raw) and not any(raw[end:padded]), 'bounded zero padding')
            cursor=padded
            if member.isdir():
                need(name in ancestors and member.mode==0o755 and member.size==0,'exact directory namespace/mode')
                directories.add(name);continue
            need(member.isfile(),'no links/special files/install hooks')
            body=raw[member.offset_data:end]
            if name in ('.PKGINFO','.BUILDINFO','.MTREE'):
                need(member.mode==0o644,'metadata mode');metadata[name]=body
            else:
                need(name in expected and dict(mode=member.mode,**data_pin(body))==expected[name], 'exact source-bound package payload')
                payload[name]=expected[name]
    need(not any(raw[cursor:]) and len(raw)-cursor>=1024 and directories==ancestors and
         set(payload)==set(expected) and set(metadata)=={'.PKGINFO','.BUILDINFO','.MTREE'}, 'complete payload/metadata/trailer')
    pkg,build=_metadata(metadata['.PKGINFO']),_metadata(metadata['.BUILDINFO'])
    for key,value in (('pkgname',recipe['name']),('pkgbase',recipe['name']),('pkgver',recipe['version']),('arch','any')):
        need(pkg.get(key)==[value],'exact PKGINFO '+key)
    for key,field in (('depend','depends'),('makedepend','makedepends'),('checkdepend','checkdepends'),('optdepend','optdepends')):
        need(pkg.get(key,[])==recipe[field],'exact PKGINFO dependencies '+key)
    need(pkg.get('license')==['MIT'],'original MIT package license')
    for key,value in (('format','2'),('pkgname',recipe['name']),('pkgbase',recipe['name']),
                      ('pkgver',recipe['version']),('pkgarch','any'),('pkgbuild_sha256sum',recipe['source_files']['PKGBUILD']['sha256'])):
        need(build.get(key)==[value],'exact BUILDINFO '+key)
    need(sorted(build.get('installed',[]))==installed and len(installed)==len(set(build['installed']))==350 and
         'check' in build.get('buildenv',[]) and '!check' not in build['buildenv'],'all350 exact dependency/check provenance')
    return dict(metadata=metadata,payload=payload)


def compare_archives(run,archives,kind,policy,map_hash):
    bodies={};decoded={};builds={};recipe=policy['recipes'][kind]
    for label in ('a','b'):
        path=archives[label]
        bodies[label]=run('compressed-'+kind+'-'+label,['/usr/bin/cat',str(path)])
        need(bodies[label]==ordinary(path,1024**2),'complete compressed archive custody joins actual file')
        raw=run('archive-'+kind+'-'+label,['/usr/bin/zstd','-dc',str(path)])
        decoded[label]=archive_data(raw,recipe,policy['buildinfo_installed'])
        builds[label]=dict(archive=data_pin(bodies[label]),metadata={n:data_pin(v) for n,v in decoded[label]['metadata'].items()},payload=decoded[label]['payload'])
    need(bodies['a']==bodies['b'] and decoded['a']==decoded['b'],'exact archive/payload/PKGINFO/BUILDINFO/MTREE pair equality')
    return dict(status='PASS_EXACT_NATIVE_BUILD_PAIR',kind=kind,archive=data_pin(bodies['a']),builds=builds,
                equality=dict(archive=True,payload=True,pkginfo=True,buildinfo=True,mtree=True),
                base_inventory_count=350,source_map_sha256=map_hash)


def inventory_expected(base,versions):
    rows=dict(line.split(' ',1) for line in base.decode().splitlines());rows.update(versions)
    return ''.join(name+' '+version+'\n' for name,version in sorted(rows.items())).encode()


def check_payload(recipe,run,pacman,label):
    expected=recipe['payload_files']
    listed=run(label+'-file-list',['/usr/bin/pacman',*pacman,'-Qlq',recipe['name']]).decode().splitlines()
    actual={name.lstrip('/') for name in listed if not name.endswith('/')}
    need(actual==set(expected),'exact ALPM owned file set')
    for index,(name,row) in enumerate(sorted(expected.items())):
        path=Path('/')/name;info=path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and
             stat.S_IMODE(info.st_mode)==row['mode'] and pin(path)=={k:row[k] for k in ('bytes','sha256')},'actual installed source bytes/mode/owner')
        owner=run(label+'-owner-'+str(index),['/usr/bin/pacman',*pacman,'-Qqo',str(path)]).decode().strip()
        need(owner==recipe['name'],'actual ALPM ownership')
    return dict(verified=True,files=expected)


def build_pair(run,source,recipes,kind,policy,alarm,report):
    recipe=policy['recipes'][kind];config=Path(source)/policy['makepkg_config']['path']
    slot=PREFIX/'build-current';seen=set();archives={}
    report['builds'][kind]={}
    for label in ('a','b'):
        path=Path(recipes)/(kind+'-'+label)
        need(not os.path.lexists(slot) and set(item.name for item in path.iterdir())==set(recipe['source_files']),
             'fresh exact independent recipe source and stable logical path')
        identity=path.stat();key=(identity.st_dev,identity.st_ino)
        need(key not in seen,'distinct clean recipe directory inodes');seen.add(key)
        for item in (path,*path.iterdir()):os.chown(item,alarm.pw_uid,alarm.pw_gid)
        item=dict(kind=kind,label=label,version=recipe['version'],build_step='build-'+kind+'-'+label,
                  logical=str(slot),directory=dict(device=key[0],inode=key[1]),check_invoked=False,
                  dependency_checking=True,initial_files=sorted(recipe['source_files']))
        report['builds'][kind][label]=item
        path.rename(slot);primary=None
        try:
            argv=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(slot),'PKGDEST='+str(slot),
                  'SRCDEST='+str(slot),'BUILDDIR='+str(slot),'SOURCE_DATE_EPOCH='+policy['build_pair']['source_date_epoch'],
                  'PACKAGER='+policy['build_pair']['packager'],'/usr/bin/makepkg','--cleanbuild','--nosign',
                  '--noconfirm','--config',str(config)]
            need('--nodeps' not in argv and '--nocheck' not in argv,'normal dependency checks and recipe checks')
            raw=run(item['build_step'],argv,cwd=slot)
            item['check']=check_result(raw,kind,policy);item['check_invoked']=True
            archive=slot/recipe['archive'];item['archive']=pin(archive);archives[label]=path/archive.name
            report['stages'].append(kind+'-'+label)
        except BaseException as error:
            primary=error
        finally:
            try:
                need(not os.path.lexists(path) and slot.is_dir() and not slot.is_symlink(),'owned source-tree retirement')
                slot.rename(path)
            except BaseException as later:
                item['source_retirement_failure']=type(later).__name__
                if primary is None:primary=later
        # Preserve the first validation/actor error after source retirement.
        # A retained archive or later cleanup success cannot swallow this error.
        if primary is not None:raise primary
    return archives


def load_module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value


def retire_private(run,work,homes):
    work=Path(work);failures=[];no_sockets=True;retired=[]
    need(work.parent==Path('/tmp') and work.name.startswith('build-tools-test-') and
         work==work.resolve() and work.is_dir() and not work.is_symlink() and work.stat().st_uid==os.getuid() and
         stat.S_IMODE(work.stat().st_mode)==0o700,'known private TEST root')
    identity=work.stat()
    need(type(homes) is list and len(homes)==len(set(homes))<=12 and len(homes)>=2,'bounded unique private GPG homes')
    for index,name in enumerate(homes):
        home=Path(name);okay=True
        try:
            need(home==home.resolve() and '..' not in home.parts and home.is_relative_to(work) and home!=work and
                 not any(p.is_symlink() for p in (home,*home.parents)),'owned private GPG home')
            if not home.exists():continue
            run('retire-private-'+str(index),['/usr/bin/gpgconf','--homedir',str(home),'--kill','all'])
            raw=run('no-agent-private-'+str(index),['/usr/bin/gpg-connect-agent','--homedir',str(home),'--no-autostart','/bye'])
            need(raw==b'gpg-connect-agent: no gpg-agent running in this session\n','exact no-agent diagnostic')
            need(not any(stat.S_ISSOCK(p.lstat().st_mode) for p in home.rglob('*')),'private GPG socket remains')
        except BaseException as error:
            okay=False;no_sockets=False;failures.append('home-'+str(index)+':'+type(error).__name__)
        if okay:retired.append(name)
    current=work.stat();need((current.st_dev,current.st_ino)==(identity.st_dev,identity.st_ino),'private cleanup identity')
    try:shutil.rmtree(work)
    except BaseException as error:failures.append('private-directory:'+type(error).__name__)
    return dict(homes_retired=not failures,no_sockets=no_sockets,private_directory_absent=not os.path.lexists(work),
                registered=len(homes),retired=len(retired),failures=failures)


def business(run,source,policy,work,alarm,report,signing,fingerprint,phase):
    members=recipe_members(source,policy)
    row=policy['first_login_journey'];helper=work/(phase+'-first-login-journey.py')
    raw=members[row['path']];need(data_pin(raw)=={key:row[key] for key in ('bytes','sha256')},'exact peer-owned journey source')
    helper.write_bytes(raw);helper.chmod(0o600)
    J=load_module(helper,'_first_login_'+phase)
    user=PREFIX/'user-data';user.mkdir(mode=0o755,exist_ok=True)
    moved=PREFIX/('moved-'+phase);moved.mkdir(mode=0o755)
    for recipe in policy['recipes'].values():
        for name,row in recipe['payload_files'].items():
            src=Path('/')/name;target=moved/name;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(ordinary(src));target.chmod(row['mode'])
    first={};enrollment={}
    for label,prefix in (('installed',Path('/')),('moved',moved)):
        home=user/(phase+'-'+label+'-home');home.mkdir(mode=0o700);os.chown(home,alarm.pw_uid,alarm.pw_gid)
        templates=user/(phase+'-'+label+'-templates');templates.mkdir(mode=0o755)
        template_pins={}
        for name,body in J.TEMPLATE_CONTENT.items():
            target=templates/name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
            target.write_bytes(body);target.chmod(0o644);template_pins[name]=data_pin(body)['sha256']
        if phase=='install':
            try:
                first[label]=J.run(dict(first_login=str(prefix/'usr/bin/cachy-asahi-first-login'),
                    setup='/usr/bin/cachy-asahi-setup',fish='/usr/bin/fish',zsh='/usr/bin/zsh',python3='/usr/bin/python3',
                    template_root=str(templates),template_sha256=template_pins,user='alarm'),home,run,
                    alarm.pw_uid,alarm.pw_gid,label=phase+'-'+label)
            except BaseException as error:
                if hasattr(error,'first_login_result'):
                    report.setdefault('business_partial',{})[phase+'-'+label]=error.first_login_result
                raise
        else:
            before_user=snapshot_receipt(home);step=phase+'-'+label+'-first-login-inspect'
            observed=json.loads(run(step,['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i',
                'PATH=/usr/bin:/bin','HOME='+str(home),'LC_ALL=C.UTF-8',str(prefix/'usr/bin/cachy-asahi-first-login'),
                'inspect','--home',str(home),'--template-root',str(templates)]))
            need(observed['operation']=='inspect' and snapshot_receipt(home)==before_user,'actual reinstall read-only inspection')
            first[label]=dict(status='PASS_REINSTALL_INSPECT_SMOKE_ONLY',ordered_steps=[step],home_unchanged=True,
                              shell_journey='NOT_REPEATED',path_pin=pin(prefix/'usr/bin/cachy-asahi-first-login'))
        cli=prefix/'usr/bin/cachy-asahi-repository-enrollment'
        for index,args in enumerate((['--help'],['--version'],['configure','--help'],['rotate','--help'],['transition','--help'],['revoke','--help'])):
            body=run(phase+'-'+label+'-enrollment-help-'+str(index),[str(cli),*args])
            need(body and (args!=['--version'] or body.strip()==b'cachy-asahi-repository-enrollment 0.3.0'),'actual installed/moved dispatch/version')
        enrollment[label]=dict(cli=str(cli),sha256=pin(cli)['sha256'],help_commands=6)
    if phase=='reinstall':
        return dict(status='PASS_REINSTALLED_AND_MOVED_CLI_SMOKE_ONLY',first_login=first,enrollment=enrollment,
                    scope='EXPLICIT_REINSTALL_SMOKE_FULL_SHELL_AND_SIGNED_TRUST_JOURNEYS_NOT_REPEATED')
    # Construct finite real signed release DATA with the exact installed verifier.
    # Its process entry is replaced by the held Commands callback: no second
    # supervisor, subprocess actor or wait owner is introduced here.
    bootstrap=work/(phase+'-verifier');shutil.copytree(Path('/usr/lib/cachy-asahi/repository-enrollment'),bootstrap)
    fixture_path=bootstrap/'scripts/release/test_release.py'
    fixture_path.write_bytes(members['recipes/enrollment/test_release.py'])
    F=load_module(fixture_path,'_enrollment_fixture_'+phase)
    counter=0
    def owned(argv,env=None):
        nonlocal counter
        args=list(map(str,argv));executable=Path(args[0]).name
        need(executable in ('gpg','gpgconf','repo-add','bsdtar','vercmp'),'finite fixture command tool')
        args[0]='/usr/bin/'+executable
        if env is not None:
            home=Path(env['GNUPGHOME']);need(home.is_relative_to(work),'private fixture keyring only')
            args=['/usr/bin/env','GNUPGHOME='+str(home),'HOME='+str(work),'LC_ALL=C',*args]
        step=phase+'-fixture-'+str(counter);counter+=1
        return run(step,args)
    F.r.run=owned
    real_temp=tempfile.TemporaryDirectory
    class PrivateTemp:
        @staticmethod
        def TemporaryDirectory(prefix):return real_temp(prefix=prefix,dir=work)
    F.tempfile=PrivateTemp
    case=F.ReleaseTests('test_source_delivery_assembles_stages_and_verifies_retained_materials')
    case.home=signing;case.key=fingerprint
    case.setUp();case.source_delivery_fixture();case.release_spec['repo_name']='cachy-asahi'
    case.release_spec['release_id']='fixture-before';case.stage();before=case.directory
    next_home=work/('next-'+phase);next_home.mkdir(mode=0o700);report['temporary_homes'].append(str(next_home))
    ngpg=['/usr/bin/gpg','--batch','--no-options','--homedir',str(next_home),'--pinentry-mode','loopback','--passphrase','']
    run(phase+'-fixture-next-key',ngpg+['--quick-generate-key','TEST ONLY transition <transition@test.invalid>','ed25519','sign','1d'])
    listing=run(phase+'-fixture-next-fingerprint',ngpg+['--with-colons','--list-keys']).decode()
    next_key=next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
    need(re.fullmatch('[A-F0-9]{40}',next_key) and next_key!=fingerprint,'separate TEST transition primary')
    case.key=next_key;case.env=dict(GNUPGHOME=str(next_home))
    case.release_spec['release_id']='fixture-after';case.stage();after=case.directory
    old_public=work/(phase+'-old-public.asc');new_public=work/(phase+'-new-public.asc')
    old_public.write_bytes(run(phase+'-fixture-old-public',['/usr/bin/gpg','--batch','--no-options','--homedir',str(signing),'--armor','--export',fingerprint]))
    new_public.write_bytes(run(phase+'-fixture-new-public',ngpg+['--armor','--export',next_key]))
    transition=bootstrap/'scripts/release/signing_transition.py'
    stamp=lambda value:value.replace(microsecond=0).isoformat().replace('+00:00','Z')
    now=datetime.now(timezone.utc);bundle=work/(phase+'-transition')
    result=json.loads(run(phase+'-create-transition',['/usr/bin/python3','-I','-B',str(transition),'create',
        '--before',str(before),'--after',str(after),'--old-key',fingerprint,'--new-key',next_key,
        '--old-certificate',str(old_public),'--new-certificate',str(new_public),
        '--old-gpg-home',str(signing),'--new-gpg-home',str(next_home),'--not-before',stamp(now-timedelta(minutes=1)),
        '--not-after',stamp(now+timedelta(hours=1)),'--as-of',stamp(now),'--output',str(bundle)]))
    need(result['status']=='VERIFIED_FINITE_PLANNED_KEY_TRANSITION_ONLY','actual dual-signed fixture creation')
    revoked_home=work/('revoked-'+phase);revoked_home.mkdir(mode=0o700)
    report['temporary_homes'].append(str(revoked_home))
    rgpg=['/usr/bin/gpg','--batch','--no-options','--no-autostart','--homedir',str(revoked_home)]
    run(phase+'-revocation-import-public',rgpg+['--import',str(new_public)])
    revocation=(next_home/'openpgp-revocs.d'/(next_key+'.rev')).read_text()
    marker=':-----BEGIN PGP PUBLIC KEY BLOCK-----';need(marker in revocation,'generated TEST primary revocation certificate')
    detached=work/(phase+'-TEST-revocation.asc');detached.write_text(revocation[revocation.index(marker):].replace(marker,marker[1:],1))
    run(phase+'-revocation-import-packet',rgpg+['--import',str(detached)])
    revoked=work/(phase+'-revoked-public.asc')
    revoked.write_bytes(run(phase+'-revocation-export-public',rgpg+['--armor','--export',next_key]))
    for label,prefix in (('installed',Path('/')),('moved',moved)):
        target=work/(phase+'-'+label+'-target');ring=target/'etc/pacman.d/gnupg'
        ring.parent.mkdir(parents=True)
        # Only newly generated TEST key material is copied, never a host keyring.
        shutil.copytree(signing,ring,ignore=shutil.ignore_patterns('S.*','*.lock'))
        report['temporary_homes'].append(str(ring))
        (target/'var/lib/pacman').mkdir(parents=True)
        cli=prefix/'usr/bin/cachy-asahi-repository-enrollment'
        (target/'etc/pacman.conf').write_bytes(b'[options]\nArchitecture = auto\n')
        original=target/'etc/pacman.d/original-public.asc';original.write_bytes(old_public.read_bytes());original.chmod(0o600)
        url='https://repo.example.invalid/generations/'+'a'*64+'/release/repo'
        configure=[str(cli),'configure','--root',str(target),'enroll','--snapshot-url',url,'--public-key',str(original),'--fingerprint',fingerprint]
        def stop_agent(operation):
            run(phase+'-'+label+'-'+operation+'-retire-agent',['/usr/bin/gpgconf','--homedir',str(ring),'--kill','all'])
            observed=run(phase+'-'+label+'-'+operation+'-no-agent',['/usr/bin/gpg-connect-agent','--homedir',str(ring),'--no-autostart','/bye'])
            need(observed==b'gpg-connect-agent: no gpg-agent running in this session\n','fixture agent naturally retired before state observation')
        preview=json.loads(run(phase+'-'+label+'-configure-preview',configure))
        need(preview['status']=='preview' and not preview['keyring_may_have_changed'],'actual configuration preview')
        # Enrollment apply is an explicit disposable-root operation, not system trust.
        enabled=json.loads(run(phase+'-'+label+'-configure-apply',[*configure,'--apply']))
        need(enabled['status']=='enabled','actual private root enrollment')
        stop_agent('configure')
        command=[str(cli),'transition','--root',str(target),'--bundle',str(bundle),'--before',str(before),'--after',str(after),
                 '--expected-current-fingerprint',fingerprint,'--fingerprint',next_key]
        frozen=snapshot_receipt(target)
        preview=json.loads(run(phase+'-'+label+'-transition-preview',command))
        need(preview['status']=='preview' and snapshot_receipt(target)==frozen,'actual signed transition preview preserves root')
        applied=json.loads(run(phase+'-'+label+'-transition-apply',[*command,'--apply']))
        need(applied['status']=='rotated' and applied['snapshot_url']==url and applied['snapshot_url_retained'] is True and
             applied['old_trust_retained'] is True and applied['snapshot_upgrade_accepted'] is False,'actual private-root transition applies without snapshot upgrade')
        stop_agent('transition')
        stale=json.loads(run(phase+'-'+label+'-transition-stale',[*command,'--apply'],expected=1))
        need(stale['status']=='failed' and stale['keyring_may_have_changed'] is False,'stale current selection refused')
        current=target/'etc/pacman.d/current-new-public.asc';current.write_bytes(new_public.read_bytes());current.chmod(0o600)
        updated=target/'etc/pacman.d/revoked-new-public.asc';updated.write_bytes(revoked.read_bytes());updated.chmod(0o600)
        revoke=[str(cli),'revoke','--root',str(target),'--expected-current-fingerprint',next_key,
                '--expected-current-certificate-sha256',pin(current)['sha256'],
                '--current-public-key',str(current),'--revoked-public-key',str(updated)]
        frozen=snapshot_receipt(target)
        preview=json.loads(run(phase+'-'+label+'-revoke-preview',revoke))
        need(preview['status']=='preview' and preview['verified_primary_revocations']==1 and
             preview['repository_enabled'] is True and snapshot_receipt(target)==frozen,'actual revocation preview preserves private root')
        quarantined=json.loads(run(phase+'-'+label+'-revoke-apply',[*revoke,'--apply']))
        need(quarantined['status']=='quarantined-revoked' and quarantined['repository_enabled'] is False and
             quarantined['revocation_confirmed'] is True and quarantined['quarantine_record_preserved'] is True and
             quarantined['keys_removed'] is False,'actual private-root primary revocation and quarantine')
        stop_agent('revoke')
        enrollment[label].update(configure='PASS_PRIVATE_TEST_ROOT',transition='PASS_REAL_DUAL_SIGNED_PRIVATE_ROOT',
            old_primary=fingerprint,new_primary=next_key,transition_sha256=result['transition_sha256'],snapshot_url=url,
            preview_preserved=True,stale_current_refused=True,revocation='PASS_REAL_PRIMARY_QUARANTINE',
            revocation_preview_preserved=True,repository_disabled=True,target_state=snapshot_receipt(target))
    # Case temporary data live below the owned work root and retire with it.
    report.setdefault('fixture_roots',[]).append(str(case.base))
    return dict(status='PASS_INSTALLED_AND_MOVED_FINITE_CLI_JOURNEYS',first_login=first,enrollment=enrollment,
                scope='NEW_PRIVATE_USER_ROOTS_AND_REAL_TEST_TRUST_ONLY_NO_SUPPORTED_MACHINE_ACCEPTANCE')

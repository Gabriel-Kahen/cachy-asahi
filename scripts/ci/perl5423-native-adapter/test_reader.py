#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Synthetic passive DATA controls; no real Reader, namespace or native actor."""
import copy
import gzip
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
MODELED_BASE_CONFIG = b"# MODELED inert makepkg configuration DATA\nPKGEXT='.pkg.tar.xz'\n"
spec = importlib.util.spec_from_file_location('perl_arm_passive_reader_tests', HERE/'reader.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def no_actors(event, args):
    if event in ('subprocess.Popen', 'os.system', 'os.exec', 'os.fork', 'os.posix_spawn',
                 'socket.connect', 'socket.bind', 'ctypes.dlopen'):
        raise AssertionError('actor forbidden in passive DATA controls: ' + event)


sys.addaudithook(no_actors)


def elf(*, soname=None, needed=(), interpreter=None):
    """Inert synthetic ELF structure, containing no executable machine code."""
    raw = bytearray(2048)
    raw[:16] = b'\x7fELF\x02\x01\x01'+bytes(9)
    strings = bytearray(b'\0')
    tags = []
    for tag, value in [(1, value) for value in needed]+[(14, soname)]:
        if value is not None:
            tags.append((tag, len(strings)))
            strings.extend(value.encode()+b'\0')
    tags += [(5, 1024), (10, len(strings)), (0, 0)]
    table = b''.join(struct.pack('<qQ', *row) for row in tags)
    headers = []
    if interpreter:
        text = interpreter.encode()+b'\0'
        raw[320:320+len(text)] = text
        headers.append((3, 4, 320, 320, 0, len(text), len(text), 1))
    headers += [(1, 5, 0, 0, 0, len(raw), len(raw), 16384),
                (2, 4, 512, 512, 0, len(table), len(table), 8)]
    struct.pack_into('<HHIQQQIHHHHHH', raw, 16, 3, 183, 1, 128, 64, 0, 0,
                     64, 56, len(headers), 0, 0, 0)
    for index, row in enumerate(headers):
        struct.pack_into('<IIQQQQQQ', raw, 64+56*index, *row)
    raw[512:512+len(table)] = table
    raw[1024:1024+len(strings)] = strings
    return bytes(raw)


def package(*, change=None):
    """Modeled archive bytes; never source-built payload or native evidence."""
    files = {'.PKGINFO': b'pkgname = perl\npkgver = 5.42.3-1.3\narch = aarch64\n',
             '.BUILDINFO': b'pkgbuild_sha256sum = '+b'1'*64+b'\n',
             '.MTREE': gzip.compress(b'#mtree\n# MODELED DATA ONLY\n', mtime=r.EPOCH),
             'usr/bin/perl': elf(needed=('libperl.so', 'libcrypt.so.2'), interpreter='/lib/ld-linux-aarch64.so.1'),
             'usr/lib/perl5/5.42/core_perl/CORE/libperl.so': elf(soname='libperl.so', needed=('libcrypt.so.2',)),
             'usr/lib/perl5/5.42/core_perl/Config.pm': b'# MODELED Config DATA\n',
             'usr/share/perl5/core_perl/strict.pm': b'# MODELED strict DATA\n',
             'usr/lib/perl5/5.42/core_perl/Config_heavy.pl': ("cf_time='"+r.CF_TIME+"'\n").encode(),
             'usr/share/perl5/core_perl/pod/perldiag.pod': b'MODELED diagnostic DATA\n'}
    for name in r.COMMANDS:
        files['usr/bin/core_perl/'+name] = b'#!/usr/bin/perl\n# MODELED script DATA\n'
    for name in r.XS:
        files['usr/lib/perl5/5.42/core_perl/auto/'+name] = elf()
    links = {'usr/bin/'+name: 'core_perl/'+name for name in r.COMMANDS}
    if change:
        change(files, links)
    directories = {str(p) for name in set(files)|set(links) for p in Path(name).parents if p != Path('.')}
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(directories):
            item = tarfile.TarInfo(name)
            item.type = tarfile.DIRTYPE
            item.mode = 0o755
            item.mtime = r.EPOCH
            archive.addfile(item)
        for name, body in sorted(files.items()):
            item = tarfile.TarInfo(name)
            item.size = len(body)
            item.mode = 0o755 if name.startswith('usr/bin/') else 0o644
            item.mtime = r.EPOCH
            archive.addfile(item, io.BytesIO(body))
        for name, target in sorted(links.items()):
            item = tarfile.TarInfo(name)
            item.type = tarfile.SYMTYPE
            item.linkname = target
            item.mode = 0o777
            item.mtime = r.EPOCH
            archive.addfile(item)
    return gzip.compress(output.getvalue(), mtime=r.EPOCH)


def provider_fixture():
    binary = elf(soname='libcrypt.so.2', needed=('libc.so.6',))
    data = dict(path='/usr/lib/libcrypt.so.2.0.0', soname='libcrypt.so.2', owner='libxcrypt',
                version='4.5.2-1', symlinks=[dict(path='/usr/lib/libcrypt.so', target='libcrypt.so.2.0.0'),
                                           dict(path='/usr/lib/libcrypt.so.2',target='libcrypt.so.2.0.0')],
                readelf_argv=['/usr/bin/readelf', '--wide', '-h', '-d', '/usr/lib/libcrypt.so.2.0.0'])
    desc = b'%NAME%\nlibxcrypt\n\n%VERSION%\n4.5.2-1\n\n%PROVIDES%\nlibcrypt.so=2-64\n'
    files = b'%FILES%\nusr/\nusr/lib/\nusr/lib/libcrypt.so\nusr/lib/libcrypt.so.2\nusr/lib/libcrypt.so.2.0.0\n'
    text = b'''ELF Header:
  Class:                             ELF64
  Data:                              2's complement, little endian
  Machine:                           AArch64
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
 0x000000000000000e (SONAME)             Library soname: [libcrypt.so.2]
'''
    return data, desc, files, b'libxcrypt\n', binary, text


def natural(code=0):
    return dict(pid=100,exit=code,natural_exit=True,forced_cleanup=False,
                retirement='REAPED',group_absent=True,leader_held_until_group_inspection=True,
                ownership_lost=False,exit_observed_via_waitpid=True,elapsed_seconds=.1)


def operands():
    """Invented identities and namespace links, never operational qualification."""
    c = json.loads((HERE/'contract.json').read_bytes())
    a = dict(schema=1,operation=c['operation'],approval='1'*64,
             source=dict(sha='2'*40,ref='codex/MODELED-NEVER-ADMITTED'),
             source_map_sha256='3'*64,run='123',job='456',image='sha256:'+'4'*64,
             domain_sha256=c['domain_sha256'],expected349_sha256=c['expected349_sha256'],
             input_signature_audit_sha256='5'*64)
    before = dict(uid=1001,gid=1001,namespaces={name:name+':['+str(index)+']' for index,name in enumerate(('user','mnt','net','pid'),1)},
                  uid_map=[[0,0,4294967295]],gid_map=[[0,0,4294967295]])
    cases = {}
    for kind in ('bwrap-user-mount-net','unshare-mapped-root'):
        after = copy.deepcopy(before)
        for name in (('user','mnt','net') if kind.startswith('bwrap') else ('user',)):
            after['namespaces'][name]=name+':[100]'
        if kind.startswith('unshare'):
            after.update(uid=0,gid=0,uid_map=[[0,1001,1]],gid_map=[[0,1001,1]])
        cases[kind]=dict(exit_code=0,outcome='SUPPORTED',before=copy.deepcopy(before),after=after,retirement=natural())
    q = dict(schema=1,status='PASS_NAMESPACE_EFFECTS',source='6'*40,run=a['run'],job=a['job'],
             image=a['image'],domain_sha256=c['domain_sha256'],reader_sha256='7'*64,cases=cases)
    a['qualification_sha256']=r.pin(r.encoded(q))['sha256']
    return c,a,q


def actor_fixture(item,c,a,inputs):
    return dict(Id='a'*64,Name='/'+item['name'],Image=a['image'],Path='/usr/bin/bash',
        Args=['--noprofile','--norc','/inputs/entry.sh'],State=dict(Running=False,Status='created'),
        Config=dict(User='1001:1001',Hostname='perl5423-native',Volumes=None,
                    Entrypoint=['/usr/bin/bash'],Cmd=['--noprofile','--norc','/inputs/entry.sh'],
                    Env=['PATH=/usr/bin','ADAPTER_ADMISSION_SHA256='+r.pin(r.encoded(a))['sha256']]),
        HostConfig=dict(NanoCpus=2000000000,Memory=4294967296,MemorySwap=4294967296,PidsLimit=256,
            ReadonlyRootfs=True,Init=True,NetworkMode='none',Privileged=False,CapDrop=['ALL'],CapAdd=None,
            SecurityOpt=['no-new-privileges'],Devices=[],DeviceRequests=None,Binds=None,PidMode='',IpcMode='private',
            UTSMode='',Tmpfs=c['domain']['tmpfs']),
        Mounts=[dict(Destination='/inputs',Type='bind',RW=False,Source=inputs),
                dict(Destination='/work',Type='volume',RW=True,Name=item['volume'])])


def capacity_fixture(root,*,shared=False):
    records=[]
    for phase,work,exports,inputs in [('before-input-snapshot',True,2,True),
                ('before-volume-1',True,2,False),('before-actor-1',True,2,False),('before-export-1',False,2,False),
                ('before-volume-2',True,1,False),('before-actor-2',True,1,False),('before-export-2',False,1,False)]:
        demands=[('/MODELED/docker',2048*r.MIB if work else 0),(str(root),(64*r.MIB if inputs else 0)+exports*512*r.MIB)]
        groups={}
        for index,(path,demand) in enumerate(demands):
            row=groups.setdefault(str(10 if shared else 10+index),dict(paths=[],required_bytes=1024*r.MIB,
                    available_bytes=12*1024*r.MIB,available_inodes=200000,total_inodes=1000000))
            row['paths'].append(path);row['required_bytes']+=demand
        records.append(dict(phase=phase,filesystems=groups,MemAvailable_bytes=8*1024*r.MIB,status='PASS'))
    return records


def reserve_fixture(capacity):
    return dict(samples=800,minimum_bytes={device:1024*r.MIB for device in capacity[0]['filesystems']},
                minimum_MemAvailable_bytes=4096*r.MIB)


def export_fixture(files,*,pax=False,extra=None):
    """Plain inert Docker-copy-shaped DATA; no filesystem extraction."""
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w',format=tarfile.PAX_FORMAT if pax else tarfile.USTAR_FORMAT) as stream:
        directory=tarfile.TarInfo('output');directory.type=tarfile.DIRTYPE;directory.mode=0o700
        stream.addfile(directory)
        for name,body in files.items():
            item=tarfile.TarInfo('output/'+name);item.mode=0o644;item.size=len(body)
            if pax:item.mtime=123.25
            stream.addfile(item,io.BytesIO(body))
        if extra:stream.addfile(extra)
    return output.getvalue()


def operation_fixture(root):
    """Modeled complete Docker transcript DATA, never Docker commands."""
    c,a,q = operands();files = {}
    token = 'perl-native-123-abcdef012345'
    items = [dict(name=token+'-'+str(i),init=token+'-init-'+str(i),volume=token+'-work-'+str(i),
                  admission_sha256=r.pin(r.encoded(a))['sha256']) for i in (1,2)]
    report = dict(schema=1,status='PASS_NATIVE_PAIR',native_acceptance=False,
                  admission_sha256=r.pin(r.encoded(a))['sha256'],qualification_sha256=a['qualification_sha256'],
                  domain_sha256=c['domain_sha256'],source_map_sha256=a['source_map_sha256'],inputs=str(root/'inputs'),
                  planned=copy.deepcopy(items),operations=[],builds=[],retired=[],cleanup=[],owned_resources_absence_verified=True,
                  capacity=capacity_fixture(root))
    report['active_reserve']=reserve_fixture(report['capacity'])
    def emit(argv,raw=b'',code=0):
        log='logs/'+str(len(report['operations'])).zfill(3)+'.log';files[log]=raw
        report['operations'].append(dict(argv=argv,log=log,returncode=code,lifecycle=natural(code),success=True))
        return log
    image = r.encoded([dict(Id=a['image'],Architecture='arm64',Os='linux',Config=dict(Volumes=None))]);files['image.json']=image
    emit(r.DOCKER+['image','inspect',a['image']],image)
    emit(r.DOCKER+['info','--format','{{.Architecture}}'],b'aarch64\n')
    emit(r.DOCKER+['info','--format','{{.DockerRootDir}}'],b'/MODELED/docker\n')
    for kind,args in [('container',r.CONTAINERS),('volume',r.VOLUMES)]:
        report['initial_'+kind+'_log']=emit(r.DOCKER+args)
    files.update({'initial-containers.txt':b'','initial-volumes.txt':b''})
    for index,item in enumerate(items,1):
        emit(r.DOCKER+['volume','create',item['volume']],(item['volume']+'\n').encode())
        emit(r.DOCKER+['create','--name',item['init'],'--cpus=2','--memory=4g','--memory-swap=4g',
            '--pids-limit=256','--network=none','--read-only','--user=0:0','--cap-drop=ALL','--cap-add=CHOWN',
            '--security-opt=no-new-privileges','--mount','type=volume,src='+item['volume']+',dst=/work',
            '--entrypoint=/usr/bin/chown',a['image'],'1001:1001','/work'],b'b'*64+b'\n')
        emit(r.DOCKER+['start','--attach',item['init']])
        emit(r.create_argv(item,a,report['inputs'],c),b'a'*64+b'\n')
        actual=actor_fixture(item,c,a,report['inputs']);files['actor-'+str(index)+'.json']=r.encoded(actual)
        log=emit(r.DOCKER+['inspect',item['name']],r.encoded([actual]))
        report['builds'].append(dict(**item,inspect_log=log,archive=r.pin(b'MODELED identical archive DATA')))
        emit(r.DOCKER+['start','--attach',item['name']])
        exported={r.ARCHIVE:b'MODELED identical archive DATA','makepkg-base.conf':MODELED_BASE_CONFIG,
                  'makepkg-effective.conf':MODELED_BASE_CONFIG+r.MAKEPKG_SUFFIX.encode()}
        files.update({'build-'+str(index)+'/'+name:body for name,body in exported.items()})
        raw_export=export_fixture(exported);captured='export-'+str(index)+'.tar';files[captured]=raw_export
        emit(r.DOCKER+['cp',item['name']+':/work/output','-'])
        report['operations'][-1].update(stdout=captured,stdout_pin=r.pin(raw_export),
                                       fsize=dict(before=[-1,-1],inherited_soft=256*r.MIB,after=[-1,-1]))
        for name in (item['name'],item['init']):emit(r.DOCKER+['rm',name],(name+'\n').encode())
        emit(r.DOCKER+['volume','rm',item['volume']],(item['volume']+'\n').encode())
        cl=emit(r.DOCKER+r.CONTAINERS);vl=emit(r.DOCKER+r.VOLUMES)
        report['retired'].append(dict(name=item['name'],init=item['init'],volume=item['volume'],container_list_log=cl,volume_list_log=vl))
    for item in reversed(items):
        for argv in (r.DOCKER+['rm','-f',item['name']],r.DOCKER+['rm','-f',item['init']],r.DOCKER+['volume','rm',item['volume']]):
            error = ('Error response from daemon: '+('No such container: '+argv[-1] if argv[2]=='rm' else 'get '+argv[-1]+': no such volume')+'\n').encode()
            log=emit(argv,error,1);report['cleanup'].append(dict(argv=argv,log=log,returncode=1))
    emit(r.DOCKER+r.CONTAINERS);emit(r.DOCKER+r.VOLUMES)
    files.update({'final-containers.txt':b'','final-volumes.txt':b''})
    def get(name,cap,*,empty=False):
        raw=files[name]
        if not (0 if empty else 1)<=len(raw)<=cap:raise ValueError('fixture byte bound')
        return raw
    return c,a,q,report,files,get


def build_fixture():
    """Synthetic package/evidence with pinned passive recipe notice DATA."""
    c,a,q=operands();metadata=c['recipe_metadata'];root=HERE.parents[2]
    lock=(root/'scripts/ci/perl5423-repro-native-source/references/expected349.lock').read_bytes()
    info={'pkgname':['perl'],'pkgbase':['perl'],'pkgver':[c['version']],'arch':['aarch64'],'builddate':[str(r.EPOCH)]}
    for key,values in [('depend',['libcrypt.so=2-64' if name=='libcrypt.so' else name for name in metadata['depends']]),
                       ('makedepend',metadata['makedepends']),('checkdepend',metadata['checkdepends']),
                       ('optdepend',metadata['optdepends']),('license',metadata['license']),('provides',metadata['provides'])]:
        info[key]=values
    build=dict(pkgbuild_sha256sum=[c['recipe_sha256']],pkgarch=['aarch64'],pkgver=[c['version']],builddate=[str(r.EPOCH)],
               installed=[line.replace(' ','-',1)+'-aarch64' for line in lock.decode().splitlines()])
    encode_fields=lambda fields:''.join(key+' = '+value+'\n' for key,values in fields.items() for value in values).encode()
    pkginfo,buildinfo=encode_fields(info),encode_fields(build)
    def change(files,links):
        files.update({'.PKGINFO':pkginfo,'.BUILDINFO':buildinfo})
        for installed,source in [('README','UPSTREAM-README'),('Artistic','UPSTREAM-Artistic'),('Copying','UPSTREAM-Copying'),('LICENSE.packaging','LICENSE.packaging')]:
            files['usr/share/licenses/perl/'+installed]=(root/'packages/port/perl5423-repro-candidate'/source).read_bytes()
        for extension,needed in [('Compress/Raw/Zlib/Zlib.so','libz.so.1'),('Compress/Raw/Bzip2/Bzip2.so','libbz2.so.1.0')]:
            files['usr/lib/perl5/5.42/core_perl/auto/'+extension]=elf(needed=[needed])
    data={r.ARCHIVE:package(change=change),'makepkg-exit.txt':b'0\n','packages.txt':lock,'PKGINFO':pkginfo,'BUILDINFO':buildinfo,
          'recipe-input-map.json':r.encoded({name:dict(type='file',**row) for name,row in c['recipe_files'].items()}),
          'source-input.json':r.encoded(dict(source=dict(bytes=c['source_bytes'],sha256=c['source_sha256']),
              packet_map_sha256=c['packet_map_sha256'],expected349_sha256=c['expected349_sha256'],adapter_source_map_sha256=a['source_map_sha256'],recipe_sha256=c['recipe_sha256'])),
          'environment.json':r.encoded(dict(uid=1001,gid=1001,uname=['Linux','MODELED','MODELED','MODELED','aarch64'],page_bytes=4096,makepkg_exit=0,
              makepkg_configuration=MODELED_BASE_CONFIG.decode(),
              cgroup={'cpu.max':'200000 100000','memory.max':'4294967296','memory.swap.max':'0','pids.max':'256'},
              status='CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nNoNewPrivs:\t1\n',
              environment=dict(PATH='/usr/bin',HOME='/work/home',TMPDIR='/work/tmp',CACHY_ASAHI_PERL_BUILD='1',SOURCE_DATE_EPOCH=str(r.EPOCH),LC_ALL='C',TZ='UTC',MAKEFLAGS='-j2',PKGDEST='/work/output'))),
          'makepkg-base.conf':MODELED_BASE_CONFIG,'makepkg-effective.conf':MODELED_BASE_CONFIG+c['makepkg_config_suffix'].encode(),
          'source-config.over':("cf_time='"+r.CF_TIME+"'\n").encode(),'source-config.sh':("cf_time='"+r.CF_TIME+"'\n").encode(),
          'staged-cf-time.txt':(r.CF_TIME+'\n').encode(),
          'staged-smoke.json':r.encoded(dict(version='v5.42.3',config='/work/recipe/pkg/perl/usr/lib/perl5/5.42/core_perl/Config.pm',
              shared_objects=['/work/recipe/pkg/perl/usr/lib/perl5/5.42/core_perl/auto/'+name for name in sorted(r.XS)])),
          'makepkg.log':b'Starting check()\nAll tests successful.\nStarting package()\n',
          'perl-5.42.3-1.3-aarch64-check.log':b'[libz.so.1]\n[libbz2.so.1.0]\nAll tests successful.\nFiles=2920, Tests=1351000, 400 wallclock secs (MODELED CPU DATA)\nResult: PASS\nPASS selected shared threaded Perl5.42.3 paths,113 core providers and five C extensions\n'}
    pf=provider_fixture()
    for name,body in zip(('provider.json','provider-desc.txt','provider-files.txt','provider-owner.txt','provider-elf.bin','provider-readelf.txt'),pf):
        data[name]=r.encoded(body) if name.endswith('.json') else body
    stage='/work/recipe/pkg/perl';includes=['-I'+stage+'/usr/lib/perl5/5.42/core_perl','-I'+stage+'/usr/share/perl5/core_perl']
    commands=[(['/usr/bin/pacman','-Q'],'packages-unsorted.txt'),
              (['/usr/bin/pacman','-Qoq',pf[0]['path']],'provider-owner.txt'),
              (pf[0]['readelf_argv'],'provider-readelf.txt'),(c['makepkg_argv'],'makepkg.log'),
              ([stage+'/usr/bin/perl',*includes,'/inputs/helpers/staged_smoke.pl',stage],'staged-smoke.json'),
              ([stage+'/usr/bin/perl',*includes,'-MConfig','-e','print $Config{cf_time}, chr(10)'],'staged-cf-time.txt'),
              (['/usr/bin/bsdtar','-xOf','/work/output/'+r.ARCHIVE,'.PKGINFO'],'PKGINFO'),
              (['/usr/bin/bsdtar','-xOf','/work/output/'+r.ARCHIVE,'.BUILDINFO'],'BUILDINFO')]
    rows=[dict(argv=argv,log=log,success=True,returncode=0,lifecycle=natural()) for argv,log in commands]
    rows[3]['lifecycle']['elapsed_seconds']=500
    data['entry-commands.json']=r.encoded(rows);data['packages-unsorted.txt']=lock
    def get(name,cap):
        raw=data[name]
        if not 0<len(raw)<=cap:raise ValueError('fixture byte bound')
        return raw
    return c,a,data,get


class PassiveData(unittest.TestCase):
    def test_single_frame_archive_recomputes_payload_and_aarch64_tables(self):
        raw = package()
        value = r.archive(raw, require_zstd=False)
        self.assertEqual(value['identity'], r.pin(raw))
        self.assertEqual(len([n for n in value['nodes'] if n.startswith('usr/bin/') and value['nodes'][n]['type']=='symlink']), 29)
        self.assertEqual(value['elfs']['usr/bin/perl']['needed'], ['libperl.so', 'libcrypt.so.2'])
        with self.assertRaisesRegex(ValueError, 'zstd'):r.archive(raw)

    def test_truncated_or_trailing_compressed_bytes_refuse(self):
        raw = package()
        for body in (raw[:-2], raw+b'UNACCEPTED', raw+raw):
            with self.subTest(bytes=len(body)), self.assertRaises(ValueError):
                r.archive(body, require_zstd=False)

    def test_wrong_elf_and_missing_or_redirected_alias_refuse(self):
        def foreign(files, links):
            body = bytearray(files['usr/bin/perl'])
            body[18:20] = (62).to_bytes(2, 'little')
            files['usr/bin/perl'] = bytes(body)
        for change in (foreign, lambda f,l:l.pop('usr/bin/prove'),
                       lambda f,l:l.update({'usr/bin/prove':'/etc/passwd'}),
                       lambda f,l:f.pop('usr/lib/perl5/5.42/core_perl/auto/threads/threads.so'),
                       lambda f,l:f.update({'usr/bin/core_perl/MODELED-extra':b'MODELED forbidden DATA'}),
                       lambda f,l:f.update({'usr/bin/perl':b'MODELED non-ELF DATA'})):
            with self.subTest(change=change), self.assertRaises(ValueError):
                r.archive(package(change=change), require_zstd=False)

    def test_escaping_service_and_control_members_refuse(self):
        for name in ('usr/local/operator', 'usr/share/libalpm/hooks/fake.hook',
                     'usr/lib/systemd/system/fake.service', '.INSTALL', '../escape'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                r.archive(package(change=lambda f,l:f.update({name:b'MODELED forbidden DATA'})), require_zstd=False)

    def test_harness_needs_full_positive_summary_and_extensions(self):
        raw = b''' 0x1 (NEEDED) Shared library: [libz.so.1]
 0x1 (NEEDED) Shared library: [libbz2.so.1.0]
../fixture.t .... skipped: MODELED skip DATA
All tests successful.
Files=2920, Tests=1351000, 400 wallclock secs (MODELED CPU DATA)
Result: PASS
PASS selected shared threaded Perl5.42.3 paths,113 core providers and five C extensions
'''
        value = r.harness(raw)
        self.assertEqual((value['files'], value['whole_file_skips']), (2920, 1))
        for files,tests in [(2917,1351002),(2923,135100),(2,2)]:
            variant=raw.replace(b'Files=2920, Tests=1351000',('Files='+str(files)+', Tests='+str(tests)).encode())
            self.assertEqual((r.harness(variant)['files'],r.harness(variant)['tests']),(files,tests))
        for body in (raw.replace(b'2920',b'0'), raw.replace(b'1351000',b'0'),
                     raw.replace(b'2920',b'12001'),raw.replace(b'1351000',b'3000001'),
                     raw.replace(b'Result: PASS',b'Result: FAIL'), raw+ b'Result: PASS\n',
                     raw.replace(b'113 core providers',b'112 core providers')):
            with self.subTest(body=body), self.assertRaises(ValueError):r.harness(body)

    def test_provider_binds_actual_binary_alpm_and_readelf(self):
        args = provider_fixture()
        value = r.provider(*args)
        self.assertEqual(value['elf'], r.pin(args[4]))
        for index, body in [(1,args[1].replace(b'=2-64',b'=1-64')),
                            (2,args[2].replace(b'usr/lib/libcrypt.so.2.0.0',b'usr/lib/other')),
                            (3,b'other\n'),(5,args[5].replace(b'libcrypt.so.2]',b'libcrypt.so.1]'))]:
            changed = list(args);changed[index]=body
            with self.subTest(index=index), self.assertRaises(ValueError):r.provider(*changed)
        changed = list(args);changed[0]=dict(args[0], readelf_argv=['readelf','--version'])
        with self.assertRaises(ValueError):r.provider(*changed)
        changed = list(args);changed[0]=dict(args[0],symlinks=args[0]['symlinks'][:1])
        with self.assertRaisesRegex(ValueError,'linker/runtime'):r.provider(*changed)

    def test_strict_json_and_stable_read_refuse_ambiguous_inputs(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e999}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):r.object_data(raw)
        self.assertEqual(r.object_data(b'{"elapsed_seconds":0.1}')['elapsed_seconds'], .1)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary);(root/'data').write_bytes(b'MODELED DATA')
            (root/'alias').symlink_to('data')
            self.assertEqual(r.read(root,'data',32), b'MODELED DATA')
            with self.assertRaises(OSError):r.read(root,'alias',32)
            with self.assertRaises(ValueError):r.read(root,'../data',32)
            with self.assertRaises(ValueError):r.read(root,'data',1)

    def test_namespace_qualification_requires_separate_real_effects_and_bindings(self):
        c,a,q=operands();r.qualified(c,a,q)
        def ignored_effect(value):value['cases']['bwrap-user-mount-net']['after']['namespaces']['net']=value['cases']['bwrap-user-mount-net']['before']['namespaces']['net']
        def wrong_map(value):value['cases']['unshare-mapped-root']['after']['uid_map']=[[0,0,1]]
        def wrong_bwrap_map(value):value['cases']['bwrap-user-mount-net']['after']['gid_map']=[[1001,0,1]]
        def forced(value):value['cases']['bwrap-user-mount-net']['retirement']['forced_cleanup']=True
        for change in (ignored_effect,wrong_map,wrong_bwrap_map,forced,lambda value:value.update(source=c['namespace']['Source3937']),
                       lambda value:value.update(run='999'),lambda value:value.update(status='NOT_RUN')):
            changed=copy.deepcopy(q);change(changed)
            admission=dict(a,qualification_sha256=r.pin(r.encoded(changed))['sha256'])
            with self.subTest(change=change),self.assertRaises(ValueError):r.qualified(c,admission,changed)
        with self.assertRaises(ValueError):r.qualified(c,dict(a,approval=None),q)
        with self.assertRaises(ValueError):r.qualified(c,dict(a,qualification_sha256='0'*64),q)

    def test_unqualified_operand_refuses_before_any_evidence_read(self):
        c,a,q=operands()
        with patch.object(r,'read',side_effect=AssertionError('must refuse before artifact reads')):
            with self.assertRaises(ValueError):r.validate_pair('/MODELED/absent',c,dict(a,approval=None),q)

    def test_exact_actual_actor_domain_refuses_profile_weakening(self):
        c,a,q=operands();item=dict(name='MODELED',volume='MODELED-work')
        actor=actor_fixture(item,c,a,'/MODELED/inputs');r.actor(actor,item,c,a)
        for key,value in [('MemorySwap',-1),('CapAdd',['SYS_ADMIN']),('ReadonlyRootfs',False),
                          ('NetworkMode','host'),('PidsLimit',512),('Init',False),('SecurityOpt',[])]:
            changed=copy.deepcopy(actor);changed['HostConfig'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):r.actor(changed,item,c,a)
        changed=copy.deepcopy(actor);changed['Config']['Entrypoint']=['/bin/sh']
        with self.assertRaises(ValueError):r.actor(changed,item,c,a)
        changed=copy.deepcopy(actor);changed['Mounts'][0]['RW']=True
        with self.assertRaises(ValueError):r.actor(changed,item,c,a)

    def test_ordered_lifecycle_joins_raw_inspection_initial_and_final_absence(self):
        root=Path('/MODELED/evidence');c,a,q,report,files,get=operation_fixture(root)
        value=r.operations(get,report,c,a,root)
        self.assertEqual([len(rows) for rows in value.pop('exports')],[3,3])
        self.assertEqual(value,dict(count=37,retired_volumes=2,final_absence=True,actor_seconds=[.1,.1],capacity=dict(phases=7,fixed_inode_only=True,active_samples=800)))
        first=report['builds'][0]
        checks=[('stale-initial',lambda rp,fs:fs.update({rp['initial_volume_log']:(first['volume']+'\n').encode(),'initial-volumes.txt':(first['volume']+'\n').encode()})),
                ('live-final',lambda rp,fs:fs.update({'final-volumes.txt':(first['volume']+'\n').encode(),rp['operations'][-1]['log']:(first['volume']+'\n').encode()})),
                ('wrong-retirement',lambda rp,fs:rp['retired'][0].update(volume=rp['builds'][1]['volume'])),
                ('forced-command',lambda rp,fs:rp['operations'][1]['lifecycle'].update(forced_cleanup=True)),
                ('missing-raw-inspection',lambda rp,fs:fs.update({rp['builds'][0]['inspect_log']:r.encoded([])})),
                ('bad-cleanup',lambda rp,fs:fs.update({rp['cleanup'][0]['log']:b'Error response from daemon: permission denied\n'})),
                ('initializer-user',lambda rp,fs:rp['operations'][6]['argv'].remove('--user=0:0')),
                ('export-copy-bytes',lambda rp,fs:fs.update({'build-1/'+r.ARCHIVE:b'MODELED forged export DATA'})),
                ('export-raw-pin',lambda rp,fs:rp['operations'][11]['stdout_pin'].update(sha256='0'*64)),
                ('export-limit-restore',lambda rp,fs:rp['operations'][11]['fsize'].update(after=[128*r.MIB,-1])),
                ('early-allocation',lambda rp,fs:rp['operations'].__setitem__(16,rp['operations'][18]))]
        for kind,change in checks:
            c,a,q,rp,fs,read=operation_fixture(root);change(rp,fs)
            with self.subTest(kind=kind),self.assertRaises(ValueError):r.operations(read,rp,c,a,root)

    def test_capacity_receipts_require_exact_remaining_demands_and_fixed_counters(self):
        c,a,q=operands();root=Path('/MODELED/evidence');docker=Path('/MODELED/docker')
        for shared in (False,True):
            report=dict(capacity=capacity_fixture(root,shared=shared));report['active_reserve']=reserve_fixture(report['capacity'])
            self.assertEqual(r.capacity_data(report,c,root,docker),dict(phases=7,fixed_inode_only=True,active_samples=800))
            changes=[lambda rows:rows.pop(),lambda rows:rows.reverse(),
                     lambda rows:rows[0].update(status='HOLD_CAPACITY'),
                     lambda rows:rows[0].update(MemAvailable_bytes=8*1024*r.MIB-1),
                     lambda rows:rows[0].update(MemAvailable_bytes=True),
                     lambda rows:rows[0]['filesystems']['10'].update(required_bytes=1),
                     lambda rows:rows[0]['filesystems']['10'].update(available_bytes=0),
                     lambda rows:rows[0]['filesystems']['10'].update(total_inodes=0,available_inodes=0),
                     lambda rows:rows[0]['filesystems']['10'].update(available_inodes=119999),
                     lambda rows:rows[0]['filesystems']['10'].update(total_inodes=120000,available_inodes=120001),
                     lambda rows:rows[0]['filesystems']['10'].update(total_inodes=-1),
                     lambda rows:rows[0]['filesystems']['10'].update(available_bytes=True),
                     lambda rows:rows[0]['filesystems']['10'].update(paths=['/MODELED/other']),
                     lambda rows:rows[1]['filesystems'].update({'99':rows[1]['filesystems'].pop('10')})]
            for change in changes:
                report=dict(capacity=capacity_fixture(root,shared=shared));report['active_reserve']=reserve_fixture(report['capacity']);change(report['capacity'])
                with self.subTest(shared=shared,change=change),self.assertRaises(ValueError):r.capacity_data(report,c,root,docker)
            active_changes=[lambda active:active.update(samples=0),lambda active:active.update(samples=6001),
                            lambda active:active.update(samples=True),lambda active:active.update(minimum_bytes={}),
                            lambda active:active['minimum_bytes'].update({'10':1024*r.MIB-1}),
                            lambda active:active['minimum_bytes'].update({'10':True}),
                            lambda active:active['minimum_bytes'].update({'99':1024*r.MIB}),
                            lambda active:active.update(minimum_MemAvailable_bytes=4096*r.MIB-1),
                            lambda active:active.update(minimum_MemAvailable_bytes=True)]
            for change in active_changes:
                report=dict(capacity=capacity_fixture(root,shared=shared));report['active_reserve']=reserve_fixture(report['capacity']);change(report['active_reserve'])
                with self.subTest(shared=shared,active_change=change),self.assertRaises(ValueError):r.capacity_data(report,c,root,docker)

    def test_pair_api_composes_parsers_and_rechecks_raw_bytes(self):
        """Composition model only: real archive/provider parsers tested above."""
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);c,a,q,report,files,get=operation_fixture(root)
            raw=b'MODELED identical archive DATA'
            files.update({'report.json':r.encoded(report),'build-1/'+r.ARCHIVE:raw,'build-2/'+r.ARCHIVE:raw})
            for index in (1,2):
                files['build-'+str(index)+'/makepkg-base.conf']=MODELED_BASE_CONFIG
                files['build-'+str(index)+'/makepkg-effective.conf']=MODELED_BASE_CONFIG+r.MAKEPKG_SUFFIX.encode()
            for name,body in files.items():
                leaf=root/name;leaf.parent.mkdir(parents=True,exist_ok=True);leaf.write_bytes(body)
            modeled=dict(archive=r.pin(raw),nodes={'MODELED':{'type':'file'}},harness={'MODELED':True},provider={'MODELED':True},commands={'seconds':.1},
                         makepkg_configs=dict(base=r.pin(MODELED_BASE_CONFIG),effective=r.pin(MODELED_BASE_CONFIG+r.MAKEPKG_SUFFIX.encode())))
            with patch.object(r,'input_snapshot') as snapshot,patch.object(r,'build_data',return_value=modeled):
                result=r.validate_pair(root,c,a,q)
                self.assertEqual(result['status'],'PASS_NATIVE_PAIR_DATA');self.assertFalse(result['native_acceptance'])
                self.assertEqual(snapshot.call_count,1)
                def retain_updated_export():
                    exported={leaf.name:leaf.read_bytes() for leaf in (root/'build-2').iterdir()}
                    raw_export=export_fixture(exported);(root/'export-2.tar').write_bytes(raw_export)
                    next(row for row in report['operations'] if row.get('stdout')=='export-2.tar')['stdout_pin']=r.pin(raw_export)
                    (root/'report.json').write_bytes(r.encoded(report))
                (root/'build-2/makepkg-effective.conf').write_bytes(b'MODELED DIFFERENT CONFIG\n')
                retain_updated_export()
                with self.assertRaisesRegex(ValueError,'configurations differ across pair'):r.validate_pair(root,c,a,q)
                (root/'build-2/makepkg-effective.conf').write_bytes(MODELED_BASE_CONFIG+r.MAKEPKG_SUFFIX.encode())
                (root/'build-2'/r.ARCHIVE).write_bytes(b'MODELED changed compressed DATA')
                retain_updated_export()
                with self.assertRaisesRegex(ValueError,'raw pair archive'):r.validate_pair(root,c,a,q)

    def test_plain_export_tar_is_complete_flat_and_matches_retained_namespace(self):
        c,a,q=operands();files={'MODELED.txt':b'MODELED inert export DATA\n'}
        for pax in (False,True):
            raw=export_fixture(files,pax=pax);rows=r.export_tar(raw,c)
            self.assertEqual(rows,{'MODELED.txt':dict(mode=0o644,**r.pin(files['MODELED.txt']))})
        raw=export_fixture(files)
        for body in (raw[:1024],raw[:2048],raw+raw,export_fixture({'nested/path':b'MODELED'}),
                     export_fixture({'../escape':b'MODELED'}),export_fixture({str(index):b'MODELED' for index in range(65)})):
            with self.subTest(bytes=len(body)),self.assertRaises((ValueError,tarfile.TarError)):r.export_tar(body,c)
        for kind in (tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.FIFOTYPE):
            item=tarfile.TarInfo('output/linked');item.type=kind;item.linkname='MODELED.txt';item.mode=0o644
            with self.subTest(kind=kind),self.assertRaises(ValueError):r.export_tar(export_fixture(files,extra=item),c)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);build=root/'build-1';build.mkdir();leaf=build/'MODELED.txt';leaf.write_bytes(files['MODELED.txt']);leaf.chmod(0o644)
            r.export_namespace(root,'build-1',rows)
            (build/'extra').write_bytes(b'MODELED extra DATA')
            with self.assertRaisesRegex(ValueError,'namespace'):r.export_namespace(root,'build-1',rows)
            (build/'extra').unlink();leaf.chmod(0o600)
            with self.assertRaisesRegex(ValueError,'mode'):r.export_namespace(root,'build-1',rows)

    def test_export_soft_limit_receipt_preserves_tighter_existing_limits(self):
        c,a,q=operands()
        for before,limit in [([-1,-1],256*r.MIB),([128*r.MIB,-1],128*r.MIB),([128*r.MIB,192*r.MIB],128*r.MIB)]:
            receipt=dict(before=before,inherited_soft=limit,after=before.copy())
            r.export_limit(dict(fsize=receipt),c,10240)
            for changed in [dict(receipt,inherited_soft=limit+1),dict(receipt,after=[-1,-1] if before!=[-1,-1] else [1,-1]),
                            dict(receipt,inherited_soft=True),dict(receipt,before=[-2,-1])]:
                with self.subTest(before=before,changed=changed),self.assertRaises(ValueError):r.export_limit(dict(fsize=changed),c,10240)
            with self.assertRaises(ValueError):r.export_limit(dict(fsize=receipt),c,limit+1)

    def test_build_data_parses_all_actual_fields_in_inert_modeled_package(self):
        c,a,data,get=build_fixture();decode=r.archive
        # Gzip permits the same inert package model on Python without zstd;
        # actual API still unconditionally requires zstd package magic.
        with patch.object(r,'archive',side_effect=lambda raw:decode(raw,require_zstd=False)):
            result=r.build_data(get,c,a)
            self.assertEqual(result['harness']['files'],2920)
            self.assertEqual(result['provider']['soname'],'libcrypt.so.2')
            self.assertEqual(result['archive'],r.pin(data[r.ARCHIVE]))
            for name,body in [('staged-cf-time.txt',b'WRONG TIME\n'),('makepkg-exit.txt',b'1\n'),
                              ('packages.txt',data['packages.txt']+b'MODELED extra package\n'),
                              ('source-config.sh',data['source-config.sh']+b"cf_time='WRONG'\n"),
                              ('BUILDINFO',data['BUILDINFO'].replace(b'pkgarch = aarch64',b'pkgarch = x86_64'))]:
                previous=data[name];data[name]=body
                try:
                    with self.subTest(name=name),self.assertRaises(ValueError):r.build_data(get,c,a)
                finally:data[name]=previous
            environment=json.loads(data['environment.json']);environment['environment']['PERL_SKIP_TESTS']='MODELED'
            original=data['environment.json'];data['environment.json']=r.encoded(environment)
            with self.assertRaisesRegex(ValueError,'recorded build environment'):r.build_data(get,c,a)
            data['environment.json']=original
            environment=json.loads(data['environment.json']);environment['status']=environment['status'].replace('NoNewPrivs:\t1','NoNewPrivs:\t0')
            data['environment.json']=r.encoded(environment)
            with self.assertRaisesRegex(ValueError,'capability/NNP'):r.build_data(get,c,a)

    def test_entry_requires_actual_full_makepkg_and_natural_retirement(self):
        c,a,data,get=build_fixture();path=json.loads(data['provider.json'])['path']
        self.assertEqual(r.entry_operations(get,c,path)['count'],8)
        for change in (lambda rows:rows[3]['argv'].append('--nodeps'),
                       lambda rows:rows[3]['lifecycle'].update(forced_cleanup=True),
                       lambda rows:rows[3].update(returncode=1),lambda rows:rows.pop()):
            rows=json.loads(data['entry-commands.json']);change(rows)
            previous=data['entry-commands.json'];data['entry-commands.json']=r.encoded(rows)
            try:
                with self.subTest(change=change),self.assertRaises(ValueError):r.entry_operations(get,c,path)
            finally:data['entry-commands.json']=previous

    def test_makepkg_config_append_is_exact_inert_and_dependency_checked(self):
        c,a,data,get=build_fixture();environment=json.loads(data['environment.json'])
        value=r.makepkg_configs(get,c,environment)
        self.assertEqual(value['effective'],r.pin(MODELED_BASE_CONFIG+r.MAKEPKG_SUFFIX.encode()))
        for body in (MODELED_BASE_CONFIG,MODELED_BASE_CONFIG+r.MAKEPKG_SUFFIX.replace('-T2','-T0').encode(),
                     MODELED_BASE_CONFIG+r.MAKEPKG_SUFFIX.encode()+b'check() { :; }\n'):
            previous=data['makepkg-effective.conf'];data['makepkg-effective.conf']=body
            try:
                with self.subTest(body=body),self.assertRaises(ValueError):r.makepkg_configs(get,c,environment)
            finally:data['makepkg-effective.conf']=previous
        with self.assertRaises(ValueError):r.makepkg_configs(get,c,dict(environment,makepkg_configuration='MODELED other base'))
        for argv in ([value for value in c['makepkg_argv'] if value not in ('--config','/work/makepkg.conf')],
                     c['makepkg_argv']+['--nocheck']):
            with self.subTest(argv=argv),self.assertRaises(ValueError):r.contract_data(dict(c,makepkg_argv=argv))


if __name__ == '__main__':unittest.main(verbosity=2)

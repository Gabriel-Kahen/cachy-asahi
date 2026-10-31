# SPDX-License-Identifier: MIT
"""Finite release-tools policy and inert fixtures; no actor on import."""
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

OPERATION='release-alpm-upgrade-v1'
NAME='cachy-asahi-release-tools'
VERSIONS=('0.1.0-1','0.2.0-1')
PREFIX=Path('/opt/native-release-tools-alpm-v1')
SOURCE=PREFIX/'source'
STORE=PREFIX/'evidence'
STAGES=('build-v1','build-v2','sign','install-v1','upgrade-v2','commands-system','commands-moved','downgrade-v1','remove','restore','cleanup')


def need(value,message):
    if not value:raise ValueError(message)


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def data_pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def pin(path):return data_pin(Path(path).read_bytes())


def ordinary(path,maximum=2*1024**2):
    path=Path(path);info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=maximum
         and not any(p.is_symlink() for p in path.parents),'ordinary bounded source required')
    return path.read_bytes()


def source_policy(root):
    root=Path(root);policy=json.loads(ordinary(root/'native/release-contract-v1.json'))
    need(policy.get('schema_version',policy.get('schema'))==1 and policy['operation']==OPERATION,'release contract identity')
    need(set(policy['recipes'])==set(VERSIONS),'exact two release versions')
    for version,prefix,count in zip(VERSIONS,('v1','v2'),(12,15)):
        row=policy['recipes'][version]
        need(row['prefix']==prefix and row['archive']==NAME+'-'+version+'-any.pkg.tar.zst','recipe/archive identity')
        need(len(row['source_files'])==(18 if prefix=='v1' else 19) and len(row['payload_files'])==count,'finite recipe/payload counts')
        for name,item in row['source_files'].items():
            need(Path(name).name==name and name not in ('.','..') and item['mode'] in (0o644,0o755)
                 and type(item['bytes']) is int and 0<item['bytes']<=1024**2
                 and re.fullmatch('[0-9a-f]{64}',item['sha256']),'flat pinned recipe source')
        for name,item in row['payload_files'].items():
            need(name.startswith('usr/') and Path(name).as_posix()==name and '..' not in Path(name).parts
                 and item['mode'] in (0o644,0o755) and 0<item['bytes']<=1024**2
                 and re.fullmatch('[0-9a-f]{64}',item['sha256']),'pinned package payload')
    need(policy['bundle']['path']=='native/release-sources-v1.tar' and policy['bundle']['members']==37
         and policy['bundle']['bytes']<=policy['bundle']['max_bytes']<=1024**2,'finite source bundle')
    retirement=policy['retirement_profile']
    need(set(retirement)=={'name','path','bytes','sha256','group_census','caller'}
         and retirement['name']=='reserved-terminal-v2'
         and retirement['path']=='scripts/virtual/owned_process_retirement_v2.py'
         and retirement['group_census']=='RESERVED_LEADER_ONLY'
         and retirement['caller']=='BUNDLED_FIXED_RETIREMENT_COMMANDS'
         and policy['original_workflow']=={k:retirement[k]for k in ('path','bytes','sha256')}
         and data_pin(ordinary(root/retirement['path']))=={k:retirement[k] for k in ('bytes','sha256')},
         'exact versioned pre-reap retirement profile required')
    base=ordinary(root/'native/expected349.lock')
    need(data_pin(base)=={k:policy['expected349'][k] for k in ('bytes','sha256')}
         and len(base.splitlines())==349,'exact base349 lock')
    versions=dict(line.decode().split(' ',1) for line in base.splitlines())
    need(all(versions.get(name)==version for name,version in policy['dependencies'].items())
         and versions.get('python')=='3.14.8-1' and versions.get('zstd')=='1.5.7-3','genuine187 dependency versions')
    conf=ordinary(root/policy['makepkg_config']['path'])
    need(data_pin(conf)=={k:policy['makepkg_config'][k] for k in ('bytes','sha256')}
         and re.search(rb'^BUILDENV=\([^\n]*\bcheck\b',conf,re.M) and b'!check' not in conf
         and b"PKGEXT='.pkg.tar.zst'" in conf,'positive makepkg check policy')
    return policy,base


def recipe_members(root,policy):
    raw=ordinary(Path(root)/policy['bundle']['path'],policy['bundle']['max_bytes'])
    need(data_pin(raw)=={k:policy['bundle'][k] for k in ('bytes','sha256')},'source bundle checksum')
    expected={row['prefix']+'/'+name:item for row in policy['recipes'].values() for name,item in row['source_files'].items()};result={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        for member in archive:
            name=member.name
            need(name in expected and name not in result and member.isfile() and not member.pax_headers
                 and member.uid==member.gid==member.mtime==0,'exact regular source bundle members')
            item=expected[name]
            need(member.mode==item['mode'] and member.size==item['bytes'],'source member size/mode')
            body=archive.extractfile(member).read()
            need(data_pin(body)=={k:item[k] for k in ('bytes','sha256')},'source member checksum');result[name]=body
    need(set(result)==set(expected) and len(result)==37,'complete two-version recipe bundle')
    return result


def extract_recipes(root,destination,policy):
    members=recipe_members(root,policy);destination=Path(destination);destination.mkdir(mode=0o755)
    for version in VERSIONS:
        row=policy['recipes'][version];target=destination/row['prefix'];target.mkdir(mode=0o755)
        for name,item in row['source_files'].items():
            path=target/name
            with path.open('xb') as stream:stream.write(members[row['prefix']+'/'+name])
            path.chmod(item['mode'])
    return destination


def load_workflow(root,policy):
    row=policy['original_workflow'];path=Path(root)/row['path'];raw=ordinary(path)
    need(data_pin(raw)=={k:row[k] for k in ('bytes','sha256')},'exact reviewed retirement core/caller bundle bytes')
    spec=importlib.util.spec_from_file_location('_release_owned_workflow_v1',path);module=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(path),'exec'),module.__dict__);return module


def inventory_expected(base,version=None):
    rows=base.splitlines(keepends=True)
    need(not any(line.startswith((NAME+' ').encode()) for line in rows),'project package absent from base')
    if version is not None:
        need(version in VERSIONS,'finite installed release version');rows.append((NAME+' '+version+'\n').encode())
    return b''.join(sorted(rows))


def snapshot(root):
    result={};root=Path(root)
    if not root.exists():return result
    for path in sorted(root.rglob('*')):
        info=path.lstat();name=path.relative_to(root).as_posix()
        if stat.S_ISREG(info.st_mode):result[name]=dict(mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,**pin(path))
        elif stat.S_ISLNK(info.st_mode):result[name]=dict(link=os.readlink(path))
        elif not stat.S_ISDIR(info.st_mode):result[name]=dict(kind='special')
    return result


def snapshot_receipt(root):
    value=snapshot(root);return dict(files=len(value),**data_pin(encoded(value)))


def check_payload(root,policy,version,run,pacman):
    expected=policy['recipes'][version]['payload_files'];all_paths=set().union(*(r['payload_files'] for r in policy['recipes'].values()))
    for name,item in expected.items():
        path=Path(root)/name;info=path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==item['mode']
             and pin(path)=={k:item[k] for k in ('bytes','sha256')},'actual ALPM payload bytes/mode/ownership: '+name)
        need(run('owner-'+version,['/usr/bin/pacman',*pacman,'-Qoq',str(path)]).strip()==NAME.encode(),'actual ALPM ownership join')
    listed=run('owned-files-'+version,['/usr/bin/pacman',*pacman,'-Qlq',NAME]).decode().splitlines()
    need(len(listed)==len(set(listed)) and all(name.startswith('/') and name.rstrip('/')==Path(name.rstrip('/')).as_posix()
         and '..' not in Path(name).parts for name in listed),'canonical unique ALPM owned paths')
    files={name.lstrip('/') for name in listed if not name.endswith('/')}
    need(files==set(expected),'exact ALPM package-owned file set')
    directories={name.lstrip('/').rstrip('/') for name in listed if name.endswith('/')}
    ancestors={str(parent) for name in expected for parent in Path(name).parents if str(parent)!='.'}
    need(directories==ancestors,'exact ALPM package-owned directory set')
    need(all(not os.path.lexists(Path(root)/name) for name in all_paths-set(expected)),'stale prior private-runtime files absent')
    return dict(version=version,count=len(expected),verified=True,stale_absent=True)


def topmem_sources(recipe):
    result={}
    with tarfile.open(Path(recipe)/'recipe-fixture.tar','r:') as archive:
        for member in archive:
            prefix='fixtures/recipe/';name=member.name.removeprefix(prefix)
            need(member.isfile() and member.name.startswith(prefix) and Path(name).name==name
                 and name not in result and member.size<=65536,'finite original Topmem fixture')
            result[name]=archive.extractfile(member).read()
    need(set(result)=={'.SRCINFO','PKGBUILD','LICENSE','NOTICE','README.md','cachy-asahi-topmem','test_topmem.py'},'exact seven inert Topmem files')
    return result


def tar_bytes(rows):
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w',format=tarfile.USTAR_FORMAT) as archive:
        for name,(raw,mode) in sorted(rows.items()):
            member=tarfile.TarInfo(name);member.size=len(raw);member.mode=mode;member.uid=member.gid=member.mtime=0
            archive.addfile(member,io.BytesIO(raw))
    return output.getvalue()


def fixture_release(directory,delivery,bodies,release_id):
    """Synthetic metadata only; no Topmem source or recipe is executed."""
    directory=Path(directory);directory.mkdir(mode=0o755);files={};name='cachy-asahi-topmem';version='0.1.0-1'
    def put(path,raw):
        target=directory/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw);target.chmod(0o644)
        files[path]=data_pin(raw)['sha256'];return raw
    info=('pkgname = '+name+'\npkgbase = '+name+'\npkgver = '+version+'\narch = any\nlicense = MIT\ndepend = python>=3.11\n').encode()
    build=('format = 2\npkgname = '+name+'\npkgver = '+version+'\npkgarch = any\npkgbuild_sha256sum = '+data_pin(bodies['PKGBUILD'])['sha256']+'\ninstalled = python-3.14.8-1-aarch64\n').encode()
    rows={'.PKGINFO':(info,0o644),'.BUILDINFO':(build,0o644),'.MTREE':(b'SYNTHETIC; no native Topmem build ran.\n',0o644),
          'usr/bin/'+name:(bodies[name],0o755),'usr/share/doc/'+name+'/README.md':(bodies['README.md'],0o644),
          'usr/share/licenses/'+name+'/NOTICE':(bodies['NOTICE'],0o644),'usr/share/licenses/'+name+'/LICENSE':(bodies['LICENSE'],0o644)}
    archive=gzip.compress(tar_bytes(rows),mtime=0);filename=name+'-'+version+'-any.pkg.tar.gz';put('repo/'+filename,archive)
    identity=dict(name=name,version=version,arch='any',sha256=data_pin(archive)['sha256'])
    package=dict(identity,filename=filename,provenance='provenance/topmem.json',license=['MIT'])
    provenance=dict(schema_version=1,package={k:identity[k] for k in ('name','version','arch')},artifact_sha256=identity['sha256'],
                    source_commit='1'*40,recipe_sha256=data_pin(bodies['PKGBUILD'])['sha256'],licenses=['MIT'],sources=[],build=None)
    put(package['provenance'],encoded(provenance));evidence=[]
    def material(key,raw):
        put('evidence/'+key,raw);row=dict(id=key,path=key,sha256=data_pin(raw)['sha256'],bytes=len(raw))
        evidence.append({k:row[k] for k in ('id','path','sha256')});return row
    record=dict(package=identity,recipe_key='PKGBUILD',review_status='SYNTHETIC FIXTURE; no legal acceptance',
        bundle=material('topmem-bundle',ordinary(Path(delivery)/'source.tar')),
        source_map=material('topmem-map',ordinary(Path(delivery)/'source-map.json')),
        recipe=material('topmem-recipe',bodies['PKGBUILD']),notices=[material('topmem-notice',bodies['NOTICE']),material('topmem-license',bodies['LICENSE'])],
        authorization=material('synthetic-review',b'SYNTHETIC inert existing review; grants no permission.\n'))
    index=material('source-index',encoded(dict(schema_version=1,purpose='release-source-delivery',synthetic=True,packages=[record])))
    spec=dict(schema_version=1,release_id=release_id,source_commit='1'*40,synthetic=True,policy=dict(selected_packages=[name]),
        packages=[dict(artifact=dict(path=filename,sha256=identity['sha256']),provenance=dict(path='provenance/topmem.json',sha256=files[package['provenance']]))],
        evidence=evidence,source_delivery=dict(schema_version=1,index={k:index[k] for k in ('id','path','sha256')}))
    put('spec.json',encoded(spec))
    manifest=dict(schema_version=1,release_id=release_id,created_utc='2026-10-28T00:00:00Z',packages=[package],files=files,symlinks={})
    (directory/'release.json').write_bytes(encoded(manifest))
    return dict(directory=str(directory),release_id=release_id,release_sha256=pin(directory/'release.json')['sha256'],materials=record)


def own_user_tree(root,uid,gid):
    root=Path(root);os.chown(root,uid,gid);root.chmod(0o755)
    for path in root.rglob('*'):
        need(not path.is_symlink(),'fixture user aliases refused');os.chown(path,uid,gid)
        path.chmod(0o755 if path.is_dir() else 0o644)


def business(run,cli,root,topmem,uid,gid,label):
    root=Path(root);root.mkdir(mode=0o755);recipe=root/'topmem';recipe.mkdir(mode=0o755)
    for name,raw in topmem.items():(recipe/name).write_bytes(raw)
    own_user_tree(root,uid,gid)
    def command(step,args):
        return run(label+'-'+step,['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','HOME='+str(root),str(cli),*map(str,args)],cwd=root)
    need(command('version',['--version'])==b'cachy-asahi-release-tools 0.2.0\n','v2 actual business launcher version')
    delivery=root/'source-bundle'
    packed=json.loads(command('recipe-pack',['recipe-pack','--recipe',recipe,'--package','cachy-asahi-topmem','--source-revision','1'*40,'--output',delivery]))
    need(packed['archive_status']=='UNBOUND_NO_ARCHIVE_SUPPLIED','unbound source evidence retained')
    unpack=root/'unpacked'
    command('recipe-unpack',['recipe-unpack','--bundle',delivery/'source.tar','--sha256',pin(delivery/'source.tar')['sha256'],'--output',unpack])
    need({p.name:p.read_bytes() for p in unpack.iterdir()}==topmem,'actual CLI exact recipe roundtrip')
    exports=[]
    for suffix in ('before','after'):
        release=fixture_release(root/('release-'+suffix),delivery,topmem,'synthetic-'+label+'-'+suffix);own_user_tree(root,uid,gid)
        output=root/('sbom-'+suffix)
        command('sbom-'+suffix,['sbom','--release-dir',release['directory'],'--release-sha256',release['release_sha256'],'--output',output])
        coverage=json.loads(ordinary(output/'coverage.json'));document=json.loads(ordinary(output/'sbom.spdx.json'));row=coverage['packages'][0]
        need(coverage['synthetic'] is True and coverage['package_count']==1 and 'PROVENANCE_SOURCES_MISSING' in row['unresolved']
             and row['build_context'] is None and document['packages'][0]['licenseConcluded']=='NOASSERTION','exporter unknown/null evidence remains explicit')
        exports.append((release,output,coverage))
    release,output,_=exports[0];source=root/'exported-source'
    command('source-export',['source-export','--release-dir',release['directory'],'--release-sha256',release['release_sha256'],'--package','cachy-asahi-topmem','--output',source])
    record=release['materials'];materials=[record[k] for k in ('bundle','source_map','recipe','authorization')]+record['notices']
    for item in materials:need(pin(source/item['id'])=={k:item[k] for k in ('bytes','sha256')},'source-export exact retained bytes')
    receipt=json.loads(ordinary(source/'source-delivery-receipt.json'))
    need(receipt['release_sha256']==release['release_sha256'] and receipt['legal_acceptance'] is False,'exact source export receipt')
    args=['sbom-compare']
    for side,(release,output,_) in zip(('before','after'),exports):
        for key,value in (('',output),('-release-id',release['release_id']),('-release-sha256',release['release_sha256']),('-spdx-sha256',pin(output/'sbom.spdx.json')['sha256']),('-coverage-sha256',pin(output/'coverage.json')['sha256'])):
            args.extend(['--'+side+key,str(value)])
    raw=command('sbom-compare',args);comparison=json.loads(raw)
    need(comparison['summary']==dict(added=0,removed=0,changed=0,held_unknowns=1)
         and comparison['release_acceptance']=='NOT_ADMITTED' and comparison['legal_acceptance'] is False,'comparator holds unknowns without acceptance')
    readable=command('sbom-compare-human',args+['--format','human'])
    need(b'1 held unknown.' in readable and b'not asserted.' in readable,'human comparison semantics')
    return dict(status='PASS_ALL_FIVE_ACTUAL_COMMANDS',cli=str(cli),synthetic=True,commands=['sbom','source-export','recipe-pack','recipe-unpack','sbom-compare'],
                roundtrip_files=len(topmem),held_unknowns=1,build_context=None,license_conclusion='NOASSERTION',exports=snapshot_receipt(root),release='NOT_ADMITTED')

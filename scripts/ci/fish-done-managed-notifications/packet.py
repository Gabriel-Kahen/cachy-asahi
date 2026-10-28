# SPDX-License-Identifier: MIT
"""Pure assembly of the exact retained Done package; no recipe/native execution."""
import hashlib,importlib.util,json,shutil,stat,sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
NAME='cachy-asahi-fish-done'


def need(ok,why):
    if not ok:raise ValueError(why)


def read(path,cap=2*1024**2):
    need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary packet path required')
    info=path.stat();need(stat.S_ISREG(info.st_mode) and info.st_size<=cap,'bounded packet file required')
    raw=path.read_bytes();need(len(raw)==info.st_size,'packet file changed');return raw


def ref(root,row):
    name=row['path'];need(name and not Path(name).is_absolute() and all(p not in ('','.','..') for p in name.split('/')),'safe packet reference required')
    path=root/name;raw=read(path)
    need(len(raw)==row['bytes'] and hashlib.sha256(raw).hexdigest()==row['sha256'],'packet identity differs: '+name)
    return path


def diagnostic_policy():
    return load('done_diagnostic_policy',HERE/'observation.py').diagnostic_policy()


def policy():
    diagnostic_policy()
    value=json.loads(read(HERE/'input-policy.json'))
    need(value['status']=='ROOT_BOUND_RETAINED_DONE_PAIR' and value['checkout_ref']=='de35c384a2e5b14b664d4156897f271b81e467ba' and value['package']==NAME and value['version']=='0.1.0-2', 'UNBOUND exact Root Done input packet')
    return value


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def stage(source,modules,output):
    declared=policy();raw=read(modules/'index.json')
    need(len(raw)==declared['index']['bytes'] and hashlib.sha256(raw).hexdigest()==declared['index']['sha256'],'exact six-module packet index required')
    index=json.loads(raw);row=index['packages'][NAME]
    need(row['version']==declared['version'] and row['native_run']==declared['native_run'] and row['native_source']==declared['native_source'] and set(row['files'])=={'a','b'},'accepted Done pair identity required')
    sys.path[:0]=[str(source/'scripts/checks'),str(source/'scripts/build')]
    checks=load('done_managed_package_checks',source/'scripts/checks/package_checks.py')
    bind=load('done_managed_metadata_bind',source/'scripts/build/build.py')
    for name,value in row['sources'].items():
        path=ref(modules,value);need(value['sha256']==row['recipe_inputs'][name],'retained source identity differs')
    for key in ('acceptance','raw_lifecycle','evidence'):ref(modules,row[key])
    packages=[]
    for value in row['files'].values():
        archive=ref(modules,value)
        need(value['bytes']==declared['archive_bytes'] and value['sha256']==declared['archive_sha256'],'exact original native Done archive required')
        pkg=checks.package(archive)
        need(not pkg['errors'] and not pkg['elf'] and not bind.bind_artifact(row['metadata'],pkg,row['recipe_inputs']['PKGBUILD']), 'Done archive/BUILDINFO/source metadata differs')
        payload={n:r for n,r in pkg['members'].items() if r['type']!='5' and n not in ('.PKGINFO','.BUILDINFO','.MTREE')}
        need(payload==row['payload'] and len(payload)==8 and all(r['type']=='0' and r['uid']==r['gid']==0 and r['mode']==0o644 for r in payload.values()),'exact ordinary eight-file Done payload required')
        packages.append(pkg)
    need(packages[0]['metadata']==packages[1]['metadata'],'native pair metadata differs')
    need(not output.exists(),'fresh candidate assembly required');output.mkdir(mode=0o700)
    path=ref(modules,row['files']['a']);shutil.copyfile(path,output/path.name)
    lock=dict(status='VERIFIED_RETAINED_DONE_PAIR_NOT_EXECUTED',name=NAME,version=row['version'],archive=path.name,sha256=declared['archive_sha256'],bytes=declared['archive_bytes'],payload=row['payload'],native_run=row['native_run'],native_source=row['native_source'],packet_ref=declared['checkout_ref'])
    (output/'done-lock.json').write_text(json.dumps(lock,sort_keys=True,indent=2)+'\n')
    return lock

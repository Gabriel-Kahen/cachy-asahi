# SPDX-License-Identifier: MIT
"""Offline DATA preparation for the unchanged Python 3.14.8-1.1 native candidate."""
import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile

HERE = Path(__file__).resolve().parent
ROOT = Path('/home/gabe/Documents/ChatGPT/cachy-asahi')
RECIPE = ROOT/'packages/port/python3148-source-candidate'
RECIPE_TREE = 'ff64cda52f9739d26c265439441470bbba53297a'
FISH = ROOT/'artifacts/development/orchestrator-resume-20261114/Root-fish70-check-retention-publication-r12/public-readback'
HELD = FISH/'held-source32/scripts/ci/fish-config02-native-source/runtime'
CATALOG_HOME = ROOT.parent/'cachy-asahi-install-completion-20261114/work/supported-composition-update-sources-20261114'
CATALOG_SHA = 'e8c33e22fe95b02dff4dd795be779c038424db50d2270a0073d0bf7428a881a4'
SOURCE_ID = 'candidate-source-0'
SRC = 'Python-3.14.8.tar.xz'
BUILDER_SHA = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
SIGNER = '68B3537F39A313B3E574D06777193F152BDBE6A6'
ARCHIVE = 'python-3.14.8-1.1-aarch64.pkg.tar.xz'
BUILD_SECONDS = 1500
TOOLS = {
    'scripts/build/build_fish02.py': '0fb88871886dfbc1ede2e2c1fe0ec6408475c0a48acf0c98da74fb8fed61409b',
    'scripts/build/container-entry-v2.sh': '9be3db97efde70536a81d1c97f9ac69893a6004ab403566f8453704a2a189d2a',
    'scripts/build/source_materials.py': '9b0d95d2604ae4689f081283fc671281ce13879fcb146ddf4188873b05c89e5a',
    'scripts/checks/package_checks.py': '314e8b4a0920b3f6d93619fc74ad1d63a6210d1b17b925618451b493d2610a1a',
    'scripts/maintenance/source_cache.py': '3c922b1c5ea737605d7fd39aa986fa281c50bcf6926660390032e677706e28f3',
    'scripts/release/source_delivery.py': '8fc7757579bb0e97ccee1f3e1634ad3f827899c8ace6823cfda9f226214df36e',
}
NEEDED_MEMBERS = {
    'bluez-libs': ('usr/include/bluetooth/bluetooth.h', 'usr/lib/pkgconfig/bluez.pc'),
    'libxss': ('usr/include/X11/extensions/scrnsaver.h', 'usr/lib/pkgconfig/xscrnsaver.pc'),
    'tcl': ('usr/include/tcl.h', 'usr/lib/pkgconfig/tcl.pc', 'usr/lib/libtcl8.6.so'),
    'tk': ('usr/include/tk.h', 'usr/lib/pkgconfig/tk.pc', 'usr/lib/libtk8.6.so'),
}
ADDITIONS = {'bluez-libs':'5.87-2','libxss':'1.2.5-1','tcl':'8.6.16-1','tk':'8.6.16-1'}
MATERIAL = HERE/'materials'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def encode(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def read(path, cap, expected=None):
    need(path.is_absolute() and path.resolve()==path,'absolute canonical material required')
    with os.fdopen(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb') as stream:
        row=os.fstat(stream.fileno())
        identity=lambda st:(st.st_dev,st.st_ino,st.st_mode,st.st_nlink,st.st_size,st.st_mtime_ns,st.st_ctime_ns)
        need(stat.S_ISREG(row.st_mode) and row.st_nlink==1 and 0<row.st_size<=cap,
             'ordinary bounded material required')
        raw=stream.read(cap+1)
        need(len(raw)==row.st_size and identity(row)==identity(os.fstat(stream.fileno()))==identity(path.lstat()),
             'material changed while reading')
    need(expected is None or expected==pin(raw),'exact material pin: '+path.name)
    return raw


def package_metadata(raw, expected):
    names, info, total=set(),None,0
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r|xz') as tar:
        for leaf in tar:
            name=leaf.name.removeprefix('./')
            path=PurePosixPath(name)
            need(name not in names and len(names)<5000 and not path.is_absolute() and '..' not in path.parts
                 and not (name=='.INSTALL' or name.startswith(('usr/share/libalpm/hooks/','etc/pacman.d/hooks/'))),
                 'bounded original package namespace without supplemental install scripts/hooks')
            names.add(name);total+=leaf.size
            need(total<=32*1024**2,'bounded supplemental decoded size')
            if name=='.PKGINFO':
                need(leaf.isreg() and 0<leaf.size<=16384,'bounded signed ALPM metadata')
                info={}
                for line in tar.extractfile(leaf).read().decode().splitlines():
                    if line and not line.startswith('#'):
                        key,value=line.split(' = ',1)
                        info.setdefault(key,[]).append(value)
    name=expected
    need(info is not None and info['pkgname']==[name] and info['pkgver']==[ADDITIONS[name]]
         and info['arch']==['aarch64'] and set(NEEDED_MEMBERS[name])<=names,
         'exact ARM archive and required build members: '+name)
    need(not any(info.get(key) for key in ('conflict','replace','replaces')),
         'supplemental dependency may not conflict with or replace the frozen base')
    return info


def checked_signature_status(raw):
    rows=[line.split()[1:] for line in raw.decode('ascii').splitlines() if line.startswith('[GNUPG:] ')]
    valid=[row for row in rows if row[0]=='VALIDSIG']
    refused={'EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','KEYEXPIRED','SIGEXPIRED'}
    need(len(valid)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==SIGNER
         and not refused & {row[0] for row in rows},'exact current ALARM detached signature result')
    return dict(fingerprint=SIGNER,signed_epoch=int(valid[0][3]),status=pin(raw))


def lock_inventory(raw):
    need(pin(raw)['sha256']==BUILDER_SHA,'closest preserved signed Fish341 builder lock')
    rows=raw.decode('ascii').splitlines()
    expected=dict(row.split(' ',1) for row in rows)
    need(len(rows)==len(expected)==341 and rows==sorted(rows)
         and expected.get('python')=='3.14.8-1' and not ADDITIONS.keys() & expected.keys(),
         'canonical 341 base and unchanged protected Python provider')
    return expected


def verify_closure(base, recipe, packages):
    declared=set(recipe.get('depends',[])+recipe.get('makedepends',[])+recipe.get('checkdepends',[]))
    need(declared-base.keys()=={'tk','bluez-libs'},'exact direct recipe dependency delta')
    added=dict(ADDITIONS)
    joined=base|added
    for name, info in packages.items():
        dependee=info.get('depend',[])
        need(all(dep in joined for dep in dependee),'supplemental dependency closure differs: '+name)
    require=set().union(*(info.get('depend',[]) for info in packages.values()))
    need((declared|require)-base.keys()==added.keys(),'exact four-package transitive delta')
    return {key:joined[key] for key in sorted(declared|require)}, (
        ''.join(f'{name} {joined[name]}\n' for name in sorted(joined))).encode()


def substitute(raw, old, new):
    need(raw.count(old)==1 and new not in raw,'one exact held source seam')
    projected=raw.replace(old,new)
    need(projected.replace(new,old)==raw,'whole held tool inverse')
    return projected


def put(path, raw, mode=0o400):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)
    path.chmod(mode)


def restore_tools(output):
    for name,expected in TOOLS.items():
        raw=read(HELD/name,128<<10)
        need(pin(raw)['sha256']==expected,'exact accepted Fish builder member '+name)
        target=name
        if name.endswith('/build_fish02.py'):
            raw=substitute(raw,b'cachy-asahi-fish-config-0.1.0-2-any.pkg.tar.xz',ARCHIVE.encode())
            target='scripts/build/build_python3148.py'
        if name.endswith('/container-entry-v2.sh'):
            raw=substitute(raw,b'export HOME=/tmp/build-home LC_ALL=C.UTF-8 TZ=UTC',
                           b'export HOME=/tmp/build-home LC_ALL=C.UTF-8 TZ=UTC MAKEFLAGS=-j2')
            raw=substitute(raw,b'LOGDEST=/out makepkg --cleanbuild --clean --force --log --noconfirm',
                           b'LOGDEST=/out makepkg --cleanbuild --clean --force --log --nosign --noconfirm')
        if target.endswith('.py'):
            compile(raw,target,'exec')
        put(output/target,raw)


def recipe_snapshot(output, archive):
    frozen=ROOT/'scripts/port/python314-tk-host-build/inputs.json'
    raw=read(frozen,16<<10)
    need(pin(raw)['sha256']=='8f476ba503d62b43e8ee07e0a35aaba6a48fd10ccbd7284a505a2619e0d24761',
         'exact frozen 12-file full-Tk host recipe descriptor')
    files=json.loads(raw)['files']
    leaves={item.name for item in RECIPE.iterdir() if item.name!='__pycache__'}
    need(leaves==set(files),'maintained recipe namespace diverged from frozen 12 inputs')
    for name,expected in files.items():
        put(output/name,read(RECIPE/name,64<<10,expected))
    checker=output/'check_source.py'
    spec=importlib.util.spec_from_file_location('frozen_python_candidate_source_data',checker)
    frozen_checker=importlib.util.module_from_spec(spec);spec.loader.exec_module(frozen_checker)
    result=frozen_checker.check(output,archive)
    need(result['status']=='PASS exact source/material/metadata checks only',
         'maintained recipe and official source correspondence')
    return result


def source_cache(output, report):
    import source_materials as sm
    catalog=CATALOG_HOME/'source-cache-inputs.json'
    data=read(catalog,64<<10)
    need(pin(data)['sha256']==CATALOG_SHA,'exact retained source catalog')
    row,= (r for r in json.loads(data)['sources'] if r['material']['id']==SOURCE_ID)
    catalog_out=output/catalog.name
    put(catalog_out,data)
    for evidence in row['license_evidence']:
        put(output/evidence['path'],read(CATALOG_HOME/evidence['path'],128<<10,
            {key:evidence[key] for key in ('bytes','sha256')}))
    cache=output/'source-cache'
    sm.cache.initialize(cache)
    held=CATALOG_HOME/'source-cache'
    obj='objects/'+row['material']['sha256']
    receipt=f'receipts/{CATALOG_SHA}-{SOURCE_ID}.json'
    put(cache/obj,read(held/obj,32<<20,{key:row['material'][key] for key in ('bytes','sha256')}),0o600)
    put(cache/receipt,read(held/receipt,128<<10),0o600)
    plan=dict(schema_version=1,purpose='offline-build-sources',recipe_inputs=report['input_sha256'],
              catalog_sha256=CATALOG_SHA,sources=[dict(source=row['url'],id=SOURCE_ID,revision=row['revision'])])
    raw=encode(plan)
    path=output/'source-plan.json';put(path,raw)
    check=sm.prepare(report,path,pin(raw)['sha256'],catalog_out,cache)
    need([item['filename'] for item in check['selected']]==[SRC],'exact offline CPython source selection')
    return plan


def plan(output):
    need(output.is_absolute() and output.resolve()==output and output.parent==HERE and not output.exists(),
         'fresh private preflight output required')
    frozen_map=read(FISH/'source-map.json',64<<10)
    need(pin(frozen_map)['sha256']=='14a3f9d1f12f224bf43a71a7bb4ef9ba3bfe03b5918b25aabc33ce1fdb71a3b2',
         'exact accepted Fish r12 Source map')
    expected=json.loads(read(HERE/'material-pins.json',16<<10))
    archive=read(MATERIAL/SRC,32<<20,expected[SRC])
    sigstore=read(MATERIAL/(SRC+'.sigstore'),16384,expected[SRC+'.sigstore'])
    sbom=read(MATERIAL/(SRC+'.spdx.json'),4<<20,expected[SRC+'.spdx.json'])
    content=json.loads(sigstore)['messageSignature']['messageDigest']
    need(content['algorithm']=='SHA2_256' and base64.b64decode(content['digest'],validate=True).hex()==pin(archive)['sha256'],
         'official Sigstore message digest corresponds to exact tar; authenticity review still pending')
    need(json.loads(sbom)['spdxVersion'].startswith('SPDX-'),'official SPDX document structure')
    for name in ('archlinuxarm-source.gpg','archlinuxarm-binary.gpg'):
        read(MATERIAL/name,16<<10,expected[name])
    archives={}; info={}; verified={}
    for name,version in ADDITIONS.items():
        leaf=f'{name}-{version}-aarch64.pkg.tar.xz'
        body=read(MATERIAL/leaf,8<<20,expected[leaf])
        signature=read(MATERIAL/(leaf+'.sig'),8192,expected[leaf+'.sig'])
        info[name]=package_metadata(body,name)
        verified[name]=checked_signature_status(read(HERE/'logs'/(leaf+'.gpg-status'),8192))
        archives[leaf]=body;archives[leaf+'.sig']=signature
    lock=FISH/'scripts/ci/fish-config02-native-source/successor_v2/expected341.lock'
    old_lock=read(lock,32<<10)
    base=lock_inventory(old_lock)
    output.mkdir(mode=0o700)
    recipe=output/'recipe'
    recipe_report=recipe_snapshot(recipe,MATERIAL/SRC)
    restore_tools(output/'runtime')
    sys.path.insert(0,str(output/'runtime/scripts/checks'))
    sys.path.insert(0,str(output/'runtime/scripts/build'))
    import package_checks as checks
    report=checks.recipe(recipe/'PKGBUILD')
    need(not report['errors'],'existing builder checker refuses unchanged candidate')
    requirements,expected_lock=verify_closure(base,report['metadata'],info)
    need(len(expected_lock.splitlines())==345,'complete candidate 345 package lock')
    put(output/'expected345.lock',expected_lock)
    put(output/'reviewed-inputs.json',encode(report['input_sha256']))
    offline=source_cache(output,report)
    for name,body in archives.items():
        put(output/'builder-delta'/name,body)
    summary=dict(status='NATIVE_PYTHON3148_PREFLIGHT_DATA_ONLY',candidate='3.14.8-1.1',recipe_tree=RECIPE_TREE,
        native_build='NOT RUN',installation='NOT RUN',M2='NOT RUN',authority=None,
        base=dict(source='19dea1cca35659ad7ab307dfea09c30a77362640',run=44243507361,
                  name='Fish r12',packages=341,lock=pin(old_lock)),
        expected_inventory=dict(packages=345,lock=pin(expected_lock)),requirements=requirements,
        extra_packages={name:dict(version=ADDITIONS[name],depends=info[name].get('depend',[]),
                      license=info[name].get('license',[]),signature_result=verified[name]) for name in ADDITIONS},
        artifacts={name:pin(body) for name,body in archives.items()},
        source=dict(tar=pin(archive),sigstore=pin(sigstore),sbom=pin(sbom),
                    sigstore_authenticity='NOT VERIFIED',source_plan=pin(encode(offline)),recipe_check=recipe_report),
        execution_candidate=dict(mode='native',network='none',expected_pagesize=4096,build_seconds=BUILD_SECONDS,
                        archive=ARCHIVE,local_input_bundle_bytes=len(archive)+sum(map(len,archives.values())),
                        preserved_installed_builder_python='3.14.8-1',
                        output_transport_review='Pending; Fish 16 MiB total public-evidence cap is not sufficient as reviewed'))
    put(output/'PREFLIGHT.DATA.json',encode(summary))
    return summary


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    print(encode(plan(parser.parse_args().output)).decode(),end='')

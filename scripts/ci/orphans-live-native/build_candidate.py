# SPDX-License-Identifier: MIT
"""Held native build/pair binding with explicit separate0.3 source directory."""
import os,shutil,subprocess,tarfile
import contract as C
from pathlib import Path

def save(path,value):path.write_bytes(C.encoded(value))
def inventory(text):
 rows=[line.split() for line in text.splitlines()];C.need(rows and all(len(r)==2 for r in rows) and len(dict(rows))==len(rows),'invalid inventory');return dict(rows)
def docker(*args,**kwargs):raise RuntimeError('owner-labelled Docker factory must be bound by run.execute')

def build(source,out,base,image,lock,name,side,epoch,execute,containers,checks,bind):
    C.verify_source(source)
    directory=out/(name+'-'+side);directory.mkdir();inputs=directory/'inputs'
    shutil.copytree(source/C.RECIPE,inputs)
    reviewed=C.recipe(source,name);artifacts=directory/'artifacts';artifacts.mkdir()
    C.need({str(f.relative_to(inputs)):C.digest(f) for f in inputs.rglob('*') if f.is_file()}==reviewed['input_sha256'],
           'fresh recipe snapshot differs from reviewed inputs')
    expected=directory/'expected-packages.lock';shutil.copyfile(lock,expected)
    container='cachy-asahi-product-'+os.urandom(16).hex();containers.append(container)
    argv=docker(image,container,artifacts)+[
        '--env=CACHY_ASAHI_CONTAINER=1','--env=SOURCE_DATE_EPOCH='+str(epoch),
        '--mount',f'type=bind,src={inputs},dst=/inputs,readonly',
        '--mount',f'type=bind,src={expected},dst=/expected-packages.lock,readonly',
        '--mount',f'type=bind,src={source}/scripts/build/container-entry.sh,dst=/builder-entry.sh,readonly',
        '--entrypoint=/bin/bash',image,'/builder-entry.sh']
    provenance=dict(status='building',image=image,image_id=image,mode='native',source_date_epoch=epoch,
        recipe_inputs=reviewed['input_sha256'],recipe_metadata=reviewed['metadata'],
        expected_packages_sha256=C.digest(expected),entry_script_sha256=C.digest(source/'scripts/build/container-entry.sh'),
        clean_environment_id=container,command=argv,hardware_status='NOT RUN')
    save(directory/'provenance.json',provenance)
    execute(argv,directory/'build.log',240)
    required=('environment.txt','packages.lock','config.sha256','makepkg.conf','pacman.conf','generated.SRCINFO')
    C.need(all((artifacts/n).is_file() and not (artifacts/n).is_symlink() for n in required),'build evidence incomplete')
    C.need(inventory((artifacts/'packages.lock').read_text())==base,'build inventory differs')
    bind.bind_generated(reviewed['metadata'],checks.metadata((artifacts/'generated.SRCINFO').read_text()))
    archives=[f for f in artifacts.glob('*.pkg.tar.*') if not f.name.endswith('.sig')]
    C.need(len(archives)==1,'exact one package required; debug/split outputs require explicit review')
    package=checks.package(archives[0]);errors=bind.bind_artifact(reviewed['metadata'],package,reviewed['input_sha256']['PKGBUILD'])
    C.need(not errors,'artifact metadata differs: '+str(errors))
    payload=C.payload(package,source,name);elf=None
    if name==C.NAME:
        # Tar extraction is confined to one in-memory member, never a filesystem extraction.
        proc=None
        if archives[0].name.endswith('.zst'):
            proc=subprocess.Popen(['zstd','-dc','--',str(archives[0])],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            archive=tarfile.open(fileobj=proc.stdout,mode='r|')
        else:archive=tarfile.open(archives[0],mode='r:*')
        try:
            with archive as tar:
                data=None
                for member in tar:
                    if checks.clean_name(member.name)=='usr/bin/'+name:
                        C.need(member.isfile() and member.size<=4*1024**2,'Welcome ELF cap')
                        data=tar.extractfile(member).read()
                C.need(data is not None,'Welcome executable absent')
            if proc:
                proc.stdout.close();diagnostic=proc.stderr.read(4097)
                C.need(proc.wait(timeout=10)==0 and len(diagnostic)<=4096,'package decompressor failed')
            elf=C.elf(data,checks)
        finally:
            if proc:
                if proc.poll() is None:proc.kill();proc.wait(timeout=5)
                proc.stdout.close();proc.stderr.close()
    tests=C.check_log(directory/'build.log',name)
    validation=dict(package=package,elf=elf,tests=tests,payload=payload,errors=[])
    save(directory/'validation.json',validation)
    provenance.update(status='built-package-static-pass',artifacts={archives[0].name:C.digest(archives[0])},
        files={'artifacts/'+f.name:C.digest(f) for f in artifacts.iterdir() if f.is_file()})
    provenance['files'].update({n:C.digest(directory/n) for n in ('build.log','validation.json','expected-packages.lock')})
    save(directory/'provenance.json',provenance)
    return dict(directory=directory,archive=archives[0],payload=payload,elf=elf,tests=tests)


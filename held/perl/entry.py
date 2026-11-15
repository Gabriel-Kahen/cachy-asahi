#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Future qualified ARM actor entry. No compiler is invoked during authoring tests."""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import importlib.util

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('perl_actor_common',ROOT/'common.py')
common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
WORK=Path('/work');OUT=WORK/'output'


def _run(cancelled):
    os.umask(0o022)
    c=common.decode(common.read(ROOT/'contract.json'))
    admission_raw=common.read(ROOT/'admission.json');qraw=common.read(ROOT/'qualification.json')
    common.need(common.pin(admission_raw)['sha256']==os.environ.get('ADAPTER_ADMISSION_SHA256'),'Root admission operand hash')
    a,q=common.decode(admission_raw),common.decode(qraw)
    common.need(common.encode(a)==admission_raw and common.encode(q)==qraw,'canonical Root operands')
    common.need(common.pin(qraw)['sha256']==a['qualification_sha256'],'Root qualification operand hash')
    common.admission(a,q,c)
    common.diagnostic(q,ROOT/'nested-namespace-diagnostic.json' if q['nested_diagnostic'] is not None else None)
    source_map=common.decode(common.read(ROOT/'adapter-source-map.json'))
    common.need(common.pin(common.read(ROOT/'adapter-source-map.json'))['sha256']==a['source_map_sha256'],'Root Source map binding')
    for name in ['common.py','runtime.py','entry.py','entry.sh','contract.json','helper-pins.json',*['helpers/'+n for n in common.decode(common.read(ROOT/'helper-pins.json'))]]:
        expected=source_map['files'][name]
        common.need(common.pin(common.read(ROOT/name,1024**2))=={k:expected[k] for k in ('bytes','sha256')},'actual readonly entry/helper source pin')
    common.need(platform.machine()=='aarch64' and os.getuid()==os.getgid()==1001,'actual native alarm1001 actor required')
    actual={n:Path('/sys/fs/cgroup/'+n).read_text().strip() for n in ('cpu.max','memory.max','memory.swap.max','pids.max')}
    common.need(actual=={'cpu.max':'200000 100000','memory.max':'4294967296','memory.swap.max':'0','pids.max':'256'},'actual native cgroup limits')
    status=Path('/proc/self/status').read_text()
    for key,value in [('CapEff','0000000000000000'),('CapBnd','0000000000000000'),('NoNewPrivs','1')]:
        common.need(next(line.split()[1] for line in status.splitlines() if line.startswith(key+':'))==value,'actual capability/NNP domain')
    for p in (WORK/'home',WORK/'tmp',WORK/'recipe',OUT):p.mkdir(mode=0o700)
    runtime=common.load('perl_actual_rootless_runtime',ROOT/'runtime.py')
    os.chdir(WORK/'recipe')
    observed=dict(schema=1,admission_sha256=common.pin(admission_raw)['sha256'],source_map_sha256=a['source_map_sha256'],domain_sha256=c['domain_sha256'],entry=runtime.context(),parent=runtime.context(1))
    (OUT/'runtime.json').write_bytes(common.encode(observed))
    runtime.validate(observed['entry'],observed['parent'])
    shutil.copytree(ROOT/'recipe',WORK/'recipe',dirs_exist_ok=True)
    source=common.read(ROOT/c['source_name'],32*1024**2)
    common.need(common.pin(source)==dict(bytes=c['source_bytes'],sha256=c['source_sha256']),'actual upstream source bytes')
    (WORK/'recipe'/c['source_name']).write_bytes(source)
    common.need(common.pin(common.read(ROOT/'packet-map.json'))['sha256']==c['packet_map_sha256'],'actual packet map')
    base_config=common.read(Path('/etc/makepkg.conf'))
    effective_config=base_config+c['makepkg_config_suffix'].encode()
    (WORK/'makepkg.conf').write_bytes(effective_config)
    (OUT/'makepkg-base.conf').write_bytes(base_config);(OUT/'makepkg-effective.conf').write_bytes(effective_config)
    env=dict(PATH='/usr/bin',HOME='/work/home',XDG_CONFIG_HOME='/work/home/.config',TMPDIR='/work/tmp',LC_ALL='C',TZ='UTC',MAKEFLAGS='-j2',CACHY_ASAHI_PERL_BUILD='1',SOURCE_DATE_EPOCH=str(c['epoch']),PKGDEST='/work/output',LOGDEST='/work/output',PYTHONDONTWRITEBYTECODE='1')
    os.environ.clear();os.environ.update(env)
    owned=common.helper('owned_child.py');deadline=time.monotonic()+c['resources']['build_seconds'];commands=[]
    def command(argv,target,seconds=30,extra=None):
        common.check_cancelled(cancelled)
        lifecycle={};record=dict(argv=argv,log=target,success=False)
        try:
            cap=min(seconds,deadline-time.monotonic())
            common.need(cap>2,'entry deadline before launch')
            with (OUT/target).open('xb') as log:
                result=owned.run(argv,timeout=cap,cwd=WORK/'recipe',env={**env,**(extra or {})},stdout=log,stderr=subprocess.STDOUT,lifecycle=lifecycle,stdout_limit=c['resources']['log_bytes'],on_tick=lambda:common.check_cancelled(cancelled))
            common.check_cancelled(cancelled)
            record.update(returncode=result.returncode,lifecycle=lifecycle)
            common.need(result.returncode==0 and common.natural(lifecycle),'entry command failed or natural retirement unproven')
            record['success']=True
            return common.read(OUT/target,c['resources']['log_bytes'])
        finally:
            record['lifecycle']=lifecycle;commands.append(record);(OUT/'entry-commands.json').write_bytes(common.encode(commands))
    packages=command(['/usr/bin/pacman','-Q'],'packages-unsorted.txt')
    lock=('\n'.join(sorted(packages.decode().splitlines()))+'\n').encode();(OUT/'packages.txt').write_bytes(lock)
    common.need(common.pin(lock)['sha256']==c['expected349_sha256'],'actual349 inventory differs')
    (OUT/'source-input.json').write_bytes(common.encode(dict(source=common.pin(source),packet_map_sha256=c['packet_map_sha256'],expected349_sha256=common.pin(lock)['sha256'],adapter_source_map_sha256=a['source_map_sha256'],recipe_sha256=common.pin(common.read(ROOT/'recipe/PKGBUILD'))['sha256'])))
    # An actual ALPM owner query, raw local DB, link chain and ELF establish the
    # provider; the declared soname string alone cannot provide this evidence.
    links=[];targets=[]
    for root in ('/usr/lib/libcrypt.so','/usr/lib/libcrypt.so.2'):
        library=Path(root)
        for _ in range(8):
            if not library.is_symlink():break
            target=os.readlink(library);edge=dict(path=str(library),target=target)
            if edge not in links:links.append(edge)
            library=Path(os.path.normpath(str(library.parent/target))) if not target.startswith('/') else Path(target)
            common.need(library.parent==Path('/usr/lib'),'provider link escapes fixed library directory')
        common.need(not library.is_symlink() and library.is_file(),'bounded actual libcrypt target')
        targets.append(library)
    common.need(targets[0]==targets[1],'linker/runtime libcrypt provider targets differ')
    library=targets[0]
    owner=command(['/usr/bin/pacman','-Qoq',str(library)],'provider-owner.txt').decode().strip()
    common.need(owner=='libxcrypt','actual libcrypt ALPM owner differs')
    version=next(line.split(' ',1)[1] for line in lock.decode().splitlines() if line.startswith('libxcrypt '))
    db=Path('/var/lib/pacman/local')/('libxcrypt-'+version)
    for name in ('desc','files'):(OUT/('provider-'+name+'.txt')).write_bytes(common.read(db/name))
    elf=common.read(library,32*1024**2);(OUT/'provider-elf.bin').write_bytes(elf)
    info=common.helper('elf64le_aarch64.py').parse_elf(elf)
    common.need(info and info.get('soname')=='libcrypt.so.2','actual AArch64 libcrypt SONAME')
    argv=['/usr/bin/readelf','--wide','-h','-d',str(library)]
    command(argv,'provider-readelf.txt')
    (OUT/'provider.json').write_bytes(common.encode(dict(path=str(library),soname=info['soname'],owner=owner,version=version,symlinks=links,readelf_argv=argv)))
    failed=None;result=1
    try:
        remaining=deadline-time.monotonic()-c['resources']['entry_metadata_reserved_seconds']
        command(c['makepkg_argv'],'makepkg.log',seconds=remaining);result=0
    except BaseException as error:failed=error
    (OUT/'makepkg-exit.txt').write_text(str(result)+'\n')
    provenance=common.helper('provenance.py');old=sys.argv
    try:sys.argv=['provenance.py','--exit',str(result)];provenance.main()
    finally:sys.argv=old
    if failed is not None:raise failed
    source_root=WORK/'recipe/src/perl5-bc3dab4d4f66de5ea67dda34e5feb5230a54c603'
    (OUT/'source-config.over').write_bytes(common.read(source_root/'config.over',128))
    stage=WORK/'recipe/pkg/perl';extra=dict(LD_LIBRARY_PATH=str(stage/'usr/lib/perl5/5.42/core_perl/CORE'))
    includes=['-I'+str(stage/'usr/lib/perl5/5.42/core_perl'),'-I'+str(stage/'usr/share/perl5/core_perl')]
    command([str(stage/'usr/bin/perl'),*includes,str(ROOT/'helpers/staged_smoke.pl'),str(stage)],'staged-smoke.json',extra=extra)
    command([str(stage/'usr/bin/perl'),*includes,'-MConfig','-e','print $Config{cf_time}, chr(10)'],'staged-cf-time.txt',extra=extra)
    archive=OUT/'perl-5.42.3-1.3-aarch64.pkg.tar.zst'
    for member,target in [('.PKGINFO','PKGINFO'),('.BUILDINFO','BUILDINFO')]:command(['/usr/bin/bsdtar','-xOf',str(archive),member],target)


def run():
    with common.cancellation_scope() as cancelled:
        result=_run(cancelled);common.check_cancelled(cancelled);return result


if __name__=='__main__':
    try:run()
    except BaseException as error:
        if OUT.is_dir():(OUT/'entry-failure.txt').write_text(type(error).__name__+': '+str(error)+'\n')
        raise

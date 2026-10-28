#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Two offline native libc builds in token-owned disposable containers.

No image build/commit/removal, package installation, host libc change or admission.
Materialize the exact full GNU source first; pin reviewed manifests explicitly.
"""
import argparse,hashlib,importlib.util,json,os,platform,re,shutil,shlex,sys,uuid
from pathlib import Path
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
LOCK='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
RUNTIME='8a7cd5e73cf383b2d81ad577b8513c6fd7d49f9fd2572961c73ae9d289cab821'
SMOKE='e10336aef200731c7dd4b06546b718e095c1ecf7718e4a25fa57d6bbed6270a6'
PREFIX='opt/cachy-asahi/glibc-rebuild/2.43-r22-g8362e8ce10b2-caa1'
LABEL='org.cachy-asahi.glibc-rebuild.job'
CASES={'allocation','dlopen_dlsym','pthread_tls_join','utf8_iconv_locale','numeric_math',
       'fd_stat_clock_random','numeric_address_lookup','fork_exec_wait'}
ENV=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TZ='UTC',PYTHONDONTWRITEBYTECODE='1')


def need(ok,reason):
    if not ok:raise ValueError(reason)


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')


def ordinary(path):
    path=Path(path).absolute()
    need(str(path)==os.path.normpath(path) and not any(c.isspace() or c in ',:\\' for c in str(path)) and
         not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute simple path required')
    return path


def read_json(path,limit=2*1024**2):
    path=ordinary(path);need(path.is_file() and path.stat().st_size<=limit,'bounded ordinary receipt required')
    return json.loads(path.read_bytes())


def checked_files(directory,files):
    need(type(files) is dict and 1<=len(files)<=32,'bounded file manifest required')
    for name,row in files.items():
        need(type(name) is str and Path(name).name==name and name not in ('.','..'),'flat manifest path required')
        path=ordinary(directory/name)
        need(path.is_file() and path.stat().st_size==row['bytes'] and sha(path)==row['sha256'],'manifest file changed: '+name)


def inputs(bundle,pin):
    bundle=ordinary(bundle);need(sha(bundle/'bundle.json')==pin,'reviewed bundle manifest differs')
    value=read_json(bundle/'bundle.json')
    need(value['status']=='SOURCE_BUNDLE_READY' and value['commit']=='8362e8ce10b24068bacc19552c128dd10e082fd9' and
         value['tree']=='912828afc79878e39e0e771d461f11080c25b715','complete exact GNU tree source bundle required')
    need({'PKGBUILD','glibc-source.tar.gz','source-lock.json'}<=set(value['files']),'complete offline source inputs required')
    checked_files(bundle,value['files'])
    # A reviewed receipt is not itself proof of a full source tree. Recompute
    # Git blob/tree identities before any container or recipe actor exists.
    spec=importlib.util.spec_from_file_location('glibc_source_inspector',HERE/'materialize.py')
    inspector=importlib.util.module_from_spec(spec);spec.loader.exec_module(inspector)
    limits=dict(seconds=180,source_compressed=96*1024**2,source_bytes=512*1024**2,source_members=60000,source_file=64*1024**2)
    observed=inspector.inspect(bundle/'glibc-source.tar.gz',value['tree'],limits)
    need(value['source']==observed,'source receipt differs from complete verified tree')
    return value


def verify_sources(path,manifest,pin):
    path=ordinary(path);manifest=ordinary(manifest)
    need(sha(manifest)==pin,'reviewed source manifest differs')
    value=read_json(manifest)
    need(value['schema_version']==1 and bool({'runner.py','run.py'}&set(value['files'])),'source runner required')
    checked_files(path,value['files']);return value


def freeze(source,files,target,manifest=None):
    target.mkdir(mode=0o700)
    for name in files:shutil.copyfile(source/name,target/name)
    if manifest:shutil.copyfile(manifest,target/manifest.name)
    checked_files(target,files)


def process_module(path):
    need(sha(path)==RUNTIME,'held process ownership runtime required')
    spec=importlib.util.spec_from_file_location('glibc_process',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    original=module.resource;hard=original.getrlimit(original.RLIMIT_NOFILE)[1]
    need(hard==original.RLIM_INFINITY or hard>=8192,'8192 descriptor budget required')
    def setrlimit(kind,bounds):
        if kind==original.RLIMIT_NOFILE:
            need(bounds==(128,128),'held descriptor request changed');bounds=(8192,8192)
        return original.setrlimit(kind,bounds)
    module.resource=SimpleNamespace(**{**vars(original),'setrlimit':setrlimit});return module


def docker_args(image,name,token,work,bundle,source,lock,passwd,group,uid,gid,smoke):
    args=['docker','create','--name',name,'--label',LABEL+'='+token,'--pull=never','--platform=linux/arm64',
          '--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
          '--user',f'{uid}:{gid}','--pids-limit=1024','--memory=12g','--cpus=4',
          '--ulimit=nofile=8192:8192','--tmpfs=/tmp:rw,nosuid,nodev,exec,size=512m',
          '--env=CACHY_ASAHI_GLIBC_BUILD=1','--env=CACHY_ASAHI_GLIBC_RUNTIME_SMOKE=1','--env=SOURCE_DATE_EPOCH=1776591129']
    for original,target,ro in ((work,'/work',False),(bundle,'/inputs',True),(source,'/runner',True),(lock,'/expected-packages.lock',True),
                               (passwd,'/etc/passwd',True),(group,'/etc/group',True),(smoke,'/smoke',True)):
        args+=['--mount','type=bind,src='+str(original)+',dst='+target+(',readonly' if ro else '')]
    return args+['--entrypoint=/bin/bash',image,'/runner/build-entry.sh']


def runtime_receipt(path,manifest,source_files):
    receipt=read_json(path);spec=read_json(manifest,65536)
    need(receipt['status']=='PASS_OWNED_CANDIDATE_GLIBC_RUNTIME_SMOKE' and receipt['mode']=='NATIVE_EXECUTE' and
         receipt['host_architecture']=='aarch64' and receipt['input_sha256']==sha(manifest) and
         receipt['runtime']['status']=='PASS' and receipt['runtime']['cases']==8 and set(receipt['cases'])==CASES,
         'complete canonical native runtime receipt required')
    for name,row in receipt['sources'].items():
        need(name in source_files and all(row[key]==source_files[name][key] for key in ('sha256','bytes')),'smoke source receipt differs')
    need(set(receipt['sources'])=={'abi_smoke.c','exec_child.c','probe.c','probe.h','plugin.c','runner.py'},'canonical smoke source set differs')
    for role in ('loader','libc','libm'):
        need(receipt['candidate_roles'][role]['sha256']==spec[role]['sha256'],'candidate runtime role hash differs')
    need(len(receipt['runtime_files'])>=3 and receipt['runtime']['page_size']>0,'runtime file/page proof absent')
    return receipt


def smoke_script(package,recipe_hash):
    # Package filename was enumerated as one ordinary archive by the parent.
    package=shlex.quote('/work/artifacts/'+package)
    return '\n'.join(('set -euo pipefail',
        f'python3 /runner/stage.py --package {package} --recipe-sha256 {recipe_hash} --output /work/stage --manifest /work/runtime-inputs.json',
        'python3 /runner/abi.py --stage /work/stage/'+PREFIX+' --output /work/evidence/static-abi.json',
        'python3 /smoke/runner.py --inputs /work/runtime-inputs.json --workspace /work/runtime-smoke --execute',
        'pacman -Q | LC_ALL=C sort > /work/evidence/packages-runtime.lock',
        'diff -u /expected-packages.lock /work/evidence/packages-runtime.lock'))+'\n'


def execute(args,selected,smoke,harness,runtime):
    need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and os.getgid()==os.getegid() and
         not any(k.startswith('DOCKER_') for k in os.environ),'ordinary local native ARM execution required')
    base=ordinary(args.base_dir);bundle=ordinary(args.bundle);out=ordinary(args.output);source=ordinary(args.source_root)
    smoke_dir=ordinary(args.smoke_dir)
    need(not out.exists() and all(not out.is_relative_to(p) and not p.is_relative_to(out) for p in (bundle,base,source,smoke_dir,HERE)),
         'fresh separate output required')
    need(shutil.disk_usage(out.parent).free>=40*1024**3,'40GiB measured output reserve required')
    base_report=read_json(base/'report.json');image=(base/'image-id').read_text().strip();lock=base/'installed-packages.lock'
    need(base_report['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and re.fullmatch('sha256:[0-9a-f]{64}',image) and base_report['image']==image and
         sha(lock)==LOCK and len(lock.read_text().splitlines())==574,'accepted exact owned574 base required')
    token=uuid.uuid4().hex;out.mkdir(mode=0o700);(out/'home').mkdir();env=dict(ENV,HOME=str(out/'home'));containers=[];success=False
    report=dict(status='FAIL',scope='UNSELECTED_OWNED_GLIBC_SUCCESSOR',upstream=selected['commit'],source_tree=selected['tree'],
                old_binary_recipe='UNRESOLVED-no-waiver',base_image=image,base_lock_sha256=LOCK,ownership_token=token,hardware='NOT RUN',
                performance='NOT MEASURED',package_admission='NOT REQUESTED',builds=[],cleanup=[],
                source_bundle_manifest_sha256=args.bundle_manifest_sha256,harness_manifest_sha256=args.harness_manifest_sha256,
                smoke_manifest_sha256=SMOKE)
    process=runtime.Runner(19800,env,out/'logs')
    def command(argv,seconds=30):return process.run(list(map(str,argv)),timeout=seconds,limit=8*1024**2)
    def required(argv,seconds=30):
        row=command(argv,seconds);need(row.returncode==0,'owned command failed: '+str(argv[:3])+': '+row.stdout.decode('utf-8','replace')[-512:]);return row.stdout
    def inspected(name):
        row=command(['docker','container','inspect',name])
        if row.returncode:
            text=row.stdout.decode('utf-8','replace').lower()
            need(row.returncode==1 and name.lower() in text and ('no such object' in text or 'no such container' in text),'container state unknown');return None
        value=json.loads(row.stdout)[0];need(value['Config']['Labels'].get(LABEL)==token and value['Image']==image,'container ownership differs');return value
    try:
        freeze(bundle,selected['files'],out/'inputs',bundle/'bundle.json')
        freeze(HERE,harness['files'],out/'runner',HERE/'source-manifest.json')
        freeze(smoke_dir,smoke['files'],out/'smoke',args.smoke_manifest)
        shutil.copyfile(lock,out/'installed-packages.lock');need(sha(out/'installed-packages.lock')==LOCK,'frozen base lock differs');lock=out/'installed-packages.lock'
        need(required(['docker','context','show']).decode().strip()=='default','default Docker context required')
        context=json.loads(required(['docker','context','inspect','default']))[0]
        need(context['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock','local Docker daemon required')
        actual=json.loads(required(['docker','image','inspect',image]))[0]
        need(actual['Id']==image and actual['Architecture']=='arm64' and actual['Os']=='linux' and
             actual['Config']['Labels'].get('org.cachy-asahi.bootstrap574.job')==base_report['ownership']['token'],'owned ARM bootstrap image differs')
        probe='caa-glibc-'+token+'-probe';containers.append(probe)
        required(['docker','create','--name',probe,'--label',LABEL+'='+token,'--pull=never','--network=none','--read-only',
                  '--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=64','--memory=128m','--cpus=1',
                  '--entrypoint=/bin/bash',image,'-c',
                  'cat /etc/passwd; printf "\\n__GROUP__\\n"; cat /etc/group; printf "\\n__PACKAGES__\\n"; pacman -Q'])
        raw=required(['docker','start','-a',probe]);account,packages=raw.split(b'\n__PACKAGES__\n');passwd,group=account.split(b'\n__GROUP__\n')
        need(b''.join(line+b'\n' for line in sorted(packages.splitlines()))==lock.read_bytes(),'actual bootstrap inventory differs')
        uid,gid=os.getuid(),os.getgid()
        if not any(line.split(b':')[2]==str(uid).encode() for line in passwd.splitlines() if line):passwd+=f'caa-glibc:x:{uid}:{gid}::/work/home:/bin/bash\n'.encode()
        if not any(line.split(b':')[2]==str(gid).encode() for line in group.splitlines() if line):group+=f'caa-glibc:x:{gid}:\n'.encode()
        (out/'passwd').write_bytes(passwd);(out/'group').write_bytes(group)
        package_hashes=[]
        for side in ('a','b'):
            directory=out/side;directory.mkdir(mode=0o700);name='caa-glibc-'+token+'-'+side;containers.append(name)
            required(docker_args(image,name,token,directory,out/'inputs',out/'runner',lock,out/'passwd',out/'group',uid,gid,out/'smoke'))
            row=command(['docker','start','-a',name],8400);(out/(side+'-build.log')).write_bytes(row.stdout)
            item=dict(side=side,container=name,makepkg_exit=row.returncode,status='FAIL');report['builds'].append(item)
            need(row.returncode==0,'native makepkg/upstream tests failed; retain work evidence')
            tests=read_json(directory/'evidence/upstream-tests.json',32*1024**2)
            need(tests['status']=='PASS_UPSTREAM_APPLICABLE_TESTS' and tests['check_exit']==tests['abi_exit']==0 and
                 tests['counts']['PASS']>0 and all(tests['counts'][k]==0 for k in ('FAIL','XPASS','ERROR')) and not tests['malformed'],
                 'applicable upstream tests incomplete/failed')
            need((directory/'evidence/packages-before.lock').read_bytes()==(directory/'evidence/packages-after.lock').read_bytes()==lock.read_bytes(),'bootstrap inventory changed')
            artifacts=list((directory/'artifacts').glob('*.pkg.tar.xz'));need(len(artifacts)==1,'one separately named candidate package required')
            package=ordinary(artifacts[0]);need(package.is_file(),'ordinary candidate archive required')
            package_hashes.append(sha(package));item.update(package=package.name,sha256=package_hashes[-1],upstream_tests=tests['counts'])
            smoke_name=name+'-smoke';containers.append(smoke_name)
            smoke_args=docker_args(image,smoke_name,token,directory,out/'inputs',out/'runner',lock,out/'passwd',out/'group',uid,gid,out/'smoke')
            required(smoke_args[:-1]+['-c',smoke_script(package.name,sha(out/'inputs/PKGBUILD'))])
            smoke_row=command(['docker','start','-a',smoke_name],900);(out/(side+'-smoke.log')).write_bytes(smoke_row.stdout)
            need(smoke_row.returncode==0,'candidate ABI/runtime smoke failed')
            abi=read_json(directory/'evidence/static-abi.json');need(abi['status']=='PASS_STATIC_PUBLIC_ABI','public ABI failed')
            # Paths inside the canonical receipt are container paths. Manifest
            # bytes are joined by SHA, not rewritten into a different receipt.
            receipt=runtime_receipt(directory/'runtime-smoke/receipt.json',directory/'runtime-inputs.json',smoke['files'])
            need((directory/'evidence/packages-runtime.lock').read_bytes()==lock.read_bytes(),'runtime bootstrap inventory changed')
            item.update(status='PASS_NATIVE_BUILD_TEST_ABI_RUNTIME',static_abi=abi['status'],runtime=receipt['status'],runtime_receipt_sha256=sha(directory/'runtime-smoke/receipt.json'))
        report['archive_bytes_reproduced']=package_hashes[0]==package_hashes[1]
        need(report['archive_bytes_reproduced'],'clean build pair archives differ; no reproducibility credit')
        need(json.loads(required(['docker','image','inspect',image]))[0]['Id']==image,'borrowed bootstrap image differs')
        success=True
    except BaseException as error:report.update(error_type=type(error).__name__,error=str(error)[:512])
    finally:
        with runtime.defer_signals() as deferred:
            # Cleanup has its own finite reserve even if the build budget ended.
            process=runtime.Runner(900,env,out/'cleanup-logs')
            for name in reversed(containers):
                try:
                    value=inspected(name)
                    if value is not None:required(['docker','rm','-f',value['Id']],120)
                    need(inspected(name) is None,'owned container remains');report['cleanup'].append(dict(container=name,status='PASS-absence-verified'))
                except BaseException as error:report['cleanup'].append(dict(container=name,status='FAIL_OR_UNKNOWN',error=str(error)[:256]))
            try:
                report['source_bundle_preserved']=inputs(bundle,args.bundle_manifest_sha256)['files']==selected['files']
                checked_files(out/'inputs',selected['files']);checked_files(out/'runner',harness['files']);checked_files(out/'smoke',smoke['files'])
                report['frozen_sources_preserved']=True
            except BaseException as error:
                report['source_bundle_preserved']=False;report['preservation_error']=str(error)[:256];success=False
            if deferred:success=False;report['cleanup_signals']=deferred
            report['status']='PASS_UNSELECTED_NATIVE_PAIR' if success and all(row['status']=='PASS-absence-verified' for row in report['cleanup']) else 'FAIL'
            save(out/'result.json',report)
    print(json.dumps(report,sort_keys=True));return int(report['status']!='PASS_UNSELECTED_NATIVE_PAIR')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('bundle','base-dir','source-root','smoke-dir','smoke-manifest','output'):parser.add_argument('--'+key,type=Path,required=True)
    for key in ('bundle-manifest-sha256','harness-manifest-sha256'):parser.add_argument('--'+key,required=True)
    parser.add_argument('--execute',action='store_true');args=parser.parse_args()
    harness=verify_sources(HERE,HERE/'source-manifest.json',args.harness_manifest_sha256)
    selected=inputs(args.bundle,args.bundle_manifest_sha256)
    smoke=verify_sources(args.smoke_dir,args.smoke_manifest,SMOKE)
    if not args.execute:
        print(json.dumps(dict(status='VALIDATED_INPUTS_ONLY',source=selected['source'],native_build='NOT RUN')));return 0
    runtime=process_module(ordinary(args.source_root)/'scripts/port/kernel-native-job/runtime.py')
    with runtime.cancellation_handlers():return execute(args,selected,smoke,harness,runtime)


if __name__=='__main__':
    try:raise SystemExit(main())
    except (ValueError,OSError,KeyError) as error:
        print(json.dumps(dict(status='REFUSED_BEFORE_NATIVE_ACTORS',error_type=type(error).__name__,error=str(error)[:256])));raise SystemExit(1)

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite PGO construction inside the explicit offline native builder only."""
import argparse,gzip,hashlib,importlib.util,json,os,platform,re,shlex,shutil,signal,stat,sys,time,zlib
from pathlib import Path
sys.dont_write_bytecode=True
SOURCE_SHA='bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16'
WORK=Path('/tmp/build');PROFILE=Path('/tmp/profile')
PREFIX='/usr/lib/cachy-asahi/experiments/zlib-pgo-v1'
BASE='-O2 -g -march=armv8-a -mtune=generic -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -frandom-seed=$@ -fno-lto'
LINK='-pie -Wl,-z,relro,-z,now,-z,max-page-size=65536,-z,common-page-size=16384 -fno-lto'
GENERATE=' -fprofile-generate=/tmp/profile -fprofile-reproducible=serial'
USE=' -fprofile-use=/tmp/profile -Werror=missing-profile -Werror=coverage-mismatch'
LOCALS={'arm_c01.py','corpus.py','pgo.py','supervisor.py','probe.c','strict-gzip.c','LICENSE.project','training.bin','validation.bin','corpus-policy.json','corpus_controls.py','profile_seal.py','pipeline.py'}
PAYLOAD=('libz.a','minigzip','example','probe','strict-gzip','zlib.h','zconf.h','LICENSE')
TOOLS=('gcc','gcc-ar','gcc-ranlib','ld','gcov-tool','make','as')

def need(ok,why):
    if not ok:raise ValueError(why)

def encoded(value):return (json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return dict(bytes=len(raw),sha256=sha(raw))

def read(path,cap=16*1024**2):
    path=Path(path);info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=cap and not any(p.is_symlink()for p in(path,*path.parents)),'bounded ordinary single-link input: '+str(path))
    raw=path.read_bytes();need(len(raw)==info.st_size,'input changed while read');return raw

def ordinary(path):
    path=Path(path).absolute();need('..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary absolute path');return path

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module

def inputs(root):
    root=ordinary(root);policy=json.loads(read(root/'recipe-policy.json'))
    need(set(policy)=={'schema','source_sha256','local_files','training','validation','training_seconds','build_seconds','job_seconds'} and policy['schema']==1 and policy['source_sha256']==SOURCE_SHA,'closed recipe policy')
    need(policy['training_seconds']==120 and policy['build_seconds']==180 and policy['job_seconds']==1200,'fixed finite budgets')
    need(set(policy['local_files'])==LOCALS,'complete local source closure')
    for name,row in policy['local_files'].items():need(pin(read(root/name))==row,'local source pin: '+name)
    need(sha(read(root/'zlib-1.3.2.tar.gz',8*1024**2))==SOURCE_SHA,'pinned upstream source archive')
    for role in ('training','validation'):
        row=policy[role];need(set(row)=={'path','bytes','sha256'} and row['path']==role+'.bin' and pin(read(root/row['path']))=={k:row[k]for k in('bytes','sha256')},'frozen '+role+' bytes')
    need(policy['training']['sha256']!=policy['validation']['sha256'],'disjoint training and validation bytes');return policy

def environment(cflags=BASE,ldflags=LINK):
    return dict(PATH='/usr/bin:/bin',HOME='/tmp/build-home',TMPDIR='/tmp',LC_ALL='C',LANG='C',TZ='UTC',SOURCE_DATE_EPOCH='1791748800',PYTHONDONTWRITEBYTECODE='1',CC='gcc',AR='gcc-ar',RANLIB='gcc-ranlib',CPPFLAGS='',CFLAGS=cflags,LDFLAGS=ldflags,MAKEFLAGS='-j2',QEMU_RUN='')

def training_plan(output):
    output=Path(output)
    return [dict(label='train-encode',argv=[str(WORK/'minigzip'),'-6'],input='training.bin',output='train.gz'),dict(label='train-decode',argv=[str(WORK/'minigzip'),'-d'],input='train.gz',output='train.decoded'),dict(label='train-example',argv=[str(WORK/'example'),str(output/'example.gz')],input=None,output=None),dict(label='train-gun',argv=[str(WORK/'gun')],input='train.gz',output='gun.decoded')]

def apply_use_flags(makefile,configure_log,core):
    raw=read(makefile);log=read(configure_log);baseline=core.configured_flags(raw,log,'baseline');suffix=shlex.split(baseline['CFLAGS'])[len(shlex.split(BASE)):]
    need(suffix and suffix[0]=='-fPIC','configure feature suffix');text=raw.decode()
    for name,value in [('CFLAGS',BASE+USE+' '+' '.join(suffix)),('LDFLAGS',LINK+USE)]:
        text,count=re.subn(r'(?m)^('+name+r'[ \t]*=[ \t]*)[^\n]*$',lambda m:m[1]+value,text);need(count==1,'one profile-use assignment: '+name)
    makefile.write_text(text);return core.configured_flags(read(makefile),log,'pgo')

def guard():
    need(platform.machine()=='aarch64' and os.geteuid()>0 and os.environ.get('CACHY_ASAHI_CONTAINER')=='1' and Path('/.dockerenv').is_file(),'explicit ordinary-user native isolated builder required')
    need(not WORK.exists() and not PROFILE.exists(),'fresh fixed build/profile paths required')
    need(Path('/out').is_dir() and not Path('/out/pgo-v1-evidence').exists(),'fresh retained builder evidence destination')

class Runner:
    def __init__(self,supervisor,output,seconds=1200):
        self.output=output;output.mkdir(mode=0o700);self.command=supervisor.Commands(output,seconds=seconds,builder_uid=os.geteuid())
    def run(self,label,argv,*,env=None,data=None,cwd=None,timeout=180,expected=0):
        result=self.command.run(label,argv,cwd=cwd,env=environment()if env is None else env,data=data,timeout=timeout,expected=expected);record=self.command.rows[-1]
        need(record['group_absent']is True and record['leader_held_until_group_inspection']is True and 'cleanup_error'not in record,'owned live group cleanup');return result
    def diagnostics(self):return read(self.output/self.command.rows[-1]['log'],16*1024**2)

def toolchain(runner):
    result={};target=runner.run('tool-target',['gcc','-dumpmachine']).decode().strip();need(re.fullmatch(r'aarch64[-A-Za-z0-9_.]*linux[-A-Za-z0-9_.]*',target),'native GCC AArch64 Linux target')
    for name in TOOLS:
        path=shutil.which(name,path='/usr/bin:/bin');need(path is not None,'required native tool: '+name);resolved=Path(path).resolve();raw=read(resolved,256*1024**2)
        version=runner.run('tool-'+name,[str(resolved),'--version']).decode().strip();need(version,'nonempty native tool version');result[name]=dict(path=path,resolved_path=str(resolved),**pin(raw),version=version)
    for name,option in [('cc1','-print-prog-name=cc1'),('collect2','-print-prog-name=collect2'),('libgcov.a','-print-file-name=libgcov.a')]:
        path=runner.run('tool-path-'+name.replace('.','-'),['gcc',option]).decode().strip();need(Path(path).is_absolute(),'GCC companion absolute path');resolved=Path(path).resolve();result[name]=dict(path=path,resolved_path=str(resolved),**pin(read(resolved,256*1024**2)),version='gcc-derived '+name)
    return dict(target=target,tools=result)

def source_map(directory):return {'upstream/'+p.relative_to(directory).as_posix():pin(read(p,8*1024**2))for p in sorted(directory.rglob('*'))if not p.is_dir()}

def fresh_source(root,core,expected=None):
    need(not WORK.exists(),'fresh same absolute source/build path');WORK.mkdir(mode=0o700);core.extract(root/'zlib-1.3.2.tar.gz',WORK);mapping=source_map(WORK)
    if expected is not None:need(mapping==expected,'clean source path/bytes identity')
    return mapping

def build_static(runner,phase,cflags,ldflags,core,use=False):
    runner.run('build-'+phase+'-configure',['./configure','--static','--prefix='+PREFIX],cwd=str(WORK),env=environment()if use else environment(cflags,ldflags))
    effective=apply_use_flags(WORK/'Makefile',WORK/'configure.log',core)if use else None
    runner.run('build-'+phase+'-static',['make','-j2','static'],cwd=str(WORK),env=environment(cflags,ldflags))
    profile_diagnostics(runner.diagnostics());return effective

def profile_diagnostics(raw):
    # Echoed -Werror=coverage-mismatch flags are commands, not diagnostics.
    need(not re.search(r'(?im)^[^\n]*\b(?:warning|error|fatal error):[^\n]*(?:profile|coverage)|^libgcov profiling error:',raw.decode()),'profile fallback/diagnostic refused')

def auxiliary(runner,root,phase):
    for name in ('probe','strict-gzip'):
        runner.run('build-'+phase+'-'+name+'-compile',['gcc',*shlex.split(BASE.replace('$@',name+'.o')),'-I'+str(WORK),'-DEXPERIMENT_VARIANT="pgo-v1"','-DEXPERIMENT_PREFIX="'+PREFIX+'"','-c',str(root/(name+'.c')),'-o',str(WORK/(name+'.o'))])
        runner.run('build-'+phase+'-'+name+'-link',['gcc',str(WORK/(name+'.o')),str(WORK/'libz.a'),'-o',str(WORK/name),*shlex.split(LINK)])

def correctness(runner,output,validation):
    roots=[output/'optimized-1',output/'optimized-2'];counts=dict(encodes=0,cross_decodes=0,strict_rejections=0,probes=0)
    data=[b'',b'x',b'cachy-asahi public workload\n'*4096,bytes(range(256))*1024]
    data += [bytes((i*13+i//257)&255 for i in range(n))for n in(16383,16384,16385)];data.append(validation)
    for index,root in enumerate(roots):
        probe=json.loads(runner.run('validate-probe-'+str(index),[str(root/'probe'),'--build-check'],timeout=15))
        need(probe==dict(status='PASS',variant='pgo-v1',prefix=PREFIX,zlib='1.3.2',source_sha256=SOURCE_SHA,roundtrips=21,negative_checks=42),'finite built probe identity');counts['probes']+=1
        for i,original in enumerate(data):
            for level in (1,6,9):
                label=f'validate-{index}-{i}-{level}';packed=runner.run(label+'-encode',[str(root/'minigzip'),'-'+str(level)],data=original,timeout=15)
                decoder=zlib.decompressobj(31);decoded=decoder.decompress(packed)+decoder.flush();need(decoded==original and decoder.eof and not decoder.unused_data,'independent Python whole-stream decode');counts['encodes']+=1
                for j,consumer in enumerate(roots):
                    decoded=runner.run(label+'-decode-'+str(j),[str(consumer/'strict-gzip')],data=packed,timeout=15);need(decoded==original,'cross-build strict decode');counts['cross_decodes']+=1
    reference=gzip.compress(data[2],mtime=0);bad=bytearray(reference);bad[-8]^=1
    for index,root in enumerate(roots):
        for i,invalid in enumerate((bytes(bad),reference[:-8],reference+b'garbage')):
            runner.run(f'validate-{index}-reject-{i}',[str(root/'strict-gzip')],data=invalid,expected=2,timeout=15);counts['strict_rejections']+=1
    return dict(**counts,input_pins=[pin(d)for d in data],includes_page_boundaries=[16383,16384,16385],physical16k='NOT RUN')

def retain_failed_profiles(directory,output):
    """Keep malformed/incomplete native counters as DATA before owned cleanup."""
    destination=output/'failed-profiles';destination.mkdir(mode=0o700);rows={};total=0
    entries=sorted(directory.iterdir());need(len(entries)<=4096,'failed profile leaf bound')
    for path in entries:
        try:
            body=read(path,4*1024**2);total+=len(body);need(total<=16*1024**2,'failed profile byte bound')
            (destination/path.name).write_bytes(body);rows[path.name]=pin(body)
        except(OSError,ValueError)as error:
            rows[path.name]=dict(retained=False,error_type=type(error).__name__,error=str(error)[:1024])
    (output/'failed-profile-inventory.json').write_bytes(encoded(rows));return rows

def construct(root,output):
    policy=inputs(root);root=ordinary(root);output=ordinary(output);guard()
    need(not output.exists() and output.parent.is_dir() and not root.is_relative_to(output),'fresh disjoint result directory');output.mkdir(mode=0o700)
    # Every imported helper is covered by the already reviewed local-source policy.
    load('corpus',root/'corpus.py');core=load('_pgo_core',root/'arm_c01.py');core.select_experiment('ARM-C03')
    old=load('_pgo_reference',root/'pgo.py');supervisor=load('_pgo_supervisor',root/'supervisor.py');seal=load('_pgo_seal',root/'profile_seal.py');corpora=load('_pgo_corpora',root/'corpus_controls.py');corpora.validate(root)
    runner=Runner(supervisor,output/'commands');prior={s:signal.signal(s,runner.command.cancel)for s in(signal.SIGINT,signal.SIGTERM)}
    report=dict(status='FAIL',source_sha256=SOURCE_SHA,hardware='NOT RUN',physical16k='NOT RUN',performance='NOT MEASURED',release='NOT_ADMITTED');made_work=False;made_profile=False
    try:
        observed=toolchain(runner);mapping=fresh_source(root,core);made_work=True;PROFILE.mkdir(mode=0o700);made_profile=True
        build_static(runner,'instrumented',BASE+GENERATE,LINK+GENERATE,core)
        runner.run('build-training-gun-compile',old._gun_compile(core),cwd=str(WORK))
        runner.run('build-training-gun-link',['gcc',str(WORK/'gun.o'),str(WORK/'libz.a'),'-o',str(WORK/'gun'),*shlex.split(LINK+GENERATE)],cwd=str(WORK))
        instrumented=output/'instrumented';instrumented.mkdir(mode=0o700)
        for name in ('libz.a','example','minigzip','gun','gun.o','Makefile','configure.log'):shutil.copyfile(WORK/name,instrumented/name)
        # Discard configure/build-probe counters. No heldout/correctness input has run.
        shutil.rmtree(PROFILE);PROFILE.mkdir(mode=0o700);plan=training_plan(output);training_results=[];began=time.monotonic()
        for row in plan:
            budget=120-(time.monotonic()-began);need(budget>0,'aggregate deterministic training deadline')
            source=root/'training.bin'if row['input']=='training.bin'else output/row['input']if row['input']else None
            raw=runner.run(row['label'],row['argv'],data=read(source)if source else None,cwd=str(WORK),timeout=budget)
            if row['output']:(output/row['output']).write_bytes(raw)
            training_results.append(dict(label=row['label'],stdout=pin(raw)))
        train=read(root/'training.bin');need(read(output/'train.decoded')==read(output/'gun.decoded')==train,'training exact roundtrips')
        decoder=zlib.decompressobj(31);need(decoder.decompress(read(output/'train.gz'))+decoder.flush()==train and decoder.eof and not decoder.unused_data,'independent training decode')
        need(zlib.decompress(read(output/'example.gz'),31)==b'hello, hello!\0','pinned upstream example fixed literals')
        native_profiles=old.profile_map(core,PROFILE);decoded=output/'decoded-profiles'
        runner.run('build-training-profile-decode',['gcov-tool','merge','-v','-w','1,1','-o',str(decoded),str(PROFILE),str(PROFILE)])
        old.check_profile_output(core,runner.diagnostics());old.profile_map(core,decoded);need(old.profile_map(core,PROFILE)==native_profiles,'decoder must not mutate original profiles')
        (output/'training-results.json').write_bytes(encoded(dict(plan=plan,results=training_results,profiles=native_profiles,instrumented={p.name:pin(read(p))for p in instrumented.iterdir()})))
        binding=dict(source_sha256=SOURCE_SHA,source_files={**mapping,**{'local/'+n:r for n,r in policy['local_files'].items()}},toolchain=observed,isa='armv8-a/generic',build_path=str(WORK),profile_path=str(PROFILE),prefix=PREFIX,
            training=dict(corpus=policy['training'],heldout=policy['validation'],command_plan_sha256=sha(encoded(plan)),results_sha256=sha(read(output/'training-results.json'))))
        sealed=seal.seal(PROFILE,binding,output/'profile-seal.json');original_seal=sealed['seal_sha256'];shutil.copytree(PROFILE,output/'profiles');shutil.rmtree(WORK);made_work=False
        effective=[];outputs=[]
        for attempt in (1,2):
            inputs(root);need(toolchain(runner)==observed,'exact training/use toolchain identity');seal.verify(PROFILE,binding,output/'profile-seal.json',expected_sha256=original_seal)
            fresh_source(root,core,mapping);made_work=True;effective.append(build_static(runner,'optimized-'+str(attempt),BASE+USE,LINK+USE,core,use=True))
            runner.run('build-optimized-'+str(attempt)+'-upstream-test',['make','teststatic'],cwd=str(WORK),env=environment(BASE+USE,LINK+USE));auxiliary(runner,root,'optimized-'+str(attempt))
            dest=output/('optimized-'+str(attempt));dest.mkdir(mode=0o700)
            for name in PAYLOAD:shutil.copyfile(WORK/name,dest/name)
            for name in ('minigzip','example','probe','strict-gzip'):(dest/name).chmod(0o755)
            for name in ('Makefile','configure.log'):shutil.copyfile(WORK/name,dest/(name+'.txt'))
            symbols=runner.run('build-optimized-'+str(attempt)+'-symbols',['gcc-nm',str(dest/'libz.a')]);need(b'__gcov_'not in symbols,'instrumented runtime survived profile-use build')
            elf=runner.run('elf-optimized-'+str(attempt),['readelf','-W','-h','-l',str(dest/'minigzip')]);need(b'AArch64'in elf,'native AArch64 ELF observation')
            outputs.append({n:pin(read(dest/n))for n in PAYLOAD});need(toolchain(runner)==observed,'toolchain changed during optimized build');seal.verify(PROFILE,binding,output/'profile-seal.json',expected_sha256=original_seal)
            shutil.rmtree(WORK);made_work=False
        need(outputs[0]==outputs[1],'two clean optimized payload builds differ');validation=correctness(runner,output,read(root/'validation.bin'));seal.verify(PROFILE,binding,output/'profile-seal.json',expected_sha256=original_seal)
        report.update(status='PASS_FINITE_PGO_CONSTRUCTION_AND_NATIVE_CORRECTNESS_ONLY',binding=binding,profile_seal_sha256=original_seal,outputs=outputs,effective_flags=effective,correctness=validation,native_page_size=os.sysconf('SC_PAGE_SIZE'),recipe_policy=pin(read(root/'recipe-policy.json')),profile_decode='GCC_NATIVE_DECODER_TRANSCRIPT_MATCHED',training_attempts=1,optimized_clean_builds=2,profile_use='SAME_SEALED_PROFILE_BOTH_BUILDS_NO_FALLBACK',optimization_acceptance='NOT RUN')
        return report
    except BaseException as error:
        report.update(error_type=type(error).__name__,error=str(error));raise
    finally:
        for sig,handler in prior.items():signal.signal(sig,handler)
        if report['status']=='FAIL' and made_profile and PROFILE.exists():
            report['failed_profiles']=retain_failed_profiles(PROFILE,output)
        if made_work:shutil.rmtree(WORK)
        if made_profile and PROFILE.exists():shutil.rmtree(PROFILE)
        (output/'result.json').write_bytes(encoded(report))
        leaves={p.relative_to(output).as_posix():pin(read(p,64*1024**2))for p in output.rglob('*')if p.is_file()}
        need(len(leaves)<=4096 and sum(r['bytes']for r in leaves.values())<=128*1024**2,'closed native evidence cap')
        (output/'receipt.json').write_bytes(encoded(dict(schema=1,status=report['status'],files=leaves,acceptance=False,performance='NOT MEASURED',hardware='NOT RUN')))
        shutil.copytree(output,Path('/out/pgo-v1-evidence'))

def check(output,root=None):
    output=ordinary(output);report=json.loads(read(output/'result.json',32*1024**2));need(report['status']=='PASS_FINITE_PGO_CONSTRUCTION_AND_NATIVE_CORRECTNESS_ONLY' and report['optimized_clean_builds']==2,'complete native construction required')
    if root is not None:
        policy=inputs(root);need(pin(read(Path(root)/'recipe-policy.json'))==report['recipe_policy'],'used recipe policy unchanged before packaging')
        need(all(report['binding']['source_files']['local/'+n]==p for n,p in policy['local_files'].items()),'used local sources unchanged before packaging')
    receipt=json.loads(read(output/'receipt.json'));leaves={p.relative_to(output).as_posix():pin(read(p,64*1024**2))for p in output.rglob('*')if not p.is_dir()and p!=output/'receipt.json'}
    need(len(leaves)<=4096 and sum(r['bytes']for r in leaves.values())<=128*1024**2,'closed passive evidence cap')
    need(set(receipt)=={'schema','status','files','acceptance','performance','hardware'} and receipt['schema']==1 and receipt['files']==leaves and receipt['status']==report['status'] and receipt['acceptance']is False,'complete retained native evidence receipt')
    for attempt,expected in enumerate(report['outputs'],1):need({n:pin(read(output/('optimized-'+str(attempt))/n))for n in PAYLOAD}==expected,'optimized payload pin differs')
    need(report['outputs'][0]==report['outputs'][1] and sha(read(output/'profile-seal.json'))==report['profile_seal_sha256'],'same payload/seal proof')
    source=Path(__file__).resolve().parent/'profile_seal.py'
    need(pin(read(source))==report['binding']['source_files']['local/profile_seal.py'],'retained profile validator source identity')
    validator=load('_pgo_check_seal',source);validator.verify(output/'profiles',report['binding'],output/'profile-seal.json',expected_sha256=report['profile_seal_sha256'])
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('build','check'));p.add_argument('--inputs',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:
        if a.action=='build':need(a.inputs is not None,'explicit input root');r=construct(a.inputs,a.output)
        else:r=check(a.output,a.inputs)
        print(json.dumps(dict(status=r['status'],hardware='NOT RUN',performance='NOT MEASURED',release='NOT_ADMITTED'),sort_keys=True));return 0
    except(OSError,ValueError,KeyError,TypeError)as error:print('PGO construction refused: '+str(error),file=sys.stderr);return 1

if __name__=='__main__':raise SystemExit(main())

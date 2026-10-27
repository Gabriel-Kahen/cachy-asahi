#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact accepted installable C01 inputs for a generic hosted ARM paired experiment."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import stat
import subprocess
import sys
import time
import zlib

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
LANE=ROOT/'scripts/ci/c01-native-paired-runtime'
SCOPE='GENERIC_HOSTED_ARM_C01_INSTALLABLE'
ACCEPTED_SHA='ae05159b0c64dd6dba1ba06a3a63c15e9df84e1a9ce321f7909164e8a53938ea'
CORPUS_SHA='c3708109ec6461fc1b496eefe720080651acd3c7350b47c253b743f6490508b9'
PROFILE_SHA='817c7da5a962251d0b4e4cd9f65a14b518959fe2e2ad15f82ef04c3328d027e0'
BASE_SHA='fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
ORDER=['baseline','candidate','candidate','baseline','candidate','baseline','baseline','candidate','baseline','candidate','candidate','baseline']


def need(ok,why):
    if not ok:raise ValueError(why)


def sha(body):return hashlib.sha256(body).hexdigest()


def read(path,limit=16*1024**2):
    path=Path(path)
    need(path.is_absolute() and not any(p.is_symlink() for p in (path,*path.parents)), 'ordinary absolute input')
    info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=limit,'bounded regular input')
    return path.read_bytes()


def pinned(path,pin):
    raw=read(path);need(sha(raw)==pin,'fixed input pin differs: '+str(path));return json.loads(raw)


def profile():
    p=pinned(LANE/'profile.json',PROFILE_SHA)
    need(p['measurement_scope']==SCOPE and p['execution_context']=='virtual' and p['order']==ORDER
         and p['payload_bytes']==16*1024**2 and p['iterations']==4 and p['minimum_trials']==6
         and p['trial_seconds']==45 and p['session_seconds']==900 and p['sample_seconds']==0.1
         and all(p[k] is None for k in ('current_source','current_run','current_image')), 'fixed hosted experiment profile')
    return p


def accepted():
    a=pinned(LANE/'accepted-inputs.json',ACCEPTED_SHA)
    need(a['purpose']=='C01_ACCEPTED_INSTALLABLE_PAIRED_RUNTIME_INPUTS' and a['measurement_scope']==SCOPE
         and set(a['packages'])=={'baseline','candidate'} and a['source_sha256']=='bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16', 'accepted input role')
    origin=a['accepted_component'];qraw=read(ROOT/origin['qualification_path'])
    need(len(qraw)==origin['qualification']['bytes'] and sha(qraw)==origin['qualification']['sha256'],'Root component qualification pin')
    q=json.loads(qraw)
    need(q['status']=='ROOT_ACCEPTED_FINITE_SINGLE_CONSUMER_NATIVE_C01_INSTALLABLE_COMPONENT_ONLY'
         and q['source']==origin['source']=='d33e595a10acf2d148752ea382ae607283fc0b73'
         and q['run']==origin['run']==40468241048 and q['artifact']==origin['artifact']==12717726584,'exact accepted component origin')
    need(sha(read(ROOT/a['base_inventory']['path']))==a['base_inventory']['sha256']==BASE_SHA,'original341 inventory')
    for logical,v in [('baseline','baseline'),('candidate','lto')]:
        row=a['packages'][logical]
        need(row['name']=='cachy-asahi-zlib-'+v and row['variant']==v and row['version']=='1.3.2-2' and row['arch']=='aarch64','exact accepted package identity')
        for name,p in row['programs'].items():
            need(name in ('minigzip','probe','strict-gzip') and p['path']=='/usr/lib/cachy-asahi/experiments/zlib-'+v+'/bin/'+name,'exact private program identity')
    return a


def archives():
    """Read exact local accepted bytes; never acquire/extract/build/install."""
    spec=importlib.util.spec_from_file_location('_accepted_c01_package_source',ROOT/'scripts/experiments/package_variants.py')
    helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    a=accepted();result={}
    for logical,row in a['packages'].items():
        raw=read(ROOT/row['archive']);need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'exact accepted archive bytes')
        members=helper.package_members(raw,row['variant'])
        need({p:sha(b) for p,b in members.items() if p not in helper.META}==row['payload'],'accepted payload correspondence')
        need(b'pkgver = 1.3.2-2\n' in members['.PKGINFO'],'accepted version2 metadata')
        own='usr/lib/cachy-asahi/experiments/zlib-'+row['variant']
        need(helper.configured_flags(members[own+'/build/Makefile'],row['variant'])==row['configured_flags'],'accepted effective compiler flags')
        result[logical]=members
    return a,result


def installed(a=None,full=False):
    a=accepted() if a is None else a
    for row in a['packages'].values():
        for program in row['programs'].values():
            raw=read(Path(program['path']));need(len(raw)==program['bytes'] and sha(raw)==program['sha256'] and os.access(program['path'],os.X_OK),'installed exact executable identity')
    if full:
        _,members=archives()
        for rows in members.values():
            for path,body in rows.items():
                if path not in ('.PKGINFO','.BUILDINFO','.MTREE'):
                    need(read(Path('/'+path))==body,'installed corresponding payload differs: '+path)
    return a


def materials(root,archive_manifest,experiment=None):
    need(Path(root).resolve()==LANE and Path(archive_manifest).resolve()==LANE/'accepted-inputs.json','fixed installed profile paths')
    a=installed();m=pinned(LANE/'corpus/manifest.json',CORPUS_SHA);raw=read(LANE/'corpus/mixed.bin',8*1024**2)
    need(len(raw)==m['bytes']==4*1024**2 and sha(raw)==m['sha256'],'fixed mixed public corpus')
    need(experiment in (None,'ARM-C01'),'installed C01 experiment selection')
    return 'ARM-C01',LANE,raw


def bounds(payload_bytes,iterations):
    p=profile();need(type(payload_bytes)is int and payload_bytes==p['payload_bytes']
                    and type(iterations)is int and iterations==p['iterations'],'fixed16MiB/four-roundtrip profile')


def validate_plan(plan):
    c=plan['config'];p=profile();a=accepted()
    need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0
         and Path('/.dockerenv').is_file() and os.environ.get('CACHY_ASAHI_DISPOSABLE_BENCHMARK')=='1','explicit ordinary disposable native ARM measurement')
    need(c.get('measurement_scope')==SCOPE and c['execution_context']=='virtual' and not c.get('hardware_gate_evidence')
         and c['order']==p['order'] and c['minimum_trials']==6 and c['timeout_seconds']==45
         and c['sample_seconds']==0.1 and c['thresholds']==p['thresholds'] and not c.get('allowed_state_changes'),'fixed generic hosted profile; no physical admission')
    need(all(s['architecture']=='aarch64' and s['execution_context']=='virtual' for s in plan['states'].values()),'native generic state records')
    expected=[str(Path(sys.executable).resolve()),'-B',str(Path(__file__).resolve()),'run',
        '--archive-manifest',str(LANE/'accepted-inputs.json'),'--corpus-manifest',str(LANE/'corpus/manifest.json'),
        '--input',str(LANE/'corpus/mixed.bin'),'--payload-bytes',str(p['payload_bytes']),'--iterations',str(p['iterations'])]
    need(c['argv']==expected,'closed installed workload argv')
    for v in ('baseline','candidate'):
        need(c['change'][v]==a['packages'][v]['programs']['minigzip']['path'],'exact accepted installed variant')
    _,_,_=materials(LANE,LANE/'accepted-inputs.json')
    required={str(Path(sys.executable).resolve()),str(Path(__file__).resolve()),str(LANE/'accepted-inputs.json'),str(LANE/'profile.json'),str(LANE/'corpus/manifest.json'),str(LANE/'corpus/mixed.bin')}
    need(required<=set(c['inputs']),'complete fixed workload/profile/corpus pins')


def noise():
    result={}
    for name,path in [('loadavg','/proc/loadavg'),('cpu_stat','/proc/stat'),('cgroup_cpu_stat','/sys/fs/cgroup/cpu.stat'),('cgroup_cpu_max','/sys/fs/cgroup/cpu.max'),('cgroup_memory_max','/sys/fs/cgroup/memory.max')]:
        try:result[name]=Path(path).read_text()[:32768]
        except (OSError,UnicodeError):result[name]=None
    result['monotonic_ns']=time.monotonic_ns();result['affinity']=sorted(os.sched_getaffinity(0))
    result['scope']='read-only observations; host tenancy/frequency not controlled'
    return result


def run_workload(args):
    bounds(args.payload_bytes,args.iterations)
    need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0
         and os.environ.get('CACHY_ASAHI_DISPOSABLE_BENCHMARK')=='1','explicit native ordinary hosted workload')
    _,_,heldout=materials(LANE,args.archive_manifest)
    need(args.corpus_manifest.resolve()==LANE/'corpus/manifest.json' and args.input.resolve()==LANE/'corpus/mixed.bin','fixed corpus argv')
    a=accepted();selected=os.environ.get('ZLIB_MINIGZIP','');allowed={r['programs']['minigzip']['path'] for r in a['packages'].values()}
    need(selected in allowed and not any(k.startswith(('LD_','DYLD_','QEMU_')) for k in os.environ),'fixed executable and loader environment')
    cwd=Path.cwd();need(not any(cwd.iterdir()),'fresh workload cwd')
    payload=(heldout*((args.payload_bytes+len(heldout)-1)//len(heldout)))[:args.payload_bytes]
    source=cwd/'payload.bin';source.write_bytes(payload);checks=[];timings=[];before=noise();cpu_start=time.process_time_ns()
    try:
        for iteration in range(args.iterations):
            encoded,decoded=cwd/'encoded.gz',cwd/'decoded.bin'
            for phase,argv,stdin_path,target in [('encode',[selected,'-6'],source,encoded),('decode',[selected,'-d'],encoded,decoded)]:
                errors=cwd/f'{iteration:02d}-{phase}.stderr'
                with stdin_path.open('rb') as stdin,target.open('xb') as stdout,errors.open('xb') as stderr:
                    r0=resource.getrusage(resource.RUSAGE_CHILDREN);t0=time.monotonic_ns()
                    completed=subprocess.run(argv,stdin=stdin,stdout=stdout,stderr=stderr,timeout=40)
                    t1=time.monotonic_ns();r1=resource.getrusage(resource.RUSAGE_CHILDREN)
                need(completed.returncode==0 and read(errors,65536)==b'','exact codec successful exit/no stderr')
                timings.append(dict(iteration=iteration,phase=phase,argv=argv,returncode=completed.returncode,
                    monotonic_start_ns=t0,monotonic_end_ns=t1,elapsed_ns=t1-t0,
                    waited_children_user_seconds=r1.ru_utime-r0.ru_utime,waited_children_system_seconds=r1.ru_stime-r0.ru_stime,
                    cpu_scope='waited codec child; resource.RUSAGE_CHILDREN delta, not system CPU'))
            compressed=read(encoded,65*1024**2);output=read(decoded,64*1024**2)
            independent=zlib.decompressobj(31);plain=independent.decompress(compressed,len(payload)+1)
            need(output==payload and plain==payload and independent.eof and not independent.unused_data and not independent.unconsumed_tail,'both exact gzip roundtrips')
            checks.append(dict(iteration=iteration,encoded_sha256=sha(compressed),decoded_sha256=sha(output),encoded_bytes=len(compressed),decoded_bytes=len(output),independent_python_decode='PASS'))
            encoded.unlink();decoded.unlink()
        report=dict(status='PASS',experiment='ARM-C01',material_profile=SCOPE,minigzip=selected,minigzip_sha256=sha(read(Path(selected))),
            accepted_inputs_sha256=ACCEPTED_SHA,heldout_sha256=sha(heldout),payload_sha256=sha(payload),payload_bytes=len(payload),iterations=args.iterations,
            compression_level=6,checks=checks,phase_timings=timings,driver_cpu_ns=time.process_time_ns()-cpu_start,
            driver_cpu_scope='Python process CPU after prepared payload through roundtrip verification; input preparation and final unlink excluded',
            noise_before=before,noise_after=noise(),timing_scope='whole driver includes validation/startup/file I/O/verification; phase wall/CPU are separate raw observations',
            hardware_validation='NOT RUN',optimization_acceptance='NOT RUN',generic16k_execution='NOT RUN',release='NOT_ADMITTED')
        print(json.dumps(report,sort_keys=True));return report
    finally:
        # Fixed bytes remain derivable from pinned corpus; do not retain18x16MiB payload copies.
        for path in (source,cwd/'encoded.gz',cwd/'decoded.bin'):
            path.unlink(missing_ok=True)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('run',))
    for name in ('archive-manifest','corpus-manifest','input'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--payload-bytes',type=int,required=True);p.add_argument('--iterations',type=int,required=True)
    a=p.parse_args()
    try:run_workload(a);return 0
    except (OSError,ValueError,KeyError,subprocess.SubprocessError,zlib.error) as error:
        print('installed C01 workload refused: '+str(error),file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact accepted private packages in one disposable original341 benchmark container."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import pwd
import signal
import sys
from types import SimpleNamespace
ROOT=Path('/inputs');LANE=ROOT/'scripts/ci/c01-native-paired-runtime';OUT=Path('/out')
sys.path.insert(0,str(ROOT/'scripts/benchmarks'))
import benchmark as B
import installed_zlib as I
import paired_zlib as P


def need(ok,why):
    if not ok:raise ValueError(why)


def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def helper_module():
    spec=importlib.util.spec_from_file_location('_accepted_package_helper',ROOT/'scripts/experiments/package_variants.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def config(run_id):
    p=I.profile();a=I.accepted();python=str(Path(sys.executable).resolve())
    controls=dict(power_source='hosted VM; physical power unavailable',display_config='headless private container',brightness='not applicable; no display',cache_mode='no flush; shared warm filesystem/input cache; balanced declared order',background_load='host tenancy/frequency uncontrolled; raw load/CPU/cgroup records',warmup='two correctness slots then one excluded ABBA warmup block',ambient_C=None,thermal_start_C=None,battery_soc_percent=None)
    return dict(experiment_id='C01-installed-runtime-'+run_id,machine_id='generic-hosted-arm-run-'+run_id,base_id='original341-'+I.BASE_SHA+'-plus-private-1.3.2-2',workload_id='fixed-mixed16MiB-four-roundtrips-level6',execution_context='virtual',measurement_scope=I.SCOPE,
        change=dict(variable='compiled-zlib-baseline-versus-LTO',environment_key='ZLIB_MINIGZIP',baseline=a['packages']['baseline']['programs']['minigzip']['path'],candidate=a['packages']['candidate']['programs']['minigzip']['path'],rationale='Exact accepted package executables; no gain assumed'),
        argv=[python,'-B',str(ROOT/'scripts/benchmarks/installed_zlib.py'),'run','--archive-manifest',str(LANE/'accepted-inputs.json'),'--corpus-manifest',str(LANE/'corpus/manifest.json'),'--input',str(LANE/'corpus/mixed.bin'),'--payload-bytes',str(p['payload_bytes']),'--iterations',str(p['iterations'])],
        inputs=[python,*[str(ROOT/'scripts/benchmarks'/n) for n in ('benchmark.py','paired_zlib.py','process_group_memory.py','installed_zlib.py','zlib_workload.py')],*[str(LANE/n) for n in ('accepted-inputs.json','accepted-component.json','profile.json','expected-packages.lock','corpus/manifest.json','corpus/mixed.bin')],*[str(ROOT/r['archive']) for r in a['packages'].values()]],
        env={'LC_ALL':'C'},variant_env={v:{'ZLIB_MINIGZIP':a['packages'][v]['programs']['minigzip']['path']} for v in ('baseline','candidate')},variant_inputs={v:[a['packages'][v]['programs']['minigzip']['path']] for v in ('baseline','candidate')},order=p['order'],minimum_trials=6,timeout_seconds=45,sample_seconds=0.1,thresholds=p['thresholds'],controls=controls,allowed_state_changes=[])


def child(args):
    need(os.getuid()==os.geteuid()>0,'ordinary benchmark worker')
    result=P.run(SimpleNamespace(plan=OUT/'plan.json',conditions_root=OUT/'conditions',output=OUT/'session',warmup_blocks=1,session_seconds=900,control_only=False))
    print(json.dumps(dict(status=result['status'],scope=result['scope'],preliminary_result=result.get('preliminary_result'),hardware='NOT RUN',optimization_acceptance='NOT RUN'),sort_keys=True))
    return 1 if result['status']=='FAIL' else 0


def run(args):
    need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()==0 and Path('/.dockerenv').is_file() and os.environ.get('CACHY_ASAHI_DISPOSABLE_BENCHMARK')=='1','explicit disposable native ARM root container')
    need(OUT.is_dir() and not any(OUT.iterdir()) and I.sha(I.read(LANE/'source-map.json'))==args.manifest_sha256,'fixed empty output and whole source map')
    need(len(args.source_sha)==40 and all(c in '0123456789abcdef' for c in args.source_sha) and args.run_id.isdecimal(),'exact current source/run')
    I.profile();accepted,_=I.archives();helper=helper_module();alarm=pwd.getpwnam('alarm');need(alarm.pw_uid>0 and alarm.pw_gid>0,'ordinary alarm user')
    (OUT/'guest-commands').mkdir();runner=helper.Commands(OUT/'guest-commands',seconds=1050,builder_uid=alarm.pw_uid)
    signals={s:signal.signal(s,runner.cancel) for s in (signal.SIGTERM,signal.SIGINT)}
    report=dict(status='FAIL',source_sha=args.source_sha,run_id=args.run_id,measurement_scope=I.SCOPE,profile_sha256=I.PROFILE_SHA,accepted_inputs_sha256=I.ACCEPTED_SHA,corpus_manifest_sha256=I.CORPUS_SHA,hardware='NOT RUN',generic16k_execution='NOT RUN',optimization_acceptance='NOT RUN',release='NOT_ADMITTED',zombie_absence='NOT_ESTABLISHED',container_retirement='REQUIRED_SEPARATELY')
    initial=I.read(LANE/'expected-packages.lock');sentinels={str(Path(p).resolve()):I.sha(I.read(Path(p).resolve())) for p in ('/usr/lib/libz.so.1','/usr/lib/libc.so.6','/usr/bin/pacman','/etc/pacman.conf')}
    def inventory(label,expected):
        raw=runner.run(label,['pacman','-Q'],timeout=20);need(raw==expected,'inventory differs: '+label);(OUT/(label+'.lock')).write_bytes(raw)
    def stable():need({p:I.sha(I.read(Path(p))) for p in sentinels}==sentinels,'base library/pacman sentinel changed')
    pacman=OUT/'pacman-local.conf';pacman.write_text('[options]\nArchitecture = aarch64\nSigLevel = Never\nLocalFileSigLevel = Never\nHookDir = /builder-disabled-hooks\n')
    need(Path('/builder-disabled-hooks').is_dir(),'accepted masked hooks required')
    try:
        inventory('initial-inventory',initial);need(I.sha(initial)==I.BASE_SHA,'exact original341')
        for row in accepted['packages'].values():need(not Path(row['programs']['minigzip']['path']).exists(),'private experiment already present')
        runner.run('pacman-install',['pacman','--config',str(pacman),'--noconfirm','--noscriptlet','-U',*[str(ROOT/accepted['packages'][v]['archive']) for v in ('baseline','candidate')]],timeout=30)
        expected=dict(line.split(' ',1) for line in initial.decode().splitlines())|{r['name']:r['version'] for r in accepted['packages'].values()}
        installed=''.join(k+' '+v+'\n' for k,v in sorted(expected.items())).encode()
        inventory('installed-inventory',installed);stable();I.installed(accepted,full=True)
        probes={}
        for v,row in accepted['packages'].items():
            probes[v]=json.loads(runner.run('installed-probe-'+v,[row['programs']['probe']['path'],'--installed-check'],timeout=15))
            need(probes[v]['status']=='PASS' and probes[v]['roundtrips']==21 and probes[v]['negative_checks']==42,'finite prefix probe')
        save(OUT/'installed-probes.json',probes)
        c=config(args.run_id);save(OUT/'config.json',c)
        live=B.live_identity('virtual');need(live['architecture']=='aarch64' and live['packages']==installed.decode().strip(),'observed native installed state')
        state={k:live[k] for k in ('architecture','machine_model','device_tree_compatible','page_size_bytes','kernel','os_release','execution_context','m2_air_size')};state.update(packages=dict(returncode=0,stdout=live['packages']),repositories=dict(sync_databases=live['repositories']))
        save(OUT/'baseline-state.json',state);save(OUT/'candidate-state.json',state)
        B.freeze(OUT/'config.json',OUT/'baseline-state.json',OUT/'candidate-state.json',OUT/'plan.json')
        conditions=OUT/'conditions';conditions.mkdir()
        for step in P.schedule(c,1):
            save(conditions/(step['name']+'.json'),dict(c['controls'],operator='source-owned hosted run '+args.run_id,notes='Automatic declaration only; no physical sensor values or host-control promises',unavailable={k:'unavailable in hosted VM; no invented physical reading' for k in ('ambient_C','thermal_start_C','battery_soc_percent')}))
        os.chown(OUT,alarm.pw_uid,alarm.pw_gid)
        argv=['runuser','-u','alarm','--','env','-i','PATH=/usr/bin:/bin','HOME=/tmp','LC_ALL=C','LANG=C','TZ=UTC','PYTHONDONTWRITEBYTECODE=1','CACHY_ASAHI_DISPOSABLE_BENCHMARK=1',str(Path(sys.executable).resolve()),'-I','-B',str(LANE/'guest.py'),'child','--source-sha',args.source_sha,'--run-id',args.run_id,'--manifest-sha256',args.manifest_sha256]
        runner.run('paired-runtime',argv,timeout=930)
        I.installed(accepted,full=True);inventory('after-measurement-inventory',installed);stable()
        session=json.loads(I.read(OUT/'session/session.json'));need(session['status']=='COMPLETE_GENERIC_HOSTED_ARM_C01_INSTALLABLE_MEASUREMENT_PENDING_REVIEW' and len(session['completed'])==18,'complete finite paired session')
        need(all(r['workload']['material_profile']==I.SCOPE and len(r['workload']['checks'])==4 for r in session['completed']),'complete scoped correctness')
        report.update(status='COMPLETE_GENERIC_HOSTED_ARM_PAIRED_EXPERIMENT',session_status=session['status'],completed_slots=18,measured_slots=12,warmups_excluded=True,preliminary_result=session['preliminary_result'],system_sentinels=sentinels,machine=platform.machine(),page_size=os.sysconf('SC_PAGE_SIZE'),baseline_packages=341,installed_packages=343)
    except (Exception,KeyboardInterrupt) as error:report.update(error_type=type(error).__name__,error=str(error)[:2048])
    finally:
        for s in signals:signal.signal(s,lambda *_:None)
        try:
            (OUT/'guest-removal').mkdir();cleanup=helper.Commands(OUT/'guest-removal',seconds=60,builder_uid=alarm.pw_uid)
            cleanup.run('pacman-remove',['pacman','--config',str(pacman),'--noconfirm','--noscriptlet','-R',*[accepted['packages'][v]['name'] for v in ('baseline','candidate')]],timeout=30)
            final=cleanup.run('final-inventory',['pacman','-Q'],timeout=20);(OUT/'final-inventory.lock').write_bytes(final);need(final==initial,'original341 not restored');stable()
            need(all(not Path('/usr/lib/cachy-asahi/experiments/zlib-'+v).exists() for v in ('baseline','lto')),'private prefixes remain')
            report['package_removal']='PASS_EXACT341_RESTORED'
        except (Exception,KeyboardInterrupt) as error:report.update(status='FAIL',package_removal='FAIL',removal_error=type(error).__name__+': '+str(error)[:2048])
        save(OUT/'result.json',report)
        for s,h in signals.items():signal.signal(s,h)
    return 0 if report['status']=='COMPLETE_GENERIC_HOSTED_ARM_PAIRED_EXPERIMENT' else 1


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('run','child'))
    p.add_argument('--source-sha',required=True);p.add_argument('--run-id',required=True);p.add_argument('--manifest-sha256',required=True);a=p.parse_args()
    try:return child(a) if a.mode=='child' else run(a)
    except (Exception,KeyboardInterrupt) as error:print(type(error).__name__+': '+str(error),file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())

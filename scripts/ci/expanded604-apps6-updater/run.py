#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One owned final604 production-updater copy; five actual prerequisites required."""
import argparse
import os
from pathlib import Path
import platform
import shutil
import signal
import sys
from types import SimpleNamespace
import uuid
import contract as C
import adapter
import gate
import before_cache


def prepare_with_plan(producer,args):
    return C.old600()[1].prepare_with_plan(producer,args)


def verify_result(row,case):
    C.need(row.get('status')=='PASS' and row.get('package_count')==row.get('final_package_count')==604 and
         row.get('installed_inventory_sha256')==row.get('final_inventory_sha256')==C.BEFORE and
         row.get('dependency_checks')=='PASS-no-waivers' and row.get('payload_ownership')=='PASS',
         'outer actual604 installation/dependency/payload verification failed')
    hook=row['full_root_upgrade'];driver=hook['driver']
    C.need(hook['status']=='PASS' and hook['persistent_source_preserved'] is True and
         driver['status']=='PASS' and driver['copy_cleanup']=='PASS-owned-workspace-removed' and
         hook['persistent_source']['source_manifest_sha256']==hook['persistent_source_after']['source_manifest_sha256'],
         'complete source preservation and owned-copy disposal required')
    expected={'normal':(1,True,True,True),'precommit-exit86':(0,False,False,False),'postcommit-exit87':(1,True,True,False)}[case]
    truth=tuple(driver.get(key) for key in ('committed_transactions','commit_started','packages_committed','checkpoint_changed'))
    C.need(truth==expected and all(type(actual) is type(wanted) for actual,wanted in zip(truth,expected)),
         'case commit/checkpoint truth differs')
    if case=='normal':C.need(driver.get('update',{}).get('checkpoint_directory_synced') is True,'normal checkpoint directory sync required')
    else:
        C.need(driver.get('case')==case and driver.get('failure_cases')==1 and driver.get('original_source_preserved') is True,
             'one exact original-source-preserving failure/disposal case required')
        if case=='postcommit-exit87':C.need(all(driver.get(k) is True for k in ('after604_database_verified','postcommit_payload_verified','postcommit_preservation_verified')),'independent committed604 state proof required')
    return hook


def cleanup_ready(path,output,owner):
    C.need(owner['purpose']=='expanded604-apps6-updater' and C.read(output/'owner.json')==owner and owner['output']==str(output) and path==output/'ready604',
         'exact owned604 cache identity required')
    if not path.exists():return
    C.safe(path);C.need(path.stat().st_uid==os.getuid(),'owned cache uid differs');entries=list(path.rglob('*'))
    C.need(len(entries)<=2000,'owned cache cleanup node bound')
    for entry in entries:C.safe(entry);C.need(entry.is_file() or entry.is_dir(),'owned cache special node refused')
    for name in ('packages','keys'):
        if (path/name).exists():(path/name).chmod(0o700)
    shutil.rmtree(path)


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('implementation','installer-source','decision-source','upgrader-source','baseline-source','baseline-decisions-source','preparation-source',
                 'product','updater','desktop','updater-v2-source','native','fdk','cache','setup4-pair',
                 *(name.replace('_','-') for name in C.INPUTS),'audio-inputs','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--implementation-revision',required=True);p.add_argument('--case',choices=tuple(C.SOURCES),required=True)
    a=p.parse_args(argv);policy=C.policy() # Before native guards, output creation, signing or any actor.
    for name,value in vars(a).items():
        if isinstance(value,Path):setattr(a,name,C.safe(value.absolute()))
    gate.own_source(a.implementation,a.implementation_revision)
    IC,materializer,installer_policy,decisions,summary=gate.inputs(a,policy)
    C.need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and
         not sys.flags.optimize,'ordinary native ARM owner with asserted original validators required')
    C.need(a.output.parent==Path('/tmp') and not a.output.exists(),'fresh direct /tmp owner output required')
    output=a.output;producer_output=output.with_name(output.name+'-producer')
    C.need(not producer_output.exists(),'fresh owned producer sibling required');output.mkdir(mode=0o700)
    owner=dict(schema_version=1,purpose='expanded604-apps6-updater',token=uuid.uuid4().hex,output=str(output),producer=str(producer_output),case=a.case)
    (output/'owner.json').write_bytes(C.encoded(owner));public=output/'public';public.mkdir()
    result=dict(status='FAIL',case=a.case,scope='GENERIC4K_APPS5_TO6_CURRENT604_COPIED_ROOT_SOFTWARE_ONLY',hardware='NOT_RUN',
        apple_acceptance='NOT_ESTABLISHED',release='NOT_ADMITTED',prerequisites=decisions,
        source=a.implementation_revision,before_sha256=C.BEFORE,after_sha256=C.AFTER,producer_cleanup='NOT_RUN')
    candidate=output/'candidate';expanded=output/'ready604';actor_owned=output/'owned.json'
    producer=C.load('_root604_producer',a.legacy_source/'scripts/ci/full-composition-installer-vm/producer.py')
    old=None;retired=True
    def cancelled(*_):raise InterruptedError('expanded604 copied-root owner interrupted')
    prior={sig:signal.signal(sig,cancelled) for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGALRM)}
    try:
        config,caller=adapter.prepare(a.upgrader_source,candidate,a.case)
        pair=C.load('apps6_pair_stage',C.HERE/'baseline.py').stage(C,a.apps6_source,output/'apps6',policy['apps6'])
        constructor=C.load('_root604_constructor',candidate/'scripts/ci/full-root-upgrade/construct_repository.py')
        constructor.inspect_package(SimpleNamespace(source_root=candidate,setup4_pair=pair,
            package=pair/'public/packages/cachy-asahi-apps-a/cachy-asahi-apps-0.1.0-6-any.pkg.tar.xz',
            provenance=pair/'public/runtime/cachy-asahi-apps-a/provenance.json'))
        original=SimpleNamespace(**vars(a),code=a.legacy_source,code_revision=IC.LEGACY);original.output=producer_output
        ready,original_plan=prepare_with_plan(producer,original);result['producer']='READY_SIGNED_INITIAL587'
        materializer.prepare(ready,producer_output,a.eight_source,a.seven_source,a.audio_inputs,a.legacy_source,expanded,installer_policy,
            a.management_source,a.setup_source,a.welcome_source,a.baseline_source)
        before_cache.bind(expanded,IC.COMPOSITION,owner)
        raw=producer_output/'private';inputs=before_cache.flat_inputs(expanded,raw,output/'inputs',original_plan,IC.COMPOSITION)
        old=C.load('_root604_original_owner',a.upgrader_source/'scripts/ci/full-root-upgrade-caller/run.py')
        old.CALLER=caller;old.HERE=a.preparation_source/'scripts/ci/full-development-composition'
        footprint=C.load('_root604_volume_owner',old.HERE/'footprint.py');footprint.prepare(a.preparation_source,raw/'footprint-source')
        name='cachy-asahi-composition-'+uuid.uuid4().hex;volume='cachy-asahi-footprint-'+uuid.uuid4().hex
        C.need(footprint.volume_present(volume)==[],'fresh owned footprint volume required')
        (actor_owned).write_bytes(C.encoded(dict(container=name,footprint_volume=volume)));retired=False
        footprint.create_volume(volume)
        args=SimpleNamespace(upgrade_code=candidate,upgrade_config=config,setup4_pair=pair)
        argv=old.container_args(args,inputs,public,raw,name,volume)
        image=(raw/'desktop574/image-id').read_text().strip()
        old.command(argv+['--entrypoint=/usr/bin/python3',image,'-I','-B','/runner.py'],public/'transaction.log',3900)
        row=C.read(public/'result.json');verify_result(row,a.case);result.update(status='PASS',composition=row)
    except BaseException as error:result.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:2048])
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        if not retired and old is not None:
            try:
                failures=old.retire_outer(actor_owned,result);retired=not failures and result.get('upgrade_volume_cleanup')=='PASS-absence-verified'
                result['outer_cleanup']='PASS' if retired else 'FAIL';result['outer_cleanup_failures']=failures
            except BaseException as error:result.update(outer_cleanup='FAIL',outer_cleanup_error=str(error)[:512]);retired=False
        elif retired:result['outer_cleanup']='NOT_CREATED'
        if retired:
            for name in ('expanded604-verifier','expanded604-before-verifier'):
                verifier=producer_output/'private'/name
                if verifier.exists() or verifier.is_symlink():
                    retired=False;result.update(status='FAIL',verifier_cleanup='RETAINED_ABSENCE_UNKNOWN',verifier=str(verifier))
        if retired:
            try:cleanup_ready(expanded,output,owner);result['expanded_cache_cleanup']='PASS'
            except BaseException as error:result.update(status='FAIL',expanded_cache_cleanup='FAIL',cache_cleanup_error=str(error)[:512]);retired=False
        if retired and (producer_output/'producer-owner.json').is_file():
            try:
                receipt=producer.cleanup(producer_output);C.need(receipt['status']=='PASS','original producer cleanup failed');result['producer_cleanup']='PASS'
            except BaseException as error:result.update(status='FAIL',producer_cleanup='FAIL',producer_cleanup_error=str(error)[:512])
        elif not retired:result.update(status='FAIL',producer_cleanup='RETAINED_CONSUMER_OR_CACHE_RETIREMENT_UNKNOWN')
        # Retain bounded public proofs; source maps/witnesses remain private as in the original lane.
        for name in ('producer.json','producer-cleanup.json'):
            path=producer_output/'public'/name
            if path.is_file() and not path.is_symlink() and path.stat().st_size<=4*1024**2:shutil.copyfile(path,public/name)
        if (candidate/'adapter.json').is_file():shutil.copyfile(candidate/'adapter.json',public/'adapter.json')
        log=public/'transaction.log'
        if log.is_file() and not log.is_symlink():
            with log.open('rb') as stream:
                stream.seek(max(0,log.stat().st_size-65536));(public/'transaction-tail.log').write_bytes(stream.read(65536))
        if result['producer_cleanup']!='PASS' or not retired:result['status']='FAIL'
        if retired:
            try:
                for name in ('candidate','inputs','apps6'):
                    path=output/name
                    if path.exists():shutil.rmtree(path)
                result['caller_private_cleanup']='PASS'
            except BaseException as error:result.update(status='FAIL',caller_private_cleanup='FAIL',private_cleanup_error=str(error)[:512])
        else:result['caller_private_cleanup']='RETAINED_RETIREMENT_UNKNOWN'
        (output/'result.json').write_bytes(C.encoded(result))
        for sig,handler in prior.items():signal.signal(sig,handler)
    return int(result['status']!='PASS')


if __name__=='__main__':raise SystemExit(main())

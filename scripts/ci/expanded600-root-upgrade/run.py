#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One owned native600 production-updater copy; three explicitly separate cases."""
import argparse
import json
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


def prepare_with_plan(producer,args):
    """Keep the real pre-volume plan that the held producer passes to its exporter."""
    original=producer.export_ready;captured={}
    def exporting(raw,ready,held,*arguments,**keywords):
        C.need(not captured,'one original producer export required')
        captured['attempted']=True
        C.need(raw==args.output/'private' and held['inputs']==raw/'inputs' and
               ready==raw/'ready' and type(held['plan']) is dict,'owned original producer plan origin differs')
        plan=C.encoded(held['plan']);C.need(0<len(plan)<=4*1024**2,'bounded original producer plan required')
        result=original(raw,ready,held,*arguments,**keywords)
        C.need(result==ready and C.encoded(held['plan'])==plan,'original producer plan/export changed')
        captured.update(ready=ready,plan=plan)
        return result
    producer.export_ready=exporting
    try:ready=producer.prepare(args)
    finally:producer.export_ready=original
    C.need(captured.get('ready')==ready and 'plan' in captured,'successful original export must precede plan use')
    return ready,json.loads(captured['plan'],parse_constant=lambda _:C.need(False,'nonfinite producer plan'))


def flat_inputs(ready,raw,target,old):
    """Install exactly574 minus upstream FDK plus27 signed additions, yielding600."""
    C.need(not target.exists(),'fresh flat inputs required')
    value=C.read(ready/'manifest.json');before,_=C.locks()
    C.need(value['status']=='READY_SIGNED_EXPANDED600' and len(value['packages'])==600 and
         {r['name']:r['version'] for r in value['packages']}==before and
         C.sha(ready/'expected-installed.lock')==C.BEFORE,'exact signed600 cache required')
    projects={r['name'] for r in value['projects']}
    names=projects|{'htmlq','pacman-contrib','archlinux-contrib','pyalpm'}|adapter.AUDIO
    rows=[r for r in value['packages'] if r['name'] in names]
    C.need(len(projects)==17 and len(rows)==27 and {r['name'] for r in rows}==names,'exact17 projects and27 additions required')
    target.mkdir(mode=0o700);packages=[]
    for row in rows:
        name=Path(row['archive']).name;sig=Path(row['signature']).name
        C.need(name not in {r['filename'] for r in packages} and sig==name+'.sig','distinct archive basenames required')
        # Package archives have a separate bound; JSON and detached signatures keep the default4MiB.
        archive=C.checked(ready,dict(path=row['archive'],bytes=row['size'],sha256=row['sha256']),cap=8*1024**2)
        signature=C.checked(ready,dict(path=row['signature'],bytes=row['signature_size'],sha256=row['signature_sha256']))
        shutil.copyfile(archive,target/name);shutil.copyfile(signature,target/sig)
        packages.append(dict(name=row['name'],version=row['version'],filename=name,size=row['size'],sha256=row['sha256'],
                             signature_size=row['signature_size'],signature_sha256=row['signature_sha256']))
    for name in ('expectedbase.lock','core-lifecycle.py','provider-helpers.py','TEST-public.asc','archlinuxarm.gpg'):
        source=C.safe(raw/'inputs'/name);C.need(source.is_file(),'original helper/key input missing');shutil.copyfile(source,target/name)
    shutil.copyfile(ready/'expected-installed.lock',target/'expected-installed.lock')
    plan={key:old[key] for key in ('hooks','signer_fingerprint','test_signer_fingerprint')}
    # setup4 remains the unchanged helper API key; its discarded package metadata is never selected.
    plan.update(packages=packages,projects=value['projects'],setup4={'helpers':old['setup4']['helpers']},full_root_upgrade=True)
    (target/'plan.json').write_bytes(C.encoded(plan));return target


def verify_result(row,case):
    C.need(row.get('status')=='PASS' and row.get('package_count')==row.get('final_package_count')==600 and
         row.get('installed_inventory_sha256')==row.get('final_inventory_sha256')==C.BEFORE and
         row.get('dependency_checks')=='PASS-no-waivers' and row.get('payload_ownership')=='PASS',
         'outer actual600 installation/dependency/payload verification failed')
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
        if case=='postcommit-exit87':C.need(all(driver.get(k) is True for k in ('after600_database_verified','postcommit_payload_verified','postcommit_preservation_verified')),'independent committed600 state proof required')
    return hook


def cleanup_ready(path,output,owner):
    C.need(C.read(output/'owner.json')==owner and owner['output']==str(output) and path==output/'ready600',
         'exact owned600 cache identity required')
    if not path.exists():return
    C.safe(path);C.need(path.stat().st_uid==os.getuid(),'owned cache uid differs');entries=list(path.rglob('*'))
    C.need(len(entries)<=2000,'owned cache cleanup node bound')
    for entry in entries:C.safe(entry);C.need(entry.is_file() or entry.is_dir(),'owned cache special node refused')
    for name in ('packages','keys'):
        if (path/name).exists():(path/name).chmod(0o700)
    shutil.rmtree(path)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('implementation','installer-source','decision-source','upgrader-source','legacy-source','preparation-source',
                 'product','updater','desktop','updater-v2-source','native','fdk','cache','setup4-pair',
                 'seven-pairs','eight-pairs','audio-inputs','setup5-checkout','output'):
        p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--implementation-revision',required=True);p.add_argument('--case',choices=tuple(C.SOURCES),required=True)
    a=p.parse_args();policy=C.policy() # Before native guards, output creation, signing or any actor.
    for name,value in vars(a).items():
        if isinstance(value,Path):setattr(a,name,C.safe(value.absolute()))
    gate.own_source(a.implementation,a.implementation_revision)
    C.need(C.revision(a.decision_source)==policy['decision_source'],'Root decision source differs');decisions=C.prerequisites(a.decision_source,policy)
    IC,materializer,installer_policy=gate.installer(a.installer_source,policy);IC.legacy(a.legacy_source)
    C.need(C.revision(a.seven_pairs)==IC.SEVEN and C.revision(a.eight_pairs)==C.EIGHT and
         C.revision(a.upgrader_source)==C.SOURCES[a.case],'immutable producer/input/upgrader source differs')
    IC.prerequisites(a.eight_pairs,installer_policy);materializer.accepted_pairs(a.eight_pairs,a.seven_pairs,a.legacy_source,installer_policy)
    C.need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and
         not sys.flags.optimize,'ordinary native ARM owner with asserted original validators required')
    C.need(a.output.parent==Path('/tmp') and not a.output.exists(),'fresh direct /tmp owner output required')
    output=a.output;producer_output=output.with_name(output.name+'-producer')
    C.need(not producer_output.exists(),'fresh owned producer sibling required');output.mkdir(mode=0o700)
    owner=dict(schema_version=1,purpose='expanded600-root-upgrade',token=uuid.uuid4().hex,output=str(output),producer=str(producer_output),case=a.case)
    (output/'owner.json').write_bytes(C.encoded(owner));public=output/'public';public.mkdir()
    result=dict(status='FAIL',case=a.case,scope='GENERIC4K_NATIVE600_COPIED_ROOT_SOFTWARE_ONLY',hardware='NOT_RUN',
        apple_acceptance='NOT_ESTABLISHED',release='NOT_ADMITTED',prerequisites=decisions,
        source=a.implementation_revision,before_sha256=C.BEFORE,after_sha256=C.AFTER,producer_cleanup='NOT_RUN')
    candidate=output/'candidate';expanded=output/'ready600';actor_owned=output/'owned.json'
    producer=C.load('_root600_producer',a.legacy_source/'scripts/ci/full-composition-installer-vm/producer.py')
    old=None;retired=True
    def cancelled(*_):raise InterruptedError('expanded600 copied-root owner interrupted')
    prior={sig:signal.signal(sig,cancelled) for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGALRM)}
    try:
        config,caller=adapter.prepare(a.upgrader_source,candidate,a.case)
        pair=gate.stage_pair(a.setup5_checkout,output/'setup5')
        constructor=C.load('_root600_constructor',candidate/'scripts/ci/full-root-upgrade/construct_repository.py')
        constructor.inspect_package(SimpleNamespace(source_root=candidate,setup4_pair=pair,
            package=pair/'packages/cachy-asahi-setup-a/cachy-asahi-setup-0.1.0-5-any.pkg.tar.xz',
            provenance=pair/'runtime/cachy-asahi-setup-a/provenance.json'))
        original=SimpleNamespace(**vars(a),code=a.legacy_source,code_revision=IC.LEGACY);original.output=producer_output
        ready,original_plan=prepare_with_plan(producer,original);result['producer']='READY_SIGNED_INITIAL587'
        materializer.prepare(ready,producer_output,a.eight_pairs,a.seven_pairs,a.audio_inputs,a.legacy_source,expanded,installer_policy)
        raw=producer_output/'private';inputs=flat_inputs(expanded,raw,output/'inputs',original_plan)
        old=C.load('_root600_original_owner',a.upgrader_source/'scripts/ci/full-root-upgrade-caller/run.py')
        old.CALLER=caller;old.HERE=a.preparation_source/'scripts/ci/full-development-composition'
        footprint=C.load('_root600_volume_owner',old.HERE/'footprint.py');footprint.prepare(a.preparation_source,raw/'footprint-source')
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
                for name in ('candidate','inputs','setup5'):
                    path=output/name
                    if path.exists():shutil.rmtree(path)
                result['caller_private_cleanup']='PASS'
            except BaseException as error:result.update(status='FAIL',caller_private_cleanup='FAIL',private_cleanup_error=str(error)[:512])
        else:result['caller_private_cleanup']='RETAINED_RETIREMENT_UNKNOWN'
        (output/'result.json').write_bytes(C.encoded(result))
        for sig,handler in prior.items():signal.signal(sig,handler)
    return int(result['status']!='PASS')


if __name__=='__main__':raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite source-only-prepared native trial. Root alone runs its actor phases."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import threading
import time
import contract as C
import planner_transport as T
import provider_bindings as B


def proof(source, output, environment):
    C.verify_source(source)
    selected = environment.get('SOURCE_SHA', '')
    C.need(len(selected) == 40 and all(c in '0123456789abcdef' for c in selected) and
           selected == environment.get('GITHUB_SHA') == environment.get('GITHUB_WORKFLOW_SHA'), 'exact new hosted source/workflow revision required')
    result = dict(status='SOURCE_BYTES_AND_HOSTED_REVISION_BINDING_ONLY', source=selected,
                  source_manifest_sha256=C.digest(source / 'scripts/ci/build-batch-native/source-manifest.json'),
                  job_token=os.urandom(8).hex(), native='NOT_RUN', hardware='NOT_RUN')
    C.save(output, result)
    if environment.get('GITHUB_OUTPUT'):
        with open(environment['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('job_token=' + result['job_token'] + '\n')
    return result


def offline_review(source, output):
    C.verify_source(source)
    output.mkdir(mode=0o700)
    value = C.topology(source)
    C.save(output / 'input-with-explicit-unknown-baseline-pins.json', value)
    planner = C.load('native_trial_offline_planner', source / 'scripts/maintenance/rebuild_plan.py')
    plan = planner.plan(value)
    C.save(output / 'source-topology-plan.json', plan)
    result = dict(status='SOURCE_INPUT_HOLDS_NO_EXECUTION', dependency_issues=plan['dependency_issues'],
                  groups=plan['groups'], baseline_count=len(plan['baseline_inputs']),
                  baseline_recipe_pins='UNAVAILABLE_UNTIL_AUTHENTICATED_NATIVE574_ARCHIVES_ARE_PRESENT',
                  native='NOT_RUN', builds='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')
    C.save(output / 'result.json', result)
    return result


def native_guard(base, source_proof):
    C.need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64') and
           os.getuid() == os.geteuid() > 0 and not any(k.startswith('DOCKER_') for k in os.environ), 'ordinary native ARM host/local Docker required')
    original = C.read(base / 'report.json')
    image = (base / 'image-id').read_text().strip()
    C.need(original['status'] == 'PASS_NATIVE_OFFLINE_574_TRANSACTION' and original['image'] == image and
           image.startswith('sha256:') and C.HEX.fullmatch(image[7:]) and
           original['ownership']['token'] == source_proof['job_token'], 'current owned successful native574 producer required')
    context = T.capture(['docker', 'context', 'inspect', 'default'])
    C.need(context.returncode == 0 and json.loads(context.stdout)[0]['Endpoints']['docker']['Host'] == 'unix:///var/run/docker.sock', 'local default Docker socket required')
    shown = T.capture(['docker', 'context', 'show'])
    arch = T.capture(['docker', 'info', '--format', '{{.Architecture}}'])
    C.need(shown.returncode == 0 and shown.stdout.strip() == b'default' and arch.returncode == 0 and
           arch.stdout.strip() in (b'arm64', b'aarch64'), 'native default Docker required')
    inspected = T.capture(['docker', 'image', 'inspect', image])
    C.need(inspected.returncode == 0, 'current native image unavailable')
    row = json.loads(inspected.stdout)[0]
    C.need(row['Id'] == image and row['Architecture'] == 'arm64' and row['Os'] == 'linux' and
           row['Config']['Labels'].get('org.cachy-asahi.bootstrap574.job') == source_proof['job_token'], 'native image ownership/architecture differs')
    return original, image


def prepare(source, base, output, image, source_proof):
    selected = C.baseline(source)
    lock = ''.join(p['name'] + ' ' + p['version'] + '\n' for p in sorted(selected['packages'], key=lambda p:p['name']))
    C.need(C.raw(base / 'installed-packages.lock') == lock.encode(), 'actual image lock differs from exact574')
    recipe_pins = {p['name']:C.archive_recipe_pin(base / 'context/deps' / p['filename'], p) for p in selected['packages']}
    value = C.topology(source, recipe_pins)
    B.receipt(source,output,image)
    value['provider_selections']=B.verify(source,image,C.raw(output/'provider-capture.json'),value)
    C.save(output/'provider-bindings.json',value['provider_selections'])
    C.save(output / 'input.json', value)
    (output / 'image-packages.lock').write_text(lock)
    tasks = []
    for name, recipe in C.recipes(source).items():
        reviewed = output / (name + '.reviewed.json')
        C.save(reviewed, recipe['report']['input_sha256'])
        tasks.append(dict(package=name, owner='Root finite native batch trial', recipe=str(recipe['directory']),
            reviewed_inputs=str(reviewed), reviewed_inputs_sha256=C.digest(reviewed),
            expected_packages=str(output / 'image-packages.lock'), expected_packages_sha256=C.digest(output / 'image-packages.lock'),
            image=image, mode='native', source_date_epoch=selected['source_date_epoch'], timeout=180,
            prerequisite_artifacts={}, image_dependency_review='No dependency between selected shell packages; complete immutable574 lock checked'))
    C.save(output / 'config.json', dict(schema_version=1, owner='Root finite native batch trial',
        review='Exact-source two shell packages; owned native574 producer; no platform changes',
        max_parallel=2, cpu_budget=8, memory_gib_budget=8, max_wall_seconds=420, max_attempts=2, tasks=tasks))
    C.save(output / 'transport.json', dict(source=str(source), base=str(base), image=image,
        base_report_sha256=C.digest(base / 'report.json'), input_sha256=C.digest(output / 'input.json'),
        source_manifest_sha256=source_proof['source_manifest_sha256'],provider_capture_sha256=C.digest(output/'provider-capture.json')))
    return value


def inject_failure(source, output, image, stop):
    """Kill only the first target's actual running OCI container, never a fake builder."""
    target = C.NAMES[0]
    path = output / 'batch' / target / 'attempt-001/build/provenance.json'
    deadline = time.monotonic() + 120
    while not stop.is_set() and time.monotonic() < deadline:
        try:
            # The builder creates this file after the observer starts. Preserve
            # genuine ENOENT as a retry; C.raw otherwise wraps it in ValueError.
            path.lstat()
            record = C.read(path)
            name = record['clean_environment_id']
            C.need(record['status'] == 'building' and record['image'] == image and
                   name.startswith('cachy-asahi-') and len(name) == 28 and all(c in '0123456789abcdef' for c in name[12:]), 'target build ownership differs')
            inspected = T.capture(['docker', 'container', 'inspect', name], 5)
            if inspected.returncode == 0:
                rows = json.loads(inspected.stdout)
                C.need(len(rows) == 1, 'ambiguous fault target')
                row = rows[0]
                expected = {(str(path.parent / 'inputs'), '/inputs', False),
                            (str(path.parent / 'artifacts'), '/out', True),
                            (str(source / 'scripts/build/container-entry.sh'), '/builder-entry.sh', False),
                            (str(path.parent / 'expected-packages.lock'), '/expected-packages.lock', False)}
                actual = {(p.get('Source'),p.get('Destination'),p.get('RW')) for p in row['Mounts'] if p.get('Type') == 'bind'}
                C.need(row['Name'] == '/' + name and row['Image'] == image and row['Config']['Image'] == image and actual == expected, 'live fault target image/mount ownership differs')
                if row['State']['Running'] is True:
                    C.save(output / 'fault-target-inspect.json', row)
                    C.save(output / 'fault-target-provenance.json', record)
                    killed = T.capture(['docker', 'kill', '--signal=KILL', name], 10)
                    (output / 'fault-kill.stdout').write_bytes(killed.stdout)
                    (output / 'fault-kill.stderr').write_bytes(killed.stderr)
                    C.need(killed.returncode == 0, 'owned container fault injection failed')
                    C.save(output / 'fault.json', dict(status='ACTUAL_RUNNING_OWNED_OCI_CONTAINER_KILLED',
                        package=target, container=name, image=image, exit_code=killed.returncode,
                        argv=['docker','kill','--signal=KILL',name]))
                    return
        except FileNotFoundError:
            pass
        except json.JSONDecodeError:
            pass  # Producer can be between truncation and its complete JSON write.
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            C.save(output / 'fault-error.json', dict(status='FAULT_NOT_ESTABLISHED',error=str(error)))
            return
        stop.wait(0.03)
    if not (output / 'fault.json').exists():
        C.save(output / 'fault-missed.json', dict(status='NO_ACTUAL_RUNNING_CONTAINER_FAULT_OBSERVED'))


def payloads(source, state, output, batch):
    expected = {
        C.NAMES[0]:{'usr/share/cachy-asahi/fish/config.fish':('config.fish',0o644),
            'usr/share/licenses/'+C.NAMES[0]+'/NOTICE':('NOTICE',0o644), 'usr/share/licenses/'+C.NAMES[0]+'/LICENSE':('LICENSE',0o644)},
        C.NAMES[1]:{'usr/share/cachy-asahi/zsh/config.zsh':('config.zsh',0o644),
            'usr/share/cachy-asahi/zsh/README.md':('usage.md',0o644),
            'usr/share/licenses/'+C.NAMES[1]+'/NOTICE':('NOTICE',0o644), 'usr/share/licenses/'+C.NAMES[1]+'/LICENSE':('LICENSE',0o644)}}
    checks = C.load('native_trial_package_checks',source/'scripts/checks/package_checks.py')
    result = {}
    for name in C.NAMES:
        path = output/'batch'/state['packages'][name]['attempts'][-1]['output']
        archives = [p for p in (path/'artifacts').glob('*.pkg.tar.*') if not p.name.endswith('.sig')]
        C.need(len(archives)==1, 'single exact archive required')
        report = checks.package(archives[0])
        actual = {p:r for p,r in report['members'].items() if r['type']!='5' and p not in checks.PACKAGE_METADATA}
        C.need(not report['errors'] and set(actual)==set(expected[name]), 'exact trial payload set differs')
        for member,(original,mode) in expected[name].items():
            row = actual[member]
            C.need(row['type']=='0' and row['mode']==mode and row['uid']==row['gid']==0 and
                   row['sha256']==C.digest(source/'packages/shells'/name/original),'archive payload/source binding differs')
        result[name] = dict(archive=archives[0].name,bytes=archives[0].stat().st_size,sha256=C.digest(archives[0]),
                           metadata=report['metadata'],payload=actual,provenance_sha256=C.digest(path/'provenance.json'))
    return result


def run(source, base, output, proof_path):
    C.verify_source(source)
    C.need(not output.exists() and not output.is_relative_to(source) and not output.is_relative_to(base), 'fresh separate native output required')
    output.mkdir(mode=0o700)
    source_proof = C.read(proof_path)
    C.need(source_proof['source_manifest_sha256']==C.digest(source/'scripts/ci/build-batch-native/source-manifest.json'), 'new source proof differs')
    result = dict(status='INPUT_HOLD_OR_UNRUN', source=source_proof['source'], native='NOT_RUN', builds='NOT_RUN',
                  hardware='NOT_RUN', release='NOT_ADMITTED', reproducibility='NOT_RUN', sustainable_capacity='NOT_MEASURED')
    try:
        original,image = native_guard(base,source_proof)
        C.save(output/'owner.json',dict(image=image,job_token=source_proof['job_token'],base_report_sha256=C.digest(base/'report.json')))
        T.provider_capture(source,output,image)
        result['provider_observations']='CAPTURED_BEFORE_ADMISSION_FROM_CURRENT_NATIVE_IMAGE'
        prepare(source,base,output,image,source_proof)
        batch = C.load('finite_native_batch',source/'scripts/maintenance/build_batch.py')
        transport = source/'scripts/ci/build-batch-native/planner_transport.py'
        def admission():
            return batch.admission(output/'input.json',C.digest(output/'input.json'),output/'config.json',C.digest(output/'config.json'),transport,C.digest(transport))
        admitted = admission()
        C.save(output/'admission.json',admitted)
        result['native_planner']='ACTUAL_QUALIFIED_IMAGE_PLANNER_RAN'
        C.need(not admitted['global_holds'] and len(admitted['groups'])==2 and all(not g['held'] for g in admitted['groups']), 'ACTUAL_PLANNER_INPUT_HOLD: inspect admission groups; no builder started')
        stop = threading.Event()
        observer = threading.Thread(target=inject_failure,args=(source,output,image,stop))
        observer.start()
        try:
            result.update(builds='ACTUAL_OCI_ATTEMPTS_STARTED_SEE_STATE',native='HOST_DAEMON_IMAGE_AARCH64_GUARDS_PASSED')
            failed = batch.run(admitted,output/'batch')  # Actual default Builder: build.py, no adapter injection.
        finally:
            stop.set();observer.join(timeout=25)
        C.need(not observer.is_alive() and (output/'fault.json').is_file(), 'actual running container fault was not established')
        C.save(output/'failure-state.json',failed)
        C.need(failed['packages'][C.NAMES[0]]['status']=='FAILED' and failed['packages'][C.NAMES[1]]['status']=='SUCCESS', 'genuine failed/independent success state absent')
        C.need(C.encoded(admission())==C.encoded(admitted), 'admission changed before actual resume')
        final = batch.run(admitted,output/'batch',resume=True,retry=[C.NAMES[0]])
        C.save(output/'final-state.json',final)
        C.need(final['status']=='COMPLETE' and len(final['packages'][C.NAMES[0]]['attempts'])==2 and
               len(final['packages'][C.NAMES[1]]['attempts'])==1 and final['kind']=='PINNED_OCI_BUILD_PY','actual native retry completion absent')
        result.update(status='PASS_FINITE_NATIVE_TWO_PACKAGE_FAILURE_AND_RESUME_ONLY',native='aarch64',builds='TWO_SUCCESSFUL_PACKAGES_ONE_CONTROLLED_CONTAINER_FAILURE',
            image=image,base_lock_sha256=C.digest(base/'installed-packages.lock'),products=payloads(source,final,output,batch),
            actual_uid=os.getuid(),actual_gid=os.getgid(),fixture_scope='REAL_UNCHANGED_PROJECT_RECIPES_NO_INSTALLATION')
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        result.update(error=str(error),error_type=type(error).__name__)
    C.save(output/'report.json',result)
    return result


def cleanup(source, base, output):
    C.verify_source(source)
    result = dict(status='PASS_NO_CONSUMERS_STARTED',builds=[],planners=[],producer='RETIRED_SEPARATELY_AFTER_ALL_CONSUMERS')
    if not output.exists() or not (output/'owner.json').exists():
        return result
    owner = C.read(output/'owner.json')
    batch = C.load('native_batch_cleanup',source/'scripts/maintenance/build_batch.py')
    if (output/'batch/state.json').exists():
        with (output/'batch/.lock').open('rb') as lease:
            fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
            state = C.read(output/'batch/state.json');admitted = C.read(output/'batch/admission.json')
            for name,row in reversed(list(state['packages'].items())):
                C.need(name in C.NAMES, 'foreign package cleanup refused')
                for index,attempt in reversed(list(enumerate(row['attempts'],1))):
                    C.need(attempt['output']==f'{name}/attempt-{index:03d}/build','attempt cleanup path differs')
                    path = output/'batch'/attempt['output']
                    batch.Builder().cleanup(admitted['tasks'][name],path)
                    result['builds'].append(dict(package=name,attempt=index,status='PASS_OWNED_CONTAINER_ABSENCE'))
    for path in sorted(output.glob('planner-owner-*.json')):
        row = C.read(path)
        C.need(row['image']==owner['image'] and row['source']==str(source) and row['runtime']==str(output), 'planner cleanup root differs')
        result['planners'].append(T.retire(row))
    result['status']='PASS_OWNED_BATCH_CONSUMERS_RETIRED'
    return result


def retain(source, base, output, proof_path, cleanup_path, public):
    C.verify_source(source)
    public.mkdir(mode=0o700)
    selected = [(proof_path,'source-proof.json'),(cleanup_path,'batch-consumer-cleanup.json')]
    selected += [(base/n,'base/'+n) for n in ('report.json','installed-packages.lock')]
    if output.exists():
        selected += [(p,'runtime/'+str(p.relative_to(output))) for p in sorted(output.rglob('*')) if p.is_file()]
    total,files = 0,{}
    C.need(len(selected)<=1024,'finite retention file bound')
    for path,name in selected:
        C.safe(path);C.need(path.is_file() and not path.is_symlink(),'retention requires ordinary leaves')
        size=path.stat().st_size;total+=size
        C.need(size<=16*1024**2 and total<=96*1024**2,'finite public evidence cap')
        target=public/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
        files[name]=dict(bytes=size,sha256=C.digest(target))
    result=dict(status='RETAINED_BYTES_ONLY_NOT_ACCEPTANCE',files=files,total_bytes=total,hardware='NOT_RUN')
    C.save(public/'retention.json',result)
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase',choices=('proof','offline-review','run','cleanup','retain'))
    for name in ('source','base','output','proof','cleanup','public'):
        parser.add_argument('--'+name,type=Path)
    args=parser.parse_args(argv)
    try:
        source=C.safe(args.source)
        if args.phase=='proof':result=proof(source,C.safe(args.proof),os.environ)
        elif args.phase=='offline-review':result=offline_review(source,C.safe(args.output))
        elif args.phase=='run':result=run(source,C.safe(args.base),C.safe(args.output),C.safe(args.proof))
        elif args.phase=='cleanup':
            result=cleanup(source,C.safe(args.base),C.safe(args.output));C.save(C.safe(args.cleanup),result)
        else:result=retain(source,C.safe(args.base),C.safe(args.output),C.safe(args.proof),C.safe(args.cleanup),C.safe(args.public))
        print(json.dumps(result,sort_keys=True))
        return 0 if result['status'].startswith(('PASS','SOURCE_BYTES','RETAINED')) else 1
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        print('native batch trial: '+str(error),file=sys.stderr);return 2


if __name__=='__main__':
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run the frozen offline planner in one owned native574 container for vercmp."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import contract as C

LABEL = 'org.cachy-asahi.batch-native.planner'


def capture(command, seconds=20):
    result = subprocess.run(command, capture_output=True, timeout=seconds)
    C.need(len(result.stdout) + len(result.stderr) <= 16 * 1024**2, 'planner transport output cap')
    return result


def command(source, runtime, image, name, token, input_path, checksum, capture_request=None):
    result = ['docker', 'run', '--rm', '--name', name, '--label', LABEL + '=' + token,
        '--pull=never', '--platform=linux/arm64', '--network=none', '--read-only',
        '--cap-drop=ALL', '--security-opt=no-new-privileges', '--pids-limit', '128',
        '--memory', '1g', '--cpus', '1', '--user', f'{os.getuid()}:{os.getgid()}',
        '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=64m',
        '--mount', f'type=bind,src={source},dst={source},readonly',
        '--mount', f'type=bind,src={runtime},dst={runtime},readonly',
        ]
    if capture_request is not None:
        return result + ['--env', 'CACHY_BATCH_ALPM_CAPTURE=1', '--env', 'CACHY_BATCH_IMAGE='+image,
            '--entrypoint','/usr/bin/python3',image,'-I','-B',
            str(source/'scripts/ci/build-batch-native/capture_providers.py'),'--request',str(capture_request)]
    return result + ['--entrypoint', '/usr/bin/python3', image, '-I', '-B',
        str(source / 'scripts/maintenance/rebuild_plan.py'), '--input', str(input_path), '--input-sha256', checksum]


def provider_capture(source,runtime,image):
    import provider_bindings as B
    request=runtime/'provider-capture-request.json';C.save(request,B.request(source,image))
    token=os.urandom(16).hex();name='cachy-asahi-batch-plan-'+token
    owner=dict(name=name,token=token,image=image,source=str(source),runtime=str(runtime),purpose='readonly-installed-provider-capture')
    C.save(runtime/('planner-owner-'+token+'.json'),owner)
    argv=command(source,runtime,image,name,token,request,'',capture_request=request)
    C.save(runtime/'provider-capture-command.json',dict(argv=argv,owner=owner))
    try:
        result=capture(argv,90)
        (runtime/'provider-capture.stderr').write_bytes(result.stderr)
        C.need(result.returncode==0,'native installed-provider capture refused')
        C.need(len(result.stdout)<=4*1024**2,'native provider capture byte bound')
        with (runtime/'provider-capture.json').open('xb')as stream:stream.write(result.stdout)
        C.save(runtime/'provider-capture-result.json',dict(status='ACTUAL_OWNED_CONTAINER_STDOUT_CAPTURED',image=image,
            returncode=result.returncode,stdout_sha256=C.digest(runtime/'provider-capture.json'),
            stderr_sha256=C.digest(runtime/'provider-capture.stderr'),command_sha256=C.digest(runtime/'provider-capture-command.json'),
            source_manifest_sha256=C.digest(source/'scripts/ci/build-batch-native/source-manifest.json')))
    finally:C.save(runtime/('planner-retired-'+token+'.json'),retire(owner))


def retire(owner):
    name, image = owner['name'], owner['image']
    C.need(name == 'cachy-asahi-batch-plan-' + owner['token'] and len(owner['token']) == 32 and
           all(c in '0123456789abcdef' for c in owner['token']), 'owned planner identity differs')
    def absent():
        result = capture(['docker', 'ps', '-aq', '--filter', 'name=^/' + name + '$'])
        C.need(result.returncode == 0 and not result.stdout.strip(), 'planner absence not established')
    result = capture(['docker', 'container', 'inspect', name])
    if result.returncode == 0:
        rows = json.loads(result.stdout)
        C.need(type(rows) is list and len(rows) == 1, 'planner inspect identity missing')
        row = rows[0]
        binds = {(m.get('Source'), m.get('Destination'), m.get('RW')) for m in row['Mounts'] if m.get('Type') == 'bind'}
        expected = {(p, p, False) for p in (owner['source'], owner['runtime'])}
        C.need(row['Name'] == '/' + name and row['Image'] == image and row['Config']['Image'] == image and
               row['Config']['Labels'].get(LABEL) == owner['token'] and binds == expected, 'planner ownership differs')
        removed = capture(['docker', 'rm', '-f', name])
        C.need(removed.returncode == 0, 'owned planner removal failed')
    absent()
    return dict(name=name, image=image, status='PASS', absence_verified=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--input-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        input_path = C.safe(args.input)
        runtime = input_path.parent
        binding = C.read(runtime / 'transport.json')
        source, base = C.safe(binding['source']), C.safe(binding['base'])
        C.verify_source(source)
        C.need(C.digest(input_path) == args.input_sha256 == binding['input_sha256'], 'planner input binding differs')
        C.need(C.digest(base / 'report.json') == binding['base_report_sha256'] and
               C.digest(source / 'scripts/ci/build-batch-native/source-manifest.json') == binding['source_manifest_sha256'], 'planner source/base binding differs')
        import provider_bindings as B
        supplied=C.read(input_path)
        C.need(C.digest(runtime/'provider-capture.json')==binding['provider_capture_sha256'],'installed-provider capture changed')
        B.receipt(source,runtime,binding['image'])
        selected=B.verify(source,binding['image'],C.raw(runtime/'provider-capture.json'),supplied)
        C.need(supplied.get('provider_selections')==selected,'planner input not bound to retained installed provider observations')
        original = C.read(base / 'report.json')
        image = binding['image']
        C.need(original['status'] == 'PASS_NATIVE_OFFLINE_574_TRANSACTION' and original['image'] == image and
               C.HEX.fullmatch(image.removeprefix('sha256:')), 'qualified current image required')
        token = os.urandom(16).hex()
        name = 'cachy-asahi-batch-plan-' + token
        owner = dict(name=name, token=token, image=image, source=str(source), runtime=str(runtime))
        C.save(runtime / ('planner-owner-' + token + '.json'), owner)
        try:
            result = capture(command(source, runtime, image, name, token, input_path, args.input_sha256), 90)
            C.need(result.returncode == 0, 'native planner refused: ' + result.stderr.decode(errors='replace')[:512])
            # Preserve the actual frozen planner output unmodified for batch admission.
            C.need(json.loads(result.stdout)['input']['sha256'] == args.input_sha256, 'native planner output binding differs')
        finally:
            C.save(runtime / ('planner-retired-' + token + '.json'), retire(owner))
        sys.stdout.buffer.write(result.stdout)
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('native planner transport: ' + str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

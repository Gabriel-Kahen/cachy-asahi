# SPDX-License-Identifier: MIT
"""Single Python native build behind the admitted Fish owner."""
import json
import os
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import preflight as P
import native_bootstrap as bootstrap

REF='refs/heads/codex/python3148-native-full-profile-source-20261118-r2'
OPERATION='PYTHON3148_NATIVE_FULL_PROFILE_R2'
CHECK_LOG='python-3.14.8-1.1-aarch64-check.log'
NATIVE_PASS='PASS_CURRENT_PYTHON3148_FULL_PROFILE'
MIB=1024**2
INNER=3000
CLEANUP=90
OWNER=3300
SERVICES=3390
CONTROLLER=3450
SCOPE=3540
ACTOR=1560
BOOTSTRAP=900
DRIVER_FILE_CAP=32*MIB
DRIVER='runtime/scripts/build/build_python3148.py'
BYTE_CAP=64*MIB
ARCHIVE_CAP=40*MIB
OLD_PROFILE=dict(build_seconds=300,pair_seconds=1200)
LOCK_SHA='d45989ab35f2b62251a0b0d0260f266d129ff4a557ce8f9d4d4346157e51ee65'
SOURCE_PLAN_SHA='913a581de17d5a7ea219c8035861dea2ea18cec803f36b2ed225d80d2e1ab398'
TESTS=set('test_hashlib test_bz2 test_lzma test_decimal test_ctypes test_sqlite3 test_gzip test_zlib test_uuid test_zoneinfo'.split())


def profile(old):
    resources=old['resources']
    P.need(all(resources[k]==v for k,v in OLD_PROFILE.items()),'exact original Fish resource seam')
    return dict(old,resources={**resources,'build_seconds':P.BUILD_SECONDS,'pair_seconds':INNER})


def bind_bootstrap(native, held, raw_inputs):
    original=native.run
    def command(argv,log=None,timeout=1800):
        if argv[:2]==['docker','build']:
            P.need('--network=none' in argv and '--pull=false' in argv and timeout==1800,
                   'bounded ordinary offline bootstrap must use original daemon command')
            timeout=BOOTSTRAP
        return original(argv,log,timeout)
    native.run=command
    return bootstrap.bind(native,P.read(held/'runtime/scripts/ci/native_arm.py',128<<10),raw_inputs/'builder-delta')


def driver_file_cap(argv):
    return DRIVER_FILE_CAP if argv[:4]==['/usr/bin/python3','-I','-B',str(HERE/DRIVER)] else 16*MIB


def build_argv(output,image,raw_inputs):
    P.need(re.fullmatch('sha256:[0-9a-f]{64}',image),'actual immutable fresh bootstrap image')
    P.need(raw_inputs.is_absolute() and raw_inputs==output.parent/'python-inputs',
           'exact separate owned raw DATA directory')
    expected=HERE/'expected345.lock'
    plan=HERE/'source-plan.json'
    P.need(P.pin(P.read(expected,32<<10))['sha256']==LOCK_SHA
           and P.pin(P.read(plan,32<<10))['sha256']==SOURCE_PLAN_SHA,'exact 345 lock and source cache plan')
    recipe=HERE.parents[2]/'packages/port/python3148-source-candidate'
    return ['/usr/bin/python3','-I','-B',str(HERE/DRIVER),str(recipe),
            '--image',image,'--mode','native','--network','none','--source-date-epoch','1791748800',
            '--timeout',str(P.BUILD_SECONDS),'--expected-packages',str(expected),
            '--reviewed-inputs',str(HERE/'reviewed-inputs.json'),'--source-plan',str(plan),
            '--source-plan-sha256',SOURCE_PLAN_SHA,'--source-catalog',str(HERE/'source-cache-inputs.json'),
            '--source-cache',str(raw_inputs/'source-cache'),'--output',str(output/'build-1')]


def finish(root,image):
    record=json.loads(P.read(root/'provenance.json',2*MIB))
    material=record['source_material']
    P.need(record['status']=='built-package-static-pass' and record['mode']=='native'
           and record['builder_host_arch'] in ('aarch64','arm64') and record['image_id']==image
           and record['recipe_inputs']==json.loads(P.read(HERE/'reviewed-inputs.json',64<<10))
           and record['expected_packages_sha256']==LOCK_SHA and material['plan_sha256']==SOURCE_PLAN_SHA
           and material['sources'][0]['record']['material']['sha256']=='c2215904f02b175596dc49351585104f4bc20341e1c47378b26a2c274360ce73'
           and record['exit_code']==0,'actual native full reviewed build/provenance required')
    artifacts=root/'artifacts'
    lock=P.read(artifacts/'packages.lock',32<<10)
    host=P.read(artifacts/'environment.txt',64<<10).splitlines()
    P.need(P.pin(lock)['sha256']==LOCK_SHA and host[1]==b'4096' and b'aarch64' in host[0],
           'actual 345 inventory and AArch64 4 KiB builder')
    raw=P.read(artifacts/P.ARCHIVE,ARCHIVE_CAP)
    log=P.read(artifacts/CHECK_LOG,8*MIB)
    tests=set(re.findall(r'\btest_[a-z0-9_]+\b',log.decode(errors='replace')))
    P.need(raw.startswith(b'\xfd7zXZ\0') and record['artifacts']=={P.ARCHIVE:P.pin(raw)['sha256']}
           and record['files']['artifacts/'+CHECK_LOG]==P.pin(log)['sha256']
           and TESTS<=tests and b'Tests result: SUCCESS' in log and b'cpython-314-aarch64-linux-gnu' in log
           and b'"profile": "candidate"' in log and b'"holds": []' in log,
           'unsigned AArch64 candidate archive, full candidate runtime and all ten upstream suites')
    return dict(status='PYTHON3148_SINGLE_NATIVE_BUILD_DATA',archive=P.pin(raw),check=P.pin(log),
                builder=P.pin(lock),image=image,pagesize=4096,Root_acceptance=None,
                reproducibility='NOT RUN',installation='NOT RUN',physical_M2='NOT RUN')

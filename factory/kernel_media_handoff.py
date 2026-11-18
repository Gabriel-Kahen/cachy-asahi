# SPDX-License-Identifier: MIT
"""Current606 KSM + virtio-input kernel handoff for a separately owned build."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re

PROFILE='KSM_ADVICE_VIRTIO_INPUT_IPV6_GENERIC16K_DIAGNOSTIC_V2'
RELEASE='7.1.13-generic16k-managed-gui'
OLD_IMAGE='039fbeaff5942de2317f47feec30a5c073691edf5f8cef8849b25d08006d4ddb'
VERIFIER_PIN=dict(bytes=9742,sha256='f23d2d0ab0a5aaf5fd1fa8325ca608ce8224d3ad5846e37bacb4bc9251da80b9')
PLAN_PIN=dict(bytes=1718,sha256='f2947db5147055ab8767705ea40a3870c752f9e8fd50cbfe071a94f58e0bec47')
EXPECTED={
    'profile':PROFILE,'release':RELEASE,'architecture':'aarch64','page_size':16384,
    'schema_version':1,'modules':'DISABLED',
    'source_revision':'94fb23346d522edf53722357c426a3e58030beea',
    'archive_sha256':'874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad',
    'helper_sha256':'f165f8aca3aca2a8a9332de7b9cc085e3aed85a1eb55c3aac6a63d5c30dfd4ca',
    'fragment_sha256':'a12ed0611ea50eb50e3c762d4df5cd074f81b82ef4c5b934303751ecb46bf544',
    'diagnostic_fragment_sha256':'cf1edfe38bbbac56055a7780515e83ae5b0b7ed5c6ee9d7a2e584b9aa7074d82',
    'config':dict(bytes=64368,sha256='8f9c37958a64701c8e0459ba29c78def06810291018a75cc657ab736a10bb917'),
}


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def verify_profile(value, cfg):
    need(type(value) is dict and set(value)==EXPECTED.keys()|{'Image'} and
         all(type(value[name]) is type(wanted) and value[name]==wanted for name,wanted in EXPECTED.items()),
         'exact KSM+virtio generated config and original-source build identities required')
    image=value['Image']
    need(type(image) is dict and set(image)=={'bytes','sha256'} and type(image['bytes']) is int and
         64<=image['bytes']<=256*1024**2 and type(image['sha256']) is str and
         re.fullmatch(r'[a-f0-9]{64}',image['sha256']) and image['sha256'] not in (OLD_IMAGE, '6c16ef2c2802f4481edc0b1b0e6cc0e9521b6e103b9060697c0bd49d32a25295'),
         'new actual combined kernel Image identity required')
    need(pin(cfg)==EXPECTED['config'] and
         all(value.encode() in cfg.splitlines() for value in
             ('CONFIG_IPV6=y','CONFIG_PROC_FS=y','CONFIG_KSM=y','CONFIG_VIRTIO_INPUT=y','CONFIG_INPUT_EVDEV=y','CONFIG_ARM64_16K_PAGES=y',
              '# CONFIG_MODULES is not set')),'unchanged KSM with built-in virtio-input and exact 16K config')
    return value


def scope(owned):
    keys=('source','run','attempt','case','job_token')
    actual={k:owned[k] for k in keys}
    need(type(actual['source']) is str and re.fullmatch(r'[a-f0-9]{40}',actual['source']) and
         type(actual['run']) is int and actual['run']>0 and type(actual['attempt']) is int and
         actual['attempt']==1 and actual['case'] in ('minimal-generic16k','overlay-generic16k') and
         actual['job_token']==hashlib.sha256(f"product-build-pair:{actual['run']}:1:{actual['source']}".encode()).hexdigest()[:16],
         'same exact attempt-one Current606 ARM16K build/GUI owner required')
    return actual


def load_verifier(verifier):
    need(verifier.is_absolute() and verifier==verifier.resolve(strict=True) and verifier.stat().st_nlink==1 and
         pin(verifier.read_bytes())==VERIFIER_PIN,'exact independently prepared KSM+input build verifier bytes')
    spec=importlib.util.spec_from_file_location('_current606_ksm_virtio_source_verifier',verifier)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def stage(runner, built, owned, verifier, plan):
    """Select only bytes from the complete, exact build under this same GUI job."""
    selected=scope(owned)
    intended=Path(owned['state'])/'keyboard-kernel'/'built'
    need(built==intended and built.is_absolute() and built==built.resolve(strict=True) and
         runner==Path(owned['state'])/'runner','same-job owned kernel and runner paths required')
    V=load_verifier(verifier)
    need(pin(V.read(plan,8192))==PLAN_PIN,'whole independently prepared source-only KSM+input plan')
    profile=V.complete(built)
    image=V.read(built/'build/arch/arm64/boot/Image',256*1024**2)
    config=V.read(built/'build/.config',256*1024)
    receipt=V.read(built/'build-receipt.json',128*1024)
    verify_profile(profile,config)
    need(pin(image)==profile['Image'],'same completed job Image body')
    body=encoded(profile)
    join=dict(status='PASS_SAME_CURRENT606_CASE_JOB_OWNED_KERNEL_BUILD_DATA_ONLY',**selected,
              verifier=VERIFIER_PIN,plan=PLAN_PIN,receipt=pin(receipt),profile=pin(body),
              Image=pin(image),config=pin(config),native_GUI=None)
    files={'diagnostic.Image':image,'kernel-profile.json':body,
           'kernel-config':config,'kernel-build-receipt.json':receipt,'kernel-build-join.json':encoded(join)}
    need(runner.is_dir() and runner==runner.resolve(strict=True) and
         not any((runner/name).exists() or (runner/name).is_symlink() for name in files),'fresh exact runner media')
    for name,raw in files.items():
        with (runner/name).open('xb') as stream:
            stream.write(raw)
    return join



def replay(H, root, public, owned, gui, private):
    """Join original same-job media custody, with raw build receipts kept by the actor."""
    actual=scope(owned)
    generated=public/'generated'
    body=H.ordinary(generated/'kernel-profile.json',65536)
    profile=json.loads(body)
    source=root/'factory/kernel-keyboard'
    V=load_verifier(source/'scripts/ci/current606-ksm-virtio-input/verify.py')
    H.need(pin(H.ordinary(source/'source-plan.json',8192))==PLAN_PIN,'exact source plan')
    _,cfg,_,_=V.source(source/'scripts/ci/current606-ksm-virtio-input')
    verify_profile(profile,cfg)
    H.need(profile['Image']==private['diagnostic.Image'] and profile['config']==private['kernel-config'],
           'original private combined Image/config digest matches generated profile')
    expected=dict(status='PASS_SAME_CURRENT606_CASE_JOB_OWNED_KERNEL_BUILD_DATA_ONLY',**actual,
                  verifier=VERIFIER_PIN,plan=PLAN_PIN,receipt=private['kernel-build-receipt.json'],
                  profile=pin(body),Image=private['diagnostic.Image'],config=pin(cfg),native_GUI=None)
    H.need(H.read(generated/'kernel-build-join.json',8192)==expected,'same exact case-owned build join')
    custody=H.read(public/'kernel-media-custody.json',65536)
    H.need(custody==dict(status='SAME_CASE_KERNEL_BUILD_AND_MEDIA_JOIN_DATA_ONLY', **actual,
                         join=expected, evidence=H.read(generated/'kernel-build-evidence.json',65536)),
           'exact same-case build provenance and private evidence pins')
    evidence=custody['evidence']
    H.need(set(evidence)=={'owner','result','controller','logs','acquisition'} and
           set(evidence['logs'])=={'configure','build','controller_stdout','controller_stderr'} and
           all(valid_pin(row) for row in (
               evidence['owner'],evidence['result'],evidence['controller'],evidence['acquisition'],*evidence['logs'].values())),
           'whole job-owned controller/acquisition result and bounded command log pins')
    boots=[row for row in gui['events'] if row.get('event')=='boot']
    H.need(len(boots)==1 and boots[0]['architecture']=='aarch64' and boots[0]['page_size']==16384 and
           boots[0]['kernel']==RELEASE and boots[0]['kernel_profile_sha256']==pin(body)['sha256'],
           'exact staged combined kernel boot')
    return custody


def valid_pin(row):
    return type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and \
           0<=row['bytes']<=16*1024**2 and type(row['sha256']) is str and re.fullmatch('[a-f0-9]{64}',row['sha256'])

# SPDX-License-Identifier: MIT
"""Stage the job-owned KSM keyboard profile and preserve the original MOPS source proof."""
import json
from pathlib import Path
import factory as F

def source_support():
    root=F.HERE/'kernel-build-context';proof=F.obj(root/'primary-profile.json')
    F.need(proof['source_revision']=='94fb23346d522edf53722357c426a3e58030beea'and set(proof['files'])=={'arch/arm64/Kconfig','arch/arm64/kernel/pi/idreg-override.c','arch/arm64/kernel/cpufeature.c','arch/arm64/lib/memset.S','arch/arm64/tools/cpucaps','arch/arm64/include/uapi/asm/hwcap.h','COPYING','LICENSES/preferred/GPL-2.0','LICENSES/exceptions/Linux-syscall-note'},'whole exact kernel primary source contract')
    for n,w in proof['files'].items():F.need(F.pin(F.read(root/'primary'/n))==w,'exact kernel primary bytes '+n)
    def read(n):return F.read(root/'primary'/n).decode()
    F.need('config ARM64_MOPS'not in read('arch/arm64/Kconfig')and 'config AS_HAS_MOPS\n\tdef_bool $(as-instr,.arch_extension mops)'in read('arch/arm64/Kconfig'),'actual assembler MOPS test; no invented ARM64_MOPS symbol')
    F.need('{ "arm64.nomops",\t\t"id_aa64isar2.mops=0" }'in read('arch/arm64/kernel/pi/idreg-override.c')and 'FIELD("mops", ID_AA64ISAR2_EL1_MOPS_SHIFT, NULL)'in read('arch/arm64/kernel/pi/idreg-override.c'),'exact actual early MOPS field override')
    F.need('#ifdef CONFIG_AS_HAS_MOPS'in read('arch/arm64/lib/memset.S')and 'alternative_if_not ARM64_HAS_MOPS'in read('arch/arm64/lib/memset.S')and 'HWCAP_CAP(ID_AA64ISAR2_EL1, MOPS, IMP, CAP_HWCAP, KERNEL_HWCAP_MOPS)'in read('arch/arm64/kernel/cpufeature.c')and '#define HWCAP2_MOPS\t\t(1UL << 43)'in read('arch/arm64/include/uapi/asm/hwcap.h'),'real kernel fallback and userspace HWCAP2 bit')
    return proof

KEYBOARD=F.HERE/'kernel-keyboard'
VERIFIER=KEYBOARD/'scripts/ci/current606-ksm-virtio-input/verify.py'
PLAN=KEYBOARD/'source-plan.json'


def route():
    profile=F.obj(F.HERE.parent/'kernel-media-profile.json')
    F.need(profile['status']=='SOURCE_ONLY_SAME_JOB_KSM_VIRTIO_INPUT_BUILD' and profile['ready'] is True and
           profile['actual'] is profile['Image'] is profile['config'] is None and
           profile['output']=='keyboard-kernel/built','exact same-job source-only input; no prior media')
    for name,wanted in profile['files'].items():
        F.need(F.pin(F.read(KEYBOARD/name))==wanted,'exact owned kernel recipe source '+name)
    return profile


def module():
    return F.load('_current606_bound_kernel_handoff',F.HERE/'kernel_media_handoff.py')


def ownership(built,owned,initialized):
    H=module(); selected=H.scope(owned)
    state=Path(owned['state']); work=state/'keyboard-kernel'
    F.need(built==work/'built' and built.resolve(strict=True)==built and
           initialized==dict(status='CURRENT606_R6_KERNEL_INIT_SOURCE_ONLY', **selected, state=str(state),
                             media=F.pin(F.read(F.HERE.parent/'kernel-media-profile.json'))),
           'same actor source-bound kernel stage')
    V=H.load_verifier(VERIFIER)
    files={key:V.read(work/name,cap) for key,name,cap in (
        ('owner','owner.json',8192),('result','result.json',65536),
        ('controller','controller.json',65536),('acquisition','acquisition.json',65536))}
    token={k:owned[k]for k in ('source','run','attempt')};token.update(repository='Gabriel-Kahen/cachy-asahi',run=str(token['run']))
    result,controller,owner,acquisition=(json.loads(files[k]) for k in ('result','controller','owner','acquisition'))
    info=work.stat()
    F.need(owner==dict(source=token,work_inode=info.st_ino,work_device=info.st_dev,work_uid=info.st_uid) and
           result['source']==token and result['status']=='BUILT_ONLY_CURRENT606_KSM_VIRTIO_INPUT' and
           result['retention']=='OWNED_JOB_OUTPUT_ONLY' and result['boot']=='NOT RUN' and
           result['controller']==controller and controller['exit_code']==0 and controller['group_absence_verified'] is True and
           acquisition['status'] in ('FETCHED_HASH_VERIFIED','RETAINED_ARCHIVE_HASH_VERIFIED'),
           'exact finished job-owned kernel acquisition and controller retirement')
    logs={}
    receipt=F.obj(built/'build-receipt.json')
    archive=work/'inputs/kernel.tar.gz'
    argv=['/usr/bin/python3','-I','-B',str(work/'build_kernel.py'),'--archive',str(archive),
          '--output',str(built),'--build','--boot-diagnostics']
    material={key:acquisition['result'][key] for key in ('path','bytes','sha256')}
    F.need(material==receipt['archive']==dict(path=str(archive),**V.ARCHIVE) and acquisition['partial_absent'] is True and
           acquisition['source_revision']==V.SOURCE and controller['argv']==argv and
           controller['time_limit']==3700 and controller['output_limit']==16*1024**2,
           'exact owned archive, controller command, helper and build paths')
    for key,home,name in (('configure',built,'configure.log'),('build',built,'build.log'),
                          ('controller_stdout',work,'controller.stdout'),('controller_stderr',work,'controller.stderr')):
        raw=F.read(home/name);F.need(len(raw)<=16*1024**2,'exact bounded held kernel command log');logs[key]=F.pin(raw)
    for index,key in enumerate(('configure','build')):
        row=receipt['commands'][index];F.need(logs[key]==dict(bytes=row['log_bytes'],sha256=row['log_sha256']),
                                              'whole held compiler command log')
    for channel in ('stdout','stderr'):
        F.need(logs['controller_'+channel]==dict(bytes=controller[channel+'_bytes'],sha256=controller[channel+'_sha256']),
               'whole held controller output log')
    return dict({key:F.pin(raw) for key,raw in files.items()},logs=logs),result['profile']


def stage(runner,built,proof,init):
    source_support();route();owned=F.obj(proof);state=Path(owned['state'])
    F.need(proof==state/'source-proof.json' and init==state/'kernel-init.json','exact same job proof input paths')
    evidence,profile=ownership(built,owned,F.obj(init))
    H=module();join=H.stage(runner,built,owned,VERIFIER,PLAN)
    F.need(F.obj(runner/'kernel-profile.json')==profile,'same completed build profile')
    (runner/'kernel-build-evidence.json').write_bytes(F.enc(evidence))
    return dict(status='SAME_CASE_KERNEL_BUILD_AND_MEDIA_JOIN_DATA_ONLY',**H.scope(owned),join=join,evidence=evidence)


def boot_contract(out):
    # Keep the legacy loader/boot body. Only the freshly generated 16K profile changes.
    p=out/'kernel_contract.py';old=F.read(p);text=old.decode();H=module()
    values={'PROFILE':H.PROFILE,'HELPER_SHA':H.EXPECTED['helper_sha256'],
            'FRAGMENT_SHA':H.EXPECTED['fragment_sha256'],'DIAGNOSTIC_SHA':H.EXPECTED['diagnostic_fragment_sha256']}
    for key,value in values.items():
        line=next(row for row in text.splitlines() if row.startswith(key+'='));text=F.once(text,line,key+'='+repr(value))
    anchor='    return value\n'
    check=f"    need(value['config']=={H.EXPECTED['config']!r} and value['Image']['sha256']!={H.OLD_IMAGE!r},'exact combined kernel profile')\n"
    text=F.once(text,anchor,check+anchor)
    raw=text.encode();compile(raw,str(p),'exec');p.write_bytes(raw)
    return dict(before=F.pin(old),after=F.pin(raw))

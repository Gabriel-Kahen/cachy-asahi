# SPDX-License-Identifier: MIT
"""Exact original KSM diagnostic media, actual managed needs, and supported MOPS guard."""
import json,shutil
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

def stage(runner,image,config,profile):
    primary=source_support();K=F.load('_current606_exact_KSM_kernel',F.HERE/'support/kernel_contract.py');value=json.loads(F.read(profile));K.validate(value)
    F.need(value['profile']=='KSM_ADVICE_GENERIC16K_DIAGNOSTIC_V1'and value['Image']==dict(bytes=8884232,sha256='039fbeaff5942de2317f47feec30a5c073691edf5f8cef8849b25d08006d4ddb')and value['config']==dict(bytes=63793,sha256='5f1f5e507586734c0955607960ceecfe822b5c908bfc1da9d29fe80ac627a8e9'),'exact original KSM Image/config; no profile relabeling')
    raw=F.read(image);conf=F.read(config);F.need(F.pin(raw)==value['Image']and F.pin(conf)==value['config'],'whole explicit original KSM media')
    root=F.HERE/'kernel-build-context';F.need(F.pin(F.read(root/'build_kernel.py'))==dict(bytes=12899,sha256='7372ebfece249fae202652f3c3bb419f730bd0e466dc076907270dac1ac873ed')and F.pin(F.read(root/'kernel.fragment'))==dict(bytes=1846,sha256='f4a6dc3fbebd5f0e184422cddc490e47e6737d208c55b7df255b678604fe9267'),'whole original native KSM build helper and fragment')
    helper=F.load('_current606_original_KSM_build_checks',root/'build_kernel.py');managed=helper.config_check(config,True);header=helper.image_check(image)
    lines=conf.decode().splitlines();F.need('CONFIG_AS_HAS_MOPS=y'in lines and not any(l.startswith('CONFIG_ARM64_MOPS=')for l in lines),'actual built assembler capability; invented config refused')
    for name,path in [('diagnostic.Image',image),('kernel-profile.json',profile)]:F.need(not(runner/name).exists(),'fresh explicit kernel media');shutil.copyfile(path,runner/name)
    return dict(status='EXACT_ORIGINAL_KSM_DIAGNOSTIC16K_MEDIA_STAGED_NOT_BOOTED',Image=value['Image'],config=value['config'],managed_route_config=managed,Image_header=header,source_revision=primary['source_revision'],NOMOPS='REQUIRES_NEW_SAME_EPOCH_ROOT_USER_HWCAP_ZERO_AND_UART',actual=None)

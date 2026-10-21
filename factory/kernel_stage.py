# SPDX-License-Identifier: MIT
"""Read only an explicit exact managed16K Image/config/profile; never build or boot."""
import json,shutil,struct
from pathlib import Path
import factory as F

def stage(runner,image,config,profile):
    K=F.load('_current606_exact_kernel',F.HERE/'support/kernel_contract.py');value=json.loads(F.read(profile));K.validate(value)
    raw=F.read(image);conf=F.read(config);F.need(F.pin(raw)==value['Image']and F.pin(conf)==value['config'],'whole explicit managed16K media')
    F.need(len(raw)>=64 and raw[56:60]==b'ARM\x64'and(struct.unpack_from('<Q',raw,24)[0]>>1)&3==2,'actual16K ARM Image header')
    lines=conf.decode().splitlines();F.need('CONFIG_ARM64_16K_PAGES=y'in lines and 'CONFIG_ARM64_MOPS=y'in lines and 'CONFIG_MODULES=y'not in lines,'exact16K built-ins and kernel NOMOPS support required')
    for name,path in [('diagnostic.Image',image),('kernel-profile.json',profile)]:F.need(not(runner/name).exists(),'fresh explicit kernel media');shutil.copyfile(path,runner/name)
    return dict(status='EXACT_MANAGED16K_MEDIA_STAGED_NOT_BOOTED',Image=value['Image'],config=value['config'],NOMOPS='REQUIRES_NEW_ORIGINAL_UART_FORCED_ZERO_READBACK',actual=None)

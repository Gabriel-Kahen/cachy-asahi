#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded DATA-only embedded IKCONFIG inspection, not a boot/hardware check."""
import gzip,hashlib,json
from pathlib import Path
NEEDED={'CONFIG_VT':'y','CONFIG_VT_CONSOLE':'y','CONFIG_VGA_CONSOLE':'y','CONFIG_FRAMEBUFFER_CONSOLE':'y','CONFIG_INPUT_EVDEV':'y','CONFIG_SERIO_I8042':'y','CONFIG_KEYBOARD_ATKBD':'y','CONFIG_DRM_BOCHS':'m'}
def inspect(kernel):
 from compression import zstd
 data=Path(kernel).read_bytes();assert len(data)<32*1024**2
 marker=b'\x28\xb5\x2f\xfd';offset=data.index(marker);decoder=zstd.ZstdDecompressor();decoded=decoder.decompress(data[offset:],max_length=128*1024**2);assert decoder.eof and len(decoded)<128*1024**2
 begin=decoded.index(b'IKCFG_ST')+8;end=decoded.index(b'IKCFG_ED',begin);assert end-begin<1024**2
 config=gzip.decompress(decoded[begin:end]);assert len(config)<1024**2
 fields=dict(line.split('=',1)for line in config.decode().splitlines()if line.startswith('CONFIG_')and '='in line)
 selected={key:fields.get(key)for key in NEEDED};assert selected==NEEDED,selected
 return {'scope':'embedded kernel configuration declarations only; VT/input/seat execution NOT RUN','kernel_sha256':hashlib.sha256(data).hexdigest(),'kernel_bytes':len(data),'embedded_config_sha256':hashlib.sha256(config).hexdigest(),'decoded_kernel_bytes':len(decoded),'config':selected}

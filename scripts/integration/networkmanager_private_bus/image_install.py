#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Only image-layer installation; exact archived bytes, hooks/scriptlets inert."""
import argparse,hashlib,json,os,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--allow-private-image-install',action='store_true');a=p.parse_args()
if not(__debug__ and a.allow_private_image_install and os.geteuid()==0 and os.environ.get('CACHY_ASAHI_PRIVATE_BUS_IMAGE_BUILD')=='1'):
 raise RuntimeError('explicit private image build only; never host installation')
mounts=[line.split(' - ')for line in Path('/proc/self/mountinfo').read_text().splitlines()]
assert any(before.split()[4]=='/'and after.split()[0]in {'overlay','fuse-overlayfs'}for before,after in mounts),'private image overlay required'
root=Path('/opt/nm-private-bus');contract=json.loads((root/'contract.json').read_text())
masks=Path('/tmp/TEST-masked-hooks');masks.mkdir()
for base in [Path('/usr/share/libalpm/hooks'),Path('/etc/pacman.d/hooks')]:
 for p in base.glob('*.hook'):
  m=masks/p.name
  if not m.is_symlink():m.symlink_to('/dev/null')
paths=[]
for ref in contract['archives']:
 p=root/ref['name'];assert p.stat().st_size==ref['bytes']and hashlib.sha256(p.read_bytes()).hexdigest()==ref['sha256'];paths.append(str(p))
config=Path('/tmp/TEST-pacman.conf');config.write_text('[options]\nArchitecture = x86_64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Optional TrustedOnly\n')
subprocess.run(['pacman','--config',str(config),'--hookdir',str(masks),'--noscriptlet','--noconfirm','-U',*paths],check=True,timeout=90)
subprocess.run(['pacman','--config',str(config),'-Dk'],check=True,timeout=10)
Path('/etc/machine-id').write_text('3143143143144143a143143143143143\n')
Path('/opt/TEST-NM-installed-inventory.txt').write_bytes(subprocess.check_output(['pacman','--config',str(config),'-Q']))

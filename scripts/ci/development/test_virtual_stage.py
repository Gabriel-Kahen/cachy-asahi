"""Virtual adapter tests use temporary fixtures and mocked fetch/owner commands."""
import copy
import base64
import hashlib
import json
import io
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).parent.resolve()
sys.path.insert(0, str(HERE))
import virtual_stage as v


# Exact public baseline metadata/signatures from native run 38218102399.
# Inline fixtures keep frozen tests independent of ignored artifact directories.
ACTUAL_UNSIGNED_BASELINE = [{'archive': 'baseline/cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.xz', 'name': 'cachy-asahi-fish-config', 'payload_sha256': {'usr/share/cachy-asahi/fish/config.fish': '223df59fe83948e1d83676f4571cd2d4ce186862adf1cc23da6d5bbd28370a1c', 'usr/share/licenses/cachy-asahi-fish-config/LICENSE': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7', 'usr/share/licenses/cachy-asahi-fish-config/NOTICE': '19eb85ed65396056e59782ddf80fb5285ee26cad5ddf77ccb378936a2d5601c9'}, 'sha256': '22e6e3ca4f23b73434c4aed284016914652900c33e845516621c0eb8b176d64e', 'version': '0.1.0-1'}, {'archive': 'baseline/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz', 'name': 'cachy-asahi-hyprland-settings', 'payload_sha256': {'usr/share/cachy-asahi/hyprland/hyprland.lua': 'f900ffbfdea86acc686299fd9ef88a235fb4822f7177afe75a43369ca48d158b', 'usr/share/cachy-asahi/hyprland/mako.conf': 'c6ab55ae475611bf2df2b7120b97a924eed5d65c149561d4da4f12b5b8c25504', 'usr/share/cachy-asahi/hyprland/waybar.css': 'a97930965a4e622adc920491c7d433a803173bb6e644c4c3c88efb79187e11d5', 'usr/share/cachy-asahi/hyprland/waybar.json': '4c7adb2deb0403fefc4562d39105635cebfc44ce88e44fe84c4a90a00b2be3c0', 'usr/share/doc/cachy-asahi-hyprland-settings/README.md': '3edac178cb92d6d06b21fe4832bbbce5f7a55ed4dde8925ac0815c5350e2c525', 'usr/share/licenses/cachy-asahi-hyprland-settings/LICENSE': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7', 'usr/share/licenses/cachy-asahi-hyprland-settings/NOTICE': '7c108a66b5a4807f8fe7696ef1b1011386b37774fb94e674dd37c7e1dec7b9e4'}, 'sha256': '5d33320b55c2b3c778b94c128980c2d07d3fbcf466b3ab91ad8a706ff538ee81', 'version': '0.1.0-1'}, {'archive': 'baseline/cachy-asahi-setup-0.1.0-2-any.pkg.tar.xz', 'name': 'cachy-asahi-setup', 'payload_sha256': {'usr/bin/cachy-asahi-setup': 'a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2', 'usr/share/doc/cachy-asahi-setup/README.md': '434328ca04e757a2dc8bba78bea82c6ed52da64b139e88666a3ec2db52ba0e56', 'usr/share/licenses/cachy-asahi-setup/LICENSE': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7', 'usr/share/licenses/cachy-asahi-setup/NOTICE': '2c28b96b5e4dca86c8a71aa0df728a049820d5951812f20241be96e7000d9744'}, 'sha256': '40e392b4af6485d8518993073c1fe643eda60053312aeb618dfa9a6c9bee3489', 'version': '0.1.0-2'}, {'archive': 'baseline/cachy-asahi-zsh-config-0.1.0-1-any.pkg.tar.xz', 'name': 'cachy-asahi-zsh-config', 'payload_sha256': {'usr/share/cachy-asahi/zsh/README.md': '19a9df455ad2c42b01eb184bdfb0b14402fe372e397fa91cc0ee28dd766bb65d', 'usr/share/cachy-asahi/zsh/config.zsh': '7639b938dca689c445b64cc307148e2d3f85c5399d51c8ce69072dcf835baa6f', 'usr/share/licenses/cachy-asahi-zsh-config/LICENSE': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7', 'usr/share/licenses/cachy-asahi-zsh-config/NOTICE': '20f1a90870566d337745019d5c465db48e14a566df3222c48a3320dc441e4de8'}, 'sha256': '1bcb8e7fde6da28bc817f252bee5c7084cd22ec4153512eaf5bb47bd83e90faa', 'version': '0.1.0-1'}]
ACTUAL_SIGNED_BASELINE = [{'archive': 'baseline/cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.xz', 'name': 'cachy-asahi-fish-config', 'payload_sha256': {'usr/share/cachy-asahi/fish/config.fish': '223df59fe83948e1d83676f4571cd2d4ce186862adf1cc23da6d5bbd28370a1c', 'usr/share/licenses/cachy-asahi-fish-config/LICENSE': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7', 'usr/share/licenses/cachy-asahi-fish-config/NOTICE': '19eb85ed65396056e59782ddf80fb5285ee26cad5ddf77ccb378936a2d5601c9'}, 'sha256': '22e6e3ca4f23b73434c4aed284016914652900c33e845516621c0eb8b176d64e', 'signature_sha256': '888c95b7b852ae820c41e4b96aa12b336f655e98b6984a03b4d60af39b66c22b', 'version': '0.1.0-1'}, {'archive': 'baseline/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz', 'name': 'cachy-asahi-hyprland-settings', 'payload_sha256': {'usr/share/cachy-asahi/hyprland/hyprland.lua': 'f900ffbfdea86acc686299fd9ef88a235fb4822f7177afe75a43369ca48d158b', 'usr/share/cachy-asahi/hyprland/mako.conf': 'c6ab55ae475611bf2df2b7120b97a924eed5d65c149561d4da4f12b5b8c25504', 'usr/share/cachy-asahi/hyprland/waybar.css': 'a97930965a4e622adc920491c7d433a803173bb6e644c4c3c88efb79187e11d5', 'usr/share/cachy-asahi/hyprland/waybar.json': '4c7adb2deb0403fefc4562d39105635cebfc44ce88e44fe84c4a90a00b2be3c0', 'usr/share/doc/cachy-asahi-hyprland-settings/README.md': '3edac178cb92d6d06b21fe4832bbbce5f7a55ed4dde8925ac0815c5350e2c525', 'usr/share/licenses/cachy-asahi-hyprland-settings/LICENSE': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7', 'usr/share/licenses/cachy-asahi-hyprland-settings/NOTICE': '7c108a66b5a4807f8fe7696ef1b1011386b37774fb94e674dd37c7e1dec7b9e4'}, 'sha256': '5d33320b55c2b3c778b94c128980c2d07d3fbcf466b3ab91ad8a706ff538ee81', 'signature_sha256': '3d90ca1056a8a4d924eef841554e53e5d390953c2c1afcf3aaa868c2e8ba2709', 'version': '0.1.0-1'}, {'archive': 'baseline/cachy-asahi-setup-0.1.0-2-any.pkg.tar.xz', 'name': 'cachy-asahi-setup', 'payload_sha256': {'usr/bin/cachy-asahi-setup': 'a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2', 'usr/share/doc/cachy-asahi-setup/README.md': '434328ca04e757a2dc8bba78bea82c6ed52da64b139e88666a3ec2db52ba0e56', 'usr/share/licenses/cachy-asahi-setup/LICENSE': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7', 'usr/share/licenses/cachy-asahi-setup/NOTICE': '2c28b96b5e4dca86c8a71aa0df728a049820d5951812f20241be96e7000d9744'}, 'sha256': '40e392b4af6485d8518993073c1fe643eda60053312aeb618dfa9a6c9bee3489', 'signature_sha256': '9f0eca6793dd1793a5c2c855168c0204541b32d1362cbdcbdee77960c7258db9', 'version': '0.1.0-2'}, {'archive': 'baseline/cachy-asahi-zsh-config-0.1.0-1-any.pkg.tar.xz', 'name': 'cachy-asahi-zsh-config', 'payload_sha256': {'usr/share/cachy-asahi/zsh/README.md': '19a9df455ad2c42b01eb184bdfb0b14402fe372e397fa91cc0ee28dd766bb65d', 'usr/share/cachy-asahi/zsh/config.zsh': '7639b938dca689c445b64cc307148e2d3f85c5399d51c8ce69072dcf835baa6f', 'usr/share/licenses/cachy-asahi-zsh-config/LICENSE': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7', 'usr/share/licenses/cachy-asahi-zsh-config/NOTICE': '20f1a90870566d337745019d5c465db48e14a566df3222c48a3320dc441e4de8'}, 'sha256': '1bcb8e7fde6da28bc817f252bee5c7084cd22ec4153512eaf5bb47bd83e90faa', 'signature_sha256': 'f14c777438033fa4852cd30fdfa43619040f4e24d9ca3b3a3eb75f051774da64', 'version': '0.1.0-1'}]
ACTUAL_BASELINE_SIGNATURES = {'baseline/cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.xz': b"\x89\x013\x04\x00\x01\x08\x00\x1d\x16!\x04R\xee\xbd\t\xed\x80M\xd5`\x82o\x82s\r7{\x03\xa6`D\x05\x02j\xcc\x8d|\x00\n\t\x10s\r7{\x03\xa6`D+i\x08\x00\xab\xff\xa8Q\x94\x97\x9b\x8e\xbb\x86\xea%\x90\x8b\xf0\xb7\xf7R\xda\x8b&\x03\x14\x9d2\x96w\xe5\xcf\x87\xed\x01\xb97\x91C-\xe6_\xbdz~\x80h$\xfdD\xc4)\xe7\xf9\x9b\xc2\xdb\x95\xc8\xbe`\xe7\x1e\x8f\xfe\x01TH'\x03\xeb\xa9F\x86\xc9\xa4O\x1c\xe7\xfb4\xf0\xe3\x0f\\\xff<(P\x08\xbd\xe1\xdd\xadf\xb2\x8a\xe6\x9dE\xea\x85\xa9\x8d\x94\n\x91c\xdd\xff\x89p\x0f \n\xb4\xe2Er\x95{\xd2GL\xf9\xe6\xb7\xc9\x8b\xd7\xba\xa47:&\xde\xd0jk\x8e\xd6\x01\xb6\xbe\xcb\xc8\xbf\xfak\xeb\x9d\xad\x15\xf0\x7fX\xfd'\x81\xf9\xe7\xbb\x89\x06$\x1a\x85\x99\x8dX\xee\xbeS\x8d\x00\xae\x0e\xb7\xe5\xb7\x85\xf5_=\xf7\xd31\xb0\xc3\x1a\xaf\x8a:%\x08}$\xfd\x02P\x1b\r\xaa`#S\xac\x12oFm\x84\xe2\xd25I\xc2NC\x88\xcf\x10\ne\xd8\xc3\xa8\xf5\xe6%\xf9V\xa6X\x1b\x90i[\x05\xa0\xcc\xa6\x7fB6*\xeb\xf8?\xbarS\x98W^\xab'RL", 'baseline/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz': b'\x89\x013\x04\x00\x01\x08\x00\x1d\x16!\x04R\xee\xbd\t\xed\x80M\xd5`\x82o\x82s\r7{\x03\xa6`D\x05\x02j\xcc\x8d|\x00\n\t\x10s\r7{\x03\xa6`D\xe7(\x07\xfe+\xf3]\xc9\x12\x07\xc4[\x8e\xd8X\xb40\xe7 \xcb)6}\xd4b\\\x9e*\xd4\xc2\xb7\xa5?O\xac\x11@\x16\x06ZU\x04\xd8R\xd3\x012\xf7\x82\x83\xa1\x87\xcb\x11*\x1c\xb0q8hV\xb6\xe0\xca\xb8\xef\x93\xdep\x12Q\x90\x19\x010\x89\xc1:\xb0.\xe0M\x95/\x1a\x84\x19_\x8b\xb9\x86\xeb\x9c\x01X\xad\x01\xe6r\x12E8i\x1e,\xfd\x91\xdbU\xbf\xd5\xc0\xdd\xda\x0et\xc7\xfbT\xd7\xd4\xa4\xb4\x8flR\xfdtKB)\xf9\xb2\xcf]s4\x91\xd8S\xc4!Pn\xef\xd1\xe2\xa8\x06\xd5\x9aVj\xb8\xfd\xbf\xc2\x83\xc3S\xfas\xcc\xae\xc8\x1b\xbf>\n\x1cgk\xf7d\xc9ey\xd58\x04:\xed\r\x1b\xba\xd6eX\x91"\x82\x8cXt\x12X/jS\xf0\xbf\x82M\xa4\x1b\xd7\x8f\xe7\xaf\x10\'\xba/\\N\x98\xcf\x1b\xbe\x03\x18\x11\xfa8\xa8-\xb1\xff\xdd\x8d\xc4t\x88\xcd\xfc\x06=Q\xe7\x08\xf8NV[\xff\xb6\xbf\x7f_.4\x1e+\x84v\xd00]=\xaf', 'baseline/cachy-asahi-setup-0.1.0-2-any.pkg.tar.xz': b'\x89\x013\x04\x00\x01\x08\x00\x1d\x16!\x04R\xee\xbd\t\xed\x80M\xd5`\x82o\x82s\r7{\x03\xa6`D\x05\x02j\xcc\x8d|\x00\n\t\x10s\r7{\x03\xa6`Dx.\x08\x00\xa0]A(\x9f\x0c\xfc\xa1F\xe3\xb4Y\xd7\xb5)\x90\x07\xe6\xac\x19|\xf4"\x0eT\xaa\x02\xd3\xbe\x07!\xa05\\\x91\xb1\xf7\xf4I\xe9\x86\x8f\x17\x1d\xe2\x1e\xcb\x8e\x92\xa6\x7f\x84\x89\xe5\xf0>\xb9S\xef\x7f\x87\xda\xd9\x8a.I\xab\xb0\xac\xc8\xbcx\'\xf7b$\xe1\x91Z+\xe4\xcf\x18T\x98\x8a\r\x99dm\x81\xc0T\xc6\xb3\xedw\xe4\xdf\xab+f\x0c%\x06\xeaH\xc7\x1b\xae\x03\x9362\xf2\xfe"\xf4\x0f9\tG\x0b\xd8\x9a\xbb\x91\xec\xd9\x88\x95\x8c\xe1*\xde\xfb\xc5\xa0\xb4V?9o\xef",\xd4\xc1\r\x19\x8fm\xa8\x98*\x1ch\x15\xe7\xa4\xb6\x8f\x98f\xac\xd0\x9bjR\xa4\xc2\x93\xac\xcc\x90lJ\x0f\xd2&\xb7N\x93\x8c%\x90\xd3\xcb"\rNu;EY\xean\x1b<u\xde\xe4\xba\x1f\n\x162\x1f[\x9f\xf5\x05h\x93(Ma\xf9\xf6\xa1\x14\xc3\xbb\xc1L[\xd1\x98M\x99\xf9\xef_\x96\xa9V\xa5K\xae)T22/\xc8\xd9+n\xf1 \xef\xd1\xa6\xa3(\xd8', 'baseline/cachy-asahi-zsh-config-0.1.0-1-any.pkg.tar.xz': b'\x89\x013\x04\x00\x01\x08\x00\x1d\x16!\x04R\xee\xbd\t\xed\x80M\xd5`\x82o\x82s\r7{\x03\xa6`D\x05\x02j\xcc\x8d|\x00\n\t\x10s\r7{\x03\xa6`D\x9d\xbb\x07\xffG\x8d(\xc1\r\\\xeb\xfe\xfc\xef\x90\x18\x97>L\x8eV\xe9i\x1c\xe2 bc\x99\xc6F\xeb=0\xed\x88\x80HY\xdf\x10\xb7yXI\x0c\xb5"\t\xdbG \xb4\x99Z\x89\x11<\x98\xf6P\x82\x1e\xbb\xc5\xef\xcc\xe7\xaf\xd9y\xd6J\xfd\x19(\xfe\xe3M@\xec\xdb\xf0\x1c\x95\xediq\x18\xee5|\x06\xcc\x0f\x8c\xe4\x05\xa5\xd6}t\x1a\xa4P\xb2\xef\xe2\x89\xb5\xec`\x94\xc2l^\xe0m\xa0\x83\xccO\xf2\xbb\xc9~\\\x9a\xccj\xc6\x14\xc8{\xd3n@\x9b\x1f\x87#T\xabA\xd0?n\x12\xab=\xc4\xe0C\x03`\xca\xe6\xb1\x90\x1cgT\x94\x92h\x9a8\xf7|td^\xd8\x92DLZ\xbe\x0e\xbb\x01\x06\xf4\n\x02L\xd1t\xfc`B\xeb\xa0\xee46\x87f\xdc\x1e\xa3e\x01\xba2\x9a\xf0\x94\xf9\xa1\x06F\xe6\xfe\x14l\x81\xcb\xbe\x14\x06\xc4\xa3{\x95\xc4\x1d[\r\xfd\xcf\xa9\x16\x9e\xc9le\x8fk\t\x04.\x0fd5}\x91oy\x8ba[\xf3R\xf2\xf4?\x9a\xa9B'}
ACTUAL_SIGNER_RECEIPT = {'contract': {'entry_sha256': '430a52245fb2adb6a6c9fb68ee256570ca1c5468863f5e0f3b04145e0d9dcf85', 'helpers_sha256': {'runner/native_arm.py': 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898', 'scripts/checks/package_checks.py': 'e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8'}, 'image_id': 'sha256:a7989a21d249515b0f16d7a83118d698f4c67e35af6f5ae9274ec457c6664ef0', 'manifest_sha256': 'dff20c842fa3974004c035e4218a0a62047f2c015fb82ae198647cdc17a8abea', 'nonce': '396c355cccd6a190184f191a8c9d6f69', 'purpose': 'TEST-ONLY-integration-signatures', 'schema_version': 1}, 'expiry': 1791876860, 'fingerprint': '52EEBD09ED804DD560826F82730D377B03A66044', 'guard': {'arch': 'aarch64', 'capabilities': {'CapAmb': 0, 'CapBnd': 0, 'CapEff': 0, 'CapInh': 0, 'CapPrm': 0}, 'caps': 0, 'device_nodes': {'/dev/full': {'kind': 'char', 'major': 1, 'minor': 7}, '/dev/null': {'kind': 'char', 'major': 1, 'minor': 3}, '/dev/pts/ptmx': {'kind': 'char', 'major': 5, 'minor': 2}, '/dev/random': {'kind': 'char', 'major': 1, 'minor': 8}, '/dev/tty': {'kind': 'char', 'major': 5, 'minor': 0}, '/dev/urandom': {'kind': 'char', 'major': 1, 'minor': 9}, '/dev/zero': {'kind': 'char', 'major': 1, 'minor': 5}}, 'docker_marker': True, 'docker_socket': False, 'interfaces': ['lo'], 'mounts': {'/': {'fs': 'overlay', 'options': ['ro', 'relatime'], 'root': '/'}, '/dev': {'fs': 'tmpfs', 'options': ['rw', 'nosuid'], 'root': '/'}, '/dev/mqueue': {'fs': 'mqueue', 'options': ['rw', 'nosuid', 'nodev', 'noexec', 'relatime'], 'root': '/'}, '/dev/pts': {'fs': 'devpts', 'options': ['rw', 'nosuid', 'noexec', 'relatime'], 'root': '/'}, '/dev/shm': {'fs': 'tmpfs', 'options': ['rw', 'nosuid', 'nodev', 'noexec', 'relatime'], 'root': '/'}, '/etc/hostname': {'fs': 'ext4', 'options': ['ro', 'relatime'], 'root': '/var/lib/docker/containers/4825f1b658810d1dea9850bb132f12e6d8d2a348743db6ec847ce63eef9b3a06/hostname'}, '/etc/hosts': {'fs': 'ext4', 'options': ['ro', 'relatime'], 'root': '/var/lib/docker/containers/4825f1b658810d1dea9850bb132f12e6d8d2a348743db6ec847ce63eef9b3a06/hosts'}, '/etc/resolv.conf': {'fs': 'ext4', 'options': ['ro', 'relatime'], 'root': '/var/lib/docker/containers/4825f1b658810d1dea9850bb132f12e6d8d2a348743db6ec847ce63eef9b3a06/resolv.conf'}, '/inputs': {'fs': 'ext4', 'options': ['ro', 'relatime'], 'root': '/home/runner/work/_temp/development-evidence/integration/work/test-signatures/inputs'}, '/out': {'fs': 'ext4', 'options': ['rw', 'relatime'], 'root': '/home/runner/work/_temp/development-evidence/integration/work/test-signatures/public'}, '/proc': {'fs': 'proc', 'options': ['rw', 'nosuid', 'nodev', 'noexec', 'relatime'], 'root': '/'}, '/proc/acpi': {'fs': 'tmpfs', 'options': ['ro', 'relatime'], 'root': '/'}, '/proc/bus': {'fs': 'proc', 'options': ['ro', 'nosuid', 'nodev', 'noexec', 'relatime'], 'root': '/bus'}, '/proc/fs': {'fs': 'proc', 'options': ['ro', 'nosuid', 'nodev', 'noexec', 'relatime'], 'root': '/fs'}, '/proc/interrupts': {'fs': 'tmpfs', 'options': ['rw', 'nosuid'], 'root': '/null'}, '/proc/irq': {'fs': 'proc', 'options': ['ro', 'nosuid', 'nodev', 'noexec', 'relatime'], 'root': '/irq'}, '/proc/kcore': {'fs': 'tmpfs', 'options': ['rw', 'nosuid'], 'root': '/null'}, '/proc/keys': {'fs': 'tmpfs', 'options': ['rw', 'nosuid'], 'root': '/null'}, '/proc/latency_stats': {'fs': 'tmpfs', 'options': ['rw', 'nosuid'], 'root': '/null'}, '/proc/scsi': {'fs': 'tmpfs', 'options': ['ro', 'relatime'], 'root': '/'}, '/proc/sys': {'fs': 'proc', 'options': ['ro', 'nosuid', 'nodev', 'noexec', 'relatime'], 'root': '/sys'}, '/proc/sysrq-trigger': {'fs': 'proc', 'options': ['ro', 'nosuid', 'nodev', 'noexec', 'relatime'], 'root': '/sysrq-trigger'}, '/proc/timer_list': {'fs': 'tmpfs', 'options': ['rw', 'nosuid'], 'root': '/null'}, '/sys': {'fs': 'sysfs', 'options': ['ro', 'nosuid', 'nodev', 'noexec', 'relatime'], 'root': '/'}, '/sys/firmware': {'fs': 'tmpfs', 'options': ['ro', 'relatime'], 'root': '/'}, '/sys/fs/cgroup': {'fs': 'cgroup2', 'options': ['ro', 'nosuid', 'nodev', 'noexec', 'relatime'], 'root': '/'}, '/tmp': {'fs': 'tmpfs', 'options': ['rw', 'nosuid', 'nodev', 'relatime'], 'root': '/'}}, 'no_new_privs': 1, 'nonce': '396c355cccd6a190184f191a8c9d6f69', 'sockets': [], 'uid': 1001, 'user': 'alarm'}, 'hardware_status': 'NOT RUN', 'production_credentials_used': False, 'public_certificate_sha256': '40344cfa5a1ae6f53c3d275c1d3026c94e4e6b4ab66a4026e600169e0c86a597', 'purpose': 'TEST-ONLY-integration-signatures', 'signatures': {'baseline/cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.xz': {'archive_sha256': '22e6e3ca4f23b73434c4aed284016914652900c33e845516621c0eb8b176d64e', 'signature_sha256': '888c95b7b852ae820c41e4b96aa12b336f655e98b6984a03b4d60af39b66c22b', 'status': '[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED 52EEBD09ED804DD560826F82730D377B03A66044 0\n[GNUPG:] SIG_ID NfOK0pXKniPdNqmcrSqrVj8Jr9E 2026-10-12 1791790460\n[GNUPG:] GOODSIG 730D377B03A66044 CACHY-ASAHI TEST ONLY 396c355cccd6a190184f191a8c9d6f69 <test-only@invalid.example>\n[GNUPG:] VALIDSIG 52EEBD09ED804DD560826F82730D377B03A66044 2026-10-12 1791790460 0 4 0 1 8 00 52EEBD09ED804DD560826F82730D377B03A66044\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n'}, 'baseline/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz': {'archive_sha256': '5d33320b55c2b3c778b94c128980c2d07d3fbcf466b3ab91ad8a706ff538ee81', 'signature_sha256': '3d90ca1056a8a4d924eef841554e53e5d390953c2c1afcf3aaa868c2e8ba2709', 'status': '[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED 52EEBD09ED804DD560826F82730D377B03A66044 0\n[GNUPG:] SIG_ID H3cOQIGxTsA7XqB7chf/OaIwN1Y 2026-10-12 1791790460\n[GNUPG:] GOODSIG 730D377B03A66044 CACHY-ASAHI TEST ONLY 396c355cccd6a190184f191a8c9d6f69 <test-only@invalid.example>\n[GNUPG:] VALIDSIG 52EEBD09ED804DD560826F82730D377B03A66044 2026-10-12 1791790460 0 4 0 1 8 00 52EEBD09ED804DD560826F82730D377B03A66044\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n'}, 'baseline/cachy-asahi-setup-0.1.0-2-any.pkg.tar.xz': {'archive_sha256': '40e392b4af6485d8518993073c1fe643eda60053312aeb618dfa9a6c9bee3489', 'signature_sha256': '9f0eca6793dd1793a5c2c855168c0204541b32d1362cbdcbdee77960c7258db9', 'status': '[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED 52EEBD09ED804DD560826F82730D377B03A66044 0\n[GNUPG:] SIG_ID MMH8Y7o8zKtVS99XgsRRopV2h/E 2026-10-12 1791790460\n[GNUPG:] GOODSIG 730D377B03A66044 CACHY-ASAHI TEST ONLY 396c355cccd6a190184f191a8c9d6f69 <test-only@invalid.example>\n[GNUPG:] VALIDSIG 52EEBD09ED804DD560826F82730D377B03A66044 2026-10-12 1791790460 0 4 0 1 8 00 52EEBD09ED804DD560826F82730D377B03A66044\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n'}, 'baseline/cachy-asahi-zsh-config-0.1.0-1-any.pkg.tar.xz': {'archive_sha256': '1bcb8e7fde6da28bc817f252bee5c7084cd22ec4153512eaf5bb47bd83e90faa', 'signature_sha256': 'f14c777438033fa4852cd30fdfa43619040f4e24d9ca3b3a3eb75f051774da64', 'status': '[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED 52EEBD09ED804DD560826F82730D377B03A66044 0\n[GNUPG:] SIG_ID v/zNZ/DJd6I/nL+JhfZ0oyqp5DE 2026-10-12 1791790460\n[GNUPG:] GOODSIG 730D377B03A66044 CACHY-ASAHI TEST ONLY 396c355cccd6a190184f191a8c9d6f69 <test-only@invalid.example>\n[GNUPG:] VALIDSIG 52EEBD09ED804DD560826F82730D377B03A66044 2026-10-12 1791790460 0 4 0 1 8 00 52EEBD09ED804DD560826F82730D377B03A66044\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n'}, 'upgrade/cachy-asahi-fish-config-0.1.1-1-any.pkg.tar.xz': {'archive_sha256': 'dbda251c19cbab7d6e43cb73ff1c0d9399ef0fe24e445a445662b6a96c53650d', 'signature_sha256': 'fe924da36bc3fec70f35a0310a1c95e96ba651db66418dc4c5143821a631e832', 'status': '[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED 52EEBD09ED804DD560826F82730D377B03A66044 0\n[GNUPG:] SIG_ID NdUVayFjaDw4cawOqyQ30oJE7DQ 2026-10-12 1791790460\n[GNUPG:] GOODSIG 730D377B03A66044 CACHY-ASAHI TEST ONLY 396c355cccd6a190184f191a8c9d6f69 <test-only@invalid.example>\n[GNUPG:] VALIDSIG 52EEBD09ED804DD560826F82730D377B03A66044 2026-10-12 1791790460 0 4 0 1 8 00 52EEBD09ED804DD560826F82730D377B03A66044\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n'}, 'upgrade/cachy-asahi-hyprland-settings-0.1.1-1-any.pkg.tar.xz': {'archive_sha256': 'f4e77696d566cf93222a663e930cf5ede81acaa8b95d1293ec0db017a1cc24b6', 'signature_sha256': '9f27b5d212c4b63ed62bd449193af72af4c5de95db06a53461bc559ac726d669', 'status': '[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED 52EEBD09ED804DD560826F82730D377B03A66044 0\n[GNUPG:] SIG_ID GzHJRXhbG0iJnqNgni1PC69E5HE 2026-10-12 1791790460\n[GNUPG:] GOODSIG 730D377B03A66044 CACHY-ASAHI TEST ONLY 396c355cccd6a190184f191a8c9d6f69 <test-only@invalid.example>\n[GNUPG:] VALIDSIG 52EEBD09ED804DD560826F82730D377B03A66044 2026-10-12 1791790460 0 4 0 1 8 00 52EEBD09ED804DD560826F82730D377B03A66044\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n'}, 'upgrade/cachy-asahi-setup-0.1.1-1-any.pkg.tar.xz': {'archive_sha256': 'f546668d61d11925c91d228588ab3b8e480cd88db5262a74d61974e6db176c6a', 'signature_sha256': 'ac8d59805dc65e91a4517ab9902c078d69c5d8c844577516023147cdfe949972', 'status': '[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED 52EEBD09ED804DD560826F82730D377B03A66044 0\n[GNUPG:] SIG_ID nHyGuXl2WfFDvte/xG4mRHbgXR8 2026-10-12 1791790460\n[GNUPG:] GOODSIG 730D377B03A66044 CACHY-ASAHI TEST ONLY 396c355cccd6a190184f191a8c9d6f69 <test-only@invalid.example>\n[GNUPG:] VALIDSIG 52EEBD09ED804DD560826F82730D377B03A66044 2026-10-12 1791790460 0 4 0 1 8 00 52EEBD09ED804DD560826F82730D377B03A66044\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n'}, 'upgrade/cachy-asahi-zsh-config-0.1.1-1-any.pkg.tar.xz': {'archive_sha256': 'b418d410a7c2ffa65b2a31c3546d18b976ea7b2ca2f7e3d7074c95389f317083', 'signature_sha256': 'ac604a7061b5f35c7ff9216ea4e4e4a5891c7c9da2860562930311610e851f06', 'status': '[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED 52EEBD09ED804DD560826F82730D377B03A66044 0\n[GNUPG:] SIG_ID sO0vZ6I4MiIerKGrf1RcbiLIGBs 2026-10-12 1791790460\n[GNUPG:] GOODSIG 730D377B03A66044 CACHY-ASAHI TEST ONLY 396c355cccd6a190184f191a8c9d6f69 <test-only@invalid.example>\n[GNUPG:] VALIDSIG 52EEBD09ED804DD560826F82730D377B03A66044 2026-10-12 1791790460 0 4 0 1 8 00 52EEBD09ED804DD560826F82730D377B03A66044\n[GNUPG:] TRUST_ULTIMATE 0 pgp\n'}}, 'status': 'TEST-SIGNATURES PASS'}

def sha(data):
    return hashlib.sha256(data).hexdigest()


class VirtualStage(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.root, self.native, self.work, self.cache = (self.base / n for n in ('root', 'native', 'work', 'cache'))
        for path in (self.root, self.native, self.work, self.cache):
            path.mkdir()
        self.output = self.base / 'stage'
        self.c = SimpleNamespace(native_out=self.native, work=self.work, image='sha256:' + 'a' * 64,
            installed='sha256:' + 'c' * 64, commit='b' * 40,
            report={'stages': {'lifecycle': {'status': 'PASS'}, 'desktop': {'status': 'FAIL'}, 'onboarding': {'status': 'FAIL'}}})
        self.base_map = {f'base-{n:03d}': '1-1' for n in range(341)}
        self.put(self.native / 'packages.lock', self.lock(self.base_map))
        self.put(self.native / 'image-id', self.c.image.encode())
        inputs = {'rootfs_packages': [], 'packages': [{'name': n, 'version': ver} for n, ver in self.base_map.items()]}
        self.put_json(self.native / 'inputs.lock.json', inputs)
        self.put_json(self.native / 'result.json', {'native_build': 'PASS', 'reviewed_inputs_sha256': v.digest(self.native / 'inputs.lock.json')})
        self.put_json(self.native / 'bootstrap.json', {'status': 'image-provisioned', 'image_id': self.c.image,
            'packages_lock_sha256': v.digest(self.native / 'packages.lock'), 'inputs_sha256': v.digest(self.native / 'inputs.lock.json')})
        self.rows = []
        for name in sorted(v.OVERLAYS):
            data = name.encode(); archive = 'baseline/' + name + '-1-1-any.pkg.tar.zst'
            self.rows.append({'name': name, 'version': '1-1', 'archive': archive, 'sha256': sha(data),
                              'payload_sha256': {'usr/share/' + name + '/setting': sha(data)}})
            self.put(self.work / 'archive-inputs' / archive, data)
        self.put_json(self.work / 'fixtures-raw/archives.json', {'baseline': self.rows})
        self.signed_rows = copy.deepcopy(self.rows)
        for row in self.signed_rows:
            data = b'\xc2\x01\x04' + row['name'].encode()
            row['signature_sha256'] = sha(data)
            self.put(self.work / 'lifecycle-inputs' / (row['archive'] + '.sig'), data)
        fingerprint = 'A' * 40
        status = '[GNUPG:] VALIDSIG ' + fingerprint + ' 2026-10-12 123 456 4 0 1 8 00 ' + fingerprint
        self.signer_receipt = {'status': 'TEST-SIGNATURES PASS', 'purpose': 'TEST-ONLY-integration-signatures',
            'production_credentials_used': False, 'hardware_status': 'NOT RUN', 'fingerprint': fingerprint,
            'contract': {'image_id': self.c.image}, 'signatures': {}}
        for row in self.signed_rows:
            record = {'archive_sha256': row['sha256'], 'signature_sha256': row['signature_sha256'], 'status': status}
            self.signer_receipt['signatures'][row['archive']] = record
            self.signer_receipt['signatures'][row['archive'].replace('baseline/', 'upgrade/')] = record.copy()
        self.put_json(self.work / 'signer-raw/test-signature-receipt.json', self.signer_receipt)
        self.c.sign_receipt = copy.deepcopy(self.signer_receipt)
        self.versions = {r['name']: r['version'] for r in self.rows}
        self.payload = {r['name']: r['payload_sha256'] for r in self.rows}
        self.handoff = self.work / 'lifecycle-raw'
        self.put(self.handoff / 'installed-packages.lock', self.lock(self.base_map | self.versions))
        self.put_json(self.handoff / 'lifecycle/result.json', {'status': 'PASS', 'baseline_handoff_ready': True,
            'source_commit': self.c.commit, 'image_id': self.c.image, 'handoff_package_versions': self.versions,
            'handoff_payload_sha256': self.payload})
        self.put_json(self.handoff / 'commit-receipt.json', {'status': 'READY', 'purpose': 'sanitized-baseline-image-handoff',
            'source_commit': self.c.commit, 'image_id': self.c.image, 'package_versions': self.versions,
            'payload_sha256': self.payload, 'installed_package_count': 345,
            'installed_packages_sha256': v.digest(self.handoff / 'installed-packages.lock'),
            'base_packages_sha256': v.digest(self.native / 'packages.lock'),
            'private_cleanup': 'PASS; no private contents or hashes recorded',
            'checks': [{'check': n, 'status': 'PASS'} for n in sorted(v.GATES)]})
        self.put_json(self.handoff / 'installed-image.json', {'image_id': self.c.installed, 'source_commit': self.c.commit,
            'base_image': self.c.image, 'lock_sha256': v.digest(self.handoff / 'installed-packages.lock'),
            'commit_receipt_sha256': v.digest(self.handoff / 'commit-receipt.json')})
        self.put_json(self.handoff / 'committed-config.json', {'status': 'PASS', 'image_id': self.c.installed,
            'accepted_base_config': {'Entrypoint': [], 'Labels': {}}, 'committed_config': {'Entrypoint': [], 'Labels': {}},
            'test_identity_in_image_env': False})
        self.put_json(self.handoff / 'committed-image/result.json', {'status': 'PASS', 'image_id': self.c.installed,
            'source_commit': self.c.commit, 'baseline': self.signed_rows,
            'installed_packages_sha256': v.digest(self.handoff / 'installed-packages.lock')})
        self.owner = self.root / 'scripts/virtual'; self.owner.mkdir(parents=True)
        self.blob_data = {}
        keys = []
        for name in ('archlinuxarm.gpg', 'archlinuxarm-trusted', 'archlinuxarm-revoked'):
            keys.append(self.blob(name))
        packages = []
        for n in range(21):
            row = self.blob(f'tooling-{n:02d}-1-1-aarch64.pkg.tar.xz')
            signature = self.blob(row['filename'] + '.sig')
            row.update(name=('qemu-hw-display-virtio-gpu' if n == 19 else 'qemu-hw-display-virtio-gpu-pci' if n == 20 else f'tooling-{n:02d}'), version='1-1', signature_sha256=signature['sha256'], signature_size=signature['size'])
            packages.append(row)
        self.put_json(self.owner / 'tooling.lock.json', {'base_inputs_lock_sha256': v.digest(self.native / 'inputs.lock.json'),
            'base_package_count': 341, 'expected_package_count': 362, 'keyring_files': keys, 'packages': packages})
        self.put_json(self.owner / 'tooling-audit.json', {'status': 'PASS', 'tooling_lock_sha256': v.digest(self.owner / 'tooling.lock.json'),
                                                       'packages': {r['name']: {} for r in packages}})
        for name in ('common.py', 'guest.py', 'prepare.py', 'run.py', 'gbm_probe.c', 'audit_tooling.py'):
            self.put(self.owner / name, (name + '\n').encode())
        shutil.copyfile(HERE.parents[1] / 'virtual/run.py', self.owner / 'run.py')
        self.rebind()
        exporter = self.root / 'scripts/ci/integration_export.py'; exporter.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(HERE.parent / 'integration_export.py', exporter)
        self.put(self.root / 'scripts/ci/native_arm.py', b'# fixture; never execute fetch\n')
        self.fetch = Mock(side_effect=self.mock_fetch)
        self.addCleanup(patch.stopall)
        patch.object(v, 'fetch_blob', self.fetch).start()
        self.command = patch.object(v, 'command', side_effect=self.mock_owner).start()

    def put(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)

    def put_json(self, path, value):
        self.put(path, (json.dumps(value, sort_keys=True) + '\n').encode())

    def lock(self, rows):
        return ''.join(f'{n} {ver}\n' for n, ver in sorted(rows.items())).encode()

    def mutate(self, path, action):
        value = v.read_json(path); action(value); self.put_json(path, value)

    def blob(self, name):
        data = ('blob-' + name).encode(); self.blob_data[name] = data
        return {'filename': name, 'url': 'https://example.invalid/' + name, 'size': len(data), 'sha256': sha(data)}

    def rebind(self):
        core = {n: v.digest(self.owner / n) for n in ('common.py', 'guest.py', 'prepare.py', 'run.py', 'gbm_probe.c')}
        self.put(self.owner / 'controller.py', ('LOCK_PIN = ' + repr(v.digest(self.owner / 'tooling.lock.json')) + '\n' +
            'AUDIT_PIN = ' + repr(v.digest(self.owner / 'tooling-audit.json')) + '\n' +
            'AUDITOR_PIN = ' + repr(v.digest(self.owner / 'audit_tooling.py')) + '\nCORE = ' + repr(core) + '\nALIASES = ' + repr(v.ALIASES) + '\n').encode())
        self.c.virtual_packet_sha256 = {n: v.digest(self.owner / n) for n in v.PACKET_FILES}

    def mock_fetch(self, row, cache, deadline=None):
        path = cache / row['filename']; self.put(path, self.blob_data[row['filename']]); return path

    def mock_owner(self, argv, log, timeout):
        self.assertEqual(timeout, 3420)
        self.assertEqual(argv[1], '-B')
        contract_path = Path(argv[argv.index('--contract') + 1]); contract = v.read_json(contract_path)
        self.assertEqual(argv[argv.index('--contract-sha256') + 1], v.digest(contract_path))
        self.assertEqual(contract['baseline'], self.signed_rows)
        self.assertEqual(set(contract['files']), v.ALIASES)
        self.assertEqual(len(list((contract_path.parent / 'tooling-cache').iterdir())), 45)
        out = Path(argv[argv.index('--output') + 1]); out.mkdir()
        events = [
            {'event': 'boot', 'nonce': 'e' * 32, 'arch': 'aarch64', 'page_size': 4096,
             'kernel': '7.2.10-1-aarch64-ARCH', 'execution': 'qemu-tcg-generic-aarch64', 'hardware_validation': 'NOT RUN'},
            {'event': 'gbm_pass', 'nonce': 'e' * 32, 'probe': {'schema': 1, 'status': 'PASS',
             'scope': 'guest_software_gbm_egl_only', 'renderer': 'llvmpipe', 'width': 64, 'height': 64,
             'verified_pixels': 4096, 'expected_rgba': [255, 0, 255, 255],
             'scanout': 'NOT_RUN', 'm2_hardware': 'NOT_RUN', 'performance': 'NOT_RUN'}}]
        for stage in ('minimal', 'overlay'):
            events.extend([{'event': 'frame_ready', 'stage': stage, 'monitors': [{'width': 8, 'height': 1}],
                            'clients': [{'pid': 100, 'mapped': True, 'size': [8, 1]}]},
                           {'event': 'phase_pass', 'stage': stage}])
        events.append({'event': 'guest_pass', 'nonce': 'e' * 32, 'software_session': 'PASS',
                       'hardware_validation': 'NOT RUN', 'graphics_acceleration': 'NOT RUN'})
        self.put_json(out / 'guest-events.json', events)
        frames = {}
        ppm = b'P6\n8 1\n255\n' + b''.join(bytes((n, n * 3, n * 5)) for n in range(8))
        for stage in ('minimal', 'overlay'):
            self.put(out / (stage + '.ppm'), ppm)
            frames[stage] = {'filename': stage + '.ppm', 'sha256': sha(ppm), 'width': 8, 'height': 1,
                             'distinct_rgb_values': 8, 'visual_review': 'NOT RUN'}
        receipt = {'schema_version': 1, 'purpose': 'bounded-generic-arm-software-proof',
            'status': 'CAPTURED_REQUIRES_VISUAL_REVIEW', 'source_commit': contract['source_commit'],
            'baseline_image': contract['installed_image_id'], 'controller_contract_sha256': v.digest(contract_path),
            'source_sha256': contract['core_sha256'] | {'controller.py': contract['controller_sha256'],
                'audit_tooling.py': contract['audit_tooling_sha256']}, 'inputs': contract['files'],
            'cleanup': [{'container': 'cachy-virtual-' + stage + '-' + 'e' * 32,
                         'status': 'PASS', 'absence_verified': True} for stage in ('tooling', 'verify', 'prepare', 'run')] +
                       [{'private_tag': 'cachy-virtual-private-' + 'e' * 32 + ':fixture', 'image_id': 'sha256:' + 'd' * 64,
                         'status': 'PASS', 'absence_verified': True, 'commit_outcome_uncertain': False}],
            'private_workspace_cleanup': 'PASS', 'proof_contract_sha256': 'f' * 64, 'prepare_receipt_sha256': 'e' * 64,
            'guest': {'status': 'CAPTURED_REQUIRES_VISUAL_REVIEW', 'execution': 'qemu-tcg-generic-aarch64',
                      'contract_sha256': 'f' * 64, 'prepare_receipt_sha256': 'e' * 64, 'image_id': 'sha256:' + 'd' * 64,
                      'nonce': 'e' * 32, 'software_session_ipc': 'PASS', 'software_compositor': 'REVIEW REQUIRED',
                      'frame_proof': 'REVIEW REQUIRED', 'hardware_validation': 'NOT RUN', 'graphics_acceleration': 'NOT RUN',
                      'm2_16k_pages': 'NOT RUN', 'performance': 'NOT RUN'},
            'frames': frames, 'guest_events_sha256': v.digest(out / 'guest-events.json'),
            'stages': {'tooling': {'status': 'READY', 'package_count': 366, 'image_id': 'sha256:' + 'd' * 64}, 'preparation': {'status': 'PREPARED'}}}
        rows = self.capabilities()
        receipt['qemu_capabilities'] = rows
        receipt['qemu_capabilities_sha256'] = self.capability_sha(rows)
        self.put_json(out / 'result.json', receipt)
        self.put(out / 'qemu.log', b'QEMU diagnostic\n')
        for stage in ('tooling', 'verify', 'prepare', 'runtime'):
            self.put(out / (stage + '-container.log'), (stage + ' diagnostic\n').encode())
        self.put(out / 'unknown.txt', b'never export this\n')
        self.put(out / 'key-init.log', b'never export this either\n')
        self.put(log, b'controlled launcher output\n')
        return 0

    def capabilities(self):
        return [{'check': name, 'status': 'PASS', 'returncode': 0, 'reason': None,
                 'stdout_sha256': sha(b'finite help'), 'stdout_bytes': 11,
                 'stderr_sha256': sha(b''), 'stderr_bytes': 0}
                for name in ('version', 'tcg', 'virt-machine', 'virtio-gpu-pci')]

    def capability_sha(self, rows):
        return sha((json.dumps(rows, sort_keys=True, indent=2) + '\n').encode())

    def run_adapter(self):
        return v.run_virtual(self.c, self.root, self.output, self.cache)

    def assert_prerequisite_refused(self):
        result = self.run_adapter(); self.assertEqual(result['status'], 'NOT RUN')
        self.fetch.assert_not_called(); self.command.assert_not_called()
        self.assertEqual(result['public'], [str(self.output / 'adapter-status')])
        return result

    def test_absent_accepted_packet_refuses_before_acquisition(self):
        del self.c.virtual_packet_sha256
        self.assertEqual(self.assert_prerequisite_refused()['error_code'], 'virtual-source-packet-not-accepted')

    def test_packet_drift_and_incomplete_map_refuse(self):
        self.c.virtual_packet_sha256['controller.py'] = '0' * 64
        self.assert_prerequisite_refused()

    def test_owner_constants_must_match_accepted_packet(self):
        with (self.owner / 'controller.py').open('ab') as stream:
            stream.write(b"LOCK_PIN = '" + b'0' * 64 + b"'\n")
        self.c.virtual_packet_sha256['controller.py'] = v.digest(self.owner / 'controller.py')
        self.assert_prerequisite_refused()

    def test_producer_signed_annotations_preserved_in_contract(self):
        self.assertNotEqual(self.rows, self.signed_rows)
        result = self.run_adapter()
        self.assertEqual(result['status'], 'PASS')
        contract = v.read_json(self.output / 'inputs/controller-contract.json')
        self.assertEqual(contract['baseline'], self.signed_rows)
        self.assertTrue(all('signature_sha256' in row for row in contract['baseline']))
        self.assertEqual(result['phase'], 'complete')
        acquisition = v.read_json(self.output / 'adapter-status/acquisition.json')
        self.assertEqual(acquisition['execution'], 'ATTEMPTED'); self.assertEqual(acquisition['planned_inputs'], 45)

    def test_actual_retained_unsigned_vs_signed_rows_and_signature_bytes_bind(self):
        self.assertNotEqual(ACTUAL_UNSIGNED_BASELINE, ACTUAL_SIGNED_BASELINE)
        for name, data in ACTUAL_BASELINE_SIGNATURES.items():
            self.put(self.work / 'lifecycle-inputs' / (name + '.sig'), data)
        self.put_json(self.work / 'signer-raw/test-signature-receipt.json', ACTUAL_SIGNER_RECEIPT)
        observed = v.signed_baseline(ACTUAL_UNSIGNED_BASELINE, ACTUAL_SIGNED_BASELINE, self.work, ACTUAL_SIGNER_RECEIPT['contract']['image_id'], ACTUAL_SIGNER_RECEIPT)
        self.assertEqual(observed, ACTUAL_SIGNED_BASELINE)
        self.assertEqual([row['payload_sha256'] for row in observed], [row['payload_sha256'] for row in ACTUAL_UNSIGNED_BASELINE])
        self.fetch.assert_not_called(); self.command.assert_not_called()

    def test_signed_original_version_archive_hash_payload_or_extra_drift_refused(self):
        path = self.handoff / 'committed-image/result.json'; original = v.read_json(path)
        changes = [lambda row: row.update(version='2-1'), lambda row: row.update(archive='baseline/other.pkg.tar.xz'),
                   lambda row: row.update(sha256='0' * 64), lambda row: row['payload_sha256'].clear(),
                   lambda row: row.update(extra='unreviewed')]
        for change in changes:
            value = copy.deepcopy(original); change(value['baseline'][0]); self.put_json(path, value)
            result = self.assert_prerequisite_refused()
            self.assertEqual(result['error_code'], 'signed-baseline-original-binding-refused')
            self.assertEqual(result['phase'], 'preflight')
            acquisition = v.read_json(self.output / 'adapter-status/acquisition.json')
            self.assertEqual(acquisition['inputs'], []); self.assertEqual(acquisition['execution'], 'NOT RUN')
            self.assertEqual(acquisition['planned_inputs'], 0)
            shutil.rmtree(self.output)

    def test_forged_signature_annotation_missing_pin_or_changed_blob_refused(self):
        path = self.handoff / 'committed-image/result.json'; original = v.read_json(path)
        for value, expected in [('0' * 64, 'signed-baseline-signer-archive-binding-refused'),
                                ('bad', 'signed-baseline-signer-archive-binding-refused')]:
            altered = copy.deepcopy(original); altered['baseline'][0]['signature_sha256'] = value; self.put_json(path, altered)
            self.assertEqual(self.assert_prerequisite_refused()['error_code'], expected)
            shutil.rmtree(self.output)
        self.put_json(path, original)
        self.put(self.work / 'lifecycle-inputs' / (self.rows[0]['archive'] + '.sig'), b'\xc2\x01\x05changed')
        self.assertEqual(self.assert_prerequisite_refused()['error_code'], 'signed-baseline-signature-binding-refused')

    def test_missing_cached_signer_authority_refused_before_acquisition(self):
        del self.c.sign_receipt
        result = self.assert_prerequisite_refused()
        self.assertEqual(result['error_code'], 'signed-baseline-cached-signer-authority-required')
        self.assertEqual(result['phase'], 'preflight')
        self.assertEqual(v.read_json(self.output / 'adapter-status/acquisition.json')['execution'], 'NOT RUN')

    def test_substituted_signature_blob_and_rehashed_annotation_cannot_bypass_signer_receipt(self):
        path = self.work / 'lifecycle-inputs' / (self.rows[0]['archive'] + '.sig')
        changed = b'\xc2\x01\x04substituted'
        self.put(path, changed)
        self.mutate(self.handoff / 'committed-image/result.json', lambda x: x['baseline'][0].update(signature_sha256=sha(changed)))
        self.assertEqual(self.assert_prerequisite_refused()['error_code'], 'signed-baseline-signer-archive-binding-refused')

    def test_wrong_signer_image_status_archive_validsig_or_cached_receipt_refused(self):
        path = self.work / 'signer-raw/test-signature-receipt.json'; original = v.read_json(path)
        for mutation, expected in [(lambda x: x['contract'].update(image_id='sha256:' + '0' * 64), 'signed-baseline-signer-receipt-refused'),
                                   (lambda x: x.update(status='PASS'), 'signed-baseline-signer-receipt-refused'),
                                   (lambda x: x['signatures'][self.rows[0]['archive']].update(archive_sha256='0' * 64), 'signed-baseline-signer-archive-binding-refused'),
                                   (lambda x: x['signatures'][self.rows[0]['archive']].update(status='[GNUPG:] BADSIG bad'), 'signed-baseline-signer-status-refused')]:
            value = copy.deepcopy(original); mutation(value); self.put_json(path, value)
            self.c.sign_receipt = copy.deepcopy(value)
            self.assertEqual(self.assert_prerequisite_refused()['error_code'], expected)
            shutil.rmtree(self.output)
        self.put_json(path, original)
        self.c.sign_receipt = {**original, 'expiry': 1}
        self.assertEqual(self.assert_prerequisite_refused()['error_code'], 'signed-baseline-cached-signer-receipt-refused')

    def test_signed_signature_symlink_and_private_marker_refused_before_acquisition(self):
        path = self.work / 'lifecycle-inputs' / (self.rows[0]['archive'] + '.sig'); data = path.read_bytes()
        path.unlink(); path.symlink_to(self.base / 'absent')
        self.assert_prerequisite_refused(); shutil.rmtree(self.output); path.unlink()
        self.put(path, b'-----BEGIN PGP PRIVATE KEY BLOCK-----')
        self.assertEqual(self.assert_prerequisite_refused()['error_code'], 'signed-baseline-public-signature-required')

    def test_diagnostics_allow_exact_fixed_codes_only_never_embedded_exception_text(self):
        fallback = 'virtual-prerequisite-refused'
        code = 'signed-baseline-signature-binding-refused'
        self.assertEqual(v.diagnostic(ValueError(code), fallback), code)
        for value in ('prefix ' + code + ' password=private', code + ': password=private', 'Bearer private-value'):
            self.assertEqual(v.diagnostic(ValueError(value), fallback), fallback)
        with patch.object(v, 'preflight', side_effect=ValueError(code + ': password=private')):
            result = self.run_adapter()
        self.assertEqual(result['error_code'], fallback)
        self.assertNotIn('password', (self.output / 'adapter-status/result.json').read_text())
        self.assertEqual(v.read_json(self.output / 'adapter-status/acquisition.json')['execution'], 'NOT RUN')

    def test_acquisition_http_and_pin_refusals_retain_fixed_transport_codes(self):
        def fetch(row, cache, deadline):
            if row['filename'] == 'archlinuxarm.gpg':
                raise v.urllib.error.HTTPError(row['url'], 503, 'password=never-retain', {}, None)
            if row['filename'] == 'archlinuxarm-trusted':
                raise ValueError('tooling-pin-differs')
            return self.mock_fetch(row, cache)
        self.fetch.side_effect = fetch
        result = self.run_adapter(); self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['phase'], 'acquisition'); self.assertEqual(result['error_code'], 'tooling-acquisition-failed')
        receipt = v.read_json(self.output / 'adapter-status/acquisition.json')
        self.assertEqual(receipt['execution'], 'ATTEMPTED'); self.assertEqual(receipt['planned_inputs'], 45)
        records = {row['filename']: row for row in receipt['inputs']}
        self.assertEqual(records['archlinuxarm.gpg']['error_code'], 'tooling-http-failed')
        self.assertEqual(records['archlinuxarm.gpg']['http_status'], 503)
        self.assertEqual(records['archlinuxarm-trusted']['error_code'], 'tooling-pin-differs')
        self.assertNotIn('password', json.dumps(receipt))

    def test_lifecycle_failure_refuses_without_fetch(self):
        self.c.report['stages']['lifecycle']['status'] = 'FAIL'; self.assert_prerequisite_refused()

    def test_wrong_installed_image_refuses(self):
        self.c.installed = 'sha256:' + 'd' * 64; self.assert_prerequisite_refused()

    def test_installed_inventory_extra_refuses(self):
        with (self.handoff / 'installed-packages.lock').open('ab') as stream:
            stream.write(b'extra 1-1\n')
        self.assert_prerequisite_refused()

    def test_lifecycle_full_payload_binding_required(self):
        self.mutate(self.handoff / 'lifecycle/result.json', lambda x: x['handoff_payload_sha256'].clear())
        self.assert_prerequisite_refused()

    def test_ready_receipt_and_all_cleanup_gates_required(self):
        self.mutate(self.handoff / 'commit-receipt.json', lambda x: x['checks'].pop())
        self.assert_prerequisite_refused()

    def test_original_archive_drift_refuses(self):
        self.put(self.work / 'archive-inputs' / self.rows[0]['archive'], b'wrong')
        self.assert_prerequisite_refused()

    def test_symlink_input_refuses_before_acquisition(self):
        path = self.handoff / 'installed-packages.lock'; target = self.base / 'actual-lock'
        path.rename(target); path.symlink_to(target)
        self.assert_prerequisite_refused()

    def test_duplicate_json_refuses(self):
        self.put(self.handoff / 'lifecycle/result.json', b'{"status":"PASS","status":"PASS"}')
        self.assert_prerequisite_refused()

    def test_reviewed_audit_cannot_be_fabricated_or_modified(self):
        self.mutate(self.owner / 'tooling-audit.json', lambda x: x.update(status='FAIL'))
        self.rebind(); self.assert_prerequisite_refused()

    def test_success_retains_only_explicit_public_capture_and_diagnostics(self):
        result = self.run_adapter()
        self.assertEqual(result['status'], 'PASS'); self.assertEqual(self.fetch.call_count, 45)
        self.assertEqual(result['owner_status'], 'CAPTURED_REQUIRES_VISUAL_REVIEW')
        self.assertEqual(result['visual_review'], 'REQUIRED'); self.assertEqual(result['hardware_validation'], 'NOT RUN')
        self.assertEqual({Path(p).name for p in result['public']}, {'adapter-status', *v.PUBLIC_DIRS})
        published = [p.name for directory in result['public'] for p in Path(directory).iterdir()]
        self.assertNotIn('unknown.txt', published); self.assertNotIn('key-init.log', published)
        acquisition = v.read_json(self.output / 'adapter-status/acquisition.json')
        self.assertEqual(len(acquisition['inputs']), 45); self.assertEqual(acquisition['status'], 'PIN_MATCH')

    def failed_capability_owner(self, out, rows=None, fields=True):
        def failed(receipt):
            receipt.update(status='FAIL', frames={}, guest={'status': 'FAILED', 'hardware_validation': 'NOT RUN'})
            receipt.pop('qemu_capabilities', None); receipt.pop('qemu_capabilities_sha256', None)
            if fields:
                receipt.update(qemu_capabilities=rows, qemu_capabilities_sha256=self.capability_sha(rows))
        self.mutate(out / 'result.json', failed)
        self.put_json(out / 'guest-events.json', [])

    def test_21_package_closure_requires_both_modules_and_refuses_historical_19(self):
        lock_path, audit_path = self.owner / 'tooling.lock.json', self.owner / 'tooling-audit.json'
        original = v.read_json(lock_path)
        for change in ('historical', 'missing-gpu', 'missing-pci'):
            lock = copy.deepcopy(original)
            if change == 'historical':
                lock['packages'] = lock['packages'][:-2]; lock['expected_package_count'] = 360
            else:
                name = 'qemu-hw-display-virtio-gpu' + ('-pci' if change == 'missing-pci' else '')
                next(row for row in lock['packages'] if row['name'] == name)['name'] = 'unrelated-module'
            self.put_json(lock_path, lock)
            self.put_json(audit_path, {'status': 'PASS', 'tooling_lock_sha256': v.digest(lock_path),
                                      'packages': {row['name']: {} for row in lock['packages']}})
            self.rebind()
            with self.subTest(case=change):
                result = self.assert_prerequisite_refused()
                self.assertEqual(result['error_code'], 'reviewed-tooling-audit-required')
            shutil.rmtree(self.output)

    def test_capability_prefix_failure_and_started_state_retained_only_as_failure(self):
        for state in ('FAIL', 'STARTING'):
            rows = self.capabilities()[:3]
            if state == 'FAIL': rows[-1].update(status='FAIL', reason='capability-missing')
            else:
                rows[-1] = {key: None for key in rows[-1]}
                rows[-1].update(check='virt-machine', status='STARTING')
            self.owner_mutation(lambda out: self.failed_capability_owner(out, rows), 1)
            result = self.run_adapter()
            self.assertEqual(result['status'], 'FAIL'); self.assertEqual(result['owner_cleanup']['status'], 'PASS')
            public = v.read_json(self.output / 'virtual-public/result/result.json')
            self.assertEqual(public['qemu_capabilities'], rows)
            self.assertEqual(public['qemu_capabilities_sha256'], self.capability_sha(rows))
            self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())
            self.assertFalse((self.output / 'virtual-public/overlay-frame').exists())
            shutil.rmtree(self.output)

    def test_failed_receipt_without_new_fields_retained_without_capture_or_19_acceptance(self):
        self.owner_mutation(lambda out: self.failed_capability_owner(out, fields=False), 1)
        result = self.run_adapter()
        self.assertEqual(result['status'], 'FAIL'); self.assertEqual(self.fetch.call_count, 45)
        public = v.read_json(self.output / 'virtual-public/result/result.json')
        self.assertNotIn('qemu_capabilities', public); self.assertEqual(public['status'], 'FAIL')

    def test_uncaptured_cancel_or_launch_failure_keeps_null_stream_observations(self):
        for reason in ('cancelled', 'launch-failed'):
            row = {key: None for key in self.capabilities()[0]}
            row.update(check='version', status='FAIL', reason=reason)
            self.owner_mutation(lambda out: self.failed_capability_owner(out, [row]), 1)
            result = self.run_adapter(); self.assertEqual(result['status'], 'FAIL')
            public = v.read_json(self.output / 'virtual-public/result/result.json')
            self.assertEqual(public['qemu_capabilities'], [row])
            self.assertIsNone(public['qemu_capabilities'][0]['stdout_sha256'])
            shutil.rmtree(self.output)

    def test_capture_requires_all_four_pass_before_any_public_result_or_frames(self):
        variants = [[], self.capabilities()[:3], self.capabilities()]
        variants[-1][-1].update(status='FAIL', reason='capability-missing')
        for rows in variants:
            self.owner_mutation(lambda out: self.mutate(out / 'result.json', lambda receipt:
                receipt.update(qemu_capabilities=rows, qemu_capabilities_sha256=self.capability_sha(rows))))
            result = self.run_adapter()
            self.assertEqual(result['error_code'], 'qemu-capability-success-required')
            self.assertEqual(result['status'], 'FAIL')
            self.assertFalse((self.output / 'virtual-public').exists())
            shutil.rmtree(self.output)
        def missing(out):
            self.mutate(out / 'result.json', lambda receipt: (receipt.pop('qemu_capabilities'),
                                                             receipt.pop('qemu_capabilities_sha256')))
        self.owner_mutation(missing)
        self.assertEqual(self.run_adapter()['error_code'], 'qemu-capability-success-required')

    def test_guest_pass_events_cannot_hide_behind_failed_partial_capabilities(self):
        def change(out):
            events = json.loads(v.read_regular(out / 'guest-events.json'))
            rows = self.capabilities()[:1]; rows[0].update(status='FAIL', reason='capability-missing')
            self.failed_capability_owner(out, rows)
            self.put_json(out / 'guest-events.json', events)
        self.owner_mutation(change, 1)
        result = self.run_adapter()
        self.assertEqual(result['error_code'], 'qemu-capability-success-required')
        self.assertFalse((self.output / 'virtual-public').exists())

    def test_capability_pair_symmetry_and_canonical_hash_required_before_copy(self):
        changes = [lambda receipt: receipt.pop('qemu_capabilities'),
                   lambda receipt: receipt.pop('qemu_capabilities_sha256'),
                   lambda receipt: receipt.update(qemu_capabilities_sha256='0' * 64),
                   lambda receipt: receipt.update(qemu_capabilities_sha256=True),
                   lambda receipt: receipt.update(qemu_capabilities_sha256=sha(json.dumps(receipt['qemu_capabilities']).encode()))]
        for change in changes:
            self.owner_mutation(lambda out: self.mutate(out / 'result.json', change))
            result = self.run_adapter()
            self.assertEqual(result['error_code'], 'qemu-capability-binding-refused')
            self.assertFalse((self.output / 'virtual-public').exists())
            shutil.rmtree(self.output)

    def test_failure_array_unknown_strings_keys_types_and_order_never_reach_public(self):
        original = self.capabilities()[:1]; original[0].update(status='FAIL', reason='capability-missing')
        variants = ['PRIVATE_SOURCE_TEXT', ['PRIVATE_SOURCE_TEXT'], {'private': 'PRIVATE_SOURCE_TEXT'},
                    [dict(original[0], stdout='PRIVATE_SOURCE_TEXT')], [dict(original[0], reason='PRIVATE_SOURCE_TEXT')],
                    [dict(original[0], returncode=True)], [dict(original[0], stdout_bytes=False)],
                    [dict(original[0], stdout_bytes=393217)], [dict(original[0], check='virtio-gpu-pci')],
                    [dict(original[0], stderr_sha256='PRIVATE_SOURCE_TEXT')],
                    [dict(original[0], status='PASS')], self.capabilities()[::-1],
                    self.capabilities() + [self.capabilities()[-1]]]
        for rows in variants:
            self.owner_mutation(lambda out: self.failed_capability_owner(out, rows), 1)
            result = self.run_adapter()
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['error_code'], 'qemu-capability-record-refused')
            self.assertFalse((self.output / 'virtual-public').exists())
            self.assertNotIn('PRIVATE_SOURCE_TEXT', (self.output / 'adapter-status/result.json').read_text())
            shutil.rmtree(self.output)

    def test_capability_source_drift_refuses_before_compilation_or_public_copy(self):
        def drift(out):
            with (self.owner / 'run.py').open('ab') as stream:
                stream.write(b'\nraise RuntimeError("PRIVATE_SOURCE_TEXT")\n')
        self.owner_mutation(drift)
        result = self.run_adapter()
        self.assertEqual(result['error_code'], 'qemu-capability-source-refused')
        self.assertFalse((self.output / 'virtual-public').exists())

    def test_captured_validator_executes_no_owner_imports_or_top_level_code(self):
        with (self.owner / 'run.py').open('a') as stream:
            stream.write('\nimport nonexistent_unreviewed_module\nraise RuntimeError("must-not-execute")\n')
        validate = v.capability_validator(self.root, v.digest(self.owner / 'run.py'))
        self.assertEqual(validate(self.capabilities()), self.capabilities())
        for data in [{'check': 'version'}, 'PRIVATE_SOURCE_TEXT']:
            with self.assertRaises(ValueError): validate(data)

    def test_result_changed_after_validation_publishes_only_captured_failure_bytes(self):
        rows = self.capabilities()[:1]; rows[0].update(status='FAIL', reason='capability-missing')
        self.owner_mutation(lambda out: self.failed_capability_owner(out, rows), 1)
        original = v.capability_receipt; captured = []
        def mutate(root, contract, receipt):
            result = original(root, contract, receipt)
            path = self.output / 'owner-public/result.json'; captured.append(path.read_bytes())
            self.mutate(path, lambda value: value.update(status='CAPTURED_REQUIRES_VISUAL_REVIEW',
                         qemu_capabilities='UNVALIDATED_RAW_TEXT', qemu_capabilities_sha256=True))
            return result
        with patch.object(v, 'capability_receipt', side_effect=mutate): result = self.run_adapter()
        self.assertEqual(result['status'], 'FAIL')
        public = self.output / 'virtual-public/result/result.json'
        self.assertEqual(public.read_bytes(), captured[0])
        self.assertNotIn('UNVALIDATED_RAW_TEXT', public.read_text())

    def test_events_changed_after_validation_publish_only_captured_empty_list(self):
        success_events = []
        def failed(out):
            success_events.extend(json.loads((out / 'guest-events.json').read_bytes()))
            self.failed_capability_owner(out, self.capabilities()[:1])
        self.owner_mutation(failed, 1)
        original = v.read_events; fired = []
        def mutate(path, policy, **kwargs):
            result = original(path, policy, **kwargs)
            if not fired:
                fired.append(True); self.put_json(path, success_events)
            return result
        with patch.object(v, 'read_events', side_effect=mutate): result = self.run_adapter()
        self.assertEqual(result['status'], 'FAIL'); self.assertTrue(fired)
        public = self.output / 'virtual-public/events/guest-events.json'
        self.assertEqual(json.loads(public.read_bytes()), [])
        self.assertEqual(len(success_events), 7)

    def test_deleted_raw_result_events_do_not_discard_validated_snapshots(self):
        self.owner_mutation(lambda out: self.failed_capability_owner(out, fields=False), 1)
        original = v.text_projection; removed = []
        def remove(exporter, source, target, selected, name=None, data=None):
            if source.name in ('result.json', 'guest-events.json'):
                self.assertIsInstance(data, bytes); source.unlink(); removed.append(source.name)
            return original(exporter, source, target, selected, name, data)
        with patch.object(v, 'text_projection', side_effect=remove): result = self.run_adapter()
        self.assertEqual(result['status'], 'FAIL'); self.assertEqual(len(removed), 2)
        self.assertEqual(v.read_json(self.output / 'virtual-public/result/result.json')['status'], 'FAIL')
        self.assertEqual(json.loads((self.output / 'virtual-public/events/guest-events.json').read_bytes()), [])

    def test_exporter_copy_mutation_never_publishes_unvalidated_result(self):
        self.owner_mutation(lambda out: self.failed_capability_owner(out, fields=False), 1)
        original = v.load_module
        def exporter(path, name):
            module = original(path, name); operation = module.export_evidence
            def mutate(selected, target):
                result = operation(selected, target)
                if (target / 'result.json').exists():
                    self.put_json(target / 'result.json', {'status': 'CAPTURED_REQUIRES_VISUAL_REVIEW',
                                                          'qemu_capabilities': 'UNVALIDATED_RAW_TEXT'})
                return result
            module.export_evidence = mutate; return module
        with patch.object(v, 'load_module', side_effect=exporter): result = self.run_adapter()
        self.assertEqual(result['error_code'], 'virtual-public-export-refused')
        self.assertFalse((self.output / 'virtual-public/result').exists())

    def test_postrename_copy_mutation_retracts_owned_invalid_public_directory(self):
        self.owner_mutation(lambda out: self.failed_capability_owner(out, fields=False), 1)
        rename = Path.rename; fired = []
        def mutate(source, target):
            result = rename(source, target)
            if Path(target) == self.output / 'virtual-public/result':
                fired.append(True)
                self.put_json(Path(target) / 'result.json', {'qemu_capabilities': ['UNVALIDATED_RAW_TEXT'],
                                                          'qemu_capabilities_sha256': True})
            return result
        with patch.object(Path, 'rename', mutate): result = self.run_adapter()
        self.assertTrue(fired); self.assertEqual(result['status'], 'FAIL')
        self.assertFalse((self.output / 'virtual-public/result').exists())
        self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())

    def test_postrename_unexpected_members_retract_accepted_and_refused_exports(self):
        exporter = v.load_module(self.root / 'scripts/ci/integration_export.py', 'member_fixture_exporter')
        rename = Path.rename
        for accepted in (True, False):
            for kind in ('file', 'directory', 'symlink'):
                with self.subTest(accepted=accepted, kind=kind):
                    output = self.base / f'members-{accepted}-{kind}'
                    source = output / 'snapshot.log'; source.parent.mkdir()
                    data = b'bounded diagnostic\n' if accepted else b'-----BEGIN PRIVATE KEY-----\n'
                    source.write_bytes(data)
                    target, selected = output / 'virtual-public/result', output / 'selected/result'
                    target.parent.mkdir(); selected.parent.mkdir()
                    changed = []
                    def inject(path, destination):
                        result = rename(path, destination)
                        if Path(destination) == target:
                            changed.append(True)
                            extra = target / 'unexpected'
                            if kind == 'directory': extra.mkdir()
                            elif kind == 'symlink': extra.symlink_to(source)
                            else: extra.write_bytes(b'unvalidated public bytes')
                        return result
                    with patch.object(Path, 'rename', inject), self.assertRaises(ValueError):
                        v.text_projection(exporter, source, target, selected, data=data)
                    self.assertTrue(changed)
                    self.assertFalse(target.exists())
                    self.assertNotIn(str(target), v.public_paths(output))

    def publication_signal_child(self, phase, sig):
        # Signals affect only this bounded child, never the unittest/controller process.
        script = r"""
import json, os, signal, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import test_virtual_stage as fixture
v = fixture.v
case = fixture.VirtualStage('test_success_retains_only_explicit_public_capture_and_diagnostics')
case.setUp()
phase, sig = sys.argv[2], int(sys.argv[3])
def interrupted(*_):
    raise KeyboardInterrupt()
previous = {s: signal.signal(s, interrupted) for s in (signal.SIGINT, signal.SIGTERM)}
try:
    if phase != 'frame':
        case.owner_mutation(lambda out: case.failed_capability_owner(out, fields=False), 1)
    target = case.output / 'virtual-public' / ('minimal-frame' if phase == 'frame' else 'result')
    rename, remove = Path.rename, fixture.shutil.rmtree
    fired, retracted = [], []
    def inject(path, destination):
        result = rename(path, destination)
        if Path(destination) == target:
            fired.append(True)
            if phase == 'frame':
                (target / 'minimal.ppm').write_bytes(b'corrupt captured frame')
            else:
                case.put_json(target / 'result.json', {'qemu_capabilities': 'UNVALIDATED_RAW_TEXT'})
            if phase != 'retraction': os.kill(os.getpid(), sig)
        return result
    def repeated(path, *args, **kwargs):
        if Path(path) == case.output / 'selected/result/invalid-public':
            retracted.append(True)
            for pending in (signal.SIGINT, signal.SIGTERM, signal.SIGINT, signal.SIGTERM):
                os.kill(os.getpid(), pending)
        return remove(path, *args, **kwargs)
    cancelled = False
    with patch.object(Path, 'rename', inject), patch.object(v.shutil, 'rmtree', side_effect=repeated):
        try: case.run_adapter()
        except KeyboardInterrupt: cancelled = True
    receipt = v.read_json(case.output / 'adapter-status/result.json')
    assert fired and cancelled, (fired, cancelled)
    assert receipt['status'] == 'FAIL' and receipt['error_code'] == 'cancelled', receipt
    assert not target.exists() and not target.is_symlink(), str(target)
    assert str(target) not in v.public_paths(case.output), v.public_paths(case.output)
    assert all(signal.getsignal(s) is interrupted for s in previous), 'signal handler not restored'
    if phase == 'retraction': assert retracted, 'retraction injection did not run'
    if phase == 'frame':
        assert not (case.output / 'virtual-public/overlay-frame').exists()
    print(json.dumps({'phase': phase, 'signal': sig, 'cancelled': cancelled,
                      'retracted': bool(retracted), 'handler_restore': True,
                      'target_absent': True, 'native_execution': 'NOT RUN'}))
finally:
    for s, handler in previous.items(): signal.signal(s, handler)
    case.doCleanups()
"""
        child = subprocess.run([sys.executable, '-I', '-B', '-Werror::ResourceWarning', '-c',
                                script, str(HERE), phase, str(sig)], capture_output=True,
                               text=True, timeout=10)
        self.assertEqual(child.returncode, 0, child.stderr)
        return json.loads(child.stdout)

    def test_real_signals_after_text_and_frame_rename_retract_before_registration(self):
        for phase in ('text', 'frame'):
            for sig in (signal.SIGINT, signal.SIGTERM):
                with self.subTest(phase=phase, signal=sig):
                    receipt = self.publication_signal_child(phase, sig)
                    self.assertTrue(receipt['target_absent'])
                    self.assertTrue(receipt['handler_restore'])

    def test_repeated_real_signals_during_retraction_restore_handlers_and_finish(self):
        receipt = self.publication_signal_child('retraction', signal.SIGINT)
        self.assertTrue(receipt['retracted'])
        self.assertTrue(receipt['cancelled'])

    def test_repeated_cancel_during_invalid_copy_retraction_finishes_cleanup(self):
        self.owner_mutation(lambda out: self.failed_capability_owner(out, fields=False), 1)
        rename, remove = Path.rename, shutil.rmtree
        destination = self.output / 'virtual-public/result'; fired = []
        def corrupt(source, target):
            result = rename(source, target)
            if Path(target) == destination:
                self.put_json(destination / 'result.json', {'qemu_capabilities': 'UNVALIDATED_RAW_TEXT'})
            return result
        def cancel(path, *args, **kwargs):
            if Path(path) == self.output / 'selected/result/invalid-public':
                fired.append(True)
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
                signal.getsignal(signal.SIGINT)(signal.SIGINT, None)
            return remove(path, *args, **kwargs)
        with patch.object(Path, 'rename', corrupt), patch.object(v.shutil, 'rmtree', side_effect=cancel), \
                self.assertRaises(KeyboardInterrupt):
            self.run_adapter()
        self.assertTrue(fired); self.assertFalse(destination.exists())
        self.assertEqual(v.read_json(self.output / 'adapter-status/result.json')['status'], 'FAIL')

    def test_failed_invalid_copy_deletion_keeps_quarantine_out_of_public_allowlist(self):
        self.owner_mutation(lambda out: self.failed_capability_owner(out, fields=False), 1)
        rename, remove = Path.rename, shutil.rmtree
        destination = self.output / 'virtual-public/result'
        def corrupt(source, target):
            result = rename(source, target)
            if Path(target) == destination:
                self.put_json(destination / 'result.json', {'qemu_capabilities': 'UNVALIDATED_RAW_TEXT'})
            return result
        def fail(path, *args, **kwargs):
            if Path(path) == self.output / 'selected/result/invalid-public':
                raise OSError('controlled quarantine deletion failure')
            return remove(path, *args, **kwargs)
        with patch.object(Path, 'rename', corrupt), patch.object(v.shutil, 'rmtree', side_effect=fail):
            result = self.run_adapter()
        self.assertEqual(result['status'], 'FAIL'); self.assertFalse(destination.exists())
        self.assertTrue((self.output / 'selected/result/invalid-public/result.json').is_file())
        self.assertNotIn(str(destination), result['public'])

    def test_frame_publication_checks_bytes_receipt_and_closed_members_before_after_rename(self):
        for phase in ('before', 'after'):
            for kind in ('bytes', 'receipt', 'file', 'directory', 'symlink'):
                if self.output.exists(): shutil.rmtree(self.output)
                with self.subTest(phase=phase, corruption=kind):
                    save, rename = v.save, Path.rename
                    fired = []
                    def corrupt(folder):
                        fired.append(True)
                        if kind == 'bytes': (folder / 'minimal.ppm').write_bytes(b'changed frame')
                        elif kind == 'receipt': self.put_json(folder / 'receipt.json', {'status': 'UNVALIDATED'})
                        elif kind == 'directory': (folder / 'extra').mkdir()
                        elif kind == 'symlink': (folder / 'extra').symlink_to(folder / 'minimal.ppm')
                        else: (folder / 'extra').write_bytes(b'unvalidated member')
                    def saved(path, value):
                        result = save(path, value)
                        if phase == 'before' and Path(path) == self.output / 'selected/minimal-frame/receipt.json':
                            corrupt(Path(path).parent)
                        return result
                    def renamed(path, target):
                        result = rename(path, target)
                        if phase == 'after' and Path(target) == self.output / 'virtual-public/minimal-frame':
                            corrupt(Path(target))
                        return result
                    with patch.object(v, 'save', side_effect=saved), patch.object(Path, 'rename', renamed):
                        result = self.run_adapter()
                    self.assertTrue(fired); self.assertEqual(result['status'], 'FAIL')
                    for stage in ('minimal', 'overlay'):
                        target = self.output / 'virtual-public' / (stage + '-frame')
                        self.assertFalse(target.exists())
                        self.assertNotIn(str(target), result['public'])
                    shutil.rmtree(self.output)

    def cleanup_signal_child(self, mode, sig):
        script = r"""
import json, os, signal, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import test_virtual_stage as fixture
v = fixture.v
case = fixture.VirtualStage('test_success_retains_only_explicit_public_capture_and_diagnostics')
case.setUp()
mode, sig = sys.argv[2], int(sys.argv[3])
def interrupted(*_): raise KeyboardInterrupt()
previous = {s: signal.signal(s, interrupted) for s in (signal.SIGINT, signal.SIGTERM)}
mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
fired, quarantines, deleted = [], [], []
rename, remove, install = Path.rename, v.shutil.rmtree, signal.signal
try:
    if mode.startswith('handler'):
        def installing(s, handler):
            result = install(s, handler)
            frame, callers = sys._getframe(), set()
            while frame:
                callers.add(frame.f_code.co_name); frame = frame.f_back
            outer = 'run_virtual' in callers and not {'receive', 'text_projection'} & callers
            if s == signal.SIGINT and not fired and (
                mode.endswith('restore') and handler is interrupted and (mode == 'handler-restore' or outer) or
                not mode.endswith('restore') and handler is not interrupted and (mode == 'handler-entry' or outer)):
                fired.append(True); os.kill(os.getpid(), sig)
            return result
        escaped = False
        with patch.object(v.signal, 'signal', side_effect=installing):
            try:
                if mode in ('handler-entry', 'handler-restore'):
                    with v.defer_finalization() as pending: body = True
                    assert body, 'guarded body was skipped'
                else: case.run_adapter()
            except KeyboardInterrupt: escaped = True
        if mode == 'handler-entry': assert not escaped and pending, 'setup interruption was not deferred'
        elif mode == 'handler-restore': assert escaped or pending, 'restoration cancellation was lost'
        else:
            assert escaped, 'outer final cancellation did not propagate'
            receipt = v.read_json(case.output / 'adapter-status/result.json')
            assert receipt['status'] == 'FAIL' and receipt['error_code'] == 'cancelled', receipt
            assert (case.output / 'adapter-status/acquisition.json').is_file()
    else:
        overlay = case.output / 'virtual-public/overlay-frame'
        def renamed(path, target):
            result = rename(path, target)
            if Path(path).parent == case.output / 'virtual-public' and Path(path).name.endswith('-frame'):
                quarantines.append(Path(path).name)
            if Path(target) == overlay:
                fired.append(True)
                (overlay / 'overlay.ppm').write_bytes(b'corrupt overlay')
                os.kill(os.getpid(), sig)
            return result
        def deleting(path, *args, **kwargs):
            if Path(path).name.startswith('minimal-frame') and 'selected' in Path(path).parts:
                deleted.append(True)
                for pending in (signal.SIGINT, signal.SIGTERM) * 3: os.kill(os.getpid(), pending)
                raise OSError('controlled first quarantine deletion failure')
            return remove(path, *args, **kwargs)
        cancelled = False
        with patch.object(Path, 'rename', renamed), patch.object(v.shutil, 'rmtree', side_effect=deleting):
            try: case.run_adapter()
            except KeyboardInterrupt: cancelled = True
        assert deleted, 'controlled deletion failure was not exercised'
        assert set(quarantines) == {'minimal-frame', 'overlay-frame'}, quarantines
        assert cancelled, 'deletion error swallowed cancellation'
        receipt = v.read_json(case.output / 'adapter-status/result.json')
        assert receipt['status'] == 'FAIL' and receipt['error_code'] == 'cancelled', receipt
        for stage in ('minimal', 'overlay'):
            target = case.output / 'virtual-public' / (stage + '-frame')
            assert not target.exists() and str(target) not in v.public_paths(case.output)
    assert fired, 'injection schedule not reached'
    assert all(signal.getsignal(s) is interrupted for s in previous), 'handler restoration failed'
    assert signal.pthread_sigmask(signal.SIG_BLOCK, []) == mask, 'signal mask restoration failed'
    print(json.dumps({'mode': mode, 'signal': sig, 'mask_restore': True, 'handler_restore': True,
                      'quarantines': quarantines, 'native_execution': 'NOT RUN'}))
finally:
    for s, handler in previous.items(): install(s, handler)
    signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    case.doCleanups()
"""
        child = subprocess.run([sys.executable, '-I', '-B', '-Werror::ResourceWarning', '-c',
                                script, str(HERE), mode, str(sig)], capture_output=True,
                               text=True, timeout=10)
        self.assertEqual(child.returncode, 0, child.stderr)
        return json.loads(child.stdout)

    def test_real_signals_during_first_handler_install_and_outer_finalization_are_guarded(self):
        for mode in ('handler-entry', 'handler-restore', 'handler-final-entry', 'handler-final-restore'):
            for sig in (signal.SIGINT, signal.SIGTERM):
                with self.subTest(mode=mode, signal=sig):
                    self.cleanup_signal_child(mode, sig)

    def test_all_frame_quarantines_attempted_despite_delete_failure_and_repeated_cancel(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=sig):
                receipt = self.cleanup_signal_child('frames-delete-error', sig)
                self.assertEqual(set(receipt['quarantines']), {'minimal-frame', 'overlay-frame'})

    def test_final_unmask_and_recovery_cancellation_durably_seal_failure(self):
        script = r"""
import hashlib, json, os, signal, sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import test_virtual_stage as fixture
v = fixture.v
case = fixture.VirtualStage('test_success_retains_only_explicit_public_capture_and_diagnostics')
case.setUp()
sig, repeated = int(sys.argv[2]), int(sys.argv[3])
source = Path(v.__file__).read_bytes()
def interrupted(*_): raise KeyboardInterrupt()
previous = {s: signal.signal(s, interrupted) for s in (signal.SIGINT, signal.SIGTERM)}
original = signal.pthread_sigmask
mask = original(signal.SIG_BLOCK, [])
fired = []
def unmask(how, selected):
    frame, callers = sys._getframe(), set()
    while frame:
        callers.add(frame.f_code.co_name); frame = frame.f_back
    outer = 'run_virtual' in callers and not {'receive', 'text_projection', 'retract_publications'} & callers
    receipt = case.output / 'adapter-status/result.json'
    if outer and 'defer_finalization' in callers and receipt.exists() and how == signal.SIG_SETMASK and \
            signal.getsignal(signal.SIGTERM) is interrupted and len(fired) < 1 + repeated:
        fired.append(v.read_json(receipt)['status'])
        os.kill(os.getpid(), sig)
    return original(how, selected)
try:
    escaped = False
    with patch.object(v.signal, 'pthread_sigmask', side_effect=unmask):
        try: case.run_adapter()
        except KeyboardInterrupt: escaped = True
    receipt = v.read_json(case.output / 'adapter-status/result.json')
    acquisition = v.read_json(case.output / 'adapter-status/acquisition.json')
    assert escaped and fired, 'final unmask cancellation did not execute'
    assert receipt['status'] == 'FAIL' and receipt['error_code'] == 'cancelled', receipt
    assert len(fired) == 1 + repeated, fired
    if repeated: assert fired[-1] == 'FAIL', 'recovery did not seal FAIL before second unmask'
    assert acquisition['status'] == 'PIN_MATCH' and len(acquisition['inputs']) == 45
    assert receipt['hardware_validation'] == 'NOT RUN'
    assert all(signal.getsignal(s) is interrupted for s in previous), 'caller handlers changed'
    assert original(signal.SIG_BLOCK, []) == mask, 'caller mask changed'
    assert Path(v.__file__).read_bytes() == source, 'source changed'
    print(json.dumps({'signal': sig, 'unmask_receipt_states': fired, 'status': receipt['status'],
                      'error_code': receipt['error_code'], 'escaped': escaped,
                      'source_sha256': hashlib.sha256(source).hexdigest(), 'native_execution': 'NOT RUN'}))
finally:
    for s, handler in previous.items(): signal.signal(s, handler)
    original(signal.SIG_SETMASK, mask)
    case.doCleanups()
"""
        for sig in (signal.SIGINT, signal.SIGTERM):
            for repeated in (False, True):
                with self.subTest(signal=sig, repeated=repeated):
                    child = subprocess.run([sys.executable, '-I', '-B', '-Werror::ResourceWarning', '-c',
                        script, str(HERE), str(sig), str(int(repeated))], capture_output=True,
                        text=True, timeout=10)
                    self.assertEqual(child.returncode, 0, child.stderr)
                    self.assertEqual(json.loads(child.stdout)['status'], 'FAIL')

    def test_retraction_preserves_foreign_replacement_and_existing_quarantine(self):
        self.owner_mutation(lambda out: self.failed_capability_owner(out, fields=False), 1)
        rename = Path.rename
        destination = self.output / 'virtual-public/result'
        existing = self.output / 'selected/result/invalid-public'
        moved = self.base / 'removed-owned-public'
        def replace(path, target):
            result = rename(path, target)
            if Path(target) == destination:
                existing.mkdir(); (existing / 'foreign-marker').write_bytes(b'existing quarantine')
                rename(destination, moved)
                destination.mkdir(); (destination / 'foreign-marker').write_bytes(b'foreign replacement')
            return result
        with patch.object(Path, 'rename', replace): result = self.run_adapter()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual((destination / 'foreign-marker').read_bytes(), b'foreign replacement')
        self.assertEqual((existing / 'foreign-marker').read_bytes(), b'existing quarantine')
        self.assertTrue((moved / 'result.json').is_file())

    def test_every_failed_owner_success_or_review_claim_requires_all_four_pass(self):
        changes = [('status', 'PASS'), ('status', 'CAPTURED_REQUIRES_VISUAL_REVIEW'),
                   ('software_compositor', 'PASS'), ('software_compositor', 'REVIEW REQUIRED'),
                   ('software_session_ipc', 'PASS'), ('frame_proof', 'PASS'), ('frame_proof', 'REVIEW REQUIRED')]
        for field, value in changes:
            def failed(out):
                rows = self.capabilities()[:1]; rows[0].update(status='FAIL', reason='capability-missing')
                self.failed_capability_owner(out, rows)
                self.mutate(out / 'result.json', lambda receipt: receipt['guest'].update({field: value}))
            self.owner_mutation(failed, 1)
            result = self.run_adapter()
            with self.subTest(field=field, value=value):
                self.assertEqual(result['error_code'], 'qemu-capability-success-required')
                self.assertFalse((self.output / 'virtual-public').exists())
            shutil.rmtree(self.output)

    def test_guest_claim_boolean_unknown_or_container_shapes_refuse_before_copy(self):
        for field, value in [('software_compositor', True), ('software_session_ipc', []),
                             ('frame_proof', {'status': 'PASS'}), ('status', 'PRIVATE_RAW_TEXT'),
                             ('software_compositor', 'PRIVATE_RAW_TEXT')]:
            def failed(out):
                self.failed_capability_owner(out, fields=False)
                self.mutate(out / 'result.json', lambda receipt: receipt['guest'].update({field: value}))
            self.owner_mutation(failed, 1)
            result = self.run_adapter(); self.assertEqual(result['error_code'], 'qemu-guest-claim-refused')
            self.assertFalse((self.output / 'virtual-public').exists()); shutil.rmtree(self.output)

    def test_late_second_frame_failure_retracts_first_published_frame(self):
        original = v.save
        def fail(path, value):
            if Path(path).parent.name == 'overlay-frame' and Path(path).name == 'receipt.json':
                raise OSError('controlled late frame failure')
            return original(path, value)
        with patch.object(v, 'save', side_effect=fail): result = self.run_adapter()
        self.assertEqual(result['status'], 'FAIL')
        self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())
        self.assertFalse((self.output / 'virtual-public/overlay-frame').exists())

    def test_validator_source_ambiguous_or_executing_signature_refused(self):
        path = self.owner / 'run.py'; original = path.read_bytes()
        variants = [original + b'\ndef capability_projection(rows): return rows\n',
                    original.replace(b'def capability_projection(rows):', b'def capability_projection(rows=__import__("unknown_module")):'),
                    original.replace(b'def capability_projection(rows):', b'def capability_projection(rows: __import__("unknown_module")):'),
                    original.replace(b'CAPABILITY_LIMIT = 128 * 1024', b'CAPABILITY_LIMIT = __import__("unknown_module")')]
        for raw in variants:
            self.put(path, raw)
            with self.assertRaises(ValueError): v.capability_validator(self.root, sha(raw))
        self.put(path, original)

    def test_all_acquisition_results_collected_after_one_failure(self):
        def fetch(row, cache, deadline):
            if row['filename'] == 'archlinuxarm.gpg':
                raise ValueError('password=do-not-export')
            return self.mock_fetch(row, cache)
        self.fetch.side_effect = fetch
        result = self.run_adapter(); self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(self.fetch.call_count, 45); self.command.assert_not_called()
        receipt = v.read_json(self.output / 'adapter-status/acquisition.json')
        self.assertEqual(len(receipt['inputs']), 45); self.assertEqual(sum(r['status'] == 'FAIL' for r in receipt['inputs']), 1)
        self.assertNotIn('do-not-export', (self.output / 'adapter-status/result.json').read_text())

    def owner_mutation(self, action, code=0):
        def invoke(argv, log, timeout):
            self.mock_owner(argv, log, timeout)
            action(self.output / 'owner-public')
            return code
        self.command.side_effect = invoke

    def test_failed_owner_retains_failure_diagnostics_and_cleanup(self):
        self.owner_mutation(lambda out: self.mutate(out / 'result.json', lambda x: x.update(status='FAIL')), 1)
        result = self.run_adapter(); self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['owner_cleanup']['status'], 'PASS')
        self.assertTrue((self.output / 'virtual-public/qemu/qemu.log').is_file())

    def test_cleanup_uncertainty_refuses_pass(self):
        self.owner_mutation(lambda out: self.mutate(out / 'result.json', lambda x: x['cleanup'][0].update(status='FAIL', absence_verified=False)))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')

    def test_incomplete_owned_cleanup_refuses_pass(self):
        self.owner_mutation(lambda out: self.mutate(out / 'result.json', lambda x: x['cleanup'].pop()))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')

    def test_wrong_guest_proof_binding_refuses_pass(self):
        self.owner_mutation(lambda out: self.mutate(out / 'result.json', lambda x: x['guest'].update(contract_sha256='0' * 64)))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')

    def test_wrong_owner_contract_binding_refuses_pass_and_all_binary_publication(self):
        self.owner_mutation(lambda out: self.mutate(out / 'result.json', lambda x: x.update(controller_contract_sha256='0' * 64)))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')
        self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())
        self.assertFalse((self.output / 'virtual-public/overlay-frame').exists())

    def test_wrong_guest_nonce_image_source_and_inputs_publish_no_frames(self):
        mutations = [lambda x: x['guest'].update(nonce='0' * 32),
                     lambda x: x['guest'].update(image_id='sha256:' + '0' * 64),
                     lambda x: x.update(source_commit='0' * 40),
                     lambda x: x['inputs'].pop('base_lock')]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.owner_mutation(lambda out: self.mutate(out / 'result.json', mutation))
                self.assertEqual(self.run_adapter()['status'], 'FAIL')
                self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())
                self.assertFalse((self.output / 'virtual-public/overlay-frame').exists())
                shutil.rmtree(self.output)

    def test_cancel_during_frame_staging_never_selects_incomplete_binary(self):
        original_save = v.save
        def interrupted(path, value):
            if Path(path).name == 'receipt.json' and Path(path).parent.name == 'minimal-frame':
                raise KeyboardInterrupt()
            return original_save(path, value)
        with patch.object(v, 'save', side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.run_adapter()
        self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())
        self.assertFalse((self.output / 'virtual-public/overlay-frame').exists())
        self.assertEqual(v.read_json(self.output / 'adapter-status/result.json')['status'], 'FAIL')

    def test_missing_or_wrong_event_binding_refuses_pass(self):
        self.owner_mutation(lambda out: self.put(out / 'guest-events.json', b'[]'))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')

    def test_wrong_frame_hash_refuses_public_binary(self):
        self.owner_mutation(lambda out: self.put(out / 'minimal.ppm', b'wrong'))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')
        self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())

    def test_private_log_content_rejected_without_copy(self):
        self.owner_mutation(lambda out: self.put(out / 'qemu.log', b'-----BEGIN PGP PRIVATE KEY BLOCK-----\n'))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')
        manifest = v.read_json(self.output / 'virtual-public/qemu/export-manifest.json')
        self.assertEqual(manifest['evidence_export'], 'FAIL')
        self.assertFalse((self.output / 'virtual-public/qemu/qemu.log').exists())

    def test_oversized_log_has_explicit_refusal_manifest(self):
        self.owner_mutation(lambda out: self.put(out / 'qemu.log', b'a' * (v.LIMIT + 1)))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')
        self.assertEqual(v.read_json(self.output / 'virtual-public/qemu/export-manifest.json')['evidence_export'], 'FAIL')

    def test_owner_public_symlink_refuses(self):
        def replace(out):
            (out / 'qemu.log').unlink(); (out / 'qemu.log').symlink_to(self.base / 'absent')
        self.owner_mutation(replace)
        self.assertEqual(self.run_adapter()['status'], 'FAIL')

    def test_timeout_retains_owner_failure_receipt(self):
        def timeout(argv, log, bound):
            self.mock_owner(argv, log, bound)
            self.mutate(self.output / 'owner-public/result.json', lambda x: x.update(status='FAIL'))
            raise ValueError('stage-deadline-exceeded')
        self.command.side_effect = timeout
        result = self.run_adapter(); self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['owner_cleanup']['status'], 'PASS')
        self.assertTrue((self.output / 'virtual-public/result/result.json').is_file())

    def test_cancel_propagates_after_fail_receipt_and_public_retention(self):
        def cancel(argv, log, bound):
            self.mock_owner(argv, log, bound)
            self.mutate(self.output / 'owner-public/result.json', lambda x: x.update(status='FAIL'))
            raise KeyboardInterrupt()
        self.command.side_effect = cancel
        with self.assertRaises(KeyboardInterrupt):
            self.run_adapter()
        receipt = v.read_json(self.output / 'adapter-status/result.json')
        self.assertEqual(receipt['status'], 'FAIL'); self.assertEqual(receipt['error_code'], 'cancelled')
        self.assertEqual(receipt['owner_cleanup']['status'], 'PASS')
        self.assertIn(str(self.output / 'virtual-public/qemu'), v.public_paths(self.output))

    def test_ordinary_exception_text_never_enters_adapter_receipt(self):
        self.command.side_effect = ValueError('Bearer sensitive-token')
        self.assertEqual(self.run_adapter()['status'], 'FAIL')
        self.assertNotIn('sensitive-token', (self.output / 'adapter-status/result.json').read_text())

    def test_cancel_during_acquisition_records_all_pending_inputs(self):
        count = 0
        def fetch(row, cache, deadline):
            nonlocal count
            count += 1
            if count == 3:
                raise KeyboardInterrupt()
            return self.mock_fetch(row, cache)
        self.fetch.side_effect = fetch
        with self.assertRaises(KeyboardInterrupt):
            self.run_adapter()
        receipt = v.read_json(self.output / 'adapter-status/acquisition.json')
        self.assertEqual(len(receipt['inputs']), 45)
        self.assertEqual(sum(r['status'] == 'PIN_MATCH' for r in receipt['inputs']), 2)
        self.assertTrue(all(r['error_code'] == 'tooling-acquisition-cancelled' for r in receipt['inputs'][2:]))
        self.command.assert_not_called()

    def test_global_deadline_stops_new_fetches_and_records_all_outcomes(self):
        clock = [0]
        def fetch(row, cache, deadline):
            clock[0] = 601
            raise v.AcquisitionDeadline('tooling-acquisition-deadline')
        self.fetch.side_effect = fetch
        with patch.object(v.time, 'monotonic', side_effect=lambda: clock[0]):
            result = self.run_adapter()
        self.assertEqual(result['status'], 'FAIL'); self.assertEqual(self.fetch.call_count, 1)
        receipt = v.read_json(self.output / 'adapter-status/acquisition.json')
        self.assertEqual(len(receipt['inputs']), 45)
        self.assertTrue(all(r['error_code'] == 'tooling-acquisition-deadline' for r in receipt['inputs']))
        self.command.assert_not_called()

    def altered_events(self, out, action):
        path = out / 'guest-events.json'
        events = json.loads(path.read_bytes())
        action(events); self.put_json(path, events)
        self.mutate(out / 'result.json', lambda x: x.update(guest_events_sha256=v.digest(path)))

    def test_rehashed_empty_incomplete_duplicate_or_reordered_events_publish_no_frames(self):
        mutations = [lambda events: events.clear(), lambda events: events.pop(3),
                     lambda events: events.insert(0, copy.deepcopy(events[0])),
                     lambda events: events.reverse()]
        for mutation in mutations:
            self.owner_mutation(lambda out: self.altered_events(out, mutation))
            self.assertEqual(self.run_adapter()['status'], 'FAIL')
            self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())
            self.assertFalse((self.output / 'virtual-public/overlay-frame').exists())
            shutil.rmtree(self.output)

    def test_nonce_boot_arch_page_and_software_probe_drift_publish_no_frames(self):
        mutations = [lambda events: events[0].update(nonce='0' * 32),
                     lambda events: events[1].update(nonce='0' * 32),
                     lambda events: events[-1].update(nonce='0' * 32),
                     lambda events: events[0].update(arch='x86_64'),
                     lambda events: events[0].update(page_size=16384),
                     lambda events: events[1]['probe'].update(renderer='host-GPU'),
                     lambda events: events[2]['clients'][0].update(mapped=False)]
        for mutation in mutations:
            self.owner_mutation(lambda out: self.altered_events(out, mutation))
            self.assertEqual(self.run_adapter()['status'], 'FAIL')
            self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())
            self.assertFalse((self.output / 'virtual-public/overlay-frame').exists())
            shutil.rmtree(self.output)

    def test_actual_interleaved_command_and_known_terminal_log_events_pass(self):
        data = b'\x1b[32mpublic compositor log\x1b[0m\n'
        def add(events):
            for command in ('/usr/bin/dmesg', '/usr/bin/pacman'):
                events.insert(1, {'event': 'command', 'argv': [command], 'returncode': 0, 'error': None,
                                  'stdout': 'public diagnostic', 'stderr': ''})
            events.insert(5, {'event': 'session_log', 'stage': 'minimal', 'filename': 'minimal-client.log',
                             'sha256': sha(data), 'base64': base64.b64encode(data).decode()})
        self.owner_mutation(lambda out: self.altered_events(out, add))
        self.assertEqual(self.run_adapter()['status'], 'PASS')

    def test_encoded_private_terminal_log_is_refused_before_event_copy(self):
        data = b'-----BEGIN PGP PRIVATE KEY BLOCK-----\n'
        def add(events):
            events.insert(3, {'event': 'session_log', 'stage': 'minimal', 'filename': 'minimal.log',
                              'sha256': sha(data), 'base64': base64.b64encode(data).decode()})
        self.owner_mutation(lambda out: self.altered_events(out, add))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')
        self.assertFalse((self.output / 'virtual-public/events').exists())
        self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())

    def test_unknown_event_fields_cannot_enter_public_projection(self):
        self.owner_mutation(lambda out: self.altered_events(out, lambda events: events[2].update(opaque='encoded-unknown-payload')))
        self.assertEqual(self.run_adapter()['status'], 'FAIL')
        self.assertFalse((self.output / 'virtual-public/events').exists())
        self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())

    def test_duplicate_event_json_fields_refused_before_public_copy(self):
        def duplicate(out):
            path = out / 'guest-events.json'
            data = path.read_bytes().replace(b'"event": "boot"', b'"event": "boot", "event": "boot"', 1)
            self.put(path, data)
            self.mutate(out / 'result.json', lambda x: x.update(guest_events_sha256=sha(data)))
        self.owner_mutation(duplicate)
        self.assertEqual(self.run_adapter()['status'], 'FAIL')
        self.assertFalse((self.output / 'virtual-public/events').exists())
        self.assertFalse((self.output / 'virtual-public/minimal-frame').exists())

    def test_unsafe_cache_ancestor_cannot_create_external_directory(self):
        external = self.base / 'external'; external.mkdir()
        link = self.base / 'linked-cache'; link.symlink_to(external, target_is_directory=True)
        result = v.run_virtual(self.c, self.root, self.output, link / 'new-cache')
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(list(external.iterdir()), [])
        self.fetch.assert_not_called(); self.command.assert_not_called()
        self.assertEqual(len(v.read_json(self.output / 'adapter-status/acquisition.json')['inputs']), 45)

    def test_repeated_late_cancel_is_deferred_then_fail_receipt_rewritten(self):
        original_save = v.save
        original_signal = v.signal.signal
        handlers = {}
        def track(sig, handler):
            handlers[sig] = handler
            return original_signal(sig, handler)
        fired = False
        def interrupted(path, value):
            nonlocal fired
            original_save(path, value)
            if Path(path) == self.output / 'adapter-status/result.json' and not fired:
                fired = True
                handlers[v.signal.SIGTERM](v.signal.SIGTERM, None)
                handlers[v.signal.SIGINT](v.signal.SIGINT, None)
        with patch.object(v.signal, 'signal', side_effect=track), patch.object(v, 'save', side_effect=interrupted), \
                self.assertRaises(KeyboardInterrupt):
            self.run_adapter()
        receipt = v.read_json(self.output / 'adapter-status/result.json')
        self.assertEqual(receipt['status'], 'FAIL'); self.assertEqual(receipt['error_code'], 'cancelled')
        self.assertEqual(len(v.read_json(self.output / 'adapter-status/acquisition.json')['inputs']), 45)
        self.assertTrue((self.output / 'virtual-public/result/result.json').is_file())

    def test_candidate_literal_drafts_bind_actual_source_without_importing_owner(self):
        actual = HERE.parents[2] / 'scripts/virtual'
        for name in v.PACKET_FILES - {'tooling.lock.json', 'tooling-audit.json'}:
            shutil.copyfile(actual / name, self.owner / name)
        accepted = {name: v.digest(self.owner / name) for name in v.PACKET_FILES}
        with self.assertRaises(ValueError):
            v.source_packet(SimpleNamespace(virtual_packet_sha256=accepted), self.root)
        declarations = {'LOCK_PIN': accepted['tooling.lock.json'], 'AUDIT_PIN': accepted['tooling-audit.json'],
                        'AUDITOR_PIN': accepted['audit_tooling.py'], 'ALIASES': v.ALIASES,
                        'CORE': {name: accepted[name] for name in ('common.py', 'guest.py', 'prepare.py', 'run.py', 'gbm_probe.c')}}
        with (self.owner / 'controller.py').open('a') as stream:
            stream.write('\n' + '\n'.join(name + ' = ' + repr(value) for name, value in declarations.items()))
            stream.write('\nraise RuntimeError("owner-must-not-be-imported")\n')
        accepted['controller.py'] = v.digest(self.owner / 'controller.py')
        v.source_packet(SimpleNamespace(virtual_packet_sha256=accepted), self.root)


class BoundedTransport(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.cache = Path(temp.name)
        self.data = b'authenticated public package bytes'
        self.row = {'filename': 'fixture.pkg.tar.xz', 'url': 'https://example.invalid/fixture.pkg.tar.xz',
                    'sha256': sha(self.data), 'size': len(self.data)}

    def response(self, data=None, url=None):
        response = io.BytesIO(self.data if data is None else data)
        response.status = 200; response.headers = {'Content-Length': str(len(self.data))}
        response.geturl = lambda: url or self.row['url']
        return response

    def test_exact_input_download_and_cached_reuse(self):
        with patch.object(v, 'open_tooling', return_value=self.response()) as transport:
            path = v.fetch_blob(self.row, self.cache, v.time.monotonic() + 600)
        transport.assert_called_once_with(self.row['url'], timeout=15)
        self.assertEqual(path.read_bytes(), self.data)
        with patch.object(v, 'open_tooling', side_effect=AssertionError('no cache fallback')):
            self.assertEqual(v.fetch_blob(self.row, self.cache, v.time.monotonic() + 600), path)
        self.assertFalse(any(p.name.endswith('.partial') for p in self.cache.iterdir()))

    def test_oversize_hash_failure_and_insecure_final_response_remove_only_owned_partial(self):
        unrelated = self.cache / 'unrelated.partial'; unrelated.write_bytes(b'preserve')
        for response in (self.response(self.data + b'x'), self.response(b'x' * len(self.data)),
                         self.response(url='http://example.invalid/fixture.pkg.tar.xz')):
            with patch.object(v, 'open_tooling', return_value=response), self.assertRaises(ValueError):
                v.fetch_blob(self.row, self.cache, v.time.monotonic() + 600)
            self.assertEqual(list(self.cache.iterdir()), [unrelated])

    def test_short_reads_are_checked_against_global_deadline(self):
        clock = [0]
        response = self.response()
        def trickle(size):
            clock[0] += 302
            return b'x'
        response.read1 = trickle
        with patch.object(v.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(v, 'open_tooling', return_value=response), self.assertRaises(v.AcquisitionDeadline):
            v.fetch_blob(self.row, self.cache, 600)
        self.assertEqual(clock[0], 604); self.assertEqual(list(self.cache.iterdir()), [])

    def test_cancelled_transport_closes_and_removes_owned_partial(self):
        response = self.response(); response.read1 = Mock(side_effect=KeyboardInterrupt())
        with patch.object(v, 'open_tooling', return_value=response), self.assertRaises(KeyboardInterrupt):
            v.fetch_blob(self.row, self.cache, v.time.monotonic() + 600)
        self.assertTrue(response.closed); self.assertEqual(list(self.cache.iterdir()), [])

    def test_symlink_or_changed_cache_refused_without_network(self):
        path = self.cache / self.row['filename']; path.symlink_to('/absent')
        with patch.object(v, 'open_tooling') as transport, self.assertRaises(ValueError):
            v.fetch_blob(self.row, self.cache, v.time.monotonic() + 600)
        transport.assert_not_called(); path.unlink(); path.write_bytes(b'wrong')
        with patch.object(v, 'open_tooling') as transport, self.assertRaises(ValueError):
            v.fetch_blob(self.row, self.cache, v.time.monotonic() + 600)
        transport.assert_not_called()

    def test_redirect_rejects_insecure_hop_before_destination_request(self):
        with self.assertRaisesRegex(ValueError, 'insecure-redirect'):
            v.HTTPSRedirect().redirect_request(None, None, 302, '', {}, 'http://example.invalid/public')

    def test_phase_alarm_bounds_header_trickle_and_restores_outer_remaining_time(self):
        handlers, clock = [], [10]
        outer = Mock()
        with patch.object(v.signal, 'getsignal', return_value=outer), \
                patch.object(v.signal, 'getitimer', return_value=(1200, 0)), \
                patch.object(v.signal, 'signal', side_effect=lambda sig, handler: handlers.append(handler)), \
                patch.object(v.signal, 'setitimer') as timer, \
                patch.object(v.time, 'monotonic', side_effect=lambda: clock[0]):
            with self.assertRaises(v.AcquisitionDeadline):
                with v.acquisition_clock() as deadline:
                    self.assertEqual(deadline, 610)
                    clock[0] = 610
                    with patch.object(v, 'open_tooling', side_effect=lambda *a, **k: handlers[0](v.signal.SIGALRM, None)):
                        v.fetch_blob(self.row, self.cache, deadline + 1)
            self.assertEqual(timer.call_args_list[0].args, (v.signal.ITIMER_REAL, 600))
            self.assertEqual(timer.call_args_list[-1].args, (v.signal.ITIMER_REAL, 600, 0))
            self.assertIs(handlers[-1], outer)
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_earlier_enclosing_alarm_remains_authoritative(self):
        handlers = []
        outer = Mock(side_effect=KeyboardInterrupt())
        with patch.object(v.signal, 'getsignal', return_value=outer), \
                patch.object(v.signal, 'getitimer', return_value=(50, 0)), \
                patch.object(v.signal, 'signal', side_effect=lambda sig, handler: handlers.append(handler)), \
                patch.object(v.signal, 'setitimer') as timer:
            with self.assertRaises(KeyboardInterrupt):
                with v.acquisition_clock():
                    handlers[0](v.signal.SIGALRM, None)
            self.assertEqual(timer.call_args_list[0].args, (v.signal.ITIMER_REAL, 50))
            self.assertEqual(timer.call_args_list[-1].args, (v.signal.ITIMER_REAL, 0))
            outer.assert_called_once_with(v.signal.SIGALRM, None)
            self.assertIs(handlers[-1], outer)


if __name__ == '__main__':
    unittest.main()

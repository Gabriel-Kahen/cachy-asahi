# SPDX-License-Identifier: MIT
"""Execute the actual prerequisite shell with inert external-command boundaries."""
import os,subprocess,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C
NAME='Bounded disposable host QEMU prerequisite before native producer'
CHECKOUT='actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
def block():
 text=C.read(C.HERE/'workflow.yml.in').decode();begin=text.index('      - name: '+NAME+'\n');end=text.index('      - name: ',begin+10);raw=text[begin:end];return '\n'.join(line[10:]for line in raw.splitlines()if line.startswith('          '))+'\n'
def run(failure=''):
 # Only these external boundaries are inert. The whole emitted run block and
 # its set -e behavior execute unchanged. No apt, sudo, QEMU or daemon is run.
 fixture=r'''
sudo() { printf 'sudo %s\n' "$*"; if [[ "$*" == *" update" && "$CONTROL_FAIL" == update || "$*" == *" install "* && "$CONTROL_FAIL" == install ]]; then return 77; fi; }
function /usr/bin/qemu-system-aarch64 { printf 'qemu %s\n' "$*"; if [[ "$CONTROL_FAIL" == qemu ]]; then return 127; fi; printf 'CONTROL ONLY QEMU VERSION\n'; }
function /usr/bin/dpkg-query { printf 'dpkg %s\n' "$*"; if [[ "$CONTROL_FAIL" == query ]]; then return 78; fi; printf 'qemu-system-arm CONTROL ONLY\n'; }
'''
 return subprocess.run(['/usr/bin/bash','-eu','-o','pipefail','-c',fixture+block()],env=dict(PATH='/usr/bin:/bin',CONTROL_FAIL=failure),capture_output=True,timeout=10)
class Host(unittest.TestCase):
 def test_actual_shell_exact_dependency_route(self):
  p=run();self.assertEqual((p.returncode,p.stderr),(0,b''));lines=p.stdout.decode().splitlines();self.assertEqual(lines[:3],['sudo timeout --signal=TERM --kill-after=10s 120s apt-get -o Acquire::Retries=0 update','sudo timeout --signal=TERM --kill-after=10s 120s apt-get -o Acquire::Retries=0 install --no-install-recommends -y qemu-system-arm','qemu --version']);self.assertIn('dpkg -W qemu-system-arm',lines)
 def test_dependency_failure_stops_before_later_commands(self):
  for failure,code,next_command in(('update',77,b' install '),('install',77,b'qemu --version'),('qemu',127,b'dpkg -W'),('query',78,b'UNREACHABLE')):
   p=run(failure);self.assertEqual(p.returncode,code);self.assertNotIn(next_command,p.stdout)
 def test_explicit_checkout_names_and_dependency_order(self):
  raw=C.read(C.HERE/'workflow.yml.in').decode();self.assertNotIn('      - uses:',raw);names=[line.split('- name: ',1)[1]for line in raw.splitlines()if line.startswith('      - name: ')];self.assertEqual(len(names),len(set(names)));self.assertEqual(names[:4],['Checkout exact original Core800 source','Checkout exact closed two-boot case source','Checkout exact original KSM637 VM source','Checkout exact accepted generic16K kernel inputs']);self.assertLess(raw.index(NAME),raw.index('Reuse unchanged owned574 native producer'));self.assertIn('timeout-minutes: 5\n        run: |\n          set -euo pipefail',raw[raw.index(NAME):]);self.assertEqual(raw.count('qemu-system-arm'),2)
if __name__=='__main__':unittest.main(verbosity=2)

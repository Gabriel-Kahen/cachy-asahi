# SPDX-License-Identifier: MIT
"""Root-only durable installed gate before unchanged real keyboard/PAM observer."""
import hashlib,importlib.util,json,os,subprocess,time
from pathlib import Path
ROOT=Path('/opt/ui-session');RUNTIME=Path('/run/ui-session')
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def wait_installed(nonce,seconds):
 assert os.geteuid()==0 and os.uname().machine=='aarch64'and os.sysconf('SC_PAGE_SIZE')==16384
 data=(ROOT/'inputs.json').read_bytes();assert len(data)<=2*1024**2;contract=json.loads(data);assert len(contract['baseline_versions'])==111 and len(contract['archives'])==172
 receipts=module('arm_ui_receipts','/usr/local/libexec/ui-receipts.py');expected={**contract['baseline_versions'],**{r['name']:r['version']for r in contract['archives']}};assert len(expected)==283
 until=time.monotonic()+seconds;last_service=0
 while time.monotonic()<until:
  value=receipts.installed_gate(receipts.DIRECTORY,nonce,hashlib.sha256(data).hexdigest(),expected,len(contract['project_payloads']))
  if value is not None:return value
  if time.monotonic()-last_service>=1:
   last_service=time.monotonic();service=subprocess.run(['/usr/bin/systemctl','show','arm16k-ui-fixture.service','--property=ActiveState','--value'],capture_output=True,timeout=5);assert service.returncode==0 and len(service.stdout)<128 and len(service.stderr)<4096
   if service.stdout.strip()==b'failed':raise RuntimeError('root-service-failed')
  time.sleep(.1)
 raise TimeoutError('durable strict283 installed gate timeout')

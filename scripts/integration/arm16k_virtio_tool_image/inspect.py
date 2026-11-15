#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Static archive/signature/module verification only; no Docker or payload execution."""
import argparse,importlib.util,json,subprocess,sys,tempfile
from pathlib import Path
H=Path(__file__).resolve().parent;s=importlib.util.spec_from_file_location('virtio_contract',H/'contract.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--archive',type=Path,required=True);p.add_argument('--signature',type=Path,required=True);p.add_argument('--binary-keyring',type=Path,required=True);p.add_argument('--qemu-binary',type=Path,required=True);a=p.parse_args();C.need(sys.version_info>=(3,14),'Python3.14 stdlib zstd required');v=C.lock();result=C.archive(a.archive.resolve());C.checked(a.signature.resolve(),v['package']['signature']);qemu=C.checked(a.qemu_binary.resolve(),v['qemu']);C.need(v['module']['stamp'].encode()in qemu,'matching actual parent QEMU ABI stamp');keyring=a.binary_keyring.resolve();C.read(keyring,4*1024**2)
 with tempfile.TemporaryDirectory(prefix='cachy-virtio-gpgv-')as home:
  r=subprocess.run(['gpgv','--homedir',home,'--keyring',str(keyring),'--status-fd','1',str(a.signature.resolve()),str(a.archive.resolve())],capture_output=True,timeout=20);C.need(r.returncode==0,'gpgv detached verification failed');result['VALIDSIG']=C.signed(r.stdout)
 print(json.dumps(dict(status='STATIC_SIGNATURE_MODULE_DATA_VERIFIED',**result),sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())

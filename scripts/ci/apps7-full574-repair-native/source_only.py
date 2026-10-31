#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Local data/source proof only: never satisfies an actor's public binding gate."""
import argparse,importlib.util,json,subprocess,sys,types
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module

def inspect(source,packet):
 C=load('apps7_source_data_contract',HERE/'contract.py')
 manifest_rows=json.loads((HERE/'source-manifest.json').read_bytes())['files']
 for n,row in manifest_rows.items():C.checked(source,dict(path=n,**row))
 binding=json.loads((HERE/'input-policy.json').read_bytes());C.need(binding['status']=='UNBOUND' and binding['packet_source'] is binding['packet_index'] is None,'default future binding remains NULL')
 original=C.load('bounded_data_facade',source/'scripts/ci/management-tools-generic16k/contract.py')
 facade=types.SimpleNamespace(**vars(original));raw=(packet/'index.json').read_bytes()
 facade.policy=lambda:dict(packet_index=dict(path='index.json',bytes=len(raw),sha256=C.sha(raw)))
 factory=C.load('new_apps7_packet',HERE/'packet.py').module(facade,source)
 value=factory.packet(packet);checks=C.load('trusted_apps7_package_checks',source/'scripts/checks/package_checks.py')
 payload,origins=factory.package_payload(packet,value,checks)
 closure=C.load('new_apps7_closure',HERE/'closure.py')
 C.need(closure.VERSIONS==C.VERSIONS and len(payload)==25 and set(origins.values())==set(C.VERSIONS),'exact four-product source payload')
 # All non-directory source-owned nodes must match the installed package payload.
 for name,rows in closure.current_payloads().items():
  for path,row in rows.items():
   if row['type']=='file':C.need(payload[path][0]==row['mode'] and C.sha(payload[path][1])==row['sha256'],'source/archive full closure: '+path)
 return dict(status='LOCAL_SOURCE_ONLY_NOT_PUBLIC',source_files=len(manifest_rows),packages={n:r['version'] for n,r in value['packages'].items()},payload_files=len(payload),packet_index_sha256=C.sha(raw),public_carrier=None,actual_runs=None,repair='NOT_RUN',hardware='NOT_RUN')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--packet',type=Path,required=True);a=p.parse_args()
 subprocess.Popen=lambda *a,**k:(_ for _ in ()).throw(AssertionError('process creation prohibited'))
 print(json.dumps(inspect(a.source.absolute(),a.packet.absolute()),sort_keys=True))

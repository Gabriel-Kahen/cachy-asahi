#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual producer/consumer DATA joins on synthetic modeled Image; no actor."""
import argparse,contextlib,ctypes,hashlib,importlib.util,json,os,socket,struct,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
CONSUMER_SHAS={'e7d3d8f0ecc6e4991ffaf3e2459a2034acf46609de6416376a74573477143fe2','c78861dbf1b1cde14484a7c335468174f78547399034022cffc5a4a97e458ebb'}


def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--consumer',type=Path,action='append',required=True);a=p.parse_args()
 for consumer in a.consumer:
  if hashlib.sha256(consumer.read_bytes()).hexdigest() not in CONSUMER_SHAS:raise ValueError('corrected exact consumer operand required')
 with contextlib.ExitStack() as stack:
  for module,names in ((subprocess,('Popen',)),(socket,('socket','create_connection')),(ctypes,('CDLL',)),(os,('system','fork','forkpty','posix_spawn','posix_spawnp','execv','execve','execvp','execvpe'))):
   for name in names:
    if hasattr(module,name):stack.enter_context(patch.object(module,name,side_effect=AssertionError('actor fenced: '+name)))
  C=load('rtc_interop_producer',HERE/'contract.py')
  class Interop(unittest.TestCase):
   def model(self,root):
    image=root/'Image';raw=bytearray(256);raw[56:60]=b'ARM\x64';struct.pack_into('<Q',raw,16,256);struct.pack_into('<Q',raw,24,4);image.write_bytes(raw)
    facts=json.loads((HERE/'data/configure-r2-facts.json').read_text())['genuine_compiler_auxiliary_facts'];lines=[];seen=set()
    for line in C.construct(C.data()).decode().splitlines():
     row=C.values((line+'\n').encode());key=next(iter(row),None)
     if key in facts:
      value=facts[key]['after'];lines.append(key+'='+value if value!='n' else '# '+key+' is not set');seen.add(key)
     else:lines.append(line)
    for key in facts:
     if key not in seen:
      value=facts[key]['after'];lines.append(key+'='+value if value!='n' else '# '+key+' is not set')
    config=root/'config';config.write_text('\n'.join(lines)+'\n');profile={'mode':'HOST_CROSS_ARM64','compiler_facts':facts}
    bundle=C.bundle(image,config,profile,'a'*64,{'clang':{'path':'/usr/bin/clang','bytes':1,'sha256':'b'*64}},[{'label':'MODELED_ONLY','retirement':{'passed':True,'reaped':True,'exit':0,'group_census':'EMPTY_TWICE'}}],'2026-11-15T00:00:00+00:00','2026-11-15T00:00:01+00:00')
    manifest=root/'bundle.json';manifest.write_text(json.dumps(bundle,sort_keys=True));approved={'kernel_bundle':C.pin(manifest),'approved_compiler_facts':facts};return bundle,approved
   def test_full_actual_producer_to_corrected_consumer(self):
    with tempfile.TemporaryDirectory() as tmp:
     root=Path(tmp);bundle,approved=self.model(root);actual=K.kernel(root,approved,HERE/'data/baseline.config');self.assertEqual(actual,bundle);self.assertIn('CONFIG_LOCALVERSION',actual['config_proof']['feature_delta']);self.assertNotIn('CONFIG_LOCALVERSION',actual['config_proof']['compiler_facts'])
   def test_extra_archive_root_metadata_refuses(self):
    with tempfile.TemporaryDirectory() as tmp:
     root=Path(tmp);bundle,approved=self.model(root);bundle['source']['archive']['root']='linux-asahi-7.1.13-3';(root/'bundle.json').write_text(json.dumps(bundle));approved['kernel_bundle']=C.pin(root/'bundle.json')
     with self.assertRaisesRegex(ValueError,'archive'):K.kernel(root,approved,HERE/'data/baseline.config')
   def test_omitted_localversion_delta_refuses(self):
    with tempfile.TemporaryDirectory() as tmp:
     root=Path(tmp);bundle,approved=self.model(root);del bundle['config_proof']['feature_delta']['CONFIG_LOCALVERSION'];(root/'bundle.json').write_text(json.dumps(bundle));approved['kernel_bundle']=C.pin(root/'bundle.json')
     with self.assertRaises(ValueError):K.kernel(root,approved,HERE/'data/baseline.config')
   def test_compiler_before_not_original_refuses(self):
    with tempfile.TemporaryDirectory() as tmp:
     root=Path(tmp);bundle,approved=self.model(root);facts=bundle['config_proof']['compiler_facts'];facts['CONFIG_CLANG_VERSION']={'before':'220108','after':'220108'};approved['approved_compiler_facts']=facts;(root/'bundle.json').write_text(json.dumps(bundle));approved['kernel_bundle']=C.pin(root/'bundle.json')
     with self.assertRaises(ValueError):K.kernel(root,approved,HERE/'data/baseline.config')
  passed=True
  for consumer in a.consumer:
   K=load('rtc_interop_consumer_'+consumer.parent.name,consumer);print('Consumer:',consumer.parent.name,flush=True)
   result=unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(Interop));passed=passed and result.wasSuccessful()
  return 0 if passed else 1


if __name__=='__main__':raise SystemExit(main())

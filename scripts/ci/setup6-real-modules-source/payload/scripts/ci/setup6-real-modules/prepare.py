#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Whole immutable accepted6 proof, then unchanged exact5/six-module staging."""
import argparse,json,shutil,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

def stage(source,packet,modules,out):
 C.verify_source(source);profile=C.read(C.HERE/'accepted6-profile.json');proof=C.load('whole_setup6_carrier_proof',source/'setup6-source/scripts/ci/setup6-retained-helpers/legacy_prefill.py').prove(packet,packet/'.git',profile,time.monotonic()+120)
 old=C.load('unchanged_real5_packet_stager',source/'scripts/ci/setup5-native-real-modules/prepare.py');old.stage(source,packet/'native/retained-setup5',modules,out)
 target=out/'setup6';target.mkdir(mode=0o700)
 for n,r in profile['files'].items():
  p=C.checked(packet,dict(path=n,**r),16*1024**2);q=target/n;q.parent.mkdir(parents=True,exist_ok=True,mode=0o700);shutil.copyfile(p,q);C.checked(target,dict(path=n,**r),16*1024**2)
 (out/'setup6-source-custody.json').write_text(json.dumps(proof,indent=2)+'\n');return proof
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','setup6-checkout','modules-checkout','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(stage(a.source.absolute(),a.setup6_checkout.absolute(),a.modules_checkout.absolute(),a.output.absolute())))

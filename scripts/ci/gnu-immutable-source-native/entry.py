"""Closed source/default refusal and the real native pipeline entry route."""
import argparse,os,subprocess,sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import deploy as D

def source(root):
 fact=D.source(root)
 with patch.object(subprocess,'Popen',side_effect=AssertionError('SOURCE_ONLY_NO_ACTORS')),patch.object(subprocess,'run',side_effect=AssertionError('SOURCE_ONLY_NO_ACTORS')):
  import kernel_input as K,binding
  K.known()
  if D.obj(D.read(root/D.LANE/'input-policy.json'))['boot_decision']is not None:binding.boot(root)
  with K.reader():pass
  I=binding.runtime(root);C=I.current_module('_immutable_source_current_phase',root/D.VM/D.INST/'contract.py');C.check_source(root/D.VM);phases=C.gate(root/D.VM/D.INST/'prerequisites');D.need(phases['native_lifecycle']['provider_archive_sha256']=='a8e9f3e1d8ffe049fdc834f62e74c14ff622b98898c2f849e1580ab8aa0fdbd9','current a8e9 CAA3 phase, never legacy b852')
  P=I.current_module('_immutable_source_current_prepare',root/D.VM/D.INST/'prepare.py');R=I.current_module('_immutable_source_current_run',root/D.VM/D.INST/'run.py');A=I.current_module('_immutable_source_current_adapter',root/D.VM/D.INST/'adapter.py');text,proof=A.derive(root/D.VM)
  sys.path.insert(0,str(root/'runtime/immutable'));W=D.load('_immutable_source_worker_deriver',root/'runtime/immutable/worker.py');compile(W.lifecycle(text.encode()),'<actual-current-lifecycle>','exec')
  N=D.load('_immutable_source_actual_native_controller',root/'runtime/immutable/native_controller.py');derived,ownerproof=N.derive(Path(R.__file__).read_bytes());compile(derived,'<actual-current-native-owner>','exec');NP=D.load('_immutable_source_actual_native_preparer',root/'runtime/immutable/native_prepare.py');NP.load(None)
 return dict(fact,current_native_phase='GENUINE_HELD_ROOT_NATIVE_PLUS_STAGED16K',current_provider='a8e9_CAA3',native_owner_seams=ownerproof['seams'],original_lifecycle_bodies_held=proof['unchanged_bodies'],boot=('NULL_REFUSES_BEFORE_ACTORS'if D.obj(D.read(root/D.LANE/'input-policy.json'))['boot_decision']is None else 'ROOT_BOUND_AVAILABILITY_ONLY_NOT_MAPPING'),actual_source=None,actual_ref=None,actual_run=None)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('source','bind','kernel'));p.add_argument('--source',type=Path,default=D.ROOT);p.add_argument('--output',type=Path);a=p.parse_args()
 if a.action=='source':value=source(a.source.absolute())
 elif a.action=='bind':
  import binding;value=binding.build(a.source,a.output)
 else:
  import binding,kernel_input;D.source(a.source);binding.boot(a.source);value=kernel_input.acquire(a.output)
 print(D.encoded(value).decode(),end='');return 0
if __name__=='__main__':raise SystemExit(main())

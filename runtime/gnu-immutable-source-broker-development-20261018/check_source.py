"""No-process source gate; does not bind authority or call broker/DM/PID1."""
import ast,hashlib,json,subprocess,sys
from pathlib import Path
from unittest.mock import patch
import context as C,protocol as P,integration
D=Path(__file__).resolve().parent
with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS')):
 pins=P.decode((D/'input-pins.json').read_bytes());P.need(pins['accepted_authorities']is None,'source-only authority selection NULL')
 for n in pins:
  if n!='accepted_authorities':C.trusted(n)
 api,modules=C.source_api();_,old=C.trusted('gnu-verity-bootstrap-development-20261018/bootstrap.py');new=integration.derive(old)
 P.need(P.pin(old)!=P.pin(new),'explicit derivative, no whole-original claim')
 for path in D.glob('*.py'):compile(path.read_bytes(),str(path),'exec')
 try:C.selection(P.decode((D/'selection.template.json').read_bytes()))
 except ValueError:pass
 else:raise AssertionError('default authority accepted')
print('PASS_WHOLE_PINNED_ORIGINALS_DERIVATIVE_INVERSE_NULL_GATE_NO_PROCESS_NO_KERNEL_AUTHORITY')

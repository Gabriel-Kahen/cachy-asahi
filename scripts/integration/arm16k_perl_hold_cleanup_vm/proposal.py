# SPDX-License-Identifier: MIT
"""Pure exact9dd controller replacement proposal; Root owns Source construction."""
import hashlib
from pathlib import Path
HERE=Path(__file__).resolve().parent
SOURCE=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-initialized-lifecycle-readiness-20261117-r2/constructed-source')
LOCK=dict(bytes=24055,sha256='9dd3695b4892a740c3f1e9b878e41fe009e9fa66494be2db012275b71dd2f946')
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
CONTROLLER={'bytes': 26390, 'sha256': 'f1253c84211dafe5f232a5e95007e5e1c911ce7f1735581a545076817d76efeb'}
def transform(controller):
 if pin(controller)!=CONTROLLER:raise ValueError('exact Source9dd controller body')
 text=controller.decode();start='def quit_hold_qmp(';end='def normal_hold_cleanup('
 if text.count(start)!=1 or text.count(end)!=1:raise ValueError('single exact HOLD quit seam')
 a=text.index(start);b=text.index(end,a)
 text=text[:a]+"def quit_hold_qmp(peer,qfile,guard,end,progress=None):\n return module('hold_cleanup').quit_hold_qmp(module('contracts'),peer,qfile,guard,end,progress)\n\n\n"+text[b:]
 old="    for handle in (serial.stream if serial is not None else None,qfile,qmp,peer):"
 if text.count(old)!=1:raise ValueError('single exact final cleanup observation seam')
 diagnostic="""    if report.get('failure'):
     try:
      report['retirement_observation']=module('hold_cleanup').retirement_observation(K,out,P.HOLD_RETIRED)
      if 'actor_failure_diagnostic'not in report:report['actor_failure_diagnostic']=capture_actor_failure(K,out,a.phase,packet['nonce'],source,cert['runtime_certificate'])
     except BaseException:report['retirement_observation']=dict(status='REFUSED_OBSERVATION',VM_acceptance=None,Root_acceptance=None)
"""
 text=text.replace(old,diagnostic+old)
 return {'controller.py':text.encode(),'hold_cleanup.py':(HERE/'hold_cleanup.py').read_bytes()}

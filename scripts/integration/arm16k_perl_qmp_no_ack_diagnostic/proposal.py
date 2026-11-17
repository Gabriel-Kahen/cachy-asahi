# SPDX-License-Identifier: MIT
"""Exact Source310 failure-observation proposal, not an issued Source constructor."""
import hashlib
import json
from pathlib import Path
HERE = Path(__file__).resolve().parent


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def replace(raw, old, new):
    if raw.count(old) != 1:
        raise ValueError('single exact observation seam required')
    return raw.replace(old, new)


def transform(controller, helper):
    inputs = json.loads((HERE / 'inputs.DATA.json').read_bytes())
    if pin(controller) != inputs['files']['controller.py'] or pin(helper) != inputs['files']['hold_cleanup.py']:
        raise ValueError('exact immutable Source310 controller/helper required')
    text = helper.decode()
    text = replace(text, "  progress['stage']='WRITE_ENTERED'", "  progress['transport_before_write']=observe_transport(peer)\n  progress['stage']='WRITE_ENTERED'")
    text = replace(text, "  progress['stage']='WRITE_RETURNED'", "  progress['stage']='WRITE_RETURNED'\n  progress['transport_after_write']=observe_transport(peer)")
    text = replace(text, ' finally:stream.settimeout(original_timeout)', " finally:\n  progress['transport_at_exit']=observe_transport(peer)\n  stream.settimeout(original_timeout)")
    text = replace(text, ' def observe(name):\n  try:', ' def observe(name):\n  result=None\n  try:')
    text = replace(text, "type(row['exit'])is int and 0<=row['exit']<=255", "type(row['exit'])is int and -64<=row['exit']<=255")
    text = replace(text, "('REAPED','OWNERSHIP_LOST')", "('REAPED','UNKNOWN','OWNED','OWNERSHIP_LOST')")
    text = replace(text, "('EMPTY_TWICE','NOT_EMPTY','UNKNOWN')", "('EMPTY_TWICE','EMPTY_ONCE','RESERVED_LEADER_ONLY','RESERVED_MEMBERS_REMAIN','PRESENT_OR_REUSED','NOT_OBSERVED','NOT_EMPTY','UNKNOWN')")
    text = replace(text, "  except BaseException:return dict(status='REFUSED_UNSAFE_OR_INVALID')", "  except BaseException:\n   return dict(status='REFUSED_UNSAFE_OR_INVALID',file=result['file'])if result is not None else dict(status='REFUSED_UNSAFE_OR_INVALID')")
    text += "\n\ndef observe_transport(peer):\n try:return module_observations().transport_observation(peer)\n except Exception:return dict(status='UNAVAILABLE',VM_acceptance=None,Root_acceptance=None)\n\n\ndef module_observations():\n from pathlib import Path\n import importlib.util\n s=importlib.util.spec_from_file_location('qmp_public_observations',Path(__file__).parent/'qmp_observations.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m\n"
    changed = controller.decode()
    # Source310 places capture_actor_failure before cleanup_scope; anchor only the
    # exact final cleanup call followed by authority, not another normal path.
    old=" scope.cleanup(report)\n\n\ndef authority("
    new=" if report.get('forced_owned_cleanup_fallback'):\n  try:module('qmp_observations').retirement_journal(module('contracts'),out,module('protocol').HOLD_RETIRED,'BEFORE_FORCED_FALLBACK',report,module('hold_cleanup').retirement_observation)\n  except Exception:pass\n scope.cleanup(report)\n\n\ndef authority("
    changed = replace(changed, old, new)
    old="      report['retirement_observation']=module('hold_cleanup').retirement_observation(K,out,P.HOLD_RETIRED)"
    changed = replace(changed, old, old+"\n      try:module('qmp_observations').retirement_journal(K,out,P.HOLD_RETIRED,'AFTER_OWNED_CLEANUP',report,module('hold_cleanup').retirement_observation)\n      except Exception:pass")
    return {'controller.py': changed.encode(), 'hold_cleanup.py': text.encode(),
            'qmp_observations.py': (HERE / 'observations.py').read_bytes()}


def inverse(controller, helper, replacement):
    if transform(controller, helper) != replacement:
        raise ValueError('whole exact failure-observation derivative required')
    return controller, helper

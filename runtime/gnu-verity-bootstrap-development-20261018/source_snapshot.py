"""Complete original read-only observer/capability maps, never a substitute map."""
import importlib,sys
from pathlib import Path
import common as C

def api():
 rows=C.source_inputs();root=C.D.parent/rows['roles']['VM226']['root'];sys.path[:0]=[str(root/'scripts/update'),str(root/'scripts/apps')]
 modules={n:importlib.import_module(n)for n in('full_root','file_capabilities','root_link_selection','aux_checkpoint')}
 for n,m in modules.items():C.need(Path(m.__file__).is_relative_to(root),'source-static original helper only: '+n)
 return modules

def raw_maps(modules, root, limits):
    F = modules['full_root']
    _phase(b'OBSERVE_BEGIN', root)
    try:
        value = F.observe(root, limits=limits, hardlinks='generic-development-internal')
        C.need(value['complete'] is True, 'complete original observation')
    except BaseException:
        try:
            _phase(b'OBSERVE_FAIL', root)
        except BaseException:
            pass
        raise
    _phase(b'OBSERVE_END', root)
    _phase(b'CAPABILITIES_BEGIN', root)
    try:
        caps, physical = modules['file_capabilities']._scan(root, value['nodes'], limits)
    except BaseException:
        try:
            _phase(b'CAPABILITIES_FAIL', root)
        except BaseException:
            pass
        raise
    _phase(b'CAPABILITIES_END', root)
    return dict(observation=value, nodes=value['nodes'], capabilities=caps, physical=physical)


def observe(modules, root, limits):
    value = raw_maps(modules, root, limits)
    _phase(b'SELECTED_LINKS_BEGIN', root)
    try:
        modules['root_link_selection'].check(value['observation'], limits)
    except BaseException:
        try:
            _phase(b'SELECTED_LINKS_FAIL', root)
        except BaseException:
            pass
        raise
    _phase(b'SELECTED_LINKS_END', root)
    _phase(b'AUXILIARY_1_BEGIN', root)
    try:
        modules['aux_checkpoint'].checkpoint(root, value['observation'], limits)
    except BaseException:
        try:
            _phase(b'AUXILIARY_1_FAIL', root)
        except BaseException:
            pass
        raise
    _phase(b'AUXILIARY_1_END', root)
    return value


def same(before,after):
 # Preserve full reports. Only fresh capacity counters may legitimately change
 # while preparing output on the same host filesystem; never rewrite raw maps.
 import copy
 a,b=copy.deepcopy(before),copy.deepcopy(after)
 for value in(a,b):
  f=value['observation']['footprint']
  for k in('filesystem_free_bytes','filesystem_free_inodes'):
   C.need(k in f and(f[k]is None or type(f[k])is int and f[k]>=0),'fresh original capacity counter');f.pop(k)
 C.need(a==b,'every original stable field/capability/physical/hardlink/rawDB map must remain equal')

import os as _phase_os
_PHASE_LABELS=(b'OBSERVE_BEGIN', b'OBSERVE_END', b'OBSERVE_FAIL', b'CAPABILITIES_BEGIN', b'CAPABILITIES_END', b'CAPABILITIES_FAIL', b'SELECTED_LINKS_BEGIN', b'SELECTED_LINKS_END', b'SELECTED_LINKS_FAIL', b'AUXILIARY_1_BEGIN', b'AUXILIARY_1_END', b'AUXILIARY_1_FAIL', b'AUXILIARY_2_BEGIN', b'AUXILIARY_2_END', b'AUXILIARY_2_FAIL', b'LIFECYCLE_BEGIN', b'LIFECYCLE_END', b'LIFECYCLE_FAIL', b'READBACK_BEGIN', b'READBACK_END', b'READBACK_FAIL', b'CLEANUP_BEGIN', b'CLEANUP_END', b'CLEANUP_FAIL')
_PHASE_ROOT_TYPE=type(Path('/held'))

def _phase(label,root=None):
 # Finite diagnostic DATA only; never a commit, result or cleanup assertion.
 if __name__!='_gnu_broker_original_snapshot' or label not in _PHASE_LABELS or(root is not None and(type(root)is not _PHASE_ROOT_TYPE or root.parts!=('/','held'))):return
 try:_phase_os.write(2,b'GNU_PHASE_DATA '+label+b'\n')
 except OSError:pass

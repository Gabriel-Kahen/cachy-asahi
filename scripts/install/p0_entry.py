# SPDX-License-Identifier: MIT
"""Root-only P0 entry. Existing live Session authority is mandatory, never minted.

Root loads/registers this body and the selected bridge through its admitted
Sources graph before entering the actual original native consumer stage.
"""
import hashlib
import math
import sys
import time
import types

OWN='scripts/install/p0_entry.py'
BRIDGE='scripts/install/native_preflight.py'
BRIDGE_NAME='native_install_preflight'
STAGE='installer-P0'
SOURCE_ROWS = {'scripts/install/native_preflight.py': {'bytes': 22585, 'mode': 420, 'sha256': '2df9bcd5e2f04160a2e8b8e498eba8293ed07cd74f8f3db4154b1171174fc8e0'}, 'scripts/install/local_transaction.py': {'bytes': 82312, 'mode': 420, 'sha256': '966aedf602511bedfc8ee8e12c29f21a7ff6b79523e4c5800b2a22a2af826eca'}, 'scripts/install/test_local_transaction.py': {'bytes': 114659, 'mode': 420, 'sha256': 'ea5299f12b4d325035ebca1476feb2832e0d8e95980a456910ac302e845aefdb'}, 'scripts/install/native_arm_trial.py': {'bytes': 74929, 'mode': 420, 'sha256': 'fe2becb4fe6c22e50903ab390db5a79aae311b7284fc71bf4b1c4b79e99824c4'}, 'scripts/install/test_native_arm_trial.py': {'bytes': 18875, 'mode': 420, 'sha256': 'e7d9564548819d340852923d704abd6c234f3f61d9aaad2624be34c974ccbc55'}, 'scripts/port/kernel-native-job/runtime.py': {'bytes': 11345, 'mode': 420, 'sha256': '8a7cd5e73cf383b2d81ad577b8513c6fd7d49f9fd2572961c73ae9d289cab821'}, 'scripts/ci/development/repository_handoff.py': {'bytes': 140258, 'mode': 420, 'sha256': '6cb320fb92eeaf78451855206bb8ec86fe4c71fff7d08b7351b4ce0ce4e83353'}, 'scripts/ci/development/controller.py': {'bytes': 99358, 'mode': 420, 'sha256': 'c3dffddf28c5fee3dd5d11d2de7fa14a78c17a61d0345864ae511b86bbcdeab5'}}


def need(value,code):
    if not value:raise ValueError(code)


def verified_bridge(raw):
    row=SOURCE_ROWS[BRIDGE]
    need(type(raw) is bytes and len(raw)==row['bytes'] and
         hashlib.sha256(raw).hexdigest()==row['sha256'],'P0_BRIDGE_BODY')
    module=sys.modules.get(BRIDGE_NAME)
    need(type(module) is types.ModuleType and type(module.__file__) is str,'P0_BRIDGE_REGISTRY')
    # Exact pinned existing Source contains only definitions/standard imports.
    expected=types.ModuleType(module.__name__);expected.__file__=module.__file__
    exec(compile(raw,module.__file__,'exec',dont_inherit=True),expected.__dict__)
    expected.namespace(module,raw,row['sha256'])
    return module


def authenticate(bridge,session,controller,end):
    bridge.live(session,controller,end)
    sources=session.sources
    own=sys.modules.get(__name__)
    need(type(own) is types.ModuleType and own.__dict__ is globals(),'P0_ENTRY_REGISTRY')
    need(OWN in sources.raw and OWN in sources.grant['source_files'],'P0_ENTRY_REGISTRATION')
    methods=vars(type(sources))
    methods['graph_namespace'](sources,own,OWN,{OWN:own},{},{})
    bridge.namespace(own,sources.raw[OWN],sources.grant['source_files'][OWN]['sha256'])
    for name,wanted in SOURCE_ROWS.items():
        need(name in sources.raw and name in sources.grant['source_files'],'P0_SOURCE_REGISTRATION')
        body=sources.raw[name];selected=sources.grant['source_files'][name]
        need(type(body) is bytes and len(body)==wanted['bytes'] and
             hashlib.sha256(body).hexdigest()==wanted['sha256'] and
             selected=={'sha256':wanted['sha256'],'mode':wanted['mode']},'P0_SOURCE_BODY')
    return sources


def projection(value):
    keys={'status','stage','receiver','cleanup','elapsed_seconds','ABI','native_matrix',
          'hardware_validation','selected_for_release','public'}
    need(type(value) is dict and set(value)==keys and value['status']=='PASS' and
         value['stage']=='native-install-preflight' and value['ABI']==value['native_matrix']==
         value['hardware_validation']=='NOT RUN' and value['selected_for_release'] is False and
         type(value['public']) is list and not value['public'],'P0_ONLY_RESULT')
    need(type(value['elapsed_seconds']) in (int,float) and math.isfinite(value['elapsed_seconds']) and
         value['elapsed_seconds']>=0 and type(value['cleanup']) is dict and
         value['cleanup']=={'remove_exit':0,'absent':True} and
         type(value['cleanup']['remove_exit']) is int and type(value['cleanup']['absent']) is bool,'P0_CLEANUP')
    row=value['receiver']
    expected=dict(schema_version=1,status='PASS_NATIVE_PREFLIGHT_ONLY',phase='complete',barrier='PASS',
        ABI='NOT_RUN',matrix='NOT_RUN',tests=1,failures=0,errors=0,skips=0,
        termination=False,owned_child_cleanup='PASS',first_failure='NONE')
    need(type(row) is dict and row==expected and set(row)==set(expected) and
         all(type(row[k]) is int for k in ('schema_version','tests','failures','errors','skips')) and
         type(row['termination']) is bool,'P0_COMPLETE_PHASE')
    return dict(schema_version=1,status='PASS_P0_ONLY',stage=STAGE,receiver=dict(row),
        cleanup=dict(value['cleanup']),ABI='NOT_RUN',matrix='NOT_RUN',hardware_validation='NOT_RUN')


def run(session,controller,output,*,token,stage,entry,deadline,nonce,runtime_contract,preflight_raw):
    # token is the existing actual SDK Session; no new object()/Boolean admission.
    need(stage==STAGE and type(stage) is str and token is session,'P0_STAGE_TOKEN')
    need(type(entry) in (int,float) and type(deadline) in (int,float) and
         math.isfinite(entry) and math.isfinite(deadline) and entry<deadline,'P0_ORIGINAL_FRAME')
    end=min(deadline,entry+60)
    now=time.monotonic();need(entry<=now<end,'P0_ORIGINAL_FRAME')
    bridge=verified_bridge(preflight_raw)
    authenticate(bridge,session,controller,end)
    # Existing run retains end-10 launch, end-5 removal and end final checks.
    value=bridge.run(session,controller,output,deadline=end,nonce=nonce,runtime_contract=runtime_contract)
    bridge.tick(end);authenticate(bridge,session,controller,end)
    return projection(value)

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
SOURCE_ROWS = {'scripts/install/native_preflight.py': {'bytes': 28342, 'mode': 420, 'sha256': 'db104c0298f3295c18ad53ee0fedbde32759e5db08e41d3e68d76ebea6339603'}, 'scripts/install/local_transaction.py': {'bytes': 82312, 'mode': 420, 'sha256': '966aedf602511bedfc8ee8e12c29f21a7ff6b79523e4c5800b2a22a2af826eca'}, 'scripts/install/test_local_transaction.py': {'bytes': 114659, 'mode': 420, 'sha256': 'ea5299f12b4d325035ebca1476feb2832e0d8e95980a456910ac302e845aefdb'}, 'scripts/install/native_arm_trial.py': {'bytes': 93054, 'mode': 420, 'sha256': '90aaedaad6ea79c1c9a172d12c7e8383c4375aa8f75ec81558dbcad26077a77d'}, 'scripts/install/test_native_arm_trial.py': {'bytes': 30725, 'mode': 420, 'sha256': '47b0ef4f06186c7539762418091f9f9d6143c5f7510def36ee6db1edf4d6f581'}, 'scripts/port/kernel-native-job/runtime.py': {'bytes': 11345, 'mode': 420, 'sha256': '8a7cd5e73cf383b2d81ad577b8513c6fd7d49f9fd2572961c73ae9d289cab821'}, 'scripts/ci/development/repository_handoff.py': {'bytes': 147775, 'mode': 420, 'sha256': 'fea5348a93631157fa394ee12b9666ec54e2b667f5fc8f535a9aba9d634162db'}, 'scripts/ci/development/controller.py': {'bytes': 99521, 'mode': 420, 'sha256': '38782fdd8ce227c7f60866a6eb602cd98671d11e19f91358894328c70110f2d1'}}


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


P0_CURRENT_CONTRACT = {'schema_version': 1, 'product': 'installer-P0-vim-9.2.1178-1-input-successor-v1', 'lineage': 'CURRENT_PRODUCT_SUCCESSOR_NOT_HISTORICAL_EVIDENCE', 'historical_inputs_sha256': '3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650', 'historical_packages_sha256': '89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f', 'inputs_sha256': 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f', 'packages_sha256': 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25', 'inputs_bytes': 328101, 'packages_bytes': 6674, 'acquisitions': 501, 'packages': 341, 'recipe_source_commit': 'ebd5812640b0b69f5c09a47752b739e37e338754', 'source_epoch': 1791748800}
TOOL_PROFILE_LINEAGE = 'HISTORICAL_REQUIRED_TOOL_WHITELIST_NOT_CURRENT_AUDIT'


def validate_input_successor(value):
    need(type(value) is dict and len(value) == 13 and all(type(key) is str for key in value) and
            set(value) == set(P0_CURRENT_CONTRACT) and
            all(type(value[key]) is type(wanted) and value[key] == wanted
                for key, wanted in P0_CURRENT_CONTRACT.items()), 'INPUT_SUCCESSOR')
    return dict(value)


def projection(value, *, input_successor=None):
    keys={'status','stage','receiver','cleanup','elapsed_seconds','ABI','native_matrix',
          'hardware_validation','selected_for_release','public'}
    if input_successor is not None:
        input_successor = validate_input_successor(input_successor)
        keys |= {'input_successor', 'tool_profile_lineage'}
        need(type(value) is dict, 'P0_INPUT_SUCCESSOR')
        validate_input_successor(value.get('input_successor'))
        need(value.get('input_successor') == input_successor and
             type(value.get('tool_profile_lineage')) is str and
             value.get('tool_profile_lineage') == TOOL_PROFILE_LINEAGE, 'P0_INPUT_SUCCESSOR')
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
    if input_successor is not None:
        expected.update(input_successor=input_successor, tool_profile_lineage=TOOL_PROFILE_LINEAGE)
        need(type(row) is dict, 'P0_INPUT_SUCCESSOR')
        validate_input_successor(row.get('input_successor'))
        need(type(row.get('tool_profile_lineage')) is str, 'P0_INPUT_SUCCESSOR')
    need(type(row) is dict and row==expected and set(row)==set(expected) and
         all(type(row[k]) is int for k in ('schema_version','tests','failures','errors','skips')) and
         type(row['termination']) is bool,'P0_COMPLETE_PHASE')
    result = dict(schema_version=1,status='PASS_P0_ONLY',stage=STAGE,receiver=dict(row),
        cleanup=dict(value['cleanup']),ABI='NOT_RUN',matrix='NOT_RUN',hardware_validation='NOT_RUN')
    if input_successor is not None:
        result.update(input_successor=input_successor)
    return result


def run(session,controller,output,*,token,stage,entry,deadline,nonce,runtime_contract,preflight_raw):
    # token is the existing actual SDK Session; no new object()/Boolean admission.
    need(stage==STAGE and type(stage) is str and token is session,'P0_STAGE_TOKEN')
    need(type(entry) in (int,float) and type(deadline) in (int,float) and
         math.isfinite(entry) and math.isfinite(deadline) and entry<deadline,'P0_ORIGINAL_FRAME')
    end=min(deadline,entry+60)
    now=time.monotonic();need(entry<=now<end,'P0_ORIGINAL_FRAME')
    bridge=verified_bridge(preflight_raw)
    authenticate(bridge,session,controller,end)
    context = bridge.live(session,controller,end)
    selected = validate_input_successor(context.get('input_successor'))
    # Existing run retains end-10 launch, end-5 removal and end final checks.
    value=bridge.run(session,controller,output,deadline=end,nonce=nonce,runtime_contract=runtime_contract)
    bridge.tick(end);authenticate(bridge,session,controller,end)
    return projection(value,input_successor=selected)

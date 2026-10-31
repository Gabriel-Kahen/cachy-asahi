# SPDX-License-Identifier: MIT
"""Dedicated Root-selected preparation and installer P0; no recipes or matrix.

The authenticated workflow captures entry before reading this Source. Its
explicit private input pins select a fresh runtime, rather than a compile grant.
The base image is borrowed from a separately admitted same-job Root producer.
"""
import hashlib
import base64
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import stat
import sys
import time
import types
import zlib
import urllib.request
import urllib.parse

OWN='scripts/ci/development/p0_ci.py'
WORKFLOW='.github/workflows/native-arm-p0.yml'
COMPOSITION='installer-preflight'
SOURCE_INPUTS_SHA='3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650'
INPUTS_SHA='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
PACKAGES_SHA='fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
INPUT_SUCCESSOR={'schema_version':1,'product':'installer-P0-vim-9.2.1178-1-input-successor-v1',
    'lineage':'CURRENT_PRODUCT_SUCCESSOR_NOT_HISTORICAL_EVIDENCE','historical_inputs_sha256':SOURCE_INPUTS_SHA,
    'historical_packages_sha256':'89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f',
    'inputs_sha256':INPUTS_SHA,'packages_sha256':PACKAGES_SHA,'inputs_bytes':328101,'packages_bytes':6674,
    'acquisitions':501,'packages':341,'recipe_source_commit':'ebd5812640b0b69f5c09a47752b739e37e338754',
    'source_epoch':1791748800}
# Exact public records from fb3c3b7d115e8a40d104a7cad4ebad5412dcdd47,
# scripts/ci/maintained-native/locks/inputs-successor.lock.json (beca39e0...).
CURRENT_VIM_ROWS=(
    {'arch':'aarch64','conflicts':['gvim','vim-minimal'],
     'depends':['vim-runtime=9.2.1178-1','gpm','acl','glibc','libgcrypt','zlib'],
     'filename':'vim-9.2.1178-1-aarch64.pkg.tar.xz','license':['custom:vim'],'name':'vim',
     'provides':['xxd','vim-minimal','vim-plugin-runtime'],'replaces':['vim-minimal'],
     'sha256':'e6dac872c70975d71550af934402f4e603bb0ebe444310440bc89f4e8c8e76c4',
     'signature_sha256':'28d7e145d8f47626e574fc7412cd45d866392a8557adda3002362ff42bb993aa',
     'signature_size':566,'size':2084600,'source_url':['https://www.vim.org'],
     'url':'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/vim-9.2.1178-1-aarch64.pkg.tar.xz',
     'version':'9.2.1178-1'},
    {'arch':'aarch64','conflicts':[],'depends':[],
     'filename':'vim-runtime-9.2.1178-1-aarch64.pkg.tar.xz','license':['custom:vim'],'name':'vim-runtime',
     'provides':[],'replaces':[],
     'sha256':'340ee0b85995517e50832aea2e69224044ff77b384fc5c8e017959bcdcfc78f8',
     'signature_sha256':'466eca3dc6734a3d10ea8f90f1a5d9ca15e339290995557d3120f03690399bf4',
     'signature_size':566,'size':7703748,'source_url':['https://www.vim.org'],
     'url':'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/vim-runtime-9.2.1178-1-aarch64.pkg.tar.xz',
     'version':'9.2.1178-1'})
OVERRIDE_ROWS={
    'jbigkit-2.1-8-aarch64.pkg.tar.xz':(48816,'ecaddb099f4a1f1bcbc1497fd0f3dc98581552b9eacaa17c5568211c38bec1db'),
    'jbigkit-2.1-8-aarch64.pkg.tar.xz.sig':(566,'f00be593f9ab5855f9e450d054e6cacd319ec834ef7fc97c51bcf3be3ebfdb1f'),
    'libtiff-4.7.2-1-aarch64.pkg.tar.xz':(354480,'02a5d2d74019b39befd6cf63d9bde95a2d16f91b4d0d56939498375e0e491ffd'),
    'libtiff-4.7.2-1-aarch64.pkg.tar.xz.sig':(566,'8dae1efda531e3ac7db09512cfe0c619eaae6787cc16fdea1315588b4fc340fa'),
    'bubblewrap-0.13.0-1-aarch64.pkg.tar.xz':(40428,'4866e25c5a7c33c3ded9f221058b5f4136cdbd991f3dc77a2f7a740368c95a61'),
    'bubblewrap-0.13.0-1-aarch64.pkg.tar.xz.sig':(566,'dc7ad4f478d7b196b5189e670e2d80f3e68ad28aa869b0bee697d2c5309064fa')}
INPUT_NAMES=('plan.json','packet.json','grant.json','runtime.json','prepared-image.json','packages.lock',
             'current-inputs.lock.json','source-publication.json')
MODULES=(('packet','scripts/ci/development/packet.py'),('common','scripts/ci/development/common.py'),
         ('development_p0_controller','scripts/ci/development/controller.py'),
         ('development_repository_handoff','scripts/ci/development/repository_handoff.py'))
PROJECT_BOOTSTRAP_ROWS = {'scripts/ci/development/packet.py': {'bytes': 35461, 'mode': 420, 'sha256': '317635f02db5c9022633f336540558ef137d584e6dfb523072a831bcc0a50f0e'}, 'scripts/ci/development/common.py': {'bytes': 16893, 'mode': 420, 'sha256': 'a9fd67f8ca192a5d27f95377fae3804a2ae69f6675440b1104c4411a35dc8a12'}, 'scripts/ci/development/controller.py': {'bytes': 99521, 'mode': 420, 'sha256': '38782fdd8ce227c7f60866a6eb602cd98671d11e19f91358894328c70110f2d1'}, 'scripts/ci/development/repository_handoff.py': {'bytes': 147775, 'mode': 420, 'sha256': 'fea5348a93631157fa394ee12b9666ec54e2b667f5fc8f535a9aba9d634162db'}}


def need(value,code):
    if not value:raise ValueError(code)


SDK_GRANT_GUARDS = frozenset(['decode-duplicate', 'decode-number', 'decode-bytes', 'decode-object', 'grant-pin', 'grant-schema', 'contract-pin', 'job-identifier', 'original-view', 'policy-source-pin', 'policy-fields'])


def attach_sdk_preflight(error, boundary):
    """Closed boundary/guard facts only; foreign metadata grants no authority."""
    try:
        if type(boundary) is not str or boundary not in ('preparation-sdk-preflight', 'P0-sdk-preflight'):
            return
        state = BaseException.__dict__['__dict__'].__get__(error)
        if type(state) is not dict or not all(type(key) is str for key in state) or 'nativeci_diagnostic' in state:
            return
        guard = state.get('nativeci_grant_guard')
        operation = guard if type(guard) is str and guard in SDK_GRANT_GUARDS else 'preflight'
        kind = 'UNKNOWN'
        for exact, label in ((ValueError, 'ValueError'), (TypeError, 'TypeError'), (RuntimeError, 'RuntimeError'),
            (OSError, 'OSError'), (FileNotFoundError, 'OSError'), (PermissionError, 'OSError'),
            (IsADirectoryError, 'OSError'), (NotADirectoryError, 'OSError'), (BlockingIOError, 'OSError'),
            (ChildProcessError, 'OSError'), (ProcessLookupError, 'OSError'), (TimeoutError, 'OSError'),
            (ConnectionError, 'OSError'), (BrokenPipeError, 'OSError'), (ConnectionAbortedError, 'OSError'),
            (ConnectionRefusedError, 'OSError'), (ConnectionResetError, 'OSError'),
            (FileExistsError, 'OSError'), (InterruptedError, 'OSError'),
            (KeyboardInterrupt, 'KeyboardInterrupt'), (SystemExit, 'SystemExit')):
            if type(error) is exact:
                kind = label
                break
        args = BaseException.__dict__['args'].__get__(error)
        code = 'grant-refused' if type(args) is tuple and len(args) == 1 and type(args[0]) is str and args[0] == 'grant-refused' else 'UNKNOWN'
        state['nativeci_diagnostic'] = {'schema_version': 1, 'stage': boundary, 'operation': operation,
                                      'exception_type': kind, 'refusal_code': code}
    except BaseException as secondary:
        if type(secondary) is KeyboardInterrupt:
            try:
                state = BaseException.__dict__['__dict__'].__get__(error)
                if type(state) is dict and all(type(key) is str for key in state):
                    state['native_preflight_cancelled'] = True
                    state['native_preflight_cleanup_uncertain'] = True
            except BaseException:
                pass


PIPELINE_FAILURE_OPERATIONS = frozenset(['load-preparation', 'verify-preparation-packet', 'load-preparation-sources', 'initialize-preparation', 'prepare-image', 'finish-preparation', 'materialize-P0', 'run-P0', 'pipeline-cleanup', 'download-input', 'download-http-error', 'download-url-error', 'download-timeout', 'supervise-child', 'supervise-child-timeout', 'check-child-outcome'])



CALLBACK_OPERATIONS = ('callback', 'class_state', 'source_graph', 'graph_namespace',
                       'graph_identity', 'global_function', 'graph_function', 'namespace_source', 'locate')
PIPELINE_FAILURE_OPERATIONS |= frozenset('run-P0-sdk-' + name for name in CALLBACK_OPERATIONS)


def callback_code_boundaries(module):
    """Bind identities immediately after the already-pinned SDK body is loaded."""
    result = []
    for name in CALLBACK_OPERATIONS:
        pending = [vars(module.Sources)[name].__code__]
        while pending:
            code = pending.pop()
            result.append((code, 'run-P0-sdk-' + name))
            pending.extend(value for value in code.co_consts if type(value) is types.CodeType)
    return tuple(result)


P0_VALUE_OPERATIONS = ('controller-installer', 'controller-consumer', 'original-main',
    'original-controller', 'preflight-namespace', 'preflight-live', 'preflight-run',
    'entry-authenticate', 'entry-run', 'entry-projection')
PIPELINE_FAILURE_OPERATIONS |= frozenset('run-P0-' + name for name in P0_VALUE_OPERATIONS)


P0_PREFLIGHT_FUNCTIONS = ('run', 'image_handoff', 'container_binding', 'selection', 'accept')
P0_PREFLIGHT_CALL_LINES = (191, 193, 194, 195, 196, 198, 199, 200, 201, 203, 207, 208, 209, 210, 211, 212, 213, 214, 217, 222, 223, 224, 225, 226, 229, 231, 232, 233, 234, 235, 236, 237, 238, 239, 251, 252, 253, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 286, 287, 288, 290, 291, 292, 294, 295, 297, 298, 304, 305, 306, 307, 309, 310, 311, 312, 313, 314, 315, 316, 318, 319, 321, 322, 323, 326, 328, 329, 331, 333, 334, 335, 336, 337, 339, 342, 343, 344, 345, 346, 347, 348, 349, 350, 351, 353, 354, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 367, 369, 370, 371, 373, 376, 381, 382, 385, 388, 390, 394, 395, 396, 398, 399, 402, 404, 405)
PIPELINE_FAILURE_OPERATIONS |= frozenset('run-P0-preflight-' + name for name in P0_PREFLIGHT_FUNCTIONS)
PIPELINE_FAILURE_OPERATIONS |= frozenset('run-P0-preflight-L' + str(line) for line in P0_PREFLIGHT_CALL_LINES)


def p0_value_code_boundaries(controller, sdk, session):
    """Only fixed members of the already-loaded Source/Session module anchors."""
    result = []
    def add(operation, *functions):
        for function in functions:
            if type(function) is not types.FunctionType: continue
            pending = [function.__code__]
            while pending:
                code = pending.pop(); result.append((code, 'run-P0-' + operation))
                pending.extend(value for value in code.co_consts if type(value) is types.CodeType)
    add('controller-installer', controller.Development.installer_module)
    add('controller-consumer', controller.Development.consume_p0)
    if type(session) is not sdk.Session: return tuple(result)
    state = object.__getattribute__(session, '__dict__')
    graph = state.get('source_graph')
    if type(graph) is not dict: return tuple(result)
    bridge = graph.get('native_preflight')
    if type(bridge) is types.ModuleType:
        body = vars(bridge)
        add('preflight-namespace', body.get('namespace'))
        add('preflight-live', body.get('live'))
        for name in P0_PREFLIGHT_FUNCTIONS: add('preflight-' + name, body.get(name))
    entry = state.get('p0_entry_module')
    if type(entry) is types.ModuleType:
        body = vars(entry)
        add('entry-authenticate', body.get('authenticate'), body.get('verified_bridge'))
        add('entry-run', body.get('run'))
        add('entry-projection', body.get('projection'))
    original = graph.get('original')
    if type(original) is dict:
        native = original.get('native_arm'); integration = original.get('integration')
        if type(native) is types.ModuleType: add('original-main', vars(native).get('main'))
        if type(integration) is types.ModuleType:
            body = vars(integration); owner = body.get('Controller')
            if type(owner) is type: add('original-controller', vars(owner).get('__init__'))
            add('original-controller', body.get('snapshot'), body.get('scan'), body.get('require_source_snapshot'))
    return tuple(result)


def mark_callback_failure(error, refusal_type, boundaries, *, value_error=False):
    """Optional fixed boundary facts; never publish operands or replace failure."""
    try:
        args = BaseException.__dict__['args'].__get__(error)
        if not ((value_error is True and type(error) is ValueError) or
                (value_error is False and type(error) is refusal_type and type(args) is tuple and len(args) == 1 and
                 type(args[0]) is str and args[0] == 'callback-refused')):
            return
        trace = BaseException.__dict__['__traceback__'].__get__(error)
        operation = None
        for _ in range(64):
            if trace is None: break
            for code, selected in boundaries:
                if trace.tb_frame.f_code is code:
                    operation = selected
                    if (value_error is True and selected in
                            tuple('run-P0-preflight-' + name for name in P0_PREFLIGHT_FUNCTIONS) and
                            trace.tb_lineno in P0_PREFLIGHT_CALL_LINES):
                        operation = 'run-P0-preflight-L' + str(trace.tb_lineno)
            trace = trace.tb_next
        if operation is not None: mark_pipeline_failure(error, operation)
    except BaseException as secondary:
        if type(secondary) is KeyboardInterrupt:
            try:
                state = BaseException.__dict__['__dict__'].__get__(error)
                if type(state) is dict and all(type(key) is str for key in state):
                    state['native_preflight_cancelled'] = True
                    state['native_preflight_cleanup_uncertain'] = True
            except BaseException:
                pass


def mark_pipeline_failure(error, operation):
    """First closed operation only; no arguments, paths, rows or child output."""
    try:
        if type(operation) is not str or operation not in PIPELINE_FAILURE_OPERATIONS:
            return
        if operation == 'supervise-child' and type(error) is subprocess.TimeoutExpired:
            operation = 'supervise-child-timeout'
        elif operation == 'download-input':
            if type(error) is urllib.error.HTTPError:operation = 'download-http-error'
            elif type(error) is urllib.error.URLError:operation = 'download-url-error'
            elif type(error) is TimeoutError:operation = 'download-timeout'
        state = BaseException.__dict__['__dict__'].__get__(error)
        if type(state) is dict and all(type(key) is str for key in state) and 'nativeci_pipeline_operation' not in state:
            state['nativeci_pipeline_operation'] = operation
    except BaseException as secondary:
        if type(secondary) is KeyboardInterrupt:
            try:
                state = BaseException.__dict__['__dict__'].__get__(error)
                if type(state) is dict and all(type(key) is str for key in state):
                    state['native_preflight_cancelled'] = True
                    state['native_preflight_cleanup_uncertain'] = True
            except BaseException:
                pass

DOWNLOAD_PREFIX='download-current-vim-v1-input-'
DOWNLOAD_OPERATIONS=frozenset(DOWNLOAD_PREFIX+str(i).zfill(3) for i in range(501))
DOWNLOAD_TYPES= {'DL_HTTP_301': 'UNKNOWN', 'DL_HTTP_302': 'UNKNOWN', 'DL_HTTP_303': 'UNKNOWN', 'DL_HTTP_307': 'UNKNOWN', 'DL_HTTP_308': 'UNKNOWN', 'DL_HTTP_400': 'UNKNOWN', 'DL_HTTP_401': 'UNKNOWN', 'DL_HTTP_403': 'UNKNOWN', 'DL_HTTP_404': 'UNKNOWN', 'DL_HTTP_405': 'UNKNOWN', 'DL_HTTP_408': 'UNKNOWN', 'DL_HTTP_410': 'UNKNOWN', 'DL_HTTP_416': 'UNKNOWN', 'DL_HTTP_429': 'UNKNOWN', 'DL_HTTP_451': 'UNKNOWN', 'DL_HTTP_500': 'UNKNOWN', 'DL_HTTP_501': 'UNKNOWN', 'DL_HTTP_502': 'UNKNOWN', 'DL_HTTP_503': 'UNKNOWN', 'DL_HTTP_504': 'UNKNOWN', 'DL_HTTP_507': 'UNKNOWN', 'DL_HTTP_508': 'UNKNOWN', 'DL_HTTP_511': 'UNKNOWN', 'DL_HTTP_OTHER': 'UNKNOWN', 'DL_HTTP_UNKNOWN': 'UNKNOWN', 'DL_KBI_AFTER_PREP_ALRM': 'KeyboardInterrupt', 'DL_KBI_AFTER_UNATTRIBUTED': 'KeyboardInterrupt', 'DL_KBI_BEFORE_PREP_ALRM': 'KeyboardInterrupt', 'DL_KBI_BEFORE_UNATTRIBUTED': 'KeyboardInterrupt', 'DL_KBI_UNKNOWN_PREP_ALRM': 'KeyboardInterrupt', 'DL_KBI_UNKNOWN_UNATTRIBUTED': 'KeyboardInterrupt', 'DL_OSERROR': 'OSError', 'DL_OTHER': 'UNKNOWN', 'DL_RUNTIMEERROR': 'RuntimeError', 'DL_SYSTEMEXIT': 'SystemExit', 'DL_TIMEOUTERROR': 'OSError', 'DL_TYPEERROR': 'TypeError', 'DL_URLERROR': 'UNKNOWN', 'DL_VALUEERROR': 'ValueError', 'prep-download-cap': 'ValueError', 'prep-download-close-custody': 'ValueError', 'prep-download-domain': 'ValueError', 'prep-download-downgrade': 'ValueError', 'prep-download-fd': 'ValueError', 'prep-download-file': 'ValueError', 'prep-download-input': 'ValueError', 'prep-download-pin': 'ValueError', 'prep-download-progress': 'ValueError', 'prep-download-redirect': 'ValueError', 'prep-download-response-custody': 'ValueError', 'prep-download-target': 'ValueError', 'prep-fixed-four-no-HTTPS-fallback': 'ValueError', 'DL_GUARD_DEADLINE_BEFORE_OPEN': 'UNKNOWN', 'DL_GUARD_DEADLINE_BEFORE_CONNECT': 'UNKNOWN', 'DL_GUARD_DEADLINE_BEFORE_READ': 'UNKNOWN', 'DL_GUARD_DEADLINE_BEFORE_WRITE': 'UNKNOWN', 'DL_GUARD_DEADLINE_BEFORE_PUBLISH': 'UNKNOWN', 'DL_GUARD_DEADLINE_AFTER_PUBLISH': 'UNKNOWN'}
DOWNLOAD_CODES=frozenset(('DL_HTTP_301', 'DL_HTTP_302', 'DL_HTTP_303', 'DL_HTTP_307', 'DL_HTTP_308', 'DL_HTTP_400', 'DL_HTTP_401', 'DL_HTTP_403', 'DL_HTTP_404', 'DL_HTTP_405', 'DL_HTTP_408', 'DL_HTTP_410', 'DL_HTTP_416', 'DL_HTTP_429', 'DL_HTTP_451', 'DL_HTTP_500', 'DL_HTTP_501', 'DL_HTTP_502', 'DL_HTTP_503', 'DL_HTTP_504', 'DL_HTTP_507', 'DL_HTTP_508', 'DL_HTTP_511', 'DL_HTTP_OTHER', 'DL_HTTP_UNKNOWN', 'DL_KBI_AFTER_PREP_ALRM', 'DL_KBI_AFTER_UNATTRIBUTED', 'DL_KBI_BEFORE_PREP_ALRM', 'DL_KBI_BEFORE_UNATTRIBUTED', 'DL_KBI_UNKNOWN_PREP_ALRM', 'DL_KBI_UNKNOWN_UNATTRIBUTED', 'DL_OSERROR', 'DL_OTHER', 'DL_RUNTIMEERROR', 'DL_SYSTEMEXIT', 'DL_TIMEOUTERROR', 'DL_TYPEERROR', 'DL_URLERROR', 'DL_VALUEERROR')) | frozenset(('DL_GUARD_DEADLINE_BEFORE_OPEN', 'DL_GUARD_DEADLINE_BEFORE_CONNECT', 'DL_GUARD_DEADLINE_BEFORE_READ', 'DL_GUARD_DEADLINE_BEFORE_WRITE', 'DL_GUARD_DEADLINE_BEFORE_PUBLISH', 'DL_GUARD_DEADLINE_AFTER_PUBLISH'))
DOWNLOAD_GUARD_CODES=frozenset(('prep-download-cap', 'prep-download-close-custody', 'prep-download-domain', 'prep-download-downgrade', 'prep-download-fd', 'prep-download-file', 'prep-download-input', 'prep-download-pin', 'prep-download-progress', 'prep-download-redirect', 'prep-download-response-custody', 'prep-download-target', 'prep-fixed-four-no-HTTPS-fallback'))
DOWNLOAD_GUARD_DEADLINES={'before-open': 'DL_GUARD_DEADLINE_BEFORE_OPEN', 'before-connect': 'DL_GUARD_DEADLINE_BEFORE_CONNECT', 'before-read': 'DL_GUARD_DEADLINE_BEFORE_READ', 'before-write': 'DL_GUARD_DEADLINE_BEFORE_WRITE', 'before-publish': 'DL_GUARD_DEADLINE_BEFORE_PUBLISH', 'after-publish': 'DL_GUARD_DEADLINE_AFTER_PUBLISH'}
_DOWNLOAD_LATCH=None


def download_fault(primary, secondary):
    try:
        lineage=type.__dict__['__mro__'].__get__(type(secondary))
        if any(base is KeyboardInterrupt for base in lineage):
            state=BaseException.__dict__['__dict__'].__get__(primary)
            if type(state) is dict and all(type(key) is str for key in state):
                state['native_preflight_cancelled']=True
                state['native_preflight_cleanup_uncertain']=True
    except BaseException:pass


def download_clock(sample,end):
    if type(sample) not in (int,float) or type(end) not in (int,float):return 'UNKNOWN'
    try:
        if not math.isfinite(sample) or not math.isfinite(end):return 'UNKNOWN'
    except OverflowError:return 'UNKNOWN'
    return 'BEFORE' if sample<end else 'AFTER'


def download_item(item):
    if type(item) is not dict or any(type(key) is not str for key in item):return None
    if not all(key in item for key in ('filename','size','sha256','url')):return None
    if any(type(item[key]) is not str for key in ('filename','sha256','url')) or type(item['size']) is not int:return None
    return tuple(item[key] for key in ('filename','size','sha256','url'))


def download_diagnostic(error):
    """Consume only this actual driver's final same-primary diagnostic latch."""
    global _DOWNLOAD_LATCH
    row=_DOWNLOAD_LATCH
    if type(row) is not tuple or len(row)!=3 or error is not row[0]:return None
    operation,code=row[1:]
    if type(operation) is not str or operation not in DOWNLOAD_OPERATIONS or type(code) is not str or code not in DOWNLOAD_TYPES:return None
    result={'schema_version':1,'stage':'pipeline','operation':operation,
            'exception_type':DOWNLOAD_TYPES[code],'refusal_code':code}
    _DOWNLOAD_LATCH=None
    return result


def latch_download(owner,error):
    global _DOWNLOAD_LATCH
    try:
        if type(owner) is not Preparation:return
        context=owner.download_failure
        if type(context) is not tuple or len(context)!=3 or error is not context[0]:return
        ordinal,frozen=context[1:]
        if type(ordinal) is not int or not 0<=ordinal<501 or type(owner.download_rows) is not tuple or len(owner.download_rows)!=501:return
        if owner.download_item is not owner.download_rows[ordinal] or type(frozen) is not tuple or len(frozen)!=2:return
        if type(owner.download_binding) is not tuple or len(owner.download_binding)!=2 or owner.download_rows is not owner.download_binding[0] or owner.download_pins is not owner.download_binding[1]:return
        if type(owner.download_pins) is not tuple or len(owner.download_pins)!=501 or download_item(owner.download_item)!=owner.download_pins[ordinal]:return
        operation,code=frozen
        if type(operation) is not str or operation!=DOWNLOAD_PREFIX+str(ordinal).zfill(3) or type(code) is not str or code not in DOWNLOAD_TYPES:return
        state=BaseException.__dict__['__dict__'].__get__(error)
        if type(state) is not dict or any(type(key) is not str for key in state):return
        marker=state.get('nativeci_pipeline_operation')
        if type(marker) is not str or marker not in ('download-input','download-http-error','download-url-error','download-timeout'):return
        _DOWNLOAD_LATCH=(error,operation,code)
    except BaseException as secondary:download_fault(error,secondary)


def finite(value):
    return type(value) in (int,float) and math.isfinite(value)


def live(end):
    need(finite(end) and time.monotonic()<end,'p0-original-end')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def decode(raw):
    def pairs(values):
        result={}
        for key,value in values:
            need(key not in result,'p0-duplicate-key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'p0-json-number'))


def input_successor(value):
    need(type(value) is dict and len(value)==len(INPUT_SUCCESSOR) and all(type(key) is str for key in value) and set(value)==set(INPUT_SUCCESSOR) and
         all(type(value[key]) is type(wanted) and value[key]==wanted for key,wanted in INPUT_SUCCESSOR.items()),
         'p0-runtime-selection')


def current_inputs(raw):
    """Derive only this fixed Vim successor; Source159 remains historical3c16."""
    need(type(raw) is bytes and len(raw)==328101 and digest(raw)==SOURCE_INPUTS_SHA,'prep-inputs')
    value=decode(raw);changed=[]
    for index,row in enumerate(value['packages']):
        for replacement in CURRENT_VIM_ROWS:
            if row['name']==replacement['name']:
                value['packages'][index]=decode(encoded(replacement));changed.append(row['name'])
    need(changed==['vim','vim-runtime'],'prep-inputs')
    result=encoded(value)
    need(len(result)==328101 and digest(result)==INPUTS_SHA,'prep-inputs')
    return result


def pin(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}',value),'p0-input-pin')
    return value


def identity(value):
    return tuple(getattr(value,name) for name in ('st_dev','st_ino','st_mode','st_uid','st_gid',
                 'st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


def merge(first,error):
    """Keep the same primary, including falsey exceptions, and sticky cleanup facts."""
    target=first if first is not None else error
    BaseException.__setattr__(target,'native_preflight_cleanup_uncertain',True)
    if isinstance(error,KeyboardInterrupt):BaseException.__setattr__(target,'native_preflight_cancelled',True)
    return target


def read(path,end,*,wanted=None,limit=1024**2,private=False):
    """Finite no-follow read; hashes authenticate bytes, Root owns writer exclusion."""
    live(end);path=Path(path)
    need(path.is_absolute() and '..' not in path.parts,'p0-input-path')
    for parent in path.parents:
        need(stat.S_ISDIR(parent.lstat().st_mode),'p0-input-ancestor')
    parent=path.parent.lstat();before=path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=limit and
         (before.st_size>0 or wanted is not None and not private) and
         stat.S_IMODE(before.st_mode) in ((0o600,) if private else (0o644,0o755)), 'p0-input-file')
    if private:
        need(parent.st_uid==before.st_uid==os.geteuid() and stat.S_IMODE(parent.st_mode)==0o700,
             'p0-private-custody')
    fd=None;held=None;first=None;raw=None;opening=False
    try:
        opening=True;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        opened=os.fstat(fd)
        need(identity(opened)==identity(before),'p0-input-replaced');held=identity(opened)
        chunks=[];size=0
        while True:
            live(end);part=os.read(fd,min(65536,limit+1-size))
            if not part:break
            chunks.append(part);size+=len(part);need(size<=limit,'p0-input-cap')
        raw=b''.join(chunks)
        need(len(raw)==before.st_size and identity(os.fstat(fd))==identity(before) and
             identity(path.lstat())==identity(before) and identity(path.parent.lstat())==identity(parent),
             'p0-input-drift')
        if wanted is not None:
            need(type(wanted) is dict and set(wanted)=={'sha256','mode'} and digest(raw)==pin(wanted['sha256']) and
                 stat.S_IMODE(before.st_mode)==wanted['mode'],'p0-source-row')
        live(end)
    except BaseException as error:
        first=error
        if opening and fd is None:BaseException.__setattr__(first,'native_preflight_cleanup_uncertain',True)
    finally:
        if fd is not None:
            try:
                need(held is not None and identity(os.fstat(fd))==held,'p0-input-close-custody')
                os.close(fd)
            except BaseException as error:first=merge(first,error)
    if first is not None:raise first
    return raw


def contract(plan,prepared,runtime,*,entry,expected_source_commit,environment):
    """Validate Root-supplied data; this function neither creates nor grants actors."""
    need(type(expected_source_commit) is str and re.fullmatch('[0-9a-f]{40}',expected_source_commit), 'p0-source-commit')
    need(type(plan) is dict and set(plan)=={'schema_version','purpose','source_commit','run_id','run_attempt',
         'outer_end','nonce','input_pins','preparation_plan_sha256','preparation_source_rows_sha256','input_successor'} and
         type(plan['schema_version']) is int and plan['schema_version']==1 and
         plan['purpose']=='reviewed-installer-P0-ci-execution','p0-runtime-selection')
    need(plan['source_commit']==expected_source_commit==environment.get('GITHUB_SHA')==environment.get('GITHUB_WORKFLOW_SHA') and
         plan['run_id']==environment.get('GITHUB_RUN_ID') and plan['run_attempt']==environment.get('GITHUB_RUN_ATTEMPT') and
         environment.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi' and
         environment.get('GITHUB_WORKFLOW_REF')=='Gabriel-Kahen/cachy-asahi/.github/workflows/native-arm-p0.yml@refs/heads/codex/signer-native-runtime-v1',
         'p0-job-context')
    need(type(plan['run_id']) is str and re.fullmatch('[1-9][0-9]{0,19}',plan['run_id']) and
         type(plan['run_attempt']) is str and re.fullmatch('[1-9][0-9]{0,9}',plan['run_attempt']) and
         finite(entry) and finite(plan['outer_end']) and entry<plan['outer_end'] and
         type(plan['nonce']) is str and re.fullmatch('[0-9a-f]{32}',plan['nonce']),'p0-frame')
    input_successor(plan['input_successor'])
    need(type(plan['input_pins']) is dict and set(plan['input_pins'])==set(INPUT_NAMES)-{'plan.json'} and
         plan['input_pins']['current-inputs.lock.json']==INPUTS_SHA,'p0-input-set')
    for value in (*plan['input_pins'].values(),plan['preparation_plan_sha256'],plan['preparation_source_rows_sha256']):pin(value)
    need(type(prepared) is dict and set(prepared)=={'schema_version','purpose','source_commit','run_id','run_attempt','image',
         'inputs_sha256','packages_sha256','preparation_plan_sha256','preparation_source_rows_sha256','base_image_owner','input_successor'} and
         type(prepared['schema_version']) is int and prepared['schema_version']==1 and
         prepared['purpose']=='Root-same-job-prepared-P0-image' and
         all(prepared[key]==plan[key] for key in ('source_commit','run_id','run_attempt','preparation_plan_sha256','preparation_source_rows_sha256')) and
         prepared['inputs_sha256']==INPUTS_SHA and prepared['packages_sha256']==PACKAGES_SHA and
         prepared['base_image_owner']=='EXTERNAL_ROOT_BORROWED' and type(prepared['image']) is str and
         re.fullmatch('sha256:[0-9a-f]{64}',prepared['image']), 'p0-prepared-image')
    input_successor(prepared['input_successor'])
    need(type(runtime) is dict and set(runtime)=={'cli_sha256','endpoint_identity','env'} and
         type(runtime['endpoint_identity']) in (tuple,list) and len(runtime['endpoint_identity'])==6 and
         all(type(v) is int and v>=0 for v in runtime['endpoint_identity']) and type(runtime['env']) is dict,
         'p0-runtime-contract');pin(runtime['cli_sha256'])
    return min(plan['outer_end'],entry+60)


def load(raw,root):
    """All269 bodies have been verified before the first project compile/exec."""
    need(set(PROJECT_BOOTSTRAP_ROWS)=={path for _,path in MODULES},'p0-bootstrap-custody')
    for path,row in PROJECT_BOOTSTRAP_ROWS.items():
        need(type(raw.get(path)) is bytes and len(raw[path])==row['bytes'] and digest(raw[path])==row['sha256'],
             'p0-bootstrap-body')
    modules={}
    try:
        for name,path in MODULES:
            need(name not in sys.modules,'p0-module-collision')
            module=types.ModuleType(name);module.__file__=str(root/path)
            sys.modules[name]=module;modules[name]=module
            exec(compile(raw[path],module.__file__,'exec',dont_inherit=True),module.__dict__)
    except BaseException:
        for name,module in modules.items():
            if sys.modules.get(name) is module:del sys.modules[name]
        raise
    return modules


def argv(output,cache,pins):
    view=output/'repository-handoff/original-view';value=['installer-P0']
    for flag,name in (('inputs','inputs.lock.json'),('recipes','recipes.lock.json'),('integration','integration.lock.json')):
        value.extend(('--'+flag,str(view/'scripts/ci'/name),'--'+flag+'-sha256',pins['scripts/ci/'+name]))
    return value+['--cache',str(cache),'--output',str(output/'native'),'--integration-output',str(output/'integration')]


def write_private(path,raw,end):
    """Create once; retain partial files, and retire only proved owned FD identity."""
    fd=None;held=None;first=None;started=False
    try:
        live(end);started=True
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        node=os.fstat(fd)
        need(stat.S_ISREG(node.st_mode) and node.st_uid==os.geteuid() and node.st_nlink==1 and
             stat.S_IMODE(node.st_mode)==0o600 and node.st_size==0,'p0-private-created')
        held=identity(node)[:6];offset=0
        while offset<len(raw):
            live(end);need(identity(os.fstat(fd))[:6]==held,'p0-private-write-custody')
            count=os.write(fd,raw[offset:offset+65536]);need(type(count) is int and 0<count<=min(65536,len(raw)-offset),'p0-private-write-progress')
            offset+=count
        node=os.fstat(fd)
        need(identity(node)[:6]==held and node.st_size==len(raw) and identity(path.lstat())==identity(node),
             'p0-private-final-custody');live(end)
    except BaseException as error:
        first=error
        if started and fd is None:BaseException.__setattr__(first,'native_preflight_cleanup_uncertain',True)
    finally:
        if fd is not None:
            try:
                need(held is not None and identity(os.fstat(fd))[:6]==held,'p0-private-close-custody')
                os.close(fd)
            except BaseException as error:first=merge(first,error)
    if first is not None:raise first


def materialize(*,entry,outer_end,root,private,output,cache,expected_source_commit,bundle_raw,bundle_sha256,environment,preparation):
    """Bind a preselected Root template to this job; never prepare an image.

    Exact template hash is the external Root selection. Only enumerated job,
    path, nonce and original-frame fields are substituted; scope/maps/Source
    rows/runtime/image/preparation bindings remain supplied by Root.
    """
    need(finite(entry) and finite(outer_end),'p0-frame');end=min(outer_end,entry+60);live(end)
    need(type(bundle_raw) is bytes and 0<len(bundle_raw)<=2*1024**2 and digest(bundle_raw)==pin(bundle_sha256),'p0-template-pin')
    bundle=decode(bundle_raw)
    need(type(bundle) is dict and set(bundle)=={'schema_version','purpose','plan','packet','grant','runtime','prepared_image','packages_b64','current_inputs_b64','publication'} and
         type(bundle['schema_version']) is int and bundle['schema_version']==1 and
         bundle['purpose']=='Root-selected-P0-private-input-template','p0-template')
    plan=bundle['plan'];packet=bundle['packet'];grant=bundle['grant'];prepared=bundle['prepared_image'];runtime=bundle['runtime']
    need(all(type(value) is dict for value in (plan,packet,grant,prepared,runtime,bundle['publication'])) and
         plan.get('purpose')=='reviewed-installer-P0-ci-execution' and grant.get('purpose')=='reviewed-installer-P0-execution' and
         type(grant.get('added_seconds')) is int and grant['added_seconds']==0 and
         grant.get('source_peer_preflight')=='PASS' and grant.get('development_only') is True and
         packet.get('composition')==COMPOSITION and type(packet.get('source_files')) is dict and
         len(packet['source_files'])==269 and OWN in packet['source_files'] and
         grant.get('source_files')==packet['source_files'],'p0-template-scope')
    for value in (plan,grant,prepared):input_successor(value.get('input_successor'))
    actual_preparation(preparation,expected_source_commit,environment,entry)
    for key in ('preparation_plan_sha256','preparation_source_rows_sha256'):
        need(plan.get(key,'ABSENT') is None and prepared.get(key,'ABSENT') is None,'p0-preparation-template')
        plan[key]=prepared[key]=preparation[key]
    need(prepared.get('image','ABSENT') is None and bundle['packages_b64'] is None and
         bundle['current_inputs_b64'] is None,'p0-preparation-template')
    prepared['image']=preparation['image'];bundle['packages_b64']=preparation['packages_b64']
    bundle['current_inputs_b64']=preparation['current_inputs_b64']
    need(type(runtime['env']) is dict and set(runtime['env'])=={'PATH','HOME','DOCKER_CONFIG','DOCKER_HOST','DOCKER_BUILDKIT','LC_ALL','TMPDIR'} and
         runtime['env']['PATH']=='/usr/bin:/bin' and runtime['env']['LC_ALL']=='C' and
         runtime['env']['DOCKER_HOST']=='unix:///run/docker.sock' and runtime['env']['DOCKER_BUILDKIT']=='0','p0-environment')
    for key in ('HOME','DOCKER_CONFIG','TMPDIR'):
        need(runtime['env'][key] is None,'p0-private-template')
        runtime['env'][key]=str(private.parent/('p0-'+key.lower()))
        path=Path(runtime['env'][key]);live(end);need(not path.exists() and not path.is_symlink(),'p0-private-fresh')
        path.mkdir(mode=0o700)
    need(expected_source_commit==environment.get('GITHUB_SHA')==environment.get('GITHUB_WORKFLOW_SHA') and
         type(expected_source_commit) is str and re.fullmatch('[0-9a-f]{40}',expected_source_commit),'p0-source-commit')
    for value in (plan,grant,prepared):
        for key,actual in (('source_commit',expected_source_commit),('run_id',environment.get('GITHUB_RUN_ID')),
                           ('run_attempt',environment.get('GITHUB_RUN_ATTEMPT'))):
            need(key in value and value[key] is None,'p0-template-job-field');value[key]=actual
    need(plan.get('outer_end') is None and plan.get('nonce') is None and plan.get('input_pins') is None and
         grant.get('initial_invocation_sha256') is None and grant.get('actor_contract_sha256') is None,'p0-template-frame')
    plan['outer_end']=outer_end;plan['nonce']=os.urandom(16).hex()
    view=grant.get('original_view')
    need(type(view) is dict and view.get('purpose')=='P0-157-held-2-overlay-copy-view' and
         view.get('root') is None and view.get('full_source_root') is None,'p0-template-view')
    view['root']=str(output/'repository-handoff/original-view');view['full_source_root']=str(root)
    invocation=argv(output,cache,packet['metadata_pins'])
    grant['initial_invocation_sha256']=digest(encoded({'argv':invocation,'output':str(output/'repository-handoff')}))
    grant['actor_contract_sha256']=digest(encoded(runtime))
    need(type(bundle['packages_b64']) is str,'p0-template-packages')
    packages=base64.b64decode(bundle['packages_b64'],validate=True)
    need(len(packages)==6674 and digest(packages)==PACKAGES_SHA,'p0-template-packages')
    need(type(bundle['current_inputs_b64']) is str and len(bundle['current_inputs_b64'])==437468,'p0-input-pin')
    current_raw=base64.b64decode(bundle['current_inputs_b64'],validate=True)
    need(len(current_raw)==328101 and digest(current_raw)==INPUTS_SHA and
         base64.b64encode(current_raw).decode('ascii')==bundle['current_inputs_b64'],'p0-input-pin')
    data={'packet.json':encoded(packet),'grant.json':encoded(grant),'runtime.json':encoded(runtime),
          'prepared-image.json':encoded(prepared),'packages.lock':packages,'current-inputs.lock.json':current_raw,
          'source-publication.json':encoded(bundle['publication'])}
    plan['input_pins']={name:digest(raw) for name,raw in data.items()}
    contract(plan,prepared,runtime,entry=entry,expected_source_commit=expected_source_commit,environment=environment)
    data['plan.json']=encoded(plan)
    need(private.is_absolute() and '..' not in private.parts and not private.exists() and not private.is_symlink() and
         all(stat.S_ISDIR(p.lstat().st_mode) for p in private.parents),'p0-private-fresh')
    live(end)
    try:private.mkdir(mode=0o700)
    except BaseException as error:
        BaseException.__setattr__(error,'native_preflight_cleanup_uncertain',True);raise
    # Fresh files remain Root-private job custody, even on a failed materialization.
    # No recursive delete or foreign-directory cleanup is attempted.
    for name,raw in data.items():
        live(end);need(0<len(raw)<=2**20,'p0-private-cap')
        write_private(private/name,raw,end);live(end)
        need(read(private/name,end,private=True,limit=2**20)==raw,'p0-input-drift')
    return {name:digest(raw) for name,raw in data.items()}


def run(*,entry,outer_end,expected_source_commit,source_root,private_root,output,cache,input_pins):
    """Future admitted workflow entry; caller captures entry before Source/data decode."""
    need(finite(entry) and finite(outer_end) and entry<=time.monotonic()<min(outer_end,entry+60),'p0-original-entry')
    end=min(outer_end,entry+60);root=Path(source_root);private=Path(private_root);output=Path(output);cache=Path(cache)
    need(type(input_pins) is dict and set(input_pins)==set(INPUT_NAMES),'p0-input-set')
    for value in input_pins.values():pin(value)
    raw={name:read(private/name,end,private=True,limit=2**20) for name in INPUT_NAMES}
    need(all(digest(raw[name])==input_pins[name] for name in INPUT_NAMES),'p0-input-pin')
    plan=decode(raw['plan.json']);prepared=decode(raw['prepared-image.json']);runtime=decode(raw['runtime.json'])
    need(type(plan) is dict and plan.get('outer_end')==outer_end,'p0-frame')
    end=contract(plan,prepared,runtime,entry=entry,expected_source_commit=expected_source_commit,environment=os.environ)
    need(plan['input_pins']=={k:v for k,v in input_pins.items() if k!='plan.json'},'p0-frame')
    live(end);need(digest(raw['packages.lock'])==PACKAGES_SHA and len(raw['packages.lock'])==6674,'p0-packages')
    current_inputs_raw=raw['current-inputs.lock.json']
    need(len(current_inputs_raw)==328101 and digest(current_inputs_raw)==INPUTS_SHA,'p0-input-pin')
    source_packet=decode(raw['packet.json']);grant=decode(raw['grant.json'])
    need(type(source_packet) is dict and source_packet.get('composition')==COMPOSITION and
         type(source_packet.get('source_files')) is dict and len(source_packet['source_files'])==269 and
         OWN in source_packet['source_files'] and type(grant) is dict and
         grant.get('purpose')=='reviewed-installer-P0-execution' and type(grant.get('added_seconds')) is int and
         grant['added_seconds']==0 and grant.get('source_files')==source_packet['source_files'],'p0-grant-scope')
    input_successor(grant.get('input_successor'))
    need(root.is_absolute() and root==Path.cwd().resolve() and
         all(p.is_absolute() and '..' not in p.parts for p in (private,output,cache)) and
         not any(a.is_relative_to(b) for a,b in ((private,root),(output,root),(cache,root),(output,cache),(cache,output))) and
         not output.exists() and not output.is_symlink(),'p0-output-boundary')
    bodies={};total=0
    for name,wanted in sorted(source_packet['source_files'].items()):
        need(type(name) is str and name and not Path(name).is_absolute() and '..' not in Path(name).parts,'p0-source-path')
        bodies[name]=read(root/name,end,wanted=wanted,limit=8*1024**2)
        total+=len(bodies[name]);need(total<=64*1024**2,'p0-source-total')
    # Root-authenticated workflow plus exact packet Git verification establish publication;
    # source-publication bytes are independently pinned inputs, not a status-flag grant.
    publication=decode(raw['source-publication.json'])
    need(type(publication) is dict and publication.get('Source')==publication.get('remote')==expected_source_commit and
         publication.get('branch')=='codex/signer-native-runtime-v1' and type(publication.get('files')) is list and
         4<=len(publication['files'])<=300,'p0-publication')
    published={}
    for row in publication['files']:
        need(type(row) is dict and set(row)=={'path','bytes','mode','sha256'} and row['path'] not in published,
             'p0-publication-row')
        path=row['path'];need(type(path) is str and (path in bodies or path==WORKFLOW),'p0-publication-row')
        body=bodies[path] if path in bodies else read(root/path,end,wanted={'mode':row['mode'],'sha256':row['sha256']})
        need(type(row['bytes']) is int and row['bytes']==len(body) and
             row['mode']==(source_packet['source_files'][path]['mode'] if path in bodies else 0o644) and
             row['sha256']==digest(body),'p0-publication-row');published[path]=row
    need({OWN,WORKFLOW,'scripts/install/p0_entry.py',*(path for _,path in MODULES)}<=set(published),
         'p0-publication-closure')
    need(set(PROJECT_BOOTSTRAP_ROWS)=={path for _,path in MODULES},'p0-bootstrap-unfilled')
    for path,wanted in PROJECT_BOOTSTRAP_ROWS.items():
        need(wanted=={'bytes':len(bodies[path]),'mode':source_packet['source_files'][path]['mode'],
             'sha256':digest(bodies[path])},'p0-bootstrap-body')
    modules=load(bodies,root)
    controller=modules['development_p0_controller'];sdk=modules['development_repository_handoff'];packet=modules['packet']
    callback_boundaries=callback_code_boundaries(sdk);callback_refusal=sdk.Refused
    first=None;result=None;session=development=None;previous={};timer=False
    try:
        need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'p0-existing-timer')
        for sig in (signal.SIGINT,signal.SIGTERM,signal.SIGALRM):previous[sig]=signal.getsignal(sig)
        for sig in previous:signal.signal(sig,controller.interrupt)
        timer=True;signal.setitimer(signal.ITIMER_REAL,end-time.monotonic());live(end)
        need(packet.preflight_composed(root,root/packet.LOCK,input_pins['packet.json'],expected_source_commit,
             composition=COMPOSITION)==source_packet,'p0-packet-drift')
        try:
            sources=sdk.preflight(root,raw['grant.json'],input_pins['grant.json'],deadline=end)
        except BaseException as error:
            attach_sdk_preflight(error, 'P0-sdk-preflight')
            raise
        need(grant['callbacks']['existing_consumers']=={'path':'scripts/ci/development/controller.py',
             'module':controller.__name__,'qualname':'Development.consume_p0'},'p0-callback')
        invocation=argv(output,cache,source_packet['metadata_pins'])
        need(digest(encoded(runtime))==grant['actor_contract_sha256'] and
             digest(encoded({'argv':invocation,'output':str(output/'repository-handoff')}))==grant['initial_invocation_sha256'],
             'p0-invocation')
        live(end);output.mkdir(mode=0o700);cache.mkdir(mode=0o700,exist_ok=True)
        session=sdk.Session(sources,output/'repository-handoff',job_deadline=end,cancelled=controller.cancelled,composition=COMPOSITION)
        development=controller.Development(root,output,cache,source_packet,deadline=end,composition=COMPOSITION,
             clock_nonce=plan['nonce'],runtime_contract=runtime)
        sources.callback('existing_consumers',development.consume_p0,end)
        result=development.run_p0(session,runtime,invocation,entry=entry,image=prepared['image'],
            inputs_raw=current_inputs_raw,packages_raw=raw['packages.lock'])
        live(end);need(type(result) is dict and result.get('status')=='PASS_P0_ONLY','p0-result')
    except BaseException as error:
        first=error
        mark_callback_failure(error,callback_refusal,callback_boundaries)
        try:
            value_boundaries=p0_value_code_boundaries(controller,sdk,session)
            mark_callback_failure(error,callback_refusal,value_boundaries,value_error=True)
        except BaseException as secondary:
            if type(secondary) is KeyboardInterrupt:
                BaseException.__setattr__(error,'native_preflight_cancelled',True)
                BaseException.__setattr__(error,'native_preflight_cleanup_uncertain',True)
    finally:
        if timer:
            try:signal.setitimer(signal.ITIMER_REAL,0)
            except BaseException as error:first=merge(first,error)
        for sig,handler in previous.items():
            try:signal.signal(sig,handler)
            except BaseException as error:first=merge(first,error)
        for name,module in modules.items():
            try:
                need(sys.modules.get(name) is module,'p0-registry-retirement');del sys.modules[name]
            except BaseException as error:first=merge(first,error)
        try:live(end);need(controller.CANCELLED is False,'p0-sticky-cancel')
        except BaseException as error:
            if first is None:first=error
            if controller.CANCELLED is True:BaseException.__setattr__(first,'native_preflight_cancelled',True)
    if first is not None:raise first
    # PASS claims only P0 child cleanup; it does not claim borrowed base-image absence.
    return {'status':'PASS_P0_ONLY','receiver':result,'base_image':'EXTERNAL_ROOT_BORROWED',
            'image_preparation':'NOT_RUN','ABI':'NOT_RUN','matrix':'NOT_RUN'}


PREPARATION_QUARANTINE=[]


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self,domain):self.domain=domain
    def redirect_request(self,request,fp,code,message,headers,newurl):
        need(type(newurl) is str and newurl.startswith('https://'),'prep-download-downgrade')
        if self.domain is not None:need(urllib.parse.urlsplit(newurl).hostname==self.domain,'prep-download-domain')
        return super().redirect_request(request,fp,code,message,headers,newurl)


def source_transfer_selection(value,binding=None):
    """Explicit conduct premise, never a filesystem immutability assertion."""
    flags=('Root_selected','trusted_host','exclusive_writer_interval','read_only_actors')
    slots=('source_commit','source_root','source_rows_sha256','grant_sha256','run_id','run_attempt')
    need(type(value) is dict and set(value)=={'schema_version','purpose','selected','scope',*flags,*slots} and
         type(value['schema_version']) is int and value['schema_version']==1 and value['purpose']=='fetch-interior-only' and
         value['scope']=='same-UID-and-privileged-writers-alternate-path-FD-mmap-leaf-ancestor-and-code-namespace-excluded' and
         type(value['selected']) is bool and all(type(value[key]) is bool and value[key] is value['selected'] for key in flags),
         'prep-source-owner')
    if binding is None or value['selected'] is False:
        need(all(value[key] is None for key in slots),'prep-source-owner')
    else:
        need(type(binding) is dict and set(binding)==set(slots) and
             all(type(value[key]) is str and value[key]==binding[key] for key in slots), 'prep-source-owner')
    return value['selected']


class Preparation:
    """Local resource custody. Sources/prep grant, not this object, admits actors."""
    def __init__(self,sources,sdk,transport,native,plan,runtime,out,cache,deadline,cleanup_end,private_chunks,source_transfer_interval):
        need(type(sources) is sdk.Sources and sources.grant['purpose']=='reviewed-installer-P0-preparation', 'prep-source-owner')
        sources.class_state(sources,'scripts/ci/development/repository_handoff.py',sdk)
        sources.guard(deadline)
        self.sources,self.sdk,self.transport,self.native=sources,sdk,transport,native
        self.plan,self.runtime,self.out,self.cache=plan,runtime,out,cache
        self.deadline,self.cleanup_end=deadline,cleanup_end
        binding={'source_commit':sources.grant['source_commit'],'source_root':str(sources.root),
            'source_rows_sha256':digest(encoded(sources.grant['source_files'])),
            'grant_sha256':digest(encoded(sources.grant)),'run_id':sources.grant['run_id'],'run_attempt':sources.grant['run_attempt']}
        self.source_interval_selected=source_transfer_selection(source_transfer_interval,binding)
        self.source_interval_binding=tuple(binding.items())
        self.source_interval_active=None;self.source_interval_unclosed=False;self.source_interval_faults=()
        self.private_chunks=private_chunks
        self.tag='cachy-asahi-p0-prep:'+plan['nonce'];self.inventory_name='cachy-asahi-p0-inventory-'+plan['nonce']
        self.cli=self.gpg_file=None;self.image=None;self.packages=None;self.current_inputs_raw=None
        self.tag_absent=False;self.tag_confirmed=False;self.inventory_cid=None
        self.build_started=False;self.inventory_started=False;self.tag_retired=False
        self.commands=0;self.cancelled=False;self.uncertain=False;self.retained=[]
        self.download_rows=self.download_pins=self.download_binding=self.download_item=self.download_failure=self.alarm_interrupt=None

    def _guard_live(self,cleanup=False):
        end=self.cleanup_end if cleanup else self.deadline
        live(end);need(not self.transport.PREP_QUARANTINE and not PREPARATION_QUARANTINE,'prep-quarantine')
        need(cleanup or not self.source_interval_unclosed,'prep-source-owner')
        return end

    def _guard_tools(self):
        if self.cli is not None:self.cli._preflight()
        if self.gpg_file is not None:
            current=self.transport.read_file('/usr/bin/gpg')
            need(current['sha256']==self.gpg_file['sha256'] and current['identity']==self.gpg_file['identity'] and
                 self.transport.identity(os.fstat(self.gpg_file['fd']))==current['identity'],'prep-gpg-drift')

    def guard(self,cleanup=False):
        end=self._guard_live(cleanup)
        self.sources.guard(end)
        self._guard_tools()

    def source_interval_begin(self):
        need(self.source_interval_active is None and not self.source_interval_unclosed,'prep-source-owner')
        if not self.source_interval_selected:return
        source=self.sources;rows=source.grant['source_files']
        need(type(source.raw) is dict and type(source.identities) is dict and type(rows) is dict and
             len(rows)==len(source.raw)==len(source.identities)==269 and set(rows)==set(source.raw)==set(source.identities),
             'prep-source-owner')
        frozen=tuple((name,rows[name]['mode'],rows[name]['sha256'],source.raw[name],source.identities[name]) for name in sorted(rows))
        need(all(type(raw) is bytes and type(node) is tuple and len(node)==9 and
             digest(raw)==sha and type(mode) is int and mode in (0o644,0o755) for name,mode,sha,raw,node in frozen),
             'prep-source-owner')
        need(tuple({'source_commit':source.grant['source_commit'],'source_root':str(source.root),
             'source_rows_sha256':digest(encoded(rows)),'grant_sha256':digest(encoded(source.grant)),
             'run_id':source.grant['run_id'],'run_attempt':source.grant['run_attempt']}.items())==self.source_interval_binding,
             'prep-source-owner')
        self.source_interval_active=(source,source.root,source.grant,source.raw,source.identities,rows,frozen)

    def _source_interval_matches(self):
        held=self.source_interval_active;source=self.sources
        need(type(held) is tuple and len(held)==7 and source is held[0] and source.root==held[1] and
             source.grant is held[2] and source.raw is held[3] and source.identities is held[4] and
             source.grant['source_files'] is held[5] and len(source.raw)==len(source.identities)==len(held[5])==269,
             'prep-source-owner')
        need(all(name in source.raw and name in source.identities and name in held[5] and
             source.raw[name] is raw and source.identities[name] is node and
             held[5][name]=={'mode':mode,'sha256':sha} for name,mode,sha,raw,node in held[6]),
             'prep-source-owner')

    def source_interval_guard(self):
        if not self.source_interval_selected:return self.guard()
        self._guard_live();self._source_interval_matches();self._guard_tools()

    def source_interval_end(self,cleanup=False):
        if not self.source_interval_selected:return
        need(self.source_interval_active is not None,'prep-source-owner')
        try:
            self._guard_live(cleanup);self._source_interval_matches();self.guard(cleanup)
        except BaseException as error:
            self.source_interval_unclosed=True
            self.source_interval_faults+=(error,)
            raise
        finally:self.source_interval_active=None

    def invoke(self,fd,args,env,*,cleanup=False,accept_nonzero=False):
        self.guard(cleanup);need(self.commands<280,'prep-command-count');self.commands+=1
        end=self.cleanup_end if cleanup else self.deadline
        # Leave a fixed slice of the same issued cleanup frame for child retirement.
        work=min(end-2,time.monotonic()+ (1800 if args[:1]==['build'] else 60))
        need(work<self.cleanup_end,'prep-command-frame')
        try:
            result,observation=self.transport.prep_supervise(['/proc/self/fd/'+str(fd),*args],env=env,
                deadline=work,cleanup_end=self.cleanup_end,limit=16*1024**2,pass_fds=(fd,),
                preflight=lambda:self.guard(cleanup))
        except BaseException as error:
            mark_pipeline_failure(error, 'supervise-child')
            markers=BaseException.__getattribute__(error,'__dict__')
            self.cancelled |= isinstance(error,KeyboardInterrupt) or markers.get('native_preflight_cancelled') is True
            self.uncertain |= markers.get('native_preflight_cleanup_uncertain') is True
            if markers.get('native_preparation_process') is not None or markers.get('native_preparation_streams'):
                self.retained.append(error)
            raise
        try:
            need(observation['direct_child_reaped'] is True and observation['group_disposal_requested'] is True and
                 observation['forced_teardown'] is False and observation['cancelled'] is False,'prep-command-retirement')
            if not accept_nonzero:need(result['exit_code']==0,'prep-command-exit')
        except BaseException as error:
            mark_pipeline_failure(error, 'check-child-outcome')
            raise
        return result

    def bind_download_rows(self,items):
        self.download_rows=self.download_pins=self.download_binding=None
        try:
            raw=self.current_inputs_raw
            if type(raw) is not bytes or len(raw)!=328101 or digest(raw)!=INPUTS_SHA:return
            inputs=decode(raw);expected=list(inputs['keyring_files'])
            for item in (inputs['rootfs'],*inputs['packages']):
                expected.extend((item,{'filename':item['filename']+'.sig','size':item['signature_size'],
                    'sha256':item['signature_sha256'],'url':item['url']+'.sig'}))
            if type(items) is not list or len(items)!=501 or len(expected)!=501:return
            actual=tuple(download_item(item) for item in items)
            if None in actual or actual!=tuple(download_item(item) for item in expected):return
            self.download_rows=tuple(items);self.download_pins=actual
            self.download_binding=(self.download_rows,self.download_pins)
        except BaseException as error:
            if isinstance(error,KeyboardInterrupt):raise

    def capture_download(self,error,ordinal,item,*,guard_phase=None):
        try:
            if self.download_failure is not None or type(ordinal) is not int or not 0<=ordinal<501:return
            if type(self.download_rows) is not tuple or len(self.download_rows)!=501 or item is not self.download_rows[ordinal]:return
            if type(self.download_binding) is not tuple or len(self.download_binding)!=2 or self.download_rows is not self.download_binding[0] or self.download_pins is not self.download_binding[1]:return
            if type(self.download_pins) is not tuple or len(self.download_pins)!=501 or download_item(item)!=self.download_pins[ordinal]:return
            self.download_item=item;self.download_failure=(error,ordinal,None)
            kind=type(error);code='DL_OTHER'
            if kind is urllib.error.HTTPError:
                state=BaseException.__dict__['__dict__'].__get__(error)
                status=state.get('code') if type(state) is dict and all(type(key) is str for key in state) else None
                label=str(status) if type(status) is int and 100<=status<=599 else 'UNKNOWN'
                if 'DL_HTTP_'+label not in DOWNLOAD_CODES:label='OTHER' if label!='UNKNOWN' else label
                code='DL_HTTP_'+label
            elif kind is KeyboardInterrupt:
                relation='UNKNOWN'
                try:relation=download_clock(time.monotonic(),self.deadline)
                except BaseException as secondary:download_fault(error,secondary)
                path='PREP_ALRM' if error is self.alarm_interrupt else 'UNATTRIBUTED'
                code='DL_KBI_'+relation+'_'+path
            else:
                for exact,label in ((urllib.error.URLError,'URLERROR'),(TimeoutError,'TIMEOUTERROR'),
                    (ValueError,'VALUEERROR'),(TypeError,'TYPEERROR'),(RuntimeError,'RUNTIMEERROR'),(SystemExit,'SYSTEMEXIT')):
                    if kind is exact:code='DL_'+label;break
                else:
                    if any(kind is exact for exact in (OSError,BlockingIOError,ChildProcessError,ConnectionError,BrokenPipeError,
                        ConnectionAbortedError,ConnectionRefusedError,ConnectionResetError,FileExistsError,
                        FileNotFoundError,InterruptedError,IsADirectoryError,NotADirectoryError,PermissionError,ProcessLookupError)):code='DL_OSERROR'
            if kind is ValueError:
                args=BaseException.__dict__['args'].__get__(error)
                if type(args) is tuple and len(args)==1 and type(args[0]) is str and args[0] in DOWNLOAD_GUARD_CODES:code=args[0]
            # Only an exact Source-owned SDK deadline caught at this guard call.
            if type(guard_phase) is str and guard_phase in DOWNLOAD_GUARD_DEADLINES:
                owner_state=object.__getattribute__(self,'__dict__')
                sdk=owner_state.get('sdk')
                sdk_state=types.ModuleType.__dict__['__dict__'].__get__(sdk) if type(sdk) is types.ModuleType else None
                if type(sdk_state) is dict and all(type(key) is str for key in sdk_state):
                    refused=sdk_state.get('Refused')
                    args=BaseException.__dict__['args'].__get__(error)
                    if (type(refused) is type and kind is refused and type(args) is tuple and len(args)==1 and
                        type(args[0]) is str and args[0]=='deadline'):
                        code=DOWNLOAD_GUARD_DEADLINES[guard_phase]
            self.download_item=item
            self.download_failure=(error,ordinal,(DOWNLOAD_PREFIX+str(ordinal).zfill(3),code))
        except BaseException as secondary:download_fault(error,secondary)

    def download_guard(self,ordinal,item,phase,*,transfer=False):
        """Observe only a failure of this unchanged guard; never bypass its checks."""
        try:
            if transfer:self.source_interval_guard()
            else:self.guard()
        except BaseException as error:
            try:self.capture_download(error,ordinal,item,guard_phase=phase)
            except BaseException as secondary:
                try:download_fault(error,secondary)
                except BaseException:pass
            raise

    def cached(self,items,cache):
        need(cache==self.cache and len(items)==501 and len({item['filename'] for item in items})==501 and
             sum(item['size'] for item in items)<=2*1024**3,'prep-cache-set')
        node=cache.lstat()
        need(stat.S_ISDIR(node.st_mode) and node.st_uid==os.geteuid() and stat.S_IMODE(node.st_mode)==0o700,'prep-cache-custody')
        rows={item['filename']:(item['size'],item['sha256']) for item in items}
        need(all(rows.get(name)==row for name,row in OVERRIDE_ROWS.items()),'prep-override-content')
        self.bind_download_rows(items)
        for ordinal,item in enumerate(items):
            self.guard();name=self.native.input_name(item['filename']);path=cache/name
            if not path.exists():
                need(name not in OVERRIDE_ROWS,'prep-fixed-four-seed-required')
                need(self.plan['cache_mode']=='selected-HTTPS','prep-warm-cache-required')
                self.fetch(item,path,ordinal=ordinal)
            need(path.is_file() and not path.is_symlink() and path.stat().st_size==item['size'] and
                 self.native.sha(path)==item['sha256'],'prep-warm-cache')
        self.guard()

    def fetch(self,item,target,*,ordinal=None):
        """Original pinned HTTPS semantics with original-frame owned partial custody."""
        try:
            need(type(item['size']) is int and 0<=item['size']<=2*1024**3 and
                 type(item['url']) is str and item['url'].startswith('https://'),'prep-download-input')
            need(item['filename'] not in OVERRIDE_ROWS,'prep-fixed-four-no-HTTPS-fallback')
            pin(item['sha256']);self.download_guard(ordinal,item,'before-open')
            partial=target.with_name(target.name+'.'+self.plan['nonce']+'.partial')
            fd=held=response=response_held=None;first=None;opened=False;connecting=False
            try:
                opened=True;fd=os.open(partial,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                node=os.fstat(fd);held=identity(node)[:6]
                need(stat.S_ISREG(node.st_mode) and node.st_uid==os.geteuid() and node.st_nlink==1 and
                     stat.S_IMODE(node.st_mode)==0o600 and node.st_size==0,'prep-download-file')
                self.download_guard(ordinal,item,'before-connect');connecting=True
                override=self.plan['url_overrides'].get(item['filename'])
                url=override['url'] if override is not None else item['url']
                domain=override['domain'] if override is not None else None
                opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),HTTPSRedirect(domain))
                response=opener.open(url,timeout=min(60,self.deadline-time.monotonic()))
                response_held=identity(os.fstat(response.fileno()))[:6]
                need(type(response.url) is str and response.url.startswith('https://'),'prep-download-redirect')
                if domain is not None:need(urllib.parse.urlsplit(response.url).hostname==domain,'prep-download-domain')
                if self.source_interval_selected:
                    self.download_guard(ordinal,item,'before-read')
                    self.source_interval_begin()
                total=0;sha=hashlib.sha256()
                while True:
                    self.download_guard(ordinal,item,'before-read',transfer=True);chunk=response.read(65536)
                    if not chunk:break
                    total+=len(chunk);need(total<=item['size'],'prep-download-cap');sha.update(chunk)
                    offset=0
                    while offset<len(chunk):
                        self.download_guard(ordinal,item,'before-write',transfer=True);need(identity(os.fstat(fd))[:6]==held,'prep-download-fd')
                        count=os.write(fd,chunk[offset:]);need(type(count) is int and 0<count<=len(chunk)-offset,'prep-download-progress')
                        offset+=count
                if self.source_interval_selected:self.source_interval_end()
                node=os.fstat(fd)
                need(total==item['size'] and sha.hexdigest()==item['sha256'] and identity(node)[:6]==held and
                     node.st_size==total and identity(partial.lstat())==identity(node),'prep-download-pin')
            except BaseException as error:
                first=error
                self.capture_download(error,ordinal,item)
                if connecting and response is None and isinstance(error,urllib.error.HTTPError):
                    # urllib owns an error response even when open() never returned it.
                    try:error.close()
                    except BaseException as close_error:first=merge(first,close_error)
                if (opened and fd is None) or (connecting and response is None):
                    first=merge(first,error);self.retained.append(error)
            finally:
                if self.source_interval_active is not None:
                    try:
                        # Use only the already issued cleanup frame; never start a replacement timer.
                        live(self.cleanup_end)
                        self.source_interval_end(cleanup=True)
                    except BaseException as error:
                        self.source_interval_unclosed=True
                        if not any(error is fault for fault in self.source_interval_faults):self.source_interval_faults+=(error,)
                        if first is None:first=error
                        elif isinstance(error,KeyboardInterrupt):
                            # Cancellation is sticky; Source uncertainty is not FD retirement uncertainty.
                            self.cancelled=True
                            BaseException.__setattr__(first,'native_preflight_cancelled',True)
                    finally:self.source_interval_active=None
                if response is not None:
                    try:
                        # HTTPResponse closes its own fp on a natural length/EOF.
                        # In that state no numeric FD is closed a second time.
                        if not response.isclosed():
                            need(response_held is not None and identity(os.fstat(response.fileno()))[:6]==response_held,
                                 'prep-download-response-custody')
                            response.close()
                    except BaseException as error:
                        self.retained.append(response);first=merge(first,error)
                if fd is not None:
                    try:
                        need(held is not None and identity(os.fstat(fd))[:6]==held,'prep-download-close-custody')
                        os.close(fd)
                    except BaseException as error:first=merge(first,error)
                if first is not None and BaseException.__getattribute__(first,'__dict__').get('native_preflight_cleanup_uncertain') is True:
                    if self not in PREPARATION_QUARANTINE:PREPARATION_QUARANTINE.append(self)
                    sys.modules['root_p0_preparation_owner_quarantine']=sys.modules[__name__]
            if first is not None:
                mark_pipeline_failure(first, 'download-input')
                raise first
            self.download_guard(ordinal,item,'before-publish');need(not target.exists() and not target.is_symlink() and identity(partial.lstat())==identity(node),
                              'prep-download-target')
            # Root-selected writer exclusion on the owned700 cache prevents a foreign replacement.
            try:partial.rename(target)
            except BaseException as error:raise merge(None,error)
            self.download_guard(ordinal,item,'after-publish')
        except BaseException as error:
            self.capture_download(error,ordinal,item)
            mark_pipeline_failure(error,'download-input')
            raise

    def gpg(self,args,log=None):
        base=['gpg','--batch','--no-options','--no-autostart','--homedir',str(self.out/'gpg'),'--no-auto-key-retrieve']
        need(args[:len(base)]==base,'prep-gpg-argv')
        tail=args[len(base):]
        allowed=tail==['--import',str(self.cache/'archlinuxarm.gpg')]
        if len(tail)==5 and tail[:3]==['--status-fd','1','--verify']:
            allowed=any(tail[3:]==[str(self.cache/(item['filename']+'.sig')),str(self.cache/item['filename'])]
                        for item in [self.plan['inputs']['rootfs'],*self.plan['inputs']['packages']])
        need(allowed,'prep-gpg-operation')
        result=self.invoke(self.gpg_file['fd'],args[1:],self.runtime['gpg_env'])
        value={**result,'stdout':result['stdout'].decode('utf-8','strict'),'stderr':result['stderr'].decode('utf-8','strict')}
        if log is not None:log.write_text(value['stdout']+value['stderr'])
        return value

    def docker(self,args,log=None):
        need(type(args) is list and args[0]=='docker','prep-docker-argv');tail=args[1:]
        allowed=(tail[:1]==['build'] and tail==['build','--network=none','--pull=false','--platform=linux/arm64',
            '--tag',self.tag,'--iidfile',str(self.out/'image-id'),str(self.out/'context')]) or (
            tail==['image','inspect',self.image]) or (
            tail==['run','--rm','--name',self.inventory_name,'--cidfile',str(self.out/'inventory-cid'),
                '--pull=never','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only',
                '--entrypoint=/bin/cat',self.image,'/builder-packages.lock'])
        # During build the image is learned from the iidfile before inspect/run.
        if self.image is None and tail[:2]==['image','inspect']:
            raw,_,_=self.sdk.read(self.out/'image-id',self.deadline,limit=128)
            self.image=raw.decode('ascii').strip();need(re.fullmatch('sha256:[0-9a-f]{64}',self.image),'prep-image-id')
            allowed=tail==['image','inspect',self.image]
        need(allowed,'prep-docker-operation')
        if tail[:1]==['build']:self.build_started=True
        if tail[:1]==['run']:self.inventory_started=True
        result=self.invoke(self.cli.fd,tail,self.cli.env)
        stdout=result['stdout'].decode('utf-8','strict').strip()
        if log is not None:log.write_bytes(result['stdout']+result['stderr'])
        return stdout

    def confirm_image(self,image,inspected,packages):
        need(image==self.image and digest(packages)==PACKAGES_SHA and len(packages)==6674,'prep-packages')
        result=self.invoke(self.cli.fd,['image','inspect',self.tag],self.cli.env)
        rows=decode(result['stdout']);need(type(rows) is list and len(rows)==1 and rows[0]['Id']==image,'prep-owned-tag')
        bridge=self.sources.module('_prep_config','scripts/install/native_preflight.py')
        receiver=self.sources.module('_prep_receiver','scripts/install/native_arm_trial.py')
        data=types.SimpleNamespace(image=image,commit=self.sources.grant['source_commit'])
        input_successor(self.plan['input_successor'])
        need(type(self.current_inputs_raw) is bytes and len(self.current_inputs_raw)==328101 and
             digest(self.current_inputs_raw)==INPUTS_SHA,'prep-inputs')
        bridge.image_handoff([inspected],data,receiver,self.current_inputs_raw,packages,input_successor=INPUT_SUCCESSOR)
        gone=self.invoke(self.cli.fd,['container','ls','-a','--no-trunc','--filter','name=^/'+self.inventory_name+'$','--format','{{.ID}}'],self.cli.env)
        need(gone['stdout']==b'','prep-inventory-container-absence')
        self.tag_confirmed=True;self.packages=packages

    def prepare(self):
        self.sources.callback('existing_consumers',self.prepare,self.deadline)
        self.guard()
        input_successor(self.plan['input_successor'])
        raw=current_inputs(self.sources.raw['scripts/ci/inputs.lock.json'])
        need(raw==self.plan['current_inputs_raw'] and decode(raw)==self.plan['inputs'],'prep-materialized-input-pin')
        self.current_inputs_raw=raw
        directory=self.out.lstat();held=identity(directory)[:6]
        need(stat.S_ISDIR(directory.st_mode) and directory.st_uid==os.geteuid() and
             stat.S_IMODE(directory.st_mode)==0o700,'prep-output-custody')
        write_private(self.out/'inputs.lock.json',raw,self.deadline)
        observed=read(self.out/'inputs.lock.json',self.deadline,limit=1024**2,private=True)
        need(observed==raw and digest(observed)==INPUTS_SHA,'prep-materialized-input-readback')
        need(identity(self.out.lstat())[:6]==held,'prep-output-drift')
        self.guard()
        self.seed_four()
        need(os.uname().sysname=='Linux' and os.uname().machine=='aarch64','prep-host-ARM')
        items=list(self.plan['inputs']['keyring_files'])
        for item in (self.plan['inputs']['rootfs'],*self.plan['inputs']['packages']):
            items.extend((item,self.native.signature_item(item)))
        self.cached(items,self.cache)
        self.cli=self.transport.DockerTransport(**self.runtime['docker'],create_validator=lambda _:None)
        self.gpg_file=self.transport.read_file('/usr/bin/gpg',hold=True)
        need(self.gpg_file['sha256']==self.runtime['gpg_sha256'] and self.gpg_file['identity'][3:5]==(0,0) and
             stat.S_IMODE(self.gpg_file['identity'][2])==0o755,'prep-gpg-pin')
        daemon=decode(self.invoke(self.cli.fd,['info','--format','{{json .}}'],self.cli.env)['stdout'])
        need(type(daemon) is dict and daemon.get('OSType')=='linux' and daemon.get('Architecture') in ('aarch64','arm64'),
             'prep-daemon-ARM')
        absent=self.invoke(self.cli.fd,['image','ls','--no-trunc','--filter','reference='+self.tag,'--format','{{.ID}}'],self.cli.env)
        need(absent['stdout']==b'','prep-tag-must-be-absent');self.tag_absent=True
        absent=self.invoke(self.cli.fd,['container','ls','-a','--no-trunc','--filter','name=^/'+self.inventory_name+'$','--format','{{.ID}}'],self.cli.env)
        need(absent['stdout']==b'','prep-inventory-name-must-be-absent')
        self.native.prepare_audit(self.plan['inputs'],self.cache,self.out,self)
        image=self.native.prepare_image(self.plan['inputs'],self.cache,self.out,self)
        self.guard();need(self.tag_confirmed and image==self.image,'prep-complete')
        return {'schema_version':1,'purpose':'ACTUAL_SAME_JOB_P0_PREPARATION','Source':self.sources.grant['source_commit'],
            'run_id':self.sources.grant['run_id'],'run_attempt':self.sources.grant['run_attempt'],'tag':self.tag,
            'image':self.image,'packages_b64':base64.b64encode(self.packages).decode(),'packages_sha256':PACKAGES_SHA,
            'current_inputs_b64':base64.b64encode(self.current_inputs_raw).decode(),
            'input_successor':decode(encoded(INPUT_SUCCESSOR)),
            'inputs_sha256':INPUTS_SHA,'cleanup_end':self.cleanup_end,'inventory_name':self.inventory_name,
            'tag_before_absent':True,'tag_after_id':self.image,'global_digest_owned':False,
            'preparation_plan_sha256':self.plan['plan_sha256'],'preparation_source_rows_sha256':digest(encoded(self.sources.grant['source_files']))}

    def seed_four(self):
        self.guard()
        captured=self.private_chunks
        decoded=decode_four(captured,self.current_inputs_raw,self.deadline)
        parent=self.cache.lstat();held=identity(parent)[:6]
        need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.geteuid() and
             stat.S_IMODE(parent.st_mode)==0o700,'prep-fixed-four-cache-custody')
        for name,body in decoded:
            self.guard();write_private(self.cache/name,body,self.deadline)
            observed=read(self.cache/name,self.deadline,limit=1024**2,private=True)
            need(observed==body and digest(observed)==OVERRIDE_ROWS[name][1],'prep-fixed-four-readback')
            need(identity(self.cache.lstat())[:6]==held,'prep-fixed-four-cache-drift')
        decoded.clear();self.guard()

    def close_fds(self,first=None):
        for kind in ('gpg','docker'):
            try:
                if kind=='gpg' and self.gpg_file is not None:
                    fd=self.gpg_file['fd'];need(self.transport.identity(os.fstat(fd))==self.gpg_file['identity'],'prep-gpg-close-custody')
                    self.gpg_file=None;os.close(fd)
                elif kind=='docker' and self.cli is not None:
                    cli=self.cli
                    need(cli.fd is not None and self.transport.identity(os.fstat(cli.fd))==cli.cli['identity'],'prep-docker-close-custody')
                    fd=cli.fd;cli.fd=None;self.cli=None;os.close(fd)
            except BaseException as error:
                first=merge(first,error)
                if self not in PREPARATION_QUARANTINE:PREPARATION_QUARANTINE.append(self)
                sys.modules['root_p0_preparation_owner_quarantine']=sys.modules[__name__]
        return first

    def retire_image(self,first=None):
        """Retire only confirmed own unique tag/container; never global image ID."""
        try:
            if self.inventory_started:
                remaining=self.invoke(self.cli.fd,['container','ls','-a','--no-trunc','--filter',
                    'name=^/'+self.inventory_name+'$','--format','{{.ID}}'],self.cli.env,cleanup=True)['stdout'].strip()
                if remaining:
                    raw,_,_=self.sdk.read(self.out/'inventory-cid',self.cleanup_end,limit=128)
                    cid=raw.decode('ascii').strip()
                    need(re.fullmatch('[0-9a-f]{64}',cid) and remaining==cid.encode(),'prep-container-custody')
                    rows=decode(self.invoke(self.cli.fd,['container','inspect',cid],self.cli.env,cleanup=True)['stdout'])
                    need(type(rows) is list and len(rows)==1 and rows[0].get('Id')==cid and
                         rows[0].get('Name')=='/'+self.inventory_name and rows[0].get('Image')==self.image,
                         'prep-container-custody')
                    self.invoke(self.cli.fd,['container','rm','--force',cid],self.cli.env,cleanup=True)
                    remaining=self.invoke(self.cli.fd,['container','ls','-a','--no-trunc','--filter',
                        'name=^/'+self.inventory_name+'$','--format','{{.ID}}'],self.cli.env,cleanup=True)['stdout'].strip()
                    need(not remaining,'prep-container-retirement')
            if self.build_started:
                rows=self.invoke(self.cli.fd,['image','ls','--no-trunc','--filter','reference='+self.tag,
                    '--format','{{.ID}}'],self.cli.env,cleanup=True)['stdout'].strip()
                if self.image is None:
                    self.uncertain=True
                    need(False,'prep-build-outcome-unknown')
                if rows:
                    need(self.tag_absent and self.image is not None and rows==self.image.encode(),
                         'prep-tag-custody')
                    current=decode(self.invoke(self.cli.fd,['image','inspect',self.tag],self.cli.env,cleanup=True)['stdout'])
                    need(type(current) is list and len(current)==1 and current[0].get('Id')==self.image and
                         self.tag in current[0].get('RepoTags',[]),'prep-tag-custody')
                    self.invoke(self.cli.fd,['image','rm','--no-prune',self.tag],self.cli.env,cleanup=True)
                rows=self.invoke(self.cli.fd,['image','ls','--no-trunc','--filter','reference='+self.tag,
                    '--format','{{.ID}}'],self.cli.env,cleanup=True)['stdout']
                need(rows==b'','prep-tag-retirement');self.tag_retired=True
        except BaseException as error:first=merge(first,error)
        return first


def prep_sources(root,source_packet,grant_raw,grant_pin,end,registered):
    """Select exactly authenticated Sources; no broad Session.execute is used."""
    # Fixed four-unit bootstrap is still literal/body-bound by the outer entry.
    try:
        sdk=sys.modules['root_p0_prep_sdk'];sources=sdk.preflight(root,grant_raw,grant_pin,deadline=end)
    except BaseException as error:
        attach_sdk_preflight(error, 'preparation-sdk-preflight')
        raise
    need(type(sources) is sdk.Sources and sources.grant['purpose']=='reviewed-installer-P0-preparation' and
         sources.grant['source_files']==source_packet['source_files'],'prep-authority')
    sources.guard(end)
    transport=sources.module('root_p0_prep_transport','scripts/port/repository-native-handoff/transport.py')
    need(transport.__name__ not in sys.modules,'prep-module-collision');sys.modules[transport.__name__]=transport;registered[transport.__name__]=transport
    # Registered fixed project import, never an arbitrary callback or file search.
    package=sources.module('package_checks','scripts/checks/package_checks.py')
    need('package_checks' not in sys.modules,'prep-module-collision');sys.modules['package_checks']=package;registered['package_checks']=package
    path='scripts/ci/development/p0_native_arm.py';native=types.ModuleType('root_p0_preparation_native');native.__file__=str(root/path)
    need(native.__name__ not in sys.modules,'prep-module-collision');sys.modules[native.__name__]=native;registered[native.__name__]=native
    previous_path=list(sys.path)
    try:exec(compile(sources.raw[path],native.__file__,'exec',dont_inherit=True),native.__dict__)
    finally:sys.path[:]=previous_path
    sources.graph_namespace(package,'scripts/checks/package_checks.py',{'scripts/checks/package_checks.py':package},{},{})
    sources.graph_namespace(native,path,{path:native,'scripts/checks/package_checks.py':package},{},{})
    sources.graph_namespace(transport,'scripts/port/repository-native-handoff/transport.py',{'scripts/port/repository-native-handoff/transport.py':transport},{},{})
    return sdk,sources,transport,native


def load_preparation(raw,root,registered):
    """Two fixed verified units; actual Sources authority stays live through cleanup."""
    for path,row in PROJECT_BOOTSTRAP_ROWS.items():
        need(type(raw.get(path)) is bytes and len(raw[path])==row['bytes'] and digest(raw[path])==row['sha256'],
             'prep-bootstrap-body')
    for name,path in (('root_p0_prep_packet','scripts/ci/development/packet.py'),
                      ('root_p0_prep_sdk','scripts/ci/development/repository_handoff.py')):
        need(name not in sys.modules,'prep-module-collision')
        module=types.ModuleType(name);module.__file__=str(root/path)
        sys.modules[name]=module;registered[name]=module
        exec(compile(raw[path],module.__file__,'exec',dont_inherit=True),module.__dict__)
    return registered['root_p0_prep_packet']


def preparation_template(raw,wanted,*,entry,outer_end,expected,environment,output,root):
    """Separate Root-selected data. P0 data is neither read nor decoded here."""
    live(outer_end);need(type(raw) is bytes and len(raw)<=2*1024**2 and digest(raw)==pin(wanted),'prep-template-pin')
    value=decode(raw)
    need(type(value) is dict and set(value)=={'schema_version','purpose','plan','packet','grant','runtime','publication','source_transfer_interval'} and
         value['schema_version']==1 and value['purpose']=='Root-selected-P0-preparation-template','prep-template')
    source_transfer_selection(value['source_transfer_interval'])
    plan,grant,runtime=value['plan'],value['grant'],value['runtime']
    need(all(type(value[key]) is dict for key in ('plan','packet','grant','runtime','publication')) and
         set(plan)=={'schema_version','purpose','source_commit','run_id','run_attempt','nonce','work_seconds','cleanup_seconds','cache_mode','url_overrides','input_successor'} and
         plan['schema_version']==1 and plan['purpose']=='reviewed-installer-P0-preparation' and
         type(plan['work_seconds']) is int and plan['work_seconds']==1800 and
         type(plan['cleanup_seconds']) is int and plan['cleanup_seconds']==1890 and
         plan['cache_mode'] in ('warm-only','selected-HTTPS'),'prep-selection')
    need(type(plan['url_overrides']) is dict and not plan['url_overrides'],'prep-fixed-four-seed-no-URLs')
    input_successor(plan['input_successor']);input_successor(grant.get('input_successor'))
    need(expected==environment.get('GITHUB_SHA')==environment.get('GITHUB_WORKFLOW_SHA') and
         type(expected) is str and re.fullmatch('[0-9a-f]{40}',expected) and
         environment.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi' and
         environment.get('GITHUB_WORKFLOW_REF')=='Gabriel-Kahen/cachy-asahi/.github/workflows/native-arm-p0.yml@refs/heads/codex/signer-native-runtime-v1',
         'prep-job-context')
    for target in (plan,grant):
        for key,actual in (('source_commit',expected),('run_id',environment.get('GITHUB_RUN_ID')),
                           ('run_attempt',environment.get('GITHUB_RUN_ATTEMPT'))):
            need(target.get(key,'ABSENT') is None,'prep-template-job');target[key]=actual
    need(plan['nonce'] is None,'prep-template-nonce');plan['nonce']=os.urandom(16).hex()
    need(re.fullmatch('[1-9][0-9]{0,19}',plan['run_id']) and re.fullmatch('[1-9][0-9]{0,9}',plan['run_attempt']) and
         grant.get('purpose')=='reviewed-installer-P0-preparation' and grant.get('added_seconds')==0 and
         type(grant.get('added_seconds')) is int and value['packet'].get('composition')==COMPOSITION and
         len(value['packet'].get('source_files',{}))==269 and grant.get('source_files')==value['packet']['source_files'],
         'prep-grant-scope')
    callback={'path':OWN,'module':__name__,'qualname':'Preparation.prepare'}
    need(grant.get('callbacks',{}).get('existing_consumers')==callback and
         grant.get('actor_contract_sha256','ABSENT') is None and grant.get('initial_invocation_sha256','ABSENT') is None,
         'prep-callback')
    view=grant['original_view']
    need(view.get('purpose')=='P0-157-held-2-overlay-copy-view' and view.get('root','ABSENT') is None and
         view.get('full_source_root','ABSENT') is None,'prep-view')
    view['root']=str(output/'unused-original-view');view['full_source_root']=str(root)
    need(set(runtime)=={'docker','gpg_sha256','gpg_env'} and set(runtime['docker'])=={'cli_sha256','endpoint_identity','env'} and
         type(runtime['docker']['endpoint_identity']) in (tuple,list) and len(runtime['docker']['endpoint_identity'])==6 and
         all(type(item) is int and item>=0 for item in runtime['docker']['endpoint_identity']),'prep-runtime')
    pin(runtime['docker']['cli_sha256']);pin(runtime['gpg_sha256'])
    docker=runtime['docker']['env'];gpg=runtime['gpg_env']
    need(type(docker) is dict and set(docker)=={'PATH','HOME','DOCKER_CONFIG','DOCKER_HOST','DOCKER_BUILDKIT','LC_ALL','TMPDIR'} and
         docker['PATH']=='/usr/bin:/bin' and docker['LC_ALL']=='C' and docker['DOCKER_HOST']=='unix:///run/docker.sock' and
         docker['DOCKER_BUILDKIT']=='0' and type(gpg) is dict and set(gpg)=={'PATH','HOME','LC_ALL','TMPDIR'} and
         gpg['PATH']=='/usr/bin:/bin' and gpg['LC_ALL']=='C','prep-environment')
    for namespace,keys,prefix in ((docker,('HOME','DOCKER_CONFIG','TMPDIR'),'docker'),(gpg,('HOME','TMPDIR'),'gpg')):
        for key in keys:
            need(namespace[key] is None,'prep-private-template');namespace[key]=str(output/(prefix+'-'+key.lower()))
    grant['actor_contract_sha256']=digest(encoded(runtime))
    grant['initial_invocation_sha256']=digest(encoded({'stage':'prepare-image-only','output':str(output)}))
    interval=value['source_transfer_interval']
    if interval['selected']:
        interval.update(source_commit=expected,source_root=str(root),source_rows_sha256=digest(encoded(grant['source_files'])),
            grant_sha256=digest(encoded(grant)),run_id=plan['run_id'],run_attempt=plan['run_attempt'])
    end=min(entry+1800,outer_end-90);cleanup_end=min(entry+1890,outer_end)
    live(end);need(entry<=time.monotonic()<end<cleanup_end,'prep-original-frame')
    return value,end,cleanup_end


def publication_bodies(root,packet,publication,expected,end):
    """Raw closure and published workflow before any project compile/exec."""
    need(type(packet.get('source_files')) is dict and len(packet['source_files'])==269 and
         OWN in packet['source_files'] and type(publication) is dict and
         publication.get('Source')==publication.get('remote')==expected and
         publication.get('branch')=='codex/signer-native-runtime-v1' and type(publication.get('files')) is list,
         'prep-publication')
    bodies={};total=0
    for name,wanted in sorted(packet['source_files'].items()):
        need(type(name) is str and name and not Path(name).is_absolute() and '..' not in Path(name).parts,'prep-source-path')
        bodies[name]=read(root/name,end,wanted=wanted,limit=8*1024**2);total+=len(bodies[name])
        need(total<=64*1024**2,'prep-source-total')
    rows={}
    for row in publication['files']:
        need(type(row) is dict and set(row)=={'path','bytes','mode','sha256'} and row['path'] not in rows,'prep-publication-row')
        path=row['path'];need(path in bodies or path==WORKFLOW,'prep-publication-row')
        body=bodies[path] if path in bodies else read(root/path,end,wanted={'sha256':row['sha256'],'mode':row['mode']})
        need(row['bytes']==len(body) and row['sha256']==digest(body) and row['mode']==0o644,'prep-publication-row')
        rows[path]=row
    required={OWN,WORKFLOW,'scripts/install/p0_entry.py','scripts/ci/development/p0_native_arm.py',
              'scripts/port/repository-native-handoff/transport.py','scripts/port/repository-native-handoff/source-map.json',
              *(path for _,path in MODULES)}
    need(required<=rows.keys(),'prep-publication-closure')
    for path,row in PROJECT_BOOTSTRAP_ROWS.items():
        need(row=={'bytes':len(bodies[path]),'mode':packet['source_files'][path]['mode'],'sha256':digest(bodies[path])},'prep-bootstrap-body')
    return bodies


def actual_preparation(value,expected,environment,entry):
    frame=sys._getframe(2)
    need(frame.f_code is pipeline.__code__ and frame.f_globals is globals() and
         sys.modules.get(__name__).__dict__ is globals(),'p0-preparation-route')
    owner=frame.f_locals.get('owner')
    need(type(owner) is Preparation and frame.f_locals.get('prepared') is value and
         frame.f_locals.get('p0_entry')==entry and owner.image==value.get('image') and
         owner.packages is not None and owner.tag_confirmed is True and
         type(owner.sources) is owner.sdk.Sources and
         owner.sources.grant['purpose']=='reviewed-installer-P0-preparation','p0-preparation-origin')
    owner.sources.guard(min(entry+60,owner.cleanup_end))
    fields={'schema_version','purpose','Source','run_id','run_attempt','tag','image','packages_b64','packages_sha256',
        'inputs_sha256','cleanup_end','inventory_name','tag_before_absent','tag_after_id','global_digest_owned',
        'preparation_plan_sha256','preparation_source_rows_sha256','current_inputs_b64','input_successor'}
    need(type(value) is dict and set(value)==fields and value['schema_version']==1 and
         value['purpose']=='ACTUAL_SAME_JOB_P0_PREPARATION' and value['Source']==expected and
         value['run_id']==environment.get('GITHUB_RUN_ID') and value['run_attempt']==environment.get('GITHUB_RUN_ATTEMPT') and
         value['inputs_sha256']==INPUTS_SHA and value['packages_sha256']==PACKAGES_SHA and
         value['tag_before_absent'] is True and value['global_digest_owned'] is False and
         value['tag_after_id']==value['image'] and re.fullmatch('sha256:[0-9a-f]{64}',value['image']) and
         finite(value['cleanup_end']) and entry<value['cleanup_end'],'p0-actual-preparation')
    input_successor(value['input_successor'])
    for key in ('preparation_plan_sha256','preparation_source_rows_sha256'):pin(value[key])
    packages=base64.b64decode(value['packages_b64'],validate=True)
    need(len(packages)==6674 and digest(packages)==PACKAGES_SHA and packages==owner.packages,
         'p0-actual-packages')
    need(type(value['current_inputs_b64']) is str and len(value['current_inputs_b64'])==437468,'p0-input-pin')
    current_raw=base64.b64decode(value['current_inputs_b64'],validate=True)
    need(len(current_raw)==328101 and digest(current_raw)==INPUTS_SHA and current_raw==owner.current_inputs_raw and
         current_raw==current_inputs(owner.sources.raw['scripts/ci/inputs.lock.json']) and
         base64.b64encode(current_raw).decode('ascii')==value['current_inputs_b64'],'p0-input-pin')
    return packages


def packed_template(value):
    need(type(value) is str,'template-packed')
    raw=base64.b64decode(value,validate=True);need(len(raw)<=65536,'template-packed-cap')
    decoder=zlib.decompressobj();data=decoder.decompress(raw,2*1024**2+1)
    need(len(data)<=2*1024**2 and decoder.eof and not decoder.unconsumed_tail and not decoder.unused_data,'template-decoded-cap')
    return data


def pipeline(*,entry,outer_end,expected_source_commit,source_root,work_root,cache,prep_template_raw,prep_template_sha256):
    """Future Root-selected preparation, fresh P0, and original-bound tag retirement."""
    global _DOWNLOAD_LATCH
    _DOWNLOAD_LATCH=None
    need(finite(entry) and finite(outer_end) and entry<=time.monotonic()<outer_end,'prep-original-entry')
    root=Path(source_root);output=Path(work_root);cache=Path(cache)
    need(root==Path.cwd().resolve() and all(p.is_absolute() and '..' not in p.parts for p in (output,cache)) and
         not output.is_relative_to(root) and not cache.is_relative_to(root) and not output.is_relative_to(cache) and
         not cache.is_relative_to(output) and not output.exists() and not output.is_symlink(),'prep-paths')
    selection,end,cleanup_end=preparation_template(prep_template_raw,prep_template_sha256,entry=entry,outer_end=outer_end,
        expected=expected_source_commit,environment=os.environ,output=output,root=root)
    # Scrub before project loading and the existing Git preflight/tool actors.
    private_chunks=take_four(os.environ)
    packet_data=selection['packet'];bodies=publication_bodies(root,packet_data,selection['publication'],expected_source_commit,end)
    registered={};owner=None;first=None;result=None;prepared=None
    alarm_handler=None;alarm_saved=False;timer_attempted=False
    previous_path=list(sys.path)
    operation='load-preparation'
    try:
        packet=load_preparation(bodies,root,registered)
        operation='verify-preparation-packet'
        # Actual repository/Source relation is checked by the existing verifier before actor construction.
        need(packet.preflight_composed(root,root/packet.LOCK,digest(encoded(packet_data)),expected_source_commit,
             composition=COMPOSITION)==packet_data,'prep-packet-drift')
        operation='load-preparation-sources'
        sdk,sources,transport,native=prep_sources(root,packet_data,encoded(selection['grant']),
            digest(encoded(selection['grant'])),end,registered)
        operation='initialize-preparation'
        live(end);output.mkdir(mode=0o700)
        if not cache.exists():
            need(selection['plan']['cache_mode']=='selected-HTTPS' and not cache.is_symlink(),'prep-cache-selection')
            cache.mkdir(mode=0o700)
        runtime=selection['runtime']
        for name in (*runtime['docker']['env'].values(),*runtime['gpg_env'].values()):
            if type(name) is str and name.startswith(str(output)+'/'):
                path=Path(name);live(end);need(not path.exists() and not path.is_symlink(),'prep-private-fresh');path.mkdir(mode=0o700)
        current_raw=current_inputs(sources.raw['scripts/ci/inputs.lock.json'])
        plan={**selection['plan'],'inputs':decode(current_raw),'current_inputs_raw':current_raw,
              'plan_sha256':digest(encoded(selection['plan']))}
        need(digest(sources.raw['scripts/ci/inputs.lock.json'])==SOURCE_INPUTS_SHA,'prep-inputs')
        owner=Preparation(sources,sdk,transport,native,plan,runtime,output,cache,end,cleanup_end,private_chunks,selection['source_transfer_interval'])
        need(signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0),'prep-existing-timer')
        alarm_handler=signal.getsignal(signal.SIGALRM);alarm_saved=True
        def expired(number,frame):
            error=KeyboardInterrupt('prep-original-end')
            if owner.alarm_interrupt is None:owner.alarm_interrupt=error
            raise error
        try:signal.signal(signal.SIGALRM,expired)
        except BaseException as error:raise merge(None,error)
        timer_attempted=True
        try:signal.setitimer(signal.ITIMER_REAL,end-time.monotonic())
        except BaseException as error:raise merge(None,error)
        operation='prepare-image'
        with transport.prep_handlers(transport.Events(),cleanup_end):prepared=owner.prepare()
        operation='finish-preparation'
        try:signal.setitimer(signal.ITIMER_REAL,0)
        except BaseException as error:raise merge(None,error)
        timer_attempted=False
        try:signal.signal(signal.SIGALRM,alarm_handler)
        except BaseException as error:raise merge(None,error)
        alarm_saved=False
        live(end)
        # Remove only the proved preparation alias before the original-view importer owns it.
        package=registered['package_checks']
        need(sys.modules.get('package_checks') is package,'prep-package-retirement');del sys.modules['package_checks']
        del registered['package_checks']
        p0_entry=time.monotonic()  # First P0 timestamp, before any P0 bundle read/decode.
        p0_end=min(p0_entry+60,cleanup_end-15);live(p0_end)
        operation='materialize-P0'
        bundle=packed_template(os.environ['P0_PRIVATE_BUNDLE_ZLIB_B64'])
        private=output/'p0-private';p0_output=output/'p0';p0_cache=output/'p0-cache'
        pins=materialize(entry=p0_entry,outer_end=p0_end,root=root,private=private,output=p0_output,cache=p0_cache,
            expected_source_commit=expected_source_commit,bundle_raw=bundle,
            bundle_sha256=os.environ['P0_PRIVATE_BUNDLE_SHA256'],environment=os.environ,preparation=prepared)
        operation='run-P0'
        result=run(entry=p0_entry,outer_end=p0_end,expected_source_commit=expected_source_commit,source_root=root,
            private_root=private,output=p0_output,cache=p0_cache,input_pins=pins)
    except BaseException as error:
        first=error
        mark_pipeline_failure(first, operation)
    finally:
        private_chunks.clear()
        if timer_attempted:
            try:signal.setitimer(signal.ITIMER_REAL,0)
            except BaseException as error:first=merge(first,error)
        if alarm_saved:
            try:signal.signal(signal.SIGALRM,alarm_handler)
            except BaseException as error:first=merge(first,error)
        if owner is not None:
            try:first=owner.retire_image(first)
            except BaseException as error:first=merge(first,error)
            try:first=owner.close_fds(first)
            except BaseException as error:first=merge(first,error)
        for name,module in registered.items():
            try:
                need(sys.modules.get(name) is module,'prep-registry-retirement')
                # Quarantine has an independent strong Root module anchor; never delete that anchor.
                del sys.modules[name]
            except BaseException as error:first=merge(first,error)
        try:sys.path[:]=previous_path
        except BaseException as error:first=merge(first,error)
        try:live(cleanup_end)
        except BaseException as error:
            if first is None:first=error
        if owner is not None and (owner.cancelled or owner.uncertain):
            if first is None:first=ValueError('prep-sticky-failure')
            if owner.cancelled:BaseException.__setattr__(first,'native_preflight_cancelled',True)
            if owner.uncertain:BaseException.__setattr__(first,'native_preflight_cleanup_uncertain',True)
    if first is not None:
        mark_pipeline_failure(first, 'pipeline-cleanup')
        latch_download(owner,first)
        raise first
    need(owner is not None and owner.tag_retired and type(result) is dict and result.get('status')=='PASS_P0_ONLY','prep-P0-complete')
    return {'status':'PASS_PREPARATION_AND_P0','P0':result,'image_tag_retired':True,
            'global_digest_absence_claimed':False,'ABI':'NOT_RUN','matrix':'NOT_RUN'}


def take_four(environment):
    return {name:environment.pop(name) for name in tuple(environment)
            if name.startswith(('CACHY_OLD_FOUR_','CACHY_RETAINED_'))}


def decode_four(captured,raw,deadline):
    """Separate exact old-four and retained-bubblewrap schemas in the original frame."""
    live(deadline);need(type(raw) is bytes and digest(raw)==INPUTS_SHA,'prep-fixed-four-inputs')
    rows=(('jbigkit-2.1-8-aarch64.pkg.tar.xz','JBIGKIT',2),
          ('jbigkit-2.1-8-aarch64.pkg.tar.xz.sig','JBIGKIT_SIG',1),
          ('libtiff-4.7.2-1-aarch64.pkg.tar.xz','LIBTIFF',15),
          ('libtiff-4.7.2-1-aarch64.pkg.tar.xz.sig','LIBTIFF_SIG',1))
    prefix='CACHY_OLD_FOUR_'
    headers={prefix+'SCHEMA',prefix+'SOURCE_EPOCH'}
    names={prefix+tag+'_'+str(index).zfill(2) for _,tag,count in rows for index in range(1,count+1)}
    need(type(captured) is dict and all(type(name) is str for name in captured) and
         {name for name in captured if name.startswith(prefix)}==names|headers and
         captured[prefix+'SCHEMA']=='1' and captured[prefix+'SOURCE_EPOCH']=='1791748800',
         'prep-fixed-four-schema')
    retained='CACHY_RETAINED_BUBBLEWRAP_V1_'
    retained_rows=(('bubblewrap-0.13.0-1-aarch64.pkg.tar.xz','PACKAGE',2),
                   ('bubblewrap-0.13.0-1-aarch64.pkg.tar.xz.sig','SIGNATURE',1))
    retained_names={retained+tag+'_'+str(index).zfill(2) for _,tag,count in retained_rows for index in range(1,count+1)}
    need(set(captured)==names|headers|retained_names,'prep-fixed-four-schema')
    decoded=[]
    try:
        for name,tag,count in rows:
            live(deadline);size,wanted=OVERRIDE_ROWS[name];length=4*((size+2)//3)
            need(count==(length+32767)//32768,'prep-fixed-four-count')
            parts=[]
            for index in range(1,count+1):
                live(deadline);part=captured.pop(prefix+tag+'_'+str(index).zfill(2))
                need(type(part) is str and len(part)==min(32768,length-(index-1)*32768) and
                     re.fullmatch('[A-Za-z0-9+/]*={0,2}',part) is not None,'prep-fixed-four-chunk')
                parts.append(part)
            text=''.join(parts);body=base64.b64decode(text.encode('ascii'),validate=True);live(deadline)
            need(base64.b64encode(body).decode('ascii')==text and len(body)==size and digest(body)==wanted,
                 'prep-fixed-four-bytes')
            decoded.append((name,body))
        need(sum(len(body) for _,body in decoded)==404428,'prep-fixed-four-total')
        for name,tag,count in retained_rows:
            live(deadline);size,wanted=OVERRIDE_ROWS[name];length=4*((size+2)//3)
            need(count==(length+32767)//32768,'prep-fixed-four-count')
            parts=[]
            for index in range(1,count+1):
                live(deadline);part=captured.pop(retained+tag+'_'+str(index).zfill(2))
                need(type(part) is str and len(part)==min(32768,length-(index-1)*32768) and
                     re.fullmatch('[A-Za-z0-9+/]*={0,2}',part) is not None,'prep-fixed-four-chunk')
                parts.append(part)
            text=''.join(parts);body=base64.b64decode(text.encode('ascii'),validate=True);live(deadline)
            need(base64.b64encode(body).decode('ascii')==text and len(body)==size and digest(body)==wanted,
                 'prep-fixed-four-bytes')
            decoded.append((name,body))
        need(sum(len(body) for _,body in decoded)==445422,'prep-fixed-four-total')
        live(deadline);return decoded
    finally:captured.clear()

#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Finite audio dispatch over the exact maintained Controller/Executor.

Only context dispatch and __file__ (the owner re-entry/code identity) differ.
The actual Controller, Executor, supervision, kernel/PIDFD and storage methods
are compiled unchanged. Import performs no probe, syscall qualification or role.
"""
import hashlib
from pathlib import Path
import sys
import types

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[2]
HELD_MEMBER = 'scripts/ci/first-login-enrollment-native-source/payload/native/owned_executor_current_v3.py'
HELD_PIN = {'bytes': 53735, 'sha256': 'aee41c0956f3249eef2e9c8974238b214622cb385e2d8f736109d9650ce7120a'}
CONTEXT_PIN = {'bytes': 8860, 'sha256': '6705f668f3dd257a251b4c674896dc6412f749580d54e3e12e6e5779515fcef3'}


def _load_context():
    path = HERE / 'context.py'
    raw = path.read_bytes()
    if {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()} != CONTEXT_PIN:
        raise ValueError('EXACT_AUDIO_CONTEXT_BEFORE_IMPORT')
    value = types.ModuleType('_bankstown_qt3_controller_context')
    value.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


C = _load_context()


def implementation():
    raw = (SOURCE / HELD_MEMBER).read_bytes()
    C.need({'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()} == HELD_PIN,
           'EXACT_MAINTAINED_EXECUTOR_REQUIRED')
    module = types.ModuleType('_bankstown_qt3_isolated_maintained_executor')
    # The unchanged Controller.execute uses this value to launch THIS wrapper;
    # unchanged admitted_inputs and owner_main then bind its whole Root pin.
    module.__file__ = str(HERE / 'controller.py')
    exec(compile(raw, str(SOURCE / HELD_MEMBER), 'exec'), module.__dict__)
    module.context_contract = C.context_contract
    return module


E = implementation()
Controller, Executor, CommandEngine = E.Controller, E.Executor, E.CommandEngine
admitted_inputs = E.admitted_inputs
_controller_main, _owner_main = E.controller_main, E.owner_main


def request_gate(d, value):
    E.need(E.pin(E.encoded(value)) == d['inputs_pin'], 'ROOT_SELECTED_AUDIO_REQUEST_PIN')
    return value


def controller_main(args):
    root = Path(args.source_root)
    raw = E.read_data(args.delegation)
    context = C.decode(E.read_data(args.context))
    d, _, _, _ = E.admitted_inputs(root, raw, args.delegation_sha256, context)
    request_raw = E.read_data(args.inputs)
    request = C.decode(request_raw)
    E.need(request_raw == E.encoded(request), 'CANONICAL_AUDIO_REQUEST')
    request_gate(d, request)
    return _controller_main(args)


def owner_main(launch_path):
    launch = C.decode(E.read_data(launch_path))
    d, _, _, _ = E.admitted_inputs(Path(launch['source_root']), E.encoded(launch['delegation']),
                                 launch['context']['delegation_pin']['sha256'], launch['context'])
    request_gate(d, launch['inputs'])
    return _owner_main(launch_path)


# Entry dispatch gains request binding; held role methods and cleanup stay intact.
E.controller_main, E.owner_main = controller_main, owner_main
main = E.main


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('HOLD_BANKSTOWN_QT3_EXECUTOR: '+type(error).__name__+': '+str(error)[:240], file=sys.stderr)
        raise SystemExit(2)

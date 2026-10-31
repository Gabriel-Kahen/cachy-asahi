#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit pinned host qualification only; default reports NOT_RUN.

Capture observes this host's identities. Check executes self-contained metadata
fixtures and one small generated-root control, never retained package inputs.
"""
import argparse
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import signal
import sys
import types
import unittest

ROOT=Path(__file__).resolve().parents[2]
HOST_FIXTURES_SHA='41d6c400f35c6844ff38f3d82eda25ad905938f38cb0d291e3234ba283f8c07d'


def loaded(path):
    raw=path.read_bytes();module=types.ModuleType('_host_component_bridge');module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__);return module


def main():
    parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='mode')
    for mode,inputs in [('capture',('metadata-configuration','tool-configuration')),
                        ('check',('metadata-profile','tool-profile','root-policy'))]:
        branch=sub.add_parser(mode)
        for name in inputs:
            branch.add_argument('--'+name,required=True);branch.add_argument('--'+name+'-sha256',required=True)
        branch.add_argument('--output',required=True)
    args=parser.parse_args()
    if args.mode is None:
        print(json.dumps({'status':'NOT_RUN','reason':'EXPLICIT_CAPTURE_OR_PINNED_HOST_CHECK_REQUIRED',
                          'native_actor_executed':False}));return
    resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3));resource.setrlimit(resource.RLIMIT_CPU,(180,180))
    resource.setrlimit(resource.RLIMIT_FSIZE,(64*1024**2,64*1024**2));resource.setrlimit(resource.RLIMIT_NOFILE,(256,256))
    def expired(*_):raise TimeoutError('host-component-wall180')
    signal.signal(signal.SIGALRM,expired);signal.alarm(180)
    bridge=loaded(ROOT/'scripts/platform/metadata_gated_ext4.py');modules=bridge.sources()
    fields=('metadata-configuration','tool-configuration') if args.mode=='capture' else ('metadata-profile','tool-profile','root-policy')
    values={name:json.loads(bridge.pinned(getattr(args,name.replace('-','_')),
                    getattr(args,(name+'-sha256').replace('-','_')))) for name in fields}
    output=Path(args.output).absolute();bridge.need(output.parent==output.parent.resolve(),'output-parent')
    output.mkdir(mode=0o700);(output/'INCOMPLETE.json').write_bytes(bridge.encoded({'status':'INCOMPLETE_NOT_ACCEPTED'}))
    try:
        actors=output/'actors';actors.mkdir(mode=0o700)
        modules['encoder'].ACTOR_DIRECTORY=actors
        if args.mode=='capture':
            metadata=modules['metadata'].pins(values['metadata-configuration'])
            tools=modules['encoder'].tool_pins(values['tool-configuration'])
            (output/'metadata-profile.json').write_bytes(bridge.encoded(metadata))
            (output/'tool-profile.json').write_bytes(bridge.encoded(tools))
            receipt=dict(status='CAPTURED_HOST_IDENTITIES_NOT_QUALIFIED',metadata_profile_sha256=bridge.sha(bridge.encoded(metadata)),
                         tool_profile_sha256=bridge.sha(bridge.encoded(tools)),host_component_validation='NOT_RUN')
        else:
            metadata,tools=values['metadata-profile'],values['tool-profile']
            bridge.need(metadata==modules['metadata'].pins(metadata.get('configuration')) and
                        tools==modules['encoder'].tool_pins(tools.get('configuration')),'host-profile-mismatch')
            path=ROOT/'tests/platform/host_metadata_fixtures.py'
            raw=bridge.pinned(path,HOST_FIXTURES_SHA)
            fixtures=types.ModuleType('_explicit_host_metadata_fixtures');fixtures.__file__=str(path)
            exec(compile(raw,str(path),'exec'),fixtures.__dict__)
            fixtures.module=modules['metadata'];fixtures.NATIVE_PINS=metadata;fixtures.OUTPUT=output
            log=io.StringIO()
            with contextlib.redirect_stdout(log):
                result=unittest.TextTestRunner(stream=log,verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(fixtures))
            (output/'metadata-fixtures.log').write_text(log.getvalue())
            bridge.need(result.wasSuccessful() and result.testsRun==8 and not result.skipped,'host-metadata-fixtures-failed')
            proof=bridge.root_proof(modules['encoder'],values['root-policy'],tools,1700000000,output/'root-proof')
            (output/'root-proof.json').write_bytes(bridge.encoded(proof))
            receipt=dict(status='PASS_EXPLICIT_PINNED_HOST_COMPONENTS_ONLY',metadata_profile_sha256=bridge.sha(bridge.encoded(metadata)),
                tool_profile_sha256=bridge.sha(bridge.encoded(tools)),metadata_methods=result.testsRun,
                generated_root_image=proof['filesystem']['image'],root_integrity_exit_code=proof['filesystem']['calls'][-1]['exit_code'],
                package_archives_read=False,real_package_pair_executed=False,native_ARM_boot_M2_release_accepted=False)
        bridge.check_sources()
        receipt.update(checker_sha256=bridge.sha(Path(__file__).read_bytes()),fixture_sha256=HOST_FIXTURES_SHA,
                       source_pins={k:dict(path=v[0],sha256=v[1]) for k,v in bridge.SOURCE_PINS.items()},host=dict(system=sys.platform,machine=os.uname().machine))
        with (output/'receipt.pending.json').open('xb') as stream:
            stream.write(bridge.encoded(receipt));stream.flush();os.fsync(stream.fileno())
        (output/'INCOMPLETE.json').unlink();os.rename(output/'receipt.pending.json',output/'receipt.json')
        signal.alarm(0);print(json.dumps({'status':receipt['status'],'output':str(output)},sort_keys=True))
    except BaseException as exc:
        (output/'failure.json').write_bytes(bridge.encoded(dict(status='REFUSED_NOT_QUALIFIED',error_type=type(exc).__name__,actual_error=str(exc))))
        raise


if __name__=='__main__':main()

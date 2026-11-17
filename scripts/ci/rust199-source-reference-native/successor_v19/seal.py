#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Seal the unbound operational constructor; issue no Source or authority."""
import argparse
import importlib.util
from pathlib import Path
import resource

HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


P = module('v19_unbound_constructor_seal', HERE / 'prepare.py')


def review(parent):
    before = P.capture(parent)
    P.fs.need(P.D.render_leaves(before) == P.D.payload_leaves(), 'whole genuine367 operational projection')
    P.embedded()
    bridge = P.fs.snapshot(HERE / 'payload')
    P.fs.need(set(bridge) == {P.BRIDGE} and bridge[P.BRIDGE][0].count(b'CONFIG_PIN=None') == 1,
              'unbound separate bridge; no actual provider config')
    P.fs.need(not any((HERE / name).exists() for name in (
        'constructor-profile.json', 'prospective.DATA.json', 'payload/' + P.CONFIG)),
        'no issued real policy/profile/Source')
    unbound = P.fs.decode(P.fs.read(HERE / 'UNBOUND.DATA.json')[0])
    P.fs.need(unbound['actual'] == P.ACTUAL and unbound['provider_policy'] is None
        and unbound['Root_provider_decision'] is None and unbound['constructor_profile'] is None
        and unbound['llhttp_archive_signature_TEST_key_source_license_native_receipts'] is None
        and unbound['libgit2_archive_signature_TEST_key_source_license_native_receipts'] is None
        and unbound['Root_grants'] is unbound['dispatch'] is unbound['runtime'] is unbound['Root_acceptance'] is None
        and all(unbound[key] is False for key in ('native_acceptance', 'release_acceptance', 'ALARM_authentication')),
        'all actual provider, runtime and acceptance operands remain unbound')
    chain = [P.identity(before)]; current = before
    for version, count in ((17, 364), (16, 361), (15, 355), (14, 351), (13, 344), (12, 340)):
        prior = current
        q = module('v19_predecessor_inverse_' + str(version), HERE.parent / ('successor_v' + str(version)) / 'prepare.py')
        current = q.undo(prior)
        P.fs.need(len(current) == count and q.render(current) == prior, 'whole predecessor inverse and re-render')
        chain.append(P.identity(current))
    return dict(schema=19, status='UNBOUND_OPERATIONAL_CONSTRUCTOR_SEALED_DATA_ONLY', parent=P.PARENT,
        constructor_files=P.inputs(), whole_predecessor_chain=chain, embedded_helpers=P.fs.descriptors(P.embedded()),
        source_identity=None, constructor_profile=None, provider_policy=None, Root_provider_decision=None,
        native='NOT RUN', runtime='NOT RUN', signing='NOT RUN', publication='NOT RUN',
        Root_grants=None, dispatch=None, actual=P.ACTUAL, unadmitted=True)


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2,) * 2)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True); parser.add_argument('--write', action='store_true')
    args = parser.parse_args(); raw = P.encode(review(args.parent)); path = HERE / 'development-seal.DATA.json'
    if args.write:
        with path.open('xb') as stream: stream.write(raw)
    else:
        P.fs.need(P.fs.read(path)[0] == raw, 'complete unbound constructor seal differs')
    print(P.encode(dict(status='PASS_EXACT_UNBOUND_OPERATIONAL_SEAL', seal=P.fs.pin(raw),
                        Source_issued=False, Root_grants=None)).decode(), end='')

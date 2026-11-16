#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Construct one unissued warm-control source from externally selected public DATA."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys

HERE = Path(__file__).resolve().parent

def module(name, root=HERE):
    spec = importlib.util.spec_from_file_location('warm_source_'+name, root/(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

V = module('verify')
OLD = HERE/'predecessor'/'arm16k_no_package_control'
K = module('contracts', OLD)
P = module('plan', OLD)
FIXED_CONTROL = dict(
    source_lock=dict(bytes=3732, sha256=V.LOCKS['arm16k_no_package_control']),
    observations=dict(bytes=10140, sha256='aad212908bfa20e9f7b6b326f02ee7e360b9d63467d3c8ed36a41727cd54cd0f'),
    report=dict(bytes=21241, sha256='c60358f08263973e5fabf8268366aa12a43c357b42fe0a77efe62f56529f3cef'),
    terminal_closure=dict(bytes=1371, sha256='9afa27cdd182cbaef4cf307069f9b4e6426ccbcc247d4944f8e57823bee13002'),
    outer_result=dict(bytes=3677, sha256='d577d6c904c2321faf7059caa056d88b804e90f035067b84403c403e8c83c6c5'),
    overlay=dict(bytes=19660800, sha256='8a6aa8f2ccd64e1bfcb2a6a6ec0f573d5e768a7d864da37cb5d32538e13edcbb'),
    package_transaction=False, normal_PAM_logout=True,
    scope='ACCEPT_FINITE_OBSERVATION_AND_CLEANUP_ONLY', next_boot_stability='NOT_RUN')


def selection(value):
    K.keys(value, ('kind', 'original_baseline', 'comparison_source65', 'control',
        'conversion', 'warmed_baseline', 'packages', 'baseline_nonce', 'kernel',
        'tool_image', 'actor_tools'), 'one warm baseline selection')
    K.need(value['kind'] == 'ROOT_SELECTED_ONE_WARM_PAM_BASELINE_DATA_V1', 'finite warm DATA kind')
    K.need(K.canonical(value['original_baseline']) == K.canonical(P.BASELINE) and
           K.canonical(value['comparison_source65']) == K.canonical(P.SOURCE65['lock']) and
           K.canonical(value['control']) == K.canonical(FIXED_CONTROL), 'complete exact original baseline control and cleanup provenance')
    K.keys(value['warmed_baseline'], ('raw', 'prepared', 'certificate'), 'warm descriptors')
    for pin in value['warmed_baseline'].values():
        K.pin_shape(pin)
    warm = value['warmed_baseline']
    K.need(warm['raw']['bytes'] == P.BASELINE['raw']['bytes'] and
           all(warm[n] != P.BASELINE[n] for n in warm), 'new exact warm baseline descriptors')
    K.keys(value['conversion'], ('report', 'raw', 'prepared', 'opaque_only', 'original_unchanged'), 'opaque conversion')
    K.pin_shape(value['conversion']['report'])
    K.need(value['conversion']['raw'] == warm['raw'] and value['conversion']['prepared'] == warm['prepared'] and
           value['conversion']['opaque_only'] is value['conversion']['original_unchanged'] is True,
           'complete exact opaque conversion joins')
    K.keys(value['packages'], ('count', 'original_inventory', 'warmed_inventory'), 'fixed package identity')
    packages = value['packages']
    K.pin_shape(packages['original_inventory'])
    K.pin_shape(packages['warmed_inventory'])
    K.need(type(packages['count']) is int and packages['count'] == 111 and
           packages['original_inventory'] == packages['warmed_inventory'], 'same fixed111 package identity')
    nonce = value['baseline_nonce']
    K.need(type(nonce) is str and len(nonce) == 32 and all(c in '0123456789abcdef' for c in nonce), 'original PAM baseline nonce')
    K.keys(value['kernel'], ('Image', 'config'), 'same actual kernel')
    for pin in value['kernel'].values():
        K.pin_shape(pin)
    K.keys(value['actor_tools'], K.TOOLS, 'same six actual tools')
    for pin in value['actor_tools'].values():
        K.pin_shape(pin)
    image = value['tool_image']
    K.need(type(image) is str and image.startswith('sha256:') and K.sha(image[7:]), 'same immutable actual tool image')
    return value


def replace_once(raw, before, after):
    K.need(raw.count(before) == 1, 'exact finite predecessor source edit')
    return raw.replace(before, after)


def bodies(selected):
    """Return exact six-file differences; runtime actor/controller are never rewritten."""
    contract = (OLD/'contracts.py').read_text()
    contract = contract.replace("'ROOT_NO_PACKAGE_CONTROL_INPUTS_V1'", "'ROOT_WARM_NO_PACKAGE_CONTROL_INPUTS_V1'")
    contract = contract.replace("'ROOT_ACCEPTED_ORIGINAL_PAM_BASELINE_DECLARATION_V1'", "'ROOT_ACCEPTED_WARMED_PAM_BASELINE_DECLARATION_V1'")
    contract = replace_once(contract,
        "('kind', 'issued_by', 'accepted', 'raw', 'prepared', 'certificate'), 'original baseline declaration'",
        "('kind', 'issued_by', 'accepted', 'raw', 'prepared', 'certificate', 'provenance'), 'warmed baseline declaration'")
    contract = replace_once(contract,
        "    need({n: baseline[n] for n in plan.BASELINE} == plan.BASELINE, 'exact original accepted baseline pins')",
        "    need({n: baseline[n] for n in plan.BASELINE} == plan.BASELINE, 'exact warmed accepted baseline pins')\n"
        "    need(canonical(baseline['provenance']) == canonical(plan.WARM_SELECTION), 'complete exact warm provenance required')\n"
        "    need(value['baseline_nonce'] == plan.WARM_SELECTION['baseline_nonce'], 'same original PAM baseline nonce')")
    contract = replace_once(contract, "    resources(value['resources'], source, now)",
        "    need({n: kernel[n] for n in ('Image', 'config')} == plan.WARM_SELECTION['kernel'] and\n"
        "         value['tool_image'] == plan.WARM_SELECTION['tool_image'] and\n"
        "         value['actor_tools'] == plan.WARM_SELECTION['actor_tools'], 'same actual kernel tool image and tool pins')\n"
        "    resources(value['resources'], source, now)")
    contract = replace_once(contract, "accepted=None, **local('plan').BASELINE),",
        "accepted=None, provenance=local('plan').WARM_SELECTION, **local('plan').BASELINE),")
    plan = (OLD/'plan.py').read_text()
    baseline_line = next(line for line in plan.splitlines() if line.startswith('BASELINE='))
    plan = replace_once(plan, baseline_line, baseline_line.replace('BASELINE=', 'ORIGINAL_BASELINE=', 1)+
        '\nWARM_SELECTION='+repr(selected)+'\nBASELINE=WARM_SELECTION[\'warmed_baseline\']')
    plan = replace_once(plan, "kind='ARM16K_NO_PACKAGE_CONTROL_DRAFT_V1'", "kind='ARM16K_WARM_NO_PACKAGE_CONTROL_DRAFT_V1'")
    plan = replace_once(plan, 'original_baseline=BASELINE,',
        'original_baseline=ORIGINAL_BASELINE,warm_baseline=BASELINE,warm_provenance=WARM_SELECTION,')
    plan = replace_once(plan,
        'Separate boot/login/logout-class drift from effects requiring the package lifecycle; observation only, no restoration or acceptance waiver',
        'Observe a second normal PAM boot of the exact initialized baseline; observation only, no premarked stability, restoration or acceptance waiver')
    plan = replace_once(plan,
        'same original baseline raw/prepared/certificate and original private PAM credential pins',
        'same exact warmed raw/prepared/Root-selected certificate, complete original/control provenance and original private PAM credential pins')
    test = (OLD/'test_prepare.py').read_text()
    test = test.replace("'ROOT_ACCEPTED_ORIGINAL_PAM_BASELINE_DECLARATION_V1'", "'ROOT_ACCEPTED_WARMED_PAM_BASELINE_DECLARATION_V1'")
    test = test.replace("'ROOT_NO_PACKAGE_CONTROL_INPUTS_V1'", "'ROOT_WARM_NO_PACKAGE_CONTROL_INPUTS_V1'")
    test = replace_once(test, "accepted=True, **copy.deepcopy(K.local('plan').BASELINE))",
        "accepted=True, provenance=copy.deepcopy(K.local('plan').WARM_SELECTION), **copy.deepcopy(K.local('plan').BASELINE))")
    test = replace_once(test, "    out = '/home/gabe/PUBLIC_MODEL/control-output'",
        "    selected = K.local('plan').WARM_SELECTION\n"
        "    packet.update(baseline_nonce=selected['baseline_nonce'], tool_image=selected['tool_image'],\n"
        "        actor_tools=copy.deepcopy(selected['actor_tools']))\n"
        "    packet['kernel'].update(copy.deepcopy(selected['kernel']))\n"
        "    out = '/home/gabe/PUBLIC_MODEL/control-output'")
    return {'plan.py': plan.encode(), 'contracts.py': contract.encode(), 'test_prepare.py': test.encode()}


def construct(selection_path, selection_sha256, output):
    K.need(K.sha(selection_sha256), 'external exact Root-selected public DATA SHA256 required')
    K.need(K.pin(selection_path)['sha256'] == selection_sha256, 'exact external one-warm selection pin')
    public = K.load(selection_path)
    K.need(K.json_pin(public)['sha256'] == selection_sha256, 'exact loaded one-warm selection pin')
    selected = selection(public)
    inverse = V.verify()
    out = K.ordinary(output)
    K.need(not out.exists() and out.parent.is_dir(), 'fresh ordinary source output')
    K.need(all(out != p and out not in p.parents and p not in out.parents for p in (HERE, K.ordinary(selection_path))),
        'source output disjoint from predecessor constructor and public selection')
    shutil.copytree(HERE/'predecessor', out)
    root = out/'arm16k_no_package_control'
    for name, raw in bodies(selected).items():
        (root/name).write_bytes(raw)
    C = module('contracts', root)
    (root/'operator-inputs.TEMPLATE.json').write_bytes(K.canonical(C.input_template()))
    (root/'test_warm.py').write_bytes((HERE/'test_warm.py').read_bytes())
    lock = K.load(OLD/'source.lock.json')
    lock['kind'] = 'ARM16K_WARM_NO_PACKAGE_CONTROL_SOURCE_LOCK_V1'
    lock['predecessor_source_lock'] = FIXED_CONTROL['source_lock']
    lock['warm_selection'] = K.json_pin(selected)
    lock['files'] = {name: row for name, row in V.rows(root).items() if name != 'source.lock.json'}
    (root/'source.lock.json').write_bytes(K.canonical(lock))
    return dict(kind='ONE_WARM_CONTROL_SOURCE_CONSTRUCTION_V1', output=str(out),
        source_lock=K.pin(root/'source.lock.json'), selection=K.json_pin(selected),
        predecessor_inverse=inverse, Root_review=None, Root_authority=None,
        actual_source=None, actual_ref=None, actual_VM=None, baseline_acceptance=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', type=Path, required=True)
    parser.add_argument('--selection-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    K.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, 'isolated bytecode-free source constructor')
    print(K.canonical(construct(args.selection, args.selection_sha256, args.output)).decode(), end='')

if __name__ == '__main__':
    main()

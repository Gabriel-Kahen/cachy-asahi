# SPDX-License-Identifier: MIT
"""Join GUI18 evidence components. This module issues no execution authority."""
import importlib.util
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent


def module(name):
    if name not in ('common', 'archive', 'native', 'runtime', 'lifecycle', 'trust'):
        raise ValueError('finite GUI adapter helper')
    path = HERE / (name+'.py')
    if path.is_symlink() or path.stat().st_nlink != 1:
        raise ValueError('ordinary trusted adapter helper')
    spec = importlib.util.spec_from_file_location('gui18_'+name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


C = module('common')
SCOPE = 'QT612_GUI18_NATIVE_EVIDENCE_COMPONENTS_ONLY_V1'
REFERENCES = ('original_archive', 'signature', 'public_key', 'tampered_archive',
              'current_public_trust', 'producer_binding', 'first_provenance',
              'second_provenance', 'comparison', 'stage', 'installed_snapshot',
              'pacman', 'load', 'offscreen', 'cmake', 'lifecycle_plan',
              'lifecycle_evidence', 'actual_pacman_config')
ACTUAL = dict.fromkeys(('Root_grant', 'source', 'runtime', 'native_acceptance',
                       'capacity_acceptance', 'M2', 'release_acceptance'))


def template():
    return dict(schema=1, kind='QT612_GUI18_NATIVE_ADAPTER_INPUT_SELECTION_V1', scope=SCOPE,
                recipe_commit=C.RECIPE_COMMIT, references=dict.fromkeys(REFERENCES),
                runtime_selection=None, lifecycle_selection=None,
                official_fingerprints=None, official_key_sha256=None,
                actual=dict(ACTUAL), full72_claim=False,
                official_0bd04f_correspondence='HOLD_UNCHANGED')


def selection(raw, external_sha256):
    C.need(type(external_sha256) is str and re.fullmatch('[0-9a-f]{64}', external_sha256)
           and C.pin(raw)['sha256'] == external_sha256, 'externally selected whole evidence request')
    value = C.decode(raw, C.MIB)
    expected = template()
    C.need(raw == C.encode(value) and type(value) is dict and set(value) == set(expected),
           'closed canonical GUI evidence request')
    for key in set(expected) - {'references', 'runtime_selection', 'lifecycle_selection', 'official_fingerprints', 'official_key_sha256'}:
        C.need(C.encode(value[key]) == C.encode(expected[key]), 'fixed unissued GUI request field '+key)
    refs = value['references']
    C.need(type(refs) is dict and set(refs) == set(REFERENCES), 'all finite original operands')
    for name, row in refs.items():
        C.reference(row, 512*C.MIB if name in ('original_archive','tampered_archive') else 64*C.MIB)
    C.need(len({r['path'] for r in refs.values()}) == len(refs), 'distinct original evidence operands')
    C.need(refs['original_archive']['path'].endswith('/'+C.FILENAME)
           and refs['signature']['path'] == refs['original_archive']['path']+'.sig',
           'original GUI package identity and detached signature names')
    for name in ('first_provenance','second_provenance'):
        C.need(refs[name]['path'].endswith('/provenance.json'), 'original normal-builder provenance name')
    C.need(Path(refs['first_provenance']['path']).parent != Path(refs['second_provenance']['path']).parent,
           'two distinct retained clean attempt roots')
    C.need(refs['stage']['path'] == str(Path(refs['first_provenance']['path']).parent /
           'artifacts/qt612-stage-contract.json'), 'original first-attempt stage bytes retained unchanged')
    for key, pattern in (('official_fingerprints','[0-9A-F]{40}'), ('official_key_sha256','[0-9a-f]{64}')):
        rows = value[key]
        C.need(type(rows) is list and rows and rows == sorted(set(rows))
               and all(type(v) is str and re.fullmatch(pattern,v) for v in rows),
               'external complete official-key exclusion custody')
    return value


def pacman_config(raw, plan):
    """Finite local-file transaction config. No includes, sync repositories or exceptions."""
    C.need(type(raw) is bytes and 0 < len(raw) <= 16384, 'bounded original pacman config')
    rows, section = {}, None
    for line in raw.decode('ascii').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('['):
            C.need(line == '[options]' and section is None, 'local-only single pacman options section')
            section = 'options'
            continue
        C.need(section == 'options' and '=' in line, 'explicit finite pacman option')
        key,value = map(str.strip,line.split('=',1))
        C.need(key not in rows, 'no duplicate signature/config options')
        rows[key] = value
    expected = dict(Architecture='aarch64', SigLevel='Required TrustedOnly',
                    LocalFileSigLevel='Required TrustedOnly', GPGDir=plan['pacman'][4])
    C.need(rows == expected, 'actual required trusted-only separate TEST local configuration')
    return C.pin(raw)


def payload(archive):
    result = {}
    for name,row in archive['archive_inventory'].items():
        if name.startswith('.'):
            continue
        value = {k:row[k] for k in ('type','mode','uid','gid')}
        if row['type'] == 'file':
            value.update({k:row[k] for k in ('bytes','sha256')})
        elif row['type'] == 'symlink':
            value['target'] = row['target']
        result['/'+name] = value
    return dict(complete=True, files=result)


def review_components(*, recipe_root, inputs_root, request_raw, request_sha256,
                      work, call, now, retained):
    """Consume separately selected original evidence; never grant native execution.

    Expected hashes, supervisor custody and the complete official-key exclusions
    must originate outside the received DATA. The explicit signature callback is
    the caller's existing supervisor, not a default subprocess implementation.
    Retained native/ALPM/runtime receipts are consistency evidence, not self-
    authenticating proof that an actor ran. Root/C owns that separate decision.
    """
    source = C.inspect_recipe(recipe_root)
    chosen = selection(request_raw, request_sha256)
    root, work = C.canonical_root(inputs_root), C.canonical_root(work)
    C.need(root != work and not root.is_relative_to(work) and not work.is_relative_to(root),
           'disjoint retained input and private work domains')
    refs = chosen['references']
    bodies = {name:C.read_ref(root,row,collect=True) for name,row in refs.items()}
    trust = module('trust').verify(package=bodies['original_archive'], signature=bodies['signature'],
        public_key=bodies['public_key'], tampered_package=bodies['tampered_archive'],
        trust_raw=bodies['current_public_trust'], external_sha=refs['current_public_trust']['sha256'],
        now=now, work=work/'public-verification', call=call,
        official_fingerprints=set(chosen['official_fingerprints']),
        official_key_sha256=set(chosen['official_key_sha256']))
    observed = module('archive').inspect_archive(root/refs['original_archive']['path'],work,recipe_root)
    archive_pin = {k:observed['archive'][k] for k in ('bytes','sha256')}
    C.need(archive_pin == C.pin(bodies['original_archive']), 'same original signed archive bytes')
    first = (root/refs['first_provenance']['path']).parent
    second = (root/refs['second_provenance']['path']).parent
    pair = module('native').validate_pair(first=first, second=second,
        comparison=root/refs['comparison']['path'],recipe_root=recipe_root,work=work,
        binding=C.decode(bodies['producer_binding']))
    C.need(pair['archive_pin'] == archive_pin
           and pair['first_provenance_pin'] == C.pin(bodies['first_provenance'])
           and pair['second_provenance_pin'] == C.pin(bodies['second_provenance'])
           and pair['comparison_pin'] == C.pin(bodies['comparison']),
           'same whole signed archive and both original native receipt operands')
    C.need(C.decode(bodies['stage']) == observed['stage'], 'original stage receipt equals current package bytes')
    runtime_selection = chosen['runtime_selection']
    C.need(type(runtime_selection) is dict and runtime_selection['stage_pin'] == C.pin(bodies['stage'])
           and runtime_selection['snapshot_pin'] == C.pin(bodies['installed_snapshot']),
           'same retained stage and installed snapshot selection')
    snapshot = C.decode(bodies['installed_snapshot'])
    package = snapshot['packages'][C.PACKAGE]
    C.need(package['archive_pin'] == archive_pin and package['signature_pin'] == C.pin(bodies['signature'])
           and package['native_provenance_pin'] == C.pin(bodies['first_provenance']),
           'runtime installed package joins signed native tuple and original first receipt')
    R = module('runtime')
    dependency = R.validate_dependencies(stage_raw=bodies['stage'],stage_pin=C.pin(bodies['stage']),
        snapshot_raw=bodies['installed_snapshot'],snapshot_pin=C.pin(bodies['installed_snapshot']),
        pacman_raw=bodies['pacman'],pacman_pin=C.pin(bodies['pacman']),
        retained=retained,selection=runtime_selection)
    dependency_raw = R.encoded(dependency)
    smoke = R.validate_smoke(dependency_raw=dependency_raw,dependency_pin=R.pin(dependency_raw),
        load_raw=bodies['load'],load_pin=C.pin(bodies['load']),
        offscreen_raw=bodies['offscreen'],offscreen_pin=C.pin(bodies['offscreen']),
        cmake_raw=bodies['cmake'],cmake_pin=C.pin(bodies['cmake']),retained=retained)
    plan = C.decode(bodies['lifecycle_plan'])
    C.need(plan['gui_package']['pin'] == archive_pin
           and plan['gui_package']['payload'] == payload(observed)
           and plan['gui_package']['depends'] == sorted(source['contract']['dependencies']['runtime']),
           'lifecycle package descriptor joins complete original GUI payload and normal dependencies')
    config_pin = pacman_config(bodies['actual_pacman_config'],plan)
    life_selection = chosen['lifecycle_selection']
    C.need(type(life_selection) is dict and life_selection['image'] == runtime_selection['image']
           and life_selection['supervisor'] == dependency['supervisor'],
           'lifecycle and runtime use the same externally selected image/supervisor')
    lifecycle = module('lifecycle').validate_evidence(plan,C.decode(bodies['lifecycle_evidence']),
                                                     selection=life_selection)
    for row in refs.values():
        C.read_ref(root,row,collect=False)
    return dict(schema=1,kind='QT612_GUI18_EVIDENCE_COMPONENT_JOIN_DATA_ONLY',scope=SCOPE,
        request_pin=C.pin(request_raw),recipe_commit=C.RECIPE_COMMIT,recipe_map=source['recipe_map'],
        archive=archive_pin,signature_component=trust,native_receipt_component=pair,
        dependency_component=dependency,smoke_receipt_component=smoke,
        lifecycle_component=lifecycle,actual_pacman_config_pin=config_pin,
        external_supervision_custody='REQUIRED_NOT_AUTHENTICATED_BY_JSON',
        baseline_signature_authentication='REQUIRES_C_SIGNED_INPUT_AND_ALPM_TRUST_CUSTODY',
        native_acceptance=False,Root_grant=None,capacity_acceptance=None,M2=None,
        full72_claim=False,other54='OUTSIDE_SCOPE',official_0bd04f_correspondence='HOLD_UNCHANGED')


def native_entry(*args, **kwargs):
    raise ValueError('HOLD: no Root/C GUI execution binding or authority issuer exists in this component family')

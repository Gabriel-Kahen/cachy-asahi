#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Independent frozen GUI18 DATA intake and producer projection; no actor entry."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
COMMIT = 'b05267833d497ef034576741bf31968019a526c3'
LOCK_PIN = dict(bytes=3753, sha256='41520326da3654b90b1f21fb8ff28398064c2730e1dcf4f7ec47adbcbb9f84cb')
PARENT_PIN = dict(bytes=505, sha256='84a07778ca467a7e3c3183a12f40a9e62554a145481df924cc0314a1766f23af')
CONTRACT_PIN = dict(bytes=14990, sha256='1896928865f4770908e0d00cd4f64dbdea5ba216b7e440c09fed2335fcfa15cf')
PACKAGE = 'cachy-asahi-qt612-gui-source-reference-6.12.0-1-aarch64.pkg.tar.xz'
GUI_BASE = {'libdrm': '2.4.134-1', 'libglvnd': '1.7.0-3', 'mesa': '1:26.2.4-1', 'wayland': '1.26.0-1'}


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def load_parent():
    """Pin every parent Python import before loading the passive library."""
    raw = (HERE/'parent.lock.json').read_bytes()
    need(pin(raw) == PARENT_PIN, 'GUI_PINNED_PARENT_LOCK')
    rows = json.loads(raw)
    need(set(rows) == {'producer.py', 'prepare.py', 'f_intake.py', 'finish_pair.py'}, 'GUI_PARENT_IMPORT_CLOSURE')
    for name, expected in rows.items():
        path = HERE.parent/name
        need(not path.is_symlink() and path.is_file() and pin(path.read_bytes()) == expected, 'GUI_PINNED_PARENT_MODULE')
    spec = importlib.util.spec_from_file_location('qt612_gui_pinned_parent', HERE.parent/'producer.py')
    parent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parent)
    return parent


def lock(parent, observed):
    io = parent.M
    value = io.load(HERE/'recipe.lock.json', LOCK_PIN, observed)
    need(value['kind'] == 'QT612_GUI_INDEPENDENT_RECIPE_PINS_DATA_V1' and value['commit'] == COMMIT
         and value['handoff_seal'] == 'UNBOUND' and value['Root_acceptance'] is value['native_pair'] is None,
         'GUI_INDEPENDENT_UNBOUND_SELECTION')
    return value


def inspect_recipe(root, archive, *, parent=None, observed=None):
    parent = parent or load_parent()
    io, seen = parent.M, observed if observed is not None else {}
    selected = lock(parent, seen)
    base = io.ordinary(root)/selected['recipe_path']
    docs = {name: io.stream(base/name, row, seen, collect=True, mode=0o644)
            for name, row in selected['references'].items()}
    contract = io.decode(docs['BUILD-CONTRACT.json'])
    need(io.pin(docs['BUILD-CONTRACT.json']) == CONTRACT_PIN
         and contract['native_recipe_files'] == selected['active_files'] and len(selected['active_files']) == 14,
         'GUI_FROZEN_ACTIVE14_CONTRACT')
    active, bodies = {}, {}
    for name, row in selected['active_files'].items():
        io.member(name)
        need('/' not in name and row['mode'] == 0o644, 'GUI_ORDINARY_ACTIVE_BASENAME')
        bodies[name] = io.stream(base/name, {k: row[k] for k in ('bytes', 'sha256')}, seen, collect=True, mode=0o644)
        active[name] = dict(row, path=str(base/name))
    recipe_files = io.decode(docs['recipe-files.lock.json'])['files']
    need(all(recipe_files[n] == r for n, r in selected['active_files'].items()), 'GUI_RECIPE_FILES_LOCK_JOIN')
    md = io.srcinfo(bodies['.SRCINFO'])
    package = contract['package']
    need(package['filename'] == PACKAGE and md.get('pkgname') == md.get('pkgbase') == [package['name']]
         and md.get('pkgver') == ['6.12.0'] and md.get('pkgrel') == ['1'] and md.get('arch') == ['aarch64']
         and md.get('provides') == package['provides'] and md.get('conflicts') == package['conflicts']
         and not md.get('replaces') and '!check' not in md.get('options', [])
         and not any(k.startswith(('source_', 'sha256sums_')) for k in md), 'GUI_PACKAGE_IDENTITY')
    need(md.get('depends', []) == contract['dependencies']['runtime']
         and md.get('makedepends', []) == contract['dependencies']['build'] and not md.get('checkdepends')
         and contract['dependencies']['normal_makepkg_checks'] is True, 'GUI_NORMAL_DEPENDENCIES')
    sources = []
    need(len(md['source']) == len(md['sha256sums']) == 13, 'GUI_ALL13_SOURCES')
    for source, digest in zip(md['source'], md['sha256sums']):
        upstream = contract['upstream']['archive']
        if source == upstream['url']:
            path, alias, row = io.ordinary(archive), upstream['filename'], {k: upstream[k] for k in ('bytes', 'sha256')}
            kind = 'upstream-archive'
        else:
            io.member(source)
            need(source in active and '/' not in source, 'GUI_LOCAL_SOURCE')
            path, alias, row, kind = base/source, source, {k: active[source][k] for k in ('bytes', 'sha256')}, 'local-recipe-source'
        need(digest == row['sha256'], 'GUI_SOURCE_SRCINFO_PIN')
        io.stream(path, row, seen, cap=51220268)
        sources.append(dict(row, source=source, alias=alias, path=str(path), kind=kind))
    need(len({r['alias'] for r in sources}) == 13, 'GUI_DISTINCT13_SOURCES')
    config = dict(re.findall(rb'^set\((\w+) (\S+) CACHE (?:BOOL|STRING) "" FORCE\)$', bodies['configure.cmake'], re.MULTILINE))
    need({k.decode(): v.decode() for k, v in config.items()} == contract['configuration']['settings']
         and len(config) == 113 and len(contract['expected_stage']['added_modules']) == 5, 'GUI113_CONFIG_5_ADDED_MODULES')
    notices = io.decode(bodies['source-notices.json'])
    need(io.pin(bodies['source-notices.json']) == contract['source_notices']['policy']
         and len(notices['source_notices']) == 173, 'GUI173_NOTICE_POLICY')
    io.unchanged(seen)
    return dict(contract=contract, active_files=active, source_refs=sources, srcinfo=md, notice_policy=notices,
        provenance=dict(recipe_commit=COMMIT, recipe_tree=selected['tree'], handoff_seal='UNBOUND',
            independently_selected_DATA=True, Root_acceptance=None, native_pair=None))


def admit_complete_preparation(recipe, base, dependencies, policy, *, parent=None):
    parent = parent or load_parent()
    io = parent.M
    need(recipe['provenance']['recipe_commit'] == COMMIT and len(recipe['active_files']) == 14
         and len(recipe['source_refs']) == 13 and io.pin(io.encoded(recipe['contract'])) == CONTRACT_PIN,
         'GUI_FROZEN_RECIPE_TUPLE')
    need(base['kind'] == 'QT612_COMPLETE517_INPUT_DATA_ONLY' and base['files'] == 517
         and len(base['inventory']) == 349 and base['Root_acceptance'] is None, 'GUI_COMPLETE_SIGNED_BASE_DATA')
    need(all(base['inventory'].get(n) == v for n, v in GUI_BASE.items()), 'GUI_BASE_GRAPHICS_PROVIDERS')
    names = {'double-conversion', 'libb2', 'libice', 'libsm', 'md4c', 'xcb-util-cursor', 'xdg-utils'}
    need(dependencies['kind'] == 'QT612_INCREMENTAL_SIGNED_INPUT_DATA_ONLY' and dependencies['complete'] is True
         and not dependencies['missing_roles'] and set(dependencies['packages']) == names
         and parent.md4c_version(dependencies['packages']['md4c']['version'])
         and dependencies['Root_acceptance'] is None, 'GUI_COMPLETE_NORMAL_DEPENDENCIES')
    need(io.pin(io.encoded(policy)) == parent.EXPERIMENTAL and policy['accepted'] is False
         and policy['Root_acceptance'] is None, 'GUI_UNISSUED_UNWIDENED_EXPERIMENTAL_POLICY')
    inventory = dict(base['inventory'])
    for name, row in dependencies['packages'].items():
        need(name not in inventory, 'GUI_NO_BASELINE_REPLACEMENT')
        inventory[name] = row['version']
    need(len(inventory) == 356 and not any(n.startswith('qt6-') for n in inventory), 'GUI356_NO_FOREIGN_QT')
    raw = ''.join(n+' '+v+'\n' for n, v in sorted(inventory.items())).encode()
    return dict(status='COMPLETE_QT612_GUI_PRODUCER_INPUTS_DATA_ONLY', input_plan_complete=True,
        inventory=inventory, inventory_pin=io.pin(raw), graphics_providers=GUI_BASE,
        normal_dependency_transaction='NOT_RUN', actor_enabled=False, Root_capacity=None, Root_runtime=None,
        Root_acceptance=None, native_pair='NOT_RUN', GPG='NOT_RUN', M2='NOT_RUN', handoff_seal='UNBOUND')


def project_builder(raw, *, parent=None):
    parent = parent or load_parent()
    text = parent.project_builder(raw).decode()
    need(text.count(parent.PACKAGE) == 1, 'GUI_EXACT_BUILDER_PACKAGE_SEAM')
    text = text.replace('CACHY_QT612_REFERENCE_', 'CACHY_QT612_GUI_REFERENCE_').replace('qt612-', 'qt612-gui-')
    text = text.replace(parent.PACKAGE.replace('qt612-', 'qt612-gui-'), PACKAGE)
    before = "    from qt612_actor_gate import require_actual_capacity\n    require_actual_capacity()"
    need(text.count(before) == 1, 'GUI_NO_F69_ACTOR_GATE_REUSE')
    text = text.replace(before, "    raise ValueError('GUI_ROOT_CAPACITY_UNISSUED_NO_ACTOR_ENTRY')")
    result = text.encode()
    compile(result, 'GUI-projected-builder', 'exec')
    return result


def project_entry(raw, requirements, *, parent=None):
    parent = parent or load_parent()
    return parent.project_entry(raw, requirements).replace(b'qt612-', b'qt612-gui-')


def project_finisher(raw, *, parent=None):
    """Project frozen parent custody checks, retaining full archive/receipt binding."""
    parent = parent or load_parent()
    rows = json.loads((HERE/'parent.lock.json').read_bytes())
    need(pin(raw) == rows['finish_pair.py'], 'GUI_PINNED_FINISHER_SOURCE')
    text = raw.decode()
    replacements = []
    def replace(before, after):
        nonlocal text
        need(text.count(before) == 1 and after not in text, 'GUI_FINISHER_EXACT_PROJECTION_SEAM')
        text = text.replace(before, after)
        replacements.append((before, after))
    replace("MARKER = b'PASS_QT612_OFFSCREEN_API_SMOKE_ONLY'", "MARKER = b'PASS_QT612_GUI_OFFSCREEN_WIDGETS_OPENGL_API_ONLY'")
    for key in ('CONTRACT_PIN', 'SERIAL_CONTRACT_PIN'):
        before = re.search(r'^'+key+r' = .+$', text, re.MULTILINE)[0]
        replace(before, key+' = '+repr(CONTRACT_PIN))
    start = text.index("        need(set(stage) == {'status','architecture'")
    stop = text.index("        validation = load(root/'validation.json')", start)
    replace(text[start:stop], "        gui_stage.validate_stage_receipt(stage,expected['contract'])\n")
    replace("    return dict(archive=sink.result(),members=members,files=files,symlinks=links,directories=directories,",
            "    elf = gui_stage.enrich_elf(elf)\n    return dict(archive=sink.result(),members=members,files=files,symlinks=links,directories=directories,")
    inverse = text
    for before, after in reversed(replacements):
        need(inverse.count(after) == 1, 'GUI_FINISHER_EXACT_INVERSE')
        inverse = inverse.replace(after, before)
    need(inverse.encode() == raw, 'GUI_FINISHER_WHOLE_INVERSE')
    text = text.replace('qt612-', 'qt612-gui-').replace('QT612_REFERENCE_NATIVE_PAIR_POSTCONDITIONS_PASSED',
        'QT612_GUI_REFERENCE_NATIVE_PAIR_POSTCONDITIONS_PASSED')
    text += '''\n# GUI source is independently pinned; parent F69 remains immutable.\nimport gui_stage\nimport gui_checker\n_parent_elf_reports = elf_reports\ndef elf_reports(raw):\n    _, geometry = _parent_elf_reports(raw)\n    return gui_checker.elf_info(raw,183), geometry\nvalidate_stage = gui_stage.validate_stage\n'''
    compile(text, 'GUI-projected-finisher', 'exec')
    return text.encode()


def pair_commands(source, output, image, inventory_pin, *, nonce, parent=None):
    parent = parent or load_parent()
    plan = parent.pair_commands(source, output, image, inventory_pin, nonce=nonce)
    for row in plan['builds']:
        row['argv'] = [s.replace('build_qt612.py', 'build_qt612_gui.py') for s in row['argv']]
        row['env'] = {k.replace('CACHY_QT612_REFERENCE_', 'CACHY_QT612_GUI_REFERENCE_'): v for k, v in row['env'].items()}
    return dict(plan, kind='QT612_GUI_UNISSUED_PAIR_COMMANDS_DATA_V1', recipe_commit=COMMIT,
                Root_runtime=None, transport_binding='UNBOUND', callable_actor_entry=False)



def dependency_image_plan(parent_image, recipe, base, dependencies, policy, *, builder_uid, builder_gid, parent=None):
    parent = parent or load_parent()
    admit_complete_preparation(recipe, base, dependencies, policy, parent=parent)
    plan = parent.dependency_image_plan(parent_image, base, dependencies, builder_uid=builder_uid, builder_gid=builder_gid)
    return dict(plan, kind='QT612_GUI_DEPENDENCY_IMAGE_PLAN_UNISSUED_DATA_V1', recipe_commit=COMMIT,
                graphics_providers=GUI_BASE, normal_dependency_transaction='NOT_RUN', Root_capacity=None)


def prepare_producer(*, framework, gui_root, archive, output, provider_ref=None, candidate_map=None, md4c=None):
    parent = load_parent()
    io, seen = parent.M, {}
    framework, root, out = map(io.ordinary, (framework, gui_root, output))
    need(not out.exists() and out.parent.is_dir() and all(not out.is_relative_to(p) and not p.is_relative_to(out)
         for p in (framework, root)), 'GUI_FRESH_DISJOINT_OUTPUT')
    recipe = inspect_recipe(root, archive, parent=parent, observed=seen)
    policy = parent.selected(HERE.parent/'resource-EXPERIMENTAL.json', parent.EXPERIMENTAL, seen)
    deps_lock = parent.selected(HERE.parent/'dependency-candidates.lock.json', parent.DEPENDENCIES, seen)
    basis = parent.selected(HERE.parent/'basis.lock.json', io.BASIS_PIN, seen)
    base = parent.validate_base_provider(provider_ref, deps_lock, seen) if provider_ref is not None else None
    deps = parent.dependency_inputs(candidate_map=candidate_map, md4c=md4c, lock=deps_lock, observed=seen) if candidate_map is not None else None
    complete = base is not None and deps is not None and deps['complete']
    admission = admit_complete_preparation(recipe, base, deps, policy, parent=parent) if complete else dict(
        status='HOLD_MISSING_QT612_GUI_SIGNED_INPUTS', input_plan_complete=False, actor_enabled=False,
        Root_capacity=None, Root_runtime=None, Root_acceptance=None, native_pair='NOT_RUN', GPG='NOT_RUN', M2='NOT_RUN', handoff_seal='UNBOUND')
    requirements = recipe['srcinfo']['depends'] + recipe['srcinfo']['makedepends']
    def framework_bytes(name):
        return io.stream(framework/name, {k: basis['framework_files'][name][k] for k in ('bytes', 'sha256')}, seen, collect=True)
    projected = {
        'runtime/scripts/build/build_qt612_gui.py': project_builder(framework_bytes('scripts/build/build_v2.py'), parent=parent),
        'runtime/scripts/build/container-entry-v2.sh': project_entry(framework_bytes('scripts/build/container-entry-v2.sh'), requirements, parent=parent),
        'runtime/scripts/build/gui_finish.py': project_finisher(io.stream(HERE.parent/'finish_pair.py', None, seen, collect=True), parent=parent),
        'runtime/scripts/build/gui_stage.py': io.stream(HERE/'stage.py', None, seen, collect=True),
        'runtime/scripts/build/gui_checker.py': io.stream(HERE/'fixtures/check_stage.py', lock(parent, seen)['references']['check_stage.py'], seen, collect=True),
    }
    profile_name = 'scripts/ci/llhttp-reference-native-source/base/profile.json'
    profile = parent.selected(framework/profile_name, {k: basis['framework_files'][profile_name][k] for k in ('bytes', 'sha256')}, seen)
    for name, row in profile['held_inputs'].items():
        if name.startswith('runtime/') and name not in ('runtime/scripts/build/build_v2.py', 'runtime/scripts/build/container-entry-v2.sh'):
            projected[name] = io.stream(framework/row['source_path'], {k: row[k] for k in ('bytes', 'sha256')}, seen, collect=True)
    writer, files = io.Writer(out), {}
    try:
        for name, raw in projected.items():
            files[name] = writer.put(name, raw=raw)
        for name, row in recipe['active_files'].items():
            files['recipe/'+name] = writer.put('recipe/'+name, source=row['path'], expected={k: row[k] for k in ('bytes', 'sha256')}, observed=seen)
        upstream = next(r for r in recipe['source_refs'] if r['kind'] == 'upstream-archive')
        name = 'recipe/'+upstream['alias']
        files[name] = writer.put(name, source=upstream['path'], expected={k: upstream[k] for k in ('bytes', 'sha256')}, observed=seen, cap=51220268)
        def put(name, value):
            files[name] = writer.put(name, raw=io.encoded(value))
        reviewed = {n: r['sha256'] for n, r in recipe['active_files'].items()}
        reviewed[upstream['alias']] = upstream['sha256']
        put('reviewed-inputs.json', reviewed)
        put('GUI-contract.DATA.json', recipe['contract'])
        put('GUI-notices.DATA.json', recipe['notice_policy'])
        put('GUI-provenance.DATA.json', recipe['provenance'])
        put('resource-EXPERIMENTAL.UNISSUED.DATA.json', policy)
        put('GUI-input-plan.DATA.json', dict(base_provider=provider_ref, dependencies=deps, complete=complete,
            graphics_providers=GUI_BASE, normal_dependency_transaction='NOT_RUN', Root_acceptance=None))
        if complete:
            files['expected356.lock'] = writer.put('expected356.lock', raw=''.join(n+' '+v+'\n' for n, v in sorted(admission['inventory'].items())).encode())
        report = dict(admission, kind='QT612_GUI_CONCRETE_PRODUCER_PREPARATION_DATA_V1', recipe_commit=COMMIT,
            active_recipe_files=14, source_operands=13, modules=18, added_modules=recipe['contract']['expected_stage']['added_modules'],
            configuration_settings=113, smoke_marker=recipe['contract']['smoke']['marker'], transport_binding='UNBOUND',
            missing_roles=(['complete517.provider'] if base is None else [])+(['signed7.additional.providers'] if deps is None else deps['missing_roles']),
            callable_actor_entry=False, stage_export='PROJECTED_NOT_RUN', release=False,
            capacity_policy_issued=False, graphics_provider_transaction='NOT_RUN')
        put('GUI-producer-report.DATA.json', report)
        put('GUI-dependency-image.UNISSUED.DATA.json', dict(kind='QT612_GUI_DEPENDENCY_IMAGE_PLAN_UNISSUED_DATA_V1',
            recipe_commit=COMMIT, parent_image=None, actual_image=None, builder_uid=None, builder_gid=None,
            required_packages=356, required_signed_additions=7, graphics_providers=GUI_BASE,
            normal_dependency_transaction='NOT_RUN', signature_policy='Required TrustedOnly',
            actor_enabled=False, Root_acceptance=None, Root_capacity=None))
        put('GUI-Root-capacity.UNISSUED.DATA.json', dict(kind='ROOT_QT612_GUI_CAPACITY_UNISSUED_DATA_V1',
            accepted=False, issued_by=None, recipe_commit=COMMIT, policy_pin=parent.EXPERIMENTAL,
            source_map_sha256=None, nonce=None, Root_acceptance=None))
        mapping = dict(schema=1, kind='QT612_GUI_REFERENCE_PRODUCER_SOURCE_DATA_V1', recipe_commit=COMMIT,
            files=files, actual=dict.fromkeys(io.ACTUAL), input_plan_complete=complete, handoff_seal='UNBOUND',
            execution_requires_fresh_Root_capacity=True, actor_enabled=False, Root_acceptance=None)
        raw = io.encoded(mapping)
        writer.put('source-map.json', raw=raw)
        io.unchanged(seen)
        verify_producer_source(out, io.pin(raw)['sha256'], parent=parent)
        return dict(report, source_map=io.pin(raw), files=len(files)+1)
    finally:
        writer.close()


def verify_producer_source(root, source_map_sha256, *, parent=None):
    parent = parent or load_parent()
    io, seen = parent.M, {}
    root = io.ordinary(root)
    need(re.fullmatch('[0-9a-f]{64}', source_map_sha256 or ''), 'GUI_EXTERNAL_SOURCE_MAP_PIN')
    value = io.load(root/'source-map.json', dict(bytes=(root/'source-map.json').lstat().st_size, sha256=source_map_sha256), seen)
    need(value['kind'] == 'QT612_GUI_REFERENCE_PRODUCER_SOURCE_DATA_V1' and value['recipe_commit'] == COMMIT
         and value['Root_acceptance'] is None and value['actor_enabled'] is False and value['handoff_seal'] == 'UNBOUND'
         and value['execution_requires_fresh_Root_capacity'] is True and set(value['actual']) == set(io.ACTUAL)
         and all(v is None for v in value['actual'].values()), 'GUI_UNISSUED_SOURCE_ONLY')
    rows, found, pending, nodes = value['files'], set(), [root], 0
    need(32 <= len(rows) <= 128 and sum(r['bytes'] for r in rows.values()) <= 256*1024**2, 'GUI_FINITE_SOURCE_MAP')
    while pending:
        for path in pending.pop().iterdir():
            nodes += 1
            need(nodes <= 512 and not path.is_symlink(), 'GUI_BOUNDED_ORDINARY_NAMESPACE')
            if path.is_dir():
                pending.append(path)
            else:
                need(path.is_file(), 'GUI_ORDINARY_SOURCE_LEAF')
                found.add(path.relative_to(root).as_posix())
    need(found == set(rows) | {'source-map.json'}, 'GUI_COMPLETE_SOURCE_NAMESPACE')
    for name, row in rows.items():
        io.member(name)
        need(set(row) == {'bytes', 'sha256', 'mode'} and row['mode'] == 0o644, 'GUI_EXACT_FILE_DESCRIPTOR')
        io.stream(root/name, {k: row[k] for k in ('bytes', 'sha256')}, seen, cap=256*1024**2, mode=0o644)
    contract = io.decode(io.stream(root/'GUI-contract.DATA.json', CONTRACT_PIN, seen, collect=True))
    wanted = {'recipe/'+n: r for n, r in contract['native_recipe_files'].items()}
    upstream = contract['upstream']['archive']
    wanted['recipe/'+upstream['filename']] = {k: upstream[k] for k in ('bytes', 'sha256')} | {'mode': 0o644}
    need({n: r for n, r in rows.items() if n.startswith('recipe/')} == wanted, 'GUI_EXACT_ACTIVE14_ARCHIVE_BUILDVIEW')
    reviewed = {n: r['sha256'] for n, r in contract['native_recipe_files'].items()}
    reviewed[upstream['filename']] = upstream['sha256']
    need(io.decode(io.stream(root/'reviewed-inputs.json', None, seen, collect=True)) == reviewed, 'GUI_EXACT_REVIEWED_INPUTS')
    io.stream(root/'resource-EXPERIMENTAL.UNISSUED.DATA.json', parent.EXPERIMENTAL, seen)
    plan = io.decode(io.stream(root/'GUI-input-plan.DATA.json', None, seen, collect=True))
    need(plan['complete'] is value['input_plan_complete'] and plan['Root_acceptance'] is None
         and plan['normal_dependency_transaction'] == 'NOT_RUN', 'GUI_SAME_PASSIVE_INPUT_PLAN')
    io.unchanged(seen)
    return dict(source_map_verified=True, input_plan_complete=value['input_plan_complete'], actor_enabled=False, Root_acceptance=None)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('framework', 'gui-root', 'archive', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    import sys
    sys.addaudithook(load_parent().M.fence)
    print(json.dumps(prepare_producer(framework=args.framework, gui_root=args.gui_root, archive=args.archive,
                                     output=args.output), sort_keys=True, indent=2))

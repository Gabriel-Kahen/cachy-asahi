# SPDX-License-Identifier: MIT
"""Read frozen F metadata and source bytes; never evaluate recipe or helper code."""
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
LOCK_PIN = dict(bytes=7754, sha256='a6ecf61d9bb36e1525e01f791cd51958426cd59c961b2f0a1d80d912fc0a1d52')
SERIAL_LOCK_PIN = dict(bytes=10713, sha256='020c248a7fc63bb058b0d607b83f6f711f0a5ae1d81354ce22b4dfaf0e2afec0')


def inspect_recipe(recipe_root, archive_path, *, io_module, observed=None):
    """Use the caller's passive prepare IO; return DATA without admission authority."""
    io = io_module
    seen = observed if observed is not None else {}
    need = io.need
    root = io.ordinary(recipe_root)
    lock = io.decode(io.stream(HERE/'f-recipe.lock.json', LOCK_PIN, seen, collect=True))
    need(lock['schema'] == 1 and lock['kind'] == 'QT612_F_INTAKE_PINS_DATA_V1'
         and lock['Root_selection'] is None and lock['native_pair'] is None, 'F_INTAKE_LOCK')
    refs, bodies, documents = lock['references'], {}, {}
    for name, row in refs.items():
        io.member(name)
        raw = io.stream(root/name, row, seen, collect=True, mode=0o644)
        bodies[name] = raw
        documents[name] = io.decode(raw)
    base = root/lock['recipe_path']
    contract = documents[lock['recipe_path']+'/BUILD-CONTRACT.json']
    handoff_name = 'work/qt612-final-DATA-20261117-r1/HANDOFF.DATA.json'
    handoff = documents[handoff_name]
    seal = documents['work/qt612-final-DATA-20261117-r1/HANDOFF-SEAL.DATA.json']
    for document in (handoff, seal):
        need(document['schema_version'] == 1 and document['commit'] == lock['commit']
             and document['tree'] == lock['tree'], 'F_HANDOFF_COMMIT_TREE')
    need(seal['Root_selection'] is None and seal['native_pair'] is None
         and handoff['holds']['Root_selection'] is None and handoff['holds']['native_pair'] is None,
         'F_UNBOUND_AUTHORITY')
    seal_handoff = seal['files']['HANDOFF.DATA.json']
    need({k:seal_handoff[k] for k in ('bytes','sha256')} == refs[handoff_name]
         and seal_handoff['path'] == lock['original_root']+'/'+handoff_name, 'F_SEAL_HANDOFF_JOIN')
    active = lock['active_files']
    need(len(active) == 14 and active == contract['native_recipe_files'], 'F_ACTIVE14_MAP')
    active_files, active_bodies = {}, {}
    for name, row in active.items():
        io.member(name)
        need('/' not in name and row['mode'] == 0o644, 'F_ACTIVE_ORDINARY_BASENAME')
        declared = handoff['files'][lock['recipe_path']+'/'+name]
        need(declared == dict(row, kind='file'), 'F_HANDOFF_ACTIVE_JOIN')
        active_bodies[name] = io.stream(base/name, {k:row[k] for k in ('bytes','sha256')},
                                        seen, collect=True, mode=row['mode'])
        active_files[name] = dict(row, path=str(base/name))
    for name, row in refs.items():
        if name.startswith(lock['recipe_path']+'/'):
            need(handoff['files'][name] == dict(row, kind='file', mode=0o644), 'F_HANDOFF_METADATA_JOIN')
    md = io.srcinfo(active_bodies['.SRCINFO'])
    package = contract['package']
    need(md.get('pkgbase') == md.get('pkgname') == [package['name']]
         and md.get('pkgver') == ['6.12.0'] and md.get('pkgrel') == ['1']
         and md.get('arch') == ['aarch64'] and md.get('provides') == package['provides']
         and md.get('conflicts') == package['conflicts'] and md.get('replaces',[]) == []
         and '!check' not in md.get('options',[]) and not any(k.startswith('source_') or
             k.startswith('sha256sums_') for k in md), 'F_SRCINFO_IDENTITY')
    sources = lock['sources']
    need(len(sources) == 13 and len({r['alias'] for r in sources}) == 13
         and md.get('source') == [r['source'] for r in sources]
         and md.get('sha256sums') == [r['sha256'] for r in sources], 'F_ALL13_SRCINFO_JOIN')
    archive = io.ordinary(archive_path)
    source_refs = []
    for row in sources:
        io.member(row['alias'])
        if row['kind'] == 'upstream-archive':
            need(row == dict(alias='qtbase-everywhere-src-6.12.0.tar.xz',
                             source=contract['upstream']['archive']['url'], kind='upstream-archive',
                             **{k:contract['upstream']['archive'][k] for k in ('bytes','sha256')}),
                 'F_UPSTREAM_ARCHIVE_JOIN')
            io.stream(archive, {k:row[k] for k in ('bytes','sha256')}, seen, cap=51220268)
            path = archive
        else:
            need(row['kind'] == 'local-recipe-source' and row['source'] == row['alias']
                 and {k:row[k] for k in ('bytes','sha256')} ==
                 {k:active[row['alias']][k] for k in ('bytes','sha256')}, 'F_LOCAL_SOURCE_JOIN')
            path = base/row['alias']
        source_refs.append(dict(row, path=str(path)))
    policy = io.decode(active_bodies['source-notices.json'])
    need(set(policy) == {'schema_version','source_notices'} and policy['schema_version'] == 1
         and type(policy['source_notices']) is dict and len(policy['source_notices']) == 173,
         'F_NOTICE173_POLICY')
    for name, digest in policy['source_notices'].items():
        io.member(name)
        need(type(digest) is str and re.fullmatch('[0-9a-f]{64}', digest), 'F_NOTICE_PIN')
    config = dict(re.findall(rb'^set\((\w+) (\S+) CACHE (?:BOOL|STRING) "" FORCE\)$',
                             active_bodies['configure.cmake'], re.MULTILINE))
    config = {k.decode():v.decode() for k,v in config.items()}
    need(len(config) == 90 and config == contract['configuration']['settings']
         and contract['patch_order'] == lock['patch_order'] and contract['patch_fuzz'] == 0
         and contract['source_notices'] == lock['source_notices']
         and contract['source_notices']['count'] == 173 and contract['source_notices']['bytes'] == 636122
         and contract['source_notices']['policy'] == {k:active['source-notices.json'][k] for k in ('bytes','sha256')},
         'F_CONFIG_PATCH_NOTICE_BINDING')
    need(md.get('depends',[]) == contract['dependencies']['runtime']
         and md.get('makedepends',[]) == contract['dependencies']['build']
         and md.get('checkdepends',[]) == [] and contract['dependencies']['normal_makepkg_checks'] is True,
         'F_NORMAL_DEPENDENCY_CONTRACT')
    io.unchanged(seen)
    return dict(contract=contract, active_files=active_files, source_ref13=source_refs,
                notice_policy=policy, srcinfo=md,
                provenance=dict(lock=dict(LOCK_PIN, path=str(HERE/'f-recipe.lock.json')),
                                references={n:dict(r,path=str(root/n)) for n,r in refs.items()},
                                recipe_commit=lock['commit'], recipe_tree=lock['tree'],
                                original_root=lock['original_root'], recipe_root=str(root),
                                holds=handoff['holds'], Root_selection=None, native_pair=None,
                                status=lock['status']))


def inspect_serial_recipe(recipe_root, archive_path, *, io_module, observed=None):
    """Read NEW 69a02851 serial recipe; preserve predecessor intake and pins."""
    io,seen = io_module,observed if observed is not None else {}
    need,root = io.need,io.ordinary(recipe_root)
    lock = io.decode(io.stream(HERE/'f-serial-recipe.lock.json',SERIAL_LOCK_PIN,seen,collect=True))
    need(lock['schema'] == 1 and lock['kind'] == 'QT612_SERIAL_F_INTAKE_PINS_DATA_V1'
         and lock['Root_selection'] is None and lock['native_pair'] is None, 'SERIAL_F_INTAKE_LOCK')
    docs = {}
    for name,row in lock['references'].items():
        io.member(name)
        raw = io.stream(root/name,row,seen,collect=True,mode=0o644)
        if name.endswith('.json'):docs[name] = io.decode(raw)
    base,handdir = root/lock['recipe_path'],lock['handoff_directory']
    contract = docs[lock['recipe_path']+'/BUILD-CONTRACT.json']
    handoff,selection = docs[handdir+'/HANDOFF.DATA.json'],docs[handdir+'/recipe-selection.CANDIDATE.DATA.json']
    need(handoff['schema'] == 1 and handoff['kind'] == 'QT612_SERIAL_EXPERIMENT_RECIPE_HANDOFF_SOURCE_ONLY'
         and handoff['recipe_commit'] == selection['recipe_commit'] == lock['commit']
         and handoff['recipe_tree'] == lock['tree'] and handoff['predecessor_commit'] == lock['predecessor_commit']
         and handoff['predecessor_untouched'] is True and handoff['actual']['Root_acceptance'] is None
         and handoff['actual']['capacity_sufficient'] is None and selection['Root_acceptance'] is None
         and handoff['BUILD_CONTRACT'] == lock['references'][lock['recipe_path']+'/BUILD-CONTRACT.json'], 'SERIAL_F_FROZEN_UNACCEPTED_HANDOFF')
    active = lock['active_files']
    need(len(active) == 14 and active == contract['native_recipe_files']
         and selection['files'] == lock['closed_export_files']
         and set(selection['files']) == set(active)|{'source.json'}
         and len(selection['files']) == handoff['closed_recipe_files'] == 15, 'SERIAL_ACTIVE14_EXPORT15')
    active_files,bodies = {},{}
    for name,row in active.items():
        io.member(name);need('/' not in name and row['mode'] == 0o644 and selection['files'][name] == row, 'SERIAL_ACTIVE_FILE_PIN')
        body = io.stream(base/name,{k:row[k] for k in ('bytes','sha256')},seen,collect=True,mode=0o644)
        bodies[name] = body;active_files[name] = dict(row,path=str(base/name))
    export = root/handdir/'recipe-root'/lock['recipe_path']
    for name,row in selection['files'].items():
        body = io.stream(export/name,{k:row[k] for k in ('bytes','sha256')},seen,collect=True,mode=0o644)
        if name == 'source.json':need(body == io.encoded(contract), 'SERIAL_SOURCE_JSON_CONTRACT_ALIAS')
    need({p.name for p in export.iterdir()} == set(selection['files']), 'SERIAL_EXACT_CLOSED_EXPORT_NAMESPACE')
    md = io.srcinfo(bodies['.SRCINFO'])
    need(md.get('pkgbase') == md.get('pkgname') == [contract['package']['name']]
         and md.get('pkgver') == ['6.12.0'] and md.get('pkgrel') == ['2'] and md.get('arch') == ['aarch64']
         and md.get('provides') == contract['package']['provides'] and md.get('conflicts') == contract['package']['conflicts']
         and not md.get('replaces') and '!check' not in md.get('options',[])
         and not any(k.startswith('source_') or k.startswith('sha256sums_') for k in md), 'SERIAL_F_SRCINFO_IDENTITY')
    sources = lock['sources']
    need(len(sources) == handoff['source_operands'] == 13 and len({r['alias'] for r in sources}) == 13
         and md.get('source') == [r['source'] for r in sources]
         and md.get('sha256sums') == [r['sha256'] for r in sources]
         and set(selection['sources']) == {r['alias'] for r in sources}, 'SERIAL_ALL13_SOURCE_JOIN')
    source_refs = []
    for row in sources:
        io.member(row['alias'])
        selected = selection['sources'][row['alias']]
        whole = {k:row[k] for k in ('bytes','sha256')}
        need({k:selected[k] for k in ('bytes','sha256')} == whole, 'SERIAL_EXPORTED_SOURCE_PIN')
        selected_path = root/handdir/'recipe-sources'/row['alias']
        need(selected['path'] == lock['original_root']+'/'+handdir+'/recipe-sources/'+row['alias'], 'SERIAL_EXPORTED_SOURCE_ORIGIN')
        io.stream(selected_path,whole,seen,cap=51220268)
        if row['kind'] == 'upstream-archive':
            path = io.ordinary(archive_path)
            need(whole == {k:contract['upstream']['archive'][k] for k in ('bytes','sha256')}
                 and row['source'] == contract['upstream']['archive']['url'], 'SERIAL_UPSTREAM_ARCHIVE_PIN')
            io.stream(path,whole,seen,cap=51220268)
        else:
            need(row['kind'] == 'local-recipe-source' and row['source'] == row['alias']
                 and whole == {k:active[row['alias']][k] for k in ('bytes','sha256')}, 'SERIAL_LOCAL_SOURCE_PIN')
            path = base/row['alias']
        source_refs.append(dict(row,path=str(path)))
    policy = io.decode(bodies['source-notices.json'])
    need(set(policy) == {'schema_version','source_notices'} and policy['schema_version'] == 1
         and len(policy['source_notices']) == handoff['source_notices'] == 173, 'SERIAL_NOTICE173')
    for name,digest in policy['source_notices'].items():
        io.member(name);need(type(digest) is str and re.fullmatch('[0-9a-f]{64}',digest), 'SERIAL_NOTICE_PIN')
    config = {k.decode():v.decode() for k,v in re.findall(rb'^set\((\w+) (\S+) CACHE (?:BOOL|STRING) "" FORCE\)$',bodies['configure.cmake'],re.MULTILINE)}
    need(len(config) == lock['configuration_settings'] == handoff['configuration_settings'] == 91
         and config == contract['configuration']['settings'] and config['CMAKE_AUTOGEN_PARALLEL'] == '1'
         and selection['features'] == [k+'='+v for k,v in sorted(config.items())]
         and contract['parallelism'] == dict(CMAKE_AUTOGEN_PARALLEL=1,CMAKE_BUILD_PARALLEL_LEVEL=1,MAX_JOBS=1,
             cmake_build_arguments=['--parallel','1'],memory_bound='EXTERNAL_C_ENFORCEMENT_REQUIRED_NO_CAPACITY_CLAIM',
             other_explicit_values='REFUSED_BEFORE_BUILD_OR_CHECK_TOOLS',unset_environment='DEFAULT_TO_1')
         and contract['patch_order'] == lock['patch_order'] and contract['patch_fuzz'] == 0
         and contract['source_notices'] == lock['source_notices'], 'SERIAL_J1_CONFIG_PATCH_NOTICE_BINDING')
    need(selection['dependencies'] == dict(depends=md.get('depends',[]),makedepends=md.get('makedepends',[]),checkdepends=[])
         and md.get('depends',[]) == contract['dependencies']['runtime']
         and md.get('makedepends',[]) == contract['dependencies']['build'] and not md.get('checkdepends')
         and contract['dependencies']['normal_makepkg_checks'] is True, 'SERIAL_NORMAL_DEPENDENCIES')
    io.unchanged(seen)
    return dict(contract=contract,active_files=active_files,source_ref13=source_refs,notice_policy=policy,srcinfo=md,
        provenance=dict(lock=dict(SERIAL_LOCK_PIN,path=str(HERE/'f-serial-recipe.lock.json')),
            references={n:dict(r,path=str(root/n)) for n,r in lock['references'].items()},
            recipe_commit=lock['commit'],recipe_tree=lock['tree'],original_root=lock['original_root'],recipe_root=str(root),
            holds=handoff['actual'],Root_selection=None,native_pair=None,status=lock['status']))

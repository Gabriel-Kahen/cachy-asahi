#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Pinned F producer plans and signed input intake; actors require separate Root truth."""
import argparse
import copy
import importlib.util
import json
import hashlib
from pathlib import Path
import re
import shlex
import tarfile

HERE = Path(__file__).resolve().parent
F_COMMIT = '69a02851b87ca29daf2e197101b66bf75ff61889'
EXPERIMENTAL = dict(bytes=1786,sha256='937d2c05b96df99dde7097d10647c5ea96aea38d3442ffcbca2f3647dd643ece')
DEPENDENCIES = dict(bytes=10357,sha256='3240b821dd9f2827732d808a94e493a8f9a9fb9550fdc802d95bc7c49397f3df')
CANDIDATE_MAP = dict(bytes=83984,sha256='a6336688c5766341a79102d1f8867d6b4e2d60c70a62fad6ad64f8666ca4bb1a')
PACKAGE = 'cachy-asahi-qt612-base-source-reference-6.12.0-2-aarch64.pkg.tar.xz'


def module(name):
    spec = importlib.util.spec_from_file_location('qt612_'+name,HERE/(name+'.py'))
    value = importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


M = module('prepare')
F = module('f_intake')
need = M.need


def reference(row,observed,*,collect=False,cap=2*1024**3):
    need(type(row) is dict and set(row) == {'path','bytes','sha256'},'EXPLICIT_PRODUCER_REFERENCE')
    return M.stream(row['path'],{k:row[k] for k in ('bytes','sha256')},observed,collect=collect,cap=cap)


def selected(path,expected,observed):return M.decode(M.stream(path,expected,observed,collect=True))


def pkginfo(path):
    """Read ordinary XZ package metadata only; no extraction or package execution."""
    info = None;count = total = 0
    with tarfile.open(path,mode='r|xz') as archive:
        for row in archive:
            count += 1;total += row.size
            need(count <= 100000 and 0 <= row.size <= 128*1024**2 and total <= 2*1024**3,'BOUNDED_DEPENDENCY_PACKAGE')
            name = row.name.removeprefix('./');M.member(name.rstrip('/'))
            if name == '.PKGINFO':
                need(info is None and row.isfile() and row.size <= 1024**2,'ONE_ORDINARY_DEPENDENCY_PKGINFO')
                with archive.extractfile(row) as stream:raw = stream.read(row.size+1)
                need(len(raw) == row.size,'WHOLE_DEPENDENCY_PKGINFO');info = M.srcinfo(raw)
    need(info is not None,'DEPENDENCY_PKGINFO_REQUIRED')
    return info


def validate_base_provider(ref,dependency_lock,observed):
    value = M.decode(reference(ref,observed,collect=True,cap=4*1024**2))
    need(value['complete'] is True and value['verified_files'] == 517
         and value['api'] == 'BASE349_CACHE_REFERENCES_V3'
         and value['kind'] == 'VERIFIED_BASE349_CACHE_REFERENCES_DATA_V3'
         and not value['missing_materials'] and all(v is None for v in value['actual'].values()),'COMPLETE_UNISSUED517_PROVIDER')
    for key,expected in (('base_lock',dependency_lock['baseline_input_lock']),('bootstrap_profile',dependency_lock['bootstrap_profile']),('baseline_inventory',dependency_lock['baseline_inventory'])):
        need({k:value[key][k] for k in ('bytes','sha256')} == expected,'FROZEN349_PROVIDER_METADATA')
    lock = M.decode(reference(value['base_lock'],observed,collect=True));profile = M.decode(reference(value['bootstrap_profile'],observed,collect=True))
    inventory_raw = reference(value['baseline_inventory'],observed,collect=True)
    inventory = dict(line.split(' ',1) for line in inventory_raw.decode().splitlines())
    need(len(inventory) == 349 and len(profile['additions']['rows']) == 8,'EXACT349_PROVIDER_INVENTORY')
    paths = []
    for key,records,signed,count in (('base_materials',[lock['rootfs'],*lock['packages']],True,498),
            ('supplemental_materials',profile['additions']['rows'],True,16),('keyring_materials',lock['keyring_files'],False,3)):
        refs = value[key];wanted = {r['filename']+suffix for r in records for suffix in (('', '.sig') if signed else ('',))}
        need(type(refs) is dict and len(refs) == count and set(refs) == wanted,'EXACT_SIGNED_PROVIDER_ROLE_SET')
        for record in records:
            for suffix in (('', '.sig') if signed else ('',)):
                row = refs[record['filename']+suffix]
                expected = dict(bytes=record['signature_size'] if suffix else record['size'],sha256=record['signature_sha256'] if suffix else record['sha256'])
                need({k:row[k] for k in ('bytes','sha256')} == expected,'EXACT_SIGNED_PROVIDER_ARCHIVE_PIN')
                paths.append(row['path']);reference(row,observed)
    need(len(paths) == len(set(paths)) == 517,'DISTINCT517_PROVIDER_PATHS')
    return dict(kind='QT612_COMPLETE517_INPUT_DATA_ONLY',files=517,inventory=inventory,
                inventory_pin=M.pin(inventory_raw),provider=ref,Root_acceptance=None,GPG='NOT_RUN')


def md4c_version(version):
    match = re.fullmatch(r'0\.5\.([0-9]+)(?:\.[0-9]+)*-[1-9][0-9]*(?:\.[0-9]+)?',version or '')
    return bool(match and int(match[1]) >= 3)


def dependency_inputs(*,candidate_map,md4c,lock,observed):
    refs = selected(candidate_map,CANDIDATE_MAP,observed);packages = {}
    for name,spec in lock['additional'].items():
        archive,signature = refs[spec['filename']],refs[spec['filename']+'.sig']
        for row,pin in ((archive,spec['archive']),(signature,spec['signature'])):
            need({k:row[k] for k in ('bytes','sha256')} == pin,'EXACT_ADDITIONAL_SIGNED_PIN');reference(row,observed)
        need(pkginfo(archive['path']) == spec['PKGINFO'],'EXACT_ADDITIONAL_PKGINFO')
        packages[name] = dict(name=name,version=spec['version'],arch=spec['arch'],filename=spec['filename'],archive=archive,signature=signature)
    missing = []
    if md4c is None:
        missing = ['md4c.archive>=0.5.3,<0.6','md4c.signature','md4c.independently_selected_metadata']
    else:
        need(type(md4c) is dict and set(md4c) == {'name','version','arch','filename','archive','signature'}
             and md4c['name'] == 'md4c' and md4c_version(md4c['version']) and md4c['arch'] == 'aarch64'
             and md4c['filename'] == 'md4c-'+md4c['version']+'-aarch64.pkg.tar.xz','NORMAL_MD4C_053_TO_BELOW06_REQUIRED')
        need(type(md4c['signature'].get('bytes')) is int and 0 < md4c['signature']['bytes'] <= 1024**2,'NONEMPTY_NORMAL_DEPENDENCY_SIGNATURE_REQUIRED')
        reference(md4c['archive'],observed);reference(md4c['signature'],observed)
        info = pkginfo(md4c['archive']['path'])
        need(info.get('pkgname') == ['md4c'] and info.get('pkgver') == [md4c['version']]
             and info.get('arch') == ['aarch64']
             and set(info.get('depend',[])) <= {'glibc','gcc-libs','libgcc','libstdc++'},'MD4C_METADATA_AND_BASE_CLOSURE')
        packages['md4c'] = copy.deepcopy(md4c)
    paths = [row[k]['path'] for row in packages.values() for k in ('archive','signature')]
    need(len(paths) == len(set(paths)) == 2*len(packages),'DISTINCT_INCREMENTAL_DEPENDENCY_REFS')
    return dict(kind='QT612_INCREMENTAL_SIGNED_INPUT_DATA_ONLY',packages=packages,missing_roles=missing,
                available_packages=len(packages),required_packages=7,complete=not missing,GPG='NOT_RUN',Root_acceptance=None)


def admit_complete_preparation(recipe,base,dependencies,policy):
    """Positive DATA admission, distinct from any actual actor/capacity grant."""
    need(recipe['provenance']['recipe_commit'] == F_COMMIT and len(recipe['active_files']) == 14
         and len(recipe['source_ref13']) == 13,'FROZEN_F_PRODUCER_TUPLE')
    need(base['kind'] == 'QT612_COMPLETE517_INPUT_DATA_ONLY' and base['files'] == 517
         and len(base['inventory']) == 349 and base['Root_acceptance'] is None,'COMPLETE_SIGNED_BASE_DATA_REQUIRED')
    need(dependencies['kind'] == 'QT612_INCREMENTAL_SIGNED_INPUT_DATA_ONLY' and dependencies['complete'] is True
         and not dependencies['missing_roles'] and set(dependencies['packages']) == {'double-conversion','libb2','libice','libsm','md4c','xcb-util-cursor','xdg-utils'}
         and md4c_version(dependencies['packages']['md4c']['version']),'COMPLETE_NORMAL_QT612_DEPENDENCIES_REQUIRED')
    need(policy['kind'] == 'QT612_SERIAL_EXPERIMENTAL_RESOURCE_POLICY_V1' and policy['accepted'] is False
         and policy['Root_acceptance'] is None and policy['builder'] == dict(memory_bytes=4294967296,memory_swap_bytes=4294967296,cpus=1,pids=512,tmpfs_bytes=4294967296,compile_parallelism=1)
         and policy['storage_bytes'] == 12884901888 and policy['cleanup_seconds'] == 90,'UNISSUED_UNWIDENED_EXPERIMENTAL_POLICY')
    inventory = dict(base['inventory'])
    for name,row in dependencies['packages'].items():
        need(name not in inventory,'NO_BASELINE_REPLACEMENT');inventory[name] = row['version']
    need(len(inventory) == 356 and 'qt6-base' not in inventory,'EXACT356_NO_FOREIGN_QT_BINARY')
    raw = ''.join(n+' '+v+'\n' for n,v in sorted(inventory.items())).encode()
    return dict(status='COMPLETE_QT612_PRODUCER_INPUTS_DATA_ONLY',input_plan_complete=True,
                inventory=inventory,inventory_pin=M.pin(raw),actor_enabled=False,
                Root_capacity=None,Root_runtime=None,Root_acceptance=None,native='NOT_RUN',GPG='NOT_RUN')


def project_builder(raw):
    text = raw.decode();edits = []
    def replace(before,after):
        nonlocal text
        need(text.count(before) == 1 and after not in text,'ONE_QT612_BUILD_PROJECTION_SEAM')
        text = text.replace(before,after);edits.append((before,after))
    replace("        name = 'cachy-asahi-' + os.urandom(8).hex()", "        name = 'cachy-qt612-reference-' + os.environ['CACHY_QT612_REFERENCE_NONCE'] + '-' + os.environ['CACHY_QT612_REFERENCE_ATTEMPT']\n        if not re.fullmatch(r'cachy-qt612-reference-[0-9a-f]{32}-[12]', name):\n            raise ValueError('fixed Qt612 clean identity required')")
    replace("                   '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',", "                   '--label', 'org.cachy-asahi.qt612-reference.nonce=' + os.environ['CACHY_QT612_REFERENCE_NONCE'],\n                   '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',")
    replace("'--memory', '4g', '--cpus', '4'", "'--memory', '4g', '--memory-swap', '4g', '--cpus', '1'")
    replace("        paths = sorted(p for p in artifacts.glob('*.pkg.tar.*') if not p.name.endswith('.sig'))", "        paths = sorted(p for p in artifacts.glob('*.pkg.tar.*') if not p.name.endswith('.sig'))\n        if len(paths) != 1 or paths[0].name != '"+PACKAGE+"':\n            raise ValueError('exact one Qt612 XZ output required')")
    replace("'pacman.conf', 'generated.SRCINFO')", "'pacman.conf', 'generated.SRCINFO', 'qt612-stage-contract.json',\n                            'qt612-configuration.json', 'qt612-source-notices.json', 'qt612-dependencies.missing')")
    replace("if __name__ == '__main__':\n    sys.exit(main())", "if __name__ == '__main__':\n    from qt612_actor_gate import require_actual_capacity\n    require_actual_capacity()\n    sys.exit(main())")
    inverse = text
    for before,after in reversed(edits):need(inverse.count(after) == 1,'EXACT_QT612_BUILD_INVERSE');inverse = inverse.replace(after,before)
    need(inverse.encode() == raw,'WHOLE_UNCHANGED_QT612_BUILD_INVERSE')
    return text.encode()


def project_entry(raw,requirements):
    text = raw.decode();edits = []
    def replace(before,after):
        nonlocal text
        need(text.count(before) == 1 and after not in text,'ONE_QT612_ENTRY_PROJECTION_SEAM')
        text = text.replace(before,after);edits.append((before,after))
    replace('export HOME=/tmp/build-home LC_ALL=C.UTF-8 TZ=UTC','export HOME=/tmp/build-home LC_ALL=C.UTF-8 TZ=UTC CMAKE_BUILD_PARALLEL_LEVEL=1 MAKEFLAGS=-j1 MAX_JOBS=1')
    marker = '# No -s, -i, sudo or host mounts: the pinned image must already contain dependencies.'
    check = 'requirements=('+ ' '.join(shlex.quote(v) for v in requirements)+')\nset +e\npacman -T "${requirements[@]}" > /out/qt612-dependencies.missing\ndependency_status=$?\nset -e\n[[ $dependency_status == 0 && ! -s /out/qt612-dependencies.missing ]] || { echo "Normal Qt612 dependencies missing" >&2; exit 2; }\n'
    replace(marker,check+marker)
    before = 'LOGDEST=/out makepkg --cleanbuild --clean --force --log --noconfirm'
    proof = '''LOGDEST=/out makepkg --cleanbuild --force --log --noconfirm
# Retain source/configuration/stage proof before natural --rm destroys tmpfs.
cp -- src/stage-contract.json /out/qt612-stage-contract.json
python /inputs/source.py configuration --build src/build --profile /inputs/configure.cmake > /out/qt612-configuration.json
python /inputs/source.py verify --root src/qtbase-everywhere-src-6.12.0 --policy /inputs/source-notices.json > /out/qt612-source-notices.json'''
    replace(before,proof)
    inverse = text
    for before,after in reversed(edits):need(inverse.count(after) == 1,'EXACT_QT612_ENTRY_INVERSE');inverse = inverse.replace(after,before)
    need(inverse.encode() == raw,'WHOLE_UNCHANGED_QT612_ENTRY_INVERSE')
    return text.encode()


def pair_commands(source,output,image,inventory_pin,*,nonce):
    need(re.fullmatch('sha256:[0-9a-f]{64}',image or '') and re.fullmatch('[0-9a-f]{32}',nonce or ''),'ROOT_IMAGE_AND_NONCE_REQUIRED_FOR_COMMANDS')
    source,output = M.ordinary(source),M.ordinary(output)
    common = ['--image',image,'--mode','native','--network','none','--source-date-epoch','1792021458',
              '--timeout','6900','--expected-packages',str(source/'expected356.lock'),
              '--reviewed-inputs',str(source/'reviewed-inputs.json')]
    return dict(builds=[dict(attempt=str(i),argv=['/usr/bin/python3','-I','-B',str(source/'runtime/scripts/build/build_qt612.py'),str(source/'recipe'),*common,'--output',str(output/('build-'+str(i)))],
                            env=dict(CACHY_QT612_REFERENCE_NONCE=nonce,CACHY_QT612_REFERENCE_ATTEMPT=str(i))) for i in (1,2)],
        compare=['/usr/bin/python3','-I','-B',str(source/'runtime/scripts/build/compare_v2.py'),str(output/'build-1'),str(output/'build-2'),'--require-bytes'],
        required_inventory=inventory_pin,serial=True,require_first_natural_absence_before_second=True,
        actor_enabled=False,Root_capacity=None)


def dependency_image_plan(parent_image,base,dependencies,*,builder_uid,builder_gid):
    need(re.fullmatch('sha256:[0-9a-f]{64}',parent_image or '') and type(builder_uid) is int
         and type(builder_gid) is int and builder_uid > 0 and builder_gid > 0,'ACTUAL_BASE_IMAGE_AND_ORDINARY_BUILDER_REQUIRED')
    need(base['files'] == 517 and len(base['inventory']) == 349 and dependencies['complete'] is True
         and md4c_version(dependencies['packages']['md4c']['version']),'COMPLETE_NORMAL_DEPENDENCIES_BEFORE_IMAGE')
    names = [dependencies['packages'][n]['filename'] for n in sorted(dependencies['packages'])]
    need(len(names) == 7 and all(re.fullmatch(r'[A-Za-z0-9._+:-]+\.pkg\.tar\.xz',n) for n in names),'EXACT_SEVEN_SIGNED_ARCHIVES')
    config = '[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\nHookDir = /builder-disabled-hooks\n'
    dockerfile = ('FROM '+parent_image+'\nUSER root\nCOPY signed-dependencies/ /qt612-deps/\n'
        'COPY qt612.pacman.conf /qt612.pacman.conf\nCOPY expected356.lock /qt612.expected.lock\n'
        'RUN pacman --config /qt612.pacman.conf -U --noconfirm --noscriptlet '+
        ' '.join('/qt612-deps/'+n for n in names)+
        ' && pacman -Q | LC_ALL=C sort > /qt612.actual.lock && diff -u /qt612.expected.lock /qt612.actual.lock'
        ' && rm -rf /qt612-deps /var/cache/pacman/pkg/*\nUSER '+str(builder_uid)+':'+str(builder_gid)+'\n')
    return dict(dockerfile=dockerfile,pacman_config=config,archives=names,expected_packages=356,
                normal_signature_policy='Required TrustedOnly',Root_acceptance=None,actor_enabled=False)


class ProducerHold(ValueError):
    def __init__(self,phase,primary,retention):
        self.phase,self.primary,self.retention = phase,primary,retention
        super().__init__('QT612_PAIR_HOLD_'+phase)


def failure_capsule(error):
    raw = str(error).encode('utf-8',errors='replace')
    return dict(exception=type(error).__name__,message_bytes=len(raw),
                message_sha256=hashlib.sha256(raw[:8192]).hexdigest(),message_truncated=len(raw)>8192)


def serial_pair(plan,executor,*,nonce,finish):
    """Owned-executor protocol; no default executor, process launcher or grant."""
    need(plan['serial'] is True and plan['require_first_natural_absence_before_second'] is True
         and len(plan['builds']) == 2 and re.fullmatch('[0-9a-f]{32}',nonce or ''),'EXACT_SERIAL_PAIR_PLAN')
    need(getattr(executor,'API',None) == 'ROOT_QT612_OWNED_EXECUTOR_V1','ROOT_SELECTED_OWNED_EXECUTOR_REQUIRED')
    need(callable(getattr(executor,'retain_public_failure_evidence',None)),'PUBLIC_FAILURE_RETENTION_REQUIRED_BEFORE_BUILD')
    receipts,phase = [],'PREPARE'
    try:
        for attempt,row in zip(('1','2'),plan['builds']):
            phase = 'BUILD_'+attempt
            need(row['attempt'] == attempt and row['env'] == dict(CACHY_QT612_REFERENCE_NONCE=nonce,CACHY_QT612_REFERENCE_ATTEMPT=attempt),'EXACT_CLEAN_ATTEMPT_BINDING')
            executor.require_domain_and_readonly_filesystem()
            executor.require_no_containers()
            receipt = executor.run(row['argv'],6900,env=row['env'])
            need(type(receipt) is dict and receipt.get('exit') == 0 and receipt.get('reaped') is True
                 and receipt.get('natural') is True and receipt.get('output_complete') is True,'NATURAL_COMPLETE_QT612_BUILD_REQUIRED')
            executor.require_absent_twice('cachy-qt612-reference-'+nonce+'-'+attempt)
            receipts.append(receipt)
        phase = 'COMPARE'
        comparison = executor.run(plan['compare'],120,env={})
        need(type(comparison) is dict and comparison.get('exit') == 0 and comparison.get('reaped') is True
             and comparison.get('natural') is True and comparison.get('output_complete') is True,'NATURAL_STRICT_COMPARISON_REQUIRED')
        executor.require_no_containers();phase = 'QUALIFY'
        return finish(receipts,comparison)
    except BaseException as error:
        primary = failure_capsule(error)
        try:
            retention = executor.retain_public_failure_evidence(phase=phase,primary=primary)
            need(type(retention) is dict and type(retention.get('complete')) is bool,'FINITE_PUBLIC_RETENTION_RECEIPT_REQUIRED')
        except BaseException as retention_error:
            retention = dict(complete=False,retention_error=failure_capsule(retention_error))
        # Caller cleanup follows this exception, after evidence-retention attempt.
        raise ProducerHold(phase,primary,retention) from None


def run_pair(plan,executor,*,expected,source_root,output_root):
    """Only an actual Root-gated owned caller can enter operational callbacks."""
    gate = module('actor_gate').require_actual_capacity(source_root=source_root)
    need(expected['nonce'] == gate['nonce'],'SAME_ACTUAL_PAIR_NONCE')
    source,output = M.ordinary(source_root),M.ordinary(output_root)
    def finish(receipts,comparison):
        finisher = module('finish_pair')
        return finisher.qualify_pair(output/'build-1',output/'build-2',output/'comparison.json',expected=expected,io_module=M)
    return serial_pair(plan,executor,nonce=gate['nonce'],finish=finish)


def verify_producer_source(root,source_map_sha256):
    root = M.ordinary(root);path = root/'source-map.json';observed = {}
    need(type(source_map_sha256) is str and re.fullmatch('[0-9a-f]{64}',source_map_sha256),'EXTERNAL_PRODUCER_MAP_PIN')
    mapping = M.load(path,dict(bytes=path.lstat().st_size,sha256=source_map_sha256),observed)
    need(mapping['kind'] == 'QT612_REFERENCE_PRODUCER_SOURCE_DATA_V1' and mapping['Root_acceptance'] is None
         and mapping['execution_requires_fresh_Root_capacity'] is True and set(mapping['actual']) == set(M.ACTUAL)
         and all(v is None for v in mapping['actual'].values()),'UNISSUED_PRODUCER_SOURCE_ONLY')
    rows = mapping['files'];need(type(rows) is dict and 32 <= len(rows) <= 128
        and sum(row['bytes'] for row in rows.values()) <= 256*1024**2,'FINITE_PRODUCER_SOURCE')
    found,pending,nodes = set(),[root],0
    while pending:
        parent = pending.pop()
        for p in parent.iterdir():
            nodes += 1;need(nodes <= 512 and not p.is_symlink(),'BOUNDED_ORDINARY_PRODUCER_NAMESPACE')
            if p.is_dir():pending.append(p)
            else:need(p.is_file(),'PRODUCER_ORDINARY_LEAF');found.add(p.relative_to(root).as_posix())
    need(found == set(rows)|{'source-map.json'},'COMPLETE_PRODUCER_SOURCE_NAMESPACE')
    for name,row in rows.items():
        M.member(name);need(set(row) == {'bytes','sha256','mode'} and row['mode'] == 0o644,'PRODUCER_EXACT_FILE_MODE')
        M.stream(root/name,{k:row[k] for k in ('bytes','sha256')},observed,cap=512*1024**2,mode=row['mode'])
    M.unchanged(observed)
    return dict(source_map_verified=True,input_plan_complete=mapping['input_plan_complete'],Root_acceptance=None)


def native_gate(*,source_root,source_map_sha256):
    source_state = verify_producer_source(source_root,source_map_sha256)
    need(source_state['input_plan_complete'] is True,'WHOLE_COMPLETE_PRODUCER_INPUT_PLAN_REQUIRED')
    root = M.ordinary(source_root);observed = {}
    def source_json(name):return M.decode(M.stream(root/name,None,observed,collect=True,cap=4*1024**2))
    contract = source_json('F-contract.DATA.json');notice = source_json('F-notices.DATA.json')
    final = module('finish_pair')
    need(M.pin(M.encoded(contract)) == final.SERIAL_CONTRACT_PIN
         and M.pin(M.encoded(notice)) == final.NOTICE_PIN,'EXACT_F_SOURCE_CONTRACT_AND_NOTICES')
    active = contract['native_recipe_files']
    for name,row in active.items():
        M.stream(root/'recipe'/name,{k:row[k] for k in ('bytes','sha256')},observed,mode=row['mode'])
    upstream = contract['upstream']['archive']
    M.stream(root/'recipe'/'qtbase-everywhere-src-6.12.0.tar.xz',
             {k:upstream[k] for k in ('bytes','sha256')},observed,cap=512*1024**2)
    recipe = dict(provenance=dict(recipe_commit=F_COMMIT),active_files=active,
                  source_ref13=[None]*13)
    lock = selected(root/'producer/dependency-candidates.lock.json',DEPENDENCIES,observed)
    policy = selected(root/'producer/resource-EXPERIMENTAL.json',EXPERIMENTAL,observed)
    plan = source_json('input-plan.DATA.json');need(plan['complete'] is True,'WHOLE_COMPLETE_INPUT_PLAN')
    base = validate_base_provider(plan['base_provider'],lock,observed)
    dependencies = plan['dependencies']
    need(dependencies['complete'] is True and len(dependencies['packages']) == 7,'WHOLE_COMPLETE_DEPENDENCY_REFS')
    for name,row in dependencies['packages'].items():
        need(type(row['signature'].get('bytes')) is int and 0 < row['signature']['bytes'] <= 1024**2,'NONEMPTY_NORMAL_DEPENDENCY_SIGNATURE_REQUIRED')
        reference(row['archive'],observed);reference(row['signature'],observed)
        info = pkginfo(row['archive']['path'])
        if name == 'md4c':
            need(md4c_version(row['version']) and info.get('pkgname') == ['md4c']
                 and info.get('pkgver') == [row['version']] and info.get('arch') == ['aarch64'],'NORMAL_MD4C_REVALIDATION')
        else:
            spec = lock['additional'][name]
            need(all(row[k] == spec[k] for k in ('version','arch','filename'))
                 and all({k:row[r][k] for k in ('bytes','sha256')} == spec[r] for r in ('archive','signature'))
                 and info == spec['PKGINFO'],'WHOLE_EXACT_DEPENDENCY_REVALIDATION')
    M.unchanged(observed)
    return admit_complete_preparation(recipe,base,dependencies,policy)


def prepare_producer(*,framework,f_root,archive,output,provider_ref=None,candidate_map=None,md4c=None):
    observed = {};framework,f_root,out = map(M.ordinary,(framework,f_root,output))
    need(not out.exists() and out.parent.is_dir() and all(not out.is_relative_to(p) and not p.is_relative_to(out) for p in (framework,f_root)),'FRESH_DISJOINT_QT612_PRODUCER_SOURCE')
    recipe = F.inspect_serial_recipe(f_root,archive,io_module=M,observed=observed)
    policy = selected(HERE/'resource-EXPERIMENTAL.json',EXPERIMENTAL,observed)
    dep_lock = selected(HERE/'dependency-candidates.lock.json',DEPENDENCIES,observed)
    basis = selected(HERE/'basis.lock.json',M.BASIS_PIN,observed)
    base = validate_base_provider(provider_ref,dep_lock,observed) if provider_ref is not None else None
    deps = dependency_inputs(candidate_map=candidate_map,md4c=md4c,lock=dep_lock,observed=observed) if candidate_map is not None else None
    complete = base is not None and deps is not None and deps['complete']
    admission = admit_complete_preparation(recipe,base,deps,policy) if complete else dict(status='HOLD_MISSING_QT612_SIGNED_INPUTS',input_plan_complete=False,actor_enabled=False,Root_capacity=None,Root_runtime=None,Root_acceptance=None)
    report = dict(schema=1,kind='QT612_CONCRETE_PRODUCER_PREPARATION_DATA_V1',**admission,
        recipe_commit=F_COMMIT,active_recipe_files=14,source_operands=13,notice_count=173,
        baseline_verified_files=0 if base is None else 517,
        signed_additional_packages=0 if deps is None else deps['available_packages'],
        missing_roles=(['complete517.provider'] if base is None else [])+(['signed7.additional.providers'] if deps is None else deps['missing_roles']),
        actual=dict.fromkeys(M.ACTUAL),GPG='NOT_RUN',native_pair='NOT_RUN',signature='NOT_RUN',M2='NOT_RUN',legal='HELD',release=False,
        official_0bd04f_correspondence='HELD',capacity_policy_issued=False,readonly_filesystem_review='ROOT_ACTUAL_REQUIRED',
        original_resource_proposal_unchanged=M.POLICY_PIN,experimental_resource_policy=EXPERIMENTAL)
    requirements = recipe['srcinfo'].get('depends',[])+recipe['srcinfo'].get('makedepends',[])+recipe['srcinfo'].get('checkdepends',[])
    raw_build = M.stream(framework/'scripts/build/build_v2.py',{k:basis['framework_files']['scripts/build/build_v2.py'][k] for k in ('bytes','sha256')},observed,collect=True)
    raw_entry = M.stream(framework/'scripts/build/container-entry-v2.sh',{k:basis['framework_files']['scripts/build/container-entry-v2.sh'][k] for k in ('bytes','sha256')},observed,collect=True)
    projected = {'runtime/scripts/build/build_qt612.py':project_builder(raw_build),'runtime/scripts/build/container-entry-v2.sh':project_entry(raw_entry,requirements)}
    profile_row = basis['framework_files']['scripts/ci/llhttp-reference-native-source/base/profile.json']
    profile = selected(framework/'scripts/ci/llhttp-reference-native-source/base/profile.json',{k:profile_row[k] for k in ('bytes','sha256')},observed)
    for name,row in profile['held_inputs'].items():
        if name.startswith('runtime/') and name not in ('runtime/scripts/build/build_v2.py','runtime/scripts/build/container-entry-v2.sh'):
            projected[name] = M.stream(framework/row['source_path'],{k:row[k] for k in ('bytes','sha256')},observed,collect=True)
    for name,body in projected.items():
        if name.endswith('.py'):compile(body,name,'exec')
    writer = M.Writer(out);files = {}
    try:
        for name,raw in projected.items():files[name] = writer.put(name,raw=raw)
        for name,row in recipe['active_files'].items():files['recipe/'+name] = writer.put('recipe/'+name,source=row['path'],expected={k:row[k] for k in ('bytes','sha256')},observed=observed)
        upstream = next(r for r in recipe['source_ref13'] if r['kind'] == 'upstream-archive')
        files['recipe/'+upstream['alias']] = writer.put('recipe/'+upstream['alias'],source=upstream['path'],expected={k:upstream[k] for k in ('bytes','sha256')},observed=observed,cap=512*1024**2)
        for name in ('producer.py','prepare.py','f_intake.py','f-recipe.lock.json','f-serial-recipe.lock.json','dependency-candidates.lock.json','finish_pair.py','actor_gate.py','resource-EXPERIMENTAL.json'):
            raw = M.stream(HERE/name,None,observed,collect=True);files['producer/'+name] = writer.put('producer/'+name,raw=raw)
        raw = M.stream(HERE/'actor_gate.py',None,observed,collect=True);files['runtime/scripts/build/qt612_actor_gate.py'] = writer.put('runtime/scripts/build/qt612_actor_gate.py',raw=raw)
        reviewed = {n:r['sha256'] for n,r in recipe['active_files'].items()}
        reviewed[upstream['alias']] = upstream['sha256']
        files['reviewed-inputs.json'] = writer.put('reviewed-inputs.json',raw=M.encoded(reviewed))
        if complete:
            inventory = ''.join(n+' '+v+'\n' for n,v in sorted(admission['inventory'].items())).encode()
            files['expected356.lock'] = writer.put('expected356.lock',raw=inventory)
        inputs = dict(base_provider=provider_ref,dependencies=deps,complete=complete,Root_acceptance=None)
        files['input-plan.DATA.json'] = writer.put('input-plan.DATA.json',raw=M.encoded(inputs))
        image_template = dict(kind='QT612_DEPENDENCY_IMAGE_PLAN_UNISSUED_V1',parent_image=None,actual_image=None,
            builder_uid=None,builder_gid=None,required_packages=356,required_signed_additions=7,
            signature_policy='Required TrustedOnly',normal_dependency_checks=True,host_package_mutations=0,
            complete_input_plan=complete,Root_acceptance=None,actor_enabled=False)
        files['dependency-image.UNISSUED.DATA.json'] = writer.put('dependency-image.UNISSUED.DATA.json',raw=M.encoded(image_template))
        files['F-contract.DATA.json'] = writer.put('F-contract.DATA.json',raw=M.encoded(recipe['contract']))
        files['F-notices.DATA.json'] = writer.put('F-notices.DATA.json',raw=M.encoded(recipe['notice_policy']))
        files['producer-report.DATA.json'] = writer.put('producer-report.DATA.json',raw=M.encoded(report))
        template = dict(kind='ROOT_QT612_EXPERIMENTAL_CAPACITY_V1',issued_by=None,accepted=False,source=None,ref=None,source_map_sha256=None,
            policy_pin=EXPERIMENTAL,recipe_commit=F_COMMIT,nonce=None,created_utc=None,expires_utc=None,run=None,attempt=None,input_plan_sha256=files['input-plan.DATA.json']['sha256'])
        files['Root-capacity.UNISSUED.DATA.json'] = writer.put('Root-capacity.UNISSUED.DATA.json',raw=M.encoded(template))
        runtime = dict(template,kind='ROOT_QT612_PRODUCER_RUNTIME_V1',readonly_filesystem_verified=None,owned_controller_kernel_verified=None,
            empty_owned_daemon_verified=None,signed_dependency_inventory_verified=None,provider_gpg_verified=None)
        files['Root-runtime.UNISSUED.DATA.json'] = writer.put('Root-runtime.UNISSUED.DATA.json',raw=M.encoded(runtime))
        mapping = dict(schema=1,kind='QT612_REFERENCE_PRODUCER_SOURCE_DATA_V1',files=files,actual=dict.fromkeys(M.ACTUAL),input_plan_complete=complete,
                       execution_requires_fresh_Root_capacity=True,Root_acceptance=None)
        raw = M.encoded(mapping);writer.put('source-map.json',raw=raw);M.unchanged(observed)
        verify_producer_source(out,M.pin(raw)['sha256'])
        return dict(report,source_map=M.pin(raw),files=len(files)+1,bytes=sum(r['bytes'] for r in files.values())+len(raw))
    finally:writer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('framework','f-root','archive','output'):parser.add_argument('--'+key,type=Path,required=True)
    parser.add_argument('--provider-json',type=Path);parser.add_argument('--provider-sha256');parser.add_argument('--candidate-map',type=Path)
    parser.add_argument('--md4c-json',type=Path);parser.add_argument('--md4c-sha256')
    args = parser.parse_args();provider = None;md4c = None
    if args.provider_json is not None:provider = dict(path=str(args.provider_json),bytes=args.provider_json.lstat().st_size,sha256=args.provider_sha256)
    if args.md4c_json is not None:md4c = M.load(args.md4c_json,dict(bytes=args.md4c_json.lstat().st_size,sha256=args.md4c_sha256),{})
    import sys
    sys.addaudithook(M.fence)
    result = prepare_producer(framework=args.framework,f_root=args.f_root,archive=args.archive,output=args.output,
        provider_ref=provider,candidate_map=args.candidate_map,md4c=md4c)
    print(json.dumps(result,sort_keys=True,indent=2))


if __name__ == '__main__':main()

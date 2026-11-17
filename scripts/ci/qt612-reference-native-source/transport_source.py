# SPDX-License-Identifier: MIT
"""New F69 Source projection; keep a767 input immutable and all actors unissued."""
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('qt612_transport_binding',HERE/'transport_binding.py')
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
P,M,need = B.P,B.M,B.need
ARCHIVE = 'qtbase-everywhere-src-6.12.0.tar.xz'
PARENT = {
    'producer.py':dict(bytes=32191,sha256='9d44ec3ba2ba6063e9857bbaf9898e48828658c506d9dccbc75ab6e0e3c7dc25'),
    'finish_pair.py':dict(bytes=22010,sha256='be918deb2d9e75e48f71ae6cbf7fbc8c820df7652324556e6e9d2f1fb9af9c98'),
    'actor_gate.py':dict(bytes=7754,sha256='74d96a00bed95cf43fe296b76f57b75e5693683a058e74fb83a072602070aac6')}


def project_producer(raw):
    before = "root/'recipe'/'qtbase-everywhere-src-6.12.0.tar.xz'"
    after = "root/'source-material'/'qtbase-everywhere-src-6.12.0.tar.xz'"
    text = raw.decode(); need(text.count(before) == 1 and after not in text,'EXACT_OFFLINE_ARCHIVE_GATE_SEAM')
    projected = text.replace(before,after)
    need(projected.replace(after,before).encode() == raw,'WHOLE_OFFLINE_ARCHIVE_GATE_INVERSE')
    return projected.encode()


def prepare_successor(*,source,source_map_sha256,license_root,output):
    out,root,notices = map(M.ordinary,(output,source,license_root))
    need(not out.exists() and all(not out.is_relative_to(p) and not p.is_relative_to(out) for p in (root,notices)),
         'FRESH_DISJOINT_TRANSPORT_SOURCE')
    P.verify_producer_source(source,source_map_sha256)
    root = M.ordinary(source); observed = {}
    mapping = M.decode(M.stream(root/'source-map.json',dict(bytes=(root/'source-map.json').lstat().st_size,
                                                          sha256=source_map_sha256),observed,collect=True))
    for name,pin in PARENT.items(): M.stream(root/'producer'/name,pin,observed)
    T = B.transport(); basis = T.basis()
    contract_raw = M.stream(root/'F-contract.DATA.json',None,observed,collect=True)
    need(M.pin(contract_raw)['sha256'] == basis['recipe_contract_sha256'],'F69_SOURCE_CONTRACT')
    contract = M.decode(contract_raw)
    inputs = M.decode(M.stream(root/'input-plan.DATA.json',None,observed,collect=True))
    lock = M.decode(M.stream(root/'producer/dependency-candidates.lock.json',P.DEPENDENCIES,observed,collect=True))
    base = P.validate_base_provider(inputs['base_provider'],lock,observed) if inputs['base_provider'] else None
    dependencies = (inputs.get('dependencies') or {}).get('packages',{})
    for name,row in dependencies.items():
        P.reference(row['archive'],observed); P.reference(row['signature'],observed)
        need(row['signature']['bytes'] > 0,'NONEMPTY_DEPENDENCY_SIGNATURE_BYTES')
        info = P.pkginfo(row['archive']['path'])
        if name == 'md4c':
            need(P.md4c_version(row['version']) and info.get('pkgname') == ['md4c']
                 and info.get('pkgver') == [row['version']] and info.get('arch') == ['aarch64'],'NORMAL_MD4C_SOURCE_REVALIDATION')
        else:
            expected = lock['additional'][name]
            need(all(row[k] == expected[k] for k in ('version','arch','filename'))
                 and all({k:row[r][k] for k in ('bytes','sha256')} == expected[r] for r in ('archive','signature'))
                 and info == expected['PKGINFO'],'EXACT_SOURCE_DEPENDENCY_REVALIDATION')
    rows = mapping['files']; writer = M.Writer(output); files = {}
    def put(name,raw): files[name] = writer.put(name,raw=raw)
    try:
        for name,row in rows.items():
            target = 'source-material/'+ARCHIVE if name == 'recipe/'+ARCHIVE else name
            if name in ('reviewed-inputs.json','producer/producer.py','producer/finish_pair.py'): continue
            files[target] = writer.put(target,source=root/name,expected={k:row[k] for k in ('bytes','sha256')},observed=observed,cap=512*1024**2)
        put('recipe/source.json',contract_raw)
        need({n.removeprefix('recipe/'):r['sha256'] for n,r in files.items() if n.startswith('recipe/')} == basis['recipe_inputs'],
             'EXACT_F_TRANSPORT_RECIPE15')
        put('reviewed-inputs.json',M.encoded(basis['recipe_inputs']))
        for name,project in (('producer.py',project_producer),('finish_pair.py',B.project_finisher)):
            original = M.stream(root/'producer'/name,None,observed,collect=True)
            put('inverse/'+name,original); put('producer/'+name,project(original))
        put('inverse/source-map.json',M.stream(root/'source-map.json',None,observed,collect=True))
        put('inverse/reviewed-inputs.json',M.stream(root/'reviewed-inputs.json',None,observed,collect=True))
        for name in ('transport_binding.py','transport_source.py','transport.lock.json'):
            put('producer/'+name,M.stream(HERE/name,None,observed,collect=True))
        lock = M.decode(M.stream(HERE/'transport.lock.json',None,observed,collect=True))
        for name,row in lock['files'].items():
            files['producer/transport_basis/'+name] = writer.put('producer/transport_basis/'+name,
                source=HERE/'transport_basis'/name,expected={k:row[k] for k in ('bytes','sha256')},observed=observed)
        policy = M.decode(M.stream(root/'F-notices.DATA.json',P.module('finish_pair').NOTICE_PIN,observed,collect=True))
        evidence = []
        for i,name in enumerate(('LICENSES/LGPL-3.0-only.txt','LICENSES/GPL-3.0-only.txt',
                                 'LICENSES/Qt-GPL-exception-1.0.txt','REUSE.toml','licenseRule.json')):
            path = M.ordinary(license_root)/name
            license_raw = M.stream(path,None,observed,collect=True)
            pin = M.pin(license_raw)
            need(pin['sha256'] == policy['source_notices'][name],'FROZEN_UPSTREAM_LICENSE_EVIDENCE')
            target = 'notices/'+name
            put('source-material/'+target,license_raw)
            evidence.append(dict(id='upstream-notice-'+str(i),path=target,**pin))
        archive_pin = contract['upstream']['archive']
        source_url = basis['recipe_metadata']['source'][0]
        record = dict(material=dict(id='qtbase612',path=ARCHIVE,**{k:archive_pin[k] for k in ('bytes','sha256')}),
            url=source_url.split('::')[-1],revision='6.12.0',
            license='Qt per-file grants and third-party terms; see pinned notice inventory; legal acceptance HELD',
            license_evidence=evidence)
        catalog = dict(schema_version=1,purpose='source-cache-inputs',sources=[record])
        catalog_raw = M.encoded(catalog); put('source-material/catalog.json',catalog_raw)
        plan = dict(schema_version=1,purpose='offline-build-sources',recipe_inputs=basis['recipe_inputs'],
            catalog_sha256=M.pin(catalog_raw)['sha256'],sources=[dict(source=source_url,id='qtbase612',revision='6.12.0')])
        put('source-material/plan.json',M.encoded(plan))
        binding = dict(schema=1,kind='QT612_F69_TRANSPORT_SOURCE_SUCCESSOR_DATA_V1',
            predecessor_source_map_sha256=source_map_sha256,predecessor_commit='a767ec7577f9b4426b0391db822fc00704e31c2e',
            transport_commit=lock['commit'],recipe_commit=basis['recipe_commit'],
            recipe_inputs=15,source_archive_location='source-material/'+ARCHIVE,
            private_cache='Fresh external owned0700/cache600 required; prepare_cache is passive only',
            source_license_evidence='Five upstream overview/grant files from pinned173 inventory; not legal acceptance',
            workflow_selected=False,operational_binding=None,Root_acceptance=None)
        put('transport-binding.DATA.json',M.encoded(binding))
        put('input-revalidation.DATA.json',M.encoded(dict(status='PASS_AVAILABLE_INPUT_WHOLE_PINS_ONLY',
            base_material_files=0 if base is None else base['files'],additional_packages=len(dependencies),
            additional_material_files=2*len(dependencies),input_plan_complete=inputs['complete'],
            missing_roles=(inputs.get('dependencies') or {}).get('missing_roles',[]),
            GPG='NOT_RUN',Root_acceptance=None)))
        successor = dict(mapping,files=files,transport_binding=files['transport-binding.DATA.json']['sha256'])
        raw = M.encoded(successor); writer.put('source-map.json',raw=raw); M.unchanged(observed)
        P.verify_producer_source(output,M.pin(raw)['sha256'])
        return dict(status='PREPARED_F69_TRANSPORT_SUCCESSOR_DATA_ONLY',source_map=M.pin(raw),
            files=len(files)+1,input_plan_complete=successor['input_plan_complete'],actor_enabled=False,Root_acceptance=None)
    finally: writer.close()


def prepare_cache(*,source,source_map_sha256,output):
    """Private cache DATA construction, no network/source execution/GPG/actor."""
    root,out = map(M.ordinary,(source,output))
    need(not out.is_relative_to(root) and not root.is_relative_to(out),'DISJOINT_PRIVATE_SOURCE_CACHE')
    P.verify_producer_source(source,source_map_sha256)
    root = M.ordinary(source); observed = {}; writer = M.Writer(output)
    def read(name): return M.stream(root/name,None,observed,collect=True)
    try:
        raw = read('source-material/catalog.json'); catalog = M.decode(raw); row = catalog['sources'][0]
        key = row['material']['sha256']; catalog_sha = M.pin(raw)['sha256']
        writer.directory(M.ordinary(output)/'.partial')
        writer.put('FORMAT',raw=b'cachy-asahi-source-cache-v1\n',mode=0o600)
        writer.put('objects/'+key,source=root/'source-material'/ARCHIVE,
            expected={k:row['material'][k] for k in ('bytes','sha256')},observed=observed,cap=512*1024**2,mode=0o600)
        receipt = dict(schema_version=1,purpose='source-cache-receipt',inputs_sha256=catalog_sha,source=row,
            object_path='objects/'+key,legal_acceptance=False,source_completeness_accepted=False)
        writer.put('receipts/'+catalog_sha+'-qtbase612.json',raw=M.encoded(receipt),mode=0o600)
        M.unchanged(observed)
        return dict(status='PREPARED_PRIVATE_OFFLINE_CACHE_DATA_ONLY',archive_sha256=key,Root_acceptance=None)
    finally: writer.close()


def pair_commands(source,output,image,inventory_pin,*,nonce,source_map_sha256,source_cache):
    """Opt-in normal source_materials preflight verifies the exact external cache."""
    P.verify_producer_source(source,source_map_sha256)
    root = M.ordinary(source); observed = {}
    plan = M.stream(root/'source-material/plan.json',None,observed,collect=True)
    plan_sha = M.pin(plan)['sha256']
    # Do not import code from a caller-selected Source. The actual gated builder
    # independently repeats maintained source_materials.prepare/stage in full.
    verify_cache(source=root,source_map_sha256=source_map_sha256,cache=source_cache)
    commands = P.pair_commands(source,output,image,inventory_pin,nonce=nonce)
    for row in commands['builds']:
        row['argv'] += ['--source-plan',str(root/'source-material/plan.json'),'--source-plan-sha256',plan_sha,
                        '--source-catalog',str(root/'source-material/catalog.json'),'--source-cache',str(M.ordinary(source_cache))]
    M.unchanged(observed)
    return commands


def verify_cache(*,source,source_map_sha256,cache):
    P.verify_producer_source(source,source_map_sha256)
    root,cache = M.ordinary(source),M.ordinary(cache); observed = {}
    raw = M.stream(root/'source-material/catalog.json',None,observed,collect=True)
    row = M.decode(raw)['sources'][0]; checksum = M.pin(raw)['sha256']; key = row['material']['sha256']
    expected_receipt = M.encoded(dict(schema_version=1,purpose='source-cache-receipt',inputs_sha256=checksum,
        source=row,object_path='objects/'+key,legal_acceptance=False,source_completeness_accepted=False))
    marker = b'cachy-asahi-source-cache-v1\n'
    names = {'FORMAT':M.pin(marker),'objects/'+key:{k:row['material'][k] for k in ('bytes','sha256')},
             'receipts/'+checksum+'-qtbase612.json':M.pin(expected_receipt)}
    import os,stat
    found = set()
    for parent in (cache,cache/'objects',cache/'receipts',cache/'.partial'):
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and not parent.is_symlink() and info.st_uid == os.geteuid()
             and stat.S_IMODE(info.st_mode) == 0o700,'OWNED_PRIVATE_SOURCE_CACHE')
        for path in parent.iterdir():
            if parent == cache and path.name in ('objects','receipts','.partial'): continue
            found.add(path.relative_to(cache).as_posix())
    need(found == set(names),'EXACT_PRIVATE_CACHE_NAMESPACE')
    for name,pin in names.items(): M.stream(cache/name,pin,observed,cap=512*1024**2,mode=0o600)
    M.unchanged(observed)
    return dict(status='PASS_PRIVATE_CACHE_WHOLE_PINS_ONLY',Root_acceptance=None)

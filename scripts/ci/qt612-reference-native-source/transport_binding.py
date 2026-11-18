# SPDX-License-Identifier: MIT
"""F69 byte-export adapter. Passive DATA tools; no upload, launcher or grant."""
import importlib.util
import os
from pathlib import Path
import re
import stat
import types

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


P = load('qt612_transport_parent', HERE/'producer.py')
M, need = P.M, P.need
STORE_BYTES, STORE_FILES = 8*1024**3, 8192
LOCK_PIN = dict(bytes=1130,sha256='d3e0ab92824fc809b9db32b69f93af5d21b7f994ca96567378e12c9be28d9653')


def transport():
    observed = {}
    lock = M.decode(M.stream(HERE/'transport.lock.json', LOCK_PIN, observed, collect=True))
    need(lock['commit'] == '75cee7ea27e1c9f3d10959e824b261764b9b1c3d'
         and lock['Root_acceptance'] is None and lock['workflow_selected'] is False,
         'FROZEN_UNSELECTED_TRANSPORT')
    need(set(lock['files']) == {'transport.py','basis.json','ACTIONS-PINS.json',
                              'workflow.fragment.yml','README.md','test_transport.py'}, 'EXACT_TRANSPORT_CLOSURE')
    code = None
    for name, row in lock['files'].items():
        raw = M.stream(HERE/'transport_basis'/name, {k:row[k] for k in ('bytes','sha256')}, observed,
                       mode=0o644,collect=name == 'transport.py')
        if name == 'transport.py': code = raw
    value = types.ModuleType('qt612_frozen_transport')
    value.__file__ = str(HERE/'transport_basis/transport.py')
    exec(compile(code,value.__file__,'exec'),value.__dict__)
    value.basis(); M.unchanged(observed)
    return value


def project_finisher(raw):
    """Only change recipe snapshot identity; retain every archive/check gate."""
    before = "    reviewed['qtbase-everywhere-src-6.12.0.tar.xz'] = contract['upstream']['archive']['sha256']"
    after = "    reviewed['source.json'] = pin(encoded(contract))['sha256']"
    before_row = "            row = expected['contract']['native_recipe_files'].get(relative,expected['contract']['upstream']['archive'])"
    after_row = "            row = (pin(encoded(expected['contract'])) if relative == 'source.json' else expected['contract']['native_recipe_files'][relative])"
    text, edits = raw.decode(), []
    for old, new in ((before,after),(before_row,after_row),
                     ('F_ACTIVE14_PLUS_ARCHIVE_BUILDVIEW15','F_ACTIVE14_PLUS_SOURCE_ALIAS_BUILDVIEW15')):
        need(text.count(old) == 1 and new not in text, 'EXACT_TRANSPORT_FINISHER_SEAM')
        text = text.replace(old,new); edits.append((old,new))
    inverse = text
    for old,new in reversed(edits):
        need(inverse.count(new) == 1,'EXACT_TRANSPORT_FINISHER_INVERSE'); inverse = inverse.replace(new,old)
    need(inverse.encode() == raw,'WHOLE_TRANSPORT_FINISHER_INVERSE')
    compile(text,'finish_transport_pair.py','exec')
    return text.encode()


def finisher(expected_sha256=None):
    observed = {}
    raw = M.stream(HERE/'finish_pair.py',None,observed,collect=True)
    original = HERE.parent/'inverse/finish_pair.py'
    if original.exists():
        need(raw == project_finisher(M.stream(original,None,observed,collect=True)),
             'PROJECTED_FINISHER_MATCHES_RETAINED_INVERSE')
    else: raw = project_finisher(raw)
    if expected_sha256 is not None:
        need(re.fullmatch('[0-9a-f]{64}',expected_sha256)
             and M.pin(raw)['sha256'] == expected_sha256,'EXECUTED_FINISHER_EXTERNAL_PIN')
    scope = {'__name__':'qt612_transport_finisher'}
    exec(compile(raw,'finish_transport_pair.py','exec'),scope)
    M.unchanged(observed)
    return scope['qualify_pair']


def operands(record):
    result = {}
    for group, prefix in (('files',''),('artifacts','artifacts/'),('recipe_inputs','inputs/')):
        need(type(record.get(group)) is dict and 0 < len(record[group]) <= 4096,'FINITE_PROVENANCE_OPERANDS')
        for name, digest in record[group].items():
            name = prefix+M.member(name)
            need(re.fullmatch('[0-9a-f]{64}',digest) and (name not in result or result[name] == digest),
                 'EXACT_UNCONFLICTED_OPERAND')
            result[name] = digest
    return result


def whole(path, observed, cap=2*1024**3):
    sink = P.module('finish_pair').HashSink()
    M.stream(path,None,observed,cap=cap,target=sink)
    return sink.result()


def retain_operands(roots, records, included, destination, store_id):
    """Copy ONLY the exact excluded provenance union; no recursive directory copy."""
    need(re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+-]{0,127}',store_id or ''),'OPAQUE_STORE_ID')
    observed, partitions, objects, total = {}, {}, {}, 0
    writer = M.Writer(destination)
    try:
        for attempt in ('build-1','build-2'):
            rows = {}; partitions[attempt] = rows
            for name,digest in operands(records[attempt]).items():
                path = M.ordinary(roots[attempt])/name
                row = whole(path,observed)
                need(row['sha256'] == digest,'CURRENT_WHOLE_PROVENANCE_OPERAND')
                target = included.get((attempt,name))
                if target:
                    rows[name] = dict(row,disposition='included',transport_path=target)
                    continue
                key = M.pin(M.encoded(dict(attempt=attempt,operand=name,**row)))['sha256']
                total += row['bytes']
                need(total <= STORE_BYTES and len(objects) < STORE_FILES,'FINITE_EXTERNAL_RETENTION')
                objects[key] = writer.put('objects/'+key,source=path,expected=row,observed=observed,
                                          cap=2*1024**3,mode=0o600)
                rows[name] = dict(row,disposition='external_retained',external_store_key=key)
        receipt = dict(schema=1,kind='QT612_EXACT_EXCLUDED_OPERANDS_RETAINED_V1',store_id=store_id,
                       objects=objects,provenance_operands=partitions,bytes=total,
                       Root_readback=None,Root_acceptance=None)
        raw = M.encoded(receipt); writer.put('receipt.json',raw=raw,mode=0o600)
        M.unchanged(observed)
        return partitions,M.pin(raw)
    finally: writer.close()


def verify_retention(root, receipt_pin, partitions=None):
    observed = {}; root = M.ordinary(root)
    receipt = M.decode(M.stream(root/'receipt.json',receipt_pin,observed,collect=True,cap=8*1024**2,mode=0o600))
    need(receipt['kind'] == 'QT612_EXACT_EXCLUDED_OPERANDS_RETAINED_V1'
         and receipt['Root_readback'] is None and receipt['Root_acceptance'] is None,'RETENTION_NOT_ROOT_ACCEPTANCE')
    rows = receipt['objects']
    need(len(rows) <= STORE_FILES and sum(r['bytes'] for r in rows.values()) <= STORE_BYTES,'FINITE_RETENTION_READBACK')
    expected = {}
    for attempt, part in receipt['provenance_operands'].items():
        need(attempt in ('build-1','build-2'),'EXACT_RETENTION_ATTEMPT')
        for name,row in part.items():
            M.member(name)
            if row['disposition'] == 'external_retained':
                key = row['external_store_key']
                need(key == M.pin(M.encoded(dict(attempt=attempt,operand=name,bytes=row['bytes'],sha256=row['sha256'])))['sha256'],
                     'RETENTION_OPERAND_KEY_BINDING')
                expected[key] = dict(bytes=row['bytes'],sha256=row['sha256'],mode=0o600)
    need(rows == expected,'COMPLETE_RETENTION_OBJECT_CLOSURE')
    if partitions is not None: need(receipt['provenance_operands'] == partitions,'EXACT_PUBLIC_PRIVATE_PARTITION_JOIN')
    def inventory():
        dirs = {}
        for directory in (root,root/'objects'):
            info = directory.lstat()
            need(stat.S_ISDIR(info.st_mode) and not directory.is_symlink() and info.st_uid == os.geteuid()
                 and stat.S_IMODE(info.st_mode) == 0o700,'PRIVATE_RETENTION_DIRECTORY')
            dirs[str(directory)] = M.identity(info)
        need({p.name for p in root.iterdir()} == {'objects','receipt.json'},'CLOSED_RETENTION_NAMESPACE')
        found = {p.name for p in (root/'objects').iterdir()}
        need(found == set(rows),'NO_EXTRA_MISSING_RETENTION_OBJECTS')
        return dirs
    before = inventory()
    for key,row in rows.items():
        M.stream(root/'objects'/key,{k:row[k] for k in ('bytes','sha256')},observed,cap=2*1024**3,mode=0o600)
    M.unchanged(observed)
    need(inventory() == before,'STABLE_RETENTION_DIRECTORY_NAMESPACE')
    return dict(status='PASS_LOCAL_EXCLUDED_OPERAND_READBACK_ONLY',objects=len(rows),Root_acceptance=None)


def selected_producer(source_root,producer,run):
    need(source_root is not None,'ROOT_SELECTED_PRODUCER_SOURCE_REQUIRED')
    need(type(producer) is dict and set(producer) == {'source_commit','source_map_sha256','program_sha256',
            'finisher_sha256','contract_sha256'} and re.fullmatch('[0-9a-f]{40}',producer['source_commit'])
         and all(re.fullmatch('[0-9a-f]{64}',v) for k,v in producer.items() if k != 'source_commit'),
         'EXACT_EXTERNAL_PRODUCER_SELECTION')
    need(type(run) is dict and set(run) == {'repository','head_sha','run_id','run_attempt','job_id'}
         and run['repository'] == 'Gabriel-Kahen/cachy-asahi' and re.fullmatch('[0-9a-f]{40}',run['head_sha'])
         and all(re.fullmatch('[1-9][0-9]{0,19}',run[k]) for k in ('run_id','run_attempt','job_id')),
         'EXACT_EXTERNAL_RUN_SELECTION')
    P.verify_producer_source(source_root,producer['source_map_sha256'])
    root = M.ordinary(source_root); observed = {}
    path = root/'source-map.json'
    M.stream(path,dict(bytes=path.lstat().st_size,sha256=producer['source_map_sha256']),observed)
    for key,name in (('program_sha256','producer/transport_binding.py'),
                     ('finisher_sha256','producer/finish_pair.py'),('contract_sha256','transport-binding.DATA.json')):
        path = root/name
        M.stream(path,dict(bytes=path.lstat().st_size,sha256=producer[key]),observed)
    own = HERE/'transport_binding.py'
    M.stream(own,dict(bytes=own.lstat().st_size,sha256=producer['program_sha256']),observed)
    M.unchanged(observed)
    return observed


def export_pair(*,first,second,comparison,expected,producer,run,store_id,retention,staging,output,source_root=None):
    """Real qualifying finisher precedes transport assertions; never an actor."""
    T = transport(); b = T.basis()
    targets = list(map(M.ordinary,(retention,staging,output)))
    inputs = list(map(M.ordinary,(first,second)))
    if source_root is not None: inputs.append(M.ordinary(source_root))
    need(all(not p.exists() and all(not p.is_relative_to(q) and not q.is_relative_to(p)
         for q in inputs+targets if p != q) for p in targets) and len(set(targets)) == 3,
         'FRESH_DISJOINT_TRANSPORT_OUTPUTS')
    need(expected['recipe_inputs'] == b['recipe_inputs'],'F69_TRANSPORT_RECIPE_IDENTITY')
    qualified_seen = selected_producer(source_root,producer,run)
    class QualifiedIO:
        def __getattr__(self,name): return getattr(M,name)
        def stream(self,path,expected,observed,**kwargs):
            result = M.stream(path,expected,observed,**kwargs)
            qualified_seen.update(observed)
            return result
    qualification = finisher(producer['finisher_sha256'])(first,second,comparison,expected=expected,io_module=QualifiedIO())
    need(qualification['status'] == 'QT612_REFERENCE_NATIVE_PAIR_POSTCONDITIONS_PASSED'
         and qualification['Root_acceptance'] is None,'REAL_CURRENT_PAIR_QUALIFICATION')
    return _export_qualified(first=first,second=second,comparison=comparison,producer=producer,run=run,
        store_id=store_id,retention=retention,staging=staging,output=output,T=T,qualified_seen=qualified_seen)


def _export_qualified(*,first,second,comparison,producer,run,store_id,retention,staging,output,T,qualified_seen=None):
    """Internal construction seam. MODEL tests do not establish native qualification."""
    b = T.basis(); observed = dict(qualified_seen or {}); records, included, attempts, files = {}, {}, {}, {}
    M.unchanged(observed)
    roots = dict(zip(T.ATTEMPTS,map(M.ordinary,(first,second))))
    writer = M.Writer(staging)
    collected = None
    def raw(path,cap=8*1024**2): return M.stream(path,None,observed,collect=True,cap=cap)
    def put(name,data=None,path=None,expected=None):
        files[name] = writer.put(name,raw=data,source=path,expected=expected,observed=observed,cap=T.MAX_BYTES)
        return files[name]
    try:
        comparison_raw = raw(comparison); put('pair/comparison.json',comparison_raw)
        for attempt,root in roots.items():
            p_raw = raw(root/'provenance.json'); p = M.decode(p_raw); records[attempt] = p
            put(attempt+'/provenance.json',p_raw)
            package = 'artifacts/'+b['filename']; archive = whole(root/package,observed,T.MAX_BYTES)
            put(attempt+'/'+package,path=root/package,expected=archive)
            put(attempt+'/validation.json',raw(root/'validation.json'))
            stage_raw = raw(root/'artifacts/qt612-stage-contract.json'); stage = M.decode(stage_raw)
            put(attempt+'/stage-contract.json',stage_raw)
            check_operand = 'artifacts/'+b['filename'].removesuffix('.pkg.tar.xz')+'-check.log'
            log_pin = whole(root/check_operand,observed,32*1024**2)
            check = dict(schema=1,status='PASS_QT612_OFFSCREEN_API_SMOKE_ONLY',normal_makepkg_check=True,
                         recipe_commit=b['recipe_commit'],archive_sha256=archive['sha256'],
                         check_log=dict(operand=check_operand,**log_pin))
            check_pin = put(attempt+'/check-receipt.json',M.encoded(check))
            license_pin = put(attempt+'/license-receipt.json',M.encoded(dict(
                status='PASS_QT612_SOURCE_NOTICES_ONLY',notices=173,bytes=636122,
                notice_policy_sha256=b['notice_policy_sha256'],archive_sha256=archive['sha256'])))
            aliases = {'artifacts/qt612-stage-contract.json':'stage-contract.json',
                       'artifacts/qt612-check-receipt.json':'check-receipt.json',
                       'artifacts/qt612-license-receipt.json':'license-receipt.json'}
            for name in operands(p):
                target = attempt+'/'+aliases.get(name,name)
                if target in T.payload_names(b): included[attempt,name] = target
            attempts[attempt] = dict(archive=archive,provenance_sha256=M.pin(p_raw)['sha256'],
                stage_canonical_sha256=M.pin(M.encoded(stage))['sha256'],check_receipt_sha256=check_pin['sha256'],
                license_receipt_sha256=license_pin['sha256'])
        put('pair/qt-pair-finisher.json',M.encoded(dict(schema=1,kind='QT612_REFERENCE_PAIR_FINISHER_V1',
            status='PASS_QT612_REFERENCE_PAIR_ONLY',recipe_commit=b['recipe_commit'],
            recipe_contract_sha256=b['recipe_contract_sha256'],comparison_sha256=M.pin(comparison_raw)['sha256'],attempts=attempts)))
        partitions,retention_pin = retain_operands(roots,records,included,retention,store_id)
        verify_retention(retention,retention_pin,partitions)
        receipt = dict(schema=1,kind='QT612_REFERENCE_PAIR_TRANSPORT_RECEIPT_V1',recipe_commit=b['recipe_commit'],
            recipe_contract_sha256=b['recipe_contract_sha256'],producer=producer,run=run,files=files,
            provenance_operands=partitions,external_retention=dict(store_id=store_id,receipt_sha256=retention_pin['sha256']),
            pair_checks=dict.fromkeys(T.FLAGS,True),Root_acceptance=None)
        receipt_raw = M.encoded(receipt)
        # Receipt is outside the exact14 staging tree, then collector writes exact16.
        # Retention namespace stays closed: the public receipt lives in its own sibling.
        receipt_path = Path(staging).parent/(Path(staging).name+'-producer-receipt.json')
        need(not receipt_path.exists(),'FRESH_PUBLIC_RECEIPT')
        fd = os.open(M.ordinary(receipt_path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        try:
            os.fchmod(fd,0o644)
            with os.fdopen(fd,'wb',closefd=False) as stream: stream.write(receipt_raw)
        finally: os.close(fd)
        M.unchanged(observed)
        result = T.collect(staging,receipt_path,M.pin(receipt_raw)['sha256'],output)
        collected = result
        M.unchanged(observed)
        return dict(result,retention_receipt=retention_pin,Root_acceptance=None)
    except BaseException:
        # A reporting-only HOLD must not leave this call's successful manifest.
        if collected is not None:
            marker = M.ordinary(output)/'transport-manifest.json'
            M.stream(marker,dict(bytes=marker.lstat().st_size,sha256=collected['manifest_sha256']),{},mode=0o644)
            marker.unlink()
        raise
    finally: writer.close()


def retain_public_failure_evidence(*,output_root,destination,phase,primary):
    """Finite whole-file HOLD export to call before executor cleanup; no truncation."""
    need(phase in ('PREPARE','BUILD_1','BUILD_2','COMPARE','QUALIFY'),'FINITE_FAILURE_PHASE')
    need(set(primary) == {'exception','message_bytes','message_sha256','message_truncated'}
         and re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,127}',primary['exception'])
         and type(primary['message_bytes']) is int and primary['message_bytes'] >= 0
         and re.fullmatch('[0-9a-f]{64}',primary['message_sha256'])
         and type(primary['message_truncated']) is bool,'HASH_ONLY_PRIMARY_FAILURE')
    root = M.ordinary(output_root); writer = M.Writer(destination); observed,files,total = {},{},0
    try:
        allowed = ['comparison.json']
        log = 'artifacts/'+P.PACKAGE.removesuffix('.pkg.tar.xz')+'-check.log'
        for a in ('build-1','build-2'):
            allowed += [a+'/'+n for n in ('build.log','provenance.json','validation.json',log,
                'artifacts/qt612-stage-contract.json','artifacts/qt612-configuration.json',
                'artifacts/qt612-source-notices.json','artifacts/qt612-dependencies.missing')]
        for name in allowed:
            path = root/name
            if not path.exists(): continue
            row = whole(path,observed,8*1024**2); total += row['bytes']
            need(total <= 32*1024**2,'FAILURE_EXPORT_WHOLE_BYTE_CAP')
            files[name] = writer.put(name,source=path,expected=row,observed=observed,cap=8*1024**2)
        receipt = dict(schema=1,status='HOLD_QT612_PAIR_FAILURE',phase=phase,primary=primary,files=files,
                       complete=True,meaning='Whole available allowlisted failure evidence only',Root_acceptance=None)
        writer.put('failure-receipt.json',raw=M.encoded(receipt)); M.unchanged(observed)
        return receipt
    finally: writer.close()


def run_transport_pair(*,plan,executor,expected,source_root,output_root,producer,run,
                       store_id,retention,staging,output,failure_output):
    """Root-selected owned actor only; concrete finite failure export before cleanup."""
    gate = P.module('actor_gate').require_actual_capacity(source_root=source_root)
    need(expected['nonce'] == gate['nonce'],'SAME_ROOT_TRANSPORT_PAIR_NONCE')
    selected_producer(source_root,producer,run)
    need(run['head_sha'] == os.environ.get('GITHUB_SHA')
         and run['run_id'] == os.environ.get('GITHUB_RUN_ID')
         and run['run_attempt'] == os.environ.get('GITHUB_RUN_ATTEMPT')
         and producer['source_commit'] == run['head_sha'],'SAME_ACTUAL_ROOT_RUN_SELECTION')
    need(getattr(executor,'API',None) == 'ROOT_QT612_OWNED_EXECUTOR_V1','ROOT_OWNED_EXECUTOR_REQUIRED')
    class RetainingExecutor:
        API = 'ROOT_QT612_OWNED_EXECUTOR_V1'
        def __getattr__(self,name): return getattr(executor,name)
        def retain_public_failure_evidence(self,*,phase,primary):
            return retain_public_failure_evidence(output_root=output_root,destination=failure_output,
                                                  phase=phase,primary=primary)
    root = M.ordinary(output_root)
    return P.serial_pair(plan,RetainingExecutor(),nonce=gate['nonce'],finish=lambda receipts,comparison:
        export_pair(first=root/'build-1',second=root/'build-2',comparison=root/'comparison.json',expected=expected,
                    producer=producer,run=run,store_id=store_id,retention=retention,staging=staging,output=output,source_root=source_root))

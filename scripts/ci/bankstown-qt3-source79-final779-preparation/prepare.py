#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Deterministic final779 DATA assembly; no actors, mounts or authority issuance."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

HERE = Path(__file__).resolve().parent
LOCK_PIN = dict(bytes=1523, sha256='9f918521ab8054eaa98f51e971c35143b541f6019a79a6308bea1f7b1630213c')
ADOPTER = 'scripts/ci/bankstown-qt3-source79-adoption-data/adopt.py'
ADOPTER_PIN = dict(bytes=18652, sha256='e845875ab62233ec374484e643a84c8624ad8ffbf7695140221f9ec1afb11e03')
HOSTED = 'scripts/ci/bankstown-qt3-hosted-v1/inputs.py'
READER = 'scripts/ci/bankstown-qt3-hosted-reader-v1/source79/reader.py'
GROUPS = ('base_materials','supplemental_materials','keyring_materials','candidate_materials')
SELECTION_KEYS = {'schema','kind','seed_owner_inputs','seed_provider','publication_receipt',
                  'source_root','material_root','official_trust','custody_selection','observed_epoch','Root_authority'}
TRUST_SCOPE = 'BANKSTOWN_QT3_IMAGE_INPUT_TRUST_ONLY'


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def bootstrap(repo):
    """Only the whole-pinned passive adopter may provide file/DATA callbacks."""
    path = Path(repo)/ADOPTER
    need(path.is_absolute() and path == path.resolve()
         and not any(p.is_symlink() for p in (path,*path.parents)), 'ORDINARY_BOOTSTRAP')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and stat.S_IMODE(before.st_mode) == 0o644 and before.st_size == ADOPTER_PIN['bytes'], 'PINNED_BOOTSTRAP_SHAPE')
        raw = os.read(fd, ADOPTER_PIN['bytes']+1)
        attrs = ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        identity = lambda row:tuple(getattr(row,k) for k in attrs)
        need(pin(raw) == ADOPTER_PIN and identity(before) == identity(os.fstat(fd))
             == identity(path.lstat()), 'WHOLE_STABLE_BOOTSTRAP')
    finally:
        os.close(fd)
    module = types.ModuleType('source79_pinned_adopter')
    module.__file__ = str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


def required_ref(A, ref, expected, observed):
    A.descriptor(ref, 4*1024**2)
    need({k:ref[k] for k in ('bytes','sha256')} == expected, 'EXACT_RETAINED_DATA_PIN')
    return A.decode(A.read(ref['path'], expected, observed))


def distinct_roles(N, owner, count):
    roles = [(group+'/'+name,ref) for group in GROUPS for name,ref in owner[group].items()]
    roles += [(key,owner[key]) for key in ('base_lock','bootstrap_profile','baseline_inventory','catalog')]
    if owner['official_trust'] is not None:
        roles += [('official_trust.'+key,owner['official_trust'][key]) for key in ('Root_admission','public_key')]
    need(len(roles) == count and len({ref['path'] for _,ref in roles}) == count, 'EXACT_DISTINCT_FILE_ROLES')
    refs = N.references(owner)
    need(len(refs) == count, 'EXACT_FINAL_REFERENCE_JOIN')
    return refs


def bind_trust(A, N, trust, fingerprint, now, observed):
    need(type(trust) is dict and set(trust) == {'Root_admission','public_key','fingerprint'}
         and type(trust['fingerprint']) is str and re.fullmatch('[0-9A-F]{40}',trust['fingerprint'])
         and trust['fingerprint'] == fingerprint, 'EXACT_OFFICIAL_TRUST_SELECTION')
    for key,cap in (('Root_admission',2*1024**2),('public_key',65536)):
        N.descriptor(trust[key],cap,empty=False)
    public = A.read(trust['public_key']['path'], {k:trust['public_key'][k] for k in ('bytes','sha256')}, observed)
    need(b'PRIVATE KEY' not in public, 'PUBLIC_CERTIFICATE_DATA_ONLY')
    admission = A.decode(A.read(trust['Root_admission']['path'],
                         {k:trust['Root_admission'][k] for k in ('bytes','sha256')}, observed))
    need(type(admission) is dict and admission.get('issuer') == 'Root' and admission.get('approved') is True
         and admission.get('scope') == TRUST_SCOPE and admission.get('public_key') == trust['public_key']
         and admission.get('fingerprint') == fingerprint
         and type(admission.get('issued_epoch')) is int and type(admission.get('expires_epoch')) is int
         and admission['issued_epoch'] <= now < admission['expires_epoch'], 'FRESH_EXTERNAL_AUDIO_TRUST_DATA')
    return copy.deepcopy(trust)


def bind_custody(A, ref, expected, now, observed):
    """Rejoin externally supplied Root DATA; never claim a mount was observed."""
    A.descriptor(ref,2*1024**2)
    value = A.decode(A.read(ref['path'], {k:ref[k] for k in ('bytes','sha256')}, observed))
    keys = {'schema','kind','issuer','approved','source','source_map','owner_inputs_pin',
            'staged_root','issued_epoch','expires_epoch','launcher_uid','mount_observation'}
    need(type(value) is dict and set(value) == keys and type(value['schema']) is int and value['schema'] == 1
         and value['kind'] == 'ROOT_SOURCE79_RETAINED_INPUT_SELECTION_V1'
         and value['issuer'] == 'Root' and value['approved'] is True, 'EXTERNAL_ROOT_CUSTODY_SELECTION_REQUIRED')
    for key in ('source','source_map','owner_inputs_pin','staged_root'):
        need(value[key] == expected[key], 'EXACT_CUSTODY_INPUT_BINDING')
    need(type(value['issued_epoch']) is int and type(value['expires_epoch']) is int
         and value['issued_epoch'] <= now < value['expires_epoch']
         and 0 < value['expires_epoch']-value['issued_epoch'] <= 4320, 'FRESH_CUSTODY_SELECTION_DATA')
    mount = value['mount_observation']
    mount_keys = {'kind','path','mount_id','parent_mount_id','device','mount_root','filesystem','st_dev','st_ino',
                  'uid','filesystem_bytes','filesystem_inodes','retirement_owner','retirement_observed_here','Root_acceptance'}
    need(type(mount) is dict and set(mount) == mount_keys
         and mount.get('kind') == 'EXTERNAL_ROOT_RETAINED_READONLY_MOUNT_OBSERVATION_V1'
         and mount.get('path') == value['staged_root'] and type(value['launcher_uid']) is int
         and value['launcher_uid'] > 0 and type(mount['uid']) is int and mount['uid'] == value['launcher_uid']
         and mount.get('retirement_owner') == 'Root' and mount.get('retirement_observed_here') is False
         and mount.get('Root_acceptance') is None, 'CALLER_OWNED_MOUNT_ROOT_AUTHORITY_SEPARATE')
    for key,cap in (('filesystem_bytes',32*1024**3),('filesystem_inodes',20000)):
        need(type(mount.get(key)) is int and 0 < mount[key] <= cap, 'FINITE_EXTERNAL_MOUNT_DATA')
    need(all(type(mount.get(k)) is str and mount[k] for k in ('mount_id','parent_mount_id','device','mount_root','filesystem'))
         and all(type(mount.get(k)) is int and mount[k] >= 0 for k in ('st_dev','st_ino')), 'EXACT_EXTERNAL_MOUNT_IDENTITIES')
    return value


def confined_references(refs, source, rows, materials, output):
    if not output.is_relative_to(materials):
        return False
    for ref in refs:
        path = Path(ref['path'])
        if path.is_relative_to(materials):
            continue
        if path.is_relative_to(source) and rows.get(path.relative_to(source).as_posix()) == dict(
                bytes=ref['bytes'],sha256=ref['sha256'],mode=0o644):
            continue
        return False
    return True


def require_unissued(delegation, request):
    need(all(delegation[k] is None for k in ('issuer','approved','nonce','issued_epoch','expires_epoch'))
         and all(request[k] is None for k in ('issuer','approved','trusted_main_commit','control_name'))
         and delegation['binding']['run'] is None and delegation['binding']['job'] is None
         and delegation['image_ids']['qt3'] is None, 'ROOT_AUTHORITY_MUST_REMAIN_UNISSUED')


def prepare(*, repo, selection, selection_pin, output):
    A = bootstrap(repo); observed = {}
    repo, out = A.ordinary(str(repo)), A.ordinary(str(output))
    lock = A.decode(A.read(HERE/'inputs.lock.json',LOCK_PIN,observed))
    value = required_ref(A,dict(path=str(selection),**selection_pin),selection_pin,observed)
    need(type(value) is dict and set(value) == SELECTION_KEYS and type(value['schema']) is int and value['schema'] == 1
         and value['kind'] == 'SOURCE79_FINAL779_PREPARATION_DATA_V1'
         and value['Root_authority'] is None and type(value['observed_epoch']) is int
         and value['observed_epoch'] > 0, 'CLOSED_UNISSUED_PREPARATION_SELECTION')
    source, materials = A.ordinary(value['source_root']), A.ordinary(value['material_root'])
    need(materials.is_dir() and not out.exists() and out.parent.is_dir()
         and not out.is_relative_to(source) and not source.is_relative_to(out)
         and not out.is_relative_to(repo/'scripts') and not materials.is_relative_to(out), 'FRESH_METADATA_OUTPUT_ONLY')
    publication = required_ref(A,value['publication_receipt'],lock['publication_receipt'],observed)
    need(all(publication.get(k) == v for k,v in lock['source'].items())
         and publication.get('public_clone_complete') is True and publication.get('public_blob_tree_join') is True
         and publication.get('issuer') == 'Root', 'EXACT_PUBLIC_SOURCE79_RECEIPT')
    R = A.module(repo,READER,lock['helpers'][READER],observed)
    readiness = R.source_readiness(source)
    need(readiness['full_inverse'] is True and readiness['dispatch_ready'] is False, 'FULL_SOURCE79_INVERSE_REQUIRED')
    N = A.module(repo,HOSTED,lock['helpers'][HOSTED],observed)
    seed = required_ref(A,value['seed_owner_inputs'],lock['seed_owner_inputs'],observed)
    provider = required_ref(A,value['seed_provider'],lock['seed_provider'],observed)
    need(set(seed) == {'base_lock','bootstrap_profile','baseline_inventory','catalog','official_trust',*GROUPS}
         and seed['official_trust'] is None, 'EXACT_UNISSUED_RETAINED_OWNER_INPUTS')
    alock = A.decode(A.read(A.HERE/'inputs.lock.json',A.LOCK_PIN,observed))
    templates = {name:A.decode(A.read(A.HERE/name,p,observed)) for name,p in alock['templates'].items()}
    delegation = templates['Root-delegation.UNISSUED.template.json']
    request = templates['Root-request.UNISSUED.template.json']
    I, rows = N.source_inputs(source,delegation)
    P = I.held(source,'base_inputs_current_v3.py')
    fields = P.assembler_fields(provider)
    need(all(seed[k] == row for k,row in fields.items()), 'EXACT_COMPLETE517_PROVIDER_TUPLE')
    seed_root = Path(seed['base_lock']['path']).parents[1]
    owner = copy.deepcopy(seed)
    for group in GROUPS:
        for name,row in owner[group].items():
            P.filename(name)
            need(Path(row['path']) == seed_root/group/name, 'EXACT_RETAINED_MATERIAL_LAYOUT')
            row['path'] = str(materials/group/name)
    for key in ('base_lock','bootstrap_profile'):
        need(Path(owner[key]['path']) == seed_root/'metadata'/(key+'.json'), 'EXACT_METADATA_LAYOUT')
        owner[key]['path'] = str(materials/'metadata'/(key+'.json'))
    for key,member in (('baseline_inventory','inputs/stages/baseline349.expected.lock'),('catalog','inputs/catalog333.DATA.json')):
        owner[key] = dict(path=str(source/member), **{k:rows[member][k] for k in ('bytes','sha256')})
    distinct_roles(N,owner,777)
    need(sum(ref['bytes'] for group in GROUPS for ref in owner[group].values()) == lock['required_material_bytes'], 'EXACT773_MATERIAL_BYTES')
    plan = I.plan_inputs(source_root=source,source_rows=rows,request=owner,verify_archives=True)
    need(plan['verified_archives'] is True and len(plan['base_rows']) == 257
         and len(plan['additions']) == 128 and len(plan['expected']) == 477, 'REAL_COMPLETE773_PROVIDER_JOIN')
    # Re-emit the genuine provider tuple with only verified material-path rebasing.
    provider = copy.deepcopy(provider)
    for key in ('base_lock','bootstrap_profile',*GROUPS[:-1]):
        provider[key] = owner[key]
    provider['rootfs'] = provider['base_materials'][plan['base']['rootfs']['filename']]
    provider['rootfs_signature'] = provider['base_materials'][plan['base']['rootfs']['filename']+'.sig']
    missing = []
    if value['official_trust'] is None:
        missing = [dict(role='official_trust.'+key,bytes=None,sha256=None)
                   for key in ('Root_admission','public_key')]
    else:
        owner['official_trust'] = bind_trust(A,N,value['official_trust'],plan['base']['signer_fingerprint'],value['observed_epoch'],observed)
    refs = distinct_roles(N,owner,777 if missing else 779)
    # Include stable, distinct inode observations for every real777/779 reference.
    for ref in refs:
        A.stream(ref,observed)
    owner_pin = N.owner_inputs_pin(owner)
    custody_template = dict(schema=1,kind='ROOT_SOURCE79_RETAINED_INPUT_SELECTION_V1',issuer=None,approved=None,
        source=lock['source']['source'],source_map=R.SOURCE79['source_map'],owner_inputs_pin=None if missing else owner_pin,
        staged_root=str(materials),issued_epoch=None,expires_epoch=None,launcher_uid=None,mount_observation=None)
    custody = None
    need(value['custody_selection'] is None or not missing, 'CUSTODY_CANNOT_BIND_INCOMPLETE777_REQUEST')
    if value['custody_selection'] is not None:
        custody = bind_custody(A,value['custody_selection'],custody_template,value['observed_epoch'],observed)
    report = dict(schema=1,kind='SOURCE79_FINAL779_PREPARATION_RESULT_DATA_ONLY',source=lock['source'],
        required_material_files=773,required_material_bytes=1737014022,verified_material_files=773,
        verified_reference_files=len(refs),verified_reference_bytes=sum(r['bytes'] for r in refs),
        missing_file_roles=missing,missing_file_count=len(missing),missing_file_bytes=None if missing else 0,
        complete773_join=True,complete779_join=not missing,archive_copies=0,
        Root_authority=None,Root_admission_issued=None,Root_material_custody=None,dispatch_ready=False,
        external_custody_selection=copy.deepcopy(value['custody_selection']),
        custody_selection_DATA_join=custody is not None,actual_mount_observed=False,GPG='NOT_RUN',
        native='NOT_RUN',M2='NOT_RUN',release=False,source_acceptance='HELD',legal='HELD',key_freshness='HELD',
        original_Qt_minus2='UNCHANGED',exact_Qt_recipe_correspondence='HELD',
        original_Qt_PKGBUILD_sha256='0bd04f4db92ed8b0992e851a4ddd68f39ac7b6b079af4e354dba466946ca2272',
        owner_inputs_pin=owner_pin,
        provider_provenance='Original onboarding source_map/baseline_inventory preserved; only operative material and metadata references rebound',
        missing_bindings=['Fresh official trust fingerprint selection'] if missing else [])
    if custody is None:
        report['missing_bindings'].append('Fresh external Root custody selection; actual mount checks remain launcher-owned')
    report['missing_bindings'] += ['Root launch/delegation authority, trusted Main, runtime context, host/resource/lease truth',
                                   'Separate live executor trial/profile selections and external retirement proof']
    sink = A.CopyDomain(out)
    try:
        owner_ref = A.write(out/'owner-inputs.UNISSUED.DATA.json',owner,sink)
        provider_ref = A.write(out/'complete517.REBOUND.DATA.json',provider,sink)
        custody_ref = A.write(out/'Root-custody.UNISSUED.DATA.json',custody_template,sink)
        envelope_ref = None
        if not missing:
            delegation['inputs_pin'] = owner_pin
            envelope = N.assemble_inputs(complete_reference_result=provider,baseline_inventory=owner['baseline_inventory'],
                candidate_materials=owner['candidate_materials'],catalog=owner['catalog'],official_trust=owner['official_trust'],
                source_root=source,delegation=delegation)
            need(envelope['owner_inputs'] == owner and envelope['staged_refs'] == refs, 'UNCHANGED_FINAL779_ASSEMBLER')
            envelope_ref = A.write(out/'staged-inputs.DATA.json',envelope,sink)
        delegation_ref = A.write(out/'Root-delegation.UNISSUED.DATA.json',delegation,sink)
        request.update(delegation_json=A.encoded(delegation).decode(),delegation_pin=N.pin(A.encoded(delegation)),
                       staged_root=str(materials),staged_inputs=envelope_ref)
        require_unissued(delegation,request)
        request_ref = A.write(out/'Root-request.UNISSUED.DATA.json',request,sink)
        confined = confined_references(refs,source,rows,materials,out)
        if not confined:
            report['missing_bindings'].append('Place small wrapper/output and every non-Source reference inside selected staged root before sealing')
        report.update(status='HOLD_MISSING_FINAL_TRUST_FILES' if missing else 'COMPLETE779_ASSEMBLED_DATA_ONLY',
            owner_inputs=owner_ref,provider=provider_ref,custody_template=custody_ref,staged_inputs=envelope_ref,
            Root_delegation=delegation_ref,Root_request=request_ref,staged_reference_confinement=confined)
        A.unchanged(observed)
        R.source_readiness(source)
        A.write(out/'preparation.DATA.json',report,sink)
        return report
    finally:
        sink.close()


def no_actors(event,args):
    need(not event.startswith(('subprocess.','socket.','ctypes.'))
         and event not in ('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'), 'PREPARATION_DATA_ONLY_NO_ACTORS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('repo','selection','output'):
        parser.add_argument('--'+key,type=Path,required=True)
    parser.add_argument('--selection-sha256',required=True)
    args = parser.parse_args()
    info = args.selection.lstat()
    need(0 < info.st_size <= 4*1024**2, 'FINITE_PREPARATION_SELECTION')
    sys.addaudithook(no_actors)
    report = prepare(repo=args.repo,selection=args.selection,
        selection_pin=dict(bytes=info.st_size,sha256=args.selection_sha256),output=args.output)
    print(json.dumps(report,sort_keys=True,indent=2))


if __name__ == '__main__':
    main()

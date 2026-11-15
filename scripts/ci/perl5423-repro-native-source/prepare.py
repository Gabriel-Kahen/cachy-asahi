#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Construct exact finite Perl ARM intake DATA; never enter operational roles."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
CANDIDATE='c8e9baea97f83f652763e701143d6dec5b679f31'
NAMESPACE='3937d8b9f3210f4e9868bf19f01dfa22de64ddfe'
HELPER=ROOT/'scripts/ci/native-build-namespace-preflight/prepare.py'
HELPER_SHA='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7'
ACTUAL=dict(source=None,ref=None,run=None,job=None,artifact=None,image=None)
GATES=['required_environment_into_actual_builder','aarch64_membership_for_dual_arch_recipe','resolved_libcrypt.so_SONAME_binding','exact_requested_resources_and_actual_inspection','full_build_deadlines_not_old180_450_second_windows','fresh_signed349_inventory_image_and_offline_source_cache','actual_namespace_Source3937_run_and_matching_Reader','closed_Source_publication_workflow_once_role_and_strict_reader_bindings']
def need(ok,why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


need(not HELPER.is_symlink() and pin(HELPER.read_bytes())['sha256']==HELPER_SHA,'read-only constructor helper changed')
spec=importlib.util.spec_from_file_location('perl_packet_atomic',HELPER)
atomic=importlib.util.module_from_spec(spec);spec.loader.exec_module(atomic)


def encode(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def metadata(raw):
    result={}
    for line in raw.decode().splitlines():
        if ' = ' in line:
            key,value=line.strip().split(' = ',1);result.setdefault(key,[]).append(value)
    return result


def dependencies(recipe,refs):
    info=metadata(recipe['.SRCINFO'])
    original=atomic.decode(refs['original-inputs.lock.json'])
    additions=atomic.decode(refs['input-profile.json'])
    desktop=atomic.decode(refs['desktop574-inputs.lock.json'])
    effective={}
    for row in original['rootfs_packages']:
        value=dict(row);value.update(name=row['name'][0],version=row['version'][0],arch=row['arch'][0]);effective[value['name']]=value
    for row in original['packages']+additions['additions']['rows']:effective[row['name']]=dict(row)
    lock=refs['expected349.lock'].decode();pairs=[line.split(' ',1) for line in lock.splitlines()]
    need(lock==''.join(sorted(lock.splitlines(keepends=True))) and len(pairs)==349,'complete sorted349 inventory required')
    expected=dict(pairs);need(len(expected)==349 and {n:r['version'] for n,r in effective.items()}==expected,'effective rootfs/original/fixed8 inventory differs')
    declared={key:info.get(key,[]) for key in ('depends','makedepends','checkdepends','optdepends','license','arch')}
    archives={r['name']:r for r in desktop['packages']};providers={};joins=[]
    for role in ('depends','makedepends','checkdepends'):
        for dep in declared[role]:
            name=re.split(r'[<>=]',dep,maxsplit=1)[0]
            if '.so' in name:
                matches=[r for r in effective.values() if any(v.split('=',1)[0]==name for v in r.get('provides',[]))]
                need(len(matches)==1,'unique SONAME provider required');row=matches[0]
            else:
                need(name in effective,'missing native dependency: '+dep);row=effective[name]
            need(row['arch'] in ('aarch64','any'),'wrong dependency architecture')
            if dep=='gdbm>=1.17':need(row['version']=='1.26-2','fixed gdbm metadata requirement')
            archived=archives[row['name']]
            need(archived['version']==row['version'] and archived['arch']==row['arch'],'individual archive/effective349 version mismatch')
            need(archived.get('license') and archived.get('source_url') and re.fullmatch('[0-9a-f]{64}',archived['sha256']) and re.fullmatch('[0-9a-f]{64}',archived['signature_sha256']),'dependency source/license/archive/signature provenance required')
            providers[row['name']]=dict(effective_metadata=row,individual_archive_metadata=archived)
            joins.append(dict(role=role,declaration=dep,provider=row['name'],version=row['version'],provides=row.get('provides',[])))
    need('libcrypt.so=2-64' in effective['libxcrypt']['provides'],'fixed crypt SONAME provider')
    return dict(schema=1,target='aarch64',declared=declared,baseline=dict(packages=349,lock=pin(refs['expected349.lock']),acquisition='ROOT_ONCE_ROUTE_RETAINED_SIGNED_ROOTFS_ORIGINAL248_FIXED8; NOT_ACQUIRED_BY_CONSTRUCTOR'),joins=joins,providers=providers,
        implicit_build_tools={n:expected[n] for n in ('base-devel','fakeroot','perl')},optional_perl_text_diff=dict(present='perl-text-diff' in effective,meaning='Optional ptardiff support; not a mandatory build dependency'),
        qualification='METADATA_ONLY_NO_FRESH_SIGNATURE_OR_NATIVE_LOAD_BUILD_RESULT')


def validate_contract(c):
    need(c['candidate_commit']==CANDIDATE and c['target']=='aarch64' and c['version']=='5.42.3-1.3','exact1.3 ARM plan')
    need(c['qualification']=='PACKET_ONLY_NATIVE_NOT_RUN' and c['native_acceptance'] is False and c['actual']==ACTUAL,'no operational/native acceptance selectors allowed')
    need(c['makepkg_argv']==['makepkg','--cleanbuild','--nosign','--noconfirm','--log'] and c['full_upstream_target']=='TEST_JOBS=2 make test_harness' and c['builds']==2,'ordinary full-test pair contract required')
    need(c['source_date_epoch']==1785628800 and c['required_environment']['SOURCE_DATE_EPOCH']=='1785628800' and c['required_environment']['CACHY_ASAHI_PERL_BUILD']=='1','exact source epoch/marker required')
    n=c['namespace_prerequisite']
    need(n['source']==NAMESPACE and n['uid']==n['gid']==1001 and n['status']=='PUBLISHED_NOT_RUN' and n['actual_run'] is n['actual_matching_reader'] is None,'Source3937 actual namespace qualification remains unmet')
    r=c['resources'];a=r['actor']
    need(r['status']=='FIXED_PROPOSAL_ROOT_ADMISSION_AND_ENFORCEMENT_NOT_RUN' and r['resource_class']=='HEAVY_NON_KERNEL' and r['concurrency_group']=='native-arm-build' and r['cancel_in_progress'] is False and r['queue']=='max','Root canonical resource admission remains pending')
    need(a['cpus']==2 and a['memory_bytes']==a['memory_swap_total_bytes']==4294967296 and a['pids']==256 and a['uid']==a['gid']==1001 and a['network']=='none' and a['readonly_root'] is True and a['cap_drop']==['ALL'] and a['no_new_privileges'] is True,'fixed proposed actor resources')
    need((r['full_build_seconds'],r['pair_seconds'],r['cleanup_reserved_seconds'],r['job_seconds'])==(2400,6000,180,8100) and r['one_work_volume_at_a_time'] is True and r['export_pin_retire_before_second'] is True,'finite full-build deadlines and sequential retirement')
    need(c['required_Root_adapters']==GATES and c['forbidden']==['nodeps','nocheck','ignorearch','test_filters','privileged_fallback','security_policy_bypass','clock_shim','postbuild_normalization','host_installation'],'all Root adapter/prerequisite and no-bypass holds')


def operands(profile_sha):
    need(type(profile_sha) is str and re.fullmatch('[0-9a-f]{64}',profile_sha),'independently reviewed profile SHA256 required')
    raw,_=atomic.read(HERE/'profile.json',1024**2);need(pin(raw)['sha256']==profile_sha,'whole profile differs')
    p=atomic.decode(raw)
    need(set(p)=={'schema','purpose','candidate_commit','namespace_source','actual','source','recipe_files','packet_files','source_constructor_helper'} and p['purpose']=='FINITE_PERL5423_NATIVE_INTAKE_DATA_ONLY','closed finite packet profile')
    need(p['source_constructor_helper']==dict(path='scripts/ci/native-build-namespace-preflight/prepare.py',sha256=HELPER_SHA),'exact read-only filesystem helper reference')
    need(p['source']['bytes']==22610875 and p['source']['sha256']=='16b23f32e34df12709fc5fa0a7028d3df3c3cfceca21e38faada6a025edff725' and p['source']['commit']=='bc3dab4d4f66de5ea67dda34e5feb5230a54c603','exact upstream source identity')
    need(p['schema']==1 and p['candidate_commit']==CANDIDATE and p['namespace_source']==NAMESPACE and p['actual']==ACTUAL,'exact unadmitted source packet profile')
    recipe=atomic.snapshot(ROOT/'packages/port/perl5423-repro-candidate')
    need(atomic.descriptors(recipe)==p['recipe_files'],'exact tested recipe namespace/bytes/modes required')
    files={};refs={}
    for name,row in p['packet_files'].items():
        atomic.relative(name);body,mode=atomic.read(HERE/name)
        need(dict(**pin(body),mode=mode)==row,'packet operand changed: '+name)
        files[name.removeprefix('packet/')]=(body,mode)
        if name.startswith('references/'):refs[name.removeprefix('references/')]=body
    contract=atomic.decode(files['contract.json'][0]);validate_contract(contract)
    need(files['dependencies.json'][0]==encode(dependencies({n:b for n,(b,_) in recipe.items()},refs)),'complete native dependency projection changed')
    invocation=atomic.decode(files['root-invocation.json'][0])
    need(invocation['authority']=='ROOT_ONLY' and invocation['actual']==ACTUAL,'Root-only unbound invocation template')
    prereq=atomic.decode(refs['namespace-contract.json'])
    need(prereq['qualification']=='SOURCE_ONLY_NOT_RUN' and prereq['acceptance'] is False and prereq['uid']==prereq['gid']==1001,'actual namespace source remains unqualified')
    commit=refs['namespace-commit.raw'];need(atomic.oid(b'commit',commit).hex()==NAMESPACE and commit.startswith(b'tree f1757dbedeed1591cdb8538f6c91e493cd451966\n'),'raw namespace commit/tree')
    files.update({'recipe/'+name:value for name,value in recipe.items()})
    return p,files


def render(source,profile_sha):
    p,files=operands(profile_sha);body,mode=atomic.read(Path(source),32*1024**2)
    need(pin(body)=={k:p['source'][k] for k in ('bytes','sha256')},'exact retained upstream archive required')
    files['sources/'+p['source']['name']]=(body,0o644)
    manifest=dict(schema=1,kind='PERL5423_NATIVE_INTAKE_PACKET_DATA_ONLY',actual=p['actual'],native_acceptance=False,namespace_qualification='NOT_RUN',profile_sha256=profile_sha,files=atomic.descriptors(files))
    files['packet-map.json']=(encode(manifest),0o644)
    need(len(files)<=64 and sum(len(body) for body,_ in files.values())<=32*1024**2,'finite packet file/byte bound')
    return files


def construct(source,profile_sha,output):
    output=atomic.absolute(output)
    frozen=[ROOT/name for name in ('packages','scripts','manifests','.github','.git','docs','tests')]
    need(not any(output.is_relative_to(path) or path.is_relative_to(output) for path in frozen),'output must be disjoint from frozen source trees')
    files=render(source,profile_sha)
    # Filesystem-only atomic no-replace helper; no Git/ref/API publication.
    atomic.publish(files,output)
    return dict(status='CONSTRUCTED_NATIVE_INTAKE_DATA_ONLY',output=str(output),files=len(files),bytes=sum(len(b) for b,_ in files.values()),packet_map=pin(files['packet-map.json'][0]),prospective_packet_tree=atomic.tree(files),actual=dict(source=None,ref=None,run=None,job=None,artifact=None,image=None),native_acceptance=False,namespace_qualification='NOT_RUN')


if __name__=='__main__':
    need(sys.flags.isolated and not sys.flags.optimize,'python -I without optimization required')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile-sha256',required=True);parser.add_argument('--source-archive',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();print(json.dumps(construct(args.source_archive,args.profile_sha256,args.output),sort_keys=True))

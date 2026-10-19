#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit generic development policy; grants no Apple platform acceptance."""
import hashlib
import importlib.util
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value)
    return value


client=load('_generic_policy_client',ROOT/'scripts/client/client.py')
asahi=load('_generic_required_unit_names',ROOT/'packages/tools/cachy-asahi-update/asahi-policy.py')
FIELDS={'schema_version','purpose','release_id','protected_packages','protected_versions','platform_roles',
        'protected_units','before_lock_sha256','after_lock_sha256'}


def need(ok,reason):
    if not ok:raise ValueError(reason)


def lock_sha(versions):
    return hashlib.sha256(''.join(f'{name} {version}\n' for name,version in sorted(versions.items())).encode()).hexdigest()


def protected_names(policy):
    need(type(policy) is dict and set(policy)==FIELDS and type(policy['schema_version']) is int
         and policy['schema_version']==1 and policy['purpose']=='cachy-asahi-generic-development-update-policy',
         'explicit generic development policy required')
    names=asahi.identifiers(policy['protected_packages'],asahi.NAME,limit=587)
    need({'glibc','pacman'}<=names and len(names)<=587,'generic package-manager/runtime protection required')
    asahi.exact(policy['platform_roles'],{'kernel'})
    kernels=asahi.identifiers(policy['platform_roles']['kernel'],asahi.NAME)
    need(kernels<=names,'generic kernels must be protected')
    need(type(policy['protected_versions']) is dict and set(policy['protected_versions'])==names,
         'complete declared protected versions required')
    asahi.versions(policy['protected_versions'],names)
    asahi.exact(policy['protected_units'],set(asahi.REQUIRED_UNITS))
    need(all(set(policy['protected_units'][scope])==units for scope,units in asahi.REQUIRED_UNITS.items()),
         'required protected unit names must be preserved')
    for key in ('before_lock_sha256','after_lock_sha256'):
        asahi.text(policy[key],asahi.SHA)
    asahi.text(policy['release_id'],asahi.NAME)
    return names


def read_policy(path,pin):
    raw=client.read_path(path,1024**2)
    need(hashlib.sha256(raw).hexdigest()==pin,'generic policy changed')
    value=client.decode(raw);protected_names(value);return value


def authorize(policy,settings,snapshot,before,after,before_files,after_files,phase='pre-transaction'):
    names=protected_names(policy)
    need(phase in ('pre-transaction','post-transaction'),'generic policy phase refused')
    need(settings.get('purpose')=='disposable-generic-bound-update'
         and settings.get('model')=='generic-development-only'
         and policy['release_id']==settings.get('release_id')==snapshot['release']['release_id'],
         'explicit generic development selection required')
    need(len(before)==len(after)==587 and lock_sha(before)==policy['before_lock_sha256']
         and lock_sha(after)==policy['after_lock_sha256'],'generic exact before/after locks differ')
    need(names<=before.keys() and names<=after.keys() and
         {name:before[name] for name in names}=={name:after[name] for name in names}==policy['protected_versions'],
         'generic protected package versions changed or absent')
    declared=set(snapshot['spec']['policy']['protected_packages'])
    need(declared==names,'generic protected selection differs from authenticated release')
    kernels=set(policy['platform_roles']['kernel'])
    asahi.owned_releases(before_files,kernels);asahi.owned_releases(after_files,kernels)
    need(all(set(before_files[name])==set(after_files[name]) for name in kernels),'generic kernel ownership changed')
    return dict(decision='generic-development-transaction-allowed',hardware='NOT RUN',apple_acceptance='NOT ESTABLISHED')

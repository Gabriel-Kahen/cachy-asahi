#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build fixed native selection from source-bound producer receipts; no actors."""
import hashlib
import json
from pathlib import Path


def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(path):return json.loads(path.read_bytes())
def encoded(value):return (json.dumps(value,sort_keys=True)+'\n').encode()
def need(ok,why):
    if not ok:raise ValueError(why)


def make(source, transport, trust, identity, image):
    """Runtime caller already proves all context/feature hashes before this stage."""
    pins=load(trust/'pins.json');kit=transport/'good'
    receipt_raw=(kit/'kit.json').read_bytes();need(sha(receipt_raw)==pins['kit_sha256']['good'],'external transport pin')
    inventory=load(kit/'kit.json')['files']
    for name,pin in inventory.items():
        need(sha((kit/name).read_bytes())==pin,'actual transported file differs: '+name)
    release=load(kit/'release/release.json');spec=load(kit/'release/spec.json')
    need(sha((kit/'development.json').read_bytes())==inventory['development.json'],'envelope checksum')
    need(spec.get('synthetic') is False and len(release['packages'])==1,'one real native candidate kit')
    package=release['packages'][0];identity_package={k:package[k] for k in ('name','version','arch','sha256')}
    need(identity_package==pins['package'],'independently retained actual producer package identity')
    name='source-delivery.json';index=load(kit/'release/evidence'/name)
    need(len(index['packages'])==1 and index['packages'][0]['package']==identity_package,'declared source association')
    association=index['packages'][0]
    # Closed allowed source set is in the exact source-bound profile module.
    names={'candidate-worker.py','candidate_profile.py','runtime.py','candidate_lifecycle.py','receiver/LICENSE',
        'receiver/scripts/release/offline_kit.py','receiver/scripts/client/client.py',
        'receiver/scripts/release/source_delivery.py','receiver/scripts/release/recipe_source_delivery.py',
        'receiver/scripts/checks/package_checks.py'}
    sources={name:dict(size=(source/name).stat().st_size,sha256=sha((source/name).read_bytes())) for name in sorted(names)}
    def ref(relative):
        path=kit/relative
        return dict(path='/media/good/'+relative,size=path.stat().st_size,sha256=sha(path.read_bytes()))
    candidate=dict(package=identity_package,archive=ref('release/repo/'+package['filename']),
        signature=ref('release/repo/'+package['filename']+'.sig'),keyring=ref('public.gpg'),
        recipe_sha256=association['recipe']['sha256'],source_bundle_sha256=association['bundle']['sha256'])
    return dict(schema_version=1,purpose='native-arm-real-candidate-development',
        seed_scope='ALPM_DATABASE_ONLY_NOT_BOOTABLE_SYSTEM',source_commit=identity['source_sha'],
        feature_code_sha=identity['feature_code_sha'],image_id=image,
        nonce=sha((identity['token']+':candidate').encode())[:32],
        profile_sha256=sha((source/'profile.json').read_bytes()),
        baseline_packages_sha256='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac',
        runtime_sha256=sources['runtime.py']['sha256'],worker_sha256=sources['candidate-worker.py']['sha256'],
        sources=sources,candidate=candidate,kit=dict(path='/media/good',state_dir='/out/client-state',
            kit_sha256=pins['kit_sha256']['good'],envelope_sha256=sha((kit/'development.json').read_bytes()),
            signer=pins['signer'],namespace=pins['namespace'],minimum_sequence=pins['minimum_sequence']))

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Post-terminal handoff boundary. Schema-2 authorization never becomes v1 VALID."""
from pathlib import Path
import tempfile

from common import decode, digest, encoded, need, pinned, read, snapshot, load_snapshot, write_new

ROOT = Path(__file__).resolve().parents[3]
HELD = {
    'adapter.py': '69ad53b4bc041d37536ad15a4ced7efa4cb2d61bcd6cb4a62fdfce8a7dbd52ab',
    'gate.py': 'f535f5f5fe76c8680e46513a7a727b5f0652488c462d3d5295293200630f080d',
}
DEPENDENCIES = {
    'scripts/release/release.py': '418c850e8a44ae71517e074f86f46f5999f5fe7433ca6798de945f318191a918',
    'scripts/client/client.py': '3025aa0e167c836e31c949e0915d4ee82a1007dc0fada598b4895240c82f5f97',
}


def held_modules(repo_root, scratch):
    """Authenticate all held sources before compiling any imported source."""
    repo_root, scratch = Path(repo_root), Path(scratch)
    source = repo_root / 'scripts/port/repository-client-stage'
    pins = {name: {'sha256': pin, 'mode': 0o644} for name, pin in HELD.items()}
    # Authenticate frozen semantic/client dependencies before importing the adapter.
    for name, pin in DEPENDENCIES.items():
        need(digest(read(repo_root / name)) == pin, 'frozen release/client dependency differs')
    copied = snapshot(source, pins, scratch / 'held')
    return load_snapshot(copied, ('gate', 'adapter'))


def terminal(summary_raw, summary_pin, public_raw, public_pin, cleanup_raw, cleanup_pin, identity):
    summary, public, cleanup = (pinned(raw, pin) for raw, pin in
                                ((summary_raw, summary_pin), (public_raw, public_pin), (cleanup_raw, cleanup_pin)))
    need(summary.get('schema_version') == 1 and summary.get('purpose') == 'frozen-development-only-native-integration'
         and summary.get('status') == 'PASS' and summary.get('cancelled') is False
         and summary.get('source_commit') == identity['source_commit'] and summary.get('base_image') == identity['image_id']
         and summary.get('owned_image_cleanup', {}).get('status') == 'PASS'
         and summary['owned_image_cleanup'].get('absence_verified') is True
         and summary['owned_image_cleanup'].get('cleanup_uncertain') is False,
         'terminal integration and image cleanup PASS required')
    need(all(summary.get('stages', {}).get(name, {}).get('status') == 'PASS' for name in
             ('fixtures', 'signer', 'lifecycle', 'repository', 'onboarding', 'desktop', 'source-suites')),
         'complete initial integration stages required')
    need(public.get('purpose') == 'accepted-repository-public-artifacts' and public.get('status') == 'PASS'
         and all(public.get(key) == identity[key] for key in ('source_commit', 'run_id', 'nonce')),
         'external successful public/binary acceptance required')
    need(cleanup.get('status') == 'PASS' and cleanup.get('container') == 'cachy-asahi-repository-' + identity['nonce']
         and isinstance(cleanup.get('container_id'), str) and len(cleanup['container_id']) == 64
         and all(char in '0123456789abcdef' for char in cleanup['container_id'])
         and all(cleanup.get(key) is True for key in ('absence_verified', 'name_absence_verified', 'id_absence_verified')),
         'original container name and CID cleanup required')
    return {'summary_sha256': summary_pin, 'public_acceptance_sha256': public_pin, 'cleanup_sha256': cleanup_pin}


def post_terminal(input_root, authority_raw, authority_pin, crypto_raw, crypto_pin, metadata_raw, metadata_pin,
                  *, repo_root=ROOT):
    """Inspect the held admission contract; refuse its incompatible crypto schema.

    Does not flatten current revoked-A outcomes into VALID. No signing worker is
    launched until a successor gate/adapter has been reviewed and pinned.
    """
    authority, crypto = pinned(authority_raw, authority_pin), pinned(crypto_raw, crypto_pin)
    metadata = pinned(metadata_raw, metadata_pin)
    need(authority.get('purpose') == 'accepted-repository-client-inputs' and authority.get('status') == 'PASS',
         'external admission authority required')
    refs = authority['refs']
    files = authority['files']
    def observation(role):
        name = refs[role]
        raw = read(Path(input_root) / name)
        need(len(raw) == files[name]['bytes'] and digest(raw) == files[name]['sha256'], 'terminal reference drift')
        return raw, files[name]['sha256']
    pins = terminal(*observation('aggregate'), *observation('public_acceptance'), *observation('cleanup'), authority)
    need(crypto.get('schema_version') == 2 and crypto.get('purpose') == 'repository-cryptographic-phases'
         and crypto.get('status') == 'PASS' and crypto.get('original_local_certification') == 'native-receipts-only'
         and crypto.get('current_A_authorization') == 'REVOKED' and crypto.get('private_work_cleanup') == 'PASS'
         and all(crypto.get(key) == authority[key] for key in ('source_commit', 'run_id', 'nonce', 'image_id')),
         'independent explicit-phase cryptographic acceptance required')
    expected = authority.get('crypto', {}).get('signed_objects', [])
    snapshot_rows, terminal_rows = crypto.get('snapshot_integrity'), crypto.get('terminal_authorization')
    need(isinstance(expected, list) and len(expected) == 15 and isinstance(snapshot_rows, list)
         and isinstance(terminal_rows, list) and len(snapshot_rows) == len(terminal_rows) == 15,
         'complete fifteen phase objects required')
    need(sum(row.get('signer') == 'signer-A' for row in expected) == 7 and
         sum(row.get('signer') == 'signer-B' for row in expected) == 8, 'exact phase signer counts required')
    for original, integrity, authorization in zip(expected, snapshot_rows, terminal_rows):
        need(all(row.get(key) == original[key] for row in (integrity, authorization) for key in ('path', 'signature', 'signer'))
             and integrity.get('integrity') == authorization.get('integrity') == 'VALID'
             and integrity.get('authorization') == 'SNAPSHOT_ONLY'
             and authorization.get('authorization') == ('REVOKED' if original['signer'] == 'signer-A' else 'VALID_AT_OBSERVATION'),
             'snapshot integrity/current authorization phase differs')
        for row in (integrity, authorization):
            need(row.get('data_sha256') == files[original['path']]['sha256']
                 and row.get('signature_sha256') == files[original['signature']]['sha256'], 'phase artifact bytes differ')
    need(metadata.get('acceptance_sha256') == authority_pin, 'metadata admission pin differs')
    with tempfile.TemporaryDirectory(prefix='cachy-asahi-rcn-contract-') as temporary:
        modules = held_modules(repo_root, Path(temporary))
        # These fields define the held v1 contract; its input gate does no crypto.
        need('crypto' in modules['gate'].FIELDS and callable(modules['adapter'].execute), 'held interface unavailable')
        need(authority.get('crypto', {}).get('purpose') == 'external-repository-cryptographic-acceptance',
             'held v1 authority schema differs')
    return {'schema_version': 1, 'purpose': 'repository-client-native-post-terminal', 'status': 'NOT RUN',
            'development_only': True, 'selected_for_release': False, 'repository_authority_sha256': authority_pin,
            'crypto_sha256': crypto_pin, 'metadata_sha256': metadata_pin, 'terminal': pins,
            'held_source_sha256': HELD, 'blockers': ['held gate schema 1 has unqualified VALID for revoked-A objects; phase-aware successor required'],
            'signer_generated': False, 'client_execution': 'NOT RUN', 'original_B_continuity': False,
            'hardware_validation': 'NOT RUN', 'installation': 'NOT RUN', 'native_end_to_end': 'NOT RUN'}

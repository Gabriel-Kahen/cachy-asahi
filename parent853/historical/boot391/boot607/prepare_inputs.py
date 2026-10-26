# SPDX-License-Identifier: MIT
"""Reuse accepted unsigned Boot bytes during the original producer TEST lifetime."""
import re
import shutil
from pathlib import Path
import accepted_inputs as A


def make(*, packet, original606_root, producer, ready604, output, C, checks, nonce):
    """Native owner only, after original source/input authority, before consumer.

    C is the whole original held604 contract. No new key generation, persistent
    signer, package build, remote request, imported carrier code or host install.
    """
    A.need(type(nonce) is str and re.fullmatch('[0-9a-f]{32}',nonce), 'fresh source-owned native context nonce')
    native = A.inspect(packet, checks)
    manifest = C.read(ready604/'manifest.json')
    roles = manifest['preparation']['signer_roles']
    A.need(set(roles) == {'ephemeral_TEST','upstream_ALARM'} and len(set(roles.values())) == 2 and
           all(re.fullmatch('[A-F0-9]{40}', value or '') for value in roles.values()), 'same two original signer roles')
    keys = manifest['keyrings']
    A.need(len(keys) == 2 and {r['path'] for r in keys} == {'keys/TEST-public.asc','keys/archlinuxarm.gpg'}, 'same original public keyring operands')
    for row in keys:
        A.need(set(row)=={'path','size','sha256'} and A.pin(A.read(ready604/row['path'],1024**2))==dict(bytes=row['size'],sha256=row['sha256']), 'complete original two public keyring bytes')
    public = next(row for row in keys if row['path'] == 'keys/TEST-public.asc')
    public_path = ready604/public['path']
    A.need(A.pin(A.read(public_path, 65536)) == dict(bytes=public['size'],sha256=public['sha256']), 'original producer public key bytes')
    A.need(not output.exists() and not output.is_symlink() and output.parent.is_dir(), 'fresh owned Boot input context')
    output.mkdir(mode=0o700)
    archive = output/native['archive'].name
    shutil.copyfile(native['archive'], archive)
    A.need(A.pin(A.read(archive)) == A.ARCHIVE, 'copied accepted archive unchanged')
    materializer = C.scoped_load('boot607_held_materializer', original606_root/'held604/scripts/ci/expanded600-installer-vm/materializer.py', {'contract':C})
    materializer.sign(producer/'private/test-signing', [archive], roles['ephemeral_TEST'])
    signature = archive.with_name(archive.name+'.sig')
    verifier_api = C.load('boot607_held_public_verifier', original606_root/'held604/scripts/ci/full-composition-installer-vm/producer.py')
    verifier = verifier_api.PublicVerifier(producer/'private/boot607-public-verifier', [public_path])
    try:
        verifier(archive, signature, roles['ephemeral_TEST'])
        # Retain the old verifier, and additionally reject complete GPG expiry
        # status tokens before any native consumer can receive the archive.
        import subprocess
        value = subprocess.run(verifier.argv+['--status-fd=1','--verify',str(signature),str(archive)],
                               capture_output=True, timeout=30, check=True)
        status = value.stdout.decode()
        verifier_api.valid_signer(status, roles['ephemeral_TEST'])
        A.need(not re.search(r'\[GNUPG:\] (KEYEXPIRED|SIGEXPIRED|BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|KEYREVOKED|NO_PUBKEY)(?: |\n|$)', status), 'strict signer/signature validity')
        verification = dict(stdout=A.pin(value.stdout),stderr=A.pin(value.stderr),returncode=value.returncode)
    finally:
        verifier.close()
    A.need(A.pin(A.read(archive)) == A.ARCHIVE, 'signing must preserve original unsigned archive')
    plan = dict(schema_version=1, status='READY_ACCEPTED_BOOT_PAIR_FRESH_ORIGINAL_TEST_SIGNATURE',
                authority_scope='INPUTS_ONLY_NO_NEW_NATIVE606_OR607_ACCEPTANCE',nonce=nonce,nonce_authority='SOURCE_OWNED_NOT_INDEPENDENT_ROOT_OBSERVATION',
                accepted_source=A.SOURCE, accepted_run=A.RUN, accepted_index=A.INDEX,original604_manifest=A.pin(A.read(ready604/'manifest.json')), 
                name=A.NAME,version=A.VERSION,archive=archive.name,**A.ARCHIVE,
                signature=dict(path=signature.name,**A.pin(A.read(signature,65536))),
                signer=roles['ephemeral_TEST'],signer_roles=roles,public_key=public,
                payload=native['payload'],verification=verification,new_builds='NOT_RUN_REUSED_ACCEPTED_PAIR',
                actual_source=None,actual_ref=None,actual_run=None)
    (output/'input-plan.json').write_bytes(C.encoded(plan))
    for path in output.iterdir():
        A.need(not path.is_symlink() and path.is_file(), 'ordinary readonly consumer inputs')
        path.chmod(0o444)
    output.chmod(0o755)
    return plan

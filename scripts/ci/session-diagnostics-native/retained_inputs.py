# SPDX-License-Identifier: MIT
"""Exact retained574 cache DATA; all original authentication/native gates remain."""
import hashlib,json
from pathlib import Path
import contract as C
need=C.need

RETAINED574_SOURCE='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
RETAINED574_BEFORE=('bubblewrap-0.13.0-1-aarch64.pkg.tar.xz', 'bubblewrap-0.13.0-1-aarch64.pkg.tar.xz.sig', 'curl-8.22.0-1-aarch64.pkg.tar.xz', 'curl-8.22.0-1-aarch64.pkg.tar.xz.sig', 'jbigkit-2.1-8-aarch64.pkg.tar.xz', 'jbigkit-2.1-8-aarch64.pkg.tar.xz.sig', 'libarchive-3.8.9-1-aarch64.pkg.tar.xz', 'libarchive-3.8.9-1-aarch64.pkg.tar.xz.sig', 'libtiff-4.7.2-1-aarch64.pkg.tar.xz', 'libtiff-4.7.2-1-aarch64.pkg.tar.xz.sig', 'openssh-10.6p1-1-aarch64.pkg.tar.xz', 'openssh-10.6p1-1-aarch64.pkg.tar.xz.sig', 'pacman-7.1.0.r9.g54d9411-2-aarch64.pkg.tar.xz', 'pacman-7.1.0.r9.g54d9411-2-aarch64.pkg.tar.xz.sig', 'uwsm-0.27.0-1-any.pkg.tar.xz', 'uwsm-0.27.0-1-any.pkg.tar.xz.sig', 'xorg-server-common-21.1.25-1-aarch64.pkg.tar.xz', 'xorg-server-common-21.1.25-1-aarch64.pkg.tar.xz.sig', 'zlib-1:1.3.2-3-aarch64.pkg.tar.xz', 'zlib-1:1.3.2-3-aarch64.pkg.tar.xz.sig')


def validate_retained_inputs(value):
    source=Path(__file__).resolve().parents[3]
    lock_path=source/'scripts/ci/maintained-desktop574-inputs.json';raw=lock_path.read_bytes()
    need(len(raw)==623664 and hashlib.sha256(raw).hexdigest()=='b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9','retained original574 lock differs')
    expected={}
    for row in json.loads(raw)['packages']:
        expected[row['filename']]=dict(bytes=row['size'],sha256=row['sha256'])
        expected[row['filename']+'.sig']=dict(bytes=row['signature_size'],sha256=row['signature_sha256'])
    need(type(value)is dict and value.get('status')=='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY' and value.get('mode')=='desktop574' and value.get('source')==RETAINED574_SOURCE and value.get('actual')is None,'exact retained574 DATA receipt required')
    carrier=value.get('carrier',{});need(type(carrier)is dict,'typed retained carrier proof required')
    need(carrier.get('source')==RETAINED574_SOURCE and carrier.get('ref')=='codex/native574-complete-retained-inputs-v1' and carrier.get('tree')=='e21f947bac3afdfbd67e4e65c8234b35ae42b00f' and carrier.get('status')=='WHOLE_IMMUTABLE_SOURCE_GIT_JOIN_NO_NATIVE_AUTHORITY' and carrier.get('files')==carrier.get('blob_joins')==1154,'whole immutable retained574 carrier proof required')
    receipt=value.get('receipt',{});need(type(receipt)is dict,'typed retained receipt required');cache=receipt.get('cache',{});need(type(cache)is dict,'typed retained cache required')
    need(receipt.get('actual_authority')is False and receipt.get('status')=='EXACT_PUBLIC_CACHE_INPUTS_JOINED_NOT_AUTHENTICATED' and receipt.get('mode')=='desktop574' and receipt.get('original_lock')==dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),'retained cache is original-lock DATA only')
    need(len(expected)==1148 and receipt.get('inputs')==cache.get('after_files')==expected,'all1148 original package/signature cache pins required')
    wanted_before={name:expected[name] for name in RETAINED574_BEFORE}
    need(cache.get('before_files')==wanted_before and cache.get('added')==1128 and cache.get('fresh_cache')is False and cache.get('mode')==0o700 and cache.get('owner')=='CALLER_UID','exact existing20 plus1128 retained cache additions required')
    prior=cache.get('before_identity');directory=cache.get('directory_identity')
    need(type(directory)is list and len(directory)==6 and all(type(v)is int for v in directory) and directory[2]==0o40700,'ordinary retained cache directory identity required')
    need(type(prior)is dict and set(prior)==set(wanted_before) and cache.get('all_previous_inode_metadata_bytes_unchanged')is True and cache.get('after_previous_identity')==prior and cache.get('after_directory_identity')==cache.get('directory_identity'),'existing input/directory identities must be preserved')
    return dict(status='PASS_EXACT_RETAINED1148_DATA_NOT_AUTHENTICATION',files=1148,added=1128,preserved=20,actual_authority=False)



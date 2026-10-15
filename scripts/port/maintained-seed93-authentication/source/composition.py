"""Pure retained selected-key coverage joins; no IO, actors, CLI or trust grant."""
import hashlib
import json
import math
import re
from helper_policy import validate_gpg, validate_observation

PINS = {'builder': {'bytes': 328101, 'sha256': 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'}, 'current_actual_admission': {'bytes': 1260, 'sha256': '860e7da809aef71d6bc7922df27f04dc6a04596dda47937b4d1aff8f4f70f488'}, 'current_actual_peer': {'bytes': 1967, 'sha256': 'b2356270bea66d9ed1559fdf91081a6f7a52ff5dbb3f1a3bae5daca19f308f45'}, 'current_archives': {'bytes': 215830, 'sha256': 'f8f4a3748a962e2f793702207cbaf32ed6106a635ad35f70a0f5551d7c6a2362'}, 'current_authentication': {'bytes': 361603, 'sha256': '11cb72325d5a73a1a57ad9cfc8c0930df8f3c47309e0666847609babec1cf3c8'}, 'current_binding': {'bytes': 2118, 'sha256': '5064c4dcea0ee3f45f82e41b7470d822eacd84aebf9a58fd155149667b06ffa0'}, 'current_core': {'bytes': 256689, 'sha256': '91b52f917c664d5c6c16686b4749b2c4bb3f2673b49097f736d145ba88016364'}, 'current_extra': {'bytes': 10610805, 'sha256': 'f26b9c8dfd9211400ac605d7a2c0d08b7cfbd2de88b595b97b8e7d8af64dcffd'}, 'current_parent': {'bytes': 511, 'sha256': '7e097a62b708190384b6cc142f59a9c86d2fd579995bce072ee2b1a487d4c07e'}, 'current_proposal': {'bytes': 4959, 'sha256': 'a7a83e750112446026a05fcd0a1a410a8c7aac218afeeed30e106a181ab9aca7'}, 'current_repositories': {'bytes': 456, 'sha256': 'f00e7e39141d125400c30108994a46cf52ff57e3b03a6d8cab72dfc1fcdee033'}, 'current_sidecar': {'bytes': 878, 'sha256': '90aa6719a47b3a62a025b846b17a472b44d24cb78439d4c157d438a03e4a042f'}, 'current_worker': {'bytes': 989543, 'sha256': 'd536a11eb27a3cade695351c3f6475d438de865b4240d9990207e42146abeca0'}, 'enrichment93': {'bytes': 92476, 'sha256': '14a85c194f4312879a239a8a6e728af3fa94b464c8ef3b6485be8ee74b51538d'}, 'enrichment_spec': {'bytes': 4520, 'sha256': 'f086a35eba4d01ed91336e994dfa7f27d8778a3723db991d3c2ab16a3522bb6b'}, 'final_lock': {'bytes': 11117, 'sha256': 'adf91712422e86817d027c4c8089023df980c53dede701e8599402e743dd0641'}, 'gap_receipt': {'bytes': 3318, 'sha256': '9b54841b28632db431a5163d7122873a38afec36d83b131135293a4fbd22cff2'}, 'historical_core': {'bytes': 256696, 'sha256': '5f184763bad034ac02662ee37d87edad8124244c8609f4a441947da1855b0b08'}, 'historical_two': {'bytes': 4197, 'sha256': '445f70b2c202cea6c3aa7b8d76530272820f05ab1986e899addb96a075352d66'}, 'key_archlinuxarm-revoked': {'bytes': 0, 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'key_archlinuxarm-trusted': {'bytes': 44, 'sha256': 'f2a7250f2a2b77542f82f4219b2bae7895f27b3dcfdf350b497e2be306af776d'}, 'key_archlinuxarm.gpg': {'bytes': 3098, 'sha256': '6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f'}, 'legacy_authenticate': {'bytes': 17452, 'sha256': '241cd67370eb593bdf948a25788f006ecf470c645ba5d198bc9c318119ebfe10'}, 'legacy_native': {'bytes': 28489, 'sha256': '1a5369e007193fafce355ca6d20f4e771a0f342e0176bfd80f95a718328a0d10'}, 'legacy_preview': {'bytes': 19736, 'sha256': 'd737c51474e05cc2c4db2e87fc021f50328eea7744983dd4076d44751fce7383'}, 'metadata_admission': {'bytes': 823, 'sha256': '978a6486c9028edd1086ac7f3fb1e9e84b9f6dd751a1f5774220b7f41b4dff7b'}, 'prior_completion': {'bytes': 25830, 'sha256': '1302243720fb2e621431fd9ed71f249aabad7979c8ea31b6990ae0f471087b8d'}, 'prior_input': {'bytes': 328101, 'sha256': 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'}, 'prior_package_audit': {'bytes': 6347750, 'sha256': 'd737215476f92511fc2d268aa02ad64b45b2011e473d4102dadc4d5dce2c6dd7'}, 'prior_peer': {'bytes': 29431, 'sha256': '07144f43ba37aeb4f83f94882a9841549c69fb45b0352b15a3eed63c0d1007af'}, 'prior_result': {'bytes': 451, 'sha256': 'bd0dee3a57cd7003b850d8b70e9579e534395dfef0afe0748a352996a1b0cd12'}, 'prior_rootfs_inventory': {'bytes': 56107, 'sha256': '72bbef83fd87e3da228b3cdc0105b0051b86f9c7c3d7c4eed90b264eb755267f'}, 'prior_signatures': {'bytes': 388022, 'sha256': '203d46d3eb69b9eb4e4a849d070376edb2a94ea103314aaa93ce24ae251500f8'}, 'projection': {'bytes': 661251, 'sha256': '2214b5170d8f2f0e0e86d7f1a88efc8a421c40d7186263d5c0c9913686d5a00a'}, 'proposal574': {'bytes': 589943, 'sha256': 'b853ef2e4568cdf0e4c669515e6dcd6eaa60cedd2c14d7228ee24cf1914bd07a'}, 'seed': {'bytes': 229285, 'sha256': 'a0e0dc168ceccddf80eff3de57f9515973f0c6810f021425813d46d9425a3e88'}, 'seed_lock': {'bytes': 6674, 'sha256': 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'}}
FILENAMES = {'builder': 'inputs/builder.json', 'current_actual_admission': 'inputs/current_actual_admission.json', 'current_actual_peer': 'inputs/current_actual_peer.json', 'current_archives': 'inputs/current_archives.json', 'current_authentication': 'inputs/current_authentication.json', 'current_binding': 'inputs/current_binding.json', 'current_core': 'inputs/current_core.db', 'current_extra': 'inputs/current_extra.db', 'current_parent': 'inputs/current_parent.json', 'current_proposal': 'inputs/current_proposal.json', 'current_repositories': 'inputs/current_repositories.json', 'current_sidecar': 'inputs/current_sidecar.json', 'current_worker': 'inputs/current_worker.json', 'enrichment93': 'inputs/enrichment93.json', 'enrichment_spec': 'inputs/enrichment_spec.json', 'final_lock': 'inputs/final_lock.lock', 'gap_receipt': 'inputs/gap_receipt.json', 'historical_core': 'inputs/historical_core.db', 'historical_two': 'inputs/historical_two.json', 'key_archlinuxarm-revoked': 'inputs/archlinuxarm-revoked', 'key_archlinuxarm-trusted': 'inputs/archlinuxarm-trusted', 'key_archlinuxarm.gpg': 'inputs/archlinuxarm.gpg', 'legacy_authenticate': 'inputs/legacy_authenticate.py', 'legacy_native': 'inputs/legacy_native.py', 'legacy_preview': 'inputs/legacy_preview.py', 'metadata_admission': 'inputs/metadata_admission.json', 'prior_completion': 'inputs/prior_completion.json', 'prior_input': 'inputs/prior_input.json', 'prior_package_audit': 'inputs/prior_package_audit.json', 'prior_peer': 'inputs/prior_peer.json', 'prior_result': 'inputs/prior_result.json', 'prior_rootfs_inventory': 'inputs/prior_rootfs_inventory.json', 'prior_signatures': 'inputs/prior_signatures.json', 'projection': 'inputs/projection.json', 'proposal574': 'inputs/proposal574.json', 'seed': 'inputs/seed.json', 'seed_lock': 'inputs/seed_lock.lock'}
ORIGINS = {'builder': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/builder-input.json', 'current_actual_admission': 'artifacts/reviews/maintained-desktop-current2-authentication-root-actual-admission-20261015/admission.json', 'current_actual_peer': 'artifacts/reviews/maintained-desktop-current2-authentication-actual-region-peer-20261015/receipt.json', 'current_archives': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/archive-lock.json', 'current_authentication': 'artifacts/maintained-desktop-authentication-current2-run-20261015-actual01/work/result/authentication/authentication-receipt.json', 'current_binding': 'artifacts/maintained-desktop-authentication-current2-run-20261015-actual01/work/result/maintained-binding.json', 'current_core': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/core.db', 'current_extra': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/extra.db', 'current_parent': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/parent-receipt.json', 'current_proposal': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/desktop-proposal.json', 'current_repositories': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/repositories.json', 'current_sidecar': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/binding-sidecar.json', 'current_worker': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/worker-receipt.json', 'enrichment93': 'artifacts/reviews/maintained-desktop-current2-whole574-trust-gap-audit-20261015/transaction-audit/seed-pin-enrichment93.json', 'enrichment_spec': 'artifacts/reviews/maintained-desktop-current2-whole574-trust-gap-audit-20261015/transaction-audit/adapter-spec-historical-successor.json', 'final_lock': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/final.lock', 'gap_receipt': 'artifacts/reviews/maintained-desktop-current2-whole574-trust-gap-audit-20261015/receipt.json', 'historical_core': 'artifacts/platform/target-metadata-20261012/core.db', 'historical_two': 'artifacts/reviews/maintained-desktop-current2-whole574-trust-gap-audit-20261015/transaction-audit/historicaltwo.json', 'key_archlinuxarm-revoked': 'artifacts/reviews/maintained-desktop-current2-authentication-operational-reader-preparation-20261015/layout/frozen/public-keys/archlinuxarm-revoked', 'key_archlinuxarm-trusted': 'artifacts/reviews/maintained-desktop-current2-authentication-operational-reader-preparation-20261015/layout/frozen/public-keys/archlinuxarm-trusted', 'key_archlinuxarm.gpg': 'artifacts/reviews/maintained-desktop-current2-authentication-operational-reader-preparation-20261015/layout/frozen/public-keys/archlinuxarm.gpg', 'legacy_authenticate': 'artifacts/reviews/maintained-desktop-current2-authentication-operational-reader-preparation-20261015/layout/frozen/source/scripts/port/authenticate.py', 'legacy_native': 'artifacts/reviews/maintained-desktop-current2-authentication-operational-reader-preparation-20261015/layout/frozen/source/scripts/ci/native_arm.py', 'legacy_preview': 'artifacts/reviews/maintained-desktop-current2-authentication-operational-reader-preparation-20261015/layout/frozen/source/scripts/port/preview.py', 'metadata_admission': 'artifacts/reviews/maintained-desktop-current-resolution2-root-admission-20261015/admission.json', 'prior_completion': 'artifacts/platform/maintained-baseline-audit-actual01-20261013/completion.json', 'prior_input': 'artifacts/platform/audit01/out/inputs.lock.json', 'prior_package_audit': 'artifacts/platform/audit01/out/package-audit.json', 'prior_peer': 'artifacts/reviews/maintained-baseline-audit-actual01-root-peer-20261013/receipt.json', 'prior_result': 'artifacts/platform/audit01/out/result.json', 'prior_rootfs_inventory': 'artifacts/platform/audit01/out/rootfs-inventory.json', 'prior_signatures': 'artifacts/platform/audit01/out/signatures.json', 'projection': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/projection-metadata.json', 'proposal574': 'artifacts/reviews/maintained-desktop-current2-whole574-trust-gap-audit-20261015/proposed-whole574-descriptors.json', 'seed': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/seed-metadata.json', 'seed_lock': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/seed.lock'}
CONTRACT_SHA = 'b86c6a1c2af3ea0d5180db8fc03ca72e4f70e1f366da74ed49e75d20c3a936f4'
SIGNER = '68B3537F39A313B3E574D06777193F152BDBE6A6'
LIMITS = {name: 'NOT_ESTABLISHED' for name in (
    'whole574_trust', 'public_key_owner', 'source_legal', 'payload_ABI',
    'Asahi_transaction', 'M2', 'installation', 'native_execution', 'release', 'global_cleanup')}
MAX_BYTES = 32 * 1024**2
BUNDLE_MAX_BYTES = 64 * 1024**2
HEX = re.compile(r'[0-9a-f]{64}\Z')

class CompositionRefusal(ValueError):
    pass

def need(ok, code):
    if not ok:
        raise CompositionRefusal(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def document(raw, limit=MAX_BYTES):
    need(type(raw) is bytes and 0 < len(raw) <= limit, 'DOCUMENT_BYTES')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    def number(text):
        value = float(text)
        need(math.isfinite(value), 'NONFINITE_JSON_NUMBER')
        return value
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_float=number,
                          parse_constant=lambda _: need(False, 'NONFINITE_JSON_NUMBER'))
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError) as error:
        raise CompositionRefusal('DOCUMENT_JSON') from error

def exact(value, fields, code):
    need(type(value) is dict and set(value) == set(fields), code)

def integer(value, expected, code):
    need(type(value) is int and value == expected, code)

def digest(value, code):
    need(type(value) is str and HEX.fullmatch(value) is not None, code)

def indexed(rows, count, code):
    need(type(rows) is list and len(rows) == count and all(type(r) is dict and type(r.get('name')) is str for r in rows), code)
    result = {r['name']: r for r in rows}
    need(len(result) == count, code)
    return result

def metadata8(meta, row):
    need(type(meta) is dict, 'METADATA_FIELDS')
    for field, key in {'pkgname': 'name', 'pkgver': 'version', 'arch': 'arch',
                       'depend': 'depends', 'provides': 'provides', 'conflict': 'conflicts',
                       'replaces': 'replaces', 'license': 'license'}.items():
        wanted = [row[key]] if key in ('name', 'version', 'arch') else row[key]
        need(type(meta.get(field, [])) is list and sorted(meta.get(field, [])) == sorted(wanted), 'EIGHT_METADATA_FIELDS')

def gpg(value):
    try:
        validate_gpg(value)
    except (ValueError, TypeError, KeyError, OverflowError) as error:
        raise CompositionRefusal('SELECTED_KEY_GPG_RECORD') from error

def _held(bundle):
    need(type(bundle) is dict and set(bundle) == set(PINS) | {'profile', 'source_manifest', 'contract'}, 'EXACT_BUNDLE_ROLES')
    need(all(type(v) is bytes for v in bundle.values()) and sum(len(v) for v in bundle.values()) <= BUNDLE_MAX_BYTES, 'BUNDLE_BYTES')
    for role, pin in PINS.items():
        need(len(bundle[role]) == pin['bytes'] and sha(bundle[role]) == pin['sha256'], 'FROZEN_ROLE_PIN')
    need(sha(bundle['contract']) == CONTRACT_SHA, 'CONTRACT_PIN')
    contract = document(bundle['contract'], 65536)
    data = {role: document(bundle[role]) for role in PINS if role not in {
        'current_core', 'current_extra', 'historical_core', 'legacy_authenticate', 'legacy_native', 'legacy_preview',
        'seed_lock', 'final_lock', 'key_archlinuxarm.gpg', 'key_archlinuxarm-trusted', 'key_archlinuxarm-revoked'}}
    profile, manifest = document(bundle['profile'], 4*1024**2), document(bundle['source_manifest'], 4*1024**2)
    exact(profile, {'schema','scope','input_roles','packages','package_rows_sha256','source_manifest_sha256','signer_fingerprint','keyring_files','contract_sha256','bounds','execution'}, 'PROFILE_SCHEMA')
    exact(manifest, {'schema','files'}, 'SOURCE_MANIFEST_SCHEMA')
    need(profile['schema']=='seed93-authentication-profile-v1' and profile['scope']==contract['scope'] and profile['contract_sha256']==CONTRACT_SHA and manifest['schema']=='seed93-source-manifest-v1' and type(manifest['files']) is dict, 'PROFILE_MANIFEST_SCOPE')
    need(set(manifest['files'])=={'source/common.py','source/seed93.py','source/operations.py','source/helper_policy.py','source/composition.py','preview.py'}, 'SOURCE_MANIFEST_EXACT6')
    for descriptor in manifest['files'].values():
        exact(descriptor, {'bytes','mode','sha256'}, 'SOURCE_FILE_DESCRIPTOR')
        need(type(descriptor['bytes']) is int and 0 < descriptor['bytes'] <= MAX_BYTES and type(descriptor['mode']) is int and descriptor['mode']==0o644, 'SOURCE_FILE_SIZE_MODE')
        digest(descriptor['sha256'], 'SOURCE_FILE_SHA256')
    need(profile['source_manifest_sha256'] == sha(bundle['source_manifest']), 'SOURCE_MANIFEST_JOIN')
    need(type(profile['input_roles']) is dict and set(profile['input_roles']) == set(PINS), 'PROFILE_INPUT_ROLES')
    for role, pin in PINS.items():
        value = profile['input_roles'][role]
        exact(value, {'filename', 'origin', 'bytes', 'sha256'}, 'PROFILE_ROLE_SCHEMA')
        need(value['bytes'] == pin['bytes'] and type(value['bytes']) is int and value['sha256'] == pin['sha256'] and
             value['filename'] == FILENAMES[role] and value['origin'] == ORIGINS[role], 'PROFILE_ROLE_JOIN')
    need(profile['signer_fingerprint'] == SIGNER and profile['execution']=={'Source_admission':None,'metadata_release_admission':None,'Root_selection':None,'whole_invocation_plan':None}, 'PROFILE_SELECTED_KEY_DORMANT')
    need(profile['bounds']=={'packages':93,'package_bytes':56410184,'signature_bytes':52638,'package_signature_bytes':56462822,'operation_timeout_seconds':60,'aggregate_deadline':'UNASSIGNED_SEPARATE_ROOT_PLAN'} and all(type(profile['bounds'][k]) is int for k in ('packages','package_bytes','signature_bytes','package_signature_bytes','operation_timeout_seconds')), 'PROFILE_EXACT_BOUNDS')
    need(canonical(profile['keyring_files']) == canonical(data['builder']['keyring_files']), 'PROFILE_HELD_KEYRING')
    builder, seed, projection = data['builder'], data['seed'], data['projection']
    old = indexed(builder['packages'], 248, 'BUILDER248')
    additions = indexed(data['current_archives']['packages'], 233, 'CURRENT233')
    new = indexed(data['enrichment93']['packages'], 93, 'SEED93')
    need(len(seed) == 341 and len(projection) == 574 and set(old).isdisjoint(new) and set(old) | set(new) == set(seed) and
         set(additions).isdisjoint(seed) and set(seed) | set(additions) == set(projection), 'EXACT_248_93_233_PARTITIONS')
    need(all(projection[n] == row for n, row in seed.items()), 'ALL341_SEED_DICTIONARIES_HELD')
    need(canonical(profile['packages']) == canonical(data['enrichment93']['packages']) and profile['package_rows_sha256'] == sha(canonical(profile['packages'])), 'PROFILE_EXACT93')
    for name, row in (old | additions | new).items():
        semantic = {'NAME':'name', 'VERSION':'version', 'ARCH':'arch', 'DEPENDS':'depends', 'PROVIDES':'provides',
                    'CONFLICTS':'conflicts', 'REPLACES':'replaces', 'LICENSE':'license', 'URL':'source_url'}
        for upper, lower in semantic.items():
            wanted = [row[lower]] if lower in ('name', 'version', 'arch') else row[lower]
            need(projection[name].get(upper, []) == wanted, '574_METADATA_TUPLES_HELD')
    integer(data['prior_completion']['actual_CLI_exit'], 0, 'PRIOR_EXIT')
    need(data['prior_completion']['input_sha256'] == PINS['builder']['sha256'] and data['prior_completion']['verified_primary_fingerprint'] == SIGNER,
         'PRIOR_COMPLETION_BUILDER_KEY')
    integer(data['prior_completion']['verified_package_metadata'], 248, 'PRIOR248_METADATA')
    integer(data['prior_completion']['verified_signature_payloads'], 249, 'PRIOR_ROOTFS_PLUS248_SIGNATURES')
    need(data['prior_peer']['verified']['metadata248_match'] is True and data['prior_peer']['verified']['signature_exit0_and_one_full_pinned_VALIDSIG'] is True,
         'PRIOR_STRICT_PEER')
    need(data['prior_result']['reviewed_inputs_sha256'] == PINS['builder']['sha256'] and data['prior_result']['status'] == 'signed-input-audit-pass', 'PRIOR_RESULT')
    integer(data['prior_result']['verified_signed_packages'], 248, 'PRIOR_RESULT248')
    need(data['prior_input'] == builder, 'PRIOR_BUILDER_EXACT')
    signatures, audit = data['prior_signatures'], data['prior_package_audit']
    need(len(audit) == 248 and set(audit) == {r['filename'] for r in old.values()}, 'PRIOR_AUDIT_MEMBERSHIP')
    for row in old.values():
        sig = signatures[row['filename']]
        exact(sig, {'command', 'diagnostic', 'exit_code', 'status'}, 'PRIOR_SIGNATURE_ABI')
        gpg(dict(exit=sig['exit_code'], status=sig['status'], diagnostic=sig['diagnostic']))
        metadata8(audit[row['filename']]['metadata'], row)
    receipt, binding, peer, admission = (data[n] for n in ('current_authentication','current_binding','current_actual_peer','current_actual_admission'))
    need(receipt['status'] == 'PASS-233-authenticated-generic-archives' and receipt['failures'] == [] and receipt['signer_fingerprint'] == SIGNER,
         'CURRENT233_RECEIPT')
    integer(receipt['verified_count'], 233, 'CURRENT233_VERIFIED'); integer(receipt['package_count'], 233, 'CURRENT233_COUNT')
    need(binding['status'] == 'PASS-current2-maintained-authenticated-archives' and binding['archive_lock_raw_sha256'] == PINS['current_archives']['sha256'] and
         binding['archive_package_rows_canonical_sha256'] == sha(canonical(data['current_archives']['packages'])), 'CURRENT233_BINDING')
    integer(binding['authenticated_count'],233,'CURRENT233_BOUND_COUNT')
    need(admission['Root_admitted'] is True and admission['review_complete'] is True and admission['peer']['sha256'] == PINS['current_actual_peer']['sha256'] and
         peer['final'] is True and peer['Source'] == admission['Source'] and peer['maintained_binding'] == 'PASS_CURRENT2', 'CURRENT_ROOT_STRICT_PEER')
    integer(admission['current_pairs'],233,'CURRENT_ROOT233'); integer(peer['current_archive_signature_pairs'],233,'CURRENT_PEER233')
    current = indexed(receipt['packages'], 233, 'CURRENT_RECEIPT_MEMBERSHIP')
    need(set(current) == set(additions), 'CURRENT_EXACT_NAMES')
    for name, row in current.items():
        expected = additions[name]
        need(row['version'] == expected['version'] and row['archive_sha256'] == expected['sha256'] and row['signature_sha256'] == expected['signature_sha256'] and
             row['status'] == 'PASS-authenticated-data', 'CURRENT_IDENTITY_VERIFIED')
        gpg(row['gpg']); observation = row['archive_observations']
        digest(observation['sha256'], 'CURRENT_OBSERVATION_HASH')
        need(observation['package_execution'] == 'NOT RUN', 'CURRENT_OBSERVATION_EXECUTION')
    need(set(LIMITS) == set(contract['limits']), 'LIMITS_CONTRACT')
    return contract, profile, new

def compose(bundle_bytes, future93_bytes=None, future93_admission_bytes=None,
            expected_admission_sha256=None, future93_peer_bytes=None):
    """The external admission literal is caller authority, never derived from reports.

    JSON alone cannot prove execution. Future positive coverage relies on a separately
    reviewed Root-frozen caller supplying that literal and exact retained peer bytes.
    """
    try:
        contract, profile, rows = _held(bundle_bytes)
        result = dict(schema='selected-key-composition-v1', status='BLOCKED_MISSING_FUTURE93_AUTHORITY',
                      scope='SELECTED_KEY_ARCHIVE_VERIFICATION_COVERAGE_ONLY', actor_grant=False,
                      coverage=dict(historical248=248, admitted_current233=233, admitted_seed93=0, total=481, required=574),
                      limits=dict(LIMITS), future93_authority='UNASSIGNED', package_verification_executed_here=False,
                      evidence_basis='RETAINED_SELECTED_PRIMARY_KEY_RECORDS_AND_EXTERNAL_ROOT_ATTESTATION_ONLY')
        if any(value is None for value in (future93_bytes, future93_admission_bytes, expected_admission_sha256, future93_peer_bytes)):
            return result
        digest(expected_admission_sha256, 'EXTERNAL_ROOT_ADMISSION_LITERAL')
        need(type(future93_admission_bytes) is bytes and sha(future93_admission_bytes) == expected_admission_sha256, 'EXTERNAL_ROOT_ADMISSION_PIN')
        report = document(future93_bytes)
        admission = document(future93_admission_bytes, 65536)
        peer = document(future93_peer_bytes, 65536)
        exact(report, contract['report_fields'], 'FUTURE_REPORT_SCHEMA')
        exact(admission, contract['admission_fields'], 'FUTURE_ADMISSION_SCHEMA')
        exact(peer, contract['strict_peer_fields'], 'FUTURE_STRICT_PEER_SCHEMA')
        profile_sha, source_sha, report_sha = sha(bundle_bytes['profile']), sha(bundle_bytes['source_manifest']), sha(future93_bytes)
        for value, schema, status in ((report, contract['report_schema'], contract['report_complete_status']),
                                     (peer, contract['strict_peer_schema'], contract['strict_peer_status']),
                                     (admission, contract['admission_schema'], contract['admission_status'])):
            need(value['schema'] == schema and value['status'] == status and value['scope'] == contract['scope'], 'FUTURE_EXACT_PHASE_SCOPE')
            need(value['profile_sha256'] == profile_sha and value['source_manifest_sha256'] == source_sha and value['limits'] == LIMITS,
                 'FUTURE_PROFILE_SOURCE_LIMITS')
            need(value['cancelled'] is False and value['first_failure'] is None, 'FUTURE_TERMINAL_FAILURE')
        need(peer['report_sha256'] == admission['report_sha256'] == report_sha and admission['strict_peer_sha256'] == sha(future93_peer_bytes), 'FUTURE_REPORT_PEER_ROOT_JOINS')
        need(admission['Root_admitted'] is True and admission['review_complete'] is True and admission['actor_grant'] is False and peer['final'] is True,
             'FUTURE_EXTERNAL_ROOT_AUTHORITY')
        for value in (admission, peer):
            integer(value['whole_guardian_exit'], 0, 'FUTURE_GUARDIAN_EXIT')
            need(value['scoped_child_cleanup'] == 'PASS', 'FUTURE_SCOPED_CLEANUP')
        integer(report['expected_count'],93,'FUTURE_EXPECTED_COUNT'); integer(report['verified_count'],93,'FUTURE_VERIFIED_COUNT')
        for field in ('actual_archive_pairs','actual_primary_GPG_records','actual_archive_observations'): integer(peer[field],93,'FUTURE_STRICT_ACTUAL93')
        need(report['archive_package_rows_canonical_sha256'] == sha(canonical(profile['packages'])) and report['failures'] == [] and
             report['terminal_state'] == contract['complete_terminal_state'] and report['producer_evidence_scope'] == contract['producer_evidence_scope'],
             'FUTURE_COMPLETE_REPORT')
        packages = indexed(report['packages'],93,'FUTURE_EXACT93_MEMBERSHIP'); need(set(packages)==set(rows),'FUTURE93_NAMES')
        for name, value in packages.items():
            expected = rows[name];exact(value,contract['package_fields'],'FUTURE_PACKAGE_SCHEMA')
            need(value['version']==expected['version'] and value['archive_sha256']==expected['sha256'] and
                 value['signature_sha256']==expected['signature_sha256'] and value['status']==contract['package_success_status'], 'FUTURE_PACKAGE_IDENTITY')
            exact(value['acquisition'],contract['acquisition_fields'],'FUTURE_ACQUISITION_SCHEMA')
            for kind, size, pin in (('archive',expected['size'],expected['sha256']),('signature',expected['signature_size'],expected['signature_sha256'])):
                record=value['acquisition'][kind];exact(record,contract['acquisition_fields'][kind],'FUTURE_ACQUISITION_ROW')
                integer(record['bytes'],size,'FUTURE_ACQUISITION_SIZE');need(record['sha256']==pin,'FUTURE_ACQUISITION_HASH')
            gpg(value['gpg'])
            need(value['observation_sha256']==sha(canonical(value['observation'])),'FUTURE_INLINE_OBSERVATION_HASH')
            try:validate_observation(value['observation'],expected)
            except (ValueError,TypeError,KeyError,OverflowError) as error:raise CompositionRefusal('FUTURE_INLINE_OBSERVATION_POLICY') from error
        result.update(status='PASS_SELECTED_KEY_ARCHIVE_VERIFICATION_COVERAGE_ONLY', future93_authority='EXTERNAL_ROOT_LITERAL_AND_STRICT_PEER_JOINED')
        result['coverage'].update(admitted_seed93=93,total=574)
        result['future93_admission_sha256']=expected_admission_sha256
        return result
    except CompositionRefusal:
        raise
    except (KeyError, TypeError, ValueError, OverflowError, RecursionError, UnicodeError) as error:
        raise CompositionRefusal('STRUCTURAL_REFUSAL') from error

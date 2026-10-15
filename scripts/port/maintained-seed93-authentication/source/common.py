"""Strict data and byte binding for the separately selected held seed93."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from dataclasses import dataclass

FIXED_INPUT_ROLES = {'builder': {'bytes': 328101, 'filename': 'inputs/builder.json', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/builder-input.json', 'sha256': 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'}, 'current_actual_admission': {'bytes': 1260, 'filename': 'inputs/current_actual_admission.json', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-root-actual-admission-20261015/admission.json', 'sha256': '860e7da809aef71d6bc7922df27f04dc6a04596dda47937b4d1aff8f4f70f488'}, 'current_actual_peer': {'bytes': 1967, 'filename': 'inputs/current_actual_peer.json', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-actual-region-peer-20261015/receipt.json', 'sha256': 'b2356270bea66d9ed1559fdf91081a6f7a52ff5dbb3f1a3bae5daca19f308f45'}, 'current_archives': {'bytes': 215830, 'filename': 'inputs/current_archives.json', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/archive-lock.json', 'sha256': 'f8f4a3748a962e2f793702207cbaf32ed6106a635ad35f70a0f5551d7c6a2362'}, 'current_authentication': {'bytes': 361603, 'filename': 'inputs/current_authentication.json', 'origin': 'artifacts/maintained-desktop-authentication-current2-run-20261015-actual01/work/result/authentication/authentication-receipt.json', 'sha256': '11cb72325d5a73a1a57ad9cfc8c0930df8f3c47309e0666847609babec1cf3c8'}, 'current_binding': {'bytes': 2118, 'filename': 'inputs/current_binding.json', 'origin': 'artifacts/maintained-desktop-authentication-current2-run-20261015-actual01/work/result/maintained-binding.json', 'sha256': '5064c4dcea0ee3f45f82e41b7470d822eacd84aebf9a58fd155149667b06ffa0'}, 'current_core': {'bytes': 256689, 'filename': 'inputs/current_core.db', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/core.db', 'sha256': '91b52f917c664d5c6c16686b4749b2c4bb3f2673b49097f736d145ba88016364'}, 'current_extra': {'bytes': 10610805, 'filename': 'inputs/current_extra.db', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/extra.db', 'sha256': 'f26b9c8dfd9211400ac605d7a2c0d08b7cfbd2de88b595b97b8e7d8af64dcffd'}, 'current_parent': {'bytes': 511, 'filename': 'inputs/current_parent.json', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/parent-receipt.json', 'sha256': '7e097a62b708190384b6cc142f59a9c86d2fd579995bce072ee2b1a487d4c07e'}, 'current_proposal': {'bytes': 4959, 'filename': 'inputs/current_proposal.json', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/desktop-proposal.json', 'sha256': 'a7a83e750112446026a05fcd0a1a410a8c7aac218afeeed30e106a181ab9aca7'}, 'current_repositories': {'bytes': 456, 'filename': 'inputs/current_repositories.json', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/repositories.json', 'sha256': 'f00e7e39141d125400c30108994a46cf52ff57e3b03a6d8cab72dfc1fcdee033'}, 'current_sidecar': {'bytes': 878, 'filename': 'inputs/current_sidecar.json', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/binding-sidecar.json', 'sha256': '90aa6719a47b3a62a025b846b17a472b44d24cb78439d4c157d438a03e4a042f'}, 'current_worker': {'bytes': 989543, 'filename': 'inputs/current_worker.json', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-source-20261015/inputs/worker-receipt.json', 'sha256': 'd536a11eb27a3cade695351c3f6475d438de865b4240d9990207e42146abeca0'}, 'enrichment93': {'bytes': 92467, 'filename': 'inputs/enrichment93.json', 'origin': 'artifacts/reviews/maintained-desktop-seed93-sqlite-acquisition-correction-20261015/source-audit/corrected/inputs/enrichment93.json', 'sha256': 'bcb6f532837d3d13bcbaee7282207250ee7a23a61fa1e8b18df33862b4e08bea'}, 'enrichment_spec': {'bytes': 9339, 'filename': 'inputs/enrichment_spec.json', 'origin': 'artifacts/reviews/maintained-desktop-seed93-sqlite-acquisition-correction-20261015/source-audit/corrected/inputs/enrichment_spec.json', 'sha256': '1beb6db4b8d45ecd16e9e1ec304788f46a3c098c45b8e4ef87a5d86ec8c78624'}, 'final_lock': {'bytes': 11117, 'filename': 'inputs/final_lock.lock', 'origin': 'artifacts/reviews/maintained-desktop-seed93-sqlite-acquisition-correction-20261015/source-audit/corrected/inputs/final_lock.lock', 'sha256': 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'}, 'gap_receipt': {'bytes': 3318, 'filename': 'inputs/gap_receipt.json', 'origin': 'artifacts/reviews/maintained-desktop-current2-whole574-trust-gap-audit-20261015/receipt.json', 'sha256': '9b54841b28632db431a5163d7122873a38afec36d83b131135293a4fbd22cff2'}, 'historical_core': {'bytes': 256696, 'filename': 'inputs/historical_core.db', 'origin': 'artifacts/platform/target-metadata-20261012/core.db', 'sha256': '5f184763bad034ac02662ee37d87edad8124244c8609f4a441947da1855b0b08'}, 'historical_two': {'bytes': 4197, 'filename': 'inputs/historical_two.json', 'origin': 'artifacts/reviews/maintained-desktop-current2-whole574-trust-gap-audit-20261015/transaction-audit/historicaltwo.json', 'sha256': '445f70b2c202cea6c3aa7b8d76530272820f05ab1986e899addb96a075352d66'}, 'key_archlinuxarm-revoked': {'bytes': 0, 'filename': 'inputs/archlinuxarm-revoked', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-operational-reader-preparation-20261015/layout/frozen/public-keys/archlinuxarm-revoked', 'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}, 'key_archlinuxarm-trusted': {'bytes': 44, 'filename': 'inputs/archlinuxarm-trusted', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-operational-reader-preparation-20261015/layout/frozen/public-keys/archlinuxarm-trusted', 'sha256': 'f2a7250f2a2b77542f82f4219b2bae7895f27b3dcfdf350b497e2be306af776d'}, 'key_archlinuxarm.gpg': {'bytes': 3098, 'filename': 'inputs/archlinuxarm.gpg', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-operational-reader-preparation-20261015/layout/frozen/public-keys/archlinuxarm.gpg', 'sha256': '6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f'}, 'legacy_authenticate': {'bytes': 17452, 'filename': 'inputs/legacy_authenticate.py', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-operational-reader-preparation-20261015/layout/frozen/source/scripts/port/authenticate.py', 'sha256': '241cd67370eb593bdf948a25788f006ecf470c645ba5d198bc9c318119ebfe10'}, 'legacy_native': {'bytes': 28489, 'filename': 'inputs/legacy_native.py', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-operational-reader-preparation-20261015/layout/frozen/source/scripts/ci/native_arm.py', 'sha256': '1a5369e007193fafce355ca6d20f4e771a0f342e0176bfd80f95a718328a0d10'}, 'legacy_preview': {'bytes': 19736, 'filename': 'inputs/legacy_preview.py', 'origin': 'artifacts/reviews/maintained-desktop-current2-authentication-operational-reader-preparation-20261015/layout/frozen/source/scripts/port/preview.py', 'sha256': 'd737c51474e05cc2c4db2e87fc021f50328eea7744983dd4076d44751fce7383'}, 'metadata_admission': {'bytes': 823, 'filename': 'inputs/metadata_admission.json', 'origin': 'artifacts/reviews/maintained-desktop-current-resolution2-root-admission-20261015/admission.json', 'sha256': '978a6486c9028edd1086ac7f3fb1e9e84b9f6dd751a1f5774220b7f41b4dff7b'}, 'prior_completion': {'bytes': 25830, 'filename': 'inputs/prior_completion.json', 'origin': 'artifacts/platform/maintained-baseline-audit-actual01-20261013/completion.json', 'sha256': '1302243720fb2e621431fd9ed71f249aabad7979c8ea31b6990ae0f471087b8d'}, 'prior_input': {'bytes': 328101, 'filename': 'inputs/prior_input.json', 'origin': 'artifacts/platform/audit01/out/inputs.lock.json', 'sha256': 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'}, 'prior_package_audit': {'bytes': 6347750, 'filename': 'inputs/prior_package_audit.json', 'origin': 'artifacts/platform/audit01/out/package-audit.json', 'sha256': 'd737215476f92511fc2d268aa02ad64b45b2011e473d4102dadc4d5dce2c6dd7'}, 'prior_peer': {'bytes': 29431, 'filename': 'inputs/prior_peer.json', 'origin': 'artifacts/reviews/maintained-baseline-audit-actual01-root-peer-20261013/receipt.json', 'sha256': '07144f43ba37aeb4f83f94882a9841549c69fb45b0352b15a3eed63c0d1007af'}, 'prior_result': {'bytes': 451, 'filename': 'inputs/prior_result.json', 'origin': 'artifacts/platform/audit01/out/result.json', 'sha256': 'bd0dee3a57cd7003b850d8b70e9579e534395dfef0afe0748a352996a1b0cd12'}, 'prior_rootfs_inventory': {'bytes': 56107, 'filename': 'inputs/prior_rootfs_inventory.json', 'origin': 'artifacts/platform/audit01/out/rootfs-inventory.json', 'sha256': '72bbef83fd87e3da228b3cdc0105b0051b86f9c7c3d7c4eed90b264eb755267f'}, 'prior_signatures': {'bytes': 388022, 'filename': 'inputs/prior_signatures.json', 'origin': 'artifacts/platform/audit01/out/signatures.json', 'sha256': '203d46d3eb69b9eb4e4a849d070376edb2a94ea103314aaa93ce24ae251500f8'}, 'projection': {'bytes': 661251, 'filename': 'inputs/projection.json', 'origin': 'artifacts/reviews/maintained-desktop-seed93-sqlite-acquisition-correction-20261015/source-audit/corrected/inputs/projection.json', 'sha256': 'fa4eead520f10385828bfa3a0116718ed7fdf23770cb7e9d8b69682913da3e6e'}, 'proposal574': {'bytes': 589956, 'filename': 'inputs/proposal574.json', 'origin': 'artifacts/reviews/maintained-desktop-seed93-sqlite-acquisition-correction-20261015/source-audit/corrected/inputs/proposal574.json', 'sha256': '1ab7b81ab9ec36331c487d0c3d444990d78ee6f109a7c489fee89cf410b2185e'}, 'seed': {'bytes': 229285, 'filename': 'inputs/seed.json', 'origin': 'artifacts/reviews/maintained-desktop-seed93-sqlite-acquisition-correction-20261015/source-audit/corrected/inputs/seed.json', 'sha256': '9d0c30351f0b1e537647a26bb416de8f562135c6ba0ac7e080dde353f297267a'}, 'seed_lock': {'bytes': 6674, 'filename': 'inputs/seed_lock.lock', 'origin': 'artifacts/reviews/maintained-desktop-seed93-sqlite-acquisition-correction-20261015/source-audit/corrected/inputs/seed_lock.lock', 'sha256': 'b02e9e2e2cb64bfb6d11b5add47060d8276a23f327237ea3dee6c6c46e97a54c'}}
CONTRACT_SHA256 = 'b86c6a1c2af3ea0d5180db8fc03ca72e4f70e1f366da74ed49e75d20c3a936f4'
PACKAGE_ROWS_SHA256 = '1f0bb89d87d95da38660d75ab4662ada3fa9cbf082cf8710f438811ac98950d3'

SCOPE = 'GENERIC-held-seed93-data-authentication'
SIGNER = '68B3537F39A313B3E574D06777193F152BDBE6A6'
LIMIT_NAMES = ('whole574_trust', 'public_key_owner', 'source_legal', 'payload_ABI',
               'Asahi_transaction', 'M2', 'installation', 'native_execution', 'release', 'global_cleanup')
LIMITS = {name: 'NOT_ESTABLISHED' for name in LIMIT_NAMES}
ROW_FIELDS = {'name','version','arch','filename','sha256','size','url','signature_sha256',
              'signature_size','license','depends','provides','conflicts','replaces','source_url','repo','isize'}


class Refusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise Refusal(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def loads(raw):
    need(type(raw) is bytes and len(raw) <= 32*1024**2, 'JSON_BYTES_BOUND')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'JSON_DUPLICATE_KEY')
            result[key] = value
        return result
    try:
        def number(text):
            value = float(text)
            need(math.isfinite(value), 'JSON_NONFINITE')
            return value
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_float=number,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refusal('JSON_NONFINITE')))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Refusal('JSON_ENCODING_OR_SHAPE') from error


def pin(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None, 'SHA256_LITERAL')
    return value


_CANCELLED_ERRORS = []  # One future Root invocation; preserve identity without instance hooks.


def propagated_cancellation(error):
    return any(item is error for item in _CANCELLED_ERRORS)


def mark_cancellation(error):
    if not propagated_cancellation(error):
        _CANCELLED_ERRORS.append(error)


def read_file(path, maximum=32*1024**2):
    path = Path(path).absolute()
    for part in [path, *path.parents]:
        need(not part.is_symlink(), 'SYMLINK_INPUT')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    original = None
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022,
             'INPUT_NODE_OR_MODE')
        need(before.st_size <= maximum, 'INPUT_SIZE_BOUND')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(maximum+1)
        need(before == os.fstat(fd) == os.lstat(path) and len(raw) == before.st_size, 'INPUT_DRIFT')
        return raw
    except BaseException as error:
        original = error
        raise
    finally:
        try:
            os.close(fd)
        except BaseException as error:
            if original is None:
                raise
            if issubclass(type(error), (KeyboardInterrupt,SystemExit)) or propagated_cancellation(error):
                mark_cancellation(original)
            try:
                BaseException.add_note(original, 'SECONDARY_FD_CLOSE_FAILURE:' + type.__dict__['__name__'].__get__(type(error)))
            except BaseException:
                pass  # Optional diagnostics cannot replace the primary read fault.


@dataclass(frozen=True)
class Bound:
    profile_sha256: str
    source_manifest_sha256: str
    package_rows_sha256: str
    rows_raw: bytes

    def rows(self):
        need(sha(self.rows_raw) == PACKAGE_ROWS_SHA256 == self.package_rows_sha256, 'BOUND_ROW_DRIFT')
        return loads(self.rows_raw)


def bind(profile_raw, bundle, source_manifest_raw, expected_profile_sha256):
    need(sha(profile_raw) == pin(expected_profile_sha256), 'PROFILE_RAW_PIN')
    need(type(bundle) is dict and set(bundle) == set(FIXED_INPUT_ROLES) | {'profile','source_manifest','contract'},
         'BUNDLE_ROLE_SET')
    need(bundle['profile'] == profile_raw and bundle['source_manifest'] == source_manifest_raw, 'BUNDLE_HEADER_BYTES')
    need(sha(bundle['contract']) == CONTRACT_SHA256, 'CONTRACT_RAW_PIN')
    for name, descriptor in FIXED_INPUT_ROLES.items():
        raw = bundle[name]
        need(type(raw) is bytes and len(raw) == descriptor['bytes'] and sha(raw) == descriptor['sha256'],
             'INPUT_RAW_PIN:' + name)
    profile = loads(profile_raw)
    fields = {'schema','scope','input_roles','packages','package_rows_sha256','source_manifest_sha256',
              'signer_fingerprint','keyring_files','contract_sha256','bounds','execution'}
    need(type(profile) is dict and set(profile) == fields, 'PROFILE_SCHEMA')
    need(profile['schema'] == 'seed93-authentication-profile-v1' and profile['scope'] == SCOPE, 'PROFILE_SCOPE')
    need(profile['input_roles'] == FIXED_INPUT_ROLES and profile['contract_sha256'] == CONTRACT_SHA256,
         'PROFILE_INPUT_DECLARATIONS')
    for role, item in profile['input_roles'].items():
        need(type(item) is dict and set(item) == {'filename','origin','bytes','sha256'} and
             type(item['bytes']) is int and type(item['filename']) is str and
             type(item['origin']) is str and type(item['sha256']) is str,
             'PROFILE_ROLE_DESCRIPTOR_TYPES:' + role)
    need(sha(source_manifest_raw) == pin(profile['source_manifest_sha256']), 'SOURCE_MANIFEST_PIN')
    manifest = loads(source_manifest_raw)
    source_files = {'source/common.py','source/seed93.py','source/operations.py',
                    'source/helper_policy.py','source/composition.py','preview.py'}
    need(type(manifest) is dict and set(manifest) == {'schema','files'} and
         manifest['schema'] == 'seed93-source-manifest-v1' and type(manifest['files']) is dict and
         set(manifest['files']) == source_files,
         'SOURCE_MANIFEST_SCHEMA')
    for item in manifest['files'].values():
        need(type(item) is dict and set(item) == {'bytes','mode','sha256'} and
             type(item['bytes']) is int and 0 < item['bytes'] <= 1024**2 and
             type(item['mode']) is int and item['mode'] == 0o644, 'SOURCE_DESCRIPTOR_SCHEMA')
        pin(item['sha256'])
    need(profile['signer_fingerprint'] == SIGNER, 'PROFILE_SIGNER')
    builder, seed, projection, additions, extra = (loads(bundle[name]) for name in
        ('builder','seed','projection','current_archives','enrichment93'))
    need(canonical(profile['keyring_files']) == canonical(builder['keyring_files']) ==
         canonical(additions['keyring_files']), 'PUBLIC_KEY_POLICY')
    need(profile['execution'] == {'Source_admission':None, 'metadata_release_admission':None,
                                'Root_selection':None, 'whole_invocation_plan':None}, 'PROPOSAL_EXECUTION_SLOTS')
    need(profile['bounds'] == {'packages':93, 'package_bytes':56409764, 'signature_bytes':52638,
                              'package_signature_bytes':56462402, 'operation_timeout_seconds':60,
                              'aggregate_deadline':'UNASSIGNED_SEPARATE_ROOT_PLAN'}, 'PROFILE_BOUNDS')
    need(all(type(profile['bounds'][key]) is int for key in ('packages','package_bytes','signature_bytes',
              'package_signature_bytes','operation_timeout_seconds')), 'PROFILE_BOUNDS_TYPES')
    rows = profile['packages']
    need(type(rows) is list and rows == extra['packages'] and len(rows) == 93 and
         sha(canonical(rows)) == profile['package_rows_sha256'] == PACKAGE_ROWS_SHA256, 'EXACT_NEW93_ROWS')
    old = {row['name']:row for row in builder['packages']}
    current = {row['name']:row for row in additions['packages']}
    new = {row['name']:row for row in rows}
    need(len(old) == 248 and len(current) == 233 and len(new) == 93, 'DUPLICATE_OR_MISSING_ROWS')
    need(set(seed) == set(old) | set(new) and not set(old) & set(new) and
         set(projection) == set(seed) | set(current) and not set(seed) & set(current), 'EXACT_DISJOINT_574')
    need(all(projection[name] == row for name,row in seed.items()), 'SEED_METADATA_RETENTION')
    need(extra['seed_versions_changed'] == 1 and type(extra['seed_versions_changed']) is int and
         extra['archive_authentication_performed'] is False and extra['Root_actor_grant'] is False,
         'ENRICHMENT_SCOPE')
    sqlite_correction_guard(rows, seed, projection, loads(bundle['enrichment_spec']))
    semantics = {'name':'NAME','version':'VERSION','arch':'ARCH','depends':'DEPENDS','provides':'PROVIDES',
                 'conflicts':'CONFLICTS','replaces':'REPLACES','license':'LICENSE','source_url':'URL'}
    for row in rows:
        need(set(row) == ROW_FIELDS, 'NEW93_ROW_SCHEMA')
        name, version, arch = row['name'], row['version'], row['arch']
        need(type(name) is str and re.fullmatch('[a-z0-9@][a-z0-9@+_.-]*', name) is not None and
             type(version) is str and not any(c.isspace() or c in '/\x00' for c in version) and
             arch in ('aarch64','any'), 'NEW93_IDENTITY')
        need(all(seed[name].get(upper,[]) == (row[lower] if type(row[lower]) is list else [row[lower]])
                 for lower,upper in semantics.items()), 'NEW93_SEMANTICS')
        need(row['filename'] == f'{name}-{version}-{arch}.pkg.tar.xz' and row['repo'] in ('core','extra') and
             row['url'] == f'https://ca.us.mirror.archlinuxarm.org/aarch64/{row["repo"]}/{row["filename"]}',
             'NEW93_OFFICIAL_ARCHIVE_IDENTITY')
        pin(row['sha256']); pin(row['signature_sha256'])
        need(type(row['size']) is int and 0 < row['size'] <= 56462402 and
             type(row['signature_size']) is int and 0 < row['signature_size'] <= 65536 and
             type(row['isize']) is int and 0 <= row['isize'] <= 2**31, 'NEW93_BYTE_BOUNDS')
    need(sum(row['size'] + row['signature_size'] for row in rows) == 56462402, 'NEW93_AGGREGATE_DECLARATION')
    return Bound(sha(profile_raw), sha(source_manifest_raw), PACKAGE_ROWS_SHA256, canonical(rows))


SQLITE_CORRECTION_PINS = {'BASE_SQLITE': {'arch': 'aarch64', 'conflicts': [], 'depends': ['readline', 'zlib', 'glibc'], 'filename': 'sqlite-3.53.4-1-aarch64.pkg.tar.xz', 'isize': 21161566, 'license': ['LicenseRef-Sqlite'], 'name': 'sqlite', 'provides': ['sqlite3=3.53.4', 'libsqlite3.so=0-64'], 'replaces': ['sqlite3'], 'repo': 'core', 'sha256': '9512d37af4ac6910e10e2a8e6f85078ab72a2ece17a8e6b51755898f50b900ba', 'signature_sha256': '3ebd5713a768e6de587faf3869485fb2563346d2570afc9cdf6d3549ce28a762', 'signature_size': 566, 'size': 1850368, 'source_url': ['https://www.sqlite.org/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/sqlite-3.53.4-1-aarch64.pkg.tar.xz', 'version': '3.53.4-1'}, 'NEW_SQLITE': {'arch': 'aarch64', 'conflicts': [], 'depends': ['readline', 'zlib', 'glibc'], 'filename': 'sqlite-3.54.0-1-aarch64.pkg.tar.xz', 'isize': 21231389, 'license': ['LicenseRef-Sqlite'], 'name': 'sqlite', 'provides': ['sqlite3=3.54.0', 'libsqlite3.so=0-64'], 'replaces': ['sqlite3'], 'repo': 'core', 'sha256': '88c1b8d04c68597ea09bc1e393ad79fb0faf94b7fe45f507f663a6e68c1c7102', 'size': 1849948, 'source_url': ['https://www.sqlite.org/'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/core/sqlite-3.54.0-1-aarch64.pkg.tar.xz', 'version': '3.54.0-1', 'signature_sha256': '567c1ca19cbee1f80b166232b0d0cc2619f1ad2100d3faf0aedcdf47656c1177', 'signature_size': 566}, 'BASE_SQLITE_SEED': {'ARCH': ['aarch64'], 'CONFLICTS': [], 'DEPENDS': ['readline', 'zlib', 'glibc'], 'FILENAME': [], 'LICENSE': ['LicenseRef-Sqlite'], 'NAME': ['sqlite'], 'PROVIDES': ['sqlite3=3.53.4', 'libsqlite3.so=0-64'], 'REPLACES': ['sqlite3'], 'SHA256SUM': [], 'URL': ['https://www.sqlite.org/'], 'VERSION': ['3.53.4-1'], 'repo': 'declared-maintained-builder-metadata'}, 'BASE_ROWS_SHA': '3e99edd9604b04a42db9db093ccfde98c74dfb7216cff9245b7d6f8a53127f8e', 'BASE_SEED_SHA': 'ba54b691b3595a03774ea45eed4cc61ab5c76c411a590bdc2d3fb78e9459b439', 'BASE_PROJECTION_SHA': 'eee3b24417c66078dc2b2c744bbf169047215608a10213276534f9a7d3ba97fb', 'ROOT_PAIR_RECEIPT_SHA': 'a65e7ea62bf8bb4208359948fe6f0ddae429b034c262624cc4f2898d9eb84b27'}

def sqlite_correction_guard(rows, seed, projection, spec):
    p = SQLITE_CORRECTION_PINS
    c = spec['sqlite_correction']
    need(type(c) is dict and set(c) == {'baseline_profile_sha256','old_row','new_row','metadata_admission_scope','current_core_sha256','root_pair_receipt','root_pair_receipt_raw'}, 'SQLITE_CORRECTION_SCHEMA')
    need(c['baseline_profile_sha256'] == '94f7894c2c39f350a2e7d1e52fd91ef5bb4cf458ac45d52dc2c35d66c64816ba' and c['old_row'] == p['BASE_SQLITE'] and c['new_row'] == p['NEW_SQLITE'], 'EXACT_SQLITE_VERSION_DELTA')
    need(c['metadata_admission_scope'] == 'HISTORICAL_BASELINE_ONLY_NEW_RELEASE_ADMISSION_PENDING' and c['current_core_sha256'] == '91b52f917c664d5c6c16686b4749b2c4bb3f2673b49097f736d145ba88016364', 'SQLITE_SCOPE_AND_METADATA_ORIGIN')
    need(type(c['root_pair_receipt_raw']) is str and sha(c['root_pair_receipt_raw'].encode()) == c['root_pair_receipt']['sha256'] == p['ROOT_PAIR_RECEIPT_SHA'] and len(c['root_pair_receipt_raw'].encode()) == c['root_pair_receipt']['bytes'], 'ROOT_PAIR_RECEIPT_METADATA_PIN')
    need(len(rows) == 93 and rows[89] == p['NEW_SQLITE'] and rows[89]['name'] == 'sqlite' and rows[89]['version'] == '3.54.0-1', 'EXACT_NEW_SQLITE')
    restored = list(rows); restored[89] = p['BASE_SQLITE']
    need(sha(canonical(restored)) == p['BASE_ROWS_SHA'], 'ALL_OTHER92_ROWS_HELD')
    expected = dict(p['BASE_SQLITE_SEED']); expected.update(VERSION=['3.54.0-1'], PROVIDES=p['NEW_SQLITE']['provides'])
    need(seed['sqlite'] == projection['sqlite'] == expected, 'ONLY_SQLITE_SEED_VERSION_PROVIDER_CHANGE')
    old_seed = dict(seed); old_seed['sqlite'] = p['BASE_SQLITE_SEED']
    old_projection = dict(projection); old_projection['sqlite'] = p['BASE_SQLITE_SEED']
    need(sha(canonical(old_seed)) == p['BASE_SEED_SHA'] and sha(canonical(old_projection)) == p['BASE_PROJECTION_SHA'], 'OTHER340_SEED_AND573_PROJECTION_HELD')

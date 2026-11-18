# SPDX-License-Identifier: MIT
"""Fixed Source207 backend route identities and published readback selector."""

NUMBER = 207
FAMILY = "scripts/ci/first-login-enrollment-native-source/"
CASE_KIND = "ROOT_SOURCE207_ONCE_CASE_V1"
READER_CONTRACT = "SOURCE207_RETAINED_PUBLIC_ROUTES_V1"
WORKFLOW_ID = 420175404

CID = '5c6bc061d547017fd9be412e3addfc2f8bbf9e65'
REF = 'refs/heads/codex/current-onboarding-staging-v7-public-routes-20261118-r3'
PUBLICATION = {'bytes': 1149, 'sha256': 'c716183850332a3263bb59db53eab6ea66cfb9d1718996583f594b99ffe50b53'}
SOURCE = {'files': 207,
 'bytes': 46173225,
 'tree': '828bdb990683df1d35ee85922df6650d5f723a58',
 'source_map': {'bytes': 41197, 'sha256': '87d10d5e85df3b7800de3d8cec0533038bc99b0bb4edad5a2fddf531b661e03c'}}
PROGRAM = dict(path=FAMILY + "successor_v7_source/program.json", bytes=15135,
               sha256="6b275a8634b95e83471dc7ff4c187fae200789e9989c92c456ad3723455658dd")
PROFILE = {'bytes': 21451, 'sha256': '00f8f61119a26009040290258058f1942cec68fc3a8993208aa5763ef84d826b'}
CORE = {'bytes': 68455, 'sha256': '2466d2f5244a7a2a6e22adde9d856f734a28d5753828c4030daffeb80c565b71'}
POLICY = dict(member=FAMILY + "payload/native/owned_current_v3.policy.PROPOSAL.json", bytes=8366,
              sha256="18546f7a7309b48eecb6098db54b5a5705ce7dd3f85e0f3fd1e2e803a4ee243c")
READER = dict(member=FAMILY + "successor_v7_source/main_route/reader_current_v3_source207.py",
              bytes=297439, sha256="752e0f666d4b610b2ee1e27f0ec8c5ff44fe6b0866b7b0dba99e514986bdf74c")
TEST_FINGERPRINT = 'C908F19D5618FE95F08864A8E397439FC7A7980D'
TEST_PUBLIC_KEY = dict(member='carrier/inputs/public/setup8-current.asc', bytes=433,
                       sha256='c23c4f80efbabdc7a34db466e0f675e035ecf8b1a1ac7b1700a716d133b8e26a')
TEST_ROLE_EXPIRES = 1795474060
DIRECT_DOWNLOAD_FILENAMES = frozenset({
    'cmake-4.4.4-1-aarch64.pkg.tar.xz',
    'cmake-4.4.4-1-aarch64.pkg.tar.xz.sig',
    'libuv-1.52.1-2-aarch64.pkg.tar.xz',
    'libuv-1.52.1-2-aarch64.pkg.tar.xz.sig',
})
DOWNLOAD_FILENAMES = DIRECT_DOWNLOAD_FILENAMES | {
    'ArchLinuxARM-2026.08-aarch64-rootfs.tar.gz',
    'ArchLinuxARM-2026.08-aarch64-rootfs.tar.gz.sig',
    'archlinuxarm-revoked',
    'archlinuxarm-trusted',
    'archlinuxarm.gpg',
    'cppdap-1.58.0-3-aarch64.pkg.tar.xz',
    'cppdap-1.58.0-3-aarch64.pkg.tar.xz.sig',
    'jsoncpp-1.9.8-1-aarch64.pkg.tar.xz',
    'jsoncpp-1.9.8-1-aarch64.pkg.tar.xz.sig',
    'meson-1.12.1-2-any.pkg.tar.xz',
    'meson-1.12.1-2-any.pkg.tar.xz.sig',
    'ninja-1.13.2-3-aarch64.pkg.tar.xz',
    'ninja-1.13.2-3-aarch64.pkg.tar.xz.sig',
    'python-tqdm-4.70.1-1-any.pkg.tar.xz',
    'python-tqdm-4.70.1-1-any.pkg.tar.xz.sig',
    'rhash-1.4.6-1-aarch64.pkg.tar.xz',
    'rhash-1.4.6-1-aarch64.pkg.tar.xz.sig',
}

# SPDX-License-Identifier: MIT
"""Exact public Source206 backend roles and independently selected Main Reader."""

NUMBER = 206

FAMILY = "scripts/ci/first-login-enrollment-native-source/"
CID = "12827a098e9401998496405efde9de751367a14b"
REF = "refs/heads/codex/current-onboarding-staging-v7-20261118-r2"
WORKFLOW_ID = 420175404
SOURCE = dict(files=206, bytes=46085317, tree="e298cec82dac0df41f8fe3d3c0878cad2195e9a3",
              source_map=dict(bytes=41001, sha256="cc7442cd46fa5ea256050c048c4d52d98e8e9854e157577e5630a3f9bceba84a"))
PROGRAM = dict(path=FAMILY + "successor_v7_source/program.json", bytes=15135,
               sha256="24d8d926357ee93058d21ac4c3fbbfac55f71fce5a603b1e492b0294b19f47df")
PROFILE = dict(bytes=21451, sha256="f86fbaa580c442d460b6cc5f4cdbec50102ea8cf4a2c7fc8e682f14bad00c38b")
POLICY = dict(member=FAMILY + "payload/native/owned_current_v3.policy.PROPOSAL.json", bytes=8366,
              sha256="18546f7a7309b48eecb6098db54b5a5705ce7dd3f85e0f3fd1e2e803a4ee243c")
READER = dict(member=FAMILY + "successor_v7_source/main_route/reader_current_v3_source206.py", bytes=284823,
              sha256="026861268976ab0b9ae72f7aca591683742a64d3df3c14aa2d245fa3c5903420")
READER_CONTRACT = "SOURCE206_C908_FINITE_TRANSPORT_V2"
CASE_KIND = "ROOT_SOURCE206_ONCE_CASE_V1"
PUBLICATION = dict(bytes=893, sha256="ed60db52d00a778ed2dc962d05bdc6a021e131a6875fbb88e09a8d624842137d")
TEST_FINGERPRINT = "C908F19D5618FE95F08864A8E397439FC7A7980D"
TEST_PUBLIC_KEY = dict(member="carrier/inputs/public/setup8-current.asc", bytes=433,
                       sha256="c23c4f80efbabdc7a34db466e0f675e035ecf8b1a1ac7b1700a716d133b8e26a")
TEST_ROLE_EXPIRES = 1795474060

# Native qualification source preparation

November 14, 2026. Root constructed these local source trees from the genuine
200-file Source97 parent, commit `97a44c4c7cb206704bf76e9fd1f1afb2266278c2`.
The constructors validate complete bodies, modes, the nonrecursive source map,
parent identity and changed/held inverse before atomic fresh output publication.
Independent Git blob/index/write-tree operations then reproduce the expected
trees. No operand or package code is executed during construction.

| Family | Profile SHA-256 | Verified source tree | Source map SHA-256 |
| --- | --- | --- | --- |
| SessionLock 0.1.0-1 / Settings 0.1.1-1 | `1b9659195df181761df47e063768f7e5171675d85f721831fd67429efd467a11` | `439c3db9ecd2b9b534753f9c8bca548f64621a6c` | `97aebeb60bff422f097112b4e49604adf94fc0532c5ca7749a3e544bda2290b3` |
| FirstLogin 0.1.0-2 / Enrollment 0.3.0-1, corrected lifecycle reader | `ee6191505aff5d19726bdd403883e473445c164d7142b5fb0dbdddaea473c9b5` | `092b015de93c24f4bd8ad1e140cf447d77ec8678` | `f3b3aacd17dc0ce669fe6c546d99418c87b96d0cd843c3bcb37614c0404d5be7` |

The FirstLogin constructor separately reads the retained qualified Setup8
archive: 33,900 bytes, SHA-256
`8de3bd0cf2d9333b41925fecdef5cbfe2ec6d40c3424d90746182142e0c7dc47`.
Root recovered both byte-identical members from the original locally retained
run40490674681 ZIP and joined the existing
[Setup8 record](setup8-migration-native-20261027.md). There was no new acquisition
or evidence Reader invocation.

The earlier FirstLogin source tree
`6a4716972f3116ae63447af3c5fcb42311bbe596` was also constructed locally and is
retained as superseded DATA. Its image-lifecycle reader expected the old tools
argv. The corrected family preserves the established base16/tools17 convention,
with quiet tools build; four new modeled lifecycle controls cover positive and
refusal paths. Neither source tree was published or used for a native trial.

The two current families pass 24 and 20 actor-fenced source controls respectively
on Python 3.14.7. These model role/data joins; they do not execute the actual
capsule Reader or establish native package success. Fresh source commits/refs,
resource admission, actual runs/jobs/artifacts, matching Reader decisions and
native qualification remain pending. The FirstLogin/Enrollment build additionally
requires independent qualification of bubblewrap and mapped-root namespaces in
the actual normal image-build RUN context. Consumer or emulated success does not
establish that prerequisite. No privileged, sysctl or test-skip fallback is granted.

Private source trees and construction receipts are retained under
`artifacts/development/orchestrator-resume-20261114/`. Three constructor calls
occurred: SessionLock/Settings once, FirstLogin/Enrollment once before correction
and once after correction. Native, Original acquisition and actual Reader calls
for these new families remain zero. Hardware, performance and release remain
unqualified.

"""Pure receipt/packet fixtures; no GPG, package commands, Docker or network."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

HERE = Path(__file__).parent.resolve(); sys.path.insert(0, str(HERE))
import initial_artifacts as a


# Exact public fixture records retained from native run 38212287407.
# Kept inline so frozen packet tests do not depend on ignored local artifacts.
ACTUAL_FIXTURE_MANIFEST = b'{\n  "M2_validation": "NOT RUN",\n  "development_only": true,\n  "frozen_lock_sha256": "20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63",\n  "generator_sha256": "0042c17f99e5ff2d3af02ba343786c860d2a9c4c698dd67da2862cc203a60824",\n  "native_build": "NOT RUN",\n  "package_upgrade": "NOT RUN",\n  "packages": {\n    "cachy-asahi-fish-config": {\n      "base_inputs_sha256": {\n        ".SRCINFO": "7cffffec6d267324bf285edbfd69567aa8b27b617e405091e2a2696ae90c69a4",\n        ".gitignore": "fe48a6c62c3b98bfd773529a7fd8a2ba2c505b0932d1376c822d821126623c5c",\n        "LICENSE": "51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7",\n        "NOTICE": "19eb85ed65396056e59782ddf80fb5285ee26cad5ddf77ccb378936a2d5601c9",\n        "PKGBUILD": "a3f0e5f693a48126086ff0e8279d8d833efb8e625dfa4644fdfd2c04ff0175fa",\n        "README.md": "a78bba7de90fb6111fcbedd29a65d75dac93b8f1e38b3ae768f8e9e08e91d9e0",\n        "arm-dependency-audit.json": "70c4f30683a3f70bee3b7fe86598b59e0db01c753e2a1a2636cff8c85cc1765d",\n        "check-config.py": "a76ea238dfbb9bb650c46e676cff741404e504fa7b05a489e06fd2759ff8f39f",\n        "config.fish": "223df59fe83948e1d83676f4571cd2d4ce186862adf1cc23da6d5bbd28370a1c",\n        "evidence/host-build-1.BUILDINFO": "080d91a9f57905a06f85df994b9d124c9fa707f880a95e04fd19b49b1d9fe2a3",\n        "evidence/host-build-1.PKGINFO": "86968ab0e100931aa0e3458ea7940dbe402a4114cac063262f3ad43d8e4fc75e",\n        "evidence/host-build-2.BUILDINFO": "824d68cf8a98b489883562cbb094c82304c320e0ee67daf718a46e1cb63e1890",\n        "evidence/host-build-2.PKGINFO": "f6cc29b1d0f787cae53e9473688bb67de82c7afac8226d2d5c89b8cc01474004",\n        "evidence/makepkg-host-1.log": "e3e97f0dd05fecabcdd28f16cb5e1b9d57853708bd667ffde683cf3ed0a5f76e",\n        "evidence/makepkg-host-2.log": "e3290261826439933092938825d3086f8dc315d0ce2ad90fc69882df0e0fb6b0",\n        "host-validation.json": "b0ce5882f96929057840ab3675cd28c784139812493877dfc3d4a4066045db2a",\n        "runtime-dependency-observation.json": "eef8a925e0f07882f9b587e418c0362fe2784742a31c5a5bead9adc0d44ca5f1",\n        "upstream-audit.json": "7fa40f3a83a3933b3eebeab7394026029e41f15d52042e74d0cb893ce30a5c62"\n      },\n      "base_recipe_sha256": "a3f0e5f693a48126086ff0e8279d8d833efb8e625dfa4644fdfd2c04ff0175fa",\n      "base_version": "0.1.0-1",\n      "baseline_recipe": "baseline/packages/shells/cachy-asahi-fish-config",\n      "behavior_expectations": [\n        "same package identity/ownership and dependencies",\n        "MIT notices retained",\n        "rollback uses exact baseline recipe/artifact version"\n      ],\n      "cli_expectation": null,\n      "diff": "diffs/cachy-asahi-fish-config.diff",\n      "diff_sha256": "1101188676716974944bd5387747d22a5f95a0efee6f8c12fdba6d080019e8a7",\n      "fixture_inputs_sha256": {\n        ".SRCINFO": "a0fa135173152da0a509e224763153265f98feea6e62b5c7bd8f01999126c70a",\n        "LICENSE": "51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7",\n        "NOTICE": "47f660f7c37c034933f4e39fd5040b9bc5e0e360b3647228ca6edff5bc72dd91",\n        "PKGBUILD": "4b1593ec14189b04c286876b32b99f3edef63a6b662e9588537b1b6f2287dc96",\n        "README.md": "c1217b97516b5d4bf67e45e57318ae5fee2dabf1255515932e846abccd045010",\n        "config.fish": "bef9da947d1fc839d4fcfcb1f34f88512b5b1e64733ba030e830e40acbc63add"\n      },\n      "fixture_recipe_sha256": "4b1593ec14189b04c286876b32b99f3edef63a6b662e9588537b1b6f2287dc96",\n      "payload_expectations": [\n        {\n          "base_sha256": "223df59fe83948e1d83676f4571cd2d4ce186862adf1cc23da6d5bbd28370a1c",\n          "fixture_sha256": "bef9da947d1fc839d4fcfcb1f34f88512b5b1e64733ba030e830e40acbc63add",\n          "marker": "DEVELOPMENT UPDATE FIXTURE cachy-asahi-fish-config 0.1.1",\n          "path": "usr/share/cachy-asahi/fish/config.fish"\n        }\n      ],\n      "recipe": "packages/shells/cachy-asahi-fish-config",\n      "reviewed_inputs": {\n        "baseline": "reviewed-inputs/baseline/cachy-asahi-fish-config.json",\n        "upgrade": "reviewed-inputs/upgrade/cachy-asahi-fish-config.json"\n      },\n      "rollback_expectation": {\n        "artifact_status": "NOT BUILT",\n        "installed_path": "usr/share/cachy-asahi/fish/config.fish",\n        "payload_sha256": "223df59fe83948e1d83676f4571cd2d4ce186862adf1cc23da6d5bbd28370a1c",\n        "version": "0.1.0-1"\n      },\n      "upgrade_recipe": "upgrade/packages/shells/cachy-asahi-fish-config",\n      "upgrade_version": "0.1.1-1"\n    },\n    "cachy-asahi-hyprland-settings": {\n      "base_inputs_sha256": {\n        ".SRCINFO": "feeb68da93a0a81f274125e00588c98ad5e7b9772377172a0973c06d5cf94c89",\n        "LICENSE": "51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7",\n        "NOTICE": "7c108a66b5a4807f8fe7696ef1b1011386b37774fb94e674dd37c7e1dec7b9e4",\n        "PKGBUILD": "4c55f488c5b886a88a277c058afde5266e4cefd3e348847f89801aef8d841bcc",\n        "README.md": "3edac178cb92d6d06b21fe4832bbbce5f7a55ed4dde8925ac0815c5350e2c525",\n        "hyprland.lua": "f900ffbfdea86acc686299fd9ef88a235fb4822f7177afe75a43369ca48d158b",\n        "mako.conf": "c6ab55ae475611bf2df2b7120b97a924eed5d65c149561d4da4f12b5b8c25504",\n        "waybar.css": "a97930965a4e622adc920491c7d433a803173bb6e644c4c3c88efb79187e11d5",\n        "waybar.json": "4c7adb2deb0403fefc4562d39105635cebfc44ce88e44fe84c4a90a00b2be3c0"\n      },\n      "base_recipe_sha256": "4c55f488c5b886a88a277c058afde5266e4cefd3e348847f89801aef8d841bcc",\n      "base_version": "0.1.0-1",\n      "baseline_recipe": "baseline/packages/desktop/cachy-asahi-hyprland-settings",\n      "behavior_expectations": [\n        "same package identity/ownership and dependencies",\n        "MIT notices retained",\n        "rollback uses exact baseline recipe/artifact version"\n      ],\n      "cli_expectation": null,\n      "diff": "diffs/cachy-asahi-hyprland-settings.diff",\n      "diff_sha256": "d4f742c52c901c150de0b2790585a652c538036b14d55b4646ee692f6c6c5ee7",\n      "fixture_inputs_sha256": {\n        ".SRCINFO": "06084d128d14fb680f7ff41a65b1a3d08b97462e5f5ddd575e0582461ccf6c51",\n        "LICENSE": "51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7",\n        "NOTICE": "f0c2a002b4ef2578e508fd246ceb328d2a379ca58fe077cdd2c1c5b992556ba6",\n        "PKGBUILD": "fc088528076598fdc6231e59ffa6b160eaf96648b4234ad84aa2b2fbf6ee15fc",\n        "README.md": "b4f1c8cfff741790ba0eb501a72c2d1722267b201a9d42a9759d12573920b47f",\n        "hyprland.lua": "2a3b7192d6f456942cb282e37d3330f1ce079fc44c5754dbeebc1c9daa6f2f0b",\n        "mako.conf": "c6ab55ae475611bf2df2b7120b97a924eed5d65c149561d4da4f12b5b8c25504",\n        "waybar.css": "a97930965a4e622adc920491c7d433a803173bb6e644c4c3c88efb79187e11d5",\n        "waybar.json": "4c7adb2deb0403fefc4562d39105635cebfc44ce88e44fe84c4a90a00b2be3c0"\n      },\n      "fixture_recipe_sha256": "fc088528076598fdc6231e59ffa6b160eaf96648b4234ad84aa2b2fbf6ee15fc",\n      "payload_expectations": [\n        {\n          "base_sha256": "f900ffbfdea86acc686299fd9ef88a235fb4822f7177afe75a43369ca48d158b",\n          "fixture_sha256": "2a3b7192d6f456942cb282e37d3330f1ce079fc44c5754dbeebc1c9daa6f2f0b",\n          "marker": "DEVELOPMENT UPDATE FIXTURE cachy-asahi-hyprland-settings 0.1.1",\n          "path": "usr/share/cachy-asahi/hyprland/hyprland.lua"\n        }\n      ],\n      "recipe": "packages/desktop/cachy-asahi-hyprland-settings",\n      "reviewed_inputs": {\n        "baseline": "reviewed-inputs/baseline/cachy-asahi-hyprland-settings.json",\n        "upgrade": "reviewed-inputs/upgrade/cachy-asahi-hyprland-settings.json"\n      },\n      "rollback_expectation": {\n        "artifact_status": "NOT BUILT",\n        "installed_path": "usr/share/cachy-asahi/hyprland/hyprland.lua",\n        "payload_sha256": "f900ffbfdea86acc686299fd9ef88a235fb4822f7177afe75a43369ca48d158b",\n        "version": "0.1.0-1"\n      },\n      "upgrade_recipe": "upgrade/packages/desktop/cachy-asahi-hyprland-settings",\n      "upgrade_version": "0.1.1-1"\n    },\n    "cachy-asahi-setup": {\n      "base_inputs_sha256": {\n        ".SRCINFO": "3b60863efc02077497206ce42a71163cac2e60286fc655c4375e575fb95b5b4e",\n        "LICENSE": "51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7",\n        "NOTICE": "2c28b96b5e4dca86c8a71aa0df728a049820d5951812f20241be96e7000d9744",\n        "PKGBUILD": "1d4326ccfa5b0a68b4eb82351c29a99ca2c0ad8af7503e84aa01bcd3dd1cbe68",\n        "README.md": "434328ca04e757a2dc8bba78bea82c6ed52da64b139e88666a3ec2db52ba0e56",\n        "cachy-asahi-setup": "a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2",\n        "check-packaged.py": "a36c6b0c5e5e51cee5a88b2bc2d21b292de413e3ea5664936f4097ff52e55ca6",\n        "check-sync.py": "ce66c6fc4b66d358378143f585fd3d1a708fddee80942e12900d5b76b2ff009b",\n        "evidence/artifact-check-1.json": "f39576fe7d072cc964479d8b4477e547ef885a69f55b42b85fdbafc84f95226f",\n        "evidence/artifact-check-2.json": "c6fa3a00eda45aca371b651e37634600cde621d53c8e1081c66f141273b41808",\n        "evidence/host-build-1-BUILDINFO.txt": "d027509d0d0bc7c74b293d781c36001df48427a726f9e0778730e9fa554b7346",\n        "evidence/host-build-1-PKGINFO.txt": "c02a9e4ac9e0d305b97fe63a6e6124446154dafdc4195254c1cac30b17e8761e",\n        "evidence/host-build-1.txt": "52b0a5112c6f23fa04567b6d60a50bd80d087f8691e9c066e91ddca8cd902923",\n        "evidence/host-build-2-BUILDINFO.txt": "e5e6c09c8f6bf62064c0200046d22a0e3b9611d57e199dc835c30e8bd55778d9",\n        "evidence/host-build-2-PKGINFO.txt": "d04e52761ae002dd63fc6a684a073d68da2e994fa6dd90395039e861070e3dae",\n        "evidence/host-build-2.txt": "c744d661c373fab100ec930c50e4fe42f70c2ab319b37490e98124ef9e6d4a0e",\n        "evidence/old-c7d-regression-reproducer.json": "0a8be1068e9c98e31fe07816065422cad6d59e10828cceda1967bea01a956a11",\n        "evidence/packaged-cli-smoke.json": "b42c30a6469ea52d0b129c22aaac337081a0c7052736412cd640796d59e3495e",\n        "evidence/packaged-regressions-1.json": "d449d77dfc618dcc3a042d2e80884f1d9dd6c0a9beee11edafdd97846412b6a5",\n        "evidence/packaged-regressions-2.json": "d449d77dfc618dcc3a042d2e80884f1d9dd6c0a9beee11edafdd97846412b6a5",\n        "evidence/prepare-drift-refusal.txt": "37701db28f3eef8d78855fc97130dc5b34737b689564d66775924bdc3a913edd",\n        "evidence/recipe-check.json": "c03666a59699d36af0ecdba565c65fcba2be2a9b7f5b3f867f42f58714400b29",\n        "evidence/superseded-c7d-host-validation.json": "1c4c1522612bb9f35c11745889d5cedabad6ea89b312f7812bbd65951d537ee3",\n        "host-validation.json": "e64e15a48b1636216c1419074ba7ae3280bddd42c5db76b7954a3da882f7766c",\n        "runtime-dependency-observation.json": "0f2382d15eb1c07c94826b1467492b248576350a43b96550cf23b94e018fa74c",\n        "source-provenance.json": "3466cccc33c98f675af0779ebdc150636ed3544d78bc5c1543bd8d25c09aded7",\n        "test-sync.py": "f2694ef9e7ccca7201f444e5cad28aa524da374faae364e8bcbb75200149e6bb"\n      },\n      "base_recipe_sha256": "1d4326ccfa5b0a68b4eb82351c29a99ca2c0ad8af7503e84aa01bcd3dd1cbe68",\n      "base_version": "0.1.0-2",\n      "baseline_recipe": "baseline/packages/settings/cachy-asahi-setup",\n      "behavior_expectations": [\n        "same package identity/ownership and dependencies",\n        "MIT notices retained",\n        "rollback uses exact baseline recipe/artifact version"\n      ],\n      "cli_expectation": {\n        "argv": [\n          "--integration-fixture-version"\n        ],\n        "stdout": "cachy-asahi-setup 0.1.1 DEVELOPMENT-FIXTURE\\n",\n        "writes_user_state": false\n      },\n      "diff": "diffs/cachy-asahi-setup.diff",\n      "diff_sha256": "818a976b034ac9c142f922ee3db62065c4ab9a08eed25a2dfd11442f28bd30f7",\n      "fixture_inputs_sha256": {\n        ".SRCINFO": "20c539cbb718e71b1d7d361f4d8893d2484892cd44a52030f5e6220bf3d28c8a",\n        "LICENSE": "51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7",\n        "NOTICE": "1d0591aed60a239d21890fa6c758772c2ab82efd38cdc197d32813b9409d98d5",\n        "PKGBUILD": "bfdaac37428ddb5b5a7ed9064ed5edb1344a3bc5da91881fbb1062fdac046de5",\n        "README.md": "2676bedc6fc1d3c6a945bcd37dcb65e3818a11b6435d6c6e0551a35e193a689f",\n        "base-setup.py": "a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2",\n        "cachy-asahi-setup": "131ce3941f65b1b4cf4845a96bfd04e9325c0f6afe409f8c6239a2a321597e7b",\n        "check-sync.py": "167b8aa2e503bc4551acc33365a0e6869ea55e9dffe19c602697d5711f6cfe58",\n        "source-provenance.json": "692730238b3458499c396baa329f775b8dc4c651c7aade83bc734d768767568c",\n        "test-sync.py": "45d237c5b9f95ad40950678f660be4e21e79438d42e14328a15e8d1a80a26aac"\n      },\n      "fixture_recipe_sha256": "bfdaac37428ddb5b5a7ed9064ed5edb1344a3bc5da91881fbb1062fdac046de5",\n      "payload_expectations": [\n        {\n          "base_sha256": "a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2",\n          "fixture_sha256": "131ce3941f65b1b4cf4845a96bfd04e9325c0f6afe409f8c6239a2a321597e7b",\n          "marker": "cachy-asahi-setup 0.1.1 DEVELOPMENT-FIXTURE",\n          "path": "usr/bin/cachy-asahi-setup"\n        }\n      ],\n      "recipe": "packages/settings/cachy-asahi-setup",\n      "reviewed_inputs": {\n        "baseline": "reviewed-inputs/baseline/cachy-asahi-setup.json",\n        "upgrade": "reviewed-inputs/upgrade/cachy-asahi-setup.json"\n      },\n      "rollback_expectation": {\n        "artifact_status": "NOT BUILT",\n        "installed_path": "usr/bin/cachy-asahi-setup",\n        "payload_sha256": "a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2",\n        "version": "0.1.0-2"\n      },\n      "upgrade_recipe": "upgrade/packages/settings/cachy-asahi-setup",\n      "upgrade_version": "0.1.1-1"\n    },\n    "cachy-asahi-zsh-config": {\n      "base_inputs_sha256": {\n        ".SRCINFO": "efb12bb5e6afbf584f1feb58a3fc057877faa3e9f0a4a452e9554eefd524bfdd",\n        ".gitignore": "c808688d038d6010547ce65a9f0f2ffebab19c1cc64d794c0415d2f9bb9c5ec9",\n        "LICENSE": "51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7",\n        "NOTICE": "20f1a90870566d337745019d5c465db48e14a566df3222c48a3320dc441e4de8",\n        "PKGBUILD": "a0d86c532654f01edac764ad39d1173bb981a13752ad0216ea49907cd49b53e1",\n        "README.md": "bad66c7f1190c63ba323800a21a1b2463e67d59736e046bf8db53e0df9cdcf65",\n        "check-config.py": "e8f03737d19528bb36f2d4b72cf945ae32c284175b7fbc517196c91248965b2c",\n        "config.zsh": "7639b938dca689c445b64cc307148e2d3f85c5399d51c8ce69072dcf835baa6f",\n        "dependency-observation.json": "bacbdde71fe07a084396508c940e6fa83fc06d995be8c9f7efc079552bffbfe7",\n        "evidence/host-build-1.BUILDINFO": "0a93cea628ad8906ebd9c2117bafa8d74c6e00db32bccb37f167d98c71d048bb",\n        "evidence/host-build-1.log": "ea4a124c7b83cdaeaad68e04eed91d30883897958cfbb2d42a31477e9eefb762",\n        "evidence/host-build-2.BUILDINFO": "16a4892a3d73fc60ae595ea5c3587b222c32c0d8ec7a89ebdb9599a2532f8a9c",\n        "evidence/host-build-2.log": "6faa57f5fc9284da4bfcea58cd754c89d2dcab049b9b6d54ea1fab35bdf37e12",\n        "excluded-source-license-observation.json": "dc231bde74452bfe97c3c7aa1734779fd04b74e48da14525f431ef915a266e5d",\n        "host-validation.json": "06e50efb9debfe11a0c7af6d88e8172e844c2c2a3870454c0e222ba97f8cdcb2",\n        "upstream-audit.json": "279045f29953cd5a0bdcd6087ae97ed4f2df6f0b49746e4f0a7a66a75f60802d",\n        "usage.md": "19a9df455ad2c42b01eb184bdfb0b14402fe372e397fa91cc0ee28dd766bb65d"\n      },\n      "base_recipe_sha256": "a0d86c532654f01edac764ad39d1173bb981a13752ad0216ea49907cd49b53e1",\n      "base_version": "0.1.0-1",\n      "baseline_recipe": "baseline/packages/shells/cachy-asahi-zsh-config",\n      "behavior_expectations": [\n        "same package identity/ownership and dependencies",\n        "MIT notices retained",\n        "rollback uses exact baseline recipe/artifact version"\n      ],\n      "cli_expectation": null,\n      "diff": "diffs/cachy-asahi-zsh-config.diff",\n      "diff_sha256": "609ef05e8e61b7a973dc63f85c64632b9d73c8b65041c18cb166354bfab4764c",\n      "fixture_inputs_sha256": {\n        ".SRCINFO": "12b27726fca7cb3516b9046ae7d649f39cbb65b2038dec25787a19a6f900d38f",\n        "LICENSE": "51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7",\n        "NOTICE": "61506efffe1d5c81099fd85782a8a9b86438b077f35c34dad04b34663cde8228",\n        "PKGBUILD": "c84e3a969a3c5930c94e2bd8aa86df065a83349568dc58f0832163d823b36a2f",\n        "README.md": "a74a845684aba6e57b83a1b2fe961f383fb304214ddf93bb776c48a821468cc7",\n        "config.zsh": "1296f7b3e61f7e624c95e93080585fb8490141849e370938dfa47e06a2e711c1",\n        "usage.md": "27313679fce073aa97805cb4dff619e92f24ba4ebdbf3153a83feeb69190c7ee"\n      },\n      "fixture_recipe_sha256": "c84e3a969a3c5930c94e2bd8aa86df065a83349568dc58f0832163d823b36a2f",\n      "payload_expectations": [\n        {\n          "base_sha256": "7639b938dca689c445b64cc307148e2d3f85c5399d51c8ce69072dcf835baa6f",\n          "fixture_sha256": "1296f7b3e61f7e624c95e93080585fb8490141849e370938dfa47e06a2e711c1",\n          "marker": "DEVELOPMENT UPDATE FIXTURE cachy-asahi-zsh-config 0.1.1",\n          "path": "usr/share/cachy-asahi/zsh/config.zsh"\n        }\n      ],\n      "recipe": "packages/shells/cachy-asahi-zsh-config",\n      "reviewed_inputs": {\n        "baseline": "reviewed-inputs/baseline/cachy-asahi-zsh-config.json",\n        "upgrade": "reviewed-inputs/upgrade/cachy-asahi-zsh-config.json"\n      },\n      "rollback_expectation": {\n        "artifact_status": "NOT BUILT",\n        "installed_path": "usr/share/cachy-asahi/zsh/config.zsh",\n        "payload_sha256": "7639b938dca689c445b64cc307148e2d3f85c5399d51c8ce69072dcf835baa6f",\n        "version": "0.1.0-1"\n      },\n      "upgrade_recipe": "upgrade/packages/shells/cachy-asahi-zsh-config",\n      "upgrade_version": "0.1.1-1"\n    }\n  },\n  "schema_version": 1,\n  "selected_for_release": false,\n  "source_commit": "ebd5812640b0b69f5c09a47752b739e37e338754",\n  "source_commit_verification": "caller-supplied full pin; byte snapshot independently bound to reviewed lock; no Git command executed",\n  "source_date_epoch": 1791748800\n}\n'
ACTUAL_ARCHIVES = b'{\n  "baseline": [\n    {\n      "archive": "baseline/cachy-asahi-fish-config-0.1.0-1-any.pkg.tar.xz",\n      "name": "cachy-asahi-fish-config",\n      "payload_sha256": {\n        "usr/share/cachy-asahi/fish/config.fish": "223df59fe83948e1d83676f4571cd2d4ce186862adf1cc23da6d5bbd28370a1c",\n        "usr/share/licenses/cachy-asahi-fish-config/LICENSE": "51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7",\n        "usr/share/licenses/cachy-asahi-fish-config/NOTICE": "19eb85ed65396056e59782ddf80fb5285ee26cad5ddf77ccb378936a2d5601c9"\n      },\n      "sha256": "22e6e3ca4f23b73434c4aed284016914652900c33e845516621c0eb8b176d64e",\n      "version": "0.1.0-1"\n    },\n    {\n      "archive": "baseline/cachy-asahi-hyprland-settings-0.1.0-1-any.pkg.tar.xz",\n      "name": "cachy-asahi-hyprland-settings",\n      "payload_sha256": {\n        "usr/share/cachy-asahi/hyprland/hyprland.lua": "f900ffbfdea86acc686299fd9ef88a235fb4822f7177afe75a43369ca48d158b",\n        "usr/share/cachy-asahi/hyprland/mako.conf": "c6ab55ae475611bf2df2b7120b97a924eed5d65c149561d4da4f12b5b8c25504",\n        "usr/share/cachy-asahi/hyprland/waybar.css": "a97930965a4e622adc920491c7d433a803173bb6e644c4c3c88efb79187e11d5",\n        "usr/share/cachy-asahi/hyprland/waybar.json": "4c7adb2deb0403fefc4562d39105635cebfc44ce88e44fe84c4a90a00b2be3c0",\n        "usr/share/doc/cachy-asahi-hyprland-settings/README.md": "3edac178cb92d6d06b21fe4832bbbce5f7a55ed4dde8925ac0815c5350e2c525",\n        "usr/share/licenses/cachy-asahi-hyprland-settings/LICENSE": "51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7",\n        "usr/share/licenses/cachy-asahi-hyprland-settings/NOTICE": "7c108a66b5a4807f8fe7696ef1b1011386b37774fb94e674dd37c7e1dec7b9e4"\n      },\n      "sha256": "5d33320b55c2b3c778b94c128980c2d07d3fbcf466b3ab91ad8a706ff538ee81",\n      "version": "0.1.0-1"\n    },\n    {\n      "archive": "baseline/cachy-asahi-setup-0.1.0-2-any.pkg.tar.xz",\n      "name": "cachy-asahi-setup",\n      "payload_sha256": {\n        "usr/bin/cachy-asahi-setup": "a6251142b9c7e54796285c1a301fb590599d8aaa1625ea0bfebd7fc21622fdc2",\n        "usr/share/doc/cachy-asahi-setup/README.md": "434328ca04e757a2dc8bba78bea82c6ed52da64b139e88666a3ec2db52ba0e56",\n        "usr/share/licenses/cachy-asahi-setup/LICENSE": "51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7",\n        "usr/share/licenses/cachy-asahi-setup/NOTICE": "2c28b96b5e4dca86c8a71aa0df728a049820d5951812f20241be96e7000d9744"\n      },\n      "sha256": "40e392b4af6485d8518993073c1fe643eda60053312aeb618dfa9a6c9bee3489",\n      "version": "0.1.0-2"\n    },\n    {\n      "archive": "baseline/cachy-asahi-zsh-config-0.1.0-1-any.pkg.tar.xz",\n      "name": "cachy-asahi-zsh-config",\n      "payload_sha256": {\n        "usr/share/cachy-asahi/zsh/README.md": "19a9df455ad2c42b01eb184bdfb0b14402fe372e397fa91cc0ee28dd766bb65d",\n        "usr/share/cachy-asahi/zsh/config.zsh": "7639b938dca689c445b64cc307148e2d3f85c5399d51c8ce69072dcf835baa6f",\n        "usr/share/licenses/cachy-asahi-zsh-config/LICENSE": "51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7",\n        "usr/share/licenses/cachy-asahi-zsh-config/NOTICE": "20f1a90870566d337745019d5c465db48e14a566df3222c48a3320dc441e4de8"\n      },\n      "sha256": "1bcb8e7fde6da28bc817f252bee5c7084cd22ec4153512eaf5bb47bd83e90faa",\n      "version": "0.1.0-1"\n    }\n  ],\n  "upgrade": [\n    {\n      "archive": "upgrade/cachy-asahi-fish-config-0.1.1-1-any.pkg.tar.xz",\n      "name": "cachy-asahi-fish-config",\n      "payload_sha256": {\n        "usr/share/cachy-asahi/fish/config.fish": "bef9da947d1fc839d4fcfcb1f34f88512b5b1e64733ba030e830e40acbc63add",\n        "usr/share/licenses/cachy-asahi-fish-config/LICENSE": "51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7",\n        "usr/share/licenses/cachy-asahi-fish-config/NOTICE": "47f660f7c37c034933f4e39fd5040b9bc5e0e360b3647228ca6edff5bc72dd91"\n      },\n      "sha256": "dbda251c19cbab7d6e43cb73ff1c0d9399ef0fe24e445a445662b6a96c53650d",\n      "version": "0.1.1-1"\n    },\n    {\n      "archive": "upgrade/cachy-asahi-hyprland-settings-0.1.1-1-any.pkg.tar.xz",\n      "name": "cachy-asahi-hyprland-settings",\n      "payload_sha256": {\n        "usr/share/cachy-asahi/hyprland/hyprland.lua": "2a3b7192d6f456942cb282e37d3330f1ce079fc44c5754dbeebc1c9daa6f2f0b",\n        "usr/share/cachy-asahi/hyprland/mako.conf": "c6ab55ae475611bf2df2b7120b97a924eed5d65c149561d4da4f12b5b8c25504",\n        "usr/share/cachy-asahi/hyprland/waybar.css": "a97930965a4e622adc920491c7d433a803173bb6e644c4c3c88efb79187e11d5",\n        "usr/share/cachy-asahi/hyprland/waybar.json": "4c7adb2deb0403fefc4562d39105635cebfc44ce88e44fe84c4a90a00b2be3c0",\n        "usr/share/doc/cachy-asahi-hyprland-settings/README.md": "b4f1c8cfff741790ba0eb501a72c2d1722267b201a9d42a9759d12573920b47f",\n        "usr/share/licenses/cachy-asahi-hyprland-settings/LICENSE": "51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7",\n        "usr/share/licenses/cachy-asahi-hyprland-settings/NOTICE": "f0c2a002b4ef2578e508fd246ceb328d2a379ca58fe077cdd2c1c5b992556ba6"\n      },\n      "sha256": "f4e77696d566cf93222a663e930cf5ede81acaa8b95d1293ec0db017a1cc24b6",\n      "version": "0.1.1-1"\n    },\n    {\n      "archive": "upgrade/cachy-asahi-setup-0.1.1-1-any.pkg.tar.xz",\n      "name": "cachy-asahi-setup",\n      "payload_sha256": {\n        "usr/bin/cachy-asahi-setup": "131ce3941f65b1b4cf4845a96bfd04e9325c0f6afe409f8c6239a2a321597e7b",\n        "usr/share/doc/cachy-asahi-setup/README.md": "2676bedc6fc1d3c6a945bcd37dcb65e3818a11b6435d6c6e0551a35e193a689f",\n        "usr/share/licenses/cachy-asahi-setup/LICENSE": "51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7",\n        "usr/share/licenses/cachy-asahi-setup/NOTICE": "1d0591aed60a239d21890fa6c758772c2ab82efd38cdc197d32813b9409d98d5"\n      },\n      "sha256": "f546668d61d11925c91d228588ab3b8e480cd88db5262a74d61974e6db176c6a",\n      "version": "0.1.1-1"\n    },\n    {\n      "archive": "upgrade/cachy-asahi-zsh-config-0.1.1-1-any.pkg.tar.xz",\n      "name": "cachy-asahi-zsh-config",\n      "payload_sha256": {\n        "usr/share/cachy-asahi/zsh/README.md": "27313679fce073aa97805cb4dff619e92f24ba4ebdbf3153a83feeb69190c7ee",\n        "usr/share/cachy-asahi/zsh/config.zsh": "1296f7b3e61f7e624c95e93080585fb8490141849e370938dfa47e06a2e711c1",\n        "usr/share/licenses/cachy-asahi-zsh-config/LICENSE": "51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7",\n        "usr/share/licenses/cachy-asahi-zsh-config/NOTICE": "61506efffe1d5c81099fd85782a8a9b86438b077f35c34dad04b34663cde8228"\n      },\n      "sha256": "b418d410a7c2ffa65b2a31c3546d18b976ea7b2ca2f7e3d7074c95389f317083",\n      "version": "0.1.1-1"\n    }\n  ]\n}\n'

def sha(data):
    return hashlib.sha256(data).hexdigest()


def sig(algorithm=1):
    mpis = b'\0\x01\x01' if algorithm == 1 else b'\x01\x07\x40' + b'\x01' * 32 + b'\x01\0' + b'\x01' * 32
    body = bytes((4, 0, algorithm, 8)) + b'\0\0\0\0ab' + mpis
    return bytes((0xc2, len(body))) + body


def cert():
    uid = b'CACHY-ASAHI TEST ONLY <test@invalid.example>'
    body = b'\xc6\x03\x04xx' + bytes((0xcd, len(uid))) + uid + sig()
    return b'-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n' + base64.b64encode(body) + b'\n-----END PGP PUBLIC KEY BLOCK-----\n'


class InitialArtifacts(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.base = Path(temp.name); self.root = self.base / 'root'; self.evidence = self.base / 'initial'
        self.root.mkdir(); self.evidence.mkdir()
        real_root = HERE.parents[2]
        for name in ('scripts/ci/integration_export.py', 'scripts/ci/sign_fixture.py', 'scripts/integration/repository.py',
                     'scripts/integration/fixtures.py', 'scripts/ci/recipes.lock.json'):
            target = self.root / name; target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(real_root / name, target)
        self.commit, self.image = '932cf519fc98e6d6d7c15bc39d28f538b8f375e5', 'sha256:' + 'a' * 64
        self.put_json(self.evidence / 'result.json', {'schema_version': 1, 'purpose': 'frozen-development-only-native-integration',
            'development_only': True, 'selected_for_release': False, 'hardware_validation': 'NOT RUN', 'production_trust': 'NOT RUN',
            'source_commit': self.commit, 'base_image': self.image,
            'stages': {n: {'status': 'PASS'} for n in ('fixtures', 'signer', 'repository')}})
        self.recipe_commit = 'ebd5812640b0b69f5c09a47752b739e37e338754'
        recipes = a.read_json(self.root / 'scripts/ci/recipes.lock.json')
        for directory in recipes:
            shutil.copytree(real_root / directory, self.root / directory)
        self.rows = {'baseline': [], 'upgrade': []}; packages = {}
        for name in sorted(a.ORIGINALS):
            packages[name] = {'base_version': '0.1.0-1', 'upgrade_version': '0.2.0-1', 'recipe': a.RECIPES[name],
                              'base_inputs_sha256': recipes[a.RECIPES[name]]}
            for stage, version in (('baseline', '0.1.0-1'), ('upgrade', '0.2.0-1')):
                archive = stage + '/' + name + '-' + version + '-any.pkg.tar.xz'; data = ('MIT fixture ' + archive).encode()
                self.rows[stage].append({'name': name, 'version': version, 'archive': archive, 'sha256': sha(data),
                                        'payload_sha256': {'usr/share/' + name + '/setting': sha(data)}})
                self.put(self.evidence / 'work/archive-inputs' / archive, data)
        self.put_json(self.evidence / 'work/fixtures-raw/archives.json', self.rows)
        self.put_json(self.evidence / 'work/fixtures/fixture-manifest.json', {'schema_version': 1, 'source_commit': self.recipe_commit,
                      'frozen_lock_sha256': a.digest(self.root / 'scripts/ci/recipes.lock.json'),
                      'generator_sha256': a.digest(self.root / 'scripts/integration/fixtures.py'), 'source_date_epoch': 1791748800,
                      'development_only': True, 'selected_for_release': False, 'packages': packages})
        self.put_json(self.root / 'scripts/ci/integration.lock.json', {'schema_version': 1,
            'purpose': 'frozen-development-only-native-integration', 'development_only': True, 'selected_for_release': False,
            'recipe_source_commit': self.recipe_commit, 'recipes_sha256': a.digest(self.root / 'scripts/ci/recipes.lock.json'),
            'source_date_epoch': 1791748800, 'source_files': {'scripts/integration/fixtures.py':
                {'sha256': a.digest(self.root / 'scripts/integration/fixtures.py'), 'mode': 0o644}},
            'generated_fixture_files': {'fixture-manifest.json':
                {'sha256': a.digest(self.evidence / 'work/fixtures/fixture-manifest.json'), 'mode': 0o644}}})
        self.fixture = self.evidence / 'public/fixture-archives'
        approved = {Path(r['archive']).name: r['sha256'] for r in self.rows['upgrade']}
        for row in self.rows['upgrade']:
            self.put(self.fixture / Path(row['archive']).name, self.data('work/archive-inputs/' + row['archive']))
        self.put_json(self.fixture / 'archive-manifest.json', {'development_only': True, 'selected_for_release': False,
                      'source_commit': self.commit, 'archives': approved, 'production_signing': 'NOT RUN'})
        expected = [{k: r[k] for k in ('name', 'version', 'sha256')} |
                    {'path': r['archive'], 'role': 'original' if stage == 'baseline' else 'upgrade-fixture'}
                    for stage in ('baseline', 'upgrade') for r in self.rows[stage]]
        self.put_json(self.evidence / 'work/archive-inputs/archive-manifest.json', {'schema_version': 1,
                      'purpose': 'TEST-ONLY-integration-signatures', 'source_commit': self.commit, 'archives': expected})
        fp = 'C' * 40
        signatures = {r['path']: {'archive_sha256': r['sha256'], 'signature_sha256': sha(sig()),
                       'status': '[GNUPG:] VALIDSIG ' + fp + ' 2026-10-12 123 456 4 0 1 8 00 ' + fp} for r in expected}
        self.put_json(self.evidence / 'work/signer-raw/test-signature-receipt.json', {'status': 'TEST-SIGNATURES PASS',
            'purpose': 'TEST-ONLY-integration-signatures', 'production_credentials_used': False, 'hardware_status': 'NOT RUN',
            'fingerprint': fp, 'expiry': 1791748800, 'public_certificate_sha256': sha(cert()), 'signatures': signatures,
            'contract': {'image_id': self.image, 'manifest_sha256': a.digest(self.evidence / 'work/archive-inputs/archive-manifest.json')}})
        self.signer = self.evidence / 'public/signer-public-artifacts'
        signer_files = {'public-key.asc': cert(), **{'signatures/' + r['path'] + '.sig': sig() for r in expected}}
        self.material(self.signer, self.evidence / 'work/test-signatures/public', signer_files,
                      {'purpose': 'TEST-ONLY-offline-signature-verification', 'fingerprint': fp, 'expiry': 1791748800,
                       'archives': {r['path']: r['sha256'] for r in expected}})
        self.repository = self.evidence / 'public/repository-public-artifacts'
        repo_files = {name: cert() for name in a.CERTS}
        repo_files.update({'TEST-repository-aliases.json': b'{"baseline":"baseline-A"}\n',
                          'TEST-repository-aliases.json.sig': sig(22), 'TEST-pacman.conf': b'[options]\nSigLevel = Required\n'})
        for label in a.LABELS:
            repo_files['TEST-repositories/' + label + '/integration.db.tar.gz'] = b'public database ' + label.encode()
            if label != 'missing-database-signature-B':
                repo_files['TEST-repositories/' + label + '/integration.db.tar.gz.sig'] = sig(22)
        self.cases = [{'name': 'trusted-baseline-full-install', 'result': 'PASS', 'expected_signature_rejection': False}]
        self.material(self.repository, self.evidence / 'work/repository-raw', repo_files,
                      {'purpose': 'TEST-ONLY-offline-repository-case-verification', 'cases': self.cases,
                       'expected_negative_cases_retained': True})
        contract = {'schema_version': 1, 'purpose': 'disposable-generic-repository-test',
                    'execution': 'native-aarch64-disposable-docker', 'allow_system_mutation': True,
                    'source_commit': self.commit, 'image_id': self.image, 'nonce': 'd' * 32,
                    'daemon_arch': 'aarch64', 'script_sha256': a.digest(self.root / 'scripts/integration/repository.py'),
                    'upgrade_kind': 'synthetic-changed-package-fixtures', **self.rows}
        self.put_json(self.evidence / 'work/repository-inputs/manifest.json', contract)
        self.put_json(self.evidence / 'work/repository-raw/result.json', {'schema_version': 1, 'status': 'PASS',
                      'purpose': 'disposable-generic-repository-test', 'source_commit': self.commit,
                      'input_contract': {k: contract[k] for k in ('nonce', 'image_id', 'daemon_arch', 'script_sha256', 'upgrade_kind')},
                      'test_private_state_removed': True, 'hardware_validation': 'NOT RUN', 'stable_promotion': 'NOT RUN',
                      'published': False, 'cases': self.cases, 'evidence_sha256': {n: sha(d) for n, d in repo_files.items()}})

    def put(self, path, data):
        path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)

    def put_json(self, path, value):
        self.put(path, (json.dumps(value, sort_keys=True) + '\n').encode())

    def data(self, name):
        return (self.evidence / name).read_bytes()

    def mutate(self, path, action):
        value = a.read_json(path); action(value); self.put_json(path, value)

    def material(self, directory, source, files, metadata):
        for name, data in files.items():
            self.put(directory / name, data); self.put(source / name, data)
        self.put_json(directory / 'public-artifact-manifest.json', {'development_only': True, 'selected_for_release': False,
                      'production_credentials_used': False, 'source_commit': self.commit,
                      'files': {n: {'sha256': sha(d), 'bytes': len(d)} for n, d in files.items()}, **metadata})

    def receive(self, directory):
        return a.receive(self.root, self.evidence, directory)

    def test_exact_three_producers_public_packet_and_ed25519_signatures_pass(self):
        for directory in (self.fixture, self.signer, self.repository):
            result = self.receive(directory)
            self.assertTrue(result['opaque_approved']); self.assertTrue(result['approved_paths'])
        result = self.receive(self.repository)
        self.assertIn('TEST-pacman.conf', result['text_approved'])
        self.assertNotIn('TEST-pacman.conf', result['opaque_approved'])
        self.assertEqual(len(self.receive(self.signer)['opaque_approved']), 9)
        self.assertEqual(len(self.receive(self.fixture)['opaque_approved']), 4)

    def test_retained_actual_fixture_origin_and_full_bytes_match_frozen_authority(self):
        real_root = HERE.parents[2]
        # These are producer-generated retained public records, never rewritten
        # to make recipe-origin and workflow commits equal.
        shutil.copyfile(real_root / 'scripts/ci/integration.lock.json', self.root / 'scripts/ci/integration.lock.json')
        self.put(self.evidence / 'work/fixtures/fixture-manifest.json', ACTUAL_FIXTURE_MANIFEST)
        self.put(self.evidence / 'work/fixtures-raw/archives.json', ACTUAL_ARCHIVES)
        observed = a.fixture_rows(self.root, self.evidence, self.commit, a.public_policy(self.root))
        self.assertEqual(set(observed), {'baseline', 'upgrade'})
        generated = a.read_json(self.evidence / 'work/fixtures/fixture-manifest.json')
        self.assertEqual(generated['source_commit'], self.recipe_commit)
        self.assertNotEqual(generated['source_commit'], self.commit)
        baseline = {r['name']: r['version'] for r in observed['baseline']}
        self.assertEqual(baseline['cachy-asahi-setup'], '0.1.0-2')
        self.assertEqual(baseline['cachy-asahi-fish-config'], '0.1.0-1')

    def test_generated_manifest_bytes_epoch_generator_and_recipe_drift_refused(self):
        path = self.evidence / 'work/fixtures/fixture-manifest.json'; original = path.read_bytes()
        for key, value in (('source_commit', self.commit), ('source_date_epoch', 1),
                           ('generator_sha256', '0' * 64), ('frozen_lock_sha256', '0' * 64)):
            self.mutate(path, lambda x: x.update({key: value}))
            with self.assertRaises(ValueError): self.receive(self.fixture)
            self.put(path, original)
        path.chmod(0o600)
        with self.assertRaises(ValueError): self.receive(self.fixture)
        path.chmod(0o644)
        recipe = self.root / a.RECIPES['cachy-asahi-setup'] / 'PKGBUILD'
        recipe.write_bytes(recipe.read_bytes() + b'\n# changed\n')
        with self.assertRaises(ValueError): self.receive(self.fixture)

    def test_wrong_directory_and_extra_private_empty_directory_refused(self):
        with self.assertRaises(ValueError):
            self.receive(self.evidence / 'public/unknown')
        (self.fixture / '.gnupg').mkdir()
        with self.assertRaises(ValueError):
            self.receive(self.fixture)

    def test_missing_extra_hash_byte_and_hardlink_drift_refused(self):
        path = next(p for p in self.fixture.iterdir() if p.name.endswith('.xz')); original = path.read_bytes()
        path.write_bytes(b'wrong')
        with self.assertRaises(ValueError): self.receive(self.fixture)
        path.write_bytes(original); (self.fixture / 'extra.bin').write_bytes(b'extra')
        with self.assertRaises(ValueError): self.receive(self.fixture)
        (self.fixture / 'extra.bin').unlink(); path.unlink()
        with self.assertRaises(OSError): self.receive(self.fixture)
        path.write_bytes(original); os.link(path, self.base / 'linked')
        with self.assertRaises(ValueError): self.receive(self.fixture)

    def test_fixture_wrong_version_role_and_signing_claim_refused(self):
        path = self.evidence / 'work/fixtures-raw/archives.json'
        original = a.read_json(path)
        for mutation in (lambda x: x['upgrade'][0].update(version='0.1.0-1'),
                         lambda x: x['upgrade'][0].update(archive=x['baseline'][0]['archive']),
                         lambda x: x['upgrade'][0].update(role='original')):
            value = copy.deepcopy(original); mutation(value); self.put_json(path, value)
            with self.assertRaises(ValueError): self.receive(self.fixture)
        self.put_json(path, original)
        self.mutate(self.fixture / 'archive-manifest.json', lambda x: x.update(production_signing='PASS'))
        with self.assertRaises(ValueError): self.receive(self.fixture)

    def test_signer_wrong_certificate_signature_archive_and_fingerprint_bindings_refused(self):
        path = self.evidence / 'work/signer-raw/test-signature-receipt.json'; original = a.read_json(path)
        for mutate in (lambda x: x.update(public_certificate_sha256='0' * 64),
                       lambda x: x['signatures'][next(iter(x['signatures']))].update(archive_sha256='0' * 64),
                       lambda x: x['signatures'][next(iter(x['signatures']))].update(signature_sha256='0' * 64),
                       lambda x: x.update(fingerprint='E' * 40)):
            value = copy.deepcopy(original); mutate(value); self.put_json(path, value)
            with self.assertRaises(ValueError): self.receive(self.signer)

    def test_private_certificate_is_refused_even_when_all_hashes_updated(self):
        data = b'-----BEGIN PGP PRIVATE KEY BLOCK-----\nprivate\n'
        for path in (self.signer / 'public-key.asc', self.evidence / 'work/test-signatures/public/public-key.asc'): self.put(path, data)
        self.mutate(self.evidence / 'work/signer-raw/test-signature-receipt.json', lambda x: x.update(public_certificate_sha256=sha(data)))
        self.mutate(self.signer / 'public-artifact-manifest.json', lambda x: x['files'].update({'public-key.asc': {'sha256': sha(data), 'bytes': len(data)}}))
        with self.assertRaises(ValueError): self.receive(self.signer)

    def test_signature_private_packet_partial_trailing_and_bad_mpi_refused(self):
        policy = a.public_policy(self.root)
        for data in (b'\xc5\x01x', b'\xc2\xe0' + sig(), sig() + sig(), sig()[:-1], b'PRIVATE KEY'):
            with self.assertRaises(ValueError): a.signature(data, policy)
        a.signature(sig(), policy); a.signature(sig(22), policy)

    def test_repository_wrong_nonce_script_source_or_cleanup_refused(self):
        path = self.evidence / 'work/repository-raw/result.json'; original = a.read_json(path)
        for mutation in (lambda x: x['input_contract'].update(nonce='e' * 32),
                         lambda x: x['input_contract'].update(script_sha256='0' * 64),
                         lambda x: x.update(source_commit='e' * 40), lambda x: x.update(test_private_state_removed=False)):
            value = copy.deepcopy(original); mutation(value); self.put_json(path, value)
            with self.assertRaises(ValueError): self.receive(self.repository)

    def test_repository_export_exact_whitelist_wrong_label_and_credential_conf_refused(self):
        self.put(self.repository / 'TEST-repositories/foreign/integration.db.tar.gz', b'unknown')
        with self.assertRaises(ValueError): self.receive(self.repository)
        shutil.rmtree(self.repository / 'TEST-repositories/foreign')
        data = b'password=fixture-private\n'
        self.put(self.repository / 'TEST-pacman.conf', data); self.put(self.evidence / 'work/repository-raw/TEST-pacman.conf', data)
        self.mutate(self.evidence / 'work/repository-raw/result.json', lambda x: x['evidence_sha256'].update({'TEST-pacman.conf': sha(data)}))
        self.mutate(self.repository / 'public-artifact-manifest.json', lambda x: x['files'].update({'TEST-pacman.conf': {'sha256': sha(data), 'bytes': len(data)}}))
        with self.assertRaises(ValueError): self.receive(self.repository)

    def test_source_commit_producer_failure_duplicate_json_and_symlink_refused(self):
        path = self.evidence / 'result.json'; original = path.read_bytes()
        self.mutate(path, lambda x: x.update(source_commit='e' * 40))
        with self.assertRaises(ValueError): self.receive(self.fixture)
        self.put(path, original); self.mutate(path, lambda x: x['stages']['fixtures'].update(status='FAIL'))
        with self.assertRaises(ValueError): self.receive(self.fixture)
        self.put(path, b'{"source_commit":"x","source_commit":"x"}')
        with self.assertRaises(ValueError): self.receive(self.fixture)
        self.put(path, original); target = self.fixture / 'archive-manifest.json'; target.rename(self.base / 'actual')
        target.symlink_to(self.base / 'actual')
        with self.assertRaises(ValueError): self.receive(self.fixture)


if __name__ == '__main__': unittest.main()

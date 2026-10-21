# Native Core fixed-BTF build pairs

Native ARM run [39589633375](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/39589633375) used source `eee19066ce9f90d1cd902815072c0b4ae2dfc9c9`, ref `codex/target-core262-btf-input-root-v1`, first attempt. All four build cells succeeded. Once-collected originals and the complete original strict reader passed; Root accepted this finite build component.

All seven archive pairs match exactly, including installed contents, PKGINFO and BUILDINFO. Each systemd build recorded 1,930 OK, 32 unchanged upstream SKIP, 0 FAIL. The effective 262-1.2 recipe retains explicit private scratch and a child-only user namespace; original assertions and the complete selected test plan remain required.

| Package | Archive bytes | SHA256 of each build |
| --- | ---: | --- |
| pacman | 909196 | `66d52fbcec4b520eafae960578a6d2116782d37c83014b0a363768a230f2a59f` |
| systemd | 9658964 | `45cab17c4a866bd132dc1389b9c6a2e74d44d46f9813100aa8ca6a9d3378e43f` |
| systemd-libs | 1283492 | `8b9bb613c2d6e5a96ff6ea210822f9882692389897b1f071b44593327d795b44` |
| systemd-resolvconf | 6640 | `69d04a69afc0b439bc88564c016265fc4d7868a38d6abfa0244981cd83e7caca` |
| systemd-sysvcompat | 9936 | `af008505692a613aeae5b8bba3ed1364d177637bde11e0cb9ab68c2b9c285824` |
| systemd-tests | 6263532 | `854c2789b5bc254c73ef79dabbc9db5280d787f54cc0ac7b253a493707e5052a` |
| systemd-ukify | 42760 | `d9f9f16b27f392ec29de3cb7d4714c2272ce0b3c4e7d40475e9eeba60f1fbe68` |

Previous run 39580569812 exposed four unequal ELF files because automatic BPF header generation depended on the host kernel. Both corrected builds used the same 8,430,525-byte pinned BTF input and produced the same 4,582,286-byte complete header, SHA256 `541017e1f57d3db3a9a7759a8b96e140be240b36160892fe1e813a78044dcdf1`. Kernel source/license/provenance and bpftool identity are retained. Makepkg preparation uses the ordinary source directory; extracted input symlinks remain refused.

This proves native AArch64 build pairs and structural 16K ELF checks only. Installation, runtime ABI, Asahi boot/platform integration, both physical M2 Air sizes and performance remain NOT RUN. The older selected 261 target provenance is unchanged and unaccepted. No release is admitted. Four distinct CI cells do not attest physical-machine independence.

Retained local decision: `artifacts/development/target-core262-btf-input-root-native-actual-20261021/Root-component-acceptance.json`, with the complete positive result, source authorization and original run/job/artifact identities beside it.

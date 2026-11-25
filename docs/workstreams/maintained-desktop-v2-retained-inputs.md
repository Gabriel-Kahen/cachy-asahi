# Maintained desktop v2 retained package inputs

[Run 45715540986](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/45715540986)
ran Source `142838491186d1e2cff9f66d01a5cdd7a27ece32` with Data
`f5e158c627616966d2486811e59e977aa95882c0`. The launcher returned controller
exit 1. Initial acquisition passed 295 of 501 objects and reported HTTP 404 for
206, exactly 103 package/signature pairs. Bubblewrap accounted for one pair.
Signature authentication, native builds, virtual acquisition, QEMU, guest
terminal/reader/frame evidence and later consumers stayed `NOT RUN`. The
handoff reported cleanup `PASS` for its owned resources. M2 remains
`NOT RUN`.

The approved private SSH profiles cover the 206 failed objects and 210 of the
496 locked package/signature objects. The successor uses the complete
credential-free carrier `refs/heads/codex/native574-complete-retained-inputs-v1`
at `4659076d3a1d3e5cf87c185a3ff383fbc38e734d`, tree
`e21f947bac3afdfbd67e4e65c8234b35ae42b00f`. The historical carrier commit
`ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad` has the same tree. The carrier index
SHA-256 is `51a53c9e0d9eab1728f350f9ab8d3d7b8932891ab0ed68c7876a1440166ff486`.
The retained input lock is byte-identical to the Source input lock
`beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f`.

The new workflow requires its dedicated Root registration, exact push ref,
matching Source and workflow SHAs, and the Source packet, input lock and
receiver hashes before carrier work. The receiver verifies the approved Git
bytes, uses hash-pinned Git DATA transport and child supervision, and compares
the advertised ref with the fixed carrier commit. It verifies the full carrier
tree and profile and stages only the exact 496 package/signature files, totaling
702,251,555 bytes. No SSH or retained-package credential is supplied in this
workflow. Carrier contents are treated as DATA.

The controller consumes the same-run staging directory after bootstrap and
packet validation, before constructing the original actor. It requires fresh
cache custody, exact membership, stable named and open file identity, and the
locked sizes and hashes. Original acquisition processes all 501 inputs,
including the rootfs, its signature and the three keyring objects. The original
GPG verification follows. The workflow retires its own staging paths after
launcher return. The original actor's clock and process cleanup remain under
the pinned launcher. The additional workflow time covers carrier preparation.

On seed failure, the controller rolls back only journaled files whose identity
still matches. It removes the cache directory only after checked emptiness
and records `HOLD / UNCERTAIN` if removal, identity or descriptor retirement
cannot be verified. Controller output creation follows a successful seed.
SIGTERM and SIGINT during carrier preparation are latched and handled inside
the retained transport's owned child wait. The guard stays active through
launcher delivery, and the pinned launcher takes over its own signal handling
during execution. The receiver restores the caller's handlers after retirement.
The receiver retires transport scratch against its held identity on every
exit path. If scratch custody changes, parent retirement stops, both names
are preserved, and the workflow reports `HOLD / UNCERTAIN`. After retiring
the checked package directory, the receiver removes the stage nonrecursively
so any late entry blocks removal. Staging cleanup
`PASS` requires verified child retirement, path absence and closed directory
descriptors. A forced SIGKILL can prevent a terminal receipt and leaves cleanup
uncertain.

Source and Data require independent review and new Root registration before any
hosted run. Local carrier and cache checks establish only DATA preparation.
Hosted execution, signature verification, guest verification and hardware
acceptance for this successor remain `NOT RUN`.

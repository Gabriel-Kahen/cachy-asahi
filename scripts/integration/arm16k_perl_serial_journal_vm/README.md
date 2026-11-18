# Initialized Perl ARM16K serial, journal and retention Source successor

This source-only constructor reuses the tracked, initialized Source339
reconstruction. It ports three host changes from the later Perl ARM16K
lifecycle onto that earlier source series.

- The login reader passes one complete nonce-bound frame with the exact session
  fields to the existing parser. It projects out only complete, allowlisted
  diagnostic records with their own leading blank. It retains the original
  transcript and the existing Perl phase rules.
- The disposable boot puts a 64 MiB tmpfs over `/var/log/journal`. After the
  original filesystem preservation checks, the actor compares the original
  journal tree. Only `atime` and `atime_ns` of the exact mountpoint directory
  are omitted. All descendant rows, contents and directory membership are exact.
- The initialized guest writes `before.cache` and `after.cache`. Export and
  host verification require the exact modern receipt names and matching
  snapshot size and SHA256. The embedded legacy runtime retains its
  saved/absent scratch receipts.

The constructor authenticates Source339's complete bytes and modes and changes
only `actor.py`, `protocol.py`, `retention.py` and the relevant existing
fixtures, then reseals the output. The output has 339 files, 3,517,150 total
bytes, and a 60,211-byte
Source lock with SHA256
`b294b396c747195c14e7328b7ef3444a0f3249aaf2ef289c5edf943660c290d1`.
The generated actor and controller remain subject to their existing separate
Source, case and Root authority gates. The older initialized guest contract,
frozen Source339 operands, and maintained cold Perl runtime stay intact.

Construct a fresh ordinary sibling using the tracked Git history, or supply an
already reconstructed exact Source339 with `--predecessor`.

```bash
python3 -I -B scripts/integration/arm16k_perl_serial_journal_vm/constructor.py --output /absolute/fresh/source
python3 -I -B -Werror::ResourceWarning scripts/integration/arm16k_perl_serial_journal_vm/test_controls.py
```

The new executable runs source construction only. The existing
`perl-observed-hold-source339.yml` workflow continues testing the frozen
predecessor. The local controls exercise synthetic login, QEMU arguments,
readback metadata, initialized and legacy retained-output contracts, and exact source sealing. Runtime evidence belongs to the
exact separately issued Source that produced it. This derived Source has
no recorded VM or ALPM result.

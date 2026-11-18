# Initialized Perl ARM16K serial and journal Source successor

This source-only constructor reuses the tracked, initialized Source339
reconstruction. It ports two host changes from the later Perl ARM16K
lifecycle onto that earlier source series.

- The login reader passes one complete nonce-bound frame with the exact session
  fields to the existing parser. It projects out only complete, allowlisted
  diagnostic records with their own leading blank. It retains the original
  transcript and the existing Perl phase rules.
- The disposable boot puts a 64 MiB tmpfs over `/var/log/journal`. After the
  original filesystem preservation checks, the actor compares the original
  journal tree. Only `atime` and `atime_ns` of the exact mountpoint directory
  are omitted. All descendant rows, contents and directory membership are exact.

The constructor authenticates Source339's complete bytes and modes and changes
only `actor.py`, `protocol.py`, and the existing journey test, then reseals
the output. The output has 339 files, 3,515,645 total bytes, and a 60,211-byte
Source lock with SHA256
`10dfe1c1534880f524aac6d1fa6f37e732671c5a51d7bdc8d7c085be4cf5198a`.
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
readback metadata and exact source sealing. Runtime evidence belongs to the
exact separately issued Source that produced it. This derived Source has
no recorded VM or ALPM result.

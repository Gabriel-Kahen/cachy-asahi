# Maintained caa3 first 16K packet

This passive assembler turns the retained native run38994309021 into the first staged16K inputs. It requires explicit accepted native-pair and compiled-probe decisions for the exact current candidate, source, original artifact and retention digest. It verifies all233 retained records, both package archives, reproduced probes, both13-command compilation receipts, measured complete payload, source authority and held rollback package before publishing a fresh output directory. Sixteen pinned pure validators preserve the original package and compiler checks. No collected executable source, package installation, signing, network, container or VM actor runs.

```sh
python3 -I -B scripts/ci/glibc-debian-maintained-staged-packet/prepare.py \
  --repo "$PWD" --collection ORIGINAL_COLLECTION_DIRECTORY \
  --pair-decision ROOT_PAIR_DECISION --normal-decision ROOT_COMPILED_PROBE_DECISION \
  --authority scripts/ci/glibc-debian-maintained-provider/root-maintained-source-authority.json \
  --held /absolute/path/glibc-2.43+r22+g8362e8ce10b2-2-aarch64.pkg.tar.xz \
  --output FRESH_PACKET_DIRECTORY
```

The actual accepted packet is22files/47425868bytes including packet.json, frozen at132aec86c0946f6c7b7a79c46e1a9ccaf91021e3. It supplies the distinct maintained-system16K lane. Normal clients are compiled inputs; execution,16K and ALPM installation require their own actual results. A prior16K receipt is deliberately excluded from this first-stage packet. Historical GNU/caa2 runtime or source credit cannot substitute. Limits remain256files/512MiB overall, with complete original retained bytes and ordinary single-link input files. Missing/old decisions, changed sources, malformed references, aliases and truncated selected proofs refuse.

Seven portable controls run with `python3 -I -B -Werror::ResourceWarning scripts/ci/glibc-debian-maintained-staged-packet/test_prepare.py`. Synthetic controls provide no native acceptance. The real retained packet also passes complete assembly and byte comparison against the frozen packet. Source/native acceptance and current signed-metadata expiry are recorded in docs/validation/glibc-debian-maintained-source-20261017.md. No hardware, performance, source-security currency or supported-release admission follows from packet creation.

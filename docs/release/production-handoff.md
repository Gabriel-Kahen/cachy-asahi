# Production signing and repository handoff

The coordinator owns the release decision and assigns the signing and hosting
operators. Use the [acceptance matrix](../acceptance.md) for release gates and
the [signing policy](recovery.md) for custody and incidents.

## Inputs for the handoff

| Owner | Required input |
| --- | --- |
| Coordinator and platform owners | An approved Asahi base, the exact predecessor and successor package sets, and the target install, update and recovery receipts for the supported M2 Air sizes. |
| Release reviewer | The frozen source revision, archive/provenance and evidence hashes, distribution review, retained base inputs, and review of which files can be shared publicly. |
| Primary and alternate signing custodians | Named custody and recovery coverage, an independently authenticated public primary certificate, authorized signing-subkey fingerprint and validity, and a private backup/revocation exercise. |
| Hosting and release operators | An approved HTTPS hostname and route, capacity for the retention policy, a way to exclude withdrawn generations from serving, and an authenticated channel for release, signer and withdrawal announcements. |

## Private signing and verification

1. Review and freeze the package archive, source, spec, base inventory and
   evidence hashes before signing. Use the [release interface](interface.md)
   to stage the exact candidate and prepare its promotion gates.
2. Keep the primary secret in offline custody. Provision the controlled signer
   home with only the authorized bound signing subkey. Pass the full **primary**
   fingerprint as `--key` for the release and export commands and as
   `--signer` for the recipient. Record the primary and actual signing-subkey
   fingerprints from GnuPG's verification status alongside the signed artifact
   hashes. The manifest and endpoint use the pinned primary identity.
3. Reverify the staging bundle from a separate public-only GPG home. Review the
   actual signed package, database and release bytes. Promote only after the
   exact stable gates pass. Use [exporter v2](../repository-endpoint.md) to
   materialize the complete generation, then verify it from an independent
   copy with the [endpoint recipient](endpoint-client.md). For a retained
   recovery generation, use the recovery recipient v2 and retain its signed
   recovery authorization with that copy.

## Hosting and withdrawal

1. Keep the complete verified generation available to authorized reviewers.
   Review the exact bytes to be served. Publish packages through the immutable
   HTTPS path ending in `/generations/<generation-digest>/release/repo`, as
   required by [enrollment](../repository-enrollment.md). Give the serving
   process access to the approved copy. Keep signing homes, workspaces and
   private evidence outside the served paths. The complete endpoint recipient
   requires the full verified generation, including its evidence. If evidence
   stays private, use the private copy for that check.
2. In a private hosting rehearsal, use a fresh recipient to retrieve the exact
   approved generation paths. Check the database and file-list names, all
   aliases and detached signatures, and every package/signature pair against
   the reviewed bytes. Check that private paths are inaccessible. Before
   announcing a public URL, repeat the checks against the selected host and
   verify effective required package and database signatures on the clients.
   Pacman uses its global trust store. Use the independent generation check to
   bind the advertised bytes to the project signer.
3. Convey the exact generation, release, signer and public certificate through
   the approved authenticated channel. Keep previous authorized generations
   available according to the retention policy. Rehearse changing the pinned
   generation in enrollment and distributing fresh trust and incident notices.
4. For a withdrawal, retain the signed incident and the restricted forensic
   copy. Quarantine unsafe repository bytes at their existing hosted paths,
   invalidate affected caches, and verify the result from a fresh recipient.
   Clients enrolled against an immutable URL keep that URL when the local
   `current` pointer changes. Check the old URL directly and distribute the
   advisory through the trusted channel. Use the [retained recovery
   contract](retained-selection-recovery.md) when the current generation is
   intact and the predecessor is compatible. After a withdrawal-only
   selection, advance through a reviewed compatible replacement.

## Local readiness on November 25, 2026

On source `ea225d8e9b0aee46ae2b93aca022b5a94b6d0956`, six retained
digests matched the [B08/B09 record](../validation/b08-b09-signed-staging-20261125.md).
Both five-package Preview staging bundles, the signed withdrawal, the offline
rehearsal's predecessor, and its signed recovery and withdrawal receipts
verified from new public-only GPG homes. The recorded Preview comparison
reproduced byte for byte. The withdrawn successor refused active verification
and its endpoint had a null package route.

A fresh disposable TEST ceremony signed a package, both repository databases,
the release manifest and a withdrawal with a signing subkey while the primary
secret was absent from the signer home. A public-only verifier authenticated
the bound subkey using the pinned primary. An isolated HTTPS listener on
loopback served 18 retained TEST staging repository names byte for byte,
including four aliases. Four private or mutable path probes returned 404.
The staging manifest digest served as a placeholder in the test route.
Production custody, host selection, public trust and both physical target
receipts remain open.

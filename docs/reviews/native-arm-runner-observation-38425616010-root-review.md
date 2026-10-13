# Fresh hosted ARM runner observation: retained Root peer review

PASS for independently checked retained read-only observation of run38425616010, job115394120698. This review authenticated Root completion SHA256 `9eccf2cdd2ce32b119d81021d0b36d5f94cae6d7ad7015075bd55364c348e473` (947 bytes,0644), all four indexed leaves, the completed successful run/job/three steps, the unique actual log report and its canonical retained JSON. No observer, tool, Git, network, daemon or native actor was replayed here.

The actual report is log line298 at `2026-10-13T15:51:34.6694567Z`, after the echoed observer body. Actual job Source and Workflow Source both equal `be33bb5d9ae6a2bd725e76506afea12b18d28f2d`, matching run `headSha`. Repository, run/attempt and Ubuntu image metadata agree. The retained run JSON does not export an event field, and the observer does not record it; this review makes no push/manual-event claim.

The echoed observer is byte-identical to the earlier38347013591 probe and current project helper: SHA256 `ad6d7908ef1dca36356cc5c8450f655c323021ec1ab89b4569708d4297989b4b`,11740 bytes. The workflow remains SHA256 `8413190ba16aa817414828fd86080a44536e8896bd2a0c211471cb9fb202093d`,15057 bytes, with identical inline body. Prior peer receipt `13c3c0c1…` and its six retained leaves were authenticated; the earlier committed-source proof's two bodies match these exact project bytes. Source was only AST-parsed here. This binds retained body and metadata evidence; it is not a fresh Git/blob query for commit be33.

| Observed item | Retained result |
| --- | --- |
| Host | aarch64, page size4096, UID1001 |
| Git | `/usr/bin/git`,4460200 bytes, SHA256 `4cda0087547ee12bef91952e1123debb4bd2ec621838b347b5ca4fdaa6fecb58` |
| Docker CLI | `/usr/bin/docker`,41651784 bytes, SHA256 `94128e4afada0d46de642165e79dd70beb08e6775014648013283ed901b68248` |
| Python | `/usr/bin/python3` link to `python3.12`; target7845048 bytes, SHA256 `c86f21d0da9290ece2d7d49a3f7ed52aed59cb029abdf0ea25c79634f6cbe960` |
| Socket | `/run/docker.sock`, UID0/GID118,0660; stat only, not connected |
| Workspace | Original and temporary directories disjoint; observed owner/ancestor/sibling-parent prerequisites pass; no sibling created |

Git, Docker and Python target rows report root ownership,0755, one link and stable named/open-FD observation. These are prior-job observations, not custody of the later composed job. Socket observation establishes recorded metadata and source-gated socket type, not daemon identity, trust, availability or private-runner isolation. Workspace ancestry establishes observed prerequisites; it is not proof that a later reservation succeeds or foreign replacement cannot occur.

The initial Root retention setup diagnostic remains authenticated and copied unchanged: GitHub's timestamp and JSON occupy the same last tab field, while the first parser expected JSON at that field's start. Independent decoding separates the timestamp, strips echoed colour framing, distinguishes source echo from report, requires one actual report and reconstructs exact canonical bytes. Raw Root log remains unchanged and hashed; the parser error was not treated as a failed hosted probe.

Three new pure negative controls refuse a foreign Workflow Source, integer1 masquerading as custody `True`, and a duplicate actual report. The previous13 controls and host binary hashing were not rerun. Project-owned TMPDIR and `-I -B` were used; the normal namespace was needed because sandbox mount initialization had previously failed with `/tmp` ENOSPC. No foreign cleanup, primary/shared workflow, manifest or Git change occurred.

Root may use these current observations to select explicit tool pins. The actual composed job must freshly rehash binaries, verify their real named/FD custody and endpoint/environment, retain its existing clock/grant and source checks, and record actual execution and disposal. This probe issued no execution clock or grant and ran no Git/Docker commands, project checkout or native builds. It grants no composed authority. Its4K page size does not establish16K compatibility; M2, installation/removal, recovery, performance and full R1–R5 acceptance remain open.

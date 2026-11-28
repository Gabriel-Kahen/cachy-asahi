# Repository handoff source identities

The original 159-file source closure and its integration lock are selected from
`bcf0cee981ee4b7f7b082f636922c859dc7e0abc`. The lock SHA-256 is
`d4d603146f094c86242eaafbb887042959c510c9bb948579dd749d065dd8fc31`.
The matching historical collector, phase map, and authority callback belong to
that source family. Its phase map SHA-256 is
`5718ca6cda60d7f6c02952cba7e92ff46666e20f8252ce7c1cdf722825ec2e43`.
Original-view tests authenticate these bytes before exercising the copied view.

The live phase tests select the checkout's phase map and its declared
dependencies in a separate root. At the time of the split, the phase map
SHA-256 is `e320a92f166303c3e6fcbbad00af2b7fe998666c9e9d7d2ea571dcfc01311932`.
Both families require `scripts/release/release.py` at the same relative path.
The original closure requires
`418c850e8a44ae71517e074f86f46f5999f5fe7433ca6798de945f318191a918`;
the live phase requires
`afd2bed6775d435e0a9a4dca62d162b5b32800d9d07dbb2cfc9642ddbcf14e6f`.
A single captured root cannot satisfy both pins.

The original-view graph exercises
registration with the checkout's mapped launcher modules, while the live phase
test authenticates and loads the checkout dependencies separately. Both
controls run without actors. The native ARM development workflow fetches the
exact fixture commit at depth one before its unit tests. The checkout stays
at the current commit and the tests verify the historical lock and all 159
file hashes and modes. The same fetch works in a local shallow checkout.

The add-on scan uses the selected fixture root with the checkout's add-on
bytes. On the current full checkout the historical scanner refuses the Qt
source-reference license symlinks before it can produce the source inventory.

## Proposed production-loader change

Combined runtime admission remains on hold. A successor packet and per-run
grant should bind two disjoint inputs. Keep the live source rows, callbacks,
and maps under the checkout root. Give the historical input its own private
read-only root, bound to the full historical commit, integration-lock SHA-256,
and original row-set digest. Supply that input independently from a reviewed
source snapshot.

Teach `packet.preflight_composed` and `repository_handoff.preflight` to validate
each root against its own manifest. Capture the historical lock and its 159
rows using the existing no-follow, mode, digest, and inode checks. Keep
`dependency_entry` on the live root. Have `Session.prepare_view`, `verify_view`,
and `view_plan` use the historical capture for the private 160-file copy, its
custody receipt, and the original invocation pins. The receipt should bind
both source roots and preserve the historical source and copy inode records.

The live launcher also pins a different `scripts/integration/repository.py`.
The successor launcher should bind the original lock to the historical runner
SHA-256 `49c87f41bbb2fe1288251f16019f12aaeabb98d81ff5339387873e88e903b940`.
Qualify the new packet, grant, and launcher together in a source-only run
that opens both roots and refuses swapped roots, either release substitution,
runner mismatch, and drift before any actor allocation.

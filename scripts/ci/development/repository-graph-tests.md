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
controls run without actors. Combined runtime admission remains on hold
because its loader requires both pins under one root. The tests need the
selected historical Git commit in the local object database. A shallow
checkout must supply that commit before running the tests.

The add-on scan uses the selected fixture root with the checkout's add-on
bytes. On the current full checkout the historical scanner refuses the Qt
source-reference license symlinks before it can produce the source inventory.

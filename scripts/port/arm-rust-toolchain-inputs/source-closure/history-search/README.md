# Bounded original recipe history search

All four required PKGBUILD hashes remain unresolved. The preserved starting
ALARM recipes and the additional exact-version Arch recipes do not match their
package BUILDINFO hashes. Original reports were not changed.

The three ALARM recipe bodies independently match the Git blob IDs in their
fixed-revision directory listings. Finite build-window histories expose no
additional same-version candidate. The official Rust Source Files and View
Changes endpoints both returned HTTP 500. These observations do not exclude
private, removed or locally modified recipes.

Official devtools v1.5.0 and pinned PlugBuild UI sources were inspected as data.
No supported transformation linking the four raw recipes to the required hashes
was found. The UI forwards commands to another builder. Devtools has explicit
version/release/checksum editing helpers; their presence does not prove use for
these packages. No recipe reconstruction was accepted or performed.

`requests.json` records all 30 sequential HTTP requests and 171,575 response
body bytes, within the 64-request/8 MiB task budget and 2 MiB response cap.
`results.json` records exact candidates, primary code revisions, hashes and limits.
No recipe evaluation, extraction, compilation, installation, native dispatch,
signature authentication or original-evidence mutation occurred.

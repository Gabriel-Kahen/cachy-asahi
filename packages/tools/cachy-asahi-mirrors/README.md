# cachy-asahi mirrors

Original MIT development candidate for the roadmap's ARM mirror-checking
replacement. `check` validates a local catalog. `rank` explicitly downloads each
mirror's repository database, requires exact bytes from the selected snapshot,
and writes a separate0600 candidate ordered by measured request duration.
It never changes pacman configuration or activates a mirror list.

```sh
cachy-asahi-mirrors check catalog.json
cachy-asahi-mirrors rank catalog.json --output ./core-mirrors.candidate
```

The caller supplies a catalog from its independently verified release/base
snapshot. This tool does not establish that catalog's trust, validate a new
release signature, authorize repository changes or refresh stale snapshot pins.
An example shape follows; example servers and hash are placeholders and cannot
be used as a working catalog:

```json
{
  "schema_version": 1,
  "architecture": "aarch64",
  "base": "asahi-alarm",
  "repository": "core",
  "database": {"bytes": 100, "sha256": "REPLACE_WITH_VERIFIED_DATABASE_SHA256"},
  "mirrors": [
    {"id": "selected", "server": "https://mirror.example/$arch/$repo"}
  ]
}
```

Only HTTPS templates with complete `$arch` and `$repo` path segments are
accepted. Credentials, query strings, fragments, redirects, encoded responses,
duplicate mirrors and non-ARM catalogs fail. Requests use certificate-verified
Python HTTPS and bypass environment proxies. The catalog has at most16 mirrors;
each exact database is at most32MiB. Socket waits are at most10 seconds and the
whole sequential sample has a120-second deadline, with at most one final socket
wait beyond it. Failures remain in the JSON report. If no mirror matches, no
candidate is written. Output publication is atomic and never replaces an
existing file or symlink.

This is one request per mirror on the current network, not a sustained bandwidth
or hardware benchmark. Rankings can vary. Use the candidate only for the named
repository and reviewed compatible base; activation, backup and restoration of
live repository configuration remain separate work. No live mirror results,
native package build, installation, M2 behavior or release admission are claimed.
No `rate-mirrors` or CachyOS wrapper source is reused.

# cachy-asahi-dns 0.1.0-2

Preview and save selected DNS settings for one exact NetworkManager connection UUID, apply them explicitly, and restore the saved values if nobody has edited those fields since. This first candidate supports plain IPv4/IPv6 DNS addresses and each family's `ignore-auto-dns` flag. It never changes a resolver file, service, interface state, VPN credentials, routing, search domains or DNS priority.

Changes affect the **stored connection profile**. The tool does not activate/deactivate a connection or call `device reapply`. Live DNS effectiveness is not measured or claimed. Use the existing NetworkManager workflow to activate the stored profile when appropriate; target Wi-Fi/VPN, live reapplication and M2 tests remain open.

## Use

Run `cachy-asahi-dns profiles` to list stored connection UUIDs, types and human-readable display names, or `cachy-asahi-dns --json profiles` for structured output. Copy the exact UUID into preview; display names are not selectors and may repeat. Discovery is read-only and never saves profile names to a receipt. It makes exactly two fixed metadata queries (UUID/type, then UUID/type/name), each under the existing15-second/64KiB child limits, with at most64 profiles and1024UTF-8 bytes per name. Identity drift, duplicates, malformed escaping or ambiguous multiline names refuse the whole listing; use your connection editor for a multiline profile’s UUID. Colons/backslashes decode exactly, Unicode names stay readable, and terminal/control characters are escaped in human output. No passwords, full profile, resolver or device state is queried. Run every step as the same user. NetworkManager's existing permissions/PolicyKit apply; the tool never invokes sudo. If using an administrator account, create and operate its receipt under that account throughout.

```sh
cachy-asahi-dns preview --uuid 11111111-2222-4333-8444-555555555555 \
  --ipv4-dns 1.1.1.1,9.9.9.9 --ipv4-ignore-auto-dns yes \
  --state-dir "$PWD/dns-change"
```

Replace the sample UUID. Preview reads only the UUID and selected DNS fields twice, prints the prior/desired values, and creates a new private0700 state directory with a durable0600 receipt. It performs no NetworkManager write. Copy the receipt SHA256 printed by preview:

```sh
cachy-asahi-dns apply "$PWD/dns-change" \
  --receipt-sha256 EXACT_PREVIEW_SHA256 --confirm APPLY_CONNECTION_DNS
cachy-asahi-dns status "$PWD/dns-change"
```

Apply rechecks the owned fields before one profile modification, verifies readback and returns the new receipt SHA256. Add `--json` before the subcommand for structured output. To restore those exact saved fields, use the current SHA256 from apply/status:

```sh
cachy-asahi-dns undo "$PWD/dns-change" \
  --receipt-sha256 EXACT_CURRENT_SHA256 --confirm RESTORE_CONNECTION_DNS
```

`--ipv6-dns 2001:4860:4860::8888 --ipv6-ignore-auto-dns yes` selects the IPv6 subset. Omitted fields are untouched. An empty value (`--ipv4-dns ''`) clears that stored list; `--ipv4-ignore-auto-dns no` permits automatically supplied DNS according to the existing IP method. Neither command changes the IP method or invents a universal DHCP reset. Undo restores the actual prior values, including custom settings. Bare IP addresses only, at most eight per family; scoped addresses, resolver URLs, malformed or duplicate values refuse. Unsupported existing selected values also refuse.

## Preservation and failure behavior

Only four DNS properties are allowed. No full profile or `--show-secrets` query occurs; receipts contain no connection names or VPN authentication fields. Unselected settings remain outside tool ownership. Undo refuses an externally edited owned field and preserves it. Completed operations are repeatable without another modification when the saved state still matches. A fresh preview requires a fresh state directory; receipts are never silently overwritten.

The private receipt lock serializes this tool's operations. Other NetworkManager editors are not locked: two matching reads and before/after checks detect observed drift, but do not provide a global compare-and-swap transaction. Use without concurrent profile editing. Each nmcli child has a15-second caller ceiling,10-second requested wait and64KiB combined output cap; raw failure output is not printed or saved. No automatic mutation retry or guessed rollback occurs after failure/interruption/unknown readback. Prior values remain in receipt.json, and the phase remains APPLYING/UNDOING or becomes APPLY_UNKNOWN/UNDO_UNKNOWN. Inspect status and the saved values before administrator recovery; this candidate deliberately refuses automatic undo from uncertain phases. A receipt write failure after the profile changed is not a rollback.

Removing the package removes its owned program/docs/licenses, not user receipts or stored DNS settings. Run undo first if restoration is wanted. No package hooks, automatic DNS changes or background services exist.

## Source and validation

Original MIT project code; Python3.11+ and NetworkManager1.44+ are dependencies. Tests require nmcli's real offline mode and refuse to skip it. Local validation uses nmcli1.58.1-1 on x86_64; it runs synthetic keyfile apply→restore without a daemon and compares both families plus preserved unrelated settings. Memory-backed failure tests and bounded real child tests cover the receipt/undo workflow. No host connection was modified. Private-daemon stored-profile discovery is locally exercised as described below; production PolicyKit, native ARM0.1.0-2 package pairs, signed ALPM lifecycle, effective DNS behavior, Wi-Fi/VPN and M2 checks are NOT_RUN. Architecture=any is not ARM/hardware acceptance.

The official [nmcli manual](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html) documents explicit UUID selection, one-value-per-line queries, offline modification and live device reapplication. The [settings reference](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-settings-nmcli.html) defines the DNS and automatic-DNS flags. This tool uses only the stored-profile subset. No upstream implementation is bundled.

## Upgrade alternative and validation scope

This recipe lives in `packages/tools/cachy-asahi-dns2` and builds the same package/installed command as DNS1, version0.1.0-2. It is an upgrade alternative, not a coinstallable package; same-name ALPM ownership handles replacement. DNS1 recipe/source/accepted native packets stay unchanged. All preview/apply/status/undo transaction and receipt functions and nmcli caller bodies are held from0.1.0-1. Only explicit `profiles` adds metadata discovery.

27 focused tests include the original21 transaction/failure/offline nmcli controls and six discovery tests. Genuine local x86 private NetworkManager1.58.1-1 grammar/installed-stage discovery is exercised in a disposable network-none/cap-dropALL actor with a private system bus and only synthetic fixture names, no activation/reapply, resolver management or host NM access. Native ARM build pairs/ALPM lifecycle, production PolicyKit and live DNS/M2 are NOT_RUN for this version; prior DNS1 evidence is not transferred. No installed native0.1.0-2 claim is made.

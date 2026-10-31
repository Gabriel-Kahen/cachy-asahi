# cachy-asahi-dns 0.1.0-1

Preview and save selected DNS settings for one exact NetworkManager connection UUID, apply them explicitly, and restore the saved values if nobody has edited those fields since. This first candidate supports plain IPv4/IPv6 DNS addresses and each family's `ignore-auto-dns` flag. It never changes a resolver file, service, interface state, VPN credentials, routing, search domains or DNS priority.

Changes affect the **stored connection profile**. The tool does not activate/deactivate a connection or call `device reapply`. Live DNS effectiveness is not measured or claimed. Use the existing NetworkManager workflow to activate the stored profile when appropriate; target Wi-Fi/VPN, live reapplication and M2 tests remain open.

## Use

Find the desired UUID in your existing connection editor, or list UUIDs with `nmcli --get-values UUID connection show`. Run every step as the same user. NetworkManager's existing permissions/PolicyKit apply; the tool never invokes sudo. If using an administrator account, create and operate its receipt under that account throughout.

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

Original MIT project code; Python3.11+ and NetworkManager1.44+ are dependencies. Tests require nmcli's real offline mode and refuse to skip it. Local validation uses nmcli1.58.1-1 on x86_64; it runs synthetic keyfile apply→restore without a daemon and compares both families plus preserved unrelated settings. Memory-backed failure tests and bounded real child tests cover the receipt/undo workflow. No host connection was modified. A real NetworkManager daemon/PolicyKit connection transaction, native ARM package pair, signed ALPM lifecycle, effective DNS behavior, Wi-Fi/VPN and M2 checks are NOT_RUN. Architecture=any is not ARM/hardware acceptance.

The official [nmcli manual](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html) documents explicit UUID selection, one-value-per-line queries, offline modification and live device reapplication. The [settings reference](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nm-settings-nmcli.html) defines the DNS and automatic-DNS flags. This tool uses only the stored-profile subset. No upstream implementation is bundled.

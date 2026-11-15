# SPDX-License-Identifier: MIT
# All files are closed before syncfs; terminal publication is last.
durable_terminal() {
 [[ -d $D && ! -L $D ]] && receipt_file "$O/summary.env" || return 2
 [[ ! -e $D/final-summary.env && ! -L $D/final-summary.env && ! -e $D/durable-terminal && ! -L $D/durable-terminal ]] || return 2
 cp -- "$O/summary.env" "$D/final-summary.env" || return
 chmod 600 "$D/final-summary.env" || return
 same_bytes "$O/summary.env" "$D/final-summary.env" || return
 printf '%s\n' "$nonce" > "$D/durable-terminal" || return
 chmod 600 "$D/durable-terminal" || return
 sync -f "$D" || return
 printf 'DURABLE_RECEIPTS=sync_f_completed\n' >> "$O/summary.env" || return
 cp -- "$O/summary.env" "$D/final-summary.env" || return
 chmod 600 "$D/final-summary.env" || return
 same_bytes "$O/summary.env" "$D/final-summary.env" || return
 sync -f "$D" || return
 # Only after both data and directory metadata have been synced may the normal
 # user proof observe terminal state and the host controller request QMP quit.
 chmod 644 "$O/summary.env" || return
 printf '%s\n' "$nonce" > "$O/terminal" || return
 chmod 644 "$O/terminal"
}

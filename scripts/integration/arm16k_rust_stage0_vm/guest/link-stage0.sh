#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Fixed direct-ld adapter; shared-runtime-only selection, not a GCC driver.
set -euo pipefail
export LC_ALL=C

rewrite_link_args() {
  local arg count=0 bytes=0 dynamic=1
  rewrite_status=REFUSED_BEFORE_EXEC
  link_args=()
  (( $# > 0 && $# <= 512 )) || return 2
  for arg in "$@"; do
    bytes=$((bytes+${#arg}+1))
    (( bytes <= 131072 )) || return 2
    case $arg in
      @*|-static|--static|-static-pie|-dn|-non_shared) return 2 ;;
      -Bstatic|--Bstatic) dynamic=0; link_args+=("$arg") ;;
      -Bdynamic|--Bdynamic) dynamic=1; link_args+=("$arg") ;;
      -lgcc_s)
        (( dynamic == 1 && count == 0 )) || return 2
        link_args+=(/usr/lib/libgcc_s.so.1); count=1 ;;
      -lgcc|-lgcc_eh|-l:libgcc.a|/usr/lib/libgcc.a|/usr/lib/libgcc_s.so|-l:libgcc_s.so|/usr/lib/libgcc_s.so.1|-l:libgcc_s.so.1) return 2 ;;
      *) link_args+=("$arg") ;;
    esac
  done
  (( count == 1 )) || return 2
  rewrite_status=REWRITE_APPROVED_BEFORE_EXEC
}

build_link_receipt() {
  local arg index=0 line
  (( $# <= 512 )) || return 2
  printf -v receipt_body 'ROOT_STAGE0_LD_ARGV_V1\nSTATUS=%s\nEXECUTABLE=/usr/bin/ld\nORIGINAL_COUNT=%d\n' "$rewrite_status" "$#"
  for arg in "$@"; do
    printf -v line 'ORIGINAL[%d]=%q\n' "$index" "$arg"
    receipt_body+=$line; (( ${#receipt_body} <= 65536 )) || return 2
    index=$((index+1))
  done
  printf -v line 'REWRITTEN_COUNT=%d\n' "${#link_args[@]}"; receipt_body+=$line; index=0
  for arg in "${link_args[@]}"; do
    printf -v line 'REWRITTEN[%d]=%q\n' "$index" "$arg"
    receipt_body+=$line; (( ${#receipt_body} <= 65536 )) || return 2
    index=$((index+1))
  done
}

main() {
  local approved=1
  rewrite_link_args "$@" || { approved=0; link_args=(); }
  build_link_receipt "$@" || return 2
  local receipt=${CACHY_RUST_STAGE0_LINK_RECEIPT-}
  [[ $receipt =~ ^/home/builder/\.cache/arm16k-rust-stage0-[0-9a-f]{32}/(direct|cargo)-ld\.receipt$ && ! -e $receipt && ! -L $receipt ]] || return 2
  umask 077
  set -o noclobber
  printf '%s' "$receipt_body" > "$receipt" || return 2
  (( approved == 1 )) || return 2
  [[ -f /usr/lib/libgcc_s.so.1 && ! -L /usr/lib/libgcc_s.so.1 && -r /usr/lib/libgcc_s.so.1 ]] || return 2
  exec /usr/bin/ld "${link_args[@]}"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi

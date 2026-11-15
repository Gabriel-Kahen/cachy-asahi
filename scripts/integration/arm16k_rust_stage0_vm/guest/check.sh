#!/usr/bin/bash
# SPDX-License-Identifier: MIT
# Source-only, untested Rust 1.98.0 / emulated ARM16K fixture.
set -euo pipefail
umask 077
[[ $# == 1 && $1 =~ ^[0-9a-f]{32}$ ]] || exit 2
nonce=$1
prefix=/opt/cachy-asahi/rust-stage0
fixture=$prefix/fixture
triple=aarch64-unknown-linux-gnu
D=/home/builder/.cache/arm16k-rust-stage0-$nonce
arch=NOT_RUN pagesize=NOT_RUN uid=NOT_RUN
rust_release=NOT_RUN rust_host=NOT_RUN cargo_version=NOT_RUN
inventory_before=NOT_RUN inventory_after=NOT_RUN
owned_before=NOT_RUN owned_after=NOT_RUN direct=NOT_RUN cargo=NOT_RUN runs=0
status=FAIL ready=0 guest_sync=NOT_RUN
rtc_keys=(RTC_PRESENT RTC_DRIVER RTC_HCTOSYS HOST_BOOT_UTC GUEST_BEFORE_CRYPTO_UTC RTC_BEFORE_CRYPTO_UTC RTC_CLOCK_ADVANCED CLOCK_SETTING)
declare -A rtc=()
for key in "${rtc_keys[@]}"; do rtc[$key]=NOT_RUN; done

file_sha() {
  local result
  result=$(/usr/bin/sha256sum -- "$1") || return 1
  printf '%s' "${result%% *}"
}

# Root supplies only the user-readable subset; complete111 checks stay offline.
verify_owned() {
  /usr/bin/sha256sum --check --strict --status "$fixture/owned-regular.sha256" || return 1
  local path target extra count=0 actual
  while IFS=$'\t' read -r path target extra || [[ -n $path ]]; do
    [[ $path == /* && -n $target && -z $extra && -L $path ]] || return 1
    actual=$(/usr/bin/readlink -- "$path") || return 1
    [[ $actual == "$target" ]] || return 1
    count=$((count+1))
  done < "$fixture/owned-links.tsv"
  (( count > 0 ))
}

inventory() {
  /usr/bin/pacman -Q | /usr/bin/sort > "$D/$1.inventory" || return 1
  [[ $(file_sha "$D/$1.inventory") == "$(file_sha "$fixture/expected111.lock")" ]]
}

finish() {
  local code=$? phase receipt receipt_size
  trap - EXIT INT TERM
  set +e
  if [[ $ready == 1 ]]; then
    if inventory after > "$D/inventory-after.log" 2>&1; then
      inventory_after=$(file_sha "$D/after.inventory")
    else
      status=FAIL
    fi
    if verify_owned > "$D/owned-after.log" 2>&1; then owned_after=PASS; else status=FAIL; fi
    if ! /usr/bin/sha256sum --check --strict --status "$fixture/guest-paths.sha256" > "$D/guest-paths-after.log" 2>&1; then status=FAIL; fi
    # Bounded exact argv DATA, outside the unchanged Rust result frame.
    # Receipt presence never proves ld exit success; build/run gates still do.
    for phase in direct cargo; do
      receipt=$D/$phase-ld.receipt
      if [[ -f $receipt && ! -L $receipt && $(/usr/bin/stat -c '%u:%a:%h' -- "$receipt") == 1000:600:1 ]]; then
        receipt_size=$(/usr/bin/stat -c '%s' -- "$receipt")
        if [[ $receipt_size =~ ^[0-9]+$ ]] && (( receipt_size > 0 && receipt_size <= 65536 )); then
          printf '\nRUST_STAGE0_LD_RECEIPT_BEGIN %s %s\n' "$nonce" "$phase"
          /usr/bin/cat -- "$receipt" || status=FAIL
          printf 'RUST_STAGE0_LD_RECEIPT_END %s %s\n' "$nonce" "$phase"
        else status=FAIL; fi
      else status=FAIL; fi
    done
    # Flush the disposable guest before Root's complete offline ownership check.
    guest_sync=FAIL
    if /usr/bin/timeout --signal=TERM --kill-after=3 10s /usr/bin/sync > "$D/guest-sync.stdout" 2> "$D/guest-sync.stderr"; then
      guest_sync=PASS
    else
      status=FAIL
    fi
  fi
  if (( code != 0 )); then status=FAIL; fi
  printf '\nRUST_STAGE0_BEGIN %s\n' "$nonce"
  printf 'STATUS=%s\nARCH=%s\nPAGESIZE=%s\nUID=%s\nPREFIX=%s\n' "$status" "$arch" "$pagesize" "$uid" "$prefix"
  printf 'RUSTC_RELEASE=%s\nRUSTC_HOST=%s\nCARGO_VERSION=%s\n' "$rust_release" "$rust_host" "$cargo_version"
  printf 'INVENTORY_BEFORE_SHA256=%s\nINVENTORY_AFTER_SHA256=%s\n' "$inventory_before" "$inventory_after"
  printf 'OWNED_READABLE_BEFORE=%s\nOWNED_READABLE_AFTER=%s\nDIRECT_RUSTC=%s\nCARGO_OFFLINE=%s\nCORRECTNESS_RUNS=%s\n' "$owned_before" "$owned_after" "$direct" "$cargo" "$runs"
  printf 'GUEST_SYNC=%s\n' "$guest_sync"
  for key in "${rtc_keys[@]}"; do printf '%s=%s\n' "$key" "${rtc[$key]}"; done
  printf 'RUST_STAGE0_END %s\n' "$nonce"
  [[ $status == PASS ]] && exit 0
  exit 1
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

arch=$(/usr/bin/uname -m)
pagesize=$(/usr/bin/getconf PAGESIZE)
uid=$(/usr/bin/id -u)
[[ $arch == aarch64 && $pagesize == 16384 && $uid == 1000 ]]
[[ $(/usr/bin/id -un) == builder && $(/usr/bin/id -G) == 1000 ]]
[[ -d /home/builder && ! -L /home/builder ]]
[[ ! -L /home/builder/.cache ]]
if [[ ! -e /home/builder/.cache ]]; then /usr/bin/mkdir -- /home/builder/.cache; fi
[[ -d /home/builder/.cache && ! -L /home/builder/.cache ]]
cache_mode=$(/usr/bin/stat -c '%a' -- /home/builder/.cache)
[[ $(/usr/bin/stat -c '%u' -- /home/builder/.cache) == 1000 && $cache_mode =~ ^[0-7]{3,4}$ ]]
(( (8#$cache_mode & 0077) == 0 ))
[[ ! -e $D && ! -L $D ]]
/usr/bin/mkdir -- "$D"
ready=1
[[ $(/usr/bin/stat -c '%u:%a' -- "$D") == 1000:700 ]]
for item in expected111.lock owned-regular.sha256 owned-links.tsv guest-paths.sha256 rtc-clock.sh link-stage0.sh Cargo.toml Cargo.lock main.rs; do
  [[ -f $fixture/$item && ! -L $fixture/$item && -r $fixture/$item ]]
done
for executable in "$prefix/bin/rustc" "$prefix/bin/cargo" "$fixture/link-stage0.sh" /usr/bin/ld /lib/ld-linux-aarch64.so.1; do
  [[ -f $executable && -x $executable ]]
done
for item in /usr/lib/Scrt1.o /usr/lib/crti.o /usr/lib/crtn.o; do [[ -f $item && -r $item ]]; done
/usr/bin/sha256sum --check --strict --status "$fixture/guest-paths.sha256" > "$D/guest-paths-before.log" 2>&1
inventory before > "$D/inventory-before.log" 2>&1
inventory_before=$(file_sha "$D/before.inventory")
verify_owned > "$D/owned-before.log" 2>&1
owned_before=PASS

# The Root preparation pins this exact frozen helper; never set the guest clock.
source "$fixture/rtc-clock.sh"
rtc_clock_guard
count=0
while IFS='=' read -r key value; do
  [[ -n ${rtc[$key]+known} && ${rtc[$key]} == NOT_RUN && -n $value ]]
  rtc[$key]=$value
  count=$((count+1))
done < "$D/rtc-clock.env"
[[ $count == ${#rtc_keys[@]} ]]

/usr/bin/mkdir -- "$D/cargo-home" "$D/target"
cd "$D"
# Cargo reads ancestor configuration despite an otherwise cleared environment.
ancestor=$D
while :; do
  for name in config config.toml; do [[ ! -e $ancestor/.cargo/$name && ! -L $ancestor/.cargo/$name ]]; done
  [[ $ancestor == / ]] && break
  ancestor=${ancestor%/*}
  [[ -n $ancestor ]] || ancestor=/
done
export HOME=$D CARGO_HOME=$D/cargo-home CARGO_NET_OFFLINE=true
export RUSTC=$prefix/bin/rustc RUSTDOC=$prefix/bin/rustdoc
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
flags=(--edition=2021 -C linker="$fixture/link-stage0.sh" -C linker-flavor=ld
  -C link-arg=/usr/lib/Scrt1.o -C link-arg=/usr/lib/crti.o -C link-arg=/usr/lib/crtn.o
  -C link-arg=--dynamic-linker=/lib/ld-linux-aarch64.so.1
  -L native=/usr/lib -C link-arg=-z -C link-arg=max-page-size=16384)
# Replace only Rust's dynamic -lgcc_s with the pinned ELF .so.1.
# The GCC-driver script and its static -lgcc are not selected.
# Other qualified ld/CRT/loader operands and both functional probes are unchanged.
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$fixture/link-stage0.sh"
# Cargo supplies the edition from Cargo.toml; rustc receives all remaining flags.
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="${flags[*]:1}"
started=$SECONDS
bounded() {
  local label=$1 cap=$2 remaining
  shift 2
  remaining=$((360-(SECONDS-started)))
  (( remaining > 3 ))
  (( cap <= remaining-3 )) || cap=$((remaining-3))
  /usr/bin/timeout --signal=TERM --kill-after=3 "${cap}s" "$@" > "$D/$label.stdout" 2> "$D/$label.stderr"
}
bounded rustc-version 20 "$prefix/bin/rustc" -vV
while IFS= read -r line; do
  case $line in
    'release: '*) [[ $rust_release == NOT_RUN ]]; rust_release=${line#release: } ;;
    'host: '*) [[ $rust_host == NOT_RUN ]]; rust_host=${line#host: } ;;
  esac
done < "$D/rustc-version.stdout"
[[ $rust_release == 1.98.0 && $rust_host == "$triple" ]]
bounded rustc-sysroot 20 "$prefix/bin/rustc" --print sysroot
[[ $(/usr/bin/cat "$D/rustc-sysroot.stdout") == "$prefix" ]]
bounded cargo-version 20 "$prefix/bin/cargo" --version
version=$(/usr/bin/cat "$D/cargo-version.stdout")
[[ $version =~ ^cargo\ (1\.98\.0)\ \([0-9a-f]+\ [0-9-]+\)$ ]]
cargo_version=${BASH_REMATCH[1]}
printf '%s\n' 'RUST_CORRECTNESS=PASS threads=4 arithmetic=500050000 files=ok' > "$D/expected.stdout"
export CACHY_RUST_STAGE0_LINK_RECEIPT=$D/direct-ld.receipt
bounded direct-build 100 "$prefix/bin/rustc" --target "$triple" "${flags[@]}" "$fixture/main.rs" -o "$D/direct"
bounded direct-run 15 "$D/direct" "$D"
[[ $(file_sha "$D/direct-run.stdout") == "$(file_sha "$D/expected.stdout")" ]]
direct=PASS
runs=1
cargo_args=(--offline --frozen --manifest-path "$fixture/Cargo.toml" --target "$triple" --target-dir "$D/target")
export CACHY_RUST_STAGE0_LINK_RECEIPT=$D/cargo-ld.receipt
bounded cargo-build 140 "$prefix/bin/cargo" build "${cargo_args[@]}"
bounded cargo-run 15 "$prefix/bin/cargo" run "${cargo_args[@]}" -- "$D"
[[ $(file_sha "$D/cargo-run.stdout") == "$(file_sha "$D/expected.stdout")" ]]
cargo=PASS
runs=2
status=PASS

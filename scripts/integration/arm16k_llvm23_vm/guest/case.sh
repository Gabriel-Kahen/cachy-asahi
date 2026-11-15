# SPDX-License-Identifier: MIT
# Fixed DATA parser shared by the two reviewed guest entry points.
case_data() {
 local key value line count=0
 declare -A seen=()
 [[ -f $D/case.env && ! -L $D/case.env && $(stat -c '%u:%g:%a' "$D/case.env") == 0:0:644 ]]
 while IFS= read -r line || [[ -n $line ]]; do
  [[ $line == *=* && ${line#*=} != *=* ]] || return 2
  key=${line%%=*};value=${line#*=}
  [[ $key =~ ^[a-z_]+$ && -n $value ]] || return 2
  [[ ! ${seen[$key]+yes} ]] || return 2
  case "$key" in
   nonce) [[ $value =~ ^[0-9a-f]{32}$ ]] || return 2;;
   signer_fingerprint) [[ $value =~ ^[0-9A-F]{40}$ ]] || return 2;;
   cert_not_before|cert_not_after) [[ $value =~ ^[1-9][0-9]{8,11}$ ]] || return 2;;
   gpg_seconds|install_seconds|probe_wait_seconds|remove_seconds|compile_seconds|run_seconds|sync_seconds|log_bytes|guest_output_cap_bytes)
    [[ $value =~ ^[1-9][0-9]{0,8}$ ]] || return 2;;
   *) return 2;;
  esac
  seen[$key]=1;printf -v "$key" '%s' "$value";count=$((count+1))
 done < "$D/case.env"
 [[ $count == 13 && $log_bytes -ge 1024 && $log_bytes -le 16777216 ]] || return 2
 (( cert_not_before < cert_not_after ))
}
file_sha() { local value;value=$(sha256sum -- "$1") || return;printf '%s' "${value%% *}"; }
probe_link_data() {
 local key value line count=0
 declare -A seen=()
 [[ -f $D/probe-link.env && ! -L $D/probe-link.env && $(stat -c '%u:%g:%a' "$D/probe-link.env") == 0:0:644 ]]
 while IFS= read -r line || [[ -n $line ]]; do
  [[ $line == *=* && ${line#*=} != *=* ]] || return 2
  key=${line%%=*};value=${line#*=}
  [[ $key =~ ^[a-z_]+$ && -n $value ]] || return 2
  [[ ! ${seen[$key]+yes} ]] || return 2
  case "$key" in
   link_mode) [[ $value == EXPLICIT_COMPILER_RT_BASELINE_SONAMES ]] || return 2;;
   crt_start|crt_init|crt_fini|lib_c|lib_m|lib_cxx|lib_unwind|builtins|loader|linker)
    [[ $value =~ ^/[A-Za-z0-9._+/@:~-]+$ && $value != */ && $value != *//* && $value != */./* && $value != */../* && $value != */. && $value != */.. ]] || return 2;;
   *) return 2;;
  esac
  seen[$key]=1;printf -v "$key" '%s' "$value";count=$((count+1))
 done < "$D/probe-link.env"
 [[ $count == 11 ]]
}
clock_valid() { local now;now=$(date -u +%s);(( now >= cert_not_before && now < cert_not_after )); }
# A mandatory Root cap bounds each command and its combined log. Do not impose
# RLIMIT_FSIZE on ALPM/clang: their installed payload/output files are larger.
bounded() {
 local seconds=$1 output=$2;shift 2
 timeout --signal=KILL "$seconds" "$@" 2>&1 | {
  local extra
  head -c "$log_bytes" > "$output" || return
  extra=$(head -c 1 | wc -c) || return
  cat > /dev/null || return
  [[ $extra == 0 ]]
 }
}
verify_paths() { sha256sum --check --strict --status "$D/runtime-paths.sha256"; }
inventory() { pacman -Q | sort; }

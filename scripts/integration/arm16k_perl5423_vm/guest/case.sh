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
   dependency_mode) [[ $value == NONE || $value == DB53 ]] || return 2;;
   baseline_perl_version) [[ $value =~ ^[A-Za-z0-9@+_.:-]{1,128}$ ]] || return 2;;
   recovery_mode) [[ $value == REMOVE || $value == SIGNED_EXACT_OLD_PACKAGE ]] || return 2;;
   signer_fingerprint) [[ $value =~ ^[0-9A-F]{40}$ ]] || return 2;;
   cert_not_before|cert_not_after) [[ $value =~ ^[1-9][0-9]{8,11}$ ]] || return 2;;
   gpg_seconds|install_seconds|probe_wait_seconds|remove_seconds|run_seconds|sync_seconds|log_bytes|guest_output_cap_bytes)
    [[ $value =~ ^[1-9][0-9]{0,8}$ ]] || return 2;;
   *) return 2;;
  esac
  seen[$key]=1;printf -v "$key" '%s' "$value";count=$((count+1))
 done < "$D/case.env"
 [[ $count == 15 && $log_bytes -ge 1024 && $log_bytes -le 16777216 ]] || return 2
 (( cert_not_before < cert_not_after ))
}
file_sha() { local value;value=$(sha256sum -- "$1") || return;printf '%s' "${value%% *}"; }
clock_valid() { local now;now=$(date -u +%s);(( now >= cert_not_before && now < cert_not_after )); }
# A mandatory Root cap bounds each command and its combined log. Do not impose
# RLIMIT_FSIZE on ALPM: their installed payload/output files are larger.
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

# The sole mutable ALPM record field accepted by Root's installed lifecycle.
# Keep the raw record and raw DB manifest separately for durable review.
normalized_desc() {
 local source=$1 target=$2 line pending=0 seen=0
 : > "$target"
 while IFS= read -r line || [[ -n $line ]];do
  if [[ $pending == 1 ]];then
   [[ $line =~ ^[0-9]+$ ]];printf '<NORMAL_ALPM_TRANSACTION_TIME>\n' >> "$target";pending=0
  else
   printf '%s\n' "$line" >> "$target"
   if [[ $line == '%INSTALLDATE%' ]];then seen=$((seen+1));pending=1;fi
  fi
 done < "$source"
 [[ $seen == 1 && $pending == 0 ]]
}

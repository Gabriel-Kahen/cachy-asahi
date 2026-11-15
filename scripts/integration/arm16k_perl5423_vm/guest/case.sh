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
# API name retained: equality is bounded length+SHA256 evidence, not a literal
# byte comparison. Both commands must succeed, including for empty/binary files.
same_bytes() {
 local path size left right
 [[ $# == 2 ]] || return 2
 for path in "$@";do
  [[ -f $path && ! -L $path ]] || return 2
  size=$(stat -c '%s' -- "$path") || return
  [[ $size =~ ^[0-9]+$ && $size -le 16777216 ]] || return 2
 done
 left=$(stat -c '%s' -- "$1") || return;right=$(stat -c '%s' -- "$2") || return
 [[ $left == "$right" ]] || return 1
 left=$(file_sha "$1") || return;right=$(file_sha "$2") || return
 [[ $left =~ ^[0-9a-f]{64}$ && $right =~ ^[0-9a-f]{64}$ && $left == "$right" ]]
}
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

# Root's EXIT path retains only fixed public command logs, never a tree or trust
# home. An incomplete manifest is not complete diagnostic evidence.
retain_failure_data() (
 umask 077
 local path name original kept hash state bytes=0 count=0 cap=${log_bytes:-65536}
 local output_cap=${guest_output_cap_bytes:-1048576} used=0 take destination=$D/failure-diagnostics
 [[ $phase =~ ^[a-z_]{1,64}$ && $failure_rc =~ ^[1-9][0-9]{0,2}$ && $failure_rc -le 255 ]] || return 2
 [[ $cap =~ ^[1-9][0-9]{0,8}$ && $output_cap =~ ^[1-9][0-9]{0,11}$ ]] || return 2
 [[ -d $S && ! -L $S && $(stat -c '%u:%g:%a' -- "$S") == 0:0:700 ]] || return 2
 [[ -f $D/failure.env && ! -L $D/failure.env && $(stat -c '%u:%g:%h:%a' -- "$D/failure.env") == 0:0:1:600 ]] || return 2
 original=$(stat -c '%s' -- "$D/failure.env") || return
 [[ $original -le 16384 && ! -e $destination && ! -L $destination ]] || return 2
 if [[ -e $D/results || -L $D/results ]];then
  [[ -d $D/results && ! -L $D/results ]] || return 2
  for path in "$D/results/"*;do
   [[ -e $path || -L $path ]] || continue
   count=$((count+1));[[ $count -le 128 && -f $path && ! -L $path && $(stat -c '%u:%g:%h:%a' -- "$path") == 0:0:1:600 ]] || return 2
   original=$(stat -c '%s' -- "$path") || return
   [[ $original -le 16777216 ]] || return 2
   used=$((used+original))
  done
 fi
 (( cap <= 1048576 )) || cap=1048576
 (( output_cap-used-32768 >= cap )) || cap=$((output_cap-used-32768))
 (( cap > 0 )) || return 2
 install -d -m700 "$destination" || return
 hash=$(file_sha "$D/failure.env") || return
 printf 'PERL5423_FAILURE_DIAGNOSTICS_V1\nFAILED_PHASE=%s\nEXIT_STATUS=%s\nFAILURE_ENV_SHA256=%s\nCAP_BYTES=%s\n' "$phase" "$failure_rc" "$hash" "$cap" > "$destination/manifest.tsv" || return
 for name in import.log secret.log keys.log ownertrust.log signature.log rollback-signature.log dependency-requires.log dependency-install.log dependencies.log install.log database-installed.log remove.log rollback.log dependency-remove.log database-final.log gpg-stop.log sync.log official-source-import.log official-selected-export.log official-import-stop.log official-import.log official-secret.log official-keys.log official-ownertrust.log official-signature.log official-stop.log;do
  path=$S/$name
  [[ -e $path || -L $path ]] || continue
  [[ -f $path && ! -L $path && $(stat -c '%u:%g:%h:%a' -- "$path") == 0:0:1:600 ]] || return 2
  original=$(stat -c '%s' -- "$path") || return
  [[ $original -le 16777216 ]] || return 2
  take=$((cap-bytes));(( take <= 65536 )) || take=65536
  if (( take == 0 ));then
   printf '%s\t0\t-\tOMITTED\t%s\n' "$original" "$name" >> "$destination/manifest.tsv" || return
   continue
  fi
  head -c "$take" -- "$path" > "$destination/$name" || return
  kept=$(stat -c '%s' -- "$destination/$name") || return
  (( original < take )) && take=$original
  [[ $kept == "$take" && $(stat -c '%s' -- "$path") == "$original" ]] || return 2
  hash=$(file_sha "$destination/$name") || return
  state=COMPLETE;(( kept == original )) || state=TRUNCATED
  bytes=$((bytes+kept));(( bytes <= cap )) || return 2
  printf '%s\t%s\t%s\t%s\t%s\n' "$original" "$kept" "$hash" "$state" "$name" >> "$destination/manifest.tsv" || return
 done
 printf 'RETAINED_BYTES=%s\nPERL5423_FAILURE_DIAGNOSTICS_END\n' "$bytes" >> "$destination/manifest.tsv" || return
 [[ $(stat -c '%s' -- "$destination/manifest.tsv") -le 16384 ]]
)

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

# SPDX-License-Identifier: MIT
# Fixed GPG receipts and informational dates; never changes verification policy.
gpg_archive() {
 case "$1" in
  python-3.14.8-1-aarch64.pkg.tar.xz) gpg_label=python;gpg_primary=68B3537F39A313B3E574D06777193F152BDBE6A6;;
  mpdecimal-4.0.1-3-aarch64.pkg.tar.xz) gpg_label=mpdecimal;gpg_primary=68B3537F39A313B3E574D06777193F152BDBE6A6;;
  cachy-asahi-ksmctl-0.1.0-1-any.pkg.tar.xz) gpg_label=ksm;gpg_primary=C98720061248F50811843544A8EC89D416F7A112;;
  *) return 2;;
 esac
}

receipt_file() { [[ -f $1 && ! -L $1 && $(stat --printf='%s' -- "$1") -le 32768 ]]; }
epoch_field() { [[ $1 =~ ^(0|[1-9][0-9]{0,11})$ ]]; }
date_before() { if epoch_field "$1" && epoch_field "$2";then if (( $1 < $2 ));then printf yes;else printf no;fi;else printf unknown;fi; }
date_expired() { if epoch_field "$1" && epoch_field "$2";then if (( $2 != 0 && $1 > $2 ));then printf yes;else printf no;fi;else printf unknown;fi; }

gpg_failure_fields() {
 local label=$1 rc=$2 directory=$3 dates=$4 now=$5 utc=$6 line code codes=unknown seen=, unknown=no error=unknown errcode=unknown errsource=none
 local created=unknown expires=unknown date_source=unknown signer=unknown primary_match=unknown
 local key_created=unknown key_expires=unknown key_scope=unknown pending_created=unknown pending_expires=unknown pending_kind=unknown
 local packet_label packet_created packet_expires archive_label=$label operation=verify
 local -a fields
 case "$label" in python|mpdecimal) local expected=68B3537F39A313B3E574D06777193F152BDBE6A6;;ksm) local expected=C98720061248F50811843544A8EC89D416F7A112;;trust_import|ownertrust) local expected=unknown;archive_label=none;operation=$label;;*) return 2;;esac
 [[ $rc =~ ^[0-9]{1,3}$ ]] || return 2
 epoch_field "$now" || now=unknown
 [[ $utc =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || utc=unknown
 if receipt_file "$dates";then
  while read -r packet_label packet_created packet_expires;do
   if [[ $packet_label == "$label" ]] && epoch_field "$packet_created" && epoch_field "$packet_expires";then created=$packet_created;expires=$packet_expires;date_source=pinned_verified_input;fi
  done < "$dates"
 fi
 if receipt_file "$directory/$label.status";then
  while IFS= read -r line || [[ -n $line ]];do
   IFS=' ' read -r -a fields <<< "$line"
   [[ ${fields[0]:-} == '[GNUPG:]' ]] || continue
   code=${fields[1]:-}
   case "$code" in NEWSIG|SIG_ID|KEY_CONSIDERED|GOODSIG|VALIDSIG|BADSIG|ERRSIG|NO_PUBKEY|EXPKEYSIG|EXPSIG|REVKEYSIG|KEYEXPIRED|KEYREVOKED|NODATA|BADARMOR|FAILURE|ERROR|TRUST_UNDEFINED|TRUST_NEVER|TRUST_MARGINAL|TRUST_FULLY|TRUST_ULTIMATE|IMPORTED|IMPORT_OK|IMPORT_PROBLEM|IMPORT_RES)
    if [[ $seen != *",$code,"* ]];then if [[ $codes == unknown ]];then codes=$code;else codes+=,$code;fi;seen+=$code,;fi;;
    *) unknown=yes;continue;;
   esac
   case "$code" in
    BADSIG) error=bad_signature;;NO_PUBKEY) error=missing_public_key;;EXPKEYSIG) error=expired_signing_key;;EXPSIG) error=expired_signature;;REVKEYSIG|KEYREVOKED) error=revoked_key;;NODATA|BADARMOR) error=invalid_signature_data;;
    ERRSIG)
     case "${fields[7]:-}" in 4) error=unsupported_algorithm;;9) error=missing_public_key;;*) error=signature_check_error;;esac
     if [[ ${fields[7]:-} =~ ^(0|[1-9][0-9]{0,9})$ ]] && (( fields[7] <= 4294967295 ));then errcode=${fields[7]};errsource=ERRSIG;fi
     if epoch_field "${fields[6]:-}" && [[ $date_source == unknown ]];then created=${fields[6]};date_source=runtime_errsig;fi;;
    FAILURE|ERROR)
     [[ $error != unknown ]] || error=gpg_error
     local number=${fields[3]:-};number=${number%%_*}
     if [[ $number =~ ^(0|[1-9][0-9]{0,9})$ ]] && (( number <= 4294967295 ));then errcode=$number;errsource=$code;fi;;
    VALIDSIG)
     if [[ ${fields[2]:-} =~ ^[0-9A-F]{40}$ ]];then signer=${fields[2]};fi
     if [[ ${fields[11]:-${fields[2]:-}} == "$expected" ]];then primary_match=yes;else primary_match=no;fi
     if epoch_field "${fields[4]:-}" && epoch_field "${fields[5]:-}";then created=${fields[4]};expires=${fields[5]};date_source=runtime_validsig;fi;;
   esac
  done < "$directory/$label.status"
 fi
 if receipt_file "$directory/$label.keys";then
  while IFS= read -r line || [[ -n $line ]];do
   IFS=: read -r -a fields <<< "$line"
   case "${fields[0]:-}" in
    pub|sub)
     pending_kind=unknown;pending_created=unknown;pending_expires=unknown
     if (( ${#fields[@]} >= 10 ));then pending_kind=${fields[0]};pending_created=${fields[5]:-unknown};pending_expires=${fields[6]:-0};fi;;
    fpr)
     if [[ ${fields[9]:-} == "$signer" || ( $signer == unknown && $pending_kind == pub && ${fields[9]:-} == "$expected" ) ]];then
      if epoch_field "$pending_created" && epoch_field "$pending_expires";then key_created=$pending_created;key_expires=$pending_expires;key_scope=$pending_kind;fi
     fi;;
   esac
  done < "$directory/$label.keys"
 fi
 [[ ${#codes} -le 256 ]] || { codes=unknown;unknown=yes; }
 case "$rc" in 124|137) error=timeout;;153) error=receipt_limit;;esac
 printf 'GPG_OPERATION=%s\nGPG_ARCHIVE=%s\nGPG_EXIT=%s\nGPG_STATUS_CODES=%s\nGPG_UNKNOWN_STATUS=%s\nGPG_ERROR_CATEGORY=%s\nGPG_ERROR_CODE=%s\nGPG_ERROR_SOURCE=%s\n' "$operation" "$archive_label" "$rc" "$codes" "$unknown" "$error" "$errcode" "$errsource"
 printf 'GPG_UTC_EPOCH=%s\nGPG_UTC=%s\nGPG_KEY_CREATED=%s\nGPG_KEY_EXPIRES=%s\nGPG_KEY_DATE_SCOPE=%s\nGPG_EXPECTED_PRIMARY_MATCH=%s\n' "$now" "$utc" "$key_created" "$key_expires" "$key_scope" "$primary_match"
 printf 'GPG_SIG_CREATED=%s\nGPG_SIG_EXPIRES=%s\nGPG_SIG_DATE_SOURCE=%s\n' "$created" "$expires" "$date_source"
 printf 'GPG_UTC_BEFORE_KEY_CREATION=%s\nGPG_UTC_AFTER_KEY_EXPIRY=%s\nGPG_UTC_BEFORE_SIG_CREATION=%s\nGPG_UTC_AFTER_SIG_EXPIRY=%s\nGPG_SIG_BEFORE_KEY_CREATION=%s\n' "$(date_before "$now" "$key_created")" "$(date_expired "$now" "$key_expires")" "$(date_before "$now" "$created")" "$(date_expired "$now" "$expires")" "$(date_before "$created" "$key_created")"
}

gpg_run_fixed() {
 local archive=$1 rc key_rc=unknown now utc verify_line name
 local -a args
 [[ $# == 1 ]] || return 2
 case "$archive" in
  trust_import) gpg_label=trust_import;gpg_primary=unknown;args=(--no-options --batch --no-autostart --no-auto-key-retrieve --homedir "$D/trust" --status-fd 1 --import "$D/materials/archlinuxarm.gpg" "$D/materials/TEST-public.asc");;
  ownertrust) gpg_label=ownertrust;gpg_primary=unknown;args=(--no-options --batch --homedir "$D/trust" --status-fd 1 --import-ownertrust);;
  *) gpg_archive "$archive" || return;args=(--no-options --batch --no-autostart --no-auto-key-retrieve --homedir "$D/trust" --status-fd 1 --verify "$D/materials/$archive.sig" "$D/materials/$archive");;
 esac
 local directory=$D/receipts
 umask 077
 [[ ! -L $directory ]] || return 2
 install -d -m700 "$directory" || return
 for name in "$gpg_label.status" "$gpg_label.stderr" "$gpg_label.supervisor.stderr" "$gpg_label.keys" "$gpg_label.keys.stderr" "$gpg_label.keys.supervisor.stderr" gpg-failure.env;do [[ ! -e $directory/$name && ! -L $directory/$name ]] || return 2;done
 expected_probes=1
 verify_line=$((LINENO+1))
 if (ulimit -c 0 && ulimit -f 32 && exec timeout --signal=TERM --kill-after=2s 20 gpg "${args[@]}") > "$directory/$gpg_label.status" 2> "$directory/$gpg_label.stderr";then rc=0;else rc=$?;fi 2> "$directory/$gpg_label.supervisor.stderr"
 expected_probes=0
 sync -f "$directory" || return
 if (( rc != 0 ));then
  failure_record "$verify_line" gpg "$rc" gpg-receipts.sh
  expected_probes=1
  if [[ $gpg_primary != unknown ]];then
   if (ulimit -c 0 && ulimit -f 32 && exec timeout --signal=TERM --kill-after=2s 10 gpg --no-options --batch --no-autostart --no-auto-key-retrieve --homedir "$D/trust" --with-colons --fixed-list-mode --with-fingerprint --with-fingerprint --list-keys "$gpg_primary") > "$directory/$gpg_label.keys" 2> "$directory/$gpg_label.keys.stderr";then key_rc=0;else key_rc=$?;fi 2> "$directory/$gpg_label.keys.supervisor.stderr"
  fi
  now=$(date -u +%s) || now=unknown
  if epoch_field "$now";then utc=$(date -u --date="@$now" +%Y-%m-%dT%H:%M:%SZ) || utc=unknown;else utc=unknown;fi
  if ! gpg_failure_fields "$gpg_label" "$rc" "$directory" "$D/signature-dates.lock" "$now" "$utc" > "$directory/gpg-failure.env";then
   printf 'GPG_ARCHIVE=%s\nGPG_EXIT=%s\nGPG_ERROR_CATEGORY=diagnostic_unavailable\n' "$gpg_label" "$rc" > "$directory/gpg-failure.env"
  fi
  printf 'GPG_KEY_METADATA_EXIT=%s\n' "$key_rc" >> "$directory/gpg-failure.env"
  sync -f "$directory" || return
  expected_probes=0
  return "$rc"
 fi
}

gpg_verify_fixed() { gpg_archive "$1" || return;gpg_run_fixed "$1"; }

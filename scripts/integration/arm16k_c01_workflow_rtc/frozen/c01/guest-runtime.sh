# SPDX-License-Identifier: MIT
# Fixed shell helpers for the disposable lifecycle; no package/code execution.
BASE_TOOLS=(gzip mktemp base64 bash cat chmod chown comm cp cut date env find getconf getfattr gpg gpgconf grep id install pacman rm rmdir runuser sha256sum sleep sort stat timeout touch tr uname wc xargs)

tool_label() {
 case "$1" in
  gzip|mktemp|base64|bash|cat|chmod|chown|comm|cp|cut|date|env|find|getconf|getfattr|gpg|gpgconf|grep|id|install|pacman|rm|rmdir|runuser|sha256sum|sleep|sort|stat|timeout|touch|tr|uname|wc|xargs|probe|minigzip|strict-gzip|same_bytes|inventory|payload_snapshot|user_snapshot|assert_users|require_base_tools|digest|assertion) printf '%s' "$1";;
  *) printf unknown;;
 esac
}

same_bytes() {
 local file size left right
 [[ $# == 2 ]] || return 2
 for file in "$@";do
  [[ -f $file && ! -L $file ]] || return 2
  size=$(stat --printf='%s' -- "$file") || return
  [[ $size =~ ^[0-9]+$ && $size -le 16777216 ]] || return 2
 done
 # Unwrapped base64 is injective over arbitrary bytes and contains no trailing
 # newlines for command substitution to discard. Encoder failures must propagate.
 left=$(base64 --wrap=0 -- "$1") || return
 right=$(base64 --wrap=0 -- "$2") || return
 [[ $left == "$right" ]]
}

failure_record() {
 local line=$1 raw=$2 code=$3 source=${4##*/} token
 [[ ${expected_probes:-0} == 0 && ${failed_line:-0} == 0 ]] || return 0
 [[ $line =~ ^[0-9]+$ && $code =~ ^[0-9]+$ ]] || return 0
 token=${raw%%[[:space:]]*};token=${token##*/}
 case "$token" in '[['|'['|'false'|'return') token=assertion;;esac
 token=$(tool_label "$token")
 case "$source" in arm16k-project-lifecycle-root) source=guest-root.sh;;guest-root.sh|guest-runtime.sh|gpg-receipts.sh) ;;*) source=unknown;;esac
 failed_line=$line;failed_tool=$token;failed_source=$source;failed_exit=$code
}

require_base_tools() {
 local tool
 for tool in "${BASE_TOOLS[@]}";do
  if [[ $(type -P -- "$tool") != /usr/bin/"$tool" || ! -x /usr/bin/$tool ]];then
   failed_line=$LINENO;failed_tool=$tool;failed_source=guest-runtime.sh;failed_exit=127
   return 127
  fi
 done
}

failure_fields() {
 local safe_phase safe_source safe_line safe_exit
 case "$phase" in tool_presence|guard|sentinels|baseline|trust|install|unprivileged-probes|remove|generated-cache-restoration|restoration|complete) safe_phase=$phase;;*) safe_phase=unknown;;esac
 case "${failed_source:-unknown}" in arm16k-project-lifecycle-root) safe_source=guest-root.sh;;guest-root.sh|guest-runtime.sh|gpg-receipts.sh) safe_source=$failed_source;;*) safe_source=unknown;;esac
 safe_line=${failed_line:-0};[[ $safe_line =~ ^[0-9]+$ ]] || safe_line=0
 safe_exit=$1;[[ $safe_exit =~ ^[0-9]+$ ]] || safe_exit=1
 printf 'STATUS=HOLD\nFAILED_PHASE=%s\nFAILED_LINE=%s\nFAILED_TOOL=%s\nFAILED_SOURCE=%s\nEXIT=%s\n' "$safe_phase" "$safe_line" "$(tool_label "${failed_tool:-unknown}")" "$safe_source" "$safe_exit"
}

# SPDX-License-Identifier: MIT
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

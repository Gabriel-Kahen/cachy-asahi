# SPDX-License-Identifier: MIT
# Explicit interactive opt-in; preserve an already loaded autosuggestions module.
[[ -o interactive ]] || return 0
(( ${+functions[_zsh_autosuggest_start]} )) && return 0
source "${${(%):-%N}:A:h}/zsh-autosuggestions.zsh"

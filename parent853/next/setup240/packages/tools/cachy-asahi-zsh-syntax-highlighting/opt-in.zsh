# SPDX-License-Identifier: MIT
# Explicit interactive opt-in; an already loaded highlighting module wins.
[[ -o interactive ]] || return 0
(( ${+functions[_zsh_highlight]} )) && return 0
source "${${(%):-%N}:A:h}/zsh-syntax-highlighting.zsh"

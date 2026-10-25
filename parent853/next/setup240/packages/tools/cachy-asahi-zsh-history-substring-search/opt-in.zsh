# SPDX-License-Identifier: MIT
# Explicit source only. Keybindings and startup files remain the user's choice.
[[ -o interactive ]] || return 0
() {
  emulate -L zsh
  local directory=$1 name
  zmodload zsh/parameter zsh/zleparameter || return 1
  for name in ${(k)functions} ${(k)widgets} ${(k)parameters}; do
    case $name in
      history-substring-search-*|_history-substring-search-*|_history_substring_search*) return 0 ;;
    esac
  done
  # Avoid upstream's older fallback that rebinds all widgets.
  ( autoload -Uz is-at-least && is-at-least 5.9 && {
      (( ${+functions[add-zle-hook-widget]} )) &&
        [[ $functions[add-zle-hook-widget] != *"builtin autoload -X"* ]] || {
          autoload -Uz add-zle-hook-widget && autoload +X add-zle-hook-widget
        }
    } ) || return 1
  source "$directory/zsh-history-substring-search.zsh"
} "${${(%):-%N}:A:h}"

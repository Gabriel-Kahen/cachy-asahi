# SPDX-License-Identifier: MIT
# Original cachy-asahi configuration; see LICENSE and NOTICE.
# Enable explicitly from an interactive user's configuration.
[[ -o interactive ]] || return 0
[[ ${_CACHY_ASAHI_ZSH_LOADED:-0} == 1 ]] && return 0

# Reuse a user's completion setup. Skip insecure directories and do not write
# a completion dump; Zsh performs its own permission audit.
if [[ ${CACHY_ASAHI_ZSH_COMPLETION:-1} == 1 ]] && (( ! ${+_comps} )); then
  autoload -Uz compinit
  compinit -i -D || return 1
fi

# A plain prompt is separately opt-in so an existing theme keeps ownership.
if [[ ${CACHY_ASAHI_ZSH_PROMPT:-0} == 1 ]]; then
  PROMPT='%n@%m %~ %# '
fi

typeset -g _CACHY_ASAHI_ZSH_LOADED=1

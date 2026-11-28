#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Shared checkout verification and selection. Only a missing push base can be fetched.
set -euo pipefail

component_selection_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

component_commit_available() {
  [[ "$(timeout 5s git cat-file -t "$1" 2>/dev/null)" == commit ]]
}

component_push_base_available() {
  local base=$1
  if component_commit_available "$base"; then
    return 0
  fi
  timeout --kill-after=5s 20s git fetch --quiet --depth=1 --filter=blob:none \
    --no-tags --no-recurse-submodules --no-auto-maintenance --no-write-fetch-head \
    --refmap= origin "$base" &&
    component_commit_available "$base"
}

component_diff() {
  timeout 30s git diff --no-ext-diff --no-renames --name-status -z "$1" "$2" -- | head -c 1048577 > "$3"
}

collect_components() {
  local group=${1:?component group required}
  local policy=${2:-"$component_selection_dir/dependencies.json"}
  local event=${SELECTION_EVENT:-} base=${SELECTION_BASE:-} event_head=${SELECTION_HEAD:-}
  local expected_checkout=${SELECTION_SHA:-} checkout='' metadata=''
  local ready=false
  local -a parents=() completeness=()
  local diff="${RUNNER_TEMP:?private runner temporary directory required}/component-name-status.z"
  : > "$diff"
  export GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_TERMINAL_PROMPT=0

  if [[ "$event" =~ ^(pull_request|push)$ && "$base" =~ ^[0-9a-f]{40}$ &&
        "$event_head" =~ ^[0-9a-f]{40}$ && "$expected_checkout" =~ ^[0-9a-f]{40}$ &&
        "$base" != 0000000000000000000000000000000000000000 ]]; then
    checkout=$(timeout 5s git rev-parse --verify 'HEAD^{commit}' 2>/dev/null) || checkout=''
    if [[ "$checkout" == "$expected_checkout" ]]; then
      if [[ "$event" == pull_request ]] &&
         component_commit_available "$base" && component_commit_available "$event_head"; then
        metadata=$(timeout 5s git show -s --no-show-signature --no-notes '--format=%H %P' "$checkout" -- 2>/dev/null) || metadata=''
        read -r -a parents <<< "$metadata"
        if [[ ${#parents[@]} == 3 && "${parents[0]}" == "$checkout" &&
              "${parents[1]}" == "$base" && "${parents[2]}" == "$event_head" ]]; then
          ready=true
        fi
      elif [[ "$event" == push && "$checkout" == "$event_head" ]] &&
           component_push_base_available "$base"; then
        ready=true
      fi
    fi
  fi
  # pipefail keeps a failed or timed-out diff incomplete even if it emits records.
  if [[ "$ready" == true ]] && component_diff "$base" "$checkout" "$diff"; then
    completeness=(--complete)
  fi
  python3 -I -B "$component_selection_dir/select.py" --policy "$policy" \
    --source-root "$PWD" --event "$event" --group "$group" --diff "$diff" \
    "${completeness[@]}" --github-output "${GITHUB_OUTPUT:?GitHub output file required}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  collect_components "$@"
fi

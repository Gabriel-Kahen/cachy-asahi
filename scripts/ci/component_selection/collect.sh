#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Shared checkout verification/selection. No fetch or history expansion.
set -euo pipefail

component_selection_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

component_commit_available() {
  [[ "$(timeout 5s git cat-file -t "$1" 2>/dev/null)" == commit ]]
}

collect_components() {
  local group=${1:?component group required}
  local policy=${2:-"$component_selection_dir/dependencies.json"}
  local event=${SELECTION_EVENT:-} base=${SELECTION_BASE:-} event_head=${SELECTION_HEAD:-}
  local expected_checkout=${SELECTION_SHA:-} checkout='' metadata=''
  local diff_base='' diff_target='' ready=false
  local -a parents=() completeness=()
  local diff="${RUNNER_TEMP:?private runner temporary directory required}/component-name-status.z"
  : > "$diff"
  export GIT_NO_REPLACE_OBJECTS=1 GIT_NO_LAZY_FETCH=1 GIT_TERMINAL_PROMPT=0

  if [[ "$event" =~ ^(pull_request|push)$ && "$base" =~ ^[0-9a-f]{40}$ &&
        "$event_head" =~ ^[0-9a-f]{40}$ && "$expected_checkout" =~ ^[0-9a-f]{40}$ &&
        "$base" != 0000000000000000000000000000000000000000 ]]; then
    checkout=$(timeout 5s git rev-parse --verify 'HEAD^{commit}' 2>/dev/null) || checkout=''
    if [[ "$checkout" == "$expected_checkout" ]] &&
       component_commit_available "$base" && component_commit_available "$event_head"; then
      if [[ "$event" == pull_request ]]; then
        metadata=$(timeout 5s git show -s --no-show-signature --no-notes '--format=%H %P' "$checkout" -- 2>/dev/null) || metadata=''
        read -r -a parents <<< "$metadata"
        if [[ ${#parents[@]} == 3 && "${parents[0]}" == "$checkout" &&
              "${parents[1]}" == "$base" && "${parents[2]}" == "$event_head" ]]; then
          # The verified merge tree is the checked-out source under test.
          diff_base=$base; diff_target=$checkout; ready=true
        fi
      elif [[ "$checkout" == "$event_head" ]]; then
        diff_base=$base; diff_target=$event_head; ready=true
      fi
    fi
  fi
  if [[ "$ready" == true ]]; then
    # Callback's final pipeline runs with explicit pipefail, including inside if.
    # Nonzero diff/timeout plus apparently valid partial records remains incomplete.
    if component_diff "$diff_base" "$diff_target" "$diff"; then
      completeness=(--complete)
    fi
  fi
  python3 -I -B "$component_selection_dir/select.py" --policy "$policy" \
    --source-root "$PWD" --event "$event" --group "$group" --diff "$diff" \
    "${completeness[@]}" --github-output "${GITHUB_OUTPUT:?GitHub output file required}"
}

# Standalone invocation uses the same bounded pipeline as the workflow callback.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  component_diff() {
    timeout 30s git diff --no-ext-diff --no-renames --name-status -z "$1" "$2" -- | head -c 1048577 > "$3"
  }
  collect_components "$@"
fi

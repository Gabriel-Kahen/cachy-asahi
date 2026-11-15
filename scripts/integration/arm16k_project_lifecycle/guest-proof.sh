#!/usr/bin/bash
# SPDX-License-Identifier: MIT
set -eu
nonce=$(cat /etc/arm16k-project-lifecycle-nonce)
[[ $nonce =~ ^[0-9a-f]{32}$ && $(id -u) == 1000 ]]
for ((attempt=0; attempt<120; attempt++));do
 if [[ -f /run/arm16k-project-lifecycle/terminal ]];then break;fi
 sleep 2
done
printf '\nARM16K_PROJECT_BEGIN %s\n' "$nonce"
if [[ -f /run/arm16k-project-lifecycle/terminal && $(cat /run/arm16k-project-lifecycle/terminal) == "$nonce" && $(stat --printf='%u:%a' /run/arm16k-project-lifecycle/summary.env) == 0:644 ]];then
 cat /run/arm16k-project-lifecycle/summary.env
else
 printf 'STATUS=HOLD\nFAILED_PHASE=terminal_wait\n'
fi
printf 'ARM16K_PROJECT_END %s\n' "$nonce"
# Preserve the genuine ordinary PAM/systemd session proof and normal logout even
# when the project transaction reports HOLD; the controller checks both scopes.
/usr/local/libexec/arm16k-login-proof-baseline

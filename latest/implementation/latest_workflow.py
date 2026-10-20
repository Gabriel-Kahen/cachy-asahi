# SPDX-License-Identifier: MIT
"""Finite source-owned five-packet workflow over the complete original391 route."""
import latest_plan as P
import latest_selection as S
BASE='expanded604-code/historical/boot391/'
ENTRY='expanded604-code/latest/implementation/latest_run.py'
WFNAME='native-arm-current607-latest-tools'
def one(text,before,after):P.need(text.count(before)==1,'one exact latest607 workflow seam '+before[:80]);return text.replace(before,after,1)
def derive(before,runner,manifest):
 text=before.replace('native-arm-current606-boot607-synthetic',WFNAME).replace('expanded604-code/',BASE)
 text=one(text,BASE+'boot607/run.py --source-preflight',ENTRY+' --source-preflight');text=one(text,BASE+'boot607/run.py --require-selection',ENTRY+' --require-selection')
 # The original old391 stamped runner/manifest still prove the complete held
 # context. Additional top stamps prove the full new closed source before gates.
 anchor='          set -euo pipefail\n          printf'
 extra="          set -euo pipefail\n          printf '%s  %s\\n' '"+runner['sha256']+"' '"+ENTRY+"' '"+manifest['sha256']+"' 'expanded604-code/latest/source-manifest.json' | sha256sum --check\n          printf"
 P.need(text.count(anchor)==1,'one beginning source admission seam');text=text.replace(anchor,extra,1)
 marker='      - name: Checkout fixed legacy public input source\n';blocks=''
 for role,row in S.PACKETS.items():
  if role=='boot':continue
  blocks+='      - name: Checkout exact accepted '+role+' latest tool input DATA\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: '+row['source']+'\n          path: latest607-'+role+'-inputs\n          persist-credentials: false\n'
 operands=' '.join('--'+role+'-packet "$GITHUB_WORKSPACE/'+('boot79-native-inputs'if role=='boot'else'latest607-'+role+'-inputs')+'"'for role in S.PACKETS)
 text=one(text,marker,blocks+'      - name: Latest five source and refusal controls before secrets\n        run: |\n          python3 -I -B '+ENTRY+' --source-preflight\n          python3 -I -B expanded604-code/latest/test_source.py\n'+marker)
 text=one(text,'run: python3 -I -B '+BASE+'boot607/run.py --native-inputs --boot-packet "$GITHUB_WORKSPACE/boot79-native-inputs"','run: python3 -I -B '+ENTRY+' --native-inputs '+operands)
 text=one(text,'python3 -I -B "$GITHUB_WORKSPACE/'+BASE+'boot607/run.py" --boot-packet "$GITHUB_WORKSPACE/boot79-native-inputs"','python3 -I -B "$GITHUB_WORKSPACE/'+ENTRY+'" '+operands)
 text=one(text,'"$GITHUB_WORKSPACE/'+BASE+'boot607/transport.py"','"$GITHUB_WORKSPACE/expanded604-code/latest/implementation/latest_transport.py"')
 text=one(text,'"$GITHUB_WORKSPACE/'+BASE+'scripts/ci/native-evidence-transport/boot607-policy.json"','"$GITHUB_WORKSPACE/expanded604-code/latest/implementation/transport-policy.json"')
 P.need('timeout-minutes: 220'in text and 'timeout-minutes: 115'in text and '6660s'in text and '--kill-after=60s'in text,'whole original job/step/shell/kill bounds held');return text

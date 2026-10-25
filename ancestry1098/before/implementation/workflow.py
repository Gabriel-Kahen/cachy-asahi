# SPDX-License-Identifier: MIT
"""Finite manual-workflow derivation; original producer stages and clocks held."""
import common as C
OLD='.github/workflows/native-arm-expanded604-apps6-public-pair-installer.yml'
ALIASES=('.github/workflows/native-arm-latest607-fresh-installer.yml','.github/workflows/native-arm-build.yml')
CHECKOUT='3d3c42e5aac5ba805825da76410c181273ba90b1'
PREFIX='''      - name: Checkout the current fresh607 source child
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ github.sha }}
          path: fresh607-code
          persist-credentials: false
      - name: Authenticate current child before original library gates or native actors
        shell: bash
        env:
          LIBRARY_SOURCE: ${{ inputs.source }}
          CURRENT_CHILD_SOURCE: ${{ inputs.fresh_source_revision }}
          CURRENT_WORKFLOW_SHA: ${{ github.sha }}
        run: |
          set -euo pipefail
          test "$LIBRARY_SOURCE" = a5bbe8972104512547dc9651c3a8a106d0a1abb4
          [[ "$CURRENT_CHILD_SOURCE" =~ ^[0-9a-f]{40}$ ]]
          test "$CURRENT_CHILD_SOURCE" = "$CURRENT_WORKFLOW_SHA"
          test "$(git -C fresh607-code rev-parse HEAD)" = "$CURRENT_CHILD_SOURCE"
          test "$(sha256sum fresh607-code/source-manifest.json | cut -d ' ' -f 1)" = @FRESH607_MANIFEST@
          python3 -I -B fresh607-code/implementation/run.py --source-preflight
      - name: Checkout issued Root accepted Six853 DATA record
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: eea3f3022c9214deacc60c92dfca13704420756b
          path: fresh607-record
          persist-credentials: false
      - name: Materialize pinned historical input DATA without acquisition or acceptance replay
        shell: bash
        run: |
          set -euo pipefail
          python3 -I -B fresh607-code/implementation/stage_inputs.py --record "$GITHUB_WORKSPACE/fresh607-record" --output "$RUNNER_TEMP/fresh607-input-data"
'''
def derive(raw):
 text=raw.decode();edits=[]
 def one(before,after,count=1):
  nonlocal text
  C.need(text.count(before)==count,'exact old workflow seam '+before[:70]);text=text.replace(before,after);edits.append((before,after,count))
 one('name: native-arm-expanded604-apps6-public-pair-installer','name: native-arm-latest607-fresh-installer')
 one('group: native-arm-expanded604-apps6-public-pair-installer','group: native-arm-latest607-fresh-installer')
 one('description: Exact Root frozen604 installer source; native604 acceptance must be bound','description: Exact original218 installer library; current fresh607 child is github.sha')
 one('      source:\n        description: Exact original218 installer library; current fresh607 child is github.sha\n        required: true','      source:\n        description: Exact original218 installer library; current fresh607 child is github.sha\n        default: a5bbe8972104512547dc9651c3a8a106d0a1abb4\n        required: true')
 one('      mode:\n','      fresh_source_revision:\n        description: Exact current Root published fresh607 child; must equal github.sha\n        required: true\n        type: string\n      mode:\n')
 anchor='      - name: Checkout the separate expanded604 installer implementation\n';one(anchor,PREFIX+anchor)
 # The current workflow/child is separately authenticated above. These held
 # old gates validate the immutable old library's own source/workflow identity.
 one('WORKFLOW_SOURCE: ${{ github.sha }}','WORKFLOW_SOURCE: ${{ inputs.source }}',2)
 one('      - name: Require Root native604 acceptance before any secret or native work','      - name: Require original library source and accepted native604 inputs before native work')
 one('      - name: Required fresh signed604 installation in the separately owned VM','      - name: Required fresh latest607 installation in the separately owned VM')
 one('          AUDIO_INPUTS_OUTCOME: ${{ steps.audio_inputs.outcome }}\n          IMPLEMENTATION_SOURCE:', '          AUDIO_INPUTS_OUTCOME: ${{ steps.audio_inputs.outcome }}\n          FRESH_SOURCE: ${{ inputs.fresh_source_revision }}\n          IMPLEMENTATION_SOURCE:')
 old='python3 -B "$GITHUB_WORKSPACE/expanded604-installer/scripts/ci/expanded604-apps6-public-pair-installer/ci.py" \\\n'
 new='python3 -I -B "$GITHUB_WORKSPACE/fresh607-code/implementation/run.py" \\\n              --six-record "$GITHUB_WORKSPACE/fresh607-record" --six-public "$RUNNER_TEMP/fresh607-input-data" \\\n              --installer604-source "$GITHUB_WORKSPACE/expanded604-installer" --fresh-source-revision "$FRESH_SOURCE" \\\n'
 one(old,new)
 one("scope='generic4K signed604 installer only; no hardware or native-container P0 credit'","scope='generic4K fresh latest607 software installer only; no hardware or native-container P0 credit'")
 inverse=text
 for before,after,count in reversed(edits):C.need(inverse.count(after)==count,'whole workflow inverse');inverse=inverse.replace(after,before)
 C.need(inverse.encode()==raw and all(x in text for x in('timeout-minutes: 350','timeout-minutes: 270','15600s','--kill-after=60s')),'all original stages/permissions/caps held');return text.encode()

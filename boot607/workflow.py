# SPDX-License-Identifier: MIT
"""Finite whole-workflow inverse; original producer/security/clocks stay held."""
import accepted_inputs as A
OLD_LANE='expanded604-code/scripts/ci/current606-apps7-closed-owner'
NEW_LANE='expanded604-code/boot607'
OLD_STAMP="          printf '%s  %s\\n' '73d4d243588ea82c7c4f7398c379121fdb2403c9ed378bb0e63ec2dce11d1875' '"+OLD_LANE+"/owner.py' '2981953cbce68ea341d92449b001de1d1885556c79943babc00acc1da7af696b' '"+OLD_LANE+"/source-manifest.json' | sha256sum --check\n          python3 -B "+OLD_LANE+"/owner.py --source-preflight\n          python3 -B "+OLD_LANE+"/owner.py --require-selection\n"
OLD_PACKET='''      - name: Checkout exact accepted Apps7 and Runtime1 native input pairs
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: 02734c705565868b0b964c48399a4f659fc6f271
          path: apps7-native-pairs
          persist-credentials: false
      - name: Checkout finite accepted606 Root decision DATA
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: 02d28b794c1a297171d82b5718fd98cddacbfa48
          path: current606-decision
          persist-credentials: false
      - name: Source and refusal controls with genuine native DATA only
        env:
          APPS7_PAIR_PACKET: ${{ github.workspace }}/apps7-native-pairs
          CURRENT606_DECISION: ${{ github.workspace }}/current606-decision/decisions/current606-native.json
        run: |
          python3 -I -B expanded604-code/scripts/ci/current606-apps7-closed-owner/test_owner.py
          python3 -I -B expanded604-code/copyworker/scripts/ci/current606-apps7-copy/test_worker.py
      - name: Verify exact accepted native pairs before secrets or producers
        run: python3 -I -B expanded604-code/scripts/ci/current606-apps7-closed-owner/owner.py --native-inputs --apps-packet "$GITHUB_WORKSPACE/apps7-native-pairs"
'''
NEW_PACKET='''      - name: Checkout exact accepted Boot79 unsigned native input DATA
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: 4decb87f5b15f8828cea31e75cbf9e4381feaeaa
          path: boot79-native-inputs
          persist-credentials: false
      - name: Source and finite native Boot refusal controls before secrets
        env:
          BOOT607_INPUT_PACKET: ${{ github.workspace }}/boot79-native-inputs/payload
        run: |
          python3 -I -B expanded604-code/boot607/test_source.py
          python3 -I -B expanded604-code/boot607/test_package_graph.py
          python3 -I -B expanded604-code/boot607/test_accepted_inputs.py
          python3 -I -B expanded604-code/boot607/test_prepare_inputs.py
          python3 -I -B expanded604-code/held606/scripts/ci/current606-native/test_lane.py
          python3 -I -B expanded604-code/boot607/accepted-boot79/packages/tools/cachy-asahi-boot-report/test_boot_report.py
      - name: Verify complete accepted Boot79 native DATA before secrets or producers
        run: python3 -I -B expanded604-code/boot607/run.py --native-inputs --boot-packet "$GITHUB_WORKSPACE/boot79-native-inputs"
'''

def derive(raw,run_pin,manifest_pin):
    text=raw.decode()
    stamp="          printf '%s  %s\\n' '"+run_pin['sha256']+"' '"+NEW_LANE+"/run.py' '"+manifest_pin['sha256']+"' '"+NEW_LANE+"/source-manifest.json' | sha256sum --check\n          python3 -I -B "+NEW_LANE+"/run.py --source-preflight\n          python3 -I -B "+NEW_LANE+"/run.py --require-selection\n"
    edits=[
      ('native-arm-current606-apps7-owned-copy','native-arm-current606-boot607-synthetic',2),
      (OLD_STAMP,stamp,1),
      (OLD_PACKET,NEW_PACKET,1),
      ('python3 -B "$GITHUB_WORKSPACE/'+OLD_LANE+'/owner.py" --apps-packet "$GITHUB_WORKSPACE/apps7-native-pairs"',
       'python3 -I -B "$GITHUB_WORKSPACE/'+NEW_LANE+'/run.py" --boot-packet "$GITHUB_WORKSPACE/boot79-native-inputs"',1),
      ('scripts/ci/native-evidence-transport/apps-policy.json','scripts/ci/native-evidence-transport/boot607-policy.json',1),
      ('expanded604-code/scripts/ci/native-evidence-transport/transport.py','expanded604-code/boot607/transport.py',1),
      ('          python3 -I -B expanded604-code/boot607/test_source.py\n','          python3 -I -B expanded604-code/boot607/test_source.py\n          python3 -I -B expanded604-code/boot607/test_transport.py\n',1),
      ('          CAA_EVIDENCE_SOURCE_SHA: ${{ inputs.source }}\n          CAA_EVIDENCE_WORKFLOW_SHA: ${{ github.sha }}\n','          CAA_EVIDENCE_SOURCE_SHA: ${{ inputs.source }}\n          CAA_EVIDENCE_WORKFLOW_SHA: ${{ github.sha }}\n          CAA_BOOT607_COMPOSITION_OUTCOME: ${{ steps.composition604.outcome }}\n',1),
      ("      - name: Upload original native framed evidence with source-bound transport receipt\n        if: always() && steps.native_public_retention.outcome == 'success'\n        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9\n        timeout-minutes: 5\n        with:\n          name: native-framed-evidence-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.job }}\n          path: ${{ runner.temp }}/native-framed-evidence/\n          retention-days: 3\n          compression-level: 0\n          include-hidden-files: false\n          if-no-files-found: error\n","      - name: Upload original native framed evidence with source-bound transport receipt\n        if: always() && steps.native_public_retention.outcome == 'success'\n        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9\n        timeout-minutes: 5\n        with:\n          name: native-framed-evidence-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.job }}\n          path: ${{ runner.temp }}/native-framed-evidence/\n          retention-days: 3\n          compression-level: 0\n          include-hidden-files: false\n          if-no-files-found: error\n      - name: Upload original Boot607 failure DATA with source-bound transport receipt\n        if: always() && steps.composition604.outcome == 'failure' && steps.native_public_retention.outcome == 'failure'\n        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9\n        timeout-minutes: 5\n        with:\n          name: boot607-failure-data-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.job }}\n          path: ${{ runner.temp }}/native-framed-evidence-failure/\n          retention-days: 3\n          compression-level: 0\n          include-hidden-files: false\n          if-no-files-found: error\n",1),
    ]
    for before,after,count in edits:
        A.need(text.count(before)==count,'exact finite Boot workflow seam')
        text=text.replace(before,after)
    restored=text
    for before,after,count in reversed(edits):
        A.need(restored.count(after)==count,'exact inverse Boot workflow seam')
        restored=restored.replace(after,before)
    A.need(restored.encode()==raw and text.count('--cap-add')==raw.decode().count('--cap-add') and
           '6660s' in text and 'timeout-minutes: 220' in text,'whole original workflow inverse/security/clocks')
    return text.encode()

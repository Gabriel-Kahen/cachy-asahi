#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Closed source-only native-producer/kernel/16K case CI emitter, no actors."""
import argparse,hashlib,json,re
from pathlib import Path
HERE=Path(__file__).resolve().parent
LANE='scripts/ci/apps7-full574-repair16k-ci';BRIDGE='scripts/ci/apps7-full574-repair16k'
WF='.github/workflows/native-arm-apps7-full574-repair16k.yml'
NATIVE_WF='.github/workflows/native-arm-apps-full574-repair.yml'
KERNEL_WF='.github/workflows/native-arm-current604-apps6-updater16k.yml'
OWN=('support.py','owner.py','kernel.py','retain.py','prepare.py','test_ci.py','README.md','borrowed-pins.json','archive32.py','archive32-policy.json','archive20.py','archive20-policy.json','archive8.py','archive8-policy.json')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def replace(text,before,after):need(text.count(before)==1,'one finite CI source seam: '+before[:80]);return text.replace(before,after)
def section(text,start,end):need(text.count(start)==text.count(end)==1,'one fixed kernel section');return text[text.index(start):text.index(end)]
def workflow(native,kernel,owner_sha,manifest_sha):
 text=native.replace('native-arm-apps-full574-repair','native-arm-apps-full574-repair16k')
 text=replace(text,'  group: native-arm-apps-full574-repair16k\n','  group: native-arm-apps-full574-repair16k-${{ inputs.repair_case }}\n')
 text=replace(text,'    timeout-minutes: 120','    timeout-minutes: 350') # New generic16K global profile, original native stays120.
 text=replace(text,'  contents: read\n','  contents: read\n  actions: read\n')
 text=replace(text,'      SLICE: scripts/ci/apps-full574-repair-native','      SLICE: '+LANE)
 text=replace(text,'          python3 -I -B "$SLICE/job.py" proof','          test "$(sha256sum "$SLICE/owner.py" | cut -d \' \' -f 1)" = '+owner_sha+'\n          test "$(sha256sum "$SLICE/source-manifest.json" | cut -d \' \' -f 1)" = '+manifest_sha+'\n          python3 -I -B "$SLICE/owner.py" proof')
 text=replace(text,"-s \"$SLICE\" -p 'test*.py'",'-s "$SLICE" -p test_ci.py')
 anchor='      - name: Seed the six exact retained inputs using existing secrets only\n'
 early='''      - name: Checkout both accepted native-case decisions
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        timeout-minutes: 2
        with:
          ref: ${{ steps.proof.outputs.native_decision_source }}
          path: repair-native-decisions
          persist-credentials: false
      - name: Checkout immutable prior accepted kernel authority
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        timeout-minutes: 2
        with:
          ref: ${{ steps.proof.outputs.kernel_authority_source }}
          path: repair-kernel-authority
          persist-credentials: false
      - name: Verify actual native-case and prior kernel authorities before secrets
        timeout-minutes: 2
        run: >-
          python3 -I -B "$SLICE/owner.py" decisions --case "$REPAIR_CASE" --source "$GITHUB_WORKSPACE"
          --native-decisions "$GITHUB_WORKSPACE/repair-native-decisions"
          --kernel-authority-root "$GITHUB_WORKSPACE/repair-kernel-authority"
          --kernel-authority "$GITHUB_WORKSPACE/repair-kernel-authority/${{ steps.proof.outputs.kernel_authority_path }}"
'''
 text=replace(text,anchor,early+anchor)
 text=replace(text,'python3 -I -B "$SLICE/job.py" check','python3 -I -B "$SLICE/owner.py" check')
 # Producer/signature/export inputs stay exact. Add the existing kernel stages.
 start='      - name: Provision existing accepted kernel tools on the disposable runner\n';end='      - name: Required separate generic16K Apps5→6 current604 copied-root updater case\n';block=section(kernel,start,end)
 block=block.replace('$GITHUB_WORKSPACE/expanded604-upgrade/scripts/ci/current604-apps6-updater16k/kernel_job.py','$GITHUB_WORKSPACE/'+LANE+'/kernel.py').replace('--implementation "$GITHUB_WORKSPACE/expanded604-upgrade" --source "${{ inputs.source }}"','--source "$GITHUB_WORKSPACE"').replace('--case "${{ inputs.case }}"','--case "$REPAIR_CASE"').replace('/tmp/cachy-asahi-apps6-updater16k-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-${{ inputs.case }}','$RUNNER_TEMP/apps574-runtime').replace('updater16k-kernel-','repair16k-kernel-')
 text=replace(text,'      - name: Actual native574 Apps copied-root transactions\n',block+'      - name: Actual generic16K Apps full574 selected repair case\n')
 text=replace(text,'python3 -I -B "$SLICE/supervise.py" run','python3 -I -B "$SLICE/owner.py" run')
 text=replace(text,'          --output "$RUNNER_TEMP/apps574-runtime"\n      - name: Retire all actors', '''          --output "$RUNNER_TEMP/apps574-runtime"
          --native-decisions "$GITHUB_WORKSPACE/repair-native-decisions"
          --kernel-authority "$GITHUB_WORKSPACE/repair-kernel-authority/${{ steps.proof.outputs.kernel_authority_path }}"
          --kernel-work "$RUNNER_TEMP/managed-gui16k-kernel"
          --kernel-receipt "$RUNNER_TEMP/managed-gui16k-kernel/helper/built/build-receipt.json"
      - name: Retire all actors''')
 text=replace(text,'python3 -I -B "$SLICE/supervise.py" cleanup','python3 -I -B "$SLICE/owner.py" cleanup')
 cleanup='''      - name: Retire completed kernel only after original consumer and producer absence
        if: always() && steps.proof.outcome == 'success'
        timeout-minutes: 2
        run: >-
          python3 -I -B "$SLICE/kernel.py" cleanup --source "$GITHUB_WORKSPACE" --case "$REPAIR_CASE"
          --work "$RUNNER_TEMP/managed-gui16k-kernel" --cache "$RUNNER_TEMP/kernel-source-cache/874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad/kernel.tar.gz"
          --output "$RUNNER_TEMP/apps574-runtime" --receipt "$RUNNER_TEMP/repair16k-kernel-cleanup.json"
          --proof "$RUNNER_TEMP/apps574-source-proof.json" --handoff "$RUNNER_TEMP/apps574-repair-job.json"
          --ordered "$RUNNER_TEMP/apps574-cleanup.json" --job-outcome '${{ steps.repair_trial.outcome }}'
'''
 text=replace(text,'      - name: Retain bounded closed actual and failure evidence\n',cleanup+'      - name: Retain bounded closed actual and failure evidence\n')
 text=replace(text,'python3 -I -B "$SLICE/job.py" retain','python3 -I -B "$SLICE/owner.py" retain')
 transport='''      - name: Preserve complete CI kernel and partial failure proof without rewriting originals
        if: always() && steps.proof.outcome == 'success'
        timeout-minutes: 2
        run: >-
          python3 -I -B "$SLICE/retain.py" --source "$GITHUB_WORKSPACE" --source-sha "$SOURCE_SHA" --case "$REPAIR_CASE"
          --public "$RUNNER_TEMP/apps574-public" --proof "$RUNNER_TEMP/apps574-source-proof.json"
          --handoff "$RUNNER_TEMP/apps574-repair-job.json" --ordered "$RUNNER_TEMP/apps574-cleanup.json"
          --metadata "$RUNNER_TEMP/repair16k-kernel-metadata.json" --kernel-cleanup "$RUNNER_TEMP/repair16k-kernel-cleanup.json"
          --acquire "$RUNNER_TEMP/repair16k-kernel-acquisition.json" --seed "$RUNNER_TEMP/repair16k-kernel-seed.json"
          --native-decisions "$GITHUB_WORKSPACE/repair-native-decisions" --kernel-authority-root "$GITHUB_WORKSPACE/repair-kernel-authority"
'''
 text=replace(text,'      - name: Upload only the bounded public evidence directory\n',transport+'      - name: Upload only the bounded public evidence directory\n')
 text=replace(text,'name: apps-full574-repair-${{ github.run_id }}-${{ github.run_attempt }}','name: apps-full574-repair16k-${{ github.run_id }}-${{ github.run_attempt }}-${{ inputs.repair_case }}')
 need('expanded604-upgrade' not in text and '${{ inputs.case }}' not in text and 'blocked' not in text,'no unrelated current604 inputs')
 text=replace(text,'          python3 -B -Werror::ResourceWarning -m unittest discover -s "$SLICE" -p test_ci.py',
  '          python3 -B "$GITHUB_WORKSPACE/'+BRIDGE+'/prepare.py" --template --source "$GITHUB_WORKSPACE" --output "$RUNNER_TEMP/apps7-repair16k-default-controls"\n          python3 -B -Werror::ResourceWarning -m unittest discover -s "$RUNNER_TEMP/apps7-repair16k-default-controls/'+BRIDGE+'" -p test_lane.py -v\n          python3 -B -Werror::ResourceWarning -m unittest discover -s "$SLICE" -p test_ci.py')
 text=text.replace('native-arm-apps-full574-repair16k','native-arm-apps7-full574-repair16k')
 text=replace(text,'  cancel-in-progress: false\n','  queue: max\n  cancel-in-progress: false\n')

 archive32_marker='      - name: Reconstruct pinned inputs and run offline owned native574 transaction\n'
 need(text.count(archive32_marker)==1,'one unchanged native574 build entry')
 text=text.replace(archive32_marker,'      - name: Prefetch and seed exact32 frozen574 bytes before unchanged producer\n        id: frozen574_archive32\n        if: ${{ success() }}\n        timeout-minutes: 4\n        shell: bash\n        run: |\n          set -euo pipefail\n          archive32_helper="$GITHUB_WORKSPACE/scripts/ci/apps7-full574-repair16k-ci/archive32.py"\n          archive32_policy="$GITHUB_WORKSPACE/scripts/ci/apps7-full574-repair16k-ci/archive32-policy.json"\n          archive32_inputs="$GITHUB_WORKSPACE/scripts/ci/maintained-desktop574-inputs.json"\n          printf \'%s  %s\\n\' \'b1e2fc13644510a613ce09e53b39d4f4471cf47fc03fa62f312258379666c418\' "$archive32_helper" \'4f6ce49214422579f1cc448ff95d9f311cbfaf47a0d0c4f32d828c9edf843585\' "$archive32_policy" | sha256sum --check\n          python3 -I -B "$archive32_helper" --policy "$archive32_policy" --inputs "$archive32_inputs" --cache "$RUNNER_TEMP/frozen574-archive32"\n          python3 -I -B - "$archive32_helper" "$archive32_policy" "$archive32_inputs" "$RUNNER_TEMP/frozen574-archive32" "$RUNNER_TEMP/desktop574/context/deps" <<\'PYARCHIVE32\'\n          import importlib.util,sys\n          from pathlib import Path\n          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_archive32_cache_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          result.update(helper=module.pin(helper.read_bytes()),policy=module.pin(policy.read_bytes()),destination=\'EXISTING_OWNED_DESKTOP574_DEPS\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE32\n'+archive32_marker,1)
 text=replace(text,'      - name: Reconstruct pinned inputs and run offline owned native574 transaction\n','      - name: Recover and seed exact20 additional frozen574 files\n        id: frozen574_archive20\n        if: ${{ success() }}\n        timeout-minutes: 4\n        shell: bash\n        run: |\n          set -euo pipefail\n          helper="$GITHUB_WORKSPACE/scripts/ci/apps7-full574-repair16k-ci/archive20.py"\n          policy="$GITHUB_WORKSPACE/scripts/ci/apps7-full574-repair16k-ci/archive20-policy.json"\n          inputs="$GITHUB_WORKSPACE/scripts/ci/maintained-desktop574-inputs.json"\n          printf \'%s  %s\\n\' \'e8ef66fc0431a04deb331f75258457bf4bdeb13a18bcd863fd5bece3b9a54968\' "$helper" \'1f966afe0c24bb9a928154cb0638a8bb78292c799ffd544132633caddf6217ae\' "$policy" | sha256sum --check\n          python3 -I -B "$helper" --policy "$policy" --inputs "$inputs" --cache "$RUNNER_TEMP/frozen574-archive20"\n          python3 -I -B - "$helper" "$policy" "$inputs" "$RUNNER_TEMP/frozen574-archive20" "$RUNNER_TEMP/desktop574/context/deps" <<\'PYARCHIVE20\'\n          import importlib.util,sys\n          from pathlib import Path\n          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_archive20_cache_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          assert result[\'files\']==20 and result[\'bytes\']==2793312\n          result.update(destination=\'EXISTING_OWNED_DESKTOP574_DEPS\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE20\n'+'      - name: Reconstruct pinned inputs and run offline owned native574 transaction\n')
 text=replace(text,'      - name: Reconstruct pinned inputs and run offline owned native574 transaction\n','      - name: Recover and seed exact8 additional frozen574 files\n        id: frozen574_archive8\n        if: ${{ success() }}\n        timeout-minutes: 4\n        shell: bash\n        run: |\n          set -euo pipefail\n          helper="$GITHUB_WORKSPACE/scripts/ci/apps7-full574-repair16k-ci/archive8.py"\n          policy="$GITHUB_WORKSPACE/scripts/ci/apps7-full574-repair16k-ci/archive8-policy.json"\n          inputs="$GITHUB_WORKSPACE/scripts/ci/maintained-desktop574-inputs.json"\n          printf \'%s  %s\\n\' \'5e24808152c727f5dcd19252c66e1ab121bdb9dbd6b90becb943820634898565\' "$helper" \'2b21c05d30a9c5efd2f717cfa8475c9de3150d7729f710b348b70a84f5b16e20\' "$policy" | sha256sum --check\n          python3 -I -B "$helper" --policy "$policy" --inputs "$inputs" --cache "$RUNNER_TEMP/frozen574-archive8"\n          python3 -I -B - "$helper" "$policy" "$inputs" "$RUNNER_TEMP/frozen574-archive8" "$RUNNER_TEMP/desktop574/context/deps" <<\'PYARCHIVE8\'\n          import importlib.util,sys\n          from pathlib import Path\n          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_archive8_cache_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          assert result[\'files\']==8 and result[\'bytes\']==2220315\n          result.update(destination=\'EXISTING_OWNED_DESKTOP574_DEPS\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE8\n      - name: Reconstruct pinned inputs and run offline owned native574 transaction\n')
 return text

def emit(root,output,implementation=None):
 root=Path(root);output=Path(output);implementation=root if implementation is None else Path(implementation);need(implementation.is_dir() and not any(p.is_symlink() for p in (implementation,*implementation.parents)),'ordinary implementation source');need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (root,output,*output.parents)),'fresh ordinary complete source output')
 borrowed=json.loads((HERE/'borrowed-pins.json').read_bytes())['files'];mfpath=root/BRIDGE/'source-manifest.json';bridge_raw=mfpath.read_bytes();rows=json.loads(bridge_raw)['files'];need(0<len(rows)<500,'bounded frozen bridge source')
 rows=dict(rows);rows[BRIDGE+'/source-manifest.json']=pin(bridge_raw)
 sources={name:root for name in rows}
 for name,row in borrowed.items():
  need(name not in rows or rows[name]==row,'borrowed pin collision');sources[name]=root if name in rows else implementation;rows[name]=row
 for name,row in rows.items():
  path=sources[name]/name;need(not any(p.is_symlink() for p in (path,*path.parents)) and path.is_file() and path.stat().st_nlink==1 and pin(path.read_bytes())==row,'closed source differs: '+name)
 output.mkdir(mode=0o700)
 def write(name,raw):p=output/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
 for name in rows:write(name,(sources[name]/name).read_bytes())
 for name in OWN:write(LANE+'/'+name,(HERE/name).read_bytes())
 files={str(p.relative_to(output)):pin(p.read_bytes()) for p in sorted(output.rglob('*')) if p.is_file()};need(len(files)<=512,'complete source bound');mf=encoded(dict(schema_version=1,status='FROZEN_GENERIC16K_REPAIR_CI_SOURCE_ONLY',files=files,native='NOT_RUN',VM='NOT_RUN',hardware='NOT_RUN'));write(LANE+'/source-manifest.json',mf)
 wf=workflow((sources[NATIVE_WF]/NATIVE_WF).read_text(),(sources[KERNEL_WF]/KERNEL_WF).read_text(),pin((HERE/'owner.py').read_bytes())['sha256'],pin(mf)['sha256']).encode();write(WF,wf)
 return dict(status='SOURCE_ONLY_NEW_AUTHORITIES_UNBOUND',source_rows=len(files),source_manifest=pin(mf),workflow=pin(wf),bridge_manifest_unchanged=pin(bridge_raw))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--implementation',type=Path);a=p.parse_args();print(json.dumps(emit(a.source,a.output,a.implementation),sort_keys=True))

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit three whole source roles plus a NULL-by-default closed owner; no Git/actors."""
import argparse,json,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

def workflow(raw,root):
 text=raw.decode();old='native-arm-current606-dns-sysctl2';C.need(text.count(old)==2,'two dedicated identity seams');text=text.replace(old,'native-arm-current606-apps7-owned-copy')
 text=text.replace('expanded604-code/','expanded604-code/held606/').replace('CURRENT604_NATIVE_SOURCE: ${{ github.workspace }}/expanded604-code','CURRENT604_NATIVE_SOURCE: ${{ github.workspace }}/expanded604-code/held606')
 lane='expanded604-code/'+C.LANE
 marker='          set -euo pipefail\n';at=text.index(marker,text.index('id: policy604'))
 insert="          printf '%s  %s\\n' '"+C.pin((root/C.LANE/'owner.py').read_bytes())['sha256']+"' '"+lane+"/owner.py' '"+C.pin((root/C.LANE/'source-manifest.json').read_bytes())['sha256']+"' '"+lane+"/source-manifest.json' | sha256sum --check\n          python3 -B "+lane+"/owner.py --source-preflight\n          python3 -B "+lane+"/owner.py --require-selection\n"
 text=text[:at]+text[at:].replace(marker,marker+insert,1)
 text=text.replace('python3 -B \"$GITHUB_WORKSPACE/expanded604-code/held606/scripts/ci/current606-native/run.py\"','python3 -B \"$GITHUB_WORKSPACE/'+lane+'/owner.py\"')
 # Original standalone hash observation is for its whole-held source. New entry
 # identity is checked above; preserve the original lane's source stamp.
 text=text.replace('sha256sum '+lane+'/owner.py','sha256sum expanded604-code/held606/scripts/ci/current606-native/run.py')
 # One new public native input checkout and complete DATA gate, before secrets.
 marker='      - name: Checkout fixed legacy public input source'
 insert="      - name: Checkout exact accepted Apps7 and Runtime1 native input pairs\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: 54352850a57a7e34e75c3a021fa20525eee59bf6\n          path: apps7-native-pairs\n          persist-credentials: false\n      - name: Checkout finite accepted606 Root decision DATA\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: 02d28b794c1a297171d82b5718fd98cddacbfa48\n          path: current606-decision\n          persist-credentials: false\n      - name: Source and refusal controls with genuine native DATA only\n        env:\n          APPS7_PAIR_PACKET: ${{ github.workspace }}/apps7-native-pairs\n          CURRENT606_DECISION: ${{ github.workspace }}/current606-decision/decisions/current606-native.json\n        run: |\n          python3 -I -B "+lane+"/test_owner.py\n          python3 -I -B expanded604-code/copyworker/scripts/ci/current606-apps7-copy/test_worker.py\n      - name: Verify exact accepted native pairs before secrets or producers\n        run: python3 -I -B "+lane+"/owner.py --native-inputs --apps-packet \"$GITHUB_WORKSPACE/apps7-native-pairs\"\n"
 C.need(text.count(marker)==1,'one original public input seam');text=text.replace(marker,insert+marker)
 command='python3 -B "'+ '$GITHUB_WORKSPACE/'+lane+'/owner.py"'
 C.need(text.count(command)==1,'one actual closed owner CLI');text=text.replace(command,command+' --apps-packet "$GITHUB_WORKSPACE/apps7-native-pairs"')

 archive32_marker='      - name: Required signed604 plus606 additions and restoration lifecycle\n'
 C.need(text.count(archive32_marker)==1,'one unchanged producer entry')
 archive32_start=text.index(archive32_marker);archive32_end=text.find('      - name:',archive32_start+len(archive32_marker))
 if archive32_end<0:archive32_end=len(text)
 archive32_body=text[archive32_start:archive32_end]
 archive32_lines=archive32_body.splitlines(keepends=True);archive32_guards=[n for n,line in enumerate(archive32_lines)if line.startswith('        if: ')]
 C.need(len(archive32_guards)==1,'one original producer condition')
 archive32_index=archive32_guards[0];archive32_guard=archive32_lines[archive32_index]
 C.need(archive32_guard.rstrip().endswith(' }}'),'original producer expression shape')
 archive32_lines[archive32_index]=archive32_guard.rstrip()[:-3]+" && steps.frozen574_archive32.outcome == 'success' }}\n"
 text=text[:archive32_start]+'      - name: Prefetch and seed exact32 frozen574 bytes before unchanged producer\n        id: frozen574_archive32\n        if: ${{ !cancelled() && steps.fdk_pair.outcome == \'success\' && steps.audio_inputs.outcome == \'success\' }}\n        timeout-minutes: 4\n        shell: bash\n        run: |\n          set -euo pipefail\n          archive32_helper="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-apps7-closed-owner/archive32.py"\n          archive32_policy="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-apps7-closed-owner/archive32-policy.json"\n          archive32_inputs="$GITHUB_WORKSPACE/composition-desktop/scripts/ci/maintained-desktop574-inputs.json"\n          printf \'%s  %s\\n\' \'b1e2fc13644510a613ce09e53b39d4f4471cf47fc03fa62f312258379666c418\' "$archive32_helper" \'4f6ce49214422579f1cc448ff95d9f311cbfaf47a0d0c4f32d828c9edf843585\' "$archive32_policy" | sha256sum --check\n          python3 -I -B "$archive32_helper" --policy "$archive32_policy" --inputs "$archive32_inputs" --cache "$RUNNER_TEMP/frozen574-archive32"\n          python3 -I -B - "$archive32_helper" "$archive32_policy" "$archive32_inputs" "$RUNNER_TEMP/frozen574-archive32" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE32\'\n          import importlib.util,sys\n          from pathlib import Path\n          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_archive32_cache_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          result.update(helper=module.pin(helper.read_bytes()),policy=module.pin(policy.read_bytes()),destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE32\n'+''.join(archive32_lines)+text[archive32_end:]
 return text

def emit(inputs,output,selection=None):
 C.need(set(inputs)==set(C.ROLES),'three explicit source roots');C.need(output.is_absolute()and output.parent.is_dir()and not output.exists()and not any(p.is_symlink()for p in(output,*output.parents)),'fresh ordinary output')
 rows=C.read(C.HERE/'source-pins.json')
 for role,home in inputs.items():
  C.need(home.is_absolute()and home.is_dir()and not any(p.is_symlink()for p in(home,*home.parents)),'ordinary source root')
  wanted=rows[role]['files'];C.need(C.files(home)==set(wanted),'whole role set before output')
  for n,row in wanted.items():C.checked(home/n,row)
 policy=C.read(C.HERE/'null-policy.json');C.need(policy['status']=='UNBOUND_SOURCE_TEMPLATE'and all(v is None for v in policy['current606'].values()),'default native606 selection NULL')
 if selection is not None:policy=C.authorize(selection)
 output.mkdir(mode=0o700)
 for role,home in inputs.items():
  for n in rows[role]['files']:
   p=output/role/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(home/n,p)
 lane=output/C.LANE;lane.mkdir(parents=True)
 for p in C.HERE.iterdir():
  if p.is_file()and p.name not in('input-policy.json','source-manifest.json'):shutil.copyfile(p,lane/p.name)
 (lane/'input-policy.json').write_bytes(C.encoded(policy))
 files={p.relative_to(output).as_posix():C.pin(p.read_bytes())for p in sorted(output.rglob('*'))if p.is_file()}
 (lane/'source-manifest.json').write_bytes(C.encoded(dict(schema_version=1,status='CLOSED_SOURCE_ONLY_CURRENT606_APPS7_NOT_NATIVE',files=files,actual_source=None,actual_ref=None,actual_run=None)))
 text=workflow((inputs['held606']/'.github/workflows/native-arm-build.yml').read_bytes(),output)
 wf=output/'.github/workflows/native-arm-current606-apps7-owned-copy.yml';wf.parent.mkdir(parents=True);wf.write_text(text);shutil.copyfile(wf,wf.with_name('native-arm-build.yml'))
 return {p.relative_to(output).as_posix():C.pin(p.read_bytes())for p in sorted(output.rglob('*'))if p.is_file()}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in C.ROLES:p.add_argument('--'+n+'-source',type=Path,required=True)
 p.add_argument('--selection',type=Path);p.add_argument('--output',type=Path,required=True);p.add_argument('--authorization',type=Path,required=True);a=p.parse_args()
 a.authorization.write_bytes(C.encoded(emit({n:getattr(a,n+'_source').absolute()for n in C.ROLES},a.output.absolute(),None if a.selection is None else C.read(a.selection))))

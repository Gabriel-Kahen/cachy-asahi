#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit four whole source roles plus a NULL-by-default closed owner; no Git/actors."""
import argparse,json,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

TRANSPORT_PINS={'transport.py': {'bytes': 17577, 'sha256': 'f5e9074a13d321be2ef0ce1cb034de1278f88cc9cf484cd36a330fae6b65d0f1'}, 'welcome-policy.json': {'bytes': 438, 'sha256': '89d089a93c73589a2b407c03fe6522b4d7c26fb93e56f12fd72a94886cc93bb8'}}

def durable_workflow(raw):
 text=raw.decode();old='      - name: Retain the separate bounded604 public closure and lifecycle\n        if: always()\n';new='      - name: Retain the separate bounded604 public closure and lifecycle\n        id: native_public_retention\n        if: always()\n        env:\n          CAA_EVIDENCE_SOURCE_SHA: ${{ inputs.source }}\n          CAA_EVIDENCE_WORKFLOW_SHA: ${{ github.sha }}\n';assert text.count(old)==1;text=text.replace(old,new)
 before='''          for packet in "$RUNNER_TEMP/expanded604-public"/part-*; do
            python3 -B scripts/ci/log_evidence.py "$packet"
          done
'''
 after='''          python3 -I -B "$GITHUB_WORKSPACE/expanded604-code/scripts/ci/native-evidence-transport/transport.py" \\
            --policy "$GITHUB_WORKSPACE/expanded604-code/scripts/ci/native-evidence-transport/welcome-policy.json" \\
            --packets "$RUNNER_TEMP/expanded604-public" \\
            --encoder "$GITHUB_WORKSPACE/scripts/ci/log_evidence.py" \\
            --output "$RUNNER_TEMP/native-framed-evidence"
      - name: Upload original native framed evidence with source-bound transport receipt
        if: always() && steps.native_public_retention.outcome == 'success'
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9
        timeout-minutes: 5
        with:
          name: native-framed-evidence-${{ github.run_id }}-${{ github.run_attempt }}-${{ github.job }}
          path: ${{ runner.temp }}/native-framed-evidence/
          retention-days: 3
          compression-level: 0
          include-hidden-files: false
          if-no-files-found: error
'''
 assert text.count(before)==1;text=text.replace(before,after);assert text.replace(after,before).replace(new,old).encode()==raw;return text

def workflow(raw,root):
 text=raw.decode();old='native-arm-current606-dns-sysctl2';C.need(text.count(old)==2,'two dedicated identity seams');text=text.replace(old,'native-arm-current606-welcome5-owned-copy')
 text=text.replace('expanded604-code/','expanded604-code/held606/').replace('CURRENT604_NATIVE_SOURCE: ${{ github.workspace }}/expanded604-code','CURRENT604_NATIVE_SOURCE: ${{ github.workspace }}/expanded604-code/held606')
 lane='expanded604-code/'+C.LANE
 marker='          set -euo pipefail\n';at=text.index(marker,text.index('id: policy604'))
 insert="          printf '%s  %s\\n' '"+C.pin((root/C.LANE/'owner.py').read_bytes())['sha256']+"' '"+lane+"/owner.py' '"+C.pin((root/C.LANE/'source-manifest.json').read_bytes())['sha256']+"' '"+lane+"/source-manifest.json' | sha256sum --check\n          python3 -B "+lane+"/owner.py --source-preflight\n          python3 -B "+lane+"/owner.py --require-selection\n"
 text=text[:at]+text[at:].replace(marker,marker+insert,1)
 text=text.replace('python3 -B \"$GITHUB_WORKSPACE/expanded604-code/held606/scripts/ci/current606-native/run.py\"','python3 -B \"$GITHUB_WORKSPACE/'+lane+'/owner.py\"')
 # Original standalone hash observation is for its whole-held source. New entry
 # identity is checked above; preserve the original lane's source stamp.
 text=text.replace('sha256sum '+lane+'/owner.py','sha256sum expanded604-code/held606/scripts/ci/current606-native/run.py')
 old_audio='python3 -B expanded604-legacy/scripts/ci/full-development-composition/retrieve_audio.py --output'
 C.need(text.count(old_audio)==1,'one original fixed audio retrieval entry')
 text=text.replace(old_audio,'python3 -B '+lane+'/owner.py --retrieve-audio --output')

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
 text=text[:archive32_start]+'      - name: Prefetch and seed exact32 frozen574 bytes before unchanged producer\n        id: frozen574_archive32\n        if: ${{ !cancelled() && steps.fdk_pair.outcome == \'success\' && steps.audio_inputs.outcome == \'success\' }}\n        timeout-minutes: 4\n        shell: bash\n        run: |\n          set -euo pipefail\n          archive32_helper="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-welcome5-closed-owner/archive32.py"\n          archive32_policy="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-welcome5-closed-owner/archive32-policy.json"\n          archive32_inputs="$GITHUB_WORKSPACE/composition-desktop/scripts/ci/maintained-desktop574-inputs.json"\n          printf \'%s  %s\\n\' \'b1e2fc13644510a613ce09e53b39d4f4471cf47fc03fa62f312258379666c418\' "$archive32_helper" \'4f6ce49214422579f1cc448ff95d9f311cbfaf47a0d0c4f32d828c9edf843585\' "$archive32_policy" | sha256sum --check\n          python3 -I -B "$archive32_helper" --policy "$archive32_policy" --inputs "$archive32_inputs" --cache "$RUNNER_TEMP/frozen574-archive32"\n          python3 -I -B - "$archive32_helper" "$archive32_policy" "$archive32_inputs" "$RUNNER_TEMP/frozen574-archive32" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE32\'\n          import importlib.util,sys\n          from pathlib import Path\n          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_archive32_cache_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          result.update(helper=module.pin(helper.read_bytes()),policy=module.pin(policy.read_bytes()),destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE32\n'+''.join(archive32_lines)+text[archive32_end:]

 early_marker='      - name: Build the fresh native base and original package pairs\n'
 C.need(text.count(early_marker)==1,'one unchanged original native base build')
 text=text.replace(early_marker,'      - name: Checkout the exact frozen574 lock before native base recovery\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: 9a2e520dbdfce7e4af417595ff3de9e6a284ef04\n          path: archive32-original-lock\n          persist-credentials: false\n      - name: Recover exact32 frozen inputs before the original native base\n        id: nativebase_archive32\n        if: ${{ success() }}\n        timeout-minutes: 4\n        shell: bash\n        run: |\n          set -euo pipefail\n          archive32_helper="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-welcome5-closed-owner/archive32.py"\n          archive32_policy="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-welcome5-closed-owner/archive32-policy.json"\n          archive32_inputs="$GITHUB_WORKSPACE/archive32-original-lock/scripts/ci/maintained-desktop574-inputs.json"\n          printf \'%s  %s\\n\' \'b1e2fc13644510a613ce09e53b39d4f4471cf47fc03fa62f312258379666c418\' "$archive32_helper" \'4f6ce49214422579f1cc448ff95d9f311cbfaf47a0d0c4f32d828c9edf843585\' "$archive32_policy" | sha256sum --check\n          python3 -I -B "$archive32_helper" --policy "$archive32_policy" --inputs "$archive32_inputs" --cache "$RUNNER_TEMP/frozen574-archive32"\n          python3 -I -B - "$archive32_helper" "$archive32_policy" "$archive32_inputs" "$RUNNER_TEMP/frozen574-archive32" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE32\'\n          import importlib.util,sys\n          from pathlib import Path\n          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_archive32_cache_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          result.update(helper=module.pin(helper.read_bytes()),policy=module.pin(policy.read_bytes()),destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE32\n'+early_marker,1)

 archive6_marker='      - name: Prefetch and seed exact32 frozen574 bytes before unchanged producer\n'
 C.need(text.count(archive6_marker)==1,'one exact late archive32 source step')
 archive6_start=text.index(archive6_marker);archive6_end=text.index('      - name:',archive6_start+len(archive6_marker))
 text=text[:archive6_end]+'          archive6_helper="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-welcome5-closed-owner/archive6.py"\n          archive6_policy="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-welcome5-closed-owner/archive6-policy.json"\n          archive6_inputs="$GITHUB_WORKSPACE/composition-updater/scripts/port/updater-extension/builder-extension.lock.json"\n          printf \'%s  %s\\n\' \'5e448ef6677fc26485e044b3ac2d35a07105703d4f1a719bb7c030678eff87ae\' "$archive6_helper" \'4d83dbda592b8b6575d02df65de829226cae3ddffc7268e3d47873ac83f3b322\' "$archive6_policy" | sha256sum --check\n          python3 -I -B "$archive6_helper" --policy "$archive6_policy" --inputs "$archive6_inputs" --cache "$RUNNER_TEMP/frozen-updater-archive6"\n          python3 -I -B - "$archive6_helper" "$archive6_policy" "$archive6_inputs" "$RUNNER_TEMP/frozen-updater-archive6" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE6\'\n          import importlib.util,sys\n          from pathlib import Path\n          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_updater_archive6_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          result.update(helper=module.pin(helper.read_bytes()),policy=module.pin(policy.read_bytes()),destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE6\n'+text[archive6_end:]
 return durable_workflow(extra8_workflow(extra20_workflow(text,root)).encode())


def extra20_workflow(text,root):
 archive20_early_marker='      - name: Build the fresh native base and original package pairs\n'
 C.need(text.count(archive20_early_marker)==1,'one original native-base entry for exact4 seed')
 archive20_early='''      - name: Prefetch full20 original frozen574 and seed only exact4 native-base files
        id: frozen574_archive20_early
        if: ${{ success() && inputs.mode == 'build' }}
        timeout-minutes: 4
        shell: bash
        run: |
          set -euo pipefail
          archive20_owner="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-welcome5-closed-owner"
          archive20_helper="$archive20_owner/archive20.py"
          archive20_policy="$archive20_owner/archive20-policy.json"
          archive20_inputs="$GITHUB_WORKSPACE/archive32-original-lock/scripts/ci/maintained-desktop574-inputs.json"
          printf '%s  %s\\n' 'e8ef66fc0431a04deb331f75258457bf4bdeb13a18bcd863fd5bece3b9a54968' "$archive20_helper" '1f966afe0c24bb9a928154cb0638a8bb78292c799ffd544132633caddf6217ae' "$archive20_policy" | sha256sum --check
          python3 -I -B "$archive20_helper" --policy "$archive20_policy" --inputs "$archive20_inputs" --cache "$RUNNER_TEMP/frozen574-archive20"
          python3 -I -B - "$archive20_owner/prepare.py" "$archive20_helper" "$archive20_policy" "$archive20_inputs" "$GITHUB_WORKSPACE/scripts/ci/inputs.lock.json" "$RUNNER_TEMP/frozen574-archive20" "$RUNNER_TEMP/alarm-cache" <<'PYARCHIVE20NATIVE'
          import importlib.util,sys
          from pathlib import Path
          prepare,helper,policy,inputs,native,cache,destination=map(Path,sys.argv[1:])
          sys.path.insert(0,str(prepare.parent))
          spec=importlib.util.spec_from_file_location('source_owned_archive20_native4',prepare)
          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
          print(module.C.encoded(module.seed_archive20_native(helper,policy,inputs,native,cache,destination)).decode(),end='')
          PYARCHIVE20NATIVE
'''
 text=text.replace(archive20_early_marker,archive20_early+archive20_early_marker,1)
 archive20_marker='      - name: Required signed604 plus606 additions and restoration lifecycle\n'
 C.need(text.count(archive20_marker)==1,'one unchanged producer entry for full20 seed')
 archive20_late='''      - name: Prefetch and seed full20 original frozen574 files before unchanged producer
        id: frozen574_archive20
        if: ${{ !cancelled() && steps.frozen574_archive32.outcome == 'success' }}
        timeout-minutes: 4
        shell: bash
        run: |
          set -euo pipefail
          archive20_helper="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-welcome5-closed-owner/archive20.py"
          archive20_policy="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-welcome5-closed-owner/archive20-policy.json"
          archive20_inputs="$GITHUB_WORKSPACE/composition-desktop/scripts/ci/maintained-desktop574-inputs.json"
          printf '%s  %s\\n' 'e8ef66fc0431a04deb331f75258457bf4bdeb13a18bcd863fd5bece3b9a54968' "$archive20_helper" '1f966afe0c24bb9a928154cb0638a8bb78292c799ffd544132633caddf6217ae' "$archive20_policy" | sha256sum --check
          python3 -I -B "$archive20_helper" --policy "$archive20_policy" --inputs "$archive20_inputs" --cache "$RUNNER_TEMP/frozen574-archive20"
          python3 -I -B - "$archive20_helper" "$archive20_policy" "$archive20_inputs" "$RUNNER_TEMP/frozen574-archive20" "$RUNNER_TEMP/alarm-cache" <<'PYARCHIVE20'
          import importlib.util,sys
          from pathlib import Path
          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])
          spec=importlib.util.spec_from_file_location('held_archive20_full_seed',helper)
          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
          result=module.seed_exact(cache,destination,module.policy(policy,inputs))
          print(module.encoded(result).decode(),end='')
          PYARCHIVE20
'''
 # Require successful full20 before the exact old producer command may start.
 start=text.index(archive20_marker);end=text.find('      - name:',start+len(archive20_marker));end=len(text)if end<0 else end
 body=text[start:end];lines=body.splitlines(keepends=True);conditions=[i for i,line in enumerate(lines)if line.startswith('        if: ')];C.need(len(conditions)==1,'one original full574 producer condition');i=conditions[0];old=lines[i];C.need(old.rstrip().endswith(' }}'),'original producer expression');lines[i]=old.rstrip()[:-3]+" && steps.frozen574_archive20.outcome == 'success' }}\n"
 text=text[:start]+archive20_late+''.join(lines)+text[end:]
 return text

def extra8_workflow(text):
 early='      - name: Build the fresh native base and original package pairs\n';late='      - name: Required signed604 plus606 additions and restoration lifecycle\n'
 C.need(text.count(early)==text.count(late)==1,'exact original eight-input insertion seams')
 text=text.replace(early,'      - name: Recover and seed exact8 additional native-base inputs\n        id: frozen574_archive8_early\n        if: ${{ success() && inputs.mode == \'build\' }}\n        timeout-minutes: 4\n        shell: bash\n        run: |\n          set -euo pipefail\n          archive8_helper="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-welcome5-closed-owner/archive8.py"\n          archive8_policy="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-welcome5-closed-owner/archive8-policy.json"\n          archive8_inputs="$GITHUB_WORKSPACE/archive32-original-lock/scripts/ci/maintained-desktop574-inputs.json"\n          printf \'%s  %s\\n\' \'5e24808152c727f5dcd19252c66e1ab121bdb9dbd6b90becb943820634898565\' "$archive8_helper" \'2b21c05d30a9c5efd2f717cfa8475c9de3150d7729f710b348b70a84f5b16e20\' "$archive8_policy" | sha256sum --check\n          python3 -I -B "$archive8_helper" --policy "$archive8_policy" --inputs "$archive8_inputs" --cache "$RUNNER_TEMP/frozen574-archive8"\n          python3 -I -B - "$archive8_helper" "$archive8_policy" "$archive8_inputs" "$GITHUB_WORKSPACE/scripts/ci/inputs.lock.json" "$RUNNER_TEMP/frozen574-archive8" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE8\'\n          import importlib.util,json,sys\n          from pathlib import Path\n          helper,policy,inputs,native,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'source_owned_archive8_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          raw=module.read(native,1024**2)\n          module.need(module.pin(raw)==dict(bytes=328101,sha256=\'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f\'),\'whole original native input lock\')\n          rows={}\n          for row in json.loads(raw)[\'packages\']:\n           for suffix,size,digest in((\'\',row[\'size\'],row[\'sha256\']),(\'.sig\',row[\'signature_size\'],row[\'signature_sha256\'])):rows[row[\'filename\']+suffix]=dict(bytes=size,sha256=digest)\n          module.need(len(selected[\'files\'])==8 and all(rows.get(n)=={k:r[k]for k in(\'bytes\',\'sha256\')}for n,r in selected[\'files\'].items()),\'all eight exact native and original574 members\')\n          result=module.seed_exact(cache,destination,selected)\n          result.update(destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE8\n'+early,1)
 at=text.index(late);end=text.find('      - name:',at+len(late));end=len(text)if end<0 else end
 lines=text[at:end].splitlines(keepends=True);guards=[i for i,line in enumerate(lines)if line.startswith('        if: ')]
 C.need(len(guards)==1,'one unchanged original producer condition')
 i=guards[0];old=lines[i];C.need(old.rstrip().endswith(' }}'),'original producer expression')
 lines[i]=old.rstrip()[:-3]+" && steps.frozen574_archive8.outcome == 'success' }}\n"
 return text[:at]+'      - name: Recover and seed exact8 additional original574 inputs\n        id: frozen574_archive8\n        if: ${{ !cancelled() && steps.frozen574_archive20.outcome == \'success\' }}\n        timeout-minutes: 4\n        shell: bash\n        run: |\n          set -euo pipefail\n          archive8_helper="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-welcome5-closed-owner/archive8.py"\n          archive8_policy="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-welcome5-closed-owner/archive8-policy.json"\n          archive8_inputs="$GITHUB_WORKSPACE/composition-desktop/scripts/ci/maintained-desktop574-inputs.json"\n          printf \'%s  %s\\n\' \'5e24808152c727f5dcd19252c66e1ab121bdb9dbd6b90becb943820634898565\' "$archive8_helper" \'2b21c05d30a9c5efd2f717cfa8475c9de3150d7729f710b348b70a84f5b16e20\' "$archive8_policy" | sha256sum --check\n          python3 -I -B "$archive8_helper" --policy "$archive8_policy" --inputs "$archive8_inputs" --cache "$RUNNER_TEMP/frozen574-archive8"\n          python3 -I -B - "$archive8_helper" "$archive8_policy" "$archive8_inputs" "$GITHUB_WORKSPACE/scripts/ci/inputs.lock.json" "$RUNNER_TEMP/frozen574-archive8" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE8\'\n          import importlib.util,json,sys\n          from pathlib import Path\n          helper,policy,inputs,native,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'source_owned_archive8_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          result.update(destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE8\n'+''.join(lines)+text[end:]

ARCHIVE20_NATIVE4={'libei-1.6.0-1-aarch64.pkg.tar.xz','libei-1.6.0-1-aarch64.pkg.tar.xz.sig','libgudev-238-3-aarch64.pkg.tar.xz','libgudev-238-3-aarch64.pkg.tar.xz.sig'}
def seed_archive20_native(helper,policy,inputs,native_inputs,cache,destination):
 """Full20 cache custody; exactly four native-base files copied, never full20 credit."""
 import ast,importlib.util
 raw=Path(helper).read_bytes();C.need(C.pin(raw)==dict(bytes=11096,sha256='e8ef66fc0431a04deb331f75258457bf4bdeb13a18bcd863fd5bece3b9a54968'),'whole archive20 helper source')
 C.need(C.pin(Path(policy).read_bytes())==dict(bytes=6155,sha256='1f966afe0c24bb9a928154cb0638a8bb78292c799ffd544132633caddf6217ae'),'whole archive20 policy source')
 spec=importlib.util.spec_from_file_location('_archive20_native_subset',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);v=module.policy(policy,inputs)
 native_raw=module.read(native_inputs,1024**2);module.need(module.pin(native_raw)==dict(bytes=328101,sha256='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'),'whole original native-base lock')
 native={}
 for row in json.loads(native_raw)['packages']:
  native[row['filename']]=dict(bytes=row['size'],sha256=row['sha256']);native[row['filename']+'.sig']=dict(bytes=row['signature_size'],sha256=row['signature_sha256'])
 selected={n:r for n,r in v['files'].items()if n in native};module.need(set(selected)==ARCHIVE20_NATIVE4 and all({k:r[k]for k in('bytes','sha256')}==native[n]for n,r in selected.items()),'exact4 native-base intersection of whole20; no other files')
 module.checked_index(cache,v)
 for n,row in v['files'].items():module.digest_file(Path(cache)/n,row)
 # Derive only the original exact copy loop's finite iterable and honest receipt.
 tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='seed_exact');old=ast.get_source_segment(raw.decode(),node)
 before="for name,row in v['files'].items():";after='for name,row in selected.items():';module.need(old.count(before)==1,'one original exact seed loop')
 receipt="return dict(status='EXACT_ORIGINAL20_SEEDED_BEFORE_UNCHANGED_BUILD',files=20,bytes=TOTAL,original_inputs=v['original_inputs'])"
 replacement="return dict(status='EXACT_NATIVE_BASE4_FROM_ARCHIVE20_SEEDED_NOT_FULL20',files=4,bytes=sum(r['bytes']for r in selected.values()),original_inputs=v['original_inputs'])"
 module.need(old.count(receipt)==1,'one original seed receipt');new=old.replace(before,after).replace(receipt,replacement);module.need(new.replace(after,before).replace(replacement,receipt)==old,'whole seed function inverse')
 space=dict(vars(module),selected=selected);exec(compile(new,'<source-owned-exact4-archive20-subset>','exec'),space)
 return space['seed_exact'](cache,destination,v)

def emit(inputs,output,selection=None):
 C.need(set(inputs)==set(C.ROLES),'four explicit source roots');C.need(output.is_absolute()and output.parent.is_dir()and not output.exists()and not any(p.is_symlink()for p in(output,*output.parents)),'fresh ordinary output')
 rows=C.read(C.HERE/'source-pins.json')
 for role,home in inputs.items():
  C.need(home.is_absolute()and home.is_dir()and not any(p.is_symlink()for p in(home,*home.parents)),'ordinary source root')
  wanted=rows[role]['files'];C.need({p.relative_to(home).as_posix()for p in home.rglob('*')if p.is_file()}==set(wanted),'whole role set before output')
  for n,row in wanted.items():C.checked(home/n,row)
 policy=C.read(C.HERE/'input-policy.json');C.need(policy['status']=='UNBOUND_SOURCE_TEMPLATE'and all(v is None for v in policy['current606'].values()),'default native606 selection NULL')
 if selection is not None:policy=C.authorize(selection)
 output.mkdir(mode=0o700)
 for role,home in inputs.items():
  for n in rows[role]['files']:
   p=output/role/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(home/n,p)
 for n,row in TRANSPORT_PINS.items():
  source=C.HERE.parent/'native-evidence-transport'/n;C.checked(source,row);dest=output/'scripts/ci/native-evidence-transport'/n;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest)
 lane=output/C.LANE;lane.mkdir(parents=True)
 for p in C.HERE.iterdir():
  if p.is_file()and p.name not in('input-policy.json','source-manifest.json'):shutil.copyfile(p,lane/p.name)
 (lane/'input-policy.json').write_bytes(C.encoded(policy))
 files={p.relative_to(output).as_posix():C.pin(p.read_bytes())for p in sorted(output.rglob('*'))if p.is_file()}
 (lane/'source-manifest.json').write_bytes(C.encoded(dict(schema_version=1,status='CLOSED_SOURCE_ONLY_CURRENT606_WELCOME5_NOT_NATIVE',files=files,actual_source=None,actual_ref=None,actual_run=None)))
 text=workflow((inputs['held606']/'.github/workflows/native-arm-build.yml').read_bytes(),output)
 wf=output/'.github/workflows/native-arm-current606-welcome5-owned-copy.yml';wf.parent.mkdir(parents=True);wf.write_text(text);shutil.copyfile(wf,wf.with_name('native-arm-build.yml'))
 return {p.relative_to(output).as_posix():C.pin(p.read_bytes())for p in sorted(output.rglob('*'))if p.is_file()}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in C.ROLES:p.add_argument('--'+n+'-source',type=Path,required=True)
 p.add_argument('--selection',type=Path);p.add_argument('--output',type=Path,required=True);p.add_argument('--authorization',type=Path,required=True);a=p.parse_args()
 a.authorization.write_bytes(C.encoded(emit({n:getattr(a,n+'_source').absolute()for n in C.ROLES},a.output.absolute(),None if a.selection is None else C.read(a.selection))))

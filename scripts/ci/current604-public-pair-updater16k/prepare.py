#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit one finite public-pair updater16K source successor; no actors or Git."""
import argparse,ast,hashlib,json,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/current604-apps6-updater16k';NEW='scripts/ci/current604-public-pair-updater16k'
UPDATER='scripts/ci/expanded604-apps6-public-pair-updater'
WF='.github/workflows/native-arm-current604-public-pair-updater16k.yml'
KERNEL='.github/workflows/native-arm-current604-apps6-generic16k.yml'
OWN=('contract.py','adapter.py','producer_diagnostic.py','cap_scope.py','disk.py','guest.py','input-policy.json','policy.json','run.py','vm.py','wiring.py','job.py','kernel_job.py','retain16k.py','prepare.py','freeze_wiring.py','README.md','WIRING.md','source-pins.json','test_lane.py','test_wiring.py','archive32.py','archive32-policy.json','archive6.py','archive6-policy.json','archive20.py','archive20-policy.json','archive8.py','archive8-policy.json')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def read(p):
 need(not any(q.is_symlink() for q in (p,*p.parents)),'ordinary source');s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=16*1024**2,'bounded single-link source');d=p.read_bytes();need(len(d)==s.st_size,'source length drift');return d

def source(root,updater):
 groups=json.loads(read(HERE/'source-pins.json'))['groups'];need(set(groups)=={'original','updater'},'two explicit source roles');blobs={}
 for role,base in (('original',root),('updater',updater)):
  for n,row in groups[role].items():
   need(not n.startswith('/') and all(p not in ('','.','..') for p in n.split('/')),'relative source path');d=read(base/n);need(pin(d)==row,'pinned source differs: '+role+':'+n)
   need(n not in blobs or blobs[n]==d,'source role conflict: '+n);blobs[n]=d
 recipes=json.loads(read(HERE/'source-pins.json'))['runtime_recipe_inputs'];need(len(recipes)==80,'exact complete runtime recipe closure')
 for n,row in recipes.items():need(n in blobs and pin(blobs[n])==row,'closed runtime recipe input differs: '+n)
 need(len(blobs)+len(OWN)+1<=512,'finite combined source');return blobs

def workflow(blobs,output,job,manifest):
 # Reuse only the original closed workflow transformer, never run its CLI/emitter.
 raw=blobs[OLD+'/freeze_wiring.py'];tree=ast.parse(raw);wanted={'need','encoded','pin','one','workflow'}
 nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in wanted];need({n.name for n in nodes}==wanted,'exact held workflow functions')
 text='\n\n'.join(ast.get_source_segment(raw.decode(),n) for n in nodes)
 text=text.replace('current604-apps6-updater16k','current604-public-pair-updater16k').replace('expanded604-apps6-updater','expanded604-apps6-public-pair-updater')
 before="before='b1ea773a32aab27dfbdb78f63877528f3edd9484d5b71877514c73ed51796fa2' if path=='run.py' else '821f2e7e616f313993212103755ab8ed142f5c0886ec58f170193429b89e7354'"
 need(text.count(before)==1,'one finite prior stamp lookup');text=text.replace(before,"before=pin((root/'"+UPDATER+"'/path).read_bytes())['sha256']")
 namespace=dict(LANE=NEW,hashlib=hashlib,json=json);exec(compile(text,'<pinned-closed-public-pair-WF-transformer>','exec'),namespace)
 raw=namespace['workflow'](blobs['.github/workflows/native-arm-expanded604-apps6-public-pair-updater.yml'],blobs[KERNEL],output,job,manifest)
 text=raw.decode();anchor='      - name: Require five actual decisions and frozen installer before input retrieval'
 # The inherited transformer keeps this step and its complete decision gate.
 need(text.count(anchor)==1,'same early five-decision step')
 text=text.replace(anchor,'''      - name: Provision host ext4 test tools on disposable runner
        timeout-minutes: 9
        shell: bash
        run: |
          set -euo pipefail
          timeout --kill-after=10s 180s sudo apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=30 update -qq
          timeout --kill-after=10s 240s sudo env DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=0 -o Acquire::http::Timeout=30 install -y --no-install-recommends e2fsprogs
          command -v mkfs.ext4
          command -v debugfs
          dpkg-query -W e2fsprogs
      - name: Source-only public-pair updater16K controls
        shell: bash
        run: |
          python3 -B -m unittest discover -s expanded604-upgrade/'''+NEW+''' -p 'test_*.py' -v
'''+anchor)

 archive32_marker='      - name: Required separate generic16K Apps5→6 current604 copied-root updater case\n'
 need(text.count(archive32_marker)==1,'one unchanged producer entry')
 archive32_start=text.index(archive32_marker);archive32_end=text.find('      - name:',archive32_start+len(archive32_marker))
 if archive32_end<0:archive32_end=len(text)
 archive32_body=text[archive32_start:archive32_end]
 archive32_lines=archive32_body.splitlines(keepends=True);archive32_guards=[n for n,line in enumerate(archive32_lines)if line.startswith('        if: ')]
 need(len(archive32_guards)==1,'one original producer condition')
 archive32_index=archive32_guards[0];archive32_guard=archive32_lines[archive32_index]
 need(archive32_guard.rstrip().endswith(' }}'),'original producer expression shape')
 archive32_lines[archive32_index]=archive32_guard.rstrip()[:-3]+" && steps.frozen574_archive32.outcome == 'success' }}\n"
 text=text[:archive32_start]+'      - name: Prefetch and seed exact32 frozen574 bytes before unchanged producer\n        id: frozen574_archive32\n        if: ${{ !cancelled() && steps.fdk_pair.outcome == \'success\' && steps.audio_inputs.outcome == \'success\' }}\n        timeout-minutes: 4\n        shell: bash\n        run: |\n          set -euo pipefail\n          archive32_helper="$GITHUB_WORKSPACE/expanded604-upgrade/scripts/ci/current604-public-pair-updater16k/archive32.py"\n          archive32_policy="$GITHUB_WORKSPACE/expanded604-upgrade/scripts/ci/current604-public-pair-updater16k/archive32-policy.json"\n          archive32_inputs="$GITHUB_WORKSPACE/composition-desktop/scripts/ci/maintained-desktop574-inputs.json"\n          printf \'%s  %s\\n\' \'b1e2fc13644510a613ce09e53b39d4f4471cf47fc03fa62f312258379666c418\' "$archive32_helper" \'4f6ce49214422579f1cc448ff95d9f311cbfaf47a0d0c4f32d828c9edf843585\' "$archive32_policy" | sha256sum --check\n          python3 -I -B "$archive32_helper" --policy "$archive32_policy" --inputs "$archive32_inputs" --cache "$RUNNER_TEMP/frozen574-archive32"\n          python3 -I -B - "$archive32_helper" "$archive32_policy" "$archive32_inputs" "$RUNNER_TEMP/frozen574-archive32" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE32\'\n          import importlib.util,sys\n          from pathlib import Path\n          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_archive32_cache_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          result.update(helper=module.pin(helper.read_bytes()),policy=module.pin(policy.read_bytes()),destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE32\n'+''.join(archive32_lines)+text[archive32_end:]

 archive32_early_marker='      - name: Build the fresh native base and original package pairs\n'
 need(text.count(archive32_early_marker)==1,'one unchanged original native base entry')
 text=text.replace(archive32_early_marker,'      - name: Checkout exact original574 archive lock before native base\n        if: ${{ success() && inputs.mode == \'build\' }}\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        timeout-minutes: 2\n        with:\n          ref: 9a2e520dbdfce7e4af417595ff3de9e6a284ef04\n          path: archive32-original-lock\n          persist-credentials: false\n      - name: Prefetch exact original26 native-base plus six extra574 bytes before original build\n        id: frozen574_archive32_early\n        if: ${{ success() && inputs.mode == \'build\' }}\n        timeout-minutes: 4\n        shell: bash\n        run: |\n          set -euo pipefail\n          archive32_helper="$GITHUB_WORKSPACE/expanded604-upgrade/scripts/ci/current604-public-pair-updater16k/archive32.py"\n          archive32_policy="$GITHUB_WORKSPACE/expanded604-upgrade/scripts/ci/current604-public-pair-updater16k/archive32-policy.json"\n          archive32_inputs="$GITHUB_WORKSPACE/archive32-original-lock/scripts/ci/maintained-desktop574-inputs.json"\n          printf \'%s  %s\\n\' \'b1e2fc13644510a613ce09e53b39d4f4471cf47fc03fa62f312258379666c418\' "$archive32_helper" \'4f6ce49214422579f1cc448ff95d9f311cbfaf47a0d0c4f32d828c9edf843585\' "$archive32_policy" | sha256sum --check\n          python3 -I -B - "$archive32_helper" "$archive32_policy" "$archive32_inputs" "$GITHUB_WORKSPACE/scripts/ci/inputs.lock.json" <<\'PYARCHIVE32NATIVE\'\n          import importlib.util,json,sys\n          from pathlib import Path\n          helper,policy,inputs,native_inputs=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_archive32_native_join\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          raw=module.read(native_inputs,1024**2)\n          expected=dict(bytes=328101,sha256=\'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f\')\n          module.need(module.pin(raw)==expected,\'whole original native-base lock required\')\n          native={}\n          for row in json.loads(raw)[\'packages\']:\n              native[row[\'filename\']]=dict(bytes=row[\'size\'],sha256=row[\'sha256\'])\n              native[row[\'filename\']+\'.sig\']=dict(bytes=row[\'signature_size\'],sha256=row[\'signature_sha256\'])\n          files={name:{key:row[key]for key in(\'bytes\',\'sha256\')}for name,row in selected[\'files\'].items()}\n          common={name:row for name,row in files.items()if name in native}\n          extra={name:row for name,row in files.items()if name not in native}\n          expected_extra={\'firefox-157.0.1-1-aarch64.pkg.tar.xz\',\'firefox-157.0.1-1-aarch64.pkg.tar.xz.sig\',\'libnotify-0.8.8-1-aarch64.pkg.tar.xz\',\'libnotify-0.8.8-1-aarch64.pkg.tar.xz.sig\',\'pcsclite-2.5.2-1-aarch64.pkg.tar.xz\',\'pcsclite-2.5.2-1-aarch64.pkg.tar.xz.sig\'}\n          module.need(len(common)==26 and all(native[name]==row for name,row in common.items())and set(extra)==expected_extra,\'exact original26 native-base and six extra574 operands\')\n          print(module.encoded(dict(status=\'EXACT_ORIGINAL_NATIVE26_AND_SIX_EXTRA574_DATA_ONLY\',native_inputs=expected,original574_inputs=selected[\'original_inputs\'],common26=common,extra6=extra,versions=\'UNCHANGED\',trust=\'UNCHANGED_ORIGINAL_CHECKS_REQUIRED\')).decode(),end=\'\')\n          PYARCHIVE32NATIVE\n          python3 -I -B "$archive32_helper" --policy "$archive32_policy" --inputs "$archive32_inputs" --cache "$RUNNER_TEMP/frozen574-archive32"\n          python3 -I -B - "$archive32_helper" "$archive32_policy" "$archive32_inputs" "$RUNNER_TEMP/frozen574-archive32" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE32\'\n          import importlib.util,sys\n          from pathlib import Path\n          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_archive32_cache_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          result.update(helper=module.pin(helper.read_bytes()),policy=module.pin(policy.read_bytes()),destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE32\n'+archive32_early_marker,1)

 archive6_marker='      - name: Prefetch and seed exact32 frozen574 bytes before unchanged producer\n'
 need(text.count(archive6_marker)==1,'one exact late archive32 source step')
 archive6_start=text.index(archive6_marker);archive6_end=text.index('      - name:',archive6_start+len(archive6_marker))
 text=text[:archive6_end]+'          archive6_helper="$GITHUB_WORKSPACE/expanded604-upgrade/scripts/ci/current604-public-pair-updater16k/archive6.py"\n          archive6_policy="$GITHUB_WORKSPACE/expanded604-upgrade/scripts/ci/current604-public-pair-updater16k/archive6-policy.json"\n          archive6_inputs="$GITHUB_WORKSPACE/composition-updater/scripts/port/updater-extension/builder-extension.lock.json"\n          printf \'%s  %s\\n\' \'5e448ef6677fc26485e044b3ac2d35a07105703d4f1a719bb7c030678eff87ae\' "$archive6_helper" \'4d83dbda592b8b6575d02df65de829226cae3ddffc7268e3d47873ac83f3b322\' "$archive6_policy" | sha256sum --check\n          python3 -I -B "$archive6_helper" --policy "$archive6_policy" --inputs "$archive6_inputs" --cache "$RUNNER_TEMP/frozen-updater-archive6"\n          python3 -I -B - "$archive6_helper" "$archive6_policy" "$archive6_inputs" "$RUNNER_TEMP/frozen-updater-archive6" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE6\'\n          import importlib.util,sys\n          from pathlib import Path\n          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_updater_archive6_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          result.update(helper=module.pin(helper.read_bytes()),policy=module.pin(policy.read_bytes()),destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE6\n'+text[archive6_end:]
 archive20_early_marker='      - name: Build the fresh native base and original package pairs\n'
 need(text.count(archive20_early_marker)==1,'one original native-base entry for exact4 seed')
 archive20_early='''      - name: Prefetch full20 original frozen574 and seed only exact4 native-base files
        id: frozen574_archive20_early
        if: ${{ success() && inputs.mode == 'build' }}
        timeout-minutes: 4
        shell: bash
        run: |
          set -euo pipefail
          archive20_owner="$GITHUB_WORKSPACE/expanded604-upgrade/scripts/ci/current604-public-pair-updater16k"
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
          print(module.encoded(module.seed_archive20_native(helper,policy,inputs,native,cache,destination)).decode(),end='')
          PYARCHIVE20NATIVE
'''
 text=text.replace(archive20_early_marker,archive20_early+archive20_early_marker,1)
 archive20_marker='      - name: Required separate generic16K Apps5→6 current604 copied-root updater case\n'
 need(text.count(archive20_marker)==1,'one unchanged producer entry for full20 seed')
 archive20_late='''      - name: Prefetch and seed full20 original frozen574 files before unchanged producer
        id: frozen574_archive20
        if: ${{ !cancelled() && steps.frozen574_archive32.outcome == 'success' }}
        timeout-minutes: 4
        shell: bash
        run: |
          set -euo pipefail
          archive20_helper="$GITHUB_WORKSPACE/expanded604-upgrade/scripts/ci/current604-public-pair-updater16k/archive20.py"
          archive20_policy="$GITHUB_WORKSPACE/expanded604-upgrade/scripts/ci/current604-public-pair-updater16k/archive20-policy.json"
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
 body=text[start:end];lines=body.splitlines(keepends=True);conditions=[i for i,line in enumerate(lines)if line.startswith('        if: ')];need(len(conditions)==1,'one original full574 producer condition');i=conditions[0];old=lines[i];need(old.rstrip().endswith(' }}'),'original producer expression');lines[i]=old.rstrip()[:-3]+" && steps.frozen574_archive20.outcome == 'success' }}\n"
 text=text[:start]+archive20_late+''.join(lines)+text[end:]
 return extra8_workflow(text).encode()

ARCHIVE20_NATIVE4={'libei-1.6.0-1-aarch64.pkg.tar.xz','libei-1.6.0-1-aarch64.pkg.tar.xz.sig','libgudev-238-3-aarch64.pkg.tar.xz','libgudev-238-3-aarch64.pkg.tar.xz.sig'}
def seed_archive20_native(helper,policy,inputs,native_inputs,cache,destination):
 """Full20 cache custody; exactly four native-base files copied, never full20 credit."""
 import ast,importlib.util
 raw=Path(helper).read_bytes();need(pin(raw)==dict(bytes=11096,sha256='e8ef66fc0431a04deb331f75258457bf4bdeb13a18bcd863fd5bece3b9a54968'),'whole archive20 helper source')
 need(pin(Path(policy).read_bytes())==dict(bytes=6155,sha256='1f966afe0c24bb9a928154cb0638a8bb78292c799ffd544132633caddf6217ae'),'whole archive20 policy source')
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


def extra8_workflow(text):
 early='      - name: Build the fresh native base and original package pairs\n';late='      - name: Required separate generic16K Apps5→6 current604 copied-root updater case\n'
 need(text.count(early)==text.count(late)==1,'exact original eight-input insertion seams')
 text=text.replace(early,'      - name: Recover and seed exact8 additional native-base inputs\n        id: frozen574_archive8_early\n        if: ${{ success() && inputs.mode == \'build\' }}\n        timeout-minutes: 4\n        shell: bash\n        run: |\n          set -euo pipefail\n          archive8_helper="$GITHUB_WORKSPACE/expanded604-upgrade/scripts/ci/current604-public-pair-updater16k/archive8.py"\n          archive8_policy="$GITHUB_WORKSPACE/expanded604-upgrade/scripts/ci/current604-public-pair-updater16k/archive8-policy.json"\n          archive8_inputs="$GITHUB_WORKSPACE/archive32-original-lock/scripts/ci/maintained-desktop574-inputs.json"\n          printf \'%s  %s\\n\' \'5e24808152c727f5dcd19252c66e1ab121bdb9dbd6b90becb943820634898565\' "$archive8_helper" \'2b21c05d30a9c5efd2f717cfa8475c9de3150d7729f710b348b70a84f5b16e20\' "$archive8_policy" | sha256sum --check\n          python3 -I -B "$archive8_helper" --policy "$archive8_policy" --inputs "$archive8_inputs" --cache "$RUNNER_TEMP/frozen574-archive8"\n          python3 -I -B - "$archive8_helper" "$archive8_policy" "$archive8_inputs" "$GITHUB_WORKSPACE/scripts/ci/inputs.lock.json" "$RUNNER_TEMP/frozen574-archive8" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE8\'\n          import importlib.util,json,sys\n          from pathlib import Path\n          helper,policy,inputs,native,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'source_owned_archive8_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          raw=module.read(native,1024**2)\n          module.need(module.pin(raw)==dict(bytes=328101,sha256=\'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f\'),\'whole original native input lock\')\n          rows={}\n          for row in json.loads(raw)[\'packages\']:\n           for suffix,size,digest in((\'\',row[\'size\'],row[\'sha256\']),(\'.sig\',row[\'signature_size\'],row[\'signature_sha256\'])):rows[row[\'filename\']+suffix]=dict(bytes=size,sha256=digest)\n          module.need(len(selected[\'files\'])==8 and all(rows.get(n)=={k:r[k]for k in(\'bytes\',\'sha256\')}for n,r in selected[\'files\'].items()),\'all eight exact native and original574 members\')\n          result=module.seed_exact(cache,destination,selected)\n          result.update(destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE8\n'+early,1)
 at=text.index(late);end=text.find('      - name:',at+len(late));end=len(text)if end<0 else end
 lines=text[at:end].splitlines(keepends=True);guards=[i for i,line in enumerate(lines)if line.startswith('        if: ')]
 need(len(guards)==1,'one unchanged original producer condition')
 i=guards[0];old=lines[i];need(old.rstrip().endswith(' }}'),'original producer expression')
 lines[i]=old.rstrip()[:-3]+" && steps.frozen574_archive8.outcome == 'success' }}\n"
 return text[:at]+'      - name: Recover and seed exact8 additional original574 inputs\n        id: frozen574_archive8\n        if: ${{ !cancelled() && steps.frozen574_archive20.outcome == \'success\' }}\n        timeout-minutes: 4\n        shell: bash\n        run: |\n          set -euo pipefail\n          archive8_helper="$GITHUB_WORKSPACE/expanded604-upgrade/scripts/ci/current604-public-pair-updater16k/archive8.py"\n          archive8_policy="$GITHUB_WORKSPACE/expanded604-upgrade/scripts/ci/current604-public-pair-updater16k/archive8-policy.json"\n          archive8_inputs="$GITHUB_WORKSPACE/composition-desktop/scripts/ci/maintained-desktop574-inputs.json"\n          printf \'%s  %s\\n\' \'5e24808152c727f5dcd19252c66e1ab121bdb9dbd6b90becb943820634898565\' "$archive8_helper" \'2b21c05d30a9c5efd2f717cfa8475c9de3150d7729f710b348b70a84f5b16e20\' "$archive8_policy" | sha256sum --check\n          python3 -I -B "$archive8_helper" --policy "$archive8_policy" --inputs "$archive8_inputs" --cache "$RUNNER_TEMP/frozen574-archive8"\n          python3 -I -B - "$archive8_helper" "$archive8_policy" "$archive8_inputs" "$GITHUB_WORKSPACE/scripts/ci/inputs.lock.json" "$RUNNER_TEMP/frozen574-archive8" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE8\'\n          import importlib.util,json,sys\n          from pathlib import Path\n          helper,policy,inputs,native,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'source_owned_archive8_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          result.update(destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE8\n'+''.join(lines)+text[end:]

def emit(root,updater,output):
 blobs=source(root,updater);need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary source output')
 for name in OWN:need(NEW+'/'+name not in blobs,'new namespace collision');blobs[NEW+'/'+name]=read(HERE/name)
 output.mkdir(mode=0o700)
 for n,d in blobs.items():p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(d)
 rows={n:pin(d) for n,d in blobs.items()};mf=encoded(dict(schema_version=1,status='SOURCE_ONLY_UNBOUND',files=rows,native='NOT_RUN',VM='NOT_RUN',hardware='NOT_RUN'));(output/NEW/'source-manifest.json').write_bytes(mf)
 rows[NEW+'/source-manifest.json']=pin(mf);wmf=encoded(dict(schema_version=1,status='FROZEN_SOURCE_ONLY_UNBOUND',files=rows,native='NOT_RUN',VM='NOT_RUN',hardware='NOT_RUN'));(output/NEW/'wiring-source-manifest.json').write_bytes(wmf)
 w=workflow(blobs,output,rows[NEW+'/job.py']['sha256'],pin(wmf)['sha256']);p=output/WF;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(w)
 result=dict(status='SOURCE_ONLY_PUBLIC_PAIR_UPDATER16K_UNBOUND',source_rows=len(rows)-1,wiring_rows=len(rows),workflow=pin(w),cases=['normal','precommit-exit86','postcommit-exit87'],native='UNBOUND',fresh='UNBOUND',updater_actuals='UNBOUND',VM='NOT_RUN',hardware='NOT_RUN');(output/'source-emission.json').write_bytes(encoded(result));return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','updater','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.updater.absolute(),a.output.absolute()),sort_keys=True))

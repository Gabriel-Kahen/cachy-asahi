#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite public-pair composition/fresh/public-assets profile16K source assembly."""
import argparse,hashlib,json,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/current604-apps6-generic16k';NEW='scripts/ci/current604-public-pair-generic16k'
INSTALLER='scripts/ci/expanded604-apps6-public-pair-installer';ASSETS='scripts/ci/current604-public-gui-assets'
WF='.github/workflows/native-arm-current604-public-pair-generic16k.yml'
OWN=('contract.py','adapter.py','ci.py','gate.py','retain.py','context604.py','install604.py','prepare.py','test_lane.py','README.md','source-pins.json','input-policy.json','public-assets-policy.json','keyboard_profile.py','archive32.py','archive32-policy.json','archive6.py','archive6-policy.json','archive20.py','archive20-policy.json','archive8.py','archive8-policy.json')
def need(v,why):
 if not v:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def read(p):
 need(not any(q.is_symlink() for q in (p,*p.parents)),'source aliases refused');s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=16*1024**2,'bounded single-link source');raw=p.read_bytes();need(len(raw)==s.st_size,'source length drift');return raw

def source(source,installer,assets):
 groups=json.loads(read(HERE/'source-pins.json'))['groups'];need(set(groups)=={'original','installer','assets'},'three explicit source roles');rows={}
 for role,root in (('original',source),('installer',installer),('assets',assets)):
  for n,pinrow in groups[role].items():
   need(not n.startswith('/') and all(x not in ('','.','..') for x in n.split('/')),'relative source path')
   # The asset helper's12 unchanged support pins live in the original checkout.
   origin=source if role=='assets' and not n.startswith(ASSETS+'/') else root
   raw=read(origin/n);need(pin(raw)==pinrow,'pinned source differs: '+role+':'+n)
   need(n not in rows or rows[n]==raw,'source roles conflict: '+n);rows[n]=raw
 need(len(rows)+len(OWN)+1<=512,'original finite source cap');return rows

def archive20_checked(path,expected):
 need(pin(read(path))==expected,'exact archive20 helper/policy source pin')

def seed_native20(helper,policy,inputs,native_inputs,cache,destination):
 """Only four exact native-lock members, from freshly verified full20 cache."""
 import importlib.util,os,time,uuid
 helper,policy,inputs,native_inputs,cache,destination=map(Path,(helper,policy,inputs,native_inputs,cache,destination))
 need(all(p.is_absolute()for p in(helper,policy,inputs,native_inputs,cache,destination)),'absolute archive20 operands')
 archive20_checked(helper,dict(bytes=11096,sha256='e8ef66fc0431a04deb331f75258457bf4bdeb13a18bcd863fd5bece3b9a54968'));archive20_checked(policy,dict(bytes=6155,sha256='1f966afe0c24bb9a928154cb0638a8bb78292c799ffd544132633caddf6217ae'))
 spec=importlib.util.spec_from_file_location('_exact_native_archive20',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 selected=module.policy(policy,inputs);raw=module.read(native_inputs,1024**2);expected=dict(bytes=328101,sha256='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f');need(module.pin(raw)==expected,'whole original native-base lock')
 native={}
 for row in json.loads(raw)['packages']:
  for suffix,size,digest in(('',row['size'],row['sha256']),('.sig',row['signature_size'],row['signature_sha256'])):native[row['filename']+suffix]=dict(bytes=size,sha256=digest)
 subset={n:r for n,r in selected['files'].items()if n in native};wanted={n+s for n in('libei-1.6.0-1-aarch64.pkg.tar.xz','libgudev-238-3-aarch64.pkg.tar.xz')for s in('','.sig')}
 need(set(subset)==wanted and all(native[n]=={k:r[k]for k in('bytes','sha256')}for n,r in subset.items()),'exact four native libei/libgudev package/signature operands')
 deadline=time.monotonic()+60;identity=module.cache_root(cache,selected['files']);module.checked_index(cache,selected);target_identity=module.ordinary(destination,True)[:2]
 need(cache!=destination and not(cache.is_relative_to(destination)or destination.is_relative_to(cache)),'disjoint native/archive20 caches')
 for n,r in selected['files'].items():module.digest_file(cache/n,r,deadline)
 for n,r in sorted(subset.items()):
  module.tick(deadline);source=cache/n;before=module.digest_file(source,r,deadline);target=destination/n
  if os.path.lexists(target):module.digest_file(target,r,deadline);continue
  partial=destination/('.archive20-native-'+uuid.uuid4().hex);owned=None
  try:
   fd=os.open(partial,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);st=os.fstat(fd);owned=(st.st_dev,st.st_ino)
   try:
    with os.fdopen(os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb')as inp:
     need((os.fstat(inp.fileno()).st_dev,os.fstat(inp.fileno()).st_ino)==before[:2],'opened native subset source identity')
     while True:
      module.tick(deadline);block=inp.read(1024**2)
      if not block:break
      view=memoryview(block)
      while view:view=view[os.write(fd,view):]
    os.fsync(fd)
   finally:os.close(fd)
   need(module.ordinary(source)==before and module.ordinary(partial)[:2]==owned and module.cache_root(cache,selected['files'])==identity and module.ordinary(destination,True)[:2]==target_identity,'native4 source/cache/destination identity');module.digest_file(partial,r,deadline);os.link(partial,target,follow_symlinks=False);partial.unlink();owned=None
  finally:
   if owned is not None:
    need(module.ordinary(partial)[:2]==owned,'owned native4 partial changed; retained');partial.unlink()
 need(module.cache_root(cache,selected['files'])==identity and module.ordinary(destination,True)[:2]==target_identity,'final native4 cache identities')
 return dict(status='EXACT_ORIGINAL_NATIVE4_SUBSET_SEEDED_FROM_FULL20_NOT_FULL20_SEED',files=4,bytes=sum(r['bytes']for r in subset.values()),native_inputs=expected,original574_inputs=selected['original_inputs'],subset={n:{k:r[k]for k in('bytes','sha256')}for n,r in sorted(subset.items())},whole20_cache='ALL20_FRESHLY_HASHED_AND_INDEX_JOINED',seconds_limit=60,versions='UNCHANGED',signature_and_trust='UNCHANGED_ORIGINAL_CHECKS_REQUIRED')

def archive20_workflow(text):
 """Two bounded acquisition-only steps; original actor commands stay exact."""
 lane='current604-public-pair-generic16k/'+NEW
 variables='''          archive20_helper="$GITHUB_WORKSPACE/OWNER/archive20.py"
          archive20_policy="$GITHUB_WORKSPACE/OWNER/archive20-policy.json"
          archive20_inputs="$GITHUB_WORKSPACE/LOCK"
          printf '%s  %s\\n' 'e8ef66fc0431a04deb331f75258457bf4bdeb13a18bcd863fd5bece3b9a54968' "$archive20_helper" '1f966afe0c24bb9a928154cb0638a8bb78292c799ffd544132633caddf6217ae' "$archive20_policy" | sha256sum --check
          python3 -I -B "$archive20_helper" --policy "$archive20_policy" --inputs "$archive20_inputs" --cache "$RUNNER_TEMP/frozen574-archive20"
'''.replace('OWNER',lane)
 early='''      - name: Prefetch full20 and seed exact native4 before unchanged native base
        id: frozen574_archive20_native
        if: ${{ success() && inputs.mode == 'build' }}
        timeout-minutes: 4
        shell: bash
        run: |
          set -euo pipefail
'''+variables.replace('LOCK','archive32-original-lock/scripts/ci/maintained-desktop574-inputs.json')+'          python3 -I -B "$GITHUB_WORKSPACE/'+lane+'/prepare.py" --seed-native-archive20 "$archive20_helper" "$archive20_policy" "$archive20_inputs" "$GITHUB_WORKSPACE/scripts/ci/inputs.lock.json" "$RUNNER_TEMP/frozen574-archive20" "$RUNNER_TEMP/alarm-cache"\n'
 late='''      - name: Prefetch and seed exact20 frozen574 bytes before unchanged producer
        id: frozen574_archive20
        if: ${{ !cancelled() && steps.frozen574_archive32.outcome == 'success' }}
        timeout-minutes: 4
        shell: bash
        run: |
          set -euo pipefail
'''+variables.replace('LOCK','composition-desktop/scripts/ci/maintained-desktop574-inputs.json')+'''          python3 -I -B - "$archive20_helper" "$archive20_policy" "$archive20_inputs" "$RUNNER_TEMP/frozen574-archive20" "$RUNNER_TEMP/alarm-cache" <<'PYARCHIVE20'
          import importlib.util,sys
          from pathlib import Path
          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])
          spec=importlib.util.spec_from_file_location('held_archive20_cache_seed',helper)
          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
          selected=module.policy(policy,inputs)
          result=module.seed_exact(cache,destination,selected)
          result.update(helper=module.pin(helper.read_bytes()),policy=module.pin(policy.read_bytes()),destination='EXISTING_OWNED_ALARM_CACHE',original_versions='UNCHANGED',original_signature_and_trust_checks='UNCHANGED')
          print(module.encoded(result).decode(),end='')
          PYARCHIVE20
'''
 before=" && steps.frozen574_archive32.outcome == 'success' }}\n";after=" && steps.frozen574_archive32.outcome == 'success' && steps.frozen574_archive20.outcome == 'success' }}\n"
 need(text.count(before)==1,'one unchanged producer condition');text=text.replace(before,after,1)
 native_marker='      - name: Build the fresh native base and original package pairs\n';producer_marker='      - name: Required actual ALPM604 current Welcome4 GUI in the separately owned16384 VM\n'
 need(text.count(native_marker)==text.count(producer_marker)==1,'one native base and one producer insertion')
 return text.replace(native_marker,early+native_marker,1).replace(producer_marker,late+producer_marker,1)

def seed_native8(helper,policy,inputs,native_inputs,cache,destination):
 """All8 exact native-lock members, through the unchanged full8 seed guards."""
 import importlib.util
 helper,policy,inputs,native_inputs,cache,destination=map(Path,(helper,policy,inputs,native_inputs,cache,destination))
 need(all(p.is_absolute()for p in(helper,policy,inputs,native_inputs,cache,destination)),'absolute archive8 operands')
 archive20_checked(helper,dict(bytes=11040,sha256='5e24808152c727f5dcd19252c66e1ab121bdb9dbd6b90becb943820634898565'));archive20_checked(policy,dict(bytes=2589,sha256='2b21c05d30a9c5efd2f717cfa8475c9de3150d7729f710b348b70a84f5b16e20'))
 spec=importlib.util.spec_from_file_location('_exact_native_archive8',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 selected=module.policy(policy,inputs);raw=module.read(native_inputs,1024**2);expected=dict(bytes=328101,sha256='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f');need(module.pin(raw)==expected,'whole original native-base lock')
 native={}
 for row in json.loads(raw)['packages']:
  for suffix,size,digest in(('',row['size'],row['sha256']),('.sig',row['signature_size'],row['signature_sha256'])):native[row['filename']+suffix]=dict(bytes=size,sha256=digest)
 wanted={name+suffix for name in('libx11-1.8.13-2-aarch64.pkg.tar.xz','libxi-1.8.3-1-aarch64.pkg.tar.xz','libxrender-0.9.12-1-aarch64.pkg.tar.xz','libxtst-1.2.5-1-aarch64.pkg.tar.xz')for suffix in('','.sig')}
 need(set(selected['files'])==wanted and all(native.get(n)=={k:r[k]for k in('bytes','sha256')}for n,r in selected['files'].items()),'all exact eight native libx11/libxi/libxrender/libxtst package/signature operands')
 result=module.seed_exact(cache,destination,selected)
 result.update(native_inputs=expected,native_intersection='ALL8_EXACT_ORIGINAL_LOCK_MEMBERS',versions='UNCHANGED',signature_and_trust='UNCHANGED_ORIGINAL_CHECKS_REQUIRED');return result

def archive8_workflow(text):
 """Two separate acquisition-only steps; previous20/32/6 remain whole."""
 lane='current604-public-pair-generic16k/'+NEW
 variables='''          archive8_helper="$GITHUB_WORKSPACE/OWNER/archive8.py"
          archive8_policy="$GITHUB_WORKSPACE/OWNER/archive8-policy.json"
          archive8_inputs="$GITHUB_WORKSPACE/LOCK"
          printf '%s  %s\\n' '5e24808152c727f5dcd19252c66e1ab121bdb9dbd6b90becb943820634898565' "$archive8_helper" '2b21c05d30a9c5efd2f717cfa8475c9de3150d7729f710b348b70a84f5b16e20' "$archive8_policy" | sha256sum --check
          python3 -I -B "$archive8_helper" --policy "$archive8_policy" --inputs "$archive8_inputs" --cache "$RUNNER_TEMP/frozen574-archive8"
'''.replace('OWNER',lane)
 early='''      - name: Prefetch and seed exact8 original native lock bytes before unchanged base
        id: frozen574_archive8_native
        if: ${{ success() && inputs.mode == 'build' }}
        timeout-minutes: 4
        shell: bash
        run: |
          set -euo pipefail
'''+variables.replace('LOCK','archive32-original-lock/scripts/ci/maintained-desktop574-inputs.json')+'          python3 -I -B "$GITHUB_WORKSPACE/'+lane+'/prepare.py" --seed-native-archive8 "$archive8_helper" "$archive8_policy" "$archive8_inputs" "$GITHUB_WORKSPACE/scripts/ci/inputs.lock.json" "$RUNNER_TEMP/frozen574-archive8" "$RUNNER_TEMP/alarm-cache"\n'
 late='''      - name: Prefetch and seed exact8 frozen574 bytes before unchanged producer
        id: frozen574_archive8
        if: ${{ !cancelled() && steps.frozen574_archive20.outcome == 'success' }}
        timeout-minutes: 4
        shell: bash
        run: |
          set -euo pipefail
'''+variables.replace('LOCK','composition-desktop/scripts/ci/maintained-desktop574-inputs.json')+'''          python3 -I -B - "$archive8_helper" "$archive8_policy" "$archive8_inputs" "$RUNNER_TEMP/frozen574-archive8" "$RUNNER_TEMP/alarm-cache" <<'PYARCHIVE8'
          import importlib.util,sys
          from pathlib import Path
          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])
          spec=importlib.util.spec_from_file_location('held_archive8_cache_seed',helper)
          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
          selected=module.policy(policy,inputs)
          result=module.seed_exact(cache,destination,selected)
          result.update(helper=module.pin(helper.read_bytes()),policy=module.pin(policy.read_bytes()),destination='EXISTING_OWNED_ALARM_CACHE',original_versions='UNCHANGED',original_signature_and_trust_checks='UNCHANGED')
          print(module.encoded(result).decode(),end='')
          PYARCHIVE8
'''
 before=" && steps.frozen574_archive20.outcome == 'success' }}\n";after=" && steps.frozen574_archive20.outcome == 'success' && steps.frozen574_archive8.outcome == 'success' }}\n"
 need(text.count(before)==1,'one unchanged producer archive20 condition');text=text.replace(before,after,1)
 native_marker='      - name: Build the fresh native base and original package pairs\n';producer_marker='      - name: Required actual ALPM604 current Welcome4 GUI in the separately owned16384 VM\n'
 need(text.count(native_marker)==text.count(producer_marker)==1,'one native base and one producer insertion')
 return text.replace(native_marker,early+native_marker,1).replace(producer_marker,late+producer_marker,1)

def workflow(raw,rows,ci_sha,mf_sha):
 text=raw.decode()
 for n,new in (('ci.py',ci_sha),('source-manifest.json',mf_sha)):
  old=pin(rows[OLD+'/'+n])['sha256'];need(text.count(old)==1,'original workflow hash marker');text=text.replace(old,new)
 text=text.replace('current604-apps6-generic16k','current604-public-pair-generic16k').replace('apps6_native_source','apps6_authority_source').replace('apps6-native','apps6-authority')
 anchor='--gui-decisions "$GITHUB_WORKSPACE/expanded604-gui-decisions"\n'
 need(text.count(anchor)==1,'one early decisions gate');text=text.replace(anchor,'--gui-decisions "$GITHUB_WORKSPACE/expanded604-gui-decisions" \\\n            --welcome-source "$GITHUB_WORKSPACE/expanded604-welcome-source/payload"\n')
 anchor='      - name: Required actual ALPM604 current Welcome4 GUI in the separately owned16384 VM\n';need(text.count(anchor)==1,"one original VM entry");text=text.replace(anchor,'      - name: Checkout exact original signed QEMU tooling inputs\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        timeout-minutes: 2\n        with:\n          ref: 9c1fa9e6674ce24edb9655a56436d4c5c0985c54\n          path: current604-qemu-tooling\n          persist-credentials: false\n'+anchor)
 env='PYTHONDONTWRITEBYTECODE=1 RUNNER_TEMP="$RUNNER_TEMP" GITHUB_ACTIONS=true RUNNER_ARCH=ARM64';need(text.count(env)==1,"one original clean runtime environment");text=text.replace(env,env+' CACHY_ASAHI_QEMU_TOOLING_INPUTS="$GITHUB_WORKSPACE/current604-qemu-tooling/tooling-inputs"')
 anchor="          for name in ('build_kernel.py','kernel.fragment'):shutil.copyfile(root/'scripts/ci/managed-gui-generic16k'/name,helper/name)\n"
 need(text.count(anchor)==1,'one whole-pinned copied GUI kernel preparation seam')
 text=text.replace(anchor,anchor+"          s.load(root,'scripts/ci/current604-public-pair-generic16k/keyboard_profile.py').prepare_kernel(root,helper)\n")

 archive32_marker='      - name: Required actual ALPM604 current Welcome4 GUI in the separately owned16384 VM\n'
 need(text.count(archive32_marker)==1,'one unchanged producer entry')
 archive32_start=text.index(archive32_marker);archive32_end=text.find('      - name:',archive32_start+len(archive32_marker))
 if archive32_end<0:archive32_end=len(text)
 archive32_body=text[archive32_start:archive32_end]
 archive32_lines=archive32_body.splitlines(keepends=True);archive32_guards=[n for n,line in enumerate(archive32_lines)if line.startswith('        if: ')]
 need(len(archive32_guards)==1,'one original producer condition')
 archive32_index=archive32_guards[0];archive32_guard=archive32_lines[archive32_index]
 need(archive32_guard.rstrip().endswith(' }}'),'original producer expression shape')
 archive32_lines[archive32_index]=archive32_guard.rstrip()[:-3]+" && steps.frozen574_archive32.outcome == 'success' }}\n"
 text=text[:archive32_start]+'      - name: Prefetch and seed exact32 frozen574 bytes before unchanged producer\n        id: frozen574_archive32\n        if: ${{ !cancelled() && steps.fdk_pair.outcome == \'success\' && steps.audio_inputs.outcome == \'success\' }}\n        timeout-minutes: 4\n        shell: bash\n        run: |\n          set -euo pipefail\n          archive32_helper="$GITHUB_WORKSPACE/current604-public-pair-generic16k/scripts/ci/current604-public-pair-generic16k/archive32.py"\n          archive32_policy="$GITHUB_WORKSPACE/current604-public-pair-generic16k/scripts/ci/current604-public-pair-generic16k/archive32-policy.json"\n          archive32_inputs="$GITHUB_WORKSPACE/composition-desktop/scripts/ci/maintained-desktop574-inputs.json"\n          printf \'%s  %s\\n\' \'b1e2fc13644510a613ce09e53b39d4f4471cf47fc03fa62f312258379666c418\' "$archive32_helper" \'4f6ce49214422579f1cc448ff95d9f311cbfaf47a0d0c4f32d828c9edf843585\' "$archive32_policy" | sha256sum --check\n          python3 -I -B "$archive32_helper" --policy "$archive32_policy" --inputs "$archive32_inputs" --cache "$RUNNER_TEMP/frozen574-archive32"\n          python3 -I -B - "$archive32_helper" "$archive32_policy" "$archive32_inputs" "$RUNNER_TEMP/frozen574-archive32" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE32\'\n          import importlib.util,sys\n          from pathlib import Path\n          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_archive32_cache_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          result.update(helper=module.pin(helper.read_bytes()),policy=module.pin(policy.read_bytes()),destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE32\n'+''.join(archive32_lines)+text[archive32_end:]

 archive32_early_marker='      - name: Build the fresh native base and original package pairs\n'
 need(text.count(archive32_early_marker)==1,'one unchanged original native base entry')
 text=text.replace(archive32_early_marker,'      - name: Checkout exact original574 archive lock before native base\n        if: ${{ success() && inputs.mode == \'build\' }}\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        timeout-minutes: 2\n        with:\n          ref: 9a2e520dbdfce7e4af417595ff3de9e6a284ef04\n          path: archive32-original-lock\n          persist-credentials: false\n      - name: Prefetch exact original26 native-base plus six extra574 bytes before original build\n        id: frozen574_archive32_early\n        if: ${{ success() && inputs.mode == \'build\' }}\n        timeout-minutes: 4\n        shell: bash\n        run: |\n          set -euo pipefail\n          archive32_helper="$GITHUB_WORKSPACE/current604-public-pair-generic16k/scripts/ci/current604-public-pair-generic16k/archive32.py"\n          archive32_policy="$GITHUB_WORKSPACE/current604-public-pair-generic16k/scripts/ci/current604-public-pair-generic16k/archive32-policy.json"\n          archive32_inputs="$GITHUB_WORKSPACE/archive32-original-lock/scripts/ci/maintained-desktop574-inputs.json"\n          printf \'%s  %s\\n\' \'b1e2fc13644510a613ce09e53b39d4f4471cf47fc03fa62f312258379666c418\' "$archive32_helper" \'4f6ce49214422579f1cc448ff95d9f311cbfaf47a0d0c4f32d828c9edf843585\' "$archive32_policy" | sha256sum --check\n          python3 -I -B - "$archive32_helper" "$archive32_policy" "$archive32_inputs" "$GITHUB_WORKSPACE/scripts/ci/inputs.lock.json" <<\'PYARCHIVE32NATIVE\'\n          import importlib.util,json,sys\n          from pathlib import Path\n          helper,policy,inputs,native_inputs=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_archive32_native_join\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          raw=module.read(native_inputs,1024**2)\n          expected=dict(bytes=328101,sha256=\'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f\')\n          module.need(module.pin(raw)==expected,\'whole original native-base lock required\')\n          native={}\n          for row in json.loads(raw)[\'packages\']:\n              native[row[\'filename\']]=dict(bytes=row[\'size\'],sha256=row[\'sha256\'])\n              native[row[\'filename\']+\'.sig\']=dict(bytes=row[\'signature_size\'],sha256=row[\'signature_sha256\'])\n          files={name:{key:row[key]for key in(\'bytes\',\'sha256\')}for name,row in selected[\'files\'].items()}\n          common={name:row for name,row in files.items()if name in native}\n          extra={name:row for name,row in files.items()if name not in native}\n          expected_extra={\'firefox-157.0.1-1-aarch64.pkg.tar.xz\',\'firefox-157.0.1-1-aarch64.pkg.tar.xz.sig\',\'libnotify-0.8.8-1-aarch64.pkg.tar.xz\',\'libnotify-0.8.8-1-aarch64.pkg.tar.xz.sig\',\'pcsclite-2.5.2-1-aarch64.pkg.tar.xz\',\'pcsclite-2.5.2-1-aarch64.pkg.tar.xz.sig\'}\n          module.need(len(common)==26 and all(native[name]==row for name,row in common.items())and set(extra)==expected_extra,\'exact original26 native-base and six extra574 operands\')\n          print(module.encoded(dict(status=\'EXACT_ORIGINAL_NATIVE26_AND_SIX_EXTRA574_DATA_ONLY\',native_inputs=expected,original574_inputs=selected[\'original_inputs\'],common26=common,extra6=extra,versions=\'UNCHANGED\',trust=\'UNCHANGED_ORIGINAL_CHECKS_REQUIRED\')).decode(),end=\'\')\n          PYARCHIVE32NATIVE\n          python3 -I -B "$archive32_helper" --policy "$archive32_policy" --inputs "$archive32_inputs" --cache "$RUNNER_TEMP/frozen574-archive32"\n          python3 -I -B - "$archive32_helper" "$archive32_policy" "$archive32_inputs" "$RUNNER_TEMP/frozen574-archive32" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE32\'\n          import importlib.util,sys\n          from pathlib import Path\n          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_archive32_cache_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          result.update(helper=module.pin(helper.read_bytes()),policy=module.pin(policy.read_bytes()),destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE32\n'+archive32_early_marker,1)

 archive6_marker='      - name: Prefetch and seed exact32 frozen574 bytes before unchanged producer\n'
 need(text.count(archive6_marker)==1,'one exact late archive32 source step')
 archive6_start=text.index(archive6_marker);archive6_end=text.index('      - name:',archive6_start+len(archive6_marker))
 text=text[:archive6_end]+'          archive6_helper="$GITHUB_WORKSPACE/current604-public-pair-generic16k/scripts/ci/current604-public-pair-generic16k/archive6.py"\n          archive6_policy="$GITHUB_WORKSPACE/current604-public-pair-generic16k/scripts/ci/current604-public-pair-generic16k/archive6-policy.json"\n          archive6_inputs="$GITHUB_WORKSPACE/composition-updater/scripts/port/updater-extension/builder-extension.lock.json"\n          printf \'%s  %s\\n\' \'5e448ef6677fc26485e044b3ac2d35a07105703d4f1a719bb7c030678eff87ae\' "$archive6_helper" \'4d83dbda592b8b6575d02df65de829226cae3ddffc7268e3d47873ac83f3b322\' "$archive6_policy" | sha256sum --check\n          python3 -I -B "$archive6_helper" --policy "$archive6_policy" --inputs "$archive6_inputs" --cache "$RUNNER_TEMP/frozen-updater-archive6"\n          python3 -I -B - "$archive6_helper" "$archive6_policy" "$archive6_inputs" "$RUNNER_TEMP/frozen-updater-archive6" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE6\'\n          import importlib.util,sys\n          from pathlib import Path\n          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_updater_archive6_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          result.update(helper=module.pin(helper.read_bytes()),policy=module.pin(policy.read_bytes()),destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE6\n'+text[archive6_end:]
 marker='          path: /tmp/cachy-asahi-current604-public-pair-generic16k-${{ github.run_id }}-${{ github.run_attempt }}/public/\n'
 need(text.count(marker)==1,'one existing bounded public upload root')
 text=text.replace(marker,marker+'          include-hidden-files: true\n',1)
 return archive8_workflow(archive20_workflow(text)).encode()

def emit(source_root,installer,assets,output):
 blobs=source(source_root,installer,assets)
 need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary output')
 for n in OWN:need(NEW+'/'+n not in blobs,'new namespace collision');blobs[NEW+'/'+n]=read(HERE/n)
 rows={n:pin(raw) for n,raw in blobs.items()}
 deps=encoded(dict(schema_version=1,files=rows));blobs[NEW+'/dependencies.json']=deps;rows[NEW+'/dependencies.json']=pin(deps)
 manifest=encoded(dict(schema_version=1,status='ROOT_FROZEN_SOURCE_ONLY',files=rows,scope='PUBLIC_PAIRS_APPS6_ONE_PROFILE_NOT_FULL60416K',native='NOT_RUN',hardware='NOT_RUN'))
 blobs[NEW+'/source-manifest.json']=manifest
 raw=blobs['.github/workflows/native-arm-current604-apps6-generic16k.yml'];blobs[WF]=workflow(raw,blobs,rows[NEW+'/ci.py']['sha256'],pin(manifest)['sha256'])
 output.mkdir(mode=0o700)
 for n,raw in blobs.items():p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
 result=dict(status='SOURCE_ONLY_PUBLIC_PAIRS_APPS6_CURRENT604_PROFILE16K_UNBOUND',source_rows=len(rows),workflow=pin(blobs[WF]),profiles=['minimal','overlay'],native='UNBOUND',fresh='UNBOUND',GUI='UNBOUND_SEPARATE_PUBLIC_COMPONENT',full60416K='NOT_ACCEPTED',hardware='NOT_RUN')
 (output/'source-emission.json').write_bytes(encoded(result));return result
if __name__=='__main__':
 import sys
 if sys.argv[1:2]==['--seed-native-archive8']:
  need(len(sys.argv)==8,'six explicit archive8 native seed operands');print(json.dumps(seed_native8(*map(Path,sys.argv[2:])),sort_keys=True));raise SystemExit(0)
 if sys.argv[1:2]==['--seed-native-archive20']:
  need(len(sys.argv)==8,'six explicit archive20 native seed operands');print(json.dumps(seed_native20(*map(Path,sys.argv[2:])),sort_keys=True));raise SystemExit(0)
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','installer','assets','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.installer.absolute(),a.assets.absolute(),a.output.absolute()),sort_keys=True))

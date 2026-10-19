#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact KSM source roles and a NULL default owner; no Git or actors."""
import argparse,json,re,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

def seed_native20(helper,policy,inputs,native_inputs,cache,destination):
 """Only four exact native-lock members, from freshly verified full20 cache."""
 import importlib.util,os,time,uuid
 helper,policy,inputs,native_inputs,cache,destination=map(Path,(helper,policy,inputs,native_inputs,cache,destination))
 C.need(all(p.is_absolute()for p in(helper,policy,inputs,native_inputs,cache,destination)),'absolute archive20 operands')
 C.checked(helper,dict(bytes=11096,sha256='e8ef66fc0431a04deb331f75258457bf4bdeb13a18bcd863fd5bece3b9a54968'));C.checked(policy,dict(bytes=6155,sha256='1f966afe0c24bb9a928154cb0638a8bb78292c799ffd544132633caddf6217ae'))
 spec=importlib.util.spec_from_file_location('_exact_native_archive20',helper);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 selected=module.policy(policy,inputs);raw=module.read(native_inputs,1024**2);expected=dict(bytes=328101,sha256='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f');C.need(module.pin(raw)==expected,'whole original native-base lock')
 native={}
 for row in json.loads(raw)['packages']:
  for suffix,size,digest in(('',row['size'],row['sha256']),('.sig',row['signature_size'],row['signature_sha256'])):native[row['filename']+suffix]=dict(bytes=size,sha256=digest)
 subset={n:r for n,r in selected['files'].items()if n in native};wanted={n+s for n in('libei-1.6.0-1-aarch64.pkg.tar.xz','libgudev-238-3-aarch64.pkg.tar.xz')for s in('','.sig')}
 C.need(set(subset)==wanted and all(native[n]=={k:r[k]for k in('bytes','sha256')}for n,r in subset.items()),'exact four native libei/libgudev package/signature operands')
 deadline=time.monotonic()+60;identity=module.cache_root(cache,selected['files']);module.checked_index(cache,selected);target_identity=module.ordinary(destination,True)[:2]
 C.need(cache!=destination and not(cache.is_relative_to(destination)or destination.is_relative_to(cache)),'disjoint native/archive20 caches')
 for n,r in selected['files'].items():module.digest_file(cache/n,r,deadline)
 for n,r in sorted(subset.items()):
  module.tick(deadline);source=cache/n;before=module.digest_file(source,r,deadline);target=destination/n
  if os.path.lexists(target):module.digest_file(target,r,deadline);continue
  partial=destination/('.archive20-native-'+uuid.uuid4().hex);owned=None
  try:
   fd=os.open(partial,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);st=os.fstat(fd);owned=(st.st_dev,st.st_ino)
   try:
    with os.fdopen(os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb')as inp:
     C.need((os.fstat(inp.fileno()).st_dev,os.fstat(inp.fileno()).st_ino)==before[:2],'opened native subset source identity')
     while True:
      module.tick(deadline);block=inp.read(1024**2)
      if not block:break
      view=memoryview(block)
      while view:view=view[os.write(fd,view):]
    os.fsync(fd)
   finally:os.close(fd)
   C.need(module.ordinary(source)==before and module.ordinary(partial)[:2]==owned and module.cache_root(cache,selected['files'])==identity and module.ordinary(destination,True)[:2]==target_identity,'native4 source/cache/destination identity');module.digest_file(partial,r,deadline);os.link(partial,target,follow_symlinks=False);partial.unlink();owned=None
  finally:
   if owned is not None:
    C.need(module.ordinary(partial)[:2]==owned,'owned native4 partial changed; retained');partial.unlink()
 C.need(module.cache_root(cache,selected['files'])==identity and module.ordinary(destination,True)[:2]==target_identity,'final native4 cache identities')
 return dict(status='EXACT_ORIGINAL_NATIVE4_SUBSET_SEEDED_FROM_FULL20_NOT_FULL20_SEED',files=4,bytes=sum(r['bytes']for r in subset.values()),native_inputs=expected,original574_inputs=selected['original_inputs'],subset={n:{k:r[k]for k in('bytes','sha256')}for n,r in sorted(subset.items())},whole20_cache='ALL20_FRESHLY_HASHED_AND_INDEX_JOINED',seconds_limit=60,versions='UNCHANGED',signature_and_trust='UNCHANGED_ORIGINAL_CHECKS_REQUIRED')

def archive20_workflow(text,root):
 """Two bounded acquisition-only steps; original actor commands stay exact."""
 lane='expanded604-code/'+C.LANE
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
 C.need(text.count(before)==1,'one unchanged producer condition');text=text.replace(before,after,1)
 native_marker='      - name: Build the fresh native base and original package pairs\n';producer_marker='      - name: Required signed604 plus606 additions and restoration lifecycle\n'
 C.need(text.count(native_marker)==text.count(producer_marker)==1,'one native base and one producer insertion')
 return text.replace(native_marker,early+native_marker,1).replace(producer_marker,late+producer_marker,1)

def workflow(raw,root,policy):
 text=raw.decode();old='native-arm-current606-dns-sysctl2';C.need(text.count(old)==2,'two dedicated identity seams');text=text.replace(old,'native-arm-current606-ksm2-owned-copy')
 text=text.replace('expanded604-code/','expanded604-code/held606/').replace('CURRENT604_NATIVE_SOURCE: ${{ github.workspace }}/expanded604-code','CURRENT604_NATIVE_SOURCE: ${{ github.workspace }}/expanded604-code/held606');lane='expanded604-code/'+C.LANE
 marker='          set -euo pipefail\n';at=text.index(marker,text.index('id: policy604'))
 insert="          printf '%s  %s\\n' '"+C.pin((root/C.LANE/'owner.py').read_bytes())['sha256']+"' '"+lane+"/owner.py' '"+C.pin((root/C.LANE/'source-manifest.json').read_bytes())['sha256']+"' '"+lane+"/source-manifest.json' | sha256sum --check\n          python3 -B "+lane+"/owner.py --source-preflight\n          python3 -B "+lane+"/owner.py --require-selection\n"
 text=text[:at]+text[at:].replace(marker,marker+insert,1)
 command='python3 -B "'+ '$GITHUB_WORKSPACE/'+lane+'/owner.py"'
 text=text.replace('python3 -B "$GITHUB_WORKSPACE/expanded604-code/held606/scripts/ci/current606-native/run.py"',command)
 C.need(text.count(command)==1,'one actual closed owner CLI');text=text.replace(command,command+' --ksm-packet "$GITHUB_WORKSPACE/ksm2-native-pairs"')
 text=text.replace('sha256sum '+lane+'/owner.py','sha256sum expanded604-code/held606/scripts/ci/current606-native/run.py')
 marker='      - name: Checkout fixed legacy public input source';C.need(text.count(marker)==1,'one public source seam')
 commands="      - name: Check KSM copy source and NULL authority before actors\n        run: |\n          python3 -B "+lane+"/owner.py --source-preflight\n          python3 -B "+lane+"/owner.py --require-selection\n"
 if policy['native_pair_source']is not None:
  commands+="      - name: Checkout exact published KSM native input DATA\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: "+policy['native_pair_source']+"\n          path: ksm2-native-pairs\n          persist-credentials: false\n      - name: Verify exact accepted KSM pair before secrets\n        run: python3 -B "+lane+"/owner.py --native-inputs --ksm-packet \"$GITHUB_WORKSPACE/ksm2-native-pairs\"\n"
 text=text.replace(marker,commands+marker)
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
 text=text[:archive32_start]+'      - name: Prefetch and seed exact32 frozen574 bytes before unchanged producer\n        id: frozen574_archive32\n        if: ${{ !cancelled() && steps.fdk_pair.outcome == \'success\' && steps.audio_inputs.outcome == \'success\' }}\n        timeout-minutes: 4\n        shell: bash\n        run: |\n          set -euo pipefail\n          archive32_helper="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-ksm2-closed-owner/archive32.py"\n          archive32_policy="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-ksm2-closed-owner/archive32-policy.json"\n          archive32_inputs="$GITHUB_WORKSPACE/composition-desktop/scripts/ci/maintained-desktop574-inputs.json"\n          printf \'%s  %s\\n\' \'b1e2fc13644510a613ce09e53b39d4f4471cf47fc03fa62f312258379666c418\' "$archive32_helper" \'4f6ce49214422579f1cc448ff95d9f311cbfaf47a0d0c4f32d828c9edf843585\' "$archive32_policy" | sha256sum --check\n          python3 -I -B "$archive32_helper" --policy "$archive32_policy" --inputs "$archive32_inputs" --cache "$RUNNER_TEMP/frozen574-archive32"\n          python3 -I -B - "$archive32_helper" "$archive32_policy" "$archive32_inputs" "$RUNNER_TEMP/frozen574-archive32" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE32\'\n          import importlib.util,sys\n          from pathlib import Path\n          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_archive32_cache_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          result.update(helper=module.pin(helper.read_bytes()),policy=module.pin(policy.read_bytes()),destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE32\n'+''.join(archive32_lines)+text[archive32_end:]

 archive32_early_marker='      - name: Build the fresh native base and original package pairs\n'
 C.need(text.count(archive32_early_marker)==1,'one unchanged original native base entry')
 text=text.replace(archive32_early_marker,'      - name: Checkout exact original574 archive lock before native base\n        if: ${{ success() && inputs.mode == \'build\' }}\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        timeout-minutes: 2\n        with:\n          ref: 9a2e520dbdfce7e4af417595ff3de9e6a284ef04\n          path: archive32-original-lock\n          persist-credentials: false\n      - name: Prefetch exact original26 native-base plus six extra574 bytes before original build\n        id: frozen574_archive32_early\n        if: ${{ success() && inputs.mode == \'build\' }}\n        timeout-minutes: 4\n        shell: bash\n        run: |\n          set -euo pipefail\n          archive32_helper="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-ksm2-closed-owner/archive32.py"\n          archive32_policy="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-ksm2-closed-owner/archive32-policy.json"\n          archive32_inputs="$GITHUB_WORKSPACE/archive32-original-lock/scripts/ci/maintained-desktop574-inputs.json"\n          printf \'%s  %s\\n\' \'b1e2fc13644510a613ce09e53b39d4f4471cf47fc03fa62f312258379666c418\' "$archive32_helper" \'4f6ce49214422579f1cc448ff95d9f311cbfaf47a0d0c4f32d828c9edf843585\' "$archive32_policy" | sha256sum --check\n          python3 -I -B - "$archive32_helper" "$archive32_policy" "$archive32_inputs" "$GITHUB_WORKSPACE/scripts/ci/inputs.lock.json" <<\'PYARCHIVE32NATIVE\'\n          import importlib.util,json,sys\n          from pathlib import Path\n          helper,policy,inputs,native_inputs=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_archive32_native_join\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          raw=module.read(native_inputs,1024**2)\n          expected=dict(bytes=328101,sha256=\'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f\')\n          module.need(module.pin(raw)==expected,\'whole original native-base lock required\')\n          native={}\n          for row in json.loads(raw)[\'packages\']:\n              native[row[\'filename\']]=dict(bytes=row[\'size\'],sha256=row[\'sha256\'])\n              native[row[\'filename\']+\'.sig\']=dict(bytes=row[\'signature_size\'],sha256=row[\'signature_sha256\'])\n          files={name:{key:row[key]for key in(\'bytes\',\'sha256\')}for name,row in selected[\'files\'].items()}\n          common={name:row for name,row in files.items()if name in native}\n          extra={name:row for name,row in files.items()if name not in native}\n          expected_extra={\'firefox-157.0.1-1-aarch64.pkg.tar.xz\',\'firefox-157.0.1-1-aarch64.pkg.tar.xz.sig\',\'libnotify-0.8.8-1-aarch64.pkg.tar.xz\',\'libnotify-0.8.8-1-aarch64.pkg.tar.xz.sig\',\'pcsclite-2.5.2-1-aarch64.pkg.tar.xz\',\'pcsclite-2.5.2-1-aarch64.pkg.tar.xz.sig\'}\n          module.need(len(common)==26 and all(native[name]==row for name,row in common.items())and set(extra)==expected_extra,\'exact original26 native-base and six extra574 operands\')\n          print(module.encoded(dict(status=\'EXACT_ORIGINAL_NATIVE26_AND_SIX_EXTRA574_DATA_ONLY\',native_inputs=expected,original574_inputs=selected[\'original_inputs\'],common26=common,extra6=extra,versions=\'UNCHANGED\',trust=\'UNCHANGED_ORIGINAL_CHECKS_REQUIRED\')).decode(),end=\'\')\n          PYARCHIVE32NATIVE\n          python3 -I -B "$archive32_helper" --policy "$archive32_policy" --inputs "$archive32_inputs" --cache "$RUNNER_TEMP/frozen574-archive32"\n          python3 -I -B - "$archive32_helper" "$archive32_policy" "$archive32_inputs" "$RUNNER_TEMP/frozen574-archive32" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE32\'\n          import importlib.util,sys\n          from pathlib import Path\n          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_archive32_cache_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          result.update(helper=module.pin(helper.read_bytes()),policy=module.pin(policy.read_bytes()),destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE32\n'+archive32_early_marker,1)

 archive6_marker='      - name: Prefetch and seed exact32 frozen574 bytes before unchanged producer\n'
 C.need(text.count(archive6_marker)==1,'one exact late archive32 source step')
 archive6_start=text.index(archive6_marker);archive6_end=text.index('      - name:',archive6_start+len(archive6_marker))
 text=text[:archive6_end]+'          archive6_helper="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-ksm2-closed-owner/archive6.py"\n          archive6_policy="$GITHUB_WORKSPACE/expanded604-code/scripts/ci/current606-ksm2-closed-owner/archive6-policy.json"\n          archive6_inputs="$GITHUB_WORKSPACE/composition-updater/scripts/port/updater-extension/builder-extension.lock.json"\n          printf \'%s  %s\\n\' \'5e448ef6677fc26485e044b3ac2d35a07105703d4f1a719bb7c030678eff87ae\' "$archive6_helper" \'4d83dbda592b8b6575d02df65de829226cae3ddffc7268e3d47873ac83f3b322\' "$archive6_policy" | sha256sum --check\n          python3 -I -B "$archive6_helper" --policy "$archive6_policy" --inputs "$archive6_inputs" --cache "$RUNNER_TEMP/frozen-updater-archive6"\n          python3 -I -B - "$archive6_helper" "$archive6_policy" "$archive6_inputs" "$RUNNER_TEMP/frozen-updater-archive6" "$RUNNER_TEMP/alarm-cache" <<\'PYARCHIVE6\'\n          import importlib.util,sys\n          from pathlib import Path\n          helper,policy,inputs,cache,destination=map(Path,sys.argv[1:])\n          spec=importlib.util.spec_from_file_location(\'held_updater_archive6_seed\',helper)\n          module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n          selected=module.policy(policy,inputs)\n          result=module.seed_exact(cache,destination,selected)\n          result.update(helper=module.pin(helper.read_bytes()),policy=module.pin(policy.read_bytes()),destination=\'EXISTING_OWNED_ALARM_CACHE\',original_versions=\'UNCHANGED\',original_signature_and_trust_checks=\'UNCHANGED\')\n          print(module.encoded(result).decode(),end=\'\')\n          PYARCHIVE6\n'+text[archive6_end:]
 return archive20_workflow(text,root)

def emit(inputs,output,selection=None,publication=None):
 C.need(set(inputs)==set(C.ROLES),'three explicit complete source roots');C.need(output.is_absolute()and output.parent.is_dir()and not output.exists()and not any(p.is_symlink()for p in(output,*output.parents)),'fresh ordinary output')
 rows=C.read(C.HERE/'source-pins.json')
 for role,home in inputs.items():
  C.need(home.is_absolute()and home.is_dir()and not any(p.is_symlink()for p in(home,*home.parents)),'ordinary source root');wanted=rows[role]['files'];C.need(C.files(home)==set(wanted),'whole role closure')
  for n,row in wanted.items():C.checked(home/n,row)
 policy=C.read(C.HERE/'null-policy.json');C.need(policy['status']=='UNBOUND_SOURCE_TEMPLATE'and all(v is None for v in policy['current606'].values())and policy['native_pair_source']is policy['native_pair_index']is None,'default authority NULL')
 source=None
 if selection is not None:
  pins=C.read(inputs['copyworker']/'scripts/ci/current606-ksm2-copy/prerequisite-pins.json')
  C.need(type(publication)is dict and publication.get('status')=='PUBLISHED_VERIFIED_REMOTE'and re.fullmatch('[0-9a-f]{40}',publication.get('source')or'')and publication.get('index')==pins['index']and publication.get('files')==pins['files'],'Root exact public carrier publication required')
  C.need(selection.get('native_pair_source')==publication['source']and selection.get('native_pair_index')==pins['index'],'source-bound public tuple')
  import selection as S
  old=(S.PAIR_SOURCE,S.PAIR_INDEX);S.PAIR_SOURCE,S.PAIR_INDEX=publication['source'],pins['index']
  try:policy=C.authorize(selection)
  finally:S.PAIR_SOURCE,S.PAIR_INDEX=old
  source=publication['source']
 output.mkdir(mode=0o700)
 for role,home in inputs.items():
  for n in rows[role]['files']:
   p=output/role/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(home/n,p)
 lane=output/C.LANE;lane.mkdir(parents=True)
 for p in C.HERE.iterdir():
  if p.is_file()and p.name not in('input-policy.json','source-manifest.json'):shutil.copyfile(p,lane/p.name)
 if source is not None:
  p=lane/'selection.py';text=p.read_text();C.need(text.count('PAIR_SOURCE=None')==text.count('PAIR_INDEX=None')==1,'finite public identity seams');p.write_text(text.replace('PAIR_SOURCE=None','PAIR_SOURCE='+repr(source)).replace('PAIR_INDEX=None','PAIR_INDEX='+repr(policy['native_pair_index'])))
  raw=(lane/'selection.py').read_bytes();api=dict(path='/runner/owner/selection.py',**C.pin(raw));(output/'copyworker/scripts/ci/current606-ksm2-copy/owner-api.json').write_bytes(C.encoded(api));(output/'bridge/scripts/ci/current606-welcome5-source-bridge/owner-api.json').write_bytes(C.encoded(dict(path=api['path'],pin=C.pin(raw))))
 (lane/'input-policy.json').write_bytes(C.encoded(policy))
 # A publication binding changes only explicit source-owned API pins/metadata.
 from metadata import refresh
 refresh(output)
 return {p.relative_to(output).as_posix():C.pin(p.read_bytes())for p in sorted(output.rglob('*'))if p.is_file()}
if __name__=='__main__':
 if sys.argv[1:2]==['--seed-native-archive20']:
  C.need(len(sys.argv)==8,'six explicit archive20 native seed operands');print(json.dumps(seed_native20(*map(Path,sys.argv[2:])),sort_keys=True));raise SystemExit(0)
 p=argparse.ArgumentParser(description=__doc__)
 for n in C.ROLES:p.add_argument('--'+n+'-source',type=Path,required=True)
 for n in('selection','publication'):p.add_argument('--'+n,type=Path)
 p.add_argument('--output',type=Path,required=True);p.add_argument('--authorization',type=Path,required=True);a=p.parse_args()
 C.need(not a.authorization.exists(),'fresh authorization');a.authorization.write_bytes(C.encoded(emit({n:getattr(a,n+'_source').absolute()for n in C.ROLES},a.output.absolute(),None if a.selection is None else C.read(a.selection),None if a.publication is None else C.read(a.publication))))

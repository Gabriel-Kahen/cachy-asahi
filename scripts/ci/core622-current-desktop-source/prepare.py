# SPDX-License-Identifier: MIT
"""Portable exact Core51→66 DATA factory; starts no source/actor program."""
import argparse,ast,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 349249, 'sha256': '5735b369418a44819edfbc8983b05c4a68164c63e8ad8f56af8d37b144db6407'}
SCOPE='CORE622_CURRENT607_COPIED_PROVISIONING_NORMAL_CORE_TWO_BOOT_GENERIC16K'
PROVISIONING='COPIED_ROOT_PROVISIONING_NOT_NORMAL_HOOK_INSTALLATION'
enc=lambda x:(json.dumps(x,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def need(ok, message):
    if not ok:
        raise ValueError(message)

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def ordinary(value):
    raw = os.fspath(value)
    need(type(raw) is str and os.path.isabs(raw) and raw == os.path.normpath(raw),
         'absolute normalized path required')
    path = Path(raw)
    need(path == path.resolve(), 'canonical resolved path required')
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary nonalias ancestry')
    return path

def identity(info):
    # Reading a file/directory may update atime; it is never identity evidence.
    return tuple(getattr(info, key) for key in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def read_state(value):
    path = ordinary(value)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 <= before.st_size <= 8 * 1024**2, 'bounded ordinary single-link source file')
        parts, size = [], 0
        while part := os.read(fd, 1024**2):
            parts.append(part)
            size += len(part)
            need(size <= before.st_size, 'source file grew during read')
        need(size == before.st_size and identity(before) == identity(os.fstat(fd)) ==
             identity(path.lstat()), 'whole stable descriptor and path identity')
        return b''.join(parts), identity(before)
    finally:
        os.close(fd)

def read(path):
    return read_state(path)[0]

def scan(value):
    root = ordinary(value)
    need(root.is_dir(), 'ordinary source root required')
    files, state, directories = {}, {}, {}
    for path in (root, *sorted(root.rglob('*'))):
        info = path.lstat()
        need(not path.is_symlink(), 'source alias refused')
        name = path.relative_to(root).as_posix() if path != root else ''
        if stat.S_ISDIR(info.st_mode):
            directories[name] = (identity(info), tuple(sorted(p.name for p in path.iterdir())))
        else:
            raw, record = read_state(path)
            files[name], state[name] = raw, record
    required = {''}
    for name in files:
        required.update('' if str(p) == '.' else p.as_posix() for p in Path(name).parents)
    need(set(directories) == required, 'closed source directory membership, no foreign empty dirs')
    for name, (record, names) in directories.items():
        path = root / name
        need(identity(path.lstat()) == record and
             tuple(sorted(p.name for p in path.iterdir())) == names, 'stable whole source namespace')
    return files, dict(files=state, directories=directories)

def tree(root):
    return scan(root)[0]

def edits(text,rules):
 before=text
 for a,b in rules:need(text.count(a)==1,'one finite51 source seam: '+a[:80]);text=text.replace(a,b)
 inverse=text
 for a,b in reversed(rules):need(inverse.count(b)==1,'unique complete before-body inverse');inverse=inverse.replace(b,a)
 need(inverse==before,'whole original51 before-body inverse');return text

def workflow(old,core_profile,value):
 # Keep the complete accepted1197 producer, old library controls, input paths,
 # acquisition, signing and cleanup workflow. The explicit actor tail is622.
 text=old
 text=edits(text,[("name: native-arm-latest607-fresh-installer","name: native-arm-core622-current-desktop"),("group: native-arm-latest607-fresh-installer","group: native-arm-core622-current-desktop"),("          ref: ${{ github.sha }}\n          path: fresh607-code","          ref: b9976eea34eaed4b6e56af3be21d4d652fa971d6\n          path: fresh607-code"),("CURRENT_WORKFLOW_SHA: ${{ github.sha }}","CURRENT_WORKFLOW_SHA: b9976eea34eaed4b6e56af3be21d4d652fa971d6"),("FRESH_SOURCE: ${{ inputs.fresh_source_revision }}","FRESH_SOURCE: b9976eea34eaed4b6e56af3be21d4d652fa971d6"),("python3 -I -B \"$GITHUB_WORKSPACE/fresh607-code/implementation/run.py\" \\","python3 -I -B \"$GITHUB_WORKSPACE/core622-code/run622.py\" --fresh607-source \"$GITHUB_WORKSPACE/fresh607-code\" \\")])
 text=text.replace('          CURRENT_CHILD_SOURCE: ${{ inputs.fresh_source_revision }}','          CURRENT_CHILD_SOURCE: b9976eea34eaed4b6e56af3be21d4d652fa971d6')
 # The inherited environment-clearing CLI receives only genuine metadata and
 # fixed source roles required by the existing Core source proof.
 text=edits(text,[("            PYTHONDONTWRITEBYTECODE=1 \\","            PYTHONDONTWRITEBYTECODE=1 SOURCE_SHA=\"${{ github.sha }}\" WORKFLOW_SHA=\"${{ github.sha }}\" \\\n            GITHUB_SHA=\"${{ github.sha }}\" GITHUB_RUN_ID=\"$GITHUB_RUN_ID\" GITHUB_RUN_ATTEMPT=\"$GITHUB_RUN_ATTEMPT\" \\\n            GITHUB_REPOSITORY=\"${{ github.repository }}\" GITHUB_EVENT_NAME=\"${{ github.event_name }}\" \\\n            GITHUB_REF_NAME=\"${{ github.ref_name }}\" RUNNER_ARCH=ARM64 GITHUB_WORKSPACE=\"$GITHUB_WORKSPACE\" \\")])
 checkout='actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1';extra=''
 roles=[('core622-code','${{ github.sha }}'),('core51-parent','11b3cfb59663e42b34247facb9f30f042e891444')]+[(path,core_profile['source_profiles'][role]['source'])for role,path in(('core800','core-source'),('ksm637','vm-source'),('kernel_carrier','kernel-inputs'),('core7_carrier','core7-inputs'))]+[('core64-inputs','7dfce898755583bbf8081aae04d8b8579f66be58'),('core622-core-record','6e29f427fe273042ebaeca24d00326173888e95d'),('core622-fresh-record','5a0789405ded23f759f4a3aa545cf737c4ec3bde')]
 for path,source in roles:extra+=f'      - name: Exact separate622 source role {path}\n        uses: {checkout}\n        with:\n          ref: {source}\n          path: {path}\n          persist-credentials: false\n'
 extra+='''      - name: Whole622 and original Core source controls before secrets or actors
        shell: bash
        run: |
          set -euo pipefail
          python3 -I -B "$GITHUB_WORKSPACE/core622-code/run622.py" --source-preflight
          python3 -I -B "$GITHUB_WORKSPACE/core-source/scripts/ci/core-native-lifecycle/entry.py" source --source "$GITHUB_WORKSPACE/core-source"
          python3 -I -B "$GITHUB_WORKSPACE/core-source/scripts/ci/core-native-lifecycle/test_contract.py"
          python3 -I -B "$GITHUB_WORKSPACE/core-source/scripts/ci/core-native-lifecycle/test_fixture.py"
          python3 -I -B "$GITHUB_WORKSPACE/core-source/scripts/ci/core-native-lifecycle/assemble.py" --source-only
          python3 -I -B "$GITHUB_WORKSPACE/core51-parent/test_case.py"
          python3 -I -B "$GITHUB_WORKSPACE/core51-parent/test_protocol.py"
          python3 -I -B "$GITHUB_WORKSPACE/core51-parent/test_emission.py"
          python3 -I -B "$GITHUB_WORKSPACE/core51-parent/test_host.py"
          python3 -I -B "$GITHUB_WORKSPACE/core51-parent/test_route.py" --vm-source "$GITHUB_WORKSPACE/vm-source"
          python3 -I -B "$GITHUB_WORKSPACE/core51-parent/test_sources.py" --core-source "$GITHUB_WORKSPACE/core-source" --vm-source "$GITHUB_WORKSPACE/vm-source" --kernel-carrier "$GITHUB_WORKSPACE/kernel-inputs"
          CORE622_CORE_SOURCE="$GITHUB_WORKSPACE/core-source" CORE622_PARENT51="$GITHUB_WORKSPACE/core51-parent" python3 -I -B "$GITHUB_WORKSPACE/core622-code/test_desktop622.py"
          python3 -I -B "$GITHUB_WORKSPACE/core622-code/test_bridge622.py" --core-source "$GITHUB_WORKSPACE/core-source" --vm-source "$GITHUB_WORKSPACE/vm-source" --fresh607-source "$GITHUB_WORKSPACE/fresh607-code"
      - name: Held generic QEMU prerequisite for separately owned twoBoot622
        timeout-minutes: 5
        run: |
          set -euo pipefail
          sudo timeout --signal=TERM --kill-after=10s 120s apt-get -o Acquire::Retries=0 update
          sudo timeout --signal=TERM --kill-after=10s 120s apt-get -o Acquire::Retries=0 install --no-install-recommends -y qemu-system-arm
          /usr/bin/qemu-system-aarch64 --version
'''
 anchor='      - name: Authenticate current child before original library gates or native actors';need(text.count(anchor)==1,'one original preactor gate boundary');text=text.replace(anchor,extra+anchor)
 # Existing bounded metadata export stays unchanged; full Core evidence is an
 # additional explicit bounded directory, produced only by the current owner.
 text+='''      - name: Preserve complete current622 public evidence without private roots
        if: always()
        shell: bash
        run: |
          set -euo pipefail
          python3 -I -B "$GITHUB_WORKSPACE/core622-code/export622.py" --output "/tmp/cachy-asahi-expanded604-installer-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT" --public "$RUNNER_TEMP/core622-public"
          python3 -I -B "$GITHUB_WORKSPACE/core622-code/export622.py" --transport-only --output "/tmp/cachy-asahi-expanded604-installer-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT" --public "$RUNNER_TEMP/core622-public" --core-source "$GITHUB_WORKSPACE/core-source" --transport "$RUNNER_TEMP/core622-transport"
      - name: Upload only original bounded opaque current Core transport
        if: always()
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9
        with:
          name: core7-real-systemd-${{ github.run_id }}-${{ github.run_attempt }}
          path: ${{ runner.temp }}/core622-transport/
          retention-days: 3
          compression-level: 0
          include-hidden-files: true
          if-no-files-found: error
'''
 text=edits(text,[('      - name: Join six original354 compiler inputs into the same private cache\n        if: ${{ !cancelled() && steps.fdk_pair.outcome == \'success\' }}\n        timeout-minutes: 5\n        shell: bash\n        run: |\n          set -euo pipefail\n          test "$(git -C "$GITHUB_WORKSPACE/retained-compiler6" rev-parse HEAD)" = 8ee14069b7a74455a7bea1171ba319932c9df304\n          test "$(git -C "$GITHUB_WORKSPACE/composition-updater" rev-parse HEAD)" = 1aea667aec50a62ba0ab2dad44be24a4dc3bd098\n          deadline=$(env -i PATH=/usr/bin:/bin python3 -I -B -c \'import time; print(time.monotonic()+240)\')\n          env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$HOME" LANG=C.UTF-8 TZ=UTC TMPDIR="$RUNNER_TEMP" \\\n            python3 -I -B "$GITHUB_WORKSPACE/fresh607-code/implementation/compiler6.py" \\\n              --carrier "$GITHUB_WORKSPACE/retained-compiler6" \\\n              --updater "$GITHUB_WORKSPACE/composition-updater" \\\n              --desktop-lock "$GITHUB_WORKSPACE/retained-complete574/desktop574-inputs.lock.json" \\\n              --cache "$RUNNER_TEMP/alarm-cache" --deadline "$deadline"\n      - name: Checkout the proven 574-package runtime builder\n        if: ${{ !cancelled() && steps.fdk_pair.outcome == \'success\' }}\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: 9a2e520dbdfce7e4af417595ff3de9e6a284ef04\n          path: composition-desktop\n          persist-credentials: false\n      - name: Checkout the exact v2 updater implementation\n        if: ${{ !cancelled() && steps.fdk_pair.outcome == \'success\' }}\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: 480053c0866a922138d85af2b9880fb0e10d7b2c\n          path: composition-updater-v2\n          persist-credentials: false\n      - name: Checkout unchanged composition preparation APIs\n        if: ${{ !cancelled() && steps.fdk_pair.outcome == \'success\' }}\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: 93bc9bfac7343ee3b443ae3332c0942ed1ba5b55\n          path: composition-preparation\n          persist-credentials: false\n', '      - name: Checkout unchanged composition preparation APIs\n        if: ${{ !cancelled() && steps.fdk_pair.outcome == \'success\' }}\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: 93bc9bfac7343ee3b443ae3332c0942ed1ba5b55\n          path: composition-preparation\n          persist-credentials: false\n      - name: Checkout exact retained incoming31 dependency DATA\n        if: ${{ !cancelled() && steps.fdk_pair.outcome == \'success\' }}\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: 405761af52cdfa92b97bbf5b0519f32230d9a254\n          path: core622-dependency-inputs\n          persist-credentials: false\n      - name: Join six original354 compiler inputs into the same private cache\n        if: ${{ !cancelled() && steps.fdk_pair.outcome == \'success\' }}\n        timeout-minutes: 5\n        shell: bash\n        run: |\n          set -euo pipefail\n          test "$(git -C "$GITHUB_WORKSPACE/retained-compiler6" rev-parse HEAD)" = 8ee14069b7a74455a7bea1171ba319932c9df304\n          test "$(git -C "$GITHUB_WORKSPACE/composition-updater" rev-parse HEAD)" = 1aea667aec50a62ba0ab2dad44be24a4dc3bd098\n          test "$(git -C "$GITHUB_WORKSPACE/composition-preparation" rev-parse HEAD)" = 93bc9bfac7343ee3b443ae3332c0942ed1ba5b55\n          test "$(git -C "$GITHUB_WORKSPACE/core622-dependency-inputs" rev-parse HEAD)" = 405761af52cdfa92b97bbf5b0519f32230d9a254\n          test "$(git -C "$GITHUB_WORKSPACE/fresh607-code" rev-parse HEAD)" = b9976eea34eaed4b6e56af3be21d4d652fa971d6\n          deadline=$(env -i PATH=/usr/bin:/bin python3 -I -B -c \'import time; print(time.monotonic()+240)\')\n          env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$HOME" LANG=C.UTF-8 TZ=UTC TMPDIR="$RUNNER_TEMP" \\\n            python3 -I -B "$GITHUB_WORKSPACE/core622-code/ownership622.py" --prepare-dependency-cache --compiler6-source "$GITHUB_WORKSPACE/fresh607-code" \\\n              --carrier "$GITHUB_WORKSPACE/retained-compiler6" \\\n              --updater "$GITHUB_WORKSPACE/composition-updater" \\\n              --desktop-lock "$GITHUB_WORKSPACE/retained-complete574/desktop574-inputs.lock.json" \\\n              --cache "$RUNNER_TEMP/alarm-cache" --deadline "$deadline" \\\n              --incoming31 "$GITHUB_WORKSPACE/core622-dependency-inputs" --preparation "$GITHUB_WORKSPACE/composition-preparation"\n      - name: Checkout the proven 574-package runtime builder\n        if: ${{ !cancelled() && steps.fdk_pair.outcome == \'success\' }}\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: 9a2e520dbdfce7e4af417595ff3de9e6a284ef04\n          path: composition-desktop\n          persist-credentials: false\n      - name: Checkout the exact v2 updater implementation\n        if: ${{ !cancelled() && steps.fdk_pair.outcome == \'success\' }}\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: 480053c0866a922138d85af2b9880fb0e10d7b2c\n          path: composition-updater-v2\n          persist-credentials: false\n')])

 # Explicit CI-only flag on the already sanitized selected caller, never inheritance.
 text=edits(text,[('GITHUB_REF_NAME="${{ github.ref_name }}" RUNNER_ARCH=ARM64 GITHUB_WORKSPACE="$GITHUB_WORKSPACE"','GITHUB_REF_NAME="${{ github.ref_name }}" GITHUB_ACTIONS=true RUNNER_ARCH=ARM64 GITHUB_WORKSPACE="$GITHUB_WORKSPACE"')])
 return text

LAYER_PARENTS={'live_auxiliary': '333f9b0a3f11bc2180557f7e9feedfa2f2359b98', 'owned_auxiliary_initialization': 'b7b1a04c1bc0172f2af271546641aa374569c898', 'owned_proof_output': '358afcba2c1364b8954d753a631d001328367ee7', 'media_contract_inflate': 'f46ac9e7aeec170ba554255e3cda380ea0364e64', 'runner_resilience': 'ad09020a776c93fad3c2625c836a99cbde0c83b9'}
LAYER_FILES=('source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml')
def before_layer(values,key):
 """Pure full66 inverse, including products/selfseal; no source execution."""
 prior=dict(values);parent=json.loads(prior['composition-parent.json']);record=parent.pop(key);need(record['schema']==1 and record['parent_source']==LAYER_PARENTS[key]and record['actual']is None and len(record['before'])==66,'exact immediate source layer')
 for name,rules in record['edits'].items():
  text=prior[name].decode()
  for old,new in reversed(rules):need(text.count(new)==1,'one complete source layer seam inverse');text=text.replace(new,old,1)
  prior[name]=text.encode()
 prior['composition-parent.json']=enc(parent);manifest=json.loads(prior['source-manifest.json']);manifest['files']={n:w for n,w in record['before'].items()if n not in LAYER_FILES};prior['source-manifest.json']=enc(manifest);text=prior['source622.py'].decode()
 for name,old in(('PRODUCTS',record['guard_products_before']),('SELF',record['guard_self_before'])):
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name);new=ast.get_source_segment(text,node);need(text.count(new)==1,'one source layer products/self inverse');text=text.replace(new,old,1)
 need(text.count(record['guard_prefix'])==1,'one source layer whole prefix inverse');text=text.replace(record['guard_prefix'],record['guard_anchor'],1);prior['source622.py']=text.encode();need({n:pin(b)for n,b in prior.items()}==record['before'],'complete immediate66 source layer before map')
 sealed={n.targets[0].id:ast.literal_eval(n.value)for n in ast.parse(text).body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('PRODUCTS','SELF')};need(all(pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all original source layer products');seal=sealed['SELF'];need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole original source layer selfseal');return prior
def before_resilience(values):return before_layer(values,'runner_resilience')
def before_media_contract(values):return before_layer(values,'media_contract_inflate')
def before_proof_output(values):return before_layer(values,'owned_proof_output')
def before_owned_initialization(values):return before_layer(values,'owned_auxiliary_initialization')
def before_live_auxiliary(values):return before_layer(values,'live_auxiliary')
def before_later(values):
 if 'runner_resilience'in json.loads(values['composition-parent.json']):values=before_resilience(values)
 if 'media_contract_inflate'in json.loads(values['composition-parent.json']):values=before_media_contract(values)
 if 'owned_proof_output'in json.loads(values['composition-parent.json']):values=before_proof_output(values)
 if 'owned_auxiliary_initialization'in json.loads(values['composition-parent.json']):values=before_owned_initialization(values)
 if 'live_auxiliary'in json.loads(values['composition-parent.json']):values=before_live_auxiliary(values)
 return values
def source_layer(values,p,operands,key,stem,parent_role):
 """Add one exact readable DATA layer while retaining every predecessor byte."""
 before={n:values[n]for n in sorted(values)};record=json.loads(operands[stem+'-context.json']);record['guard_prefix']=operands[stem+'-inverse.py.txt'].decode();need(record['schema']==1 and record['parent_source']==LAYER_PARENTS[key]==p[parent_role]['source']and record['actual']is None and record['before']==p[parent_role]['files']=={n:pin(b)for n,b in before.items()},'whole exact source layer parent')
 if key=='runner_resilience':need(all(record['edits'].get(n)==record['edits']['workflow.yml.in']for n in LAYER_FILES[1:]),'complete runner-resilience workflow alias inverse edits')
 out=dict(before)
 for name,rules in record['edits'].items():out[name]=edits(out[name].decode(),rules).encode()
 guard=before['source622.py'].decode();assign={n.targets[0].id:ast.get_source_segment(guard,n)for n in ast.parse(guard).body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('PRODUCTS','SELF')};need(assign==dict(PRODUCTS=record['guard_products_before'],SELF=record['guard_self_before']),'exact predecessor products/self operands');need(guard.count(record['guard_anchor'])==1,'one source-owned DATA namespace before layer');guard=guard.replace(record['guard_anchor'],record['guard_prefix'],1).replace(assign['PRODUCTS'],'PRODUCTS=None',1).replace(assign['SELF'],"SELF='@SELF@'",1)
 parent=json.loads(before['composition-parent.json']);need(key not in parent,'fresh finite source layer');parent[key]=record;out['composition-parent.json']=enc(parent);products={n:pin(out[n])for n in sorted(out)if n not in('source622.py',*LAYER_FILES)};guard=guard.replace('PRODUCTS=None','PRODUCTS='+repr(products),1);guard=guard.replace("SELF='@SELF@'","SELF="+repr(hashlib.sha256(guard.encode()).hexdigest()),1);out['source622.py']=guard.encode();manifest=json.loads(before['source-manifest.json']);manifest['files']={n:pin(b)for n,b in out.items()if n not in LAYER_FILES};out['source-manifest.json']=enc(manifest);need(before_layer(out,key)==before,'entire source layer byte inverse');return out

def before_capability(values):
 """Pure DATA inverse of every immediate097757 source byte."""
 values=before_later(values)
 prior=dict(values);parent=json.loads(prior['composition-parent.json']);r=parent.pop('capability_boundary');need(r['schema']==1 and r['parent_source']=='09775710e2ad55d647993eab81890f1696572c86'and r['actual']is None,'fixed capability-boundary parent context')
 for name,rules in r['edits'].items():
  text=prior[name].decode()
  for a,b in reversed(rules):need(text.count(b)==1,'one exact capability helper inverse');text=text.replace(b,a,1)
  prior[name]=text.encode()
 prior['composition-parent.json']=enc(parent);m=json.loads(prior['source-manifest.json']);m['files']={n:w for n,w in r['before'].items()if n not in('source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml')};prior['source-manifest.json']=enc(m);text=prior['source622.py'].decode()
 for name,before in(('PRODUCTS',r['guard_products_before']),('SELF',r['guard_self_before'])):
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name);after=ast.get_source_segment(text,node);need(text.count(after)==1,'one capability guard seal inverse');text=text.replace(after,before,1)
 need(text.count(r['guard_prefix'])==1,'one finite capability source prefix');text=text.replace(r['guard_prefix'],r['guard_anchor'],1);prior['source622.py']=text.encode();need(len(prior)==66 and {n:pin(b)for n,b in prior.items()}==r['before'],'ENTIRE immediate09775766 before inverse');return prior

def capability_stage(values,p,operands):
 """Extend only the exact source-owned capability guard anchor, defaults held."""
 before={n:values[n]for n in sorted(values)};r=json.loads(operands['capability-context.json']);r['guard_prefix']=operands['capability-inverse.py.txt'].decode();need({n:pin(b)for n,b in before.items()}==p['capability_parent']['files']==r['before']and r['parent_source']==p['capability_parent']['source']and r['actual']is None,'whole exact097757 capability parent')
 out=dict(before)
 for name,rules in r['edits'].items():out[name]=edits(out[name].decode(),rules).encode()
 guard=before['source622.py'].decode();assign={n.targets[0].id:ast.get_source_segment(guard,n)for n in ast.parse(guard).body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('PRODUCTS','SELF')};need(assign==dict(PRODUCTS=r['guard_products_before'],SELF=r['guard_self_before']),'whole original097757 source seals');need(guard.count(r['guard_anchor'])==1,'one original local source DATA namespace');guard=guard.replace(r['guard_anchor'],r['guard_prefix'],1).replace(assign['PRODUCTS'],'PRODUCTS=None',1).replace(assign['SELF'],"SELF='@SELF@'",1)
 parent=json.loads(before['composition-parent.json']);need('capability_boundary'not in parent,'fresh exact capability DATA layer');parent['capability_boundary']=r;out['composition-parent.json']=enc(parent);aliases=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml');products={n:pin(b)for n,b in out.items()if n not in('source622.py','source-manifest.json',*aliases)};guard=guard.replace('PRODUCTS=None','PRODUCTS='+repr(products),1);guard=guard.replace("SELF='@SELF@'","SELF="+repr(hashlib.sha256(guard.encode()).hexdigest()),1);out['source622.py']=guard.encode();m=json.loads(before['source-manifest.json']);m['files']={n:pin(b)for n,b in out.items()if n not in('source-manifest.json',*aliases)};out['source-manifest.json']=enc(m);need(before_capability(out)==before,'complete capability stage byte inverse');return out

def before_environment(values):
 """Reconstruct all66 immediate bbdf DATA bytes without loading source code."""
 if 'capability_boundary'in json.loads(values['composition-parent.json']):values=before_capability(values)
 prior=dict(values);parent=json.loads(prior['composition-parent.json']);record=parent.pop('apparmor_environment')
 need(record['schema']==1 and record['parent_source']=='bbdf05888b8bacb8a7ee8dfde4def4d508cc812b'and record['actual']is None,'fixed CI environment before context')
 for name,rules in record['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):need(text.count(after)==1,'one current CI flag inverse');text=text.replace(after,before,1)
  prior[name]=text.encode()
 prior['composition-parent.json']=enc(parent);manifest=json.loads(prior['source-manifest.json']);manifest['files']={n:w for n,w in record['before'].items()if n not in('source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml')};prior['source-manifest.json']=enc(manifest)
 text=prior['source622.py'].decode()
 for name,before in(('PRODUCTS',record['guard_products_before']),('SELF',record['guard_self_before'])):
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and n.targets[0].id==name);after=ast.get_source_segment(text,node);need(text.count(after)==1,'one current seal inverse');text=text.replace(after,before,1)
 need(text.count(record['guard_prefix'])==1,'one finite CI guard prefix');text=text.replace(record['guard_prefix'],'',1);prior['source622.py']=text.encode()
 need({n:pin(b)for n,b in prior.items()}==record['before'],'whole immediate bbdf66 inverse')
 constants={n.targets[0].id:ast.literal_eval(n.value)for n in ast.parse(text).body if isinstance(n,ast.Assign)and n.targets[0].id in('PRODUCTS','SELF')};need(all(pin(prior[n])==w for n,w in constants['PRODUCTS'].items()),'entire bbdf product map');seal=constants['SELF'];need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'entire bbdf source selfseal');return prior

def compose(roots,runner_resilience=False):
 need(type(runner_resilience)is bool,'explicit maintained runner-resilience selection')
 need(set(roots)=={'parent','fresh607','core_record','fresh_record'},'four explicit pinned public DATA roles')
 profile_raw,profile_state=read_state(HERE/'profile.json');need(pin(profile_raw)==PROFILE,'fixed factory profile');p=json.loads(profile_raw)
 need(p['counts']==dict(before=51,after=66,held=40,changed=11,added=15)and p['actual']is None and p['native_acceptance']is False,'finite source-only scope')
 states={'profile.json':(profile_raw,profile_state),'prepare.py':read_state(HERE/'prepare.py')};inputs={};input_states={}
 for role,root in roots.items():
  values,state=scan(root);need({n:pin(b)for n,b in values.items()}==p['inputs'][role]['files'],'whole exact public role '+role);inputs[role]=values;input_states[role]=(values,state)
 operands={}
 for name,w in p['operands'].items():
  raw,state=read_state(HERE/name);need(pin(raw)==w,'fixed readable source operand '+name);operands[name]=raw;states[name]=(raw,state)
 v=json.loads(operands['composition.json'])
 public=v['public'];old=dict(inputs['parent']);need({n:pin(b)for n,b in old.items()}==public['core7-serial-line-framing-trial-root-20261025']['files'],'entire before51 map');out=dict(old)
 # Source-owned copied-root/context data contains no author paths or originals.
 composition={k:x for k,x in v.items()if k not in('external','physical')};composition['public']={n:{k:x for k,x in row.items()if k!='path'}for n,row in public.items()};out['composition.json']=enc(composition)
 for n in ('desktop622.py','formation622.py','provision622.py','lane622.py','assembly622.py','run622.py','ownership622.py','test_desktop622.py','test_bridge622.py','export622.py'):out[n]=operands[n+'.in']
 out['expected607.lock']=operands['expected607.lock'];out['expected622.lock']=operands['expected622.lock']
 profile=json.loads(old['profile.json']);profile['purpose']=SCOPE;profile['composition']=dict(scope=SCOPE,base=607,supported=620,installed=622,held=602,provisioning=PROVISIONING,normal_fresh607_installation='NOT_RUN',fit='NOT_ESTABLISHED',actual=None);out['profile.json']=enc(profile)
 out['case.py']=edits(old['case.py'].decode(),[("value['scope']=='CORE7_AUTOMATIC_HOOKS_ACTUAL_SYSTEMD_PID1_GENERIC16K'","value['scope']==__import__('desktop622').SCOPE ")]).encode()
 out['adapter.py']=edits(old['adapter.py'].decode(),[("api=C.helpers(root/'runtime/runtime-vm');return type('CoreBodies',(),dict(C=C,F=F,T=T,api=api,root=root))","api=C.helpers(root/'runtime/runtime-vm');original=type('CoreBodies',(),dict(C=C,F=F,T=T,api=api,root=root));import desktop622;return desktop622.core(original,G.decode(G.read(G.HERE/'composition.json',4*1024**2)))")]).encode()
 # Keep original source() available through exact reconstruction; current route
 # uses its distinct complete source guard, not a loose profile rebinding.
 tree=ast.parse(old['entry.py']);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='source');lines=old['entry.py'].decode().splitlines(keepends=True);before=''.join(lines[node.lineno-1:node.end_lineno]);out['entry.py']=edits(old['entry.py'].decode(),[(before,"def source(root):\n return __import__('source622').verify(root)\n")]).encode()
 text=old['controller.py'].decode();text=edits(text,[("ast,","ast,inspect,"),(" return changed\n"," return __import__('lane622').owner_text(changed)\n"),("namespace=dict(vars(O),NEW_VM=vm)","namespace=dict(vars(O),NEW_VM=vm,C=adapter.core(args.core_source).C,PROVISION607=__import__('lane622').provision,assembly=lambda *a:__import__('lane622').assembly(O,*a),binding=lambda *a:__import__('lane622').binding(__import__('desktop622').clone(O,C=adapter.core(args.core_source).C),*a))"),("work.mkdir(mode=0o700);media.mkdir(mode=0o700)","C.need(work.is_dir(),'same already staged owned607 preparation work');media.mkdir(mode=0o700)"),(" prepare_work(args,work)\n prep=", " C.need(adapter.source_rows(work)==C.decode(C.read(args.output/'vm-work-map.json',4*1024**2)),'whole staged source work unchanged after formation')\n prep=")])
 # The actor body stays complete via a counted source transformation factory.
 node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='actor');lines=text.splitlines(keepends=True);body=''.join(lines[node.lineno-1:node.end_lineno]);replacement="def actor(*args,**kwargs):\n namespace=dict(globals());text=__import__('lane622').actor_text("+repr(body)+");exec(compile(text,'whole-original-five-cap-Core-actor','exec'),namespace);return namespace['actor'](*args,**kwargs)\n";text=edits(text,[(body,replacement)]);out['controller.py']=text.encode()
 out['media.py']=edits(old['media.py'].decode(),[("text,_=derive(root);m=", "text,_=derive(root);text=__import__('lane622').media_text(text);m=")]).encode()
 out['evidence.py']=edits(old['evidence.py'].decode(),[(" copy(a.proof.parent/'legacy-prefill.json','retained/legacy-prefill.json');copy(a.proof.parent/'retained-custody.json','retained/retained-custody.json')", " for n in('fresh607-manifest.json','fresh607-producer.json','fresh607-base-build.json','fresh607-owner.json','fresh607-tooling-seed.json'):copy(a.proof.parent/n,'retained/'+n,4*1024**2)"),("  result['original_cleanup']=O.cleanup(a)","  if(a.output/'owner.json').exists():\n   report=C.decode(C.read(a.output/'owner.json',16*1024**2));__import__('lane622').retire(a,report,O.command_api(a.workspace,a.output,report),end)\n  result['original_cleanup']=__import__('lane622').old_cleanup(O,a)"),(" for n in('vm-result.json'", " if(a.output/'current607-public').exists():\n  for p in sorted((a.output/'current607-public').iterdir()):\n   if p.is_file():copy(p,'current607/'+p.name,64*1024**2)\n if(a.output/'data/current607-lease.json').exists():copy(a.output/'data/current607-lease.json','current607/lease.json')\n for n in('vm-result.json'")]).encode()
 wf=workflow(inputs['fresh607']['.github/workflows/native-arm-build.yml'].decode(),json.loads(old['profile.json']),v).encode();out['workflow.yml.in']=wf
 for n in ('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml'):out[n]=wf
 changed={n:b.decode()for n,b in old.items()if out.get(n)!=b or n=='source-manifest.json'};out['composition-parent.json']=enc(dict(dependency_cache_context=json.loads(operands['dependency-cache-context.json']),dependency_source_data=json.loads(operands['dependency-source-data.json']),schema=1,source=public['core7-serial-line-framing-trial-root-20261025']['source'],before={n:pin(b)for n,b in old.items()},changed=changed,clocks=v['clocks'],actual=None,actual_desktop_helper=dict(source='9a2e520dbdfce7e4af417595ff3de9e6a284ef04',path='scripts/ci/maintained_desktop574.py',body=operands['actual-maintained_desktop574.py.txt'].decode(),pin=pin(operands['actual-maintained_desktop574.py.txt']))))
 out['composition-parent.json']=enc(dict(json.loads(out['composition-parent.json']),isolated_cache_import=json.loads(operands['isolated-import-parent.json']),apparmor_environment=json.loads(operands['environment-parent.json'])));guard=operands['source622.py.in'].decode();products={n:pin(out[n])for n in sorted(out)if n not in('source-manifest.json',*('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml'))};guard=guard.replace('PRODUCTS=None','PRODUCTS='+repr(products));seal=hashlib.sha256(guard.encode()).hexdigest();guard=guard.replace("SELF='@SELF@'","SELF="+repr(seal));out['source622.py']=guard.encode()
 out['source-manifest.json']=enc(dict(schema=1,purpose=SCOPE,actual=None,files={n:pin(b)for n,b in out.items()if n not in('source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml')}))
 for n,b in out.items():
  if n.endswith('.py'):ast.parse(b,filename=n)

 need({n:pin(b)for n,b in out.items()}==p['capability_parent']['files'],'all66 exact097757 intermediate bytes');out=capability_stage(out,p,operands)
 need({n:pin(b)for n,b in out.items()}==p['diagnostic_parent']['files'],'all66 exact333f maintained intermediate')
 out=source_layer(out,p,operands,'live_auxiliary','live-auxiliary','diagnostic_parent');need({n:pin(b)for n,b in out.items()}==p['initialization_parent']['files'],'all66 exact b7 diagnostic intermediate')
 out=source_layer(out,p,operands,'owned_auxiliary_initialization','owned-initialization','initialization_parent')
 need({n:pin(b)for n,b in out.items()}==p['proof_output_parent']['files'],'all66 exact358 initializer intermediate')
 out=source_layer(out,p,operands,'owned_proof_output','proof-output','proof_output_parent')
 need({n:pin(b)for n,b in out.items()}==p['media_contract_parent']['files'],'all66 exactf46 owned-output intermediate')
 out=source_layer(out,p,operands,'media_contract_inflate','media-contract','media_contract_parent')
 need({n:pin(b)for n,b in out.items()}==p['result']['files'],'all66 exact public result bytes')
 before_environment(out)  # All immediate66 predicates remain mandatory before original51 inverse.
 restored=dict(out)
 for n in p['added']:restored.pop(n)
 for n,raw in changed.items():restored[n]=raw.encode()
 need(restored==old and all(out[n]==old[n]for n in p['held']),'whole51 inverse and all40 held')
 if runner_resilience:
  out=source_layer(out,p,operands,'runner_resilience','runner-resilience','resilience_parent')
  need({n:pin(b)for n,b in out.items()}==p['runner_resilience_result']['files']and p['runner_resilience_result']['source']is p['runner_resilience_result']['ref']is None,'complete unbound maintained diagnostic result; no published25d7 claim')
 need(all(scan(roots[k])==input_states[k]for k in roots)and all(read_state(HERE/n)==w for n,w in states.items()),'late whole input/operand identity drift')
 return out,p,input_states,states

def paths(roots,output):
 roots={k:ordinary(v)for k,v in roots.items()};output=ordinary(output);need(output.parent.is_dir()and not os.path.lexists(output),'fresh output before writes');need(not any('native-actual'in q.name for q in(output,*output.parents)),'actual roots refused')
 protected=[HERE,*roots.values()]
 for i,a in enumerate(protected):
  for b in protected[i+1:]:need(not a.is_relative_to(b)and not b.is_relative_to(a),'disjoint public input roles')
 for a in protected:need(not output.is_relative_to(a)and not a.is_relative_to(output),'disjoint output/input/factory')
 return roots,output

def emit(roots,output,context,runner_resilience=False):
 need(context in('known','null'),'explicit known/NULL source-only context');roots,output=paths(roots,output);values,p,inputs,states=compose(roots,True)if runner_resilience else compose(roots);paths(roots,output)
 need(all(scan(roots[k])==inputs[k]for k in roots)and all(read_state(HERE/n)==w for n,w in states.items()),'late complete identity before any write');output.mkdir(mode=0o700)
 for name,raw in sorted(values.items()):
  q=output/name;q.parent.mkdir(parents=True,exist_ok=True);fd=os.open(q,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb')as f:f.write(raw);os.fchmod(f.fileno(),0o644)
 need(tree(output)==values,'exact complete66 emission')
 if runner_resilience:return dict(status='SOURCE_ONLY_UNBOUND_MAINTAINED_CORE622_RESILIENCE',source=None,ref=None,parent_source=p['resilience_parent']['source'],actual=None,native_acceptance=False,hardware='NOT_RUN',fit='NOT_ESTABLISHED',files=66,context=context,publication_binding='UNISSUED')
 return dict(status='SOURCE_ONLY_EXACT_CORE622_NOT_NATIVE_ACCEPTANCE',source=p['result']['source']if context=='known'else None,ref=p['result']['ref']if context=='known'else None,actual=None,native_acceptance=False,hardware='NOT_RUN',fit='NOT_ESTABLISHED',files=66,context=context)

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 for role in('parent','fresh607','core-record','fresh-record','output','context'):parser.add_argument('--'+role,required=True)
 parser.add_argument('--runner-resilience',action='store_true',help='unbound diagnostic layer after exact ad090 default')
 args=parser.parse_args();roots={k:getattr(args,k)for k in('parent','fresh607','core_record','fresh_record')};print(json.dumps(emit(roots,args.output,args.context,args.runner_resilience),sort_keys=True))

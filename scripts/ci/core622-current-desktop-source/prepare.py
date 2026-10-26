# SPDX-License-Identifier: MIT
"""Portable exact Core51→66 DATA factory; starts no source/actor program."""
import argparse,ast,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 277466, 'sha256': '07231b7133108ce3946801eb4a0ef75cd48b66cfc6445e55cfe8d7c35c30d313'}
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
 return text

def compose(roots):
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
 changed={n:b.decode()for n,b in old.items()if out.get(n)!=b or n=='source-manifest.json'};out['composition-parent.json']=enc(dict(schema=1,source=public['core7-serial-line-framing-trial-root-20261025']['source'],before={n:pin(b)for n,b in old.items()},changed=changed,clocks=v['clocks'],actual=None))
 guard=operands['source622.py.in'].decode();products={n:pin(b)for n,b in out.items()if n not in('source-manifest.json',*('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml'))};guard=guard.replace('PRODUCTS=None','PRODUCTS='+repr(products));seal=hashlib.sha256(guard.encode()).hexdigest();guard=guard.replace("SELF='@SELF@'","SELF="+repr(seal));out['source622.py']=guard.encode()
 out['source-manifest.json']=enc(dict(schema=1,purpose=SCOPE,actual=None,files={n:pin(b)for n,b in out.items()if n not in('source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml')}))
 for n,b in out.items():
  if n.endswith('.py'):ast.parse(b,filename=n)

 need({n:pin(b)for n,b in out.items()}==p['result']['files'],'all66 exact public result bytes')
 restored=dict(out)
 for n in p['added']:restored.pop(n)
 for n,raw in changed.items():restored[n]=raw.encode()
 need(restored==old and all(out[n]==old[n]for n in p['held']),'whole51 inverse and all40 held')
 need(all(scan(roots[k])==input_states[k]for k in roots)and all(read_state(HERE/n)==w for n,w in states.items()),'late whole input/operand identity drift')
 return out,p,input_states,states

def paths(roots,output):
 roots={k:ordinary(v)for k,v in roots.items()};output=ordinary(output);need(output.parent.is_dir()and not os.path.lexists(output),'fresh output before writes');need(not any('native-actual'in q.name for q in(output,*output.parents)),'actual roots refused')
 protected=[HERE,*roots.values()]
 for i,a in enumerate(protected):
  for b in protected[i+1:]:need(not a.is_relative_to(b)and not b.is_relative_to(a),'disjoint public input roles')
 for a in protected:need(not output.is_relative_to(a)and not a.is_relative_to(output),'disjoint output/input/factory')
 return roots,output

def emit(roots,output,context):
 need(context in('known','null'),'explicit known/NULL source-only context');roots,output=paths(roots,output);values,p,inputs,states=compose(roots);paths(roots,output)
 need(all(scan(roots[k])==inputs[k]for k in roots)and all(read_state(HERE/n)==w for n,w in states.items()),'late complete identity before any write');output.mkdir(mode=0o700)
 for name,raw in sorted(values.items()):
  q=output/name;q.parent.mkdir(parents=True,exist_ok=True);fd=os.open(q,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb')as f:f.write(raw);os.fchmod(f.fileno(),0o644)
 need(tree(output)==values,'exact complete66 emission')
 return dict(status='SOURCE_ONLY_EXACT_CORE622_NOT_NATIVE_ACCEPTANCE',source=p['result']['source']if context=='known'else None,ref=p['result']['ref']if context=='known'else None,actual=None,native_acceptance=False,hardware='NOT_RUN',fit='NOT_ESTABLISHED',files=66,context=context)

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 for role in('parent','fresh607','core-record','fresh-record','output','context'):parser.add_argument('--'+role,required=True)
 args=parser.parse_args();roots={k:getattr(args,k)for k in('parent','fresh607','core_record','fresh_record')};print(json.dumps(emit(roots,args.output,args.context),sort_keys=True))

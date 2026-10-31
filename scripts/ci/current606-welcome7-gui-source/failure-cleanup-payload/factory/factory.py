#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit one actual installed606 GUI profile; source emission never grants acceptance."""
import argparse,ast,hashlib,importlib.util,json,shutil,sys,types,shlex,time,math
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent

def need(ok,why):
    if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path):
    need(not any(p.is_symlink()for p in(path,*path.parents))and path.is_file()and path.stat().st_nlink==1,'ordinary singlelink source')
    return path.read_bytes()
def obj(path):return json.loads(read(path))
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m

def once(text,before,after):
    need(text.count(before)==1,'exact GUI source seam '+before[:80]);return text.replace(before,after,1)
def source(root):
    p=obj(HERE/'profile.json');need(len(p['source_files'])==348,'complete accepted348 source')
    for n,w in p['source_files'].items():need(pin(read(root/n))==w,'accepted source drift '+n)
    for n,w in p['support'].items():need(pin(read(HERE/'support'/n))==w,'held support drift '+n)
    need(pin(read(HERE/'expected606.lock'))==p['expected606'],'exact606 selection')
    return p

def transform(out,mode):
    changes={}
    def edit(name,fn):
        q=out/name;old=q.read_text();new=fn(old);need(old!=new,'actual finite derivative '+name);ast.parse(new)if q.suffix=='.py'else None;q.write_text(new);changes[name]=dict(before=pin(old.encode()),after=pin(new.encode()))
    edit('management_root.py',lambda s:once(s,'len(baseline)==595','len(baseline)==606'))
    def phase(s):
        for a,b in (("len(missing['inventory'])==593","len(missing['inventory'])==604"),('len(inventory)==595','len(inventory)==606'),('present_count=595,absent_count=593','present_count=606,absent_count=604')):s=once(s,a,b)
        return s
    edit('management_phase.py',phase)
    edit('management_contract.py',lambda s:once(s,"result.get('present_count')==595 and result.get('absent_count')==593 and len(result.get('inventory',{}))==595","result.get('present_count')==606 and result.get('absent_count')==604 and len(result.get('inventory',{}))==606"))
    edit('gui_contract.py',lambda s:once(s,"'cachy-asahi-doctor':'0.1.0-1'","'cachy-asahi-doctor':'0.2.0-1'"))
    edit('doctor_worker.py',lambda s:once(s,'Welcome 0.1.0-4 | Doctor 0.1.0-1 | installed package observations PASS','Welcome 0.1.0-7 | Doctor 0.2.0-1 | installed package observations PASS'))
    text=(out/'desktop574_runtime.py').read_text();tree=ast.parse(text);main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main');trial=next(n for n in main.body if isinstance(n,ast.Try));start=next(n for n in trial.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='recipe_dir'for t in n.targets));end=next(n for n in trial.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='inputs'for t in n.targets));old=''.join(text.splitlines(keepends=True)[start.lineno-1:end.lineno-1]);need(old.count('hosted.fetch')==1 and old.count("'package-build'")==1,'whole old595 network/build/install block')
    replacement="""        runner = Path(__file__).resolve().parent
        import context606
        derived, archives, expected, qemu_image = context606.build(runner, image, out, execute, text_command, bind_local_base, images, report)
"""
    edit('desktop574_runtime.py',lambda s:once(s,old,replacement))
    edit('desktop574_runtime.py',lambda s:once(s,'cmd = qemu_command(derived, name, fixture, source, runner)','cmd = qemu_command(qemu_image, name, fixture, source, runner)'))
    edit('desktop574_runtime.py',lambda s:once(s,"    verify_source(source)","    verify_source(source)\n    import context606\n    context606.authorize_runner(Path(__file__).resolve().parent)"))
    installed=read(HERE/'support/installed604.py').decode();need(installed.count('604')==8,'held complete owned observer count seams');(out/'installed606.py').write_text(installed.replace('604','606'))
    for n in('alpm_reader.py','file_capabilities.py'):shutil.copyfile(HERE/'support'/n,out/n)
    fixture=(out/'desktop574_fixture.sh').read_text();anchor='allocated=$(du -sx --block-size=1 "$root" | cut -f1)';insert='cp /runner/installed606.py /runner/alpm_reader.py /runner/file_capabilities.py "$root/usr/local/share/desktop574/"\npython3 -I -B /runner/installed606.py capture "$root" /runner/alpm_reader.py /runner/expected606.lock "$root/usr/local/share/desktop574/installed606.json" > /out/installed606-capture.json\n'+anchor
    edit('desktop574_fixture.sh',lambda s:once(s,anchor,insert))
    anchor="        need(code == 0, 'desktop user session failed')"
    insert=anchor+"\n        proof=command(['/usr/bin/python3','-I','-B',str(SHARE/'installed606.py'),'verify','/',str(SHARE/'alpm_reader.py'),str(SHARE/'expected.lock'),str(SHARE/'installed606.json')],env,logs,'installed606-preserved',timeout=600)\n        emit('installed606_preserved',status='PASS',receipt=json.loads(proof),hardware='NOT_RUN')"
    edit('base_guest.py',lambda s:once(s,anchor,insert))
    shutil.copyfile(HERE/'current_products.py',out/'current_products.py')
    for name in('apps14_runtime.py','apps14-installed-profile.json','apps14_diagnostic.py'):shutil.copyfile(HERE/name,out/name)
    edit('desktop574_fixture.sh',lambda s:once(s,'cp /runner/service_outcome.py', 'cp /runner/apps14_runtime.py /runner/apps14-installed-profile.json /runner/apps14_diagnostic.py \"$root/usr/local/share/desktop574/\"\ncp /runner/current_products.py "$root/usr/local/share/desktop574/"\ncp /runner/service_outcome.py'))
    edit('base_guest.py',lambda s:once(s,"    emit('gbm_pass', probe=probe)","    emit('gbm_pass', probe=probe)\n    import importlib.util\n    product_spec=importlib.util.spec_from_file_location('current606_actual_products',SHARE/'current_products.py')\n    product=importlib.util.module_from_spec(product_spec)\n    product_spec.loader.exec_module(product)\n    emit('current606_products',receipt=product.run(SHARE,HOME,env))"))
    contract=(out/'contract.py').read_text();contract+='''\n_current606_full_gui=verify_result
def verify_result(events,lock):
    rows=[e for e in events if e.get('event')=='installed606_preserved']
    C.need(len(rows)==1 and rows[0]['status']=='PASS' and rows[0]['receipt']['packages']==606,'complete606 actual payload/database/capability readback required')
    products=[e for e in events if e.get('event')=='current606_products']
    C.need(len(products)==1,'actual installed Apps14 and KSM2 commands required')
    import current_products
    product=current_products.validate(products[0]['receipt'],PAGE_SIZE)
    result=_current606_full_gui(events,lock)
    return dict(result,current606_preservation=rows[0],current606_products=product,native_acceptance='REQUIRES_NEW_PAIR_AND_ROOT_REPLAY')
''';contract=contract.replace('PAGE_SIZE',str(16384 if mode=='generic16k'else 4096));(out/'contract.py').write_text(contract)
    for name in ('management_phase.py','management_contract.py'):
        edit(name,lambda s:once(s,'GENERIC4K_UNPRIVILEGED_ACTUAL_DEFAULT_TOOLS','CURRENT606_'+mode.upper()+'_UNPRIVILEGED_ACTUAL_DEFAULT_TOOLS'))
    if mode=='generic16k':extend16(out)
    load('_source_bound_welcome8_extension',HERE/'extend_welcome8.py').apply(out,obj(out/'candidate-lock.json')['profile'])
    def status(s):
        need(s.count('PASS_INSTALLED_WELCOME_SINGLE_PROFILE_GUI_METADATA')==2,'exact success assignment and exit gates');return s.replace('PASS_INSTALLED_WELCOME_SINGLE_PROFILE_GUI_METADATA','PASS_CURRENT606_WELCOME8_'+mode.upper()+'_GUI_METADATA')
    edit('desktop574_runtime.py',status)
    def retirement(s):
        s=once(s,'    containers, images, active = [], [], None','    import failure_cleanup\n    containers, images, active = [], [], None')
        s=once(s,"        def cleanup(argv, label):", "        base_reference = report.get('base_reference', base_reference)\n        try:report['resource_acquisition']=failure_cleanup.plan(containers,images,image,base_reference,(out/'fixture').is_dir())\n        except Exception as error:report['resource_acquisition_error']=type(error).__name__\n        def cleanup(argv, label):")
        s=once(s,"                require(done.returncode == 0, 'cleanup command failed')", "                require(done.returncode == 0, 'cleanup command failed')\n                row.update(failure_cleanup.output(done.stdout))")
        return s
    edit('desktop574_runtime.py',retirement)
    shutil.copyfile(HERE/'failure_cleanup.py',out/'failure_cleanup.py')

    return changes

def extend16(out):
    raw=read(HERE/'support/managed16k_prepare.py').decode()
    start="    s.check_source(source)\n    candidates=s.load(source,'scripts/ci/welcome-managed-gui/candidates.py');sys.modules['candidates']=candidates\n    shared=s.load(source,'scripts/ci/welcome-managed-gui/prepare.py');shared.prepare(source,output,assets)"
    text=once(raw,start,'    s.check_source(source)')
    need(text.count("output/'contract.py'")==2,'exact original16K inner contract pair');text=text.replace("output/'contract.py'","output/'legacy_contract.py'")
    text=once(text,"source/'scripts/virtual/generic16k/fixture.py'","s.HERE/'elf_reader.py'")
    shim=types.SimpleNamespace(HERE=HERE/'support',need=need,sha=lambda b:hashlib.sha256(b).hexdigest(),read=lambda p:read(p),check_source=lambda _:None)
    ns=dict(__name__='_held16k_exact_adapter',__file__=str(HERE/'support/managed16k_prepare.py'));saved=sys.modules.get('support');sys.modules['support']=shim
    try:exec(compile(text,'<whole-managed16k-adapter-minus-prior-emitter>','exec'),ns);ns['prepare'](HERE,out,None)
    finally:
        if saved is None:sys.modules.pop('support',None)
        else:sys.modules['support']=saved
    runtime=(out/'desktop574_runtime.py').read_text();runtime=once(runtime,'cachy_asahi_managed_gui16k=1','cachy_asahi_managed_gui16k=1 arm64.nomops')
    tree=ast.parse(runtime);q=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='qemu_command');shell=next(n.value for n in ast.walk(q)if isinstance(n,ast.Constant)and isinstance(n.value,str)and' -append "'in n.value);words=shlex.split(shell);cmdline=words[words.index('-append')+1]
    runtime=once(runtime,'        active.finish(); active = None',"        active.finish(); active = None\n        import nomops606\n        report['kernel_nomops']=nomops606.check((out/'guest.log').read_bytes())")
    (out/'desktop574_runtime.py').write_text(runtime)
    helper=r"""# SPDX-License-Identifier: MIT
import hashlib,re
COMMAND=__COMMAND__
def check(raw):
    if type(raw)is not bytes or len(raw)>8*1024**2:raise ValueError('bounded complete original GUI UART')
    text=raw.decode('utf8','strict');commands=[l.split('Kernel command line: ',1)[1]for l in text.splitlines()if 'Kernel command line: 'in l]
    if commands!=[COMMAND]or COMMAND.split().count('arm64.nomops')!=1 or len(re.findall(r'ID_AA64ISAR2_EL1\[19:16\]: forced to 0\b',text))!=1 or 'CPU features: detected: Memory Copy and Memory Set instructions'in text:raise ValueError('exact source command and original NOMOPS forced-zero efficacy required')
    return dict(status='PASS_NEW_GUI_ORIGINAL_NOMOPS_FORCED_ZERO_ONLY',UART=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),enabled_MOPS=False,actual_acceptance='REQUIRES_COMPLETE_NEW_GUI_PAIR_REPLAY')
""".replace('__COMMAND__',repr(cmdline))
    (out/'nomops606.py').write_text(helper)
    shutil.copyfile(HERE/'hwcap_probe.c',out/'hwcap_probe.c');shutil.copyfile(HERE/'user_hwcap.py',out/'user_hwcap.py')
    fixture=(out/'desktop574_fixture.sh').read_text();anchor='allocated=$(du -sx --block-size=1 "$root" | cut -f1)';fixture=once(fixture,anchor,'cc -std=c11 -O2 -Wall -Wextra -Werror -Wl,-z,max-page-size=16384 /runner/hwcap_probe.c -o "$root/usr/local/share/desktop574/hwcap-probe"\n'+anchor);(out/'desktop574_fixture.sh').write_text(fixture)
    guest=(out/'base_guest.py').read_text();guest+=r"""

def current_nomops(role):
    value=json.loads(subprocess.check_output([str(SHARE/'hwcap-probe')],timeout=5))
    uid=0 if role=='root'else23001
    need(value['mops'] is False and not(value['hwcap2']&(1<<43)) and value['uid']==uid and value['page_size']==16384,'actual userspace MOPS zero before GUI')
    emit('nomops_userspace',role=role,uid=uid,probe=value,boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
"""
    # Define the probe before the existing module's __main__ entry can call it.
    start=guest.index('\ndef current_nomops(');body=guest[start:];guest=guest[:start];anchor="if __name__ == '__main__':";guest=once(guest,anchor,body+'\n'+anchor)
    guest=once(guest,"        actual = command(['/usr/bin/pacman', '-Q'], env, logs, 'inventory')","        current_nomops('root')\n        actual = command(['/usr/bin/pacman', '-Q'], env, logs, 'inventory')")
    guest=once(guest,"    logs = HOME / 'logs'","    current_nomops('user')\n    logs = HOME / 'logs'")
    (out/'base_guest.py').write_text(guest.replace('else23001','else 23001'))
    contract=(out/'contract.py').read_text();contract+="\n_nomops_full_gui=verify_result\ndef verify_result(events,lock):\n    import user_hwcap\n    probe=user_hwcap.validate(events)\n    return dict(_nomops_full_gui(events,lock),userspace_NOMOPS=probe)\n";(out/'contract.py').write_text(contract)


def prepare_code(root,assets,out,selected,mode):
    root,assets,out=(Path(p).absolute()for p in(root,assets,out));profile=source(root)
    need(selected in('minimal','overlay')and mode in('generic4k','generic16k')and not out.exists()and out.parent.is_dir(),'explicit independent profile/mode and fresh output')
    home=root/'scripts/ci/welcome5-native-gui';sys.path.insert(0,str(home))
    held=load('_accepted_welcome7_prepare',home/'prepare.py');held.prepare(root,assets,out,selected)
    changes=transform(out,mode)
    for n in('context606.py','install606.py','build_scope.py'):shutil.copyfile(HERE/n,out/n)
    shutil.copyfile(HERE/'expected606.lock',out/'expected606.lock')
    return profile,changes

def seal(out,selected,mode,profile,changes,ready):
    for p in out.glob('*.py'):ast.parse(p.read_text(),filename=str(p))
    rows={p.relative_to(out).as_posix():pin(read(p))for p in sorted(out.rglob('*'))if p.is_file()and p.name!='current606-proof.json'}
    proof=dict(status='EMITTED_CURRENT606_WELCOME8_GUI_SOURCE_ONLY'if ready else'UNBOUND_CURRENT606_GUI_CODE_ONLY_RUNTIME_REFUSES',mode=mode,profile=selected,packages=606,optional_absent=604,files=rows,derivatives=changes,accepted_input_source=profile['source'],actual_run=None,GUI='NOT_RUN',page_size=16384 if mode=='generic16k'else 4096,hardware='NOT_RUN',release='NOT_ADMITTED')
    (out/'current606-proof.json').write_bytes(enc(proof));return proof

def emit(root,assets,ready,out,selected,mode,kernel=None,tooling=None,tooling_git=None,deadline=None):
    root,assets,ready,out=(Path(p).absolute()for p in(root,assets,ready,out));profile=source(root)
    need(mode!='generic16k'or(kernel is not None and len(kernel)==3 and all(isinstance(p,Path)for p in kernel)),'generic16K requires exact explicit Image/config/profile')
    need(tooling is not None and tooling_git is not None and type(deadline)in(int,float)and math.isfinite(deadline)and time.monotonic()<deadline,'explicit tooling89 carrier/Git directory and original source-owned deadline')
    helperpins=obj(HERE/'retained-helper-pins.json')
    for n,w in helperpins.items():need(pin(read(HERE/'retained-helpers'/n))==w,'whole maintained source/Git proof helper '+n)
    sys.path.insert(0,str(HERE/'retained-helpers'));L=load('_gui_tooling_whole_source_git_proof',HERE/'retained-helpers/legacy_prefill.py');external=obj(HERE/'tooling-carrier-profile.json');need(external['source']=='fb515d735a81194f06ea117539dee60438bb8d87'and external['ref']=='codex/gui16-controller-tooling-v1'and len(external['files'])==89 and external['actual']is None,'exact Root published tooling89 input-only source');tooling_proof=L.prove(Path(tooling).absolute(),Path(tooling_git).absolute(),external,deadline)
    api=load('_current606_context_factory',HERE/'context606.py');bundle=api.verify(ready,root,profile)
    profile,changes=prepare_code(root,assets,out,selected,mode);api.stage(ready,root,out,bundle,profile)
    load('_current606_qemu_context',HERE/'qemu_context.py').prepare(root,Path(tooling).absolute()/'packages',out,ready)
    (out/'tooling89-source-proof.json').write_bytes(enc(tooling_proof))
    if mode=='generic16k':load('_current606_kernel_stage',HERE/'kernel_stage.py').stage(out,*kernel)
    return seal(out,selected,mode,profile,changes,True)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in('source','assets','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--ready606',type=Path);p.add_argument('--tooling-carrier',type=Path);p.add_argument('--tooling-git-dir',type=Path);p.add_argument('--deadline',type=float);p.add_argument('--source-only',action='store_true')
    [p.add_argument('--kernel-'+n,type=Path)for n in('image','config','profile')]
    p.add_argument('--profile',choices=('minimal','overlay'),required=True);p.add_argument('--mode',choices=('generic4k','generic16k'),required=True);a=p.parse_args()
    if a.source_only:
        profile,changes=prepare_code(a.source,a.assets,a.output,a.profile,a.mode);r=seal(a.output,a.profile,a.mode,profile,changes,False)
    else:
        need(a.ready606 is not None,'explicit signed606 cache required');r=emit(a.source,a.assets,a.ready606,a.output,a.profile,a.mode,None if a.kernel_image is None and a.kernel_config is None and a.kernel_profile is None else(a.kernel_image,a.kernel_config,a.kernel_profile),a.tooling_carrier,a.tooling_git_dir,a.deadline)
    print(json.dumps({k:v for k,v in r.items()if k not in('files','derivatives')},sort_keys=True))

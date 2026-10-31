# SPDX-License-Identifier: MIT
"""Counted, source-pinned adapters; original593/594 transports remain untouched."""
import ast
import json
from pathlib import Path
import shutil
import sys
import contract as C


def one(text,old,new):
    C.need(text.count(old)==1,'exact604 adapter anchor differs: '+old[:100]);return text.replace(old,new)


def derive16_prepare(source):
    path='scripts/ci/managed-gui-generic16k/prepare.py';raw=C.read(C.checked(source,dict(path=path,**C.pins()[path])))
    text=raw.decode()
    text=one(text,'    s.check_source(source)\n    candidates=s.load(source,\'scripts/ci/welcome-managed-gui/candidates.py\');sys.modules[\'candidates\']=candidates\n    shared=s.load(source,\'scripts/ci/welcome-managed-gui/prepare.py\');shared.prepare(source,output,assets)',
        "    s.check_source(source)\n    shared=s.load(source,'scripts/ci/welcome-management-native/prepare.py');shared.prepare(source,output,assets)")
    text=one(text,"shutil.copyfile(s.HERE/name,output/name)","shutil.copyfile(source/'scripts/ci/managed-gui-generic16k'/name,output/name)")
    # The current management wrapper retains the complete original14-frame verifier as legacy_contract.
    C.need(text.count("output/'contract.py'")==2,'original16K contract read/write pair required')
    text=text.replace("output/'contract.py'","output/'legacy_contract.py'")
    text=one(text,"'PASS_INSTALLED_WELCOME_DOCTOR_MANAGED_GUI_METADATA','PASS_INSTALLED_WELCOME_DOCTOR_MANAGED_GUI_GENERIC16K_METADATA'",
        "'PASS_INSTALLED_WELCOME_MANAGEMENT_GUI_METADATA','"+C.PASS+"'")
    # Do not import its sibling support: use only this verified finite source loader.
    text=one(text,'import support as s','s=__import__("sys").modules["managed604_contract"]')
    ast.parse(text);space={'__name__':'_derived604_prepare','__file__':str(source/path)}
    sys.modules['managed604_contract']=C;exec(compile(text,'<source-pinned16K604prepare>','exec'),space)
    return space['prepare'],dict(source_sha256=C.sha(raw),adapted_sha256=C.sha(text.encode()),edits=6)


def transform_counts(text,name):
    rules={
        'management_root.py':(('len(baseline)==594','len(baseline)==604'),('exact594 installed','exact604 installed'),('len(inventory())==592','len(inventory())==602')),
        'management_phase.py':(("len(missing['inventory'])==592","len(missing['inventory'])==602"),('len(inventory)==594','len(inventory)==604'),('present_count=594,absent_count=592','present_count=604,absent_count=602')),
        'management_contract.py':(("result.get('present_count')==594 and result.get('absent_count')==592 and len(result.get('inventory',{}))==594",
                                  "result.get('present_count')==604 and result.get('absent_count')==602 and len(result.get('inventory',{}))==604"),),
    }
    for old,new in rules.get(name,()):text=one(text,old,new)
    if name in ('management_root.py','management_contract.py','management_phase.py'):
        # Qualification only; preserve the original operation and guard bodies.
        count=text.count('GENERIC4K_UNPRIVILEGED_ACTUAL_DEFAULT_TOOLS')
        C.need(count==(0 if name=='management_root.py' else 1),'finite actual scope count differs')
        text=text.replace('GENERIC4K_UNPRIVILEGED_ACTUAL_DEFAULT_TOOLS','GENERIC16K_604_UNPRIVILEGED_ACTUAL_DEFAULT_TOOLS')
    ast.parse(text);return text


def runtime604(text):
    tree=ast.parse(text);main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
    begin=next(n for n in main.body if isinstance(n,ast.Try))
    starts=[n for n in begin.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='recipe_dir' for t in n.targets)]
    C.need(len(starts)==1,'one original install block required');start=starts[0]
    end=next(n for n in begin.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='inputs' for t in n.targets))
    lines=text.splitlines(keepends=True);old=''.join(lines[start.lineno-1:end.lineno-1])
    C.need(old.count("'package-build'")==1 and old.count("'runtime-image'")==1 and old.count('hosted.fetch')==1 and old.count('bind_local_base(')==1,'one complete historical build/fetch/install block required')
    replacement='''        runner = Path(__file__).resolve().parent
        import context604
        context604.verify(source,runner)
        bundle=runner/'ready604'
        expected=dict(line.split() for line in (bundle/'expected-installed.lock').read_text().splitlines())
        require(len(expected)==604 and all(expected.get(n)==v for n,v in base.items()),'exact604 closed installed target required')
        context=runner/'install-context'
        archives=[bundle/'packages'/json.loads((runner/'desktop-archive.json').read_text())['name']]
        base_reference = 'cachy-asahi-desktop574-base:' + os.urandom(16).hex()
        bind_local_base(image, base_reference, execute, text_command)
        report['base_reference'] = base_reference
        (context/'Dockerfile').write_text('FROM '+base_reference+'\\nCOPY . /tmp/managed604/\\nRUN python3 -I -B /tmp/managed604/install604.py && rm -rf /tmp/managed604\\n')
        iid=out/'runtime-image-id'
        execute(['docker','build','--network=none','--pull=false','--iidfile',str(iid),str(context)],'runtime-image',300)
        derived=iid.read_text().strip()
        require(re.fullmatch('sha256:[0-9a-f]{64}',derived) and derived!=image,'invalid604 derivative image')
        images.append(derived)
        report.update(base_image=image,runtime_image=derived,runtime_package_count=len(expected),
            workflow_scope='installed604-welcome4-management-generic16k',target_manifest_sha256=hashlib.sha256((bundle/'manifest.json').read_bytes()).hexdigest())
'''
    text=one(text,old,replacement)
    # Preserve the unchanged readonly installed desktop payload/configuration verifier.
    anchor="        verifier = out / 'verifier'; verifier.mkdir()"
    text=one(text,anchor,"        for row in json.loads((bundle/'manifest.json').read_text())['keyrings']:\n            shutil.copyfile(bundle/row['path'],inputs/Path(row['path']).name)\n"+anchor)
    ast.parse(text);return text


def prepare(source,output,assets,ready):
    C.check_source(source)
    method,derivation=derive16_prepare(source);method(source,output,assets)
    rows=C.json_read(ready/'manifest.json',1024**2)['packages'];byname={r['name']:r for r in rows}
    lock=C.json_read(output/'candidate-lock.json')
    for name,row in lock['products'].items():
        C.need(row['sha256']==byname[name]['sha256'] and row['version']==byname[name]['version'],'actual GUI archive and signed604 bundle differ')
    lock['producer_lifecycle']='ROOT_ACCEPTED_NATIVE604_AND_SEPARATE_CURRENT_WELCOME4_GUI'
    C.save(output/'candidate-lock.json',lock)
    for name in ('management_root.py','management_contract.py','management_phase.py'):
        p=output/name;p.write_text(transform_counts(p.read_text(),name))
    p=output/'contract.py';text=p.read_text();text=one(text,"return dict(baseline=original,management=M.verify_result(events,lock)",
        "return dict(baseline=original,diagnostic_kernel=original['diagnostic_kernel'],managed_session=original['managed_session'],management=M.verify_result(events,lock)")
    text=one(text,'    baseline=[e for e in events',"    C.need(len([e for e in events if e.get('event')=='installed604_preserved' and e.get('status')=='PASS'])==1,'complete604 final payload proof required')\n    baseline=[e for e in events")
    p.write_text(text)
    p=output/'desktop574_runtime.py';p.write_text(runtime604(p.read_text()))
    p=output/'desktop574_fixture.sh';text=p.read_text()
    anchor='python3 -I -B /runner/elf_audit.py'
    text=one(text,anchor,'cp /runner/installed604.py /runner/alpm_reader.py /runner/file_capabilities.py "$root/usr/local/share/desktop574/"\n'+
        'python3 -I -B /runner/installed604.py capture "$root" /runner/alpm_reader.py /runner/ready604/expected-installed.lock "$root/usr/local/share/desktop574/installed604.json" > /out/installed604-capture.json\n'+anchor)
    p.write_text(text)
    p=output/'base_guest.py';text=p.read_text()
    text=one(text,"        need(code == 0, 'desktop user session failed')", "        need(code == 0, 'desktop user session failed')\n"+
        "        proof=command(['/usr/bin/python3','-I','-B',str(SHARE/'installed604.py'),'verify','/',str(SHARE/'alpm_reader.py'),str(SHARE/'expected.lock'),str(SHARE/'installed604.json')],env,logs,'installed604-preserved',timeout=600)\n"+
        "        emit('installed604_preserved',status='PASS',receipt=json.loads(proof),hardware='NOT_RUN')")
    p.write_text(text)
    shutil.copyfile(C.HERE/'installed604.py',output/'installed604.py')
    shutil.copyfile(C.checked(source,dict(path='scripts/apps/file_capabilities.py',**C.pins()['scripts/apps/file_capabilities.py'])),output/'file_capabilities.py')
    shutil.copyfile(source/'scripts/ci/full-root-upgrade/root_upgrade.py',output/'alpm_reader.py')
    C.save(output/'adapter.json',dict(status='DERIVED_SOURCE_ONLY',kernel_adapter=derivation,scope=C.SCOPE,native='NOT_RUN',hardware='NOT_RUN'))
    return output

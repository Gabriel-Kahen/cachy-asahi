# SPDX-License-Identifier: MIT
"""Materialize a closed derivative of the pinned existing native owner."""
import ast
from pathlib import Path
import contract as K
import profile_adapter as A

ORIGINAL='scripts/ci/welcome-management-native'
NAMES=('native_contract.py','input-policy.json','infrastructure-pins.json','installed.py','lifecycle.py','run.py','job.py',
       'prepare.py','management_contract.py','management_phase.py','management_root.py','doctor_lifetime.py','a11y_driver.c','candidates.py')

def bodies(source,selected):
    K.profile(selected);pins=K.read(K.HERE/'source-pins.json')['files'];K.files(source,pins)
    original={name:(source/ORIGINAL/name).read_bytes() for name in NAMES};values=dict(original)
    def edit(name,fn):values[name]=fn(values[name].decode()).encode()
    def select(t):return A.replace(t,"for stage in ('minimal','overlay'):",'for stage in '+repr((selected,))+':')
    edit('management_contract.py',lambda t:'INDEPENDENT_PROFILE = '+repr(selected)+'\n'+A.replace(A.replace(select(t),
        'def verify_result(events,lock):',
        'def verify_result(events,lock):\n    need({e["stage"] for e in events if "stage" in e}=={'+repr(selected)+'},"foreign or missing profile event")'),
        'PASS_MANAGEMENT_NATIVE_METADATA_PIXELS_PENDING_REVIEW','PASS_SINGLE_PROFILE_MANAGEMENT_METADATA_PIXELS_PENDING_REVIEW'))
    def root(t):
        t=A.replace(t,"stage==('minimal' if not profiles else 'overlay') and stage not in profiles and (not profiles or retired_profiles=={'minimal'})",
            'stage=='+repr(selected)+' and not profiles and not retired_profiles')
        t=A.replace(t,"set(profiles)==retired_profiles=={'minimal','overlay'}",'set(profiles)==retired_profiles=={'+repr(selected)+'}')
        return 'INDEPENDENT_PROFILE = '+repr(selected)+'\n'+t
    edit('management_root.py',root)
    edit('native_contract.py',lambda t:A.replace(A.replace(t,"LABEL='org.cachy-asahi.welcome-management-native.job'",
        "LABEL='org.cachy-asahi.welcome-independent-profile-native.job'"),"HERE.parent/'welcome-native/contract.py'",repr(str(source/'scripts/ci/welcome-native/contract.py'))))
    # The unchanged original generator performs all source/package validation;
    # only its final generated runner is narrowed to the selected full profile.
    edit('prepare.py',lambda t:A.replace(A.replace(t,'import candidates\nimport management_contract as M\n','import candidates\nimport management_contract as M\nimport profile_adapter\n'),
        '    return output\n','    profile_adapter.runner(output,'+repr(selected)+')\n    return output\n'))
    def run(t):
        t=A.replace(t,"report=dict(status='FAIL',scope=",'report=dict(status=\'FAIL\',profile='+repr(selected)+',scope=')
        t=A.replace(t,'PASS_INSTALLED_WELCOME_MANAGEMENT_GUI_METADATA',K.GUI)
        t=A.replace(t,'PASS_NATIVE_MANAGEMENT_PAIR_READONLY_LIFECYCLE_AND_GUI',K.NATIVE)
        return t
    edit('run.py',run)
    def job(t):
        t=A.replace(t,'len(manifest[\'files\'])<=256',"len(manifest['files'])<=512")
        t=A.replace(t,"manifest.get('status')=='FROZEN_ROOT_FINAL_SOURCE'","manifest.get('status')=='FROZEN_ROOT_INDEPENDENT_PROFILE_SOURCE'")
        t=A.replace(t,"'welcome-management-consumer:'","'welcome-independent-profile:"+selected+":'")
        t=A.replace(t,"for stage in ('minimal','overlay'):",'for stage in '+repr((selected,))+':')
        t=A.replace(t,'len(frame_rows)==24','len(frame_rows)==12')
        t=A.replace(t,'all24 original first frame identities required','all12 selected original first frame identities required')
        t=A.replace(t,'PASS_NATIVE_MANAGEMENT_PAIR_READONLY_LIFECYCLE_AND_GUI',K.NATIVE)
        t=A.replace(t,'PASS_INSTALLED_WELCOME_MANAGEMENT_GUI_METADATA',K.GUI)
        t=A.replace(t,'PASS_NATIVE_MANAGEMENT_METADATA_PIXELS_PENDING_ROOT_REVIEW',K.RETAINED,2)
        return t
    edit('job.py',job)
    values['profile_adapter.py']=(K.HERE/'profile_adapter.py').read_bytes()
    for name,raw in values.items():
        if name.endswith('.py'):ast.parse(raw,filename=name)
    receipt=dict(schema_version=1,profile=selected,scope='ONE_PROFILE_NOT_FULL_GUI_ACCEPTANCE',
        originals={name:K.pin(source/ORIGINAL/name) for name in NAMES},derived={name:A.pin(raw) for name,raw in values.items()})
    values['derivation.json']=K.encoded(receipt);return values

def materialize(source,selected,output):
    values=bodies(source,selected)
    if output.exists():
        K.need(output.is_dir() and not output.is_symlink() and {p.name for p in output.iterdir()}==set(values),'closed existing derivative required')
        for name,raw in values.items():
            path=output/name;K.need(not path.is_symlink() and K.pin(path)==A.pin(raw),'derivative drift: '+name)
    else:
        output.mkdir(mode=0o700)
        for name,raw in values.items():
            with (output/name).open('xb') as stream:stream.write(raw)
    return output

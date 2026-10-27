# SPDX-License-Identifier: MIT
"""Exact-anchor adapters; inherited producer/build/source/ownership files unchanged."""
from pathlib import Path
import hashlib
import contract as C

HERE=Path(__file__).resolve().parent


def source(kind,root):
    C.need(kind in ('run','job'),'fixed inherited helper required');text=C.pinned(root,'scripts/ci/tools-native/'+kind+'.py')
    replacements=[('PASS_NATIVE_TOOLS_PAIRS_AND_CLI_PTY_LIFECYCLE','PASS_NATIVE_SETUP8_PAIR_AND_LEGACY_LIFECYCLE',1)]
    if kind=='run':
        replacements += [('len(self)<8','len(self)<6',1),('THREE_UNSELECTED_TOOLS_CANDIDATES','TWO_UNSELECTED_SETUP_PROFILES',1),
            ("'--env=CACHY_ASAHI_TOOLS_LIFECYCLE=1'", "'--env=CACHY_ASAHI_SETUP8_LIFECYCLE=1','--env=CACHY_ASAHI_SETUP7_LIFECYCLE=1'", 1),
            ("            '--mount',f'type=bind,src={source}/scripts/ci/zsh-highlighting-native,dst=/highlighting-fixture,readonly',\n", "            '--mount',f'type=bind,src={source}/scripts/ci/setup7-native,dst=/baseline7,readonly',\n", 1),
            ("shutil.copytree(source/'packages/tools'/name,context/'sources'/name)","C.stage_recipe(source,context/'sources'/name,name)",1),
            ("        container='cachy-asahi-product-lifecycle-'", "        C.stage_retained(context,checks,bind)\n        container='cachy-asahi-product-lifecycle-'",1),
            ('signal.ITIMER_REAL,2350','signal.ITIMER_REAL,1500',1),("if __name__=='__main__':","def main():",1)]
    else:
        replacements += [('MAX_TOTAL=192*1024**2','MAX_TOTAL=96*1024**2',1),('len(names)<=8','len(names)<=6',1),
            ("len(owner['containers'])==8","len(owner['containers'])==6",1),("len(ordered['consumer']['containers'])==8","len(ordered['consumer']['containers'])==6",1),
            ('all eight owned consumers','all six owned consumers',1),
            ("C.validate_lifecycle(report['lifecycle'])", "actual_lifecycle=read(runtime/'lifecycle.json',4*1024**2);C.need(report['lifecycle']==actual_lifecycle,'report lifecycle differs');C.validate_lifecycle(actual_lifecycle)",1),
            ('scripts/ci/tools-native','scripts/ci/setup8-native',2),('tools-consumer:','setup8-consumer:',1),
            ('PASS_NATIVE_TOOLS_CANDIDATES_CLI_PTY_LIFECYCLE','PASS_NATIVE_SETUP8_CANDIDATE_LEGACY_LIFECYCLE',2),
            ("    for path in sorted((source/'scripts/ci/setup8-native').iterdir()):\n        if path.is_file():copy(path,'harness/'+path.name,2*1024**2)",
             "    for relative in read(source/'scripts/ci/setup8-native/source-manifest.json')['files']:\n        if relative.startswith('scripts/ci/setup8-native/'):\n            path=source/relative;copy(path,'harness/'+path.name,2*1024**2)",1),
            ("        for path in sorted((source/'packages/tools'/product).iterdir()):copy(path,'source/'+product+'/'+path.name,1024**2)",
             "        for basename in sorted(C.recipe(source,product)['input_sha256']):\n            path=source/C.recipe_path(product)/basename;copy(path,'source/'+product+'/'+path.name,1024**2)",1),
            ("    try:\n        C.verify_source(source)\n        source_proof=", "    import retained\n    for name in read(source/'scripts/ci/setup7-native/retained-inputs.json'):\n        copy(runtime/'lifecycle-inputs/retained-setup4'/name,'retained-setup4/'+name,1024**2)\n    for profile in (*C.LEGACY,'new-grouped-journal'):\n        for phase in ('legacy','upgrade','rollback','forward'):\n            name=profile+'-'+phase+'.json';copy(runtime/'observations'/name,'observations/'+name,65536)\n    try:\n        C.verify_source(source)\n        retained.verify(runtime/'lifecycle-inputs/retained-setup4')\n        source_proof=",1),
            ("        C.need(read(runtime/'lifecycle.json',4*1024**2)==report['lifecycle'],'parent/standalone lifecycle mismatch')",
             "        C.need(read(runtime/'lifecycle.json',4*1024**2)==report['lifecycle'],'parent/standalone lifecycle mismatch')\n        for row in actual_lifecycle['baseline7']['actual_observations']:\n            C.need(read(runtime/'observations'/(row['profile']+'-'+row['phase']+'.json'))==row['proof'],'standalone user observation differs')",1),
            (",external_mirror_rank='NOT_RUN'",'',1),("if __name__=='__main__':","def main():",1)]
    if kind=='job':
        replacements += [("    try:\n        C.verify_source(source)\n        retained.verify(runtime/'lifecycle-inputs/retained-setup4')", "    copy(base/'setup7-retained-inputs.json','base/setup8-retained-inputs.json',2*1024**2)\n    copy(runtime/'recovery-preview.json','runtime/recovery-preview.json',65536)\n    import retained5\n    for name in read(source/'scripts/ci/setup7-native/setup5-carrier.json')['files']:\n        copy(runtime/'lifecycle-inputs/retained-setup5'/name,'retained-setup5/'+name,2*1024**2)\n    try:\n        C.verify_source(source)\n        retained.verify(runtime/'lifecycle-inputs/retained-setup4')\n        retained5.verify(runtime/'lifecycle-inputs/retained-setup5')",1)]
    if kind=='run':
        replacements += [("            '--mount',f'type=bind,src={HERE},dst=/runner,readonly',\n", "            '--mount',f'type=bind,src={source},dst=/source,readonly',\n            '--mount',f'type=bind,src={HERE},dst=/runner,readonly',\n",1)]
    if kind=='job':
        replacements += [("expected=product+'-'+C.version(source,product)+'-any.pkg.tar.'", "expected=C.PACKAGE+'-'+C.version(source,product)+'-any.pkg.tar.'",1),
            ("name=product+'-'+version+'-any.pkg.tar.'+suffix", "name=C.PACKAGE+'-'+version+'-any.pkg.tar.'+suffix",1),
            ("basename.startswith(product+'-')", "basename.startswith(C.PACKAGE+'-')",1),
            ("    try:\n        C.verify_source(source)\n        retained.verify(runtime/'lifecycle-inputs/retained-setup4')", "    for relative in read(source/'scripts/ci/setup8-native/source-manifest.json')['files']:\n        copy(source/relative,'source-context/'+relative,16*1024**2)\n    for name in ('baseline7-lifecycle.json','migration-delivery.json','migration-reinstall.json','upgrade-home.json'):\n        copy(runtime/name,'runtime/'+name,1024**2)\n    try:\n        C.verify_source(source)\n        retained.verify(runtime/'lifecycle-inputs/retained-setup4')",1),
            ("        C.need(read(runtime/'lifecycle.json',4*1024**2)==report['lifecycle'],'parent/standalone lifecycle mismatch')", "        C.need(read(runtime/'lifecycle.json',4*1024**2)==report['lifecycle'],'parent/standalone lifecycle mismatch')\n        for key,name in (('baseline7','baseline7-lifecycle.json'),('migration_delivery','migration-delivery.json'),('migration_reinstall','migration-reinstall.json'),('upgrade_home','upgrade-home.json')):\n            C.need(read(runtime/name,1024**2)==actual_lifecycle[key],'standalone installed proof differs')",1)]
    for old,new,count in replacements:
        C.need(text.count(old)==count,'frozen '+kind+' adapter anchor differs: '+old[:72]);text=text.replace(old,new)
    return text


def adapter(kind,root):
    value=dict(__file__=str(HERE/(kind+'.py')),__name__='setup8_accepted_'+kind);exec(compile(source(kind,root),value['__file__'],'exec'),value);value['C']=C
    if kind=='job':
        original=value['prove']
        def prove(*args):
            result=original(*args);result['setup8_adapter_sha256']={n:hashlib.sha256(source(n,root).encode()).hexdigest() for n in ('run','job')};result['setup8_adapter_sha256']['welcome_build']=hashlib.sha256(C.build_source(root).encode()).hexdigest();return result
        value['prove']=prove
    return value

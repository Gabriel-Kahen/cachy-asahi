# SPDX-License-Identifier: MIT
"""Small exact-anchor adapters for the two immutable tools-native helpers."""
import hashlib
from pathlib import Path
import contract as C

HERE=Path(__file__).resolve().parent


def source(kind,root):
    C.need(kind in ('run','job'),'fixed inherited helper required')
    text=C.pinned(root,'scripts/ci/tools-native/'+kind+'.py')
    replacements=[('PASS_NATIVE_TOOLS_PAIRS_AND_CLI_PTY_LIFECYCLE','PASS_NATIVE_FISH_AUTOPAIR_PAIR_AND_LIFECYCLE',1)]
    if kind=='run':
        replacements += [('len(self)<8','len(self)<4',1),('THREE_UNSELECTED_TOOLS_CANDIDATES','ONE_UNSELECTED_FISH_AUTOPAIR_CANDIDATE',1),
            ('--env=CACHY_ASAHI_TOOLS_LIFECYCLE=1','--env=CACHY_ASAHI_FISH_AUTOPAIR_LIFECYCLE=1',1),
            ("            '--mount',f'type=bind,src={source}/scripts/ci/zsh-highlighting-native,dst=/highlighting-fixture,readonly',\n",'',1),
            ('signal.ITIMER_REAL,2350','signal.ITIMER_REAL,1350',1),
            ("if __name__=='__main__':","def main():",1)]
    else:
        replacements += [('MAX_TOTAL=192*1024**2','MAX_TOTAL=96*1024**2',1),('len(names)<=8','len(names)<=4',1),
            ("len(owner['containers'])==8","len(owner['containers'])==4",1),
            ("len(ordered['consumer']['containers'])==8","len(ordered['consumer']['containers'])==4",1),
            ('all eight owned consumers','all four owned consumers',1),
            ('scripts/ci/tools-native','scripts/ci/fish-autopair-native',2),('tools-consumer:','fish-autopair-consumer:',1),
            ('PASS_NATIVE_TOOLS_CANDIDATES_CLI_PTY_LIFECYCLE','PASS_NATIVE_FISH_AUTOPAIR_CANDIDATE_LIFECYCLE',2),
            ("C.validate_lifecycle(report['lifecycle'])",
             "C.validate_retained_lifecycle(report,read(runtime/'lifecycle.json',4*1024**2))",1),
            ("    for path in sorted((source/'scripts/ci/fish-autopair-native').iterdir()):\n        if path.is_file():copy(path,'harness/'+path.name,2*1024**2)",
             "    for relative in read(source/'scripts/ci/fish-autopair-native/source-manifest.json')['files']:\n        if relative.startswith('scripts/ci/fish-autopair-native/'):\n            path=source/relative;copy(path,'harness/'+path.name,2*1024**2)",1),
            ("        for path in sorted((source/'packages/tools'/product).iterdir()):copy(path,'source/'+product+'/'+path.name,1024**2)",
             "        for basename in sorted(C.recipe(source,product)['input_sha256']):\n            path=source/'packages/tools'/product/basename;copy(path,'source/'+product+'/'+path.name,1024**2)",1),
            (",external_mirror_rank='NOT_RUN'",'',1),("if __name__=='__main__':","def main():",1)]
    for old,new,count in replacements:
        C.need(text.count(old)==count,'frozen '+kind+' adapter anchor differs: '+old[:72]);text=text.replace(old,new)
    return text


def adapter(kind,root):
    namespace=dict(__file__=str(HERE/(kind+'.py')),__name__='fish_autopair_accepted_'+kind)
    exec(compile(source(kind,root),namespace['__file__'],'exec'),namespace)
    namespace['C']=C
    if kind=='job':
        original=namespace['prove']
        def prove(*args):
            result=original(*args)
            result['fish_adapter_sha256']={name:hashlib.sha256(source(name,root).encode()).hexdigest() for name in ('run','job')}
            return result
        namespace['prove']=prove
    return namespace

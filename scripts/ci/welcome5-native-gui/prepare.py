#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit a source-bound Welcome5/DNS2 runner, without changing historical lanes."""
import argparse,ast,hashlib,importlib.util,json,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import candidates as A
import derive as D
HERE=Path(__file__).resolve().parent

def prepare(source,assets,output,selected):
    # NULL selection refuses before output creation, package staging or actors.
    A.selection(source);A.need(selected in ('minimal','overlay'),'explicit independent profile required');A.PROFILE=selected;A.need(not output.exists(),'fresh generated runner required')
    before={k:v for k,v in sys.modules.items()if k in ('native_contract','candidates','management_contract')}
    try:
        C=A.load('native_contract',source/'scripts/ci/welcome-management-native/native_contract.py')
        M=A.load('management_contract',source/'scripts/ci/welcome-management-native/management_contract.py')
        shared=A.load('welcome5_original_prepare',source/'scripts/ci/welcome-management-native/prepare.py')
        shared.C=C;shared.M=M;shared.candidates=A
        shared.prepare(source,output,assets)
        changes=D.runner(source,output)
        independent=D.independent(source,output,selected)
        for name in ('candidates.py','source-manifest.json','input-policy.json'):
            shutil.copyfile(HERE/name,output/name)
        runtime=(output/'desktop574_runtime.py').read_text()
        runtime=D.once(runtime,'for name in ("TEST-public.asc","control.json"):',
            'for name in ("TEST-public.asc","control.json","trust.json","trust.py","welcome5-TEST.asc","dns2-TEST.asc"):')
        start='mkdir -m700 /tmp/management-trust';finish='&& ldconfig'
        A.need(runtime.count(start)==1,'exact original disposable signature-trust setup required')
        left=runtime.index(start);right=runtime.index(finish,left)
        old=runtime[left:right]
        A.need('SigLevel = Required'in old and 'LocalFileSigLevel = Required'in old and 'pacman -U --noconfirm --noscriptlet --config /tmp/management.conf /tmp/products/*.pkg.tar.xz'in old,'original Required signature gate differs')
        runtime=runtime[:left]+'python3 /tmp/products/trust.py && pacman -U --noconfirm --noscriptlet --config /tmp/management.conf /tmp/products/*.pkg.tar.xz && gpgconf --homedir /tmp/management-trust --kill all && rm -rf /tmp/management-trust /tmp/management.conf '+runtime[right:]
        (output/'desktop574_runtime.py').write_text(runtime)
        for path in output.glob('*.py'):ast.parse(path.read_text(),filename=str(path))
        files={p.name:dict(bytes=p.stat().st_size,sha256=A.digest(p))for p in output.iterdir()if p.is_file()and p.name!='runner-proof.json'}
        (output/'runner-proof.json').write_text(json.dumps(dict(status='DERIVED_SOURCE_ONLY_GUI_NOT_RUN',files=files,
            original_twelve_views='REQUIRED',added_view='management-dns',present_count=595,absent_count=593,
            native_pair_inputs='INPUTS_ONLY',source_derivative=changes,profile=selected,independent_profile_derivation=independent,actuals={'minimal':None,'overlay':None},hardware='NOT_RUN'),sort_keys=True,indent=2)+'\n')
        return output
    finally:
        for name in ('native_contract','candidates','management_contract'):
            if name in before:sys.modules[name]=before[name]
            else:sys.modules.pop(name,None)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','assets','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--profile',required=True,choices=('minimal','overlay'))
    a=p.parse_args();print(prepare(a.source.absolute(),a.assets.absolute(),a.output.absolute(),a.profile))
if __name__=='__main__':main()

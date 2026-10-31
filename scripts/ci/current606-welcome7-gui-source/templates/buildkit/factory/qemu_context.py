# SPDX-License-Identifier: MIT
"""Original sixteen-tool controller context, kept out of the exact606 guest."""
import importlib.util,json,shutil,sys
from pathlib import Path
import context606 as C
HERE=Path(__file__).resolve().parent

def prepare(source,cache,out,ready):
    base=C.obj(source/'scripts/ci/maintained-desktop574-inputs.json');expected={r['name']:r['version']for r in base['packages']};rows=[r for r in C.obj(source/'scripts/virtual/tooling.lock.json')['packages']if r['name']not in expected];C.need(len(rows)==16 and len({r['name']for r in rows})==16,'original exact16 tooling additions')
    names=set()
    for r in rows:
        for suffix,size,sha in [('',r['size'],r['sha256']),('.sig',r['signature_size'],r['signature_sha256'])]:C.checked(cache,r['filename']+suffix,size,sha);names.add(r['filename']+suffix)
    C.need({p.name for p in cache.iterdir()}==names,'exact32 original tooling cache members; no mirror fallback')
    context=out/'qemu-context';(context/'packages').mkdir(parents=True)
    s=importlib.util.spec_from_file_location('_qemu_context_package_checks',source/'scripts/checks/package_checks.py');checks=importlib.util.module_from_spec(s);s.loader.exec_module(checks);payload=[]
    # Reuse the original official metadata reader without executing its
    # download, GPG or main entrypoints. Scope its ordinary helper import.
    saved=sys.modules.get('common');spec=importlib.util.spec_from_file_location('common',HERE/'support/common.py');common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common);sys.modules['common']=common
    try:
        spec=importlib.util.spec_from_file_location('_gui_official_tooling',HERE/'support/audit_tooling.py');official=importlib.util.module_from_spec(spec);spec.loader.exec_module(official)
    finally:
        if saved is None:sys.modules.pop('common',None)
        else:sys.modules['common']=saved

    for r in rows:
        expected[r['name']]=r['version']
        for suffix in('','.sig'):shutil.copyfile(cache/(r['filename']+suffix),context/'packages'/(r['filename']+suffix))
        official_report=official.inspect(cache/r['filename'],r);C.need(official_report['archive_sha256']==r['sha256'],'original official eight-field metadata and whole archive check');report=checks.package(cache/r['filename']);diagnostics=C.obj(HERE/'profile.json')['controller_official_project_policy_diagnostics'];C.need(report['errors']==diagnostics.get(r['name'],[])and report['metadata']['.PKGINFO']['pkgname']==[r['name']]and report['metadata']['.PKGINFO']['pkgver']==[r['version']],'whole actual original tooling package')
        payload.append(dict(name=r['name'],version=r['version'],project_policy_diagnostics=report['errors'],payload={n:v for n,v in report['members'].items()if v['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')}))
    C.need(len(expected)==590,'controller590 distinct from guest606');(context/'expected590.lock').write_text(''.join(n+' '+v+'\n'for n,v in sorted(expected.items())))
    manifest=C.obj(ready/'manifest.json');key=next(r for r in manifest['keyrings']if r['path']=='keys/archlinuxarm.gpg');shutil.copyfile(C.checked(ready,key['path'],key['size'],key['sha256']),context/'archlinuxarm.gpg')
    (context/'tooling.json').write_bytes(C.enc(dict(rows=rows,signer=manifest['preparation']['signer_roles']['upstream_ALARM'],payload=payload)))
    for n in('contract604.py','lifecycle604.py','alpm_reader.py'):shutil.copyfile(HERE/'support'/n,context/n)
    shutil.copyfile(HERE/'build_scope.py',context/'build_scope.py');shutil.copyfile(HERE/'install_tooling.py',context/'install_tooling.py');return {p.relative_to(context).as_posix():C.pin(C.read(p))for p in sorted(context.rglob('*'))if p.is_file()}

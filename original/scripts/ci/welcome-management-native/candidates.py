# SPDX-License-Identifier: MIT
"""Only same-job source-bound native pair outputs and public TEST verification inputs."""
import json
from pathlib import Path
import re
import shutil
import native_contract as C

NAMES=C.NAMES
need,digest,regular=C.need,C.digest,None
read=C.read
verify_source=C.verify_source


def regular(path,cap):
    import stat
    C.safe(Path(path).absolute());info=path.lstat();C.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=cap,'ordinary bounded native input required');return info


def stage(source,assets,output):
    C.verify_source(source);C.need(not output.exists(),'fresh candidate staging required')
    products=C.read(assets/'products.json');C.need(set(products)==set(NAMES),'three source-bound products required')
    checks=C.load('management_gui_archive_checks',source/'scripts/checks/package_checks.py')
    import sys
    sys.path[:0]=[str(source/'scripts/build'),str(source/'scripts/checks')]
    binding=C.load('management_gui_archive_binding',source/'scripts/build/build.py')
    for name,row in products.items():
        expected=name+'-'+C.version(source,name)+'-'+C.product(name)['arch']+'.pkg.tar.xz'
        path=assets/row['archive'];info=regular(path,8*1024**2)
        C.need(path.parent==assets and row['archive']==expected and C.digest(path)==row['sha256'] and row['version']==C.version(source,name),'fixed native candidate identity differs')
        recipe=C.recipe(source,name);checked=checks.package(path)
        C.need(not binding.bind_artifact(recipe['metadata'],checked,recipe['input_sha256']['PKGBUILD']) and C.payload(checked,source,name)==row['payload'],'native source/package/payload join differs')
        regular(assets/(row['archive']+'.sig'),16384)
    control=C.read(assets/'control.json');C.need(re.fullmatch('[0-9A-F]{40}',control.get('signer','')),'ephemeral TEST signer fingerprint required')
    regular(assets/'TEST-public.asc',65536)
    output.mkdir(mode=0o700)
    for row in products.values():
        for name in (row['archive'],row['archive']+'.sig'):shutil.copyfile(assets/name,output/name)
    for name in ('products.json','control.json','TEST-public.asc'):shutil.copyfile(assets/name,output/name)
    lock=dict(schema_version=1,status='VERIFIED_NATIVE_CANDIDATES',eligibility='PRIVATE_GUI_TRIAL_ONLY',products=products,policy=C.policy(),
        producer_lifecycle='PASS_SAME_JOB_SIGNED_THREE_PRODUCT_LIFECYCLE',signature='EPHEMERAL_TEST_ONLY')
    (output/'candidate-lock.json').write_bytes(C.encoded(lock));return lock

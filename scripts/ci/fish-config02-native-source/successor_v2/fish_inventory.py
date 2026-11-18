# SPDX-License-Identifier: MIT
"""Apply one exact physical inventory to the Fish bootstrap, build plans and finisher."""

from hashlib import sha256
from pathlib import Path
from types import ModuleType

HERE = Path(__file__).resolve().parent
INVENTORY_SHA = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
FINISHER_SHA = 'f6a10e289503044880b77c601afce4729286c5678c480adf936c7ad89427e0bb'
EDITS = (
    (b"        C.need((output/'bootstrap/packages.lock').read_bytes()==C.read(HERE/'expected349.lock'),'genuine exact freshly provisioned349 inventory')",
     b"        expected_inventory=FISH_INVENTORY.inventory(inputs)\n"
     b"        C.need((output/'bootstrap/packages.lock').read_bytes()==C.read(expected_inventory),'genuine exact freshly provisioned341 inventory')"),
    (b"        builds,compare=C.plans(HERE,output,image)",
     b"        builds,compare=FISH_INVENTORY.plans(C,HERE,output,image,expected_inventory)"),
    (b"        finisher=C.module(HERE/'finish_pair.py','fish02_finisher');",
     b"        finisher=FISH_INVENTORY.finisher(HERE,expected_inventory);"),
)


def need(ok, guard):
    if not ok:
        raise ValueError(guard)


def project_entry(raw):
    result = raw
    for before,after in EDITS:
        need(result.count(before)==1 and after not in result,'one exact Fish inventory seam')
        result=result.replace(before,after,1)
    restored=result
    for before,after in reversed(EDITS):
        restored=restored.replace(after,before,1)
    need(restored==raw,'whole original Fish inventory projection inverse')
    return result


def inventory(inputs):
    rootfs={row['name'][0]:row['version'][0] for row in inputs['rootfs_packages']}
    selected={row['name']:row['version'] for row in inputs['packages']}
    expected=rootfs|selected
    need(len(inputs['rootfs_packages'])==len(rootfs)==165 and len(inputs['packages'])==len(selected)==248
         and len(rootfs.keys()&selected.keys())==72 and len(expected)==341,
         'exact frozen rootfs and selected package populations')
    lock=HERE/'expected341.lock'
    raw=lock.read_bytes()
    derived=''.join(f'{name} {expected[name]}\n' for name in sorted(expected)).encode()
    need(raw==derived and sha256(raw).hexdigest()==INVENTORY_SHA,'whole exact derived Fish341 inventory')
    return lock


def plans(contract, here, output, image, lock):
    builds,compare=contract.plans(here,output,image)
    need(len(builds)==2,'exact pair of held Fish build plans')
    bound=[]
    for command in builds:
        need(command.count('--expected-packages')==1,'single expected package argument in each held build')
        index=command.index('--expected-packages')+1
        need(index<len(command) and command[index]==str(here/'expected349.lock'),'exact inherited Fish inventory operand')
        bound.append([*command[:index],str(lock),*command[index+1:]])
    return bound,compare


def finisher(here, lock):
    path=here/'finish_pair.py'
    raw=path.read_bytes()
    before=b"(HERE/'expected349.lock').read_bytes()"
    after=b"FISH_EXPECTED_LOCK.read_bytes()"
    need(sha256(raw).hexdigest()==FINISHER_SHA and raw.count(before)==1 and after not in raw,
         'exact held Fish finisher inventory seam')
    projected=raw.replace(before,after,1)
    need(projected.replace(after,before,1)==raw,'whole original Fish finisher inverse')
    module=ModuleType('fish02_exact_inventory_finisher')
    module.__file__=str(path)
    module.FISH_EXPECTED_LOCK=lock
    exec(compile(projected,str(path),'exec'),module.__dict__)
    return module

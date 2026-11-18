# SPDX-License-Identifier: MIT
"""Fixed signed dependency addition to Fish r12's owned bootstrap, no actor entrypoint."""
import ast
import json
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
import preflight as P

NATIVE_SHA='8e71ba83e7d5037c6f7772401ec3b872684ccfa8472d855d8d6d3052cb1f41ba'
PINS_SHA='b1e9bbb7e26ae0e6fe2b0e6414571d9952af3db67ff2bc7fe5a97559ea8e9643'
CONTEXT_LEAF='python3148-builder-delta'


def payload(directory):
    body=P.read(P.HERE/'material-pins.json',16<<10)
    P.need(P.pin(body)['sha256']==PINS_SHA,'exact staged package pin map')
    pins=json.loads(body)
    required={f'{name}-{version}-aarch64.pkg.tar.xz' for name,version in P.ADDITIONS.items()}
    required|={name+'.sig' for name in required}
    P.need({item.name for item in directory.iterdir()}==required,'exact four ALARM archive/signature pairs')
    return {name:P.read(directory/name,8<<20,pins[name]) for name in sorted(required)}


def project(native_source):
    P.need(P.pin(native_source)['sha256']==NATIVE_SHA,'exact pinned accepted native_arm.py build body')
    text=native_source.decode()
    node,=(row for row in ast.parse(text).body if isinstance(row,ast.FunctionDef) and row.name=='build')
    original=ast.get_source_segment(text,node).encode()
    P.need(original.count(b'shutil.copyfile(')==3,'expected accepted context handoff copies')
    original=original.replace(b'shutil.copyfile(',b'PINNED_CONTEXT_TRANSFER(')
    # All added archives join the existing Required ALPM transaction after trusted keys are
    # populated. They never touch the host ALPM database or extend the original carrier contract.
    substitutions=(
        (b"                  'COPY disabled-hooks.txt /tmp/disabled-hooks.txt\\n'",
         b"                  'COPY disabled-hooks.txt /tmp/disabled-hooks.txt\\n'\n"
         b"                  'COPY python3148-builder-delta/ /tmp/python3148-builder-delta/\\n'"),
        (b"                  '&& pacman -U --noconfirm --noscriptlet /tmp/deps/*.pkg.tar.xz '",
         b"                  '&& pacman -U --noconfirm --noscriptlet /tmp/deps/*.pkg.tar.xz /tmp/python3148-builder-delta/*.pkg.tar.xz '"),
        (b"'&& ldconfig && rm -rf /tmp/deps /var/cache/pacman/pkg/* '",
         b"'&& ldconfig && rm -rf /tmp/deps /tmp/python3148-builder-delta /var/cache/pacman/pkg/* '"),
        (b"    (context / 'Dockerfile').write_text(dockerfile)",
         b"    _stage_exact_python_delta(context)\n    (context / 'Dockerfile').write_text(dockerfile)"),
        (b"    if lock != ''.join(f'{name} {version}\\n' for name, version in sorted(expected.items())):",
         b"    _extend_python345_inventory(expected)\n"
         b"    if lock != ''.join(f'{name} {version}\\n' for name, version in sorted(expected.items())):"),
    )
    result=original
    for before,after in substitutions:
        result=P.substitute(result,before,after)
    inverse=result
    for before,after in reversed(substitutions):
        inverse=inverse.replace(after,before,1)
    P.need(inverse==original,'whole accepted native build inverse')
    compile(result,'<python3148-signed-native-bootstrap>','exec')
    return result


def extend(expected):
    raw=(''.join(f'{name} {version}\n' for name,version in sorted(expected.items()))).encode()
    P.lock_inventory(raw)
    expected.update(P.ADDITIONS)


def bind(native, source, directory):
    """Install the projection after the caller's separately admitted Fish context handoff."""
    P.need(callable(getattr(native,'PINNED_CONTEXT_TRANSFER',None)),
           'existing same-inode ALARM carrier transfer must already be bound')
    projected=project(source)
    operands=payload(directory)

    def stage(context):
        path=context/CONTEXT_LEAF
        info=context.lstat()
        P.need(context.name=='context' and context.resolve()==context and stat.S_ISDIR(info.st_mode)
               and info.st_uid==os.getuid() and not stat.S_IMODE(info.st_mode)&0o022,
               'existing owned bootstrap context')
        path.mkdir(mode=0o700)
        for name,raw in operands.items():
            P.put(path/name,raw,0o644)
        P.need(payload(path)==operands,'exact uploaded supplemental ALPM payload bytes')

    native.__dict__['_stage_exact_python_delta']=stage
    native.__dict__['_extend_python345_inventory']=extend
    exec(compile(projected,'<python3148-signed-native-bootstrap>','exec'),native.__dict__)
    return projected


def retire(context):
    """Retire only the spent supplemental directory after the owned context upload."""
    owned=context/CONTEXT_LEAF
    before=payload(owned)
    for name,raw in before.items():
        path=owned/name
        P.read(path,8<<20,P.pin(raw))
        path.unlink()
    owned.rmdir()

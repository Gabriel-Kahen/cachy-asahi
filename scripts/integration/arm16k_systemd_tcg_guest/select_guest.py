#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Select whole installed package records from the exact signed rootfs DATA."""
import argparse
import ctypes
import json
from pathlib import Path
import re

TARGETS=('filesystem','bash','coreutils','systemd','pambase','dbus-broker-units','util-linux',
         'shadow','pacman','archlinuxarm-keyring','procps-ng','e2fsprogs','gnupg','curl',
         'ca-certificates','tar','gzip','zstd','xz','sed','grep','findutils')
ALPM=None


def version_compare(version,wanted):
    # Pure DATA imports work on non-Arch hosts; actual selection still requires
    # the original ALPM16 comparator and has no replacement/version fallback.
    global ALPM
    if ALPM is None:
        library=ctypes.CDLL('libalpm.so.16')
        library.alpm_pkg_vercmp.argtypes=[ctypes.c_char_p,ctypes.c_char_p]
        library.alpm_pkg_vercmp.restype=ctypes.c_int
        ALPM=library
    return ALPM.alpm_pkg_vercmp(version.encode(),wanted.encode())


def atom(value):
    match=re.fullmatch(r'([A-Za-z0-9@._+:-]+)(?:(>=|<=|=|>|<)([^\s]+))?',value)
    if not match:raise ValueError('unsupported dependency expression: '+value)
    return match.groups()


def satisfies(version,operator,wanted):
    if not operator:return True
    if version is None:return False
    compared=version_compare(version,wanted)
    return {'=':compared==0,'>=':compared>=0,'<=':compared<=0,'>':compared>0,'<':compared<0}[operator]


def select(index):
    packages={row['desc']['NAME'][0]:(directory,row)for directory,row in index['packages'].items()}
    provides={}
    for name,(_,row)in packages.items():
        for text in row['desc'].get('PROVIDES',[]):
            symbol,op,version=atom(text)
            if op not in (None,'='):raise ValueError('unsupported provided version')
            provides.setdefault(symbol,[]).append((name,version))
    selected=set();pending=list(TARGETS);edges=[]
    while pending:
        expression=pending.pop();name,op,wanted=atom(expression)
        if name in packages and satisfies(packages[name][1]['desc']['VERSION'][0],op,wanted):provider=name
        else:
            candidates=[p for p,v in provides.get(name,[])if satisfies(v,op,wanted)]
            if len(candidates)!=1:raise ValueError('missing/ambiguous rootfs provider: '+expression)
            provider=candidates[0]
        if provider in selected:continue
        selected.add(provider);deps=packages[provider][1]['desc'].get('DEPENDS',[])
        edges += [{'package':provider,'dependency':d}for d in deps];pending+=deps
    paths=set();records=[]
    for name in sorted(selected):
        directory,row=packages[name]
        for p in row['files'].get('FILES',[]):paths.add(p.rstrip('/'))
        paths|={p for p in index['nodes']if p.startswith('var/lib/pacman/local/'+directory+'/')}
        records.append({'name':name,'version':row['desc']['VERSION'][0],'directory':directory,
                        'inherited_validation':row['desc'].get('VALIDATION',[]),'desc':row['desc']})
    paths|={'var/lib/pacman/local/ALPM_DB_VERSION','etc/passwd','etc/group','etc/shadow','etc/gshadow'}
    # Whole selected package payloads and their exact copied registration, no partial pruning.
    missing=sorted(p for p in paths if p not in index['nodes'])
    if missing:raise ValueError('selected installed payload absent in rootfs: '+repr(missing[:8]))
    paths|={str(parent)for p in list(paths)for parent in Path(p).parents if str(parent)!='.'}
    logical=sum(index['nodes'].get(p,{}).get('bytes',0)for p in paths)
    if logical>1024**3:raise ValueError('selected guest exceeds 1GiB data cap')
    return {'schema':1,'targets':list(TARGETS),'packages':records,'paths':sorted(paths),
        'logical_file_bytes':logical,'dependency_edges':edges,
        'package_registration':'copied selected original installed DB; no new guest ALPM transaction',
        'signature':'whole exact rootfs detached signature required; per-package validation is inherited DATA',
        'excluded':'unselected base metapackage, stock kernel/modules/firmware and other unselected packages',
        'VM_boot':'NOT RUN','native_ARM':'NOT RUN','M2':'NOT RUN'}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--index',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();result=select(json.loads(a.index.read_text()))
    with a.output.open('x')as f:json.dump(result,f,indent=2,sort_keys=True)
    print(json.dumps({'packages':len(result['packages']),'paths':len(result['paths']),
                      'logical_file_bytes':result['logical_file_bytes'],'VM_boot':'NOT RUN'}))

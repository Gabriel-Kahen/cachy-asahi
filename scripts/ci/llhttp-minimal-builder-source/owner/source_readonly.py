# SPDX-License-Identifier: MIT
"""Declare only the exact Source bind read-only; never mutate Source contents."""
from pathlib import Path
import re

DECLARATION=dict(kind='LLHTTP_EXACT_SOURCE_READONLY_NAMESPACE_V5',
    source='EXACT_DECLARED_CANONICAL_SOURCE_ROOT',namespaces=['owner','daemon'],
    property='BindReadOnlyPaths',quota_readwrite_paths_unchanged=True,
    tmp_vartmp_readonly_unchanged=True,source_staging_overlap=False,
    source_contents_changed=False,guard_predicates_unchanged=True,
    actual_namespace_effect='REQUIRES_NEXT_ACTUAL_NATIVE_OBSERVATION')

def need(value,why):
    if not value:raise ValueError(why)

def _canonical(value):
    path=Path(value)
    need(str(value)==str(path) and path.is_absolute() and re.fullmatch(r'/[A-Za-z0-9_./-]+',str(path))
         and path==path.resolve() and not any(p.is_symlink() for p in (path,*path.parents)),
         'exact declared canonical namespace path without aliases or property syntax')
    need(not path.exists() or path.is_dir(),'namespace roots and writable destinations must be directories')
    return path

def project_service(argv,root,out,nonce,kind):
    """Pure argv projection after existing executable/source/custody admission."""
    root,out=map(_canonical,(root,out))
    need(root!=Path('/') and root!=out and not root.is_relative_to(out)
         and not out.is_relative_to(root),'Source and all staging/quota paths must be disjoint')
    need(kind in ('owner','daemon') and re.fullmatch('[0-9a-f]{32}',nonce or ''),
         'exact owned service kind and nonce')
    need(type(argv) is list and 20<len(argv)<256 and all(type(a) is str and a for a in argv)
         and argv.count('--')==1,'complete existing finite service argv')
    boundary=argv.index('--');properties=argv[:boundary]
    group='/sys/fs/cgroup/system.slice/cachy-llhttp-minimal-builder-'+nonce+'-daemon.service'
    volume=out/'volume'
    writable=str(volume/'work') if kind=='owner' else str(volume)+' '+group
    required={'ProtectSystem':'strict','ReadOnlyPaths':'/tmp /var/tmp /sys/fs/cgroup',
              'ReadWritePaths':writable}
    for key,wanted in required.items():
        found=[a for a in properties if a.startswith('--property='+key+'=')]
        need(found==['--property='+key+'='+wanted],'unchanged exact existing namespace property: '+key)
    forbidden=('BindPaths','BindReadOnlyPaths','ReadWriteDirectories','ReadOnlyDirectories',
               'RootDirectory','RootImage','TemporaryFileSystem','ProtectControlGroups','MountFlags')
    need(not any(a.startswith('--property='+key+'=') for a in properties for key in forbidden),
         'no existing bind/root/temporary-filesystem override or writable alias')
    # Check the full pre-existing writable destinations, not just the work leaf.
    for value in writable.split(' '):
        path=_canonical(value)
        need(not root.is_relative_to(path) and not path.is_relative_to(root),
             'exact Source cannot overlap any writable namespace destination')
    return [*argv[:boundary],'--property=BindReadOnlyPaths='+str(root),*argv[boundary:]]

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only libalpm cache queries. CLI runs only in the explicit native container."""
import argparse
import ctypes
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import platform
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

HERE=Path(__file__).resolve().parent
HELPER=HERE/'retained-orphans-reader'
QUERIES=(('curl','depend','ca-certificates'),('systemd','depend','dbus-units'))


def reader():
    loader=importlib.machinery.SourceFileLoader('batch_retained_orphans_reader',str(HELPER))
    spec=importlib.util.spec_from_loader(loader.name,loader);module=importlib.util.module_from_spec(spec);loader.exec_module(module)
    return module


def inspect_database(root,db,queries):
    """No transaction API. Tests use only a private fixture DB, never the host DB."""
    M=reader();M.unlocked(db);before,expected=M.database_snapshot(db);api=M.Installed(root,db)
    try:
        arch=api.lib.alpm_pkg_get_arch;arch.argtypes=[ctypes.c_void_p];arch.restype=ctypes.c_char_p
        local=api.lib.alpm_get_localdb(api.handle);C.need(local and api.lib.alpm_db_get_valid(local)==0,'valid local metadata required')
        head=api.lib.alpm_db_get_pkgcache(local);pointers=M.nodes(head,M.MAX_PACKAGES);names=[api.name(p)for p in pointers]
        C.need(len(names)==len(set(names)) and set(names)==set(expected),'complete unique installed cache required')
        rows={}
        for name,pointer in zip(names,pointers):
            version=api.lib.alpm_pkg_get_version(pointer);architecture=arch(pointer)
            C.need(version is not None and architecture is not None,'complete installed identity required')
            rows[name]=dict(name=name,version=version.decode(),arch=architecture.decode(),
                depend=api.relations(pointer,'depends'),provides=api.relations(pointer,'provides'))
            C.need(rows[name]['version']==expected[name]['version'],'raw/ALPM version differs')
        observations=[]
        for consumer,field,dependency in queries:
            C.need(field=='depend' and consumer in rows and dependency in rows[consumer]['depend'],'exact installed consumer relation required')
            candidates=[]
            for index,(name,pointer) in enumerate(zip(names,pointers)):
                single=api.lib.alpm_list_add(None,pointer);C.need(single,'candidate list allocation failed')
                try:
                    selected=api.satisfier(single,dependency)
                    if selected is not None:
                        C.need(selected==name,'single-candidate ALPM result differs')
                        candidates.append(dict(package=name,version=rows[name]['version'],cache_index=index))
                finally:api.lib.alpm_list_free(single)
            selected=api.satisfier(head,dependency)
            C.need(selected is not None and selected in {p['package']for p in candidates},'actual installed satisfier absent')
            observations.append(dict(package=consumer,field=field,dependency=dependency,candidates=candidates,
                                     selected=dict(name=selected,version=rows[selected]['version']),
                                     method='alpm_find_satisfier(actual_local_cache_order)'))
        version=api.version
    finally:api.close()
    descriptions={}
    for name,row in rows.items():
        relative='local/'+name+'-'+row['version']+'/desc'
        body=C.raw(db/relative,65536)
        C.need(hashlib.sha256(body).hexdigest()==before['nodes'][relative]['sha256'],'raw installed desc changed')
        descriptions[relative]=body.decode('utf-8')
    M.unlocked(db);after,_=M.database_snapshot(db);C.need(before==after,'installed database changed during readonly query')
    return dict(packages=[rows[n]for n in sorted(rows)],cache_order=names,queries=observations,
                db_before=before,db_after=after,raw_descriptions=descriptions,libalpm_version=version)


def capture(request):
    C.need(os.environ.get('CACHY_BATCH_ALPM_CAPTURE')=='1' and platform.system()=='Linux' and
           platform.machine()in('aarch64','arm64')and os.getuid()==os.geteuid()>0,'explicit ordinary native capture container required')
    C.need(any(line.split()[1]=='/'and'ro'in line.split()[3].split(',')for line in Path('/proc/mounts').read_text().splitlines()),'read-only container root required')
    C.need(set(request)=={'schema_version','image','inventory_sha256','packages','queries'} and type(request['schema_version'])is int and request['schema_version']==1,'exact provider capture request required')
    C.need(request['image']==os.environ.get('CACHY_BATCH_IMAGE')and request['image'].startswith('sha256:')and C.HEX.fullmatch(request['image'][7:]),'current image binding required')
    C.need(request['queries']==[list(row)for row in QUERIES],'finite exact consumer query set required')
    started=time.monotonic();value=inspect_database(Path('/'),Path('/var/lib/pacman'),QUERIES)
    C.need(len(value['packages'])==574 and value['packages']==request['packages'],'actual installed574 metadata differs from selected input')
    lock=''.join(p['name']+' '+p['version']+'\n'for p in value['packages'])
    C.need(hashlib.sha256(lock.encode()).hexdigest()==request['inventory_sha256'],'actual installed574 lock differs')
    library=Path('/usr/lib/libalpm.so.16').resolve(strict=True)
    value.update(schema_version=1,status='CAPTURED_INSTALLED_ALPM_SELECTIONS_ONLY',image=request['image'],
        inventory_sha256=request['inventory_sha256'],inventory_lock=lock,architecture=platform.machine(),
        uid=os.getuid(),page_size=os.sysconf('SC_PAGE_SIZE'),collector_sha256=C.digest(Path(__file__)),
        retained_reader_sha256=C.digest(HELPER),libalpm=dict(path=str(library),sha256=C.digest(library),version=value.pop('libalpm_version')),
        elapsed_seconds=round(time.monotonic()-started,6),hardware='NOT_RUN',release='NOT_ADMITTED')
    return value


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--request',type=Path,required=True);args=parser.parse_args()
    try:
        value=capture(C.read(args.request));raw=C.encoded(value);C.need(len(raw)<=4*1024**2,'provider capture output bound')
        sys.stdout.buffer.write(raw);return 0
    except (OSError,ValueError,KeyError,TypeError)as error:
        print('installed provider capture: '+str(error),file=sys.stderr);return 2


if __name__=='__main__':sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Partition one private DESTDIR, retaining every leaf and explicit OVS move."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat

PACKAGES=('networkmanager','libnm','nm-cloud-setup','networkmanager-docs')
SOURCE_SHA='843306ad54a3006ef7a60ba62932a3a2015cc87d46bd438fd5ac906d952c88d6'
OVS='usr/lib/systemd/system/NetworkManager.service.d/NetworkManager-ovs.conf'


def owner(path):
    if path==OVS:return 'networkmanager-docs','usr/share/doc/networkmanager/NetworkManager-ovs.conf.example'
    if 'nm-cloud-setup' in Path(path).name:return 'nm-cloud-setup',path
    if path.startswith('usr/share/gtk-doc/'):return 'networkmanager-docs',path
    if (path.startswith(('usr/include/libnm/','usr/lib/girepository-1.0/NM-','usr/share/gir-1.0/NM-','usr/share/vala/vapi/libnm.','usr/lib/libnm.'))
            or path in ('usr/lib/nm-libnm-helper','usr/lib/pkgconfig/libnm.pc')):return 'libnm',path
    return 'networkmanager',path


def leaf(path):
    s=path.lstat();mode=stat.S_IMODE(s.st_mode)
    assert not mode&0o6000,path
    if path.is_symlink():
        target=os.readlink(path);assert not Path(target).is_absolute(),path
        return {'kind':'symlink','mode':mode,'target':target}
    assert stat.S_ISREG(s.st_mode) and s.st_nlink>=1,path
    return {'kind':'file','mode':mode,'bytes':s.st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}


def partition(stage,output):
    stage=stage.resolve(strict=True);assert stage!=Path('/') and not output.exists()
    assert (stage/'usr').is_dir()
    output.mkdir(mode=0o700)
    for name in PACKAGES:(output/name).mkdir(mode=0o700)
    records=[]
    for path in sorted(stage.rglob('*')):
        rel=path.relative_to(stage).as_posix()
        assert not rel.startswith(('etc/resolv.conf','usr/share/libalpm/hooks/','etc/pacman','boot/','var/lib/pacman/')),rel
        if path.is_symlink():assert path.resolve().is_relative_to(stage),rel
        if path.is_dir() and not path.is_symlink():
            package,dest=owner(rel+'/')
            target=output/package/dest.rstrip('/');target.mkdir(parents=True,exist_ok=True);target.chmod(stat.S_IMODE(path.stat().st_mode))
            continue
        assert not rel.startswith(('etc/NetworkManager/system-connections/','var/lib/NetworkManager/')),rel
        package,dest=owner(rel);target=output/package/dest
        target.parent.mkdir(parents=True,exist_ok=True);assert not target.exists() and not target.is_symlink()
        details=leaf(path)
        if details['kind']=='symlink':target.symlink_to(details['target'])
        else:shutil.copyfile(path,target);target.chmod(details['mode'])
        records.append({'source':rel,'package':package,'destination':dest,**details})
    result={'schema_version':1,'version':'1.58.1-2.1','source_sha256':SOURCE_SHA,'records':records,
            'OVS_dropin_policy':'retained as docs example; no new automatic OVS service dependency',
            'system_mutation':False,'native_ARM':'NOT RUN'}
    (output/'ownership.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    verify(output)
    return result



def require_layout(output):
    required={
      'networkmanager':['usr/bin/NetworkManager','usr/bin/nmcli','usr/bin/nmtui','usr/bin/nm-online','etc/NetworkManager/NetworkManager.conf','usr/lib/systemd/system/NetworkManager.service','usr/lib/NetworkManager/conf.d/20-connectivity.conf'],
      'libnm':['usr/lib/libnm.so','usr/lib/pkgconfig/libnm.pc','usr/include/libnm/NetworkManager.h','usr/lib/girepository-1.0/NM-1.0.typelib','usr/share/gir-1.0/NM-1.0.gir','usr/share/vala/vapi/libnm.vapi','usr/lib/nm-libnm-helper'],
      'nm-cloud-setup':['usr/lib/nm-cloud-setup','usr/lib/systemd/system/nm-cloud-setup.service','usr/lib/systemd/system/nm-cloud-setup.timer'],
      'networkmanager-docs':['usr/share/doc/networkmanager/NetworkManager-ovs.conf.example'],
    }
    for name,paths in required.items():
        for rel in paths:assert (output/name/rel).is_file(),(name,rel)
    assert any((output/'networkmanager-docs/usr/share/gtk-doc').rglob('*.html')),'built API documentation required'
    connections=output/'networkmanager/etc/NetworkManager/system-connections'
    assert connections.is_dir() and stat.S_IMODE(connections.stat().st_mode)==0o700
    assert not list(connections.iterdir()),'no packaged connections'
    assert not (output/'networkmanager'/OVS).exists(),'no new OVS service dependency'
    for name in PACKAGES:
        assert not any((output/name/'usr/share/polkit-1/rules.d').glob('*'))


def verify(output):
    output=output.resolve(strict=True)
    result=json.loads((output/'ownership.json').read_text());assert result['version']=='1.58.1-2.1' and result['source_sha256']==SOURCE_SHA
    expected={name:{}for name in PACKAGES}
    for row in result['records']:
        expected[row['package']][row['destination']]={k:row[k]for k in row if k not in ('source','package','destination')}
    for name in PACKAGES:
        actual={p.relative_to(output/name).as_posix():leaf(p)for p in (output/name).rglob('*')if p.is_symlink()or p.is_file()}
        assert actual==expected[name],name
        for rel in actual:
            p=output/name/rel
            if p.is_symlink():assert p.resolve().is_relative_to(output/name),rel
    require_layout(output)
    return {'split_leaves':{name:len(rows)for name,rows in expected.items()},'source_sha256':SOURCE_SHA}


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--stage',type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--verify',action='store_true');args=p.parse_args()
    print(json.dumps(verify(args.output)if args.verify else partition(args.stage,args.output),sort_keys=True))

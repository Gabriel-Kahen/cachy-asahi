#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Owned offline image extension: stage signed bytes, never install or execute them."""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import socket
import sys
import time

HERE=Path(__file__).resolve().parent
DEST='var/lib/arm16k-llvm23-vm'
UNIT='etc/systemd/system/arm16k-llvm23-vm.service'
WANTS='etc/systemd/system/multi-user.target.wants/arm16k-llvm23-vm.service'
MATERIALS={'archive':'cachy-asahi-llvm23-source-reference-23.1.1-1-aarch64.pkg.tar.zst',
           'signature':'cachy-asahi-llvm23-source-reference-23.1.1-1-aarch64.pkg.tar.zst.sig',
           'public_TEST_certificate':'TEST-public.asc','signing_receipt':'signing-receipt.json'}


def ops():
    s=importlib.util.spec_from_file_location('llvm23_prepare_ops',HERE/'ops.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def scan_limits(ctx,baseline_nodes):
    limits=ctx['limits'];candidate=ctx['certs']['runtime_certificate']['candidate_namespace']
    passes=limits['image_scan_passes']
    if type(passes) is not int or not 1<=passes<=16:raise ValueError('Root explicit bounded image scan passes required')
    maximum=max([ctx['case']['package']['archive']['bytes'],limits['guest_output_cap_bytes']]+[r['bytes']for r in candidate.values()if r['kind']=='f']+[r['bytes']for r in baseline_nodes.values()if r['kind']=='file'])
    return dict(max_file_bytes=maximum,max_read_bytes=limits['prepared_raw_bytes']*passes)


def qualify_baseline(ctx,scan,O,K):
    expected=ctx['certs']['baseline_certificate']['inventory'];nodes=scan['nodes']
    K.need(len(expected)==111,'this image adapter selects only the retained original111')
    owned=O.all_owned_records(scan['records'],expected,nodes)
    for path,row in ctx['certs']['runtime_certificate']['files'].items():
        if row['owner']==K.PACKAGE['name']:continue
        resolved,node=O.resolve_nodes(nodes,path)
        K.need(resolved==row['resolved'] and all(node[n]==row[n]for n in('bytes','sha256','mode')) and
               row['owner'] in owned.get(resolved.lstrip('/'),{}).get('owners',[]) and expected[row['owner']]==row['version'],
               'actual baseline runtime path/owner/version/mode differs: '+path)
    protected=set(O.PROTECTED)|set(ctx['baseline']['guest_required_pins'])
    K.need(protected<=set(nodes),'all Root protected original PAM/boot paths required')
    for path,pin in ctx['baseline']['guest_required_pins'].items():
        K.need(type(pin)is str and re.fullmatch('[0-9a-f]{64}',pin) and nodes[path].get('kind')=='file' and nodes[path].get('sha256')==pin,'Root original protected path differs: '+path)
    return owned,{n:nodes[n]for n in sorted(protected)}


def plan(ctx,packet,materials,nodes,K):
    """Only fresh fixed service and staged DATA; never candidate installed paths."""
    report=K.load(packet/'case-packet.json');nonce=ctx['nonce']
    K.need(report['operation']==K.OP and report['nonce']==nonce and re.fullmatch('[0-9a-f]{32}',nonce), 'Root packet nonce/operation')
    K.need(report['Source_lock']==ctx['source_lock'],'packet Source closure differs')
    K.need(not any(n==DEST or n.startswith(DEST+'/') or n==K.PREFIX.lstrip('/') or n.startswith(K.PREFIX.lstrip('/')+'/') for n in nodes), 'fresh staging and absent uninstalled LLVM prefix required')
    K.need(UNIT not in nodes and WANTS not in nodes,'fresh fixed service paths required')
    rows={};files={}
    def directory(path,mode=0o755):
        if path in nodes:K.need(nodes[path]['kind']=='dir','ordinary existing staging ancestor');return
        rows[path]=dict(kind='dir',mode=mode)
    def regular(path,source,expected,mode):
        K.need(K.pin(source,expected['bytes'])=={n:expected[n]for n in('bytes','sha256')},'staged input bytes: '+path)
        rows[path]=dict(kind='file',mode=mode,bytes=expected['bytes'],sha256=expected['sha256']);files[path]=source
    for n in ('var','var/lib','etc','etc/systemd','etc/systemd/system'):K.need(nodes.get(n,{}).get('kind')=='dir','original service/data ancestors required')
    directory(DEST)
    actual=set()
    for current,dirs,names in os.walk(packet,followlinks=False):
        for name in dirs:K.need(not(Path(current)/name).is_symlink(),'packet directory alias')
        for name in names:actual.add((Path(current)/name).relative_to(packet).as_posix())
    K.need(actual==set(report['files'])|{'case-packet.json'},'closed tiny case packet membership')
    for name,row in report['files'].items():
        K.need(type(name)is str and re.fullmatch('[A-Za-z0-9._/-]+',name) and all(x not in('', '.', '..')for x in name.split('/')),'literal packet member')
        K.need(row['mode']==0o644,'case packet DATA files must be0644')
        target=UNIT if name=='arm16k-llvm23-vm.service'else DEST+'/'+name
        for parent in reversed(Path(target).parents):
            if parent.as_posix()!='.':directory(parent.as_posix())
        regular(target,packet/name,row,0o644)
    K.need(UNIT in rows and DEST+'/case.env' in rows and DEST+'/root.sh'in rows,'complete fixed service/case payload')
    for name,leaf in MATERIALS.items():regular(DEST+'/'+leaf,materials/leaf,ctx['case']['package'][name],0o644)
    directory(DEST+'/trust',0o700);directory(DEST+'/cache',0o700)
    directory(str(Path(WANTS).parent));rows[WANTS]=dict(kind='link',mode=0o777,target='../arm16k-llvm23-vm.service')
    K.need(not set(rows)&set(nodes),'only newly added guest paths')
    return rows,files


def edits(rows,files):
    commands=[]
    for name,row in sorted(rows.items(),key=lambda v:(v[0].count('/'),v[0])):
        target='/'+name
        if row['kind']=='dir':commands.append('mkdir '+target);kind=0o040000
        elif row['kind']=='link':commands.append('symlink '+target+' '+row['target']);kind=0o120000
        else:
            source=str(files[name]);
            if not re.fullmatch('/[A-Za-z0-9._/-]+',source):raise ValueError('debugfs input path must have literal safe spelling')
            commands.append('write '+source+' '+target);kind=0o100000
        commands.extend('set_inode_field '+target+' '+field+' '+value for field,value in
                        [('mode','0'+format(kind|row['mode'],'o')),('uid','0'),('gid','0')])
    return ('\n'.join(commands)+'\n').encode()


def build(ctx,paths,command,guard,modules):
    K,R,B,O,D=modules;W=Path(paths['work']);A=W/'assembly';limits=ctx['limits'];deadline=ctx['deadline']
    K.need(callable(guard) and time.monotonic()<deadline,'live finite preparation guard required');guard()
    K.need(not any(W.iterdir()),'empty newly owned preparation work')
    base=Path(paths['base']);kernel=Path(paths['kernel_bundle']);packet=Path(paths['packet']);materials=Path(paths['materials'])
    baseline=ctx['certs']['baseline_certificate'];expected=baseline['inventory']
    K.need(K.pin(base/'guest.raw',baseline['raw']['bytes'])==baseline['raw'],'original raw pin before any clone')
    original_size=(base/'guest.raw').stat().st_size;target=limits['prepared_raw_bytes']
    K.need(type(target)is int and original_size<=target<=4*1024**3 and target%4096==0,'supported nonshrinking Root ext4 geometry up to4GiB')
    before=D.scan(base/'guest.raw',deadline,guard);owned,protected=qualify_baseline(ctx,before,O,K)
    rows,files=plan(ctx,packet,materials,before['nodes'],K)
    A.mkdir(mode=0o700);raw=A/'guest.raw'
    def cmd(label,argv,**kwargs):
        guard();result=command(label,argv,**kwargs);guard();return result
    cmd('readonly-baseline-ext4',['e2fsck','-fn',str(base/'guest.raw')])
    cmd('sparse-clone',['cp','--sparse=always','--reflink=never',str(base/'guest.raw'),str(raw)])
    if target>original_size:
        cmd('grow-raw',['qemu-img','resize','-f','raw',str(raw),str(target)])
        checked=cmd('grow-owned-ext4-check',['e2fsck','-p','-f',str(raw)],check=False,completed=True)
        K.need(checked.returncode in(0,1),'owned clone ext4 pre-growth check')
        cmd('grow-owned-ext4',['resize2fs',str(raw)])
    K.need(raw.stat().st_size==target,'actual Root-selected raw geometry')
    script=W/'edits.debugfs';script.write_bytes(edits(rows,files))
    cmd('stage-case-DATA',['debugfs','-w','-f',str(script),str(raw)])
    cmd('readonly-prepared-ext4',['e2fsck','-fn',str(raw)])
    after=D.scan(raw,deadline,guard,**scan_limits(ctx,before['nodes']));nodes=after['nodes']
    K.need(all(nodes.get(n)==row for n,row in before['nodes'].items()),'complete original111 namespace changed')
    K.need(O.all_owned_records(after['records'],expected,nodes)==owned,'all original111 ALPM paths/records changed')
    K.need(set(nodes)-set(before['nodes'])==set(rows) and all(nodes[n]==row for n,row in rows.items()),'exact staged DATA/service-only readback')
    K.need(K.pin(base/'guest.raw',baseline['raw']['bytes'])==baseline['raw'],'immutable original raw changed')
    ownership=dict(packages=expected,owned=owned,protected=protected,old_namespace=before['nodes'],staged_namespace=rows,
                   scope='ALL111_BYTES_TYPES_MODES_ALPM_RECORDS_PROTECTED_PAM_PLUS_EXACT_SERVICE_DATA_ADDITIONS')
    (A/'ownership.json').write_bytes(K.canonical(ownership))
    for source,dest in [('Image','Image'),('config','kernel.config')]:
        pin=ctx['kernel']['files'][source];K.need(K.pin(kernel/source,pin['bytes'])==pin,'exact RTC kernel input');shutil.copy2(kernel/source,A/dest)
    report=dict(schema=1,operation=K.OP,status='PREPARED_LLVM23_IMAGE_NOT_BOOTED',nonce=ctx['nonce'],baseline_nonce=ctx['base']['nonce'],
                source_lock=ctx['source_lock'],case=ctx['case'],certs=ctx['certs'],limits=limits,authority=ctx['authority'],
                base_files=ctx['base']['files'],kernel=ctx['kernel'],tool=ctx['tool'],packet=K.pin(packet/'case-packet.json'),
                files={n:K.pin(A/n,target if n=='guest.raw'else 64*1024**2)for n in('guest.raw','Image','kernel.config')},
                ownership=K.pin(A/'ownership.json',64*1024**2),raw_logical_bytes=target,raw_allocated_bytes=raw.stat().st_blocks*512,
                readback_profiles=dict(baseline=before['profile'],prepared=after['profile']),actual=dict(VM=None,ALPM=None,compiler=None,Root_acceptance=None))
    (A/'prepared.json').write_bytes(K.canonical(report));guard();return report


def main():
    T=ops();ctx=T.actor_context(Path('/inputs'),Path('/work'),phase='prepare');K,R,B,O,D=T.modules()
    K.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__ and os.environ.get('CACHY_LLVM23_PREPARE')=='1' and Path('/.dockerenv').is_file(),'explicit isolated offline preparation actor')
    status=dict(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if ':'in line)
    K.need(all(int(status[n].strip(),16)==0 for n in('CapEff','CapPrm','CapBnd','CapInh','CapAmb')) and status['NoNewPrivs'].strip()=='1' and {n for _,n in socket.if_nameindex()}=={'lo'} and not Path('/dev/kvm').exists(),'cap0/NNP/no-network/no-device actor')
    W=Path('/work');guard=T.guard(ctx,W);deadline=ctx['deadline']
    def command(label,argv,**kwargs):
        return R.command(argv,W/'assembly',label,max(1,deadline-time.monotonic()),deadline,watched_tree=(W,ctx['limits']['clone_allocated_cap_bytes']+ctx['limits']['logs_cap_bytes'],ctx['limits']['reserve_bytes']),**kwargs)
    previous=getattr(R,'LIVE_GUARD',None);R.LIVE_GUARD=guard
    try:build(ctx,dict(base='/base',materials='/materials',kernel_bundle='/kernel',packet='/packet',work='/work'),command,guard,(K,R,B,O,D))
    finally:R.LIVE_GUARD=previous
    return 0


if __name__=='__main__':raise SystemExit(main())

#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Future fixed offline prefix extension; no guest code, ALPM or boot execution."""
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import sys
import time

HERE = Path(__file__).resolve().parent


def module(name):
    s=importlib.util.spec_from_file_location('rust16k_prepare_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def main():
    K,R,O,S,D = (module(n) for n in ('contracts','runtime','ownership','stage0','image'))
    K.need(__debug__ and sys.flags.isolated and sys.dont_write_bytecode and os.environ.get('CACHY_RUST_STAGE0_PREPARE') == '1' and Path('/.dockerenv').is_file(),'explicit offline container entry required')
    security = dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    K.need(all(int(security[n].strip(),16) == 0 for n in ('CapEff','CapPrm','CapBnd','CapInh','CapAmb')) and security['NoNewPrivs'].strip() == '1' and {r[1] for r in socket.if_nameindex()} == {'lo'} and not Path('/dev/kvm').exists(), 'actual cap0/NNP/no-network preparation domain required')
    manifest = K.load(Path('/inputs/input-manifest.json'));K.need(manifest['source_lock'] == K.source(),'exact Root-reviewed preparation source')
    base = K.load(Path('/base/prepared.json'));K.checked(Path('/base/guest.raw'),manifest['base_files']['guest.raw'])
    for name,row in manifest['archives'].items():K.checked(Path('/materials')/name,{k:row[k] for k in ('bytes','sha256')})
    W=Path('/work');A=W/'assembly';K.need(not any(W.iterdir()),'empty owned preparation work required');A.mkdir(mode=0o700)
    until = manifest['work_deadline_monotonic']-5;K.need(0<until-time.monotonic()<=550,'finite assigned preparation work budget');K.END=until
    last=[0.0]
    def guard(force=False):
        now=time.monotonic();K.need(now<until,'finite preparation budget')
        if not force and now-last[0]<.5:return
        raw_path=A/'guest.raw';prefix_path=W/'prefix'
        raw_bytes=raw_path.stat().st_blocks*512 if raw_path.exists() else 0
        prefix_bytes=R.allocated(prefix_path,until) if prefix_path.exists() else 0
        total=R.allocated(W,until);metadata=total-raw_bytes-prefix_bytes
        K.need(raw_bytes<=K.RESOURCES['extended_raw_allocated_cap'] and prefix_bytes<=K.RESOURCES['prefix_allocated_cap'] and metadata<=K.RESOURCES['output_metadata_allocated_cap'] and total<=K.RESOURCES['prepare_allocated_cap'] and shutil.disk_usage(W).free>=K.RESOURCES['reserve_bytes'],'finite raw/prefix/metadata allocation or reserve exceeded')
        last[0]=time.monotonic()
    def cmd(label,argv,cap=120):
        result=R.command(argv,A,label,cap,until,watched_tree=(W,K.RESOURCES['prepare_allocated_cap'],K.RESOURCES['reserve_bytes']))
        guard(True);return result
    # One bounded readonly streaming inventory; no exported baseline tree.
    K.need(Path('/base/guest.raw').stat().st_blocks*512<=K.RESOURCES['base_raw_allocated_cap'],'actual baseline allocation exceeds reviewed envelope')
    baseline_scan=D.scan(Path('/base/guest.raw'),until,guard)
    nodes=baseline_scan['nodes'];expected={r['name']:r['version'] for r in base['base_packages']}
    owned=O.all_owned_records(baseline_scan['records'],expected,nodes);certificate=manifest['guest_inputs']
    qualified=O.qualify_nodes(certificate,owned,nodes)
    K.need(not any(name == K.PREFIX.lstrip('/') or name.startswith(K.PREFIX.lstrip('/')+'/') for name in nodes),'private stage0 prefix already exists')
    raw=A/'guest.raw';cmd('sparse-clone',['cp','--sparse=always','--reflink=never','/base/guest.raw',str(raw)],180)
    prefix=W/'prefix';spec=K.load(HERE/'data/stage0.json');model=S.assemble(Path('/materials'),prefix,HERE/'data',spec,guard=guard)
    fixture=prefix/'fixture';fixture.mkdir(mode=0o755);fixture.chmod(0o755)
    for name in ('check.sh','Cargo.toml','Cargo.lock','main.rs'):shutil.copy2(HERE/'guest'/name,fixture/name);(fixture/name).chmod(0o755 if name=='check.sh' else 0o644)
    shutil.copy2(HERE/'frozen/rtc-clock.sh',fixture/'rtc-clock.sh');(fixture/'rtc-clock.sh').chmod(0o644)
    shutil.copy2(HERE/'data/expected111.lock',fixture/'expected111.lock');(fixture/'expected111.lock').chmod(0o644)
    readable = O.readable(owned,nodes)
    regular = ''.join(row['sha256']+'  /'+name+'\n' for name,row in readable.items() if row['kind']=='file')
    links = ''.join('/'+name+'\t'+row['target']+'\n' for name,row in readable.items() if row['kind']=='link')
    paths = ''.join(row['sha256']+'  '+name+'\n' for name,row in sorted(qualified.items()))
    for name,body in [('owned-regular.sha256',regular),('owned-links.tsv',links),('guest-paths.sha256',paths)]:
        (fixture/name).write_text(body);(fixture/name).chmod(0o644)
    # All root edits are additions under exactly this prefix. No shadow, machine-id,
    # PAM, profile, nonce, package registration, hook, service or baseline-file edit.
    payload=O.namespace(prefix);edits=[]
    for directory in ('/opt/cachy-asahi',K.PREFIX):
        if directory.lstrip('/') not in nodes:
            edits += ['mkdir '+directory,'set_inode_field '+directory+' mode 040755','set_inode_field '+directory+' uid 0','set_inode_field '+directory+' gid 0']
        else:K.need(nodes[directory.lstrip('/')]['kind']=='dir' and nodes[directory.lstrip('/')]['mode'] & 0o005 == 0o005,'existing private-prefix ancestor is not ordinary-user accessible')
    for name,row in sorted(payload.items(),key=lambda x:(x[0].count('/'),x[0])):
        guest=K.PREFIX+'/'+name
        if row['kind']=='dir':edits += ['mkdir '+guest,'set_inode_field '+guest+' mode 0'+format(0o040000|row['mode'],'o'),'set_inode_field '+guest+' uid 0','set_inode_field '+guest+' gid 0']
        else:
            K.need(row['kind']=='file','link-free reviewed stage0 payload required')
            edits += ['write '+str(prefix/name)+' '+guest,'set_inode_field '+guest+' mode 0'+format(0o100000|row['mode'],'o'),'set_inode_field '+guest+' uid 0','set_inode_field '+guest+' gid 0']
    script=W/'edits.debugfs';script.write_text('\n'.join(edits)+'\n')
    cmd('private-prefix-write',['debugfs','-w','-f',str(script),str(raw)],180)
    cmd('ext4-readonly-check',['e2fsck','-fn',str(raw)],90)
    # Hashes/models are now held as bounded DATA; retire only our staged prefix.
    # The full raw readback below streams bodies instead of exporting a second tree.
    guard(True);shutil.rmtree(prefix);guard(True)
    readback_scan=D.scan(raw,until,guard);current=readback_scan['nodes']
    K.need(all(current.get(name)==row for name,row in nodes.items()),'old guest namespace bytes/type/mode changed')
    K.need(O.all_owned_records(readback_scan['records'],expected,current)==owned,'all111 package-owned payload/metadata changed')
    for name,row in payload.items():K.need(current.get(K.PREFIX.lstrip('/')+'/'+name)==row,'complete private-prefix readback differs')
    additions=set(current)-set(nodes);allowed={K.PREFIX.lstrip('/')+'/'+name for name in payload}|{'opt/cachy-asahi',K.PREFIX.lstrip('/')}
    K.need(additions<=allowed,'unreviewed path added outside private prefix')
    protected_names=set(O.PROTECTED)|set(K.load(HERE/'data/base.json')['guest_required_pins'])
    K.need(protected_names<=set(nodes),'complete retained PAM/boot proof paths required')
    protected={name:nodes[name] for name in sorted(protected_names)}
    (A/'ownership.json').write_text(json.dumps({'protected':protected,'readable_owned_paths':len(readable),'scope':'ALL111_OWNED_CONTENT_TYPE_MODE_PLUS_COMPLETE_OLD_NAMESPACE','packages':expected,'owned':owned,'old_namespace_nodes':len(nodes),'old_owned_paths':len(owned),'protected_PAM_and_boot_changed':False},indent=2,sort_keys=True)+'\n')
    for name,source in [('Image','Image'),('kernel.config','config')]:shutil.copy2(Path('/kernel')/source,A/name)
    nonce=secrets.token_hex(16)
    report=dict(schema=1,operation=K.OP,status='PREPARED_NOT_BOOTED',nonce=nonce,baseline_nonce=base['nonce'],base_packages=base['base_packages'],base_files=manifest['base_files'],original_marker=manifest['original_marker'],source_lock=manifest['source_lock'],authority=manifest['authority'],kernel_bundle=manifest['kernel_bundle'],qemu_metadata=manifest['qemu_metadata'],stage0_component_model=model,fixture_payload=payload,ownership=K.pin(A/'ownership.json'),files={p.name:K.pin(p) for p in (raw,A/'Image',A/'kernel.config')},raw_logical_bytes=raw.stat().st_size,raw_allocated_bytes=raw.stat().st_blocks*512,readback_profiles={'baseline':baseline_scan['profile'],'prepared':readback_scan['profile']},allocated_budget=K.pin(HERE/'data/allocated-budget-v2.json'),VM_boot='NOT RUN',native16K='UNQUALIFIED',M2='UNQUALIFIED',performance='NOT MEASURED',release='UNQUALIFIED')
    K.need(raw.stat().st_size<=K.RESOURCES['raw_cap_bytes'],'logical raw cap exceeded')
    (A/'prepared.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    guard(True)
    return 0


if __name__=='__main__':raise SystemExit(main())

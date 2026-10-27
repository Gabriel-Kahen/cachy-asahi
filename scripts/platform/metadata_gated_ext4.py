#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Checkout-relative, opt-in native metadata→verified-staging→ext4 pipeline.

Default imports/tests do not open package inputs or dispatch native tools. The
only production module graph is this directory plus portable intake's own bundle.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import signal
import stat
import sys
import tarfile
import types

BASE=Path(__file__).resolve().parent
SOURCE_PINS={
 'intake':('archive_intake.py','dfc6e2d429b654359075bd135969c5948b12dd81db67f522ae46e1be61911a67'),
 'verifier':('verify_staging.py','279201558a90ea6e429822fc7d5b63827e6bd47ef022f8aef3126109bdfaa711'),
 'metadata':('archive_inode_metadata.py','8d8255ab64e8eb83148365e11aba391c1104bbabfc9f2da85a0adb21043a7a85'),
 'encoder':('filesystem_encoder.py','b23104886d8026798e7fb60c77180bc0a31357d6353495f4d5daa6880cfae97a'),
 'reader':('independent_readback.py','8fb8c2c32dc5a40998bf31cc5727768f88ce51e423b7090cfb702116bdc9b5d3'),
 'owned_process':('scripts/virtual/owned_process.py','83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f')}


def need(ok,why):
    if not ok:raise ValueError(why)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()


def pinned(path,digest,maximum=1024**2):
    path=Path(path).absolute();need(path==path.resolve(),'input-or-source-symlink')
    fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=maximum,'ordinary-input-bound')
        with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(maximum+1)
        fields=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        need(all(getattr(before,k)==getattr(os.fstat(fd),k)==getattr(path.lstat(),k) for k in fields),'input-source-drift')
        need(len(raw)==before.st_size and sha(raw)==digest,'input-source-pin')
        return raw
    finally:os.close(fd)


def source_path(relative):
    return BASE.parents[1]/relative if relative.startswith('scripts/') else BASE/relative


def sources():
    modules={}
    for name,(relative,digest) in SOURCE_PINS.items():
        raw=pinned(source_path(relative),digest)
        module=types.ModuleType('_portable_ext4_'+name);module.__file__=str(source_path(relative))
        exec(compile(raw,module.__file__,'exec'),module.__dict__);modules[name]=module
    encoder,reader=modules['encoder'],modules['reader']
    def pinned_readback(image):
        return reader.read_inventory(image,max_file_bytes=encoder.MAX_BYTES,max_nodes=encoder.MAX_NODES+1)
    encoder.readback=pinned_readback
    encoder.OWNED_CORE=modules['owned_process']
    modules['metadata'].RUN_COMMAND=encoder.run_command
    return modules


def check_sources():
    for relative,digest in SOURCE_PINS.values():pinned(source_path(relative),digest)
    pinned(Path(__file__),ENTRY_SOURCE_SHA)


def exact_selection(selection):
    expected={name:dict(name=name,version=version,arch='aarch64') for name,version in
              (('networkmanager','1.58.1-1'),('perl','5.42.2-2'))}
    need(type(selection)is dict and type(selection.get('packages'))is list and len(selection['packages'])==2,
         'exact-two-selection-required')
    identities=[row.get('identity') for row in selection['packages'] if type(row)is dict]
    need(len(identities)==2 and all(type(x)is dict for x in identities) and
         {x.get('name') for x in identities}==set(expected) and
         all(x==expected[x['name']] for x in identities),'exact-two-identities-required')


def bundle_bodies(directory,manifest,receipt,encoder):
    raw=pinned(directory/'staging.tar',receipt['bundle']['sha256'],encoder.MAX_BYTES)
    need(len(raw)==receipt['bundle']['bytes'],'staging-size')
    bodies={};nodes=manifest['output_nodes']
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r|') as archive:
        for entry in archive:
            need(set(entry.pax_headers)<={'path','linkpath','size'},'unknown-staging-metadata')
            if entry.name.startswith('rootfs/') and entry.isfile():
                path=entry.name[len('rootfs/'):]
                need(path in nodes and nodes[path]['type']=='file' and path not in bodies,'staging-body-closure')
                need(entry.size==nodes[path]['bytes'],'staging-body-size')
                with archive.extractfile(entry) as stream:body=stream.read(entry.size+1)
                need(len(body)==entry.size and sha(body)==nodes[path]['sha256'],'staging-body-hash')
                bodies[path]=body
    need(set(bodies)=={p for p,n in nodes.items() if n['type']=='file'},'complete-staging-bodies')
    return bodies


def root_proof(encoder,policy,pins,epoch,output):
    manifest=dict(schema_version=1,base='FRESH_PRISTINE_PREPARED_PACKAGE_TREE',
        kind='PROJECT_NEW_ROOT_POLICY_CONTROL_ONLY_NOT_ARCHIVE_PAYLOAD',source_date_epoch=epoch,
        output_nodes={'root-policy-control':dict(type='directory',mode=0o755,uid=0,gid=0)},
        platform={'root_uuid':'725346d2-f127-47bc-b464-9dd46155e8d6'})
    meta=dict(schema_version=1,complete=True,root=dict(policy),nodes={'root-policy-control':dict(acl=None,xattrs={})})
    result=encoder.encode(manifest,{},meta,pins,output)
    root=encoder.readback(output/'root.ext4')['nodes']['.']
    need(all(root[k]==policy[k] for k in ('mode','uid','gid','xattrs')) and
         root['type']=='directory' and root['xattrs']=={} and policy['acl'] is None,'root-policy-proof')
    return dict(status='PASS_SEPARATE_GENERATED_ROOT_POLICY',policy=policy,observed_root=root,
                filesystem=result,archive_ownership_claim=False)


def _pipeline(modules,selection,authentication,tool_pins,metadata_pins,root_policy,output,epoch):
    """Sequencing core. Tests substitute inert services; CLI pins every service."""
    exact_selection(selection)
    intake,verify,metadata,encoder=(modules[k] for k in ('intake','verifier','metadata','encoder'))
    encoder.ACTOR_DIRECTORY=output/'actors';encoder.ACTOR_DIRECTORY.mkdir(mode=0o700)
    need(type(metadata_pins)is dict and metadata_pins.get('schema_version')==2 and
         type(tool_pins)is dict and tool_pins.get('schema_version')==2,'dependency-profiles-v2-required')
    need(metadata.pins(metadata_pins.get('configuration'))==metadata_pins and
         encoder.tool_pins(tool_pins.get('configuration'))==tool_pins,'runtime-tool-library-pins')
    retained=intake.run(selection,authentication,output/'staging',epoch,seconds=120)
    verified=verify.verify(output/'staging')
    manifest=intake.decode(pinned(output/'staging/assembly.json',retained['manifest_sha256'],32*1024**2))
    portable=retained['portable_source_inputs']
    need(portable['entrypoint_sha256']==SOURCE_PINS['intake'][1] and
         portable['graph_manifest_sha256']==intake.BUNDLE_SHA and portable['engine_sha256']==intake.ENGINE_SHA,
         'portable-intake-source-association')
    native=output/'native-metadata';native.mkdir(mode=0o700);reports={}
    for row in selection['packages']:
        name=row['identity']['name']
        try:report=metadata.complete(row['archive'],metadata_pins)
        except BaseException as exc:
            if hasattr(exc,'metadata_observations'):(native/(name+'-REFUSED.json')).write_bytes(encoded(exc.metadata_observations))
            raise
        report.update(identity=row['identity'],archive_reference=row['archive'],signature_reference=row['signature'])
        (native/(name+'.json')).write_bytes(encoded(report));reports[name]=report
    sidecar,bindings=metadata.join_metadata(manifest,reports,root_policy)
    (native/'member-and-inode-bindings.json').write_bytes(encoded(bindings))
    (output/'inode-metadata.json').write_bytes(encoded(sidecar))
    # No image can be created until direct native observations and all joins pass.
    proof=root_proof(encoder,root_policy,tool_pins,epoch,output/'new-root-policy-proof')
    (native/'root-policy-proof.json').write_bytes(encoded(proof))
    bodies=bundle_bodies(output/'staging',manifest,retained,encoder)
    image=encoder.encode(manifest,bodies,sidecar,tool_pins,output/'encoded')
    observed=encoder.readback(output/'encoded/root.ext4')['nodes']
    associations={p:dict(node=n,packages=manifest['output_ownership'][p]['package_owners'],observed=observed[p])
                  for p,n in manifest['output_nodes'].items()}
    (output/'node-associations.json').write_bytes(encoded(associations))
    return dict(status='PASS_EXACT_TWO_DIRECT_METADATA_GATED_EXT4',intake=retained,staging_verification=verified,
        source_pins={k:dict(path=v[0],sha256=v[1]) for k,v in SOURCE_PINS.items()},
        bridge_sha256=ENTRY_SOURCE_SHA,filesystem=image,
        direct_metadata=dict(adapter_sha256=SOURCE_PINS['metadata'][1],native_pins=metadata_pins,
          reports_sha256={n:sha(encoded(r)) for n,r in sorted(reports.items())},
          member_counts={n:len(r['members']) for n,r in reports.items()},
          bindings_sha256=sha(encoded(bindings)),root_proof_sha256=sha(encoded(proof)),generic_empty_inference_used=False),
        node_associations_sha256=sha(encoded(associations)),
        acceptance={k:False for k in ('full261','new_owner_trust','source_license','installed_metadata','scriptlet_state','native_arm','boot','M2','release')})


def run(selection,authentication,tool_pins,metadata_pins,root_policy,output,epoch=1700000000):
    exact_selection(selection)
    modules=sources()
    need(type(epoch)is int and 0<=epoch<=2147483647,'epoch-bound')
    output=Path(output).absolute();need(output.parent==output.parent.resolve(),'output-parent')
    output.mkdir(mode=0o700);(output/'INCOMPLETE.json').write_bytes(encoded(dict(status='INCOMPLETE_NOT_ACCEPTED')))
    try:
        result=_pipeline(modules,selection,authentication,tool_pins,metadata_pins,root_policy,output,epoch)
        check_sources()
        with (output/'receipt.pending.json').open('xb') as stream:
            stream.write(encoded(result));stream.flush();os.fsync(stream.fileno())
        (output/'INCOMPLETE.json').unlink();os.rename(output/'receipt.pending.json',output/'receipt.json')
        return result
    except BaseException as exc:
        (output/'failure.json').write_bytes(encoded(dict(status='REFUSED_NOT_ACCEPTED',error_type=type(exc).__name__,actual_error=str(exc))))
        raise


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('selection','authentication','tool-pins','metadata-pins','root-policy'):
        ap.add_argument('--'+name,required=True);ap.add_argument('--'+name+'-sha256',required=True)
    ap.add_argument('--output',required=True);ap.add_argument('--epoch',type=int,default=1700000000)
    ap.add_argument('--reverse',action='store_true');args=ap.parse_args()
    resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3));resource.setrlimit(resource.RLIMIT_CPU,(180,180))
    resource.setrlimit(resource.RLIMIT_FSIZE,(256*1024**2,256*1024**2));resource.setrlimit(resource.RLIMIT_NOFILE,(256,256))
    def expired(*_):raise TimeoutError('portable-ext4-wall180')
    signal.signal(signal.SIGALRM,expired);signal.alarm(180)
    values={key:json.loads(pinned(getattr(args,key.replace('-','_')),getattr(args,(key+'-sha256').replace('-','_'))))
            for key in ('selection','authentication','tool-pins','metadata-pins','root-policy')}
    if args.reverse:values['selection']['packages'].reverse()
    result=run(values['selection'],values['authentication'],values['tool-pins'],values['metadata-pins'],values['root-policy'],args.output,args.epoch)
    signal.alarm(0);print(json.dumps(dict(status=result['status'],image=result['filesystem']['image']),sort_keys=True))


ENTRY_SOURCE_SHA=sha(Path(__file__).read_bytes())


if __name__=='__main__':main()

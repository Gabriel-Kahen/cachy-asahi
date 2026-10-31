# SPDX-License-Identifier: MIT
"""Original Apps6 transaction adapter plus explicit public input evidence seams."""
import ast,hashlib
from pathlib import Path
import contract as C
OLD='scripts/ci/expanded604-apps6-updater';PREFIX='scripts/ci/expanded604-apps6-public-pair-updater/'
prior=C.scoped('_public_pairs_original_apps6_adapter',C.HERE.parent/'expanded604-apps6-updater/adapter.py',{'contract':C});prior.PREFIX=PREFIX
# Only data inspection dependencies are added; existing transaction bodies stay held.
def constructor(raw):
 C.need(len(raw)==13124 and hashlib.sha256(raw).hexdigest()=='f25b0969fbd8fe9b8818cc1be0107c43cfe1124779372ddfdf9e12099bd9671e','exact whole Apps6 constructor source required')
 text=raw.decode()
 for before,after,count in [('build_lock','build_evidence',3),('build575.lock','public-build-evidence.json',2)]:
  C.need(text.count(before)==count,'exact public constructor evidence seam: '+before);text=text.replace(before,after)
 node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='convert_provenance');body=ast.get_source_segment(text,node);before="'inventory_count': 575";C.need(body.count(before)==1,'one explicit public build provenance scope');body=body.replace(before,before+", 'inventory_evidence': 'PUBLIC_ROOT_PAIR_AUTHORITY_AND_COMPLETE_BUILDINFO', 'raw_pacman_Q_lock': 'NOT_PRESENT_NOT_FABRICATED'");text=text[:text.index(ast.get_source_segment(text,node))]+body+text[text.index(ast.get_source_segment(text,node))+len(ast.get_source_segment(text,node)):]
 # Only issuance operands change at the immediate build seam; validators stay held.
 anchor="def stage(args, *, prepared):";C.need(text.count(anchor)==1,'one actual metadata stage');text=text.replace(anchor,'def fresh_test_metadata_window(api, args):\n    """Issue this exact disposable TEST fixture at use with its unchanged lifetime."""\n    need((args.issued_utc, args.expires_utc) == (\'2026-10-16T00:00:00Z\', \'2026-10-18T00:00:00Z\'),\n         \'exact original TEST fixture metadata window required\')\n    lifetime = api.client.stamp(args.expires_utc) - api.client.stamp(args.issued_utc)\n    need(lifetime.total_seconds() == 172800, \'original two-day TEST metadata lifetime required\')\n    now = api.client.datetime.now(api.client.timezone.utc).replace(microsecond=0)\n    return api.client.utc(now), api.client.utc(now + lifetime)\n\n\n'+anchor)
 anchor="    metadata = out / 'metadata.json'\n";C.need(text.count(anchor)==1,'one immediate metadata creation seam');text=text.replace(anchor,anchor+"    issued_utc, expires_utc = fresh_test_metadata_window(api, args)\n")
 anchor='issued_utc=args.issued_utc, expires_utc=args.expires_utc';C.need(text.count(anchor)==1,'one unchanged client build issuance call');text=text.replace(anchor,'issued_utc=issued_utc, expires_utc=expires_utc')
 ast.parse(text);return text.encode()

def normal_driver_headroom(config,target):
 # The actual driver owns one supervisor: --worker bypasses its optional nested
 # supervisor. This adds total-worker headroom, not a reserved work/cleanup split.
 pins={'scripts/update/aux_copy.py':(3736,'bff93c029e21f9fce0868c80566396984443c8d3438264fac8a91c985175f05b'),
       'scripts/update/disposable_copy.py':(6098,'fb05d12a0d67a598cc940e0bc7edb5aa9ffc8cf87ce7b9f695ba5fbd26747667')}
 C.need(type(config.get('driver_seconds')) is int and config['driver_seconds']==1800,'exact original normal driver budget required')
 for name,(size,digest) in pins.items():
  path=target/name;C.need(path.is_file() and not path.is_symlink() and path.stat().st_nlink==1 and path.stat().st_size==size and C.sha(path)==digest,'exact existing normal copy cleanup allowance source required')
 base,cleanup,ceiling=1800,60,2400
 C.need(base+cleanup==1860 and base+cleanup<=ceiling,'finite normal cleanup headroom within unchanged caller ceiling')
 config['driver_seconds']=base+cleanup
 return dict(status='BOUNDED_NORMAL_TOTAL_WORKER_HEADROOM_ONLY',before_seconds=base,after_seconds=base+cleanup,existing_cleanup_seconds=cleanup,caller_ceiling=ceiling,semantics='TOTAL_ENVELOPE_NOT_RESERVED_CLEANUP_TIME',cleanup='UNCHANGED_60S_COMPLETION_REQUIRED',copy_cleanup_sources={name:dict(bytes=size,sha256=digest)for name,(size,digest)in pins.items()},runtime_acceptance=False)


def prepare(source,target,case,*,git=True,implementation=None):
 implementation=Path(implementation or C.SOURCE);config,caller=prior.prepare(source,target,case,git=git,implementation=implementation)
 helper=C.load('_public_apps6_auxiliary_transition',C.HERE/'aux_transition.py');p=target/'scripts/update/aux_runtime.py';changed,auxiliary_selection=helper.derive(p.read_bytes());p.write_bytes(changed)
 p=target/'scripts/update/linked_runtime.py';linked,linked_selection=helper.derive_linked(p.read_bytes());p.write_bytes(linked)
 postcommit_selection=None
 if case=='postcommit-exit87':
  p=target/'scripts/ci/full-root-postcommit-failure/run.py';postcommit,postcommit_selection=helper.derive_postcommit(p.read_bytes());p.write_bytes(postcommit)
 p=target/'scripts/ci/full-root-upgrade/construct_repository.py';p.write_bytes(constructor(p.read_bytes()));rows=C.read(C.HERE/'source-pins.json')['inspection_files']
 for name,pin in rows.items():
  path=C.checked(implementation,dict(path=name,**pin));dest=target/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(path.read_bytes())
 value=C.read(config)
 normal_headroom=normal_driver_headroom(value,target) if case=='normal' else None
 for name in rows:value['code_pins'][name]=C.sha(target/name)
 value['code_pins']={name:C.sha(target/name) for name in value['code_pins']};value['release']['release_id']='public-pairs-apps6-current604-'+case+'-20261017';value['release']['namespace']='cachy-asahi-public-pairs-apps6-current604-'+case;config.write_bytes(C.encoded(value));row=C.read(target/'adapter.json');row['selection']['scripts/ci/full-root-upgrade/construct_repository.py']['after']=C.sha(target/'scripts/ci/full-root-upgrade/construct_repository.py');row.update(auxiliary_selection=auxiliary_selection,linked_runtime_selection=linked_selection,public_input_seams=['typed_public_build_evidence_not_raw_Q','complete_public_current4_validation'],status='PRIVATE_PUBLIC_PAIRS_APPS5_TO6_CURRENT604_SELECTION_ONLY',input_authority='PUBLIC659_PAIR_AND_INDEPENDENT_BYTECASE_NO_RAW223',config_sha256=C.sha(config),raw_Q_lock='NOT_PRESENT_NOT_FABRICATED',new604_and_fresh='UNBOUND');row.update(**({'postcommit_selection':postcommit_selection} if postcommit_selection is not None else {}));row.update(**({'normal_cleanup_headroom':normal_headroom} if normal_headroom is not None else {}));(target/'adapter.json').write_bytes(C.encoded(row));return config,caller

# SPDX-License-Identifier: MIT
"""Finite source-owned KSM VM input and DATA contract; no authority from PASS."""
import hashlib,importlib.util,json,os,re,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
RECIPE='e753936b4d90d0b5127647581bed2a7fda64ce70';PROFILE='KSM_ADVICE_GENERIC16K_DIAGNOSTIC_V1';PACKAGE='cachy-asahi-ksmctl';VERSION='0.1.0-2'
NATIVE_STATUS='ROOT_ACCEPTED_NATIVE_KSM1_TO2_UPGRADE_RETAINED_SCOPE'
SHARED_SECONDS=3000;PRODUCT_SECONDS=5;CAP=16*1024**2

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def sha(v):return hashlib.sha256(v).hexdigest()
def pin(v):return dict(bytes=len(v),sha256=sha(v))
def decode(raw):
 def pairs(rows):
  d={}
  for k,v in rows:need(k not in d,'duplicate JSON');d[k]=v
  return d
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def relative(s):need(type(s)is str and s and not s.startswith('/')and '\\'not in s and all(p not in('','.','..')for p in s.split('/'))and '\0'not in s,'finite relative path');return s
def read(path,cap=4*1024**2):
 p=Path(path);need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary source/input path');a=p.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded single-link source/input');raw=p.read_bytes();b=p.lstat();ident=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(ident(a)==ident(b)and len(raw)==a.st_size,'input drift');return raw
def checked(root,row,cap=4*1024**2,allow_empty=False):
 need(type(row)is dict and set(row)=={'path','bytes','sha256'}and type(row['bytes'])is int and (0 if allow_empty else 1)<=row['bytes']<=cap and re.fullmatch('[0-9a-f]{64}',row['sha256']or''),'exact bounded reference');raw=read(Path(root)/relative(row['path']),cap);need(pin(raw)=={k:row[k]for k in('bytes','sha256')},'reference pin differs');return raw
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def support(root=HERE):
 root=Path(root);rows=decode(read(root/'support-pins.json'))['files']
 for n,p in rows.items():need(pin(read(root/relative(n),16*1024**2))==p,'whole borrowed source differs: '+n)
 return rows

def row(path):
 p=Path(path);a=p.lstat();need(not any(q.is_symlink()for q in(p,*p.parents))and stat.S_ISREG(a.st_mode)and a.st_nlink==1,'ordinary whole-file pin')
 with p.open('rb')as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
 b=p.lstat();need((a.st_dev,a.st_ino,a.st_mode,a.st_uid,a.st_gid,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_mode,b.st_uid,b.st_gid,b.st_size,b.st_mtime_ns,b.st_ctime_ns),'whole-file drift');return dict(bytes=a.st_size,sha256=digest)
def save(path,value):Path(path).write_bytes(encoded(value))
def native_record(value,source,run,root=HERE):
 proposal=decode(read(Path(root)/'native-decision-contract.json',65536))
 need(source==proposal['known_source']and run==proposal['known_run'],'exact known native component source/run, no foreign acceptance')
 need(type(value)is dict and set(value)==set(proposal['required_fields'])and value['status']==NATIVE_STATUS and value['source']==source and type(value['run'])is int and value['run']==run,'exact genuine Root native qualification required')
 need(value['recipe_sources']==dict(baseline=RECIPE,candidate=RECIPE)and value['actual_architecture']=='aarch64'and value['actual_page_size']==4096,'exact native recipe/architecture/page scope')
 for name,expected in proposal['finite_expectations'].items():need(value[name]==expected,'finite native retained scope: '+name)
 for key in('strict_replay','lifecycle'):
  p=value[key];need(type(p)is dict and set(p)=={'bytes','sha256'}and type(p['bytes'])is int and 0<p['bytes']<=192*1024**2 and re.fullmatch('[0-9a-f]{64}',p['sha256']or''),'finite retained native receipt pin')
 transport=value['original_transport'];need(type(transport)is dict and set(transport)=={'metadata','artifact_metadata','artifact','logs'},'four original native transport pins')
 for p in transport.values():need(type(p)is dict and set(p)=={'bytes','sha256'}and type(p['bytes'])is int and p['bytes']>0 and re.fullmatch('[a-f0-9]{64}',p['sha256']or''),'original native transport stream pin')
 artifacts=value['native_artifacts'];need(type(artifacts)is dict and set(artifacts)==set(proposal['native_artifacts']),'exact native artifact roles')
 need(artifacts['package_name']==PACKAGE and artifacts['baseline_version']=='0.1.0-1'and artifacts['candidate_version']==VERSION and artifacts['path_scope']=='ORIGINAL_PUBLIC_ARTIFACT_ROOT_NOT_A_PUBLISHED_CARRIER','native artifact product scope')
 need(type(value['limits'])is list and value['limits'],'retained native limitations required')
 return value

RENEWAL_FILES={'Root-acceptance.json': {'bytes': 4672, 'sha256': 'f251675c58cb4086a8885b903d2e9649ad2186526e54e50fa57364e780a13261'}, 'TEST-signing/TEST-public.asc': {'bytes': 429, 'sha256': 'fe1694d4616ab2f515e8a28c351c4a76b9de7e275449582ed9211658963a9254'}, 'TEST-signing/cachy-asahi-ksmctl-0.1.0-1-any.pkg.tar.xz.sig': {'bytes': 119, 'sha256': '3f5dc11e2d56f4c404f2b71fc2b3a676836b45b08901cc5b1aa83be91c7af76d'}, 'TEST-signing/cachy-asahi-ksmctl-0.1.0-2-any.pkg.tar.xz.sig': {'bytes': 119, 'sha256': '0d0e9bb33204e965abc615e14c6b9f30cc5b9cdd9ae59669948e43ddf466c6a2'}, 'TEST-signing/control.json': {'bytes': 59, 'sha256': 'f50e7c7a96960bb163cbe30f5be6a282da4006fbac5f03c0cdaf82813a2e0a3a'}, 'index.json': {'bytes': 12513, 'sha256': '4fa63d8a633efc3f337110917d69abf6a932461354e9452ca8632990bf0120ec'}, 'original-transport.json': {'bytes': 495, 'sha256': '0e1c026798f4cb2b4b5f6154816059753d824dceba27ed2545907631212cca0d'}, 'packages/cachy-asahi-ksmctl-a/cachy-asahi-ksmctl-0.1.0-1-any.pkg.tar.xz': {'bytes': 17244, 'sha256': 'b518e711c41b8d6bcdae71364b5529aaac982d12cef600f1b2fa17f51c895a4a'}, 'packages/cachy-asahi-ksmctl-b/cachy-asahi-ksmctl-0.1.0-1-any.pkg.tar.xz': {'bytes': 17244, 'sha256': 'b518e711c41b8d6bcdae71364b5529aaac982d12cef600f1b2fa17f51c895a4a'}, 'packages/cachy-asahi-ksmctl2-a/cachy-asahi-ksmctl-0.1.0-2-any.pkg.tar.xz': {'bytes': 24128, 'sha256': 'bac3d222b6490412c1c9c7bafd72d8169e8679a1e7b411b5794246aed0b57b5f'}, 'packages/cachy-asahi-ksmctl2-b/cachy-asahi-ksmctl-0.1.0-2-any.pkg.tar.xz': {'bytes': 24128, 'sha256': 'bac3d222b6490412c1c9c7bafd72d8169e8679a1e7b411b5794246aed0b57b5f'}, 'recipes/cachy-asahi-ksmctl2/.SRCINFO': {'bytes': 1557, 'sha256': '79c491a2930cc6d92648b301cc9af766d1d20dcb7e0687ab2690237b62e30a7f'}, 'recipes/cachy-asahi-ksmctl2/LICENSE': {'bytes': 17984, 'sha256': 'edaef632cbb643e4e7a221717a6c441a4c1a7c918e6e4d56debc3d8739b233f6'}, 'recipes/cachy-asahi-ksmctl2/NOTICE': {'bytes': 1359, 'sha256': '939ad92c65a6c2f9da2c723a4c6e136add87ccb4a7a6e8ba0dd89692a77f3f10'}, 'recipes/cachy-asahi-ksmctl2/PKGBUILD': {'bytes': 2373, 'sha256': 'c4f2cd4a506181df68edadc5ae36a976f3402910ff63d07ac1d3715bd38a3e9a'}, 'recipes/cachy-asahi-ksmctl2/README.md': {'bytes': 7590, 'sha256': 'a0422a6b280c5b1583afe5da7575ba6e98c476c8ce1efbe196ba33513e94a4ed'}, 'recipes/cachy-asahi-ksmctl2/adaptation.patch': {'bytes': 8216, 'sha256': '0bc6b1f4725eb510a0f890bd616ce682b98332b371c93d2144ad643181727212'}, 'recipes/cachy-asahi-ksmctl2/cachy-asahi-ksm-experiment': {'bytes': 20549, 'sha256': '1ea518cc25a0d3099b7723756fd66631c35d7a79d50b300f6387a25588306d79'}, 'recipes/cachy-asahi-ksmctl2/cachy-asahi-ksmctl': {'bytes': 6433, 'sha256': 'f9fd76eaa6a205d56fa4bb9123b8c721ea1277249c4cab58d1b57eaf8edc7558'}, 'recipes/cachy-asahi-ksmctl2/check-source.py': {'bytes': 2342, 'sha256': '7cca209ee6ad36726b03c0f54100b07bd6d08d974473d00c2092bbd5be4089a6'}, 'recipes/cachy-asahi-ksmctl2/experiment-provenance.json': {'bytes': 2144, 'sha256': 'e27da2f0e55a384bf8cb243e59437405391034347d10ff458fea7435898bba21'}, 'recipes/cachy-asahi-ksmctl2/source-provenance.json': {'bytes': 1016, 'sha256': 'd46e93a9893225d205a01fdcd3429782ba51d44c86b78e77fce458b53448b849'}, 'recipes/cachy-asahi-ksmctl2/test_experiment.py': {'bytes': 16687, 'sha256': '2f13fe326171a7e42dc84d6c4e2ac2bbe6eb8391f9e06393f6e2c09fa8dbb843'}, 'recipes/cachy-asahi-ksmctl2/test_ksmctl.py': {'bytes': 17730, 'sha256': 'e42602fd16579e30c8cb799f26c897c1e3e89515f20a49a346b1888ce3c94b6f'}, 'recipes/cachy-asahi-ksmctl2/upstream-ksmctl': {'bytes': 2606, 'sha256': 'cd5c8aa86df5a06a268ecc21297b4cd7d8df1053c90c8bcd4e53ef9bb16194d9'}, 'renewal/TEST-public.asc': {'bytes': 441, 'sha256': 'f4a8ffaa7a9b476f26523bfbe4bc41efb7cd0364f25c04502f1a3c28351ef4f5'}, 'renewal/cachy-asahi-ksmctl-0.1.0-2-any.pkg.tar.xz.sig': {'bytes': 119, 'sha256': '5c6163ec3b4da098fd1f02f59d4fe71b3cd328a00eac6f1900856da8aff79bbf'}, 'renewal/receipt.json': {'bytes': 2883, 'sha256': '0da6d71e91b6caf53fa7606d0b283c4ae00c22659fd764f3794cf9ed11120c5e'}, 'retention.json': {'bytes': 17717, 'sha256': 'b0535edfde656823a02f479abd65343875e7db06639224e7060c1c074b8668a1'}, 'runner-derivations.json': {'bytes': 1343, 'sha256': '92ff369cadeccd208d452f7aa851cb29288695a25a640945001e279934faad7e'}, 'runtime/lifecycle.json': {'bytes': 11539, 'sha256': '15a7c0bf0ac064770eb209db284253707ce337a6e2c10b5dfe549ac49ce95d88'}, 'runtime/report.json': {'bytes': 38890, 'sha256': '898ca2da29a3cd36c291efc25871fd6c063cf4eb73828a0d990be62be573c71e'}}
RENEWAL_OLD_FILES={'Root-acceptance.json': {'bytes': 4672, 'sha256': 'f251675c58cb4086a8885b903d2e9649ad2186526e54e50fa57364e780a13261'}, 'TEST-signing/TEST-public.asc': {'bytes': 429, 'sha256': 'fe1694d4616ab2f515e8a28c351c4a76b9de7e275449582ed9211658963a9254'}, 'TEST-signing/cachy-asahi-ksmctl-0.1.0-1-any.pkg.tar.xz.sig': {'bytes': 119, 'sha256': '3f5dc11e2d56f4c404f2b71fc2b3a676836b45b08901cc5b1aa83be91c7af76d'}, 'TEST-signing/cachy-asahi-ksmctl-0.1.0-2-any.pkg.tar.xz.sig': {'bytes': 119, 'sha256': '0d0e9bb33204e965abc615e14c6b9f30cc5b9cdd9ae59669948e43ddf466c6a2'}, 'TEST-signing/control.json': {'bytes': 59, 'sha256': 'f50e7c7a96960bb163cbe30f5be6a282da4006fbac5f03c0cdaf82813a2e0a3a'}, 'index.json': {'bytes': 12352, 'sha256': '398f0208b50a3b7c581ae76daff8b9e2508d11cee33b497e55376fd9e3e4b339'}, 'original-transport.json': {'bytes': 495, 'sha256': '0e1c026798f4cb2b4b5f6154816059753d824dceba27ed2545907631212cca0d'}, 'packages/cachy-asahi-ksmctl-a/cachy-asahi-ksmctl-0.1.0-1-any.pkg.tar.xz': {'bytes': 17244, 'sha256': 'b518e711c41b8d6bcdae71364b5529aaac982d12cef600f1b2fa17f51c895a4a'}, 'packages/cachy-asahi-ksmctl-b/cachy-asahi-ksmctl-0.1.0-1-any.pkg.tar.xz': {'bytes': 17244, 'sha256': 'b518e711c41b8d6bcdae71364b5529aaac982d12cef600f1b2fa17f51c895a4a'}, 'packages/cachy-asahi-ksmctl2-a/cachy-asahi-ksmctl-0.1.0-2-any.pkg.tar.xz': {'bytes': 24128, 'sha256': 'bac3d222b6490412c1c9c7bafd72d8169e8679a1e7b411b5794246aed0b57b5f'}, 'packages/cachy-asahi-ksmctl2-b/cachy-asahi-ksmctl-0.1.0-2-any.pkg.tar.xz': {'bytes': 24128, 'sha256': 'bac3d222b6490412c1c9c7bafd72d8169e8679a1e7b411b5794246aed0b57b5f'}, 'recipes/cachy-asahi-ksmctl2/.SRCINFO': {'bytes': 1557, 'sha256': '79c491a2930cc6d92648b301cc9af766d1d20dcb7e0687ab2690237b62e30a7f'}, 'recipes/cachy-asahi-ksmctl2/LICENSE': {'bytes': 17984, 'sha256': 'edaef632cbb643e4e7a221717a6c441a4c1a7c918e6e4d56debc3d8739b233f6'}, 'recipes/cachy-asahi-ksmctl2/NOTICE': {'bytes': 1359, 'sha256': '939ad92c65a6c2f9da2c723a4c6e136add87ccb4a7a6e8ba0dd89692a77f3f10'}, 'recipes/cachy-asahi-ksmctl2/PKGBUILD': {'bytes': 2373, 'sha256': 'c4f2cd4a506181df68edadc5ae36a976f3402910ff63d07ac1d3715bd38a3e9a'}, 'recipes/cachy-asahi-ksmctl2/README.md': {'bytes': 7590, 'sha256': 'a0422a6b280c5b1583afe5da7575ba6e98c476c8ce1efbe196ba33513e94a4ed'}, 'recipes/cachy-asahi-ksmctl2/adaptation.patch': {'bytes': 8216, 'sha256': '0bc6b1f4725eb510a0f890bd616ce682b98332b371c93d2144ad643181727212'}, 'recipes/cachy-asahi-ksmctl2/cachy-asahi-ksm-experiment': {'bytes': 20549, 'sha256': '1ea518cc25a0d3099b7723756fd66631c35d7a79d50b300f6387a25588306d79'}, 'recipes/cachy-asahi-ksmctl2/cachy-asahi-ksmctl': {'bytes': 6433, 'sha256': 'f9fd76eaa6a205d56fa4bb9123b8c721ea1277249c4cab58d1b57eaf8edc7558'}, 'recipes/cachy-asahi-ksmctl2/check-source.py': {'bytes': 2342, 'sha256': '7cca209ee6ad36726b03c0f54100b07bd6d08d974473d00c2092bbd5be4089a6'}, 'recipes/cachy-asahi-ksmctl2/experiment-provenance.json': {'bytes': 2144, 'sha256': 'e27da2f0e55a384bf8cb243e59437405391034347d10ff458fea7435898bba21'}, 'recipes/cachy-asahi-ksmctl2/source-provenance.json': {'bytes': 1016, 'sha256': 'd46e93a9893225d205a01fdcd3429782ba51d44c86b78e77fce458b53448b849'}, 'recipes/cachy-asahi-ksmctl2/test_experiment.py': {'bytes': 16687, 'sha256': '2f13fe326171a7e42dc84d6c4e2ac2bbe6eb8391f9e06393f6e2c09fa8dbb843'}, 'recipes/cachy-asahi-ksmctl2/test_ksmctl.py': {'bytes': 17730, 'sha256': 'e42602fd16579e30c8cb799f26c897c1e3e89515f20a49a346b1888ce3c94b6f'}, 'recipes/cachy-asahi-ksmctl2/upstream-ksmctl': {'bytes': 2606, 'sha256': 'cd5c8aa86df5a06a268ecc21297b4cd7d8df1053c90c8bcd4e53ef9bb16194d9'}, 'retention.json': {'bytes': 17717, 'sha256': 'b0535edfde656823a02f479abd65343875e7db06639224e7060c1c074b8668a1'}, 'runner-derivations.json': {'bytes': 1343, 'sha256': '92ff369cadeccd208d452f7aa851cb29288695a25a640945001e279934faad7e'}, 'runtime/lifecycle.json': {'bytes': 11539, 'sha256': '15a7c0bf0ac064770eb209db284253707ce337a6e2c10b5dfe549ac49ce95d88'}, 'runtime/report.json': {'bytes': 38890, 'sha256': '898ca2da29a3cd36c291efc25871fd6c063cf4eb73828a0d990be62be573c71e'}}

def renewed_native_index(index,inputs):
 """Authenticate new TEST32 role then recover original29 historical native index."""
 import copy
 need(len(RENEWAL_FILES)==32 and len(RENEWAL_OLD_FILES)==29 and set(RENEWAL_FILES)-set(RENEWAL_OLD_FILES)=={'renewal/TEST-public.asc','renewal/cachy-asahi-ksmctl-0.1.0-2-any.pkg.tar.xz.sig','renewal/receipt.json'},'finite complete TEST renewal role')
 for name,row in RENEWAL_FILES.items():checked(inputs,dict(path=name,**row),16*1024**2)
 need(pin(encoded(index))==RENEWAL_FILES['index.json'],'whole new Root-published native-input index')
 for name,row in RENEWAL_OLD_FILES.items():
  if name!='index.json':need(RENEWAL_FILES[name]==row,'all28 original native/recipe/license/transport/key/signature DATA bodies held')
 prior=copy.deepcopy(index);need(prior.pop('test_signature_renewal')==dict(path='renewal/receipt.json',**RENEWAL_FILES['renewal/receipt.json']),'exact renewal receipt ref')
 prior['signer']='7E73A80AF8FD5DA6529EF27E1AB823DC28925AA5'
 for role,path in(('public_key','TEST-signing/TEST-public.asc'),('signature','TEST-signing/cachy-asahi-ksmctl-0.1.0-2-any.pkg.tar.xz.sig')):prior['files'][role]=dict(path=path,**RENEWAL_OLD_FILES[path])
 need(pin(encoded(prior))==RENEWAL_OLD_FILES['index.json'],'whole original historical native index inverse before all unchanged native gates')
 receipt=decode(checked(inputs,index['test_signature_renewal'],65536));need(receipt['purpose']=='ARCHITECTURE_NEUTRAL_EPHEMERAL_TEST_SIGNATURE_RENEWAL_ONLY'and receipt['historical_native']==dict(archive_bodies='EXACT_BYTE_HELD',build_credit='HISTORICAL_NATIVE_BUILD_ONLY_NO_NEW_BUILD',native_decision=index['native_decision'],recipe_sources=index['recipe_sources'],run=index['run'],source=index['source'])and receipt['original_carrier']=='7a976288a9e67b93e23860c7ee1664775ccb2dbd','same complete historical native authority; no renewed build credit')
 signer=receipt['signer'];need(signer==dict(authority='EPHEMERAL_TEST_ONLY_NOT_PRODUCTION_TRUST',created=1792434846,expires=1793039646,fingerprint='D0B033AD1C44F88A1B64A645D72B18C8C32E249A',validity_seconds=604800)and index['signer']==signer['fingerprint']and receipt['old_signer']==prior['signer']and receipt['archive']=={k:index['files']['a'][k]for k in('bytes','sha256')},'exact renewed TEST signer over identical historical archive')
 for role,path in(('public_key','renewal/TEST-public.asc'),('signature','renewal/cachy-asahi-ksmctl-0.1.0-2-any.pkg.tar.xz.sig')):need(index['files'][role]==dict(path=path,**receipt[role])and receipt[role]==RENEWAL_FILES[path],'exact new TEST signature/public key operands only')
 need(receipt['actual_lifecycle']=='NOT_RUN'and receipt['hardware']=='NOT_RUN'and receipt['release']=='NOT_ADMITTED','TEST renewal grants no lifecycle/hardware/release acceptance')
 old=receipt['historical_expired_signature_verification'];need(old['acceptance']=='REFUSED_EXPIRED_KEY_EVEN_IF_GPG_EXIT_ZERO'and '[GNUPG:] KEYEXPIRED 'in old['status_stdout']and '[GNUPG:] EXPKEYSIG 'in old['status_stdout'],'historical expired TEST signature remains failure DATA')
 return prior

def native_gate(selection,inputs,root=HERE):
 need(type(selection)is dict and all(selection.get(k)is not None for k in('native_source','native_run','native_decision','native_inputs')),'UNBOUND native qualification: no output or actors')
 need(re.fullmatch('[0-9a-f]{40}',selection['native_source']or'')and type(selection['native_run'])is int and selection['native_run']>0,'exact native source/run identity')
 authority=decode(checked(inputs,selection['native_decision'],65536));native_record(authority,selection['native_source'],selection['native_run'],root)
 current_index=decode(checked(inputs,selection['native_inputs'],2*1024**2));index=renewed_native_index(current_index,inputs);need(index.get('purpose')=='KSM2_NATIVE_INPUTS_ONLY_NO_VM_CREDIT'and index.get('source')==selection['native_source']and index.get('run')==selection['native_run']and index.get('name')==PACKAGE and index.get('version')==VERSION,'same accepted native input index')
 need(set(index['files'])=={'a','b','signature','public_key','control','runtime_report'}and re.fullmatch('[0-9A-F]{40}',index.get('signer')or''),'exact native archive/trust/report roles')
 artifacts=authority['native_artifacts'];joins=dict(a=artifacts['candidate']['a'],b=artifacts['candidate']['b'],signature=artifacts['signatures']['candidate'],public_key=artifacts['TEST_public_key'],control=artifacts['TEST_control'],runtime_report=artifacts['runtime_report'])
 refs=[artifacts['TEST_control'],artifacts['TEST_public_key'],artifacts['baseline']['a'],artifacts['baseline']['b'],artifacts['candidate']['a'],artifacts['candidate']['b'],artifacts['lifecycle'],artifacts['retained_package_output_index'],artifacts['runner_derivations'],artifacts['runtime_report'],artifacts['signatures']['baseline'],artifacts['signatures']['candidate']]
 need(index['native_decision']==selection['native_decision']and index['native_artifact_refs']==refs and index['recipe_sources']==dict(baseline=RECIPE,candidate=RECIPE),'exact index Root decision/artifact/recipe joins')
 for p in refs:checked(inputs,p,16*1024**2)
 recipe=index['recipe'];need(recipe['source']==RECIPE and recipe['path']=='recipes/cachy-asahi-ksmctl2'and len(recipe['files'])==14,'exact source-owned candidate recipe role')
 expected={p.name:pin(read(p,1024**2))for p in(Path(root)/'native-source/packages/tools/cachy-asahi-ksmctl2').iterdir()if p.is_file()};need(recipe['files']==expected,'whole native candidate recipe source table')
 for name,p in recipe['files'].items():checked(inputs,dict(path=recipe['path']+'/'+relative(name),**p),1024**2)
 need(index['files']==joins,'original retained artifact references must join Root decision without path remapping')
 data={k:checked(inputs,p,16*1024**2)for k,p in index['files'].items()};need(data['a']==data['b']and index['files']['a']['path']!=index['files']['b']['path'],'two exact native archives')
 transport=checked(inputs,index['transport'],1024**2);need(decode(transport)==authority['original_transport'],'exact four native transport pins in byte-pinned DATA receipt')
 control=decode(data['control']);need(control.get('signer')==index['signer'],'signer/control join')
 report=decode(data['runtime_report']);product=report['products']['cachy-asahi-ksmctl2'];need(index.get('product')==product,'whole native product payload/report join')
 need(product['version']==VERSION and len(product['builds'])==2 and type(product['builds'][0]['payload'])is dict,'actual native candidate version and full payload')
 need(all(p['sha256']==sha(data['a'])for p in product['builds']),'actual native report/archive byte hash join')
 need(product['builds'][0]['archive']==Path(index['files']['a']['path']).name and product['builds'][1]['archive']==Path(index['files']['b']['path']).name,'actual native archive basenames')
 return authority,current_index

def actual_identity(selection):
 need(re.fullmatch('[0-9a-f]{40}',selection.get('VM_source')or'')and type(selection.get('VM_run'))is int and selection['VM_run']>0 and re.fullmatch('codex/[a-z0-9-]+',selection.get('VM_ref')or''),'exact actual VM identity')

def actual_environment(s):
 actual_identity(s);need(all(os.environ.get(k)==s['VM_source']for k in('SOURCE_SHA','GITHUB_SHA','GITHUB_WORKFLOW_SHA'))and os.environ.get('GITHUB_RUN_ID')==str(s['VM_run'])and os.environ.get('GITHUB_RUN_ATTEMPT')=='1'and os.environ.get('GITHUB_REF_NAME')==s['VM_ref']and os.environ.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and os.environ.get('GITHUB_EVENT_NAME')=='workflow_dispatch','genuine first-attempt same-source VM workflow environment required')

def source_check(root=HERE):
 root=Path(root);rows=decode(read(root/'source-files.json',1024**2))['files']
 actual={p.relative_to(root).as_posix()for p in root.rglob('*')if p.is_file()};need(actual==set(rows)|{'source-files.json'},'closed VM source files only')
 for name,p in rows.items():need(pin(read(root/relative(name),16*1024**2))==p,'VM source pin differs: '+name)
 return rows

def gate(selection,inputs,root=HERE):
 need(type(selection)is dict and all(selection.get(k)is not None for k in('native_decision','native_inputs','kernel_build','media','VM_source','VM_ref','VM_run')),'UNBOUND native qualification/kernel/media: no output or actors')
 actual_identity(selection);return native_gate(selection,inputs,root)

def guest_guard(s,worker=False):
 need((os.getpid()!=1 and os.getppid()==1 if worker else os.getpid()==1)and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and os.sysconf('SC_PAGE_SIZE')==16384,'actual private generic16K PID1 only')
 need(type(s['nonce'])is str and re.fullmatch('[0-9a-f]{32}',s['nonce']),'fixed VM nonce')
 tokens=Path('/proc/cmdline').read_text().split();need(tokens.count('caa_ksm2_vm='+s['nonce'])==1 and 'init=/init-ksm2'in tokens,'owned boot marker')
 need({p.name for p in Path('/sys/class/net').iterdir()}<={'lo'}and s['kernel']['profile']==PROFILE and os.uname().release==s['kernel']['release'],'private noNIC/new kernel scope')

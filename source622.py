# SPDX-License-Identifier: MIT
"""Closed622 lane AND exact original51/800 source mechanisms; no actors."""
import ast,hashlib,json,os,subprocess,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import case as C,desktop622 as X
PRODUCTS={'Core800-acceptance.json': {'bytes': 2043, 'sha256': 'd6f67e4c2782f9b609309e6e5627ad6534f172f0560ec7e2e2ec5c3a4f251e9d'}, 'LICENSE': {'bytes': 27836, 'sha256': '624b2335eff599a84764ef0a51b6d2962b5ef504a792e1b362ea31f0cbc1ac4c'}, 'README.md': {'bytes': 6730, 'sha256': '849d859eb0d7c49d4a1a673218fbc74a7bcf378b711b3e2ebb21ab3887dcff8e'}, 'acl_policy.py': {'bytes': 83174, 'sha256': '9204e5794f01b49a0b301088f3a5b4439e57eb7273fc5afac278b3f967816462'}, 'adapter.py': {'bytes': 1401, 'sha256': 'fb0aadeb5fb230346161be90e94696aecaecf6d2b3e1e3f40538d7ab72f23586'}, 'assembly622.py': {'bytes': 466, 'sha256': '610836ad8beeed379079b711c37d20867b28218d9422631ff7857d8a4872be55'}, 'boot.py': {'bytes': 5422, 'sha256': 'f6df3d8e5b5602f3b9eca4ebfbb54afaa354ac29b7b4b9cc26988a9de064349e'}, 'candidate_capacity.py': {'bytes': 49900, 'sha256': '03018514575bb12b0f6623b4f4a2396a2ce3fa3691225c6134f061a787d12a83'}, 'case.py': {'bytes': 8668, 'sha256': '07ea5e72a4ad8b22b9a6594aada61941abefa4659b46b26fc0bb59efa239319b'}, 'clock.py': {'bytes': 4205, 'sha256': 'cf43f16973294a8e687c65341cb63329a71d9a2a2ea488f0f6f2e20b97087c3c'}, 'composition-parent.json': {'bytes': 3104180, 'sha256': 'b9fc19e8f0868d55470a7dfc6542ea63796b8d758377d09764d6d7661976c1f7'}, 'composition.json': {'bytes': 444951, 'sha256': '154aab2490617a23d3fb745cc8c03d3bc4abb35d3c836f4a43394b1758158d6c'}, 'compression-profile.json': {'bytes': 1179, 'sha256': 'aec949ee839909702d208a3f91710c4565b5dcf46fa4fca0b2bd3bc13558d57c'}, 'controller.py': {'bytes': 11715, 'sha256': '50061a1e0e91dabdbe66572500cfaf343c97e6cd750f77665b17c4ec4a1cb719'}, 'desktop622.py': {'bytes': 9856, 'sha256': 'eace06a0842aa08b803de34522178a086943c3e05086b1ed07f7fb986fd07400'}, 'effects.py': {'bytes': 6147, 'sha256': 'e2d4d80f64736975437615146f09f8796c20a634b02bb31d167614700609aae7'}, 'entry.py': {'bytes': 6025, 'sha256': 'f34a53b6ea08ef673d0d187e70a4fc1a496b8b00882cd432fbe3af0e50ddac68'}, 'evidence.py': {'bytes': 7937, 'sha256': '21da5d7bc45214cac174da7fa779ddf281760841f5a233b9c57b21b154d4e4be'}, 'expected607.lock': {'bytes': 12076, 'sha256': 'be35402204ba5c03d78279722afa83047c9575d2da70fb5c4064f46ed15954c5'}, 'expected622.lock': {'bytes': 12444, 'sha256': '189d037738680f5dfc9a5d48169eddf866383a06b070c094dac613c9d1b4eca8'}, 'export622.py': {'bytes': 55755, 'sha256': 'b06fbfdc820f27bc4553345cdbc65b85b5e81e33f28e2175321a18ea02a20ce4'}, 'formation622.py': {'bytes': 4938, 'sha256': 'c0dba994e0edb0da162e796a68b555ead745889baf5cd70a929fa465e79b4485'}, 'graph_api.py': {'bytes': 1899, 'sha256': '16839d25ad6a3957b68848fb6718a393840840b433361eba1ae07ddbbdafe5d7'}, 'graph_stage_source.py': {'bytes': 56225, 'sha256': 'b0ce77149ff72ea2936c23fcbdeefe3c011a2dfc75d60d40ec650ab233e5e845'}, 'guest.py': {'bytes': 23657, 'sha256': 'e921b2aa54f47125dd83c8c4932fa6ba3c4048f107e4dcf6df4d42680c71b874'}, 'guest_guard.py': {'bytes': 4160, 'sha256': '8db72fbc36f59c5660f7ddc4f56f3bdbed81cdec4344c65017db522501f83de7'}, 'hook.py': {'bytes': 787, 'sha256': 'b3e2bd1c4eb715928919028be1dddce2090605d233ba8f4d6bf98d67e95f5fa3'}, 'host.py': {'bytes': 4302, 'sha256': 'd25d18a115483bf7b6f2f0f0f1bfe21d19de37951949e55685edcfb77d84248b'}, 'initramfs.py': {'bytes': 4502, 'sha256': '50d3a4833f5b783704c1a07fb3c213819769a08294eb677e7066ec13595d4b98'}, 'journal_acl.py': {'bytes': 94610, 'sha256': 'e3849c1604b6520c4fb813692290a0989d08542cf3ada1fbf412948a83a26c9c'}, 'lane622.py': {'bytes': 9700, 'sha256': '31d47330f090f82c5ed5a1da108045492fa4de9d47bd45bbb2c169781d7c52bf'}, 'media.py': {'bytes': 9202, 'sha256': '4ade0d8e6fb970e1291b2f9a5f55653934844c36e866491c338678650ac8af0e'}, 'mime-profile.json': {'bytes': 259815, 'sha256': '4c601c715c4ee64484f49dacebfddb53da9391893c29e3c0626a92942a36a793'}, 'mime_cache.py': {'bytes': 47294, 'sha256': '1e04c1a6d7918c6499a3a356397749a60083000bb493e9fb3df1f277ea635922'}, 'ownership622.py': {'bytes': 63574, 'sha256': '4392285392cca3e9e01241599443f061bb4cdd559c507556b2ef5e1ae2915a8f'}, 'pid1-baseline.json': {'bytes': 528, 'sha256': 'b508b5ff108bc90d79952c7a90efdb812ccd008421297412b9338a2c6c1c8be6'}, 'pid1-expected.json': {'bytes': 548, 'sha256': '2891023d89c1f35b47c8e4cb8b7c88105ddce72b18796a377b161e7278f03659'}, 'prepare.py': {'bytes': 1394, 'sha256': '554c52290776a5f4ec314ba8abad836db1d99ab81e4782964e3a0d4bbe04a8a2'}, 'profile.json': {'bytes': 334009, 'sha256': 'e03456c28bcae23d3cb6ae856af81adf75a1a60905aefb0e0238acd147e3de24'}, 'provision622.py': {'bytes': 48590, 'sha256': '0e11e0d2339ec94eef3a760c1298d74ba5caab2367adcf601258c1c3826ec341'}, 'run622.py': {'bytes': 29686, 'sha256': 'b063b6ef9b93a1c2d6a539cc0a9c4b9f9aaac6566d4d3b82b5089609b6c01aa3'}, 'serial-profile.json': {'bytes': 734, 'sha256': 'f7cd6095424948d3e108b3b96763674612fc086e2da08cb783da78057a0f0c0e'}, 'serial_result.py': {'bytes': 52907, 'sha256': 'd708f9de5f31a15882596ed95fb9514958ce8df4a85ce2152dcb265f878b3991'}, 'test_bridge622.py': {'bytes': 144293, 'sha256': 'b11df712429024b4052f0a8d3214ef73f269b475cffd972886ee7c2aea6d5cdb'}, 'test_case.py': {'bytes': 19195, 'sha256': '723c962fafa76c84e8d6764e687bdebe5faad63b00a96edb0355f27c8ad7a189'}, 'test_desktop622.py': {'bytes': 5072, 'sha256': 'ed28a02f696c57785041c53b8c8380b3817cbb2e884b1fd3df4451881c7a6daf'}, 'test_emission.py': {'bytes': 2521, 'sha256': '57a4a755385a5e380e303f3e3da33bafcfc71063ffce2041f22b22b5a5ffdf8f'}, 'test_host.py': {'bytes': 3090, 'sha256': 'b01d3159bd0b0c688434bac69976dd16cf173358a598957f3be58f49c1642460'}, 'test_initramfs.py': {'bytes': 7864, 'sha256': '0d0a521c9f4e8793c4b15a82119dfca7a46642033c94b72327e27118a797bae2'}, 'test_protocol.py': {'bytes': 4378, 'sha256': 'ac482fa3a8fc0ab932bcf8e65b864e4ac26affc1ecf30ecea61cd42b52264d25'}, 'test_route.py': {'bytes': 9847, 'sha256': 'b32ab0d4b5dd3cbfbb131811a8460bc82b07dcd517598971c1b14bdc437123ab'}, 'test_sources.py': {'bytes': 19838, 'sha256': 'eef8c2a75e8f3c5e282eb48daba98ce471c58791b29e0653626fe0949a06a8e7'}, 'tmpfiles_hash.py': {'bytes': 41582, 'sha256': '6912c9ae1a14477212921c6aed68b54e7c83a6a9308664e515c51619603eba6b'}, 'transaction_output.py': {'bytes': 42998, 'sha256': '8ce374e17744888ad70ca0b19485ffd6f72d6cf029f47f6fdfaa07c47dce6ce9'}, 'units/caa-core-observer.service': {'bytes': 474, 'sha256': '95b66c92d2acbbfdb5d904c2c0f6b61518fd3bb7c71eb290751a27e9d2fc8e6e'}, 'units/caa-core-probe.service': {'bytes': 358, 'sha256': 'b8a4a142045304e53893608548c293b684fbe295831e25a84d5cf3c19ef0a6b4'}, 'units/caa-core-worker.service': {'bytes': 352, 'sha256': '70ebee606afc5fee5359d3ea05cee62445766c8a4033d6fbee7398f0be6f9353'}, 'units/caa-core.target': {'bytes': 189, 'sha256': '1025ff9b01e2132861b26cf35fd5f4a25424638f03e49222552ef0cbbb719e37'}, 'validate.py': {'bytes': 7302, 'sha256': '00fd4f5a2c4652d6a6c39737188decc60b8a001964bf919fdaf9d68c11b1c051'}, 'vm_validation.py': {'bytes': 52784, 'sha256': 'a69264ea55374b2058048ca2441c89942e65f43d06125b0d1ad71d3e021202e1'}, 'workflow.yml.in': {'bytes': 63426, 'sha256': 'aae8136a909eb8a0f0bcdee355ad986ed657e12a65460dec5d16927b4128bda0'}, 'xattr_diagnostic.py': {'bytes': 17502, 'sha256': 'ad88aee4e41afa9f78d45785a45f274abeac1aaf335225ec0c4cc61240cbba47'}}
SELF='fa7b172df7faac6b075d11433fc97f5dfc323cb4b9993851f3d9bd504bc72b86'
ALIASES=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml')

def files(root):
 result={}
 for p in Path(root).rglob('*'):
  name=p.relative_to(root).as_posix()
  if name.split('/')[0]=='.git':continue
  C.need(not p.is_symlink()and(p.is_dir()or p.is_file()),'ordinary full closed source')
  if p.is_file():result[name]=C.pin(C.read(p,32*1024**2))
 return result

def inverse(root):
 record=C.decode(C.read(root/'composition-parent.json',4*1024**2));rows=files(root);historical=same66_before(root);before=record['before'];C.need(record['source']=='11b3cfb59663e42b34247facb9f30f042e891444'and len(before)==51 and set(record['changed'])<=set(before),'whole published51 predecessor')
 out={}
 for n,pin in before.items():
  raw=record['changed'][n].encode()if n in record['changed']else historical[n];C.need(C.pin(raw)==pin,'complete exact51 inverse: '+n);out[n]=raw
 C.need({n:C.pin(raw)for n,raw in out.items()}==before,'whole before-source51 map');return out

def verify(root):
 root=Path(root).absolute();start=time.monotonic();same66_before(root);rows=files(root);manifest=C.decode(C.read(root/'source-manifest.json',4*1024**2));C.need(manifest['purpose']==X.SCOPE and manifest['actual']is None,'distinct unbound current622 source lane');C.need(rows==dict(manifest['files'],**{'source-manifest.json':C.pin(C.read(root/'source-manifest.json',4*1024**2)),**{n:rows[n]for n in ALIASES}}),'closed current source namespace')
 C.need(PRODUCTS is not None and all(rows[n]==pin for n,pin in PRODUCTS.items()),'every fixed current product/data operand');raw=C.read(root/'source622.py');C.need(SELF!='@SELF@'and raw.count(SELF.encode())==1 and hashlib.sha256(raw.replace(SELF.encode(),b'@SELF@')).hexdigest()==SELF,'whole current sourceguard selfseal');C.need(all(C.read(root/n)==C.read(root/'workflow.yml.in')for n in ALIASES),'exact decoded workflow aliases')
 value=C.decode(C.read(root/'composition.json',4*1024**2));X.plan(value);before=inverse(root)
 # Original51 source executes only its unchanged source-only route in an exact
 # private reconstruction. No current/native/result or actor authority follows.
 with tempfile.TemporaryDirectory(prefix='core622-exact-source51-')as td:
  target=Path(td)
  for n,raw in before.items():p=target/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
  C.need(files(target)==C.decode(C.read(root/'composition-parent.json',4*1024**2))['before'],'entire private51 inverse before source gate')
  result=subprocess.run([sys.executable,'-I','-B',str(target/'entry.py'),'source','--source',str(target)],stdin=subprocess.DEVNULL,capture_output=True,timeout=max(.001,300-(time.monotonic()-start)),env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1'))
  C.need(result.returncode==0 and not result.stderr and len(result.stdout)<=1024**2,'whole original51 and older source predicate');fact=C.decode(result.stdout);C.need(fact['status']=='PASS_CLOSED_SOURCE_ONLY_NOT_EXECUTED'and fact['files']==51,'genuine original51 source-only fact')
 # All selected facades/actors are syntax checked; this source phase starts none.
 for n in ('desktop622.py','formation622.py','provision622.py','lane622.py','assembly622.py','run622.py','ownership622.py'):ast.parse(C.read(root/n),filename=n)
 C.need(time.monotonic()-start<300,'original fixed source300');return dict(status='PASS_SOURCE_ONLY_CURRENT607_COPIED_PROVISIONING_NORMAL_CORE622_TWO_BOOT_NOT_RUN',files=len(rows),parent51=fact,base=607,supported=620,installed=622,held=602,provisioning=X.PROVISIONING,normal_fresh607_installation='NOT_RUN',new_actual=None,fit='NOT_ESTABLISHED',M2='NOT_RUN',baseline_capacity_diagnostic=__import__('candidate_capacity').diagnostic_profile(__import__('candidate_capacity').DIAGNOSTIC_NAME))

# Finite whole immediate66 inverse; the existing verify body and original51
# execution remain mandatory. No historical actor/result is executed here.
def same66_before(root):
 C=globals()['C'];root=Path(root)
 causal=C.decode(C.read(root/'composition-parent.json',4*1024**2))['runner_resilience_causal']
 C.need(causal['schema']==1 and causal['parent_source']=='04a943632f8c8eab4d03f073a46f3b161567b1e3' and causal['actual']is None and causal['publication_parent']=='04a943632f8c8eab4d03f073a46f3b161567b1e3'and len(causal['before'])==66 and causal['acceptance']is False,'exact staged export66 before retained DATA route, no invented publication')
 prior={n:C.read(root/n,4*1024**2)for n in causal['before']}
 for name,rules in causal['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact retained causal source inverse');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('runner_resilience_causal')==causal,'complete causal parent inverse');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in causal['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode()
 for name,before in(('PRODUCTS',causal['guard_products_before']),('SELF',causal['guard_self_before'])):
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one retained causal guard seal inverse');text=text.replace(after,before,1)
 C.need(text.count(causal['guard_prefix'])==1,'one retained causal guard prefix inverse');text=text.replace(causal['guard_prefix'],causal['guard_anchor'],1);prior['source622.py']=text.encode();C.need({n:C.pin(raw)for n,raw in prior.items()}==causal['before'],'whole exact staged export66 before all previous Source predicates')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('PRODUCTS','SELF')};C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all preceding export66 products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole preceding export66 selfseal')
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'bounded complete export66 inverse only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 causal=C.decode(C.read(root/'composition-parent.json',4*1024**2))['private_context_retirement_inventory_causal']
 C.need(causal['schema']==1 and causal['parent_source']=='425901e440a4fbe24a5aa00857a9962714599be4' and causal['actual']is None and causal['publication_parent']=='425901e440a4fbe24a5aa00857a9962714599be4'and len(causal['before'])==66 and causal['acceptance']is False,'exact staged export66 before retained DATA route, no invented publication')
 prior={n:C.read(root/n,4*1024**2)for n in causal['before']}
 for name,rules in causal['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact retained causal source inverse');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('private_context_retirement_inventory_causal')==causal,'complete causal parent inverse');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in causal['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode()
 for name,before in(('PRODUCTS',causal['guard_products_before']),('SELF',causal['guard_self_before'])):
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one retained causal guard seal inverse');text=text.replace(after,before,1)
 C.need(text.count(causal['guard_prefix'])==1,'one retained causal guard prefix inverse');text=text.replace(causal['guard_prefix'],causal['guard_anchor'],1);prior['source622.py']=text.encode();C.need({n:C.pin(raw)for n,raw in prior.items()}==causal['before'],'whole exact staged export66 before all previous Source predicates')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('PRODUCTS','SELF')};C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all preceding export66 products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole preceding export66 selfseal')
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'bounded complete export66 inverse only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 causal=C.decode(C.read(root/'composition-parent.json',4*1024**2))['context_observations_control_profile_causal']
 C.need(causal['schema']==1 and causal['parent_source']=='d308e08bbffb98e0b57ad7b6af42ff8e5aa9de2a' and causal['actual']is None and causal['publication_parent']=='d308e08bbffb98e0b57ad7b6af42ff8e5aa9de2a'and len(causal['before'])==66 and causal['acceptance']is False,'exact staged export66 before retained DATA route, no invented publication')
 prior={n:C.read(root/n,4*1024**2)for n in causal['before']}
 for name,rules in causal['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact retained causal source inverse');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('context_observations_control_profile_causal')==causal,'complete causal parent inverse');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in causal['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode()
 for name,before in(('PRODUCTS',causal['guard_products_before']),('SELF',causal['guard_self_before'])):
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one retained causal guard seal inverse');text=text.replace(after,before,1)
 C.need(text.count(causal['guard_prefix'])==1,'one retained causal guard prefix inverse');text=text.replace(causal['guard_prefix'],causal['guard_anchor'],1);prior['source622.py']=text.encode();C.need({n:C.pin(raw)for n,raw in prior.items()}==causal['before'],'whole exact staged export66 before all previous Source predicates')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('PRODUCTS','SELF')};C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all preceding export66 products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole preceding export66 selfseal')
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'bounded complete export66 inverse only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 causal=C.decode(C.read(root/'composition-parent.json',4*1024**2))['context_retirement_observations_causal']
 C.need(causal['schema']==1 and causal['parent_source']=='23be54e7ee694ed766bfc11fe7bf841a1089b4ba' and causal['actual']is None and causal['publication_parent']=='23be54e7ee694ed766bfc11fe7bf841a1089b4ba'and len(causal['before'])==66 and causal['acceptance']is False,'exact staged export66 before retained DATA route, no invented publication')
 prior={n:C.read(root/n,4*1024**2)for n in causal['before']}
 for name,rules in causal['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact retained causal source inverse');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('context_retirement_observations_causal')==causal,'complete causal parent inverse');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in causal['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode()
 for name,before in(('PRODUCTS',causal['guard_products_before']),('SELF',causal['guard_self_before'])):
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one retained causal guard seal inverse');text=text.replace(after,before,1)
 C.need(text.count(causal['guard_prefix'])==1,'one retained causal guard prefix inverse');text=text.replace(causal['guard_prefix'],causal['guard_anchor'],1);prior['source622.py']=text.encode();C.need({n:C.pin(raw)for n,raw in prior.items()}==causal['before'],'whole exact staged export66 before all previous Source predicates')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('PRODUCTS','SELF')};C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all preceding export66 products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole preceding export66 selfseal')
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'bounded complete export66 inverse only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 causal=C.decode(C.read(root/'composition-parent.json',4*1024**2))['outer_capture_control_causal']
 C.need(causal['schema']==1 and causal['parent_source']=='cc5608ea4343022fa9e2035af1d8f23bde88949a' and causal['actual']is None and causal['publication_parent']=='cc5608ea4343022fa9e2035af1d8f23bde88949a'and len(causal['before'])==66 and causal['acceptance']is False,'exact staged export66 before retained DATA route, no invented publication')
 prior={n:C.read(root/n,4*1024**2)for n in causal['before']}
 for name,rules in causal['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact retained causal source inverse');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('outer_capture_control_causal')==causal,'complete causal parent inverse');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in causal['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode()
 for name,before in(('PRODUCTS',causal['guard_products_before']),('SELF',causal['guard_self_before'])):
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one retained causal guard seal inverse');text=text.replace(after,before,1)
 C.need(text.count(causal['guard_prefix'])==1,'one retained causal guard prefix inverse');text=text.replace(causal['guard_prefix'],causal['guard_anchor'],1);prior['source622.py']=text.encode();C.need({n:C.pin(raw)for n,raw in prior.items()}==causal['before'],'whole exact staged export66 before all previous Source predicates')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('PRODUCTS','SELF')};C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all preceding export66 products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole preceding export66 selfseal')
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'bounded complete export66 inverse only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 causal=C.decode(C.read(root/'composition-parent.json',4*1024**2))['outer_diagnostics_causal']
 C.need(causal['schema']==1 and causal['parent_source']=='28c361dc39a7865b30c46015c2778091ed621784' and causal['actual']is None and causal['publication_parent']=='28c361dc39a7865b30c46015c2778091ed621784'and len(causal['before'])==66 and causal['acceptance']is False,'exact staged export66 before retained DATA route, no invented publication')
 prior={n:C.read(root/n,4*1024**2)for n in causal['before']}
 for name,rules in causal['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact retained causal source inverse');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('outer_diagnostics_causal')==causal,'complete causal parent inverse');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in causal['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode()
 for name,before in(('PRODUCTS',causal['guard_products_before']),('SELF',causal['guard_self_before'])):
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one retained causal guard seal inverse');text=text.replace(after,before,1)
 C.need(text.count(causal['guard_prefix'])==1,'one retained causal guard prefix inverse');text=text.replace(causal['guard_prefix'],causal['guard_anchor'],1);prior['source622.py']=text.encode();C.need({n:C.pin(raw)for n,raw in prior.items()}==causal['before'],'whole exact staged export66 before all previous Source predicates')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('PRODUCTS','SELF')};C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all preceding export66 products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole preceding export66 selfseal')
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'bounded complete export66 inverse only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 causal=C.decode(C.read(root/'composition-parent.json',4*1024**2))['closed_source_fixture_causal']
 C.need(causal['schema']==1 and causal['parent_source']=='60bc34a87077ae12725d55f3c84fb97cba20554d' and causal['actual']is None and causal['publication_parent']=='60bc34a87077ae12725d55f3c84fb97cba20554d'and len(causal['before'])==66 and causal['acceptance']is False,'exact staged export66 before retained DATA route, no invented publication')
 prior={n:C.read(root/n,4*1024**2)for n in causal['before']}
 for name,rules in causal['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact retained causal source inverse');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('closed_source_fixture_causal')==causal,'complete causal parent inverse');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in causal['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode()
 for name,before in(('PRODUCTS',causal['guard_products_before']),('SELF',causal['guard_self_before'])):
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one retained causal guard seal inverse');text=text.replace(after,before,1)
 C.need(text.count(causal['guard_prefix'])==1,'one retained causal guard prefix inverse');text=text.replace(causal['guard_prefix'],causal['guard_anchor'],1);prior['source622.py']=text.encode();C.need({n:C.pin(raw)for n,raw in prior.items()}==causal['before'],'whole exact staged export66 before all previous Source predicates')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('PRODUCTS','SELF')};C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all preceding export66 products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole preceding export66 selfseal')
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'bounded complete export66 inverse only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 causal=C.decode(C.read(root/'composition-parent.json',4*1024**2))['isolated_import_retention_causal']
 C.need(causal['schema']==1 and causal['parent_source']=='9fa6e0c290fbca14b94290ac087c3b40c749452e' and causal['actual']is None and causal['publication_parent']=='9fa6e0c290fbca14b94290ac087c3b40c749452e'and len(causal['before'])==66 and causal['acceptance']is False,'exact staged export66 before retained DATA route, no invented publication')
 prior={n:C.read(root/n,4*1024**2)for n in causal['before']}
 for name,rules in causal['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact retained causal source inverse');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('isolated_import_retention_causal')==causal,'complete causal parent inverse');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in causal['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode()
 for name,before in(('PRODUCTS',causal['guard_products_before']),('SELF',causal['guard_self_before'])):
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one retained causal guard seal inverse');text=text.replace(after,before,1)
 C.need(text.count(causal['guard_prefix'])==1,'one retained causal guard prefix inverse');text=text.replace(causal['guard_prefix'],causal['guard_anchor'],1);prior['source622.py']=text.encode();C.need({n:C.pin(raw)for n,raw in prior.items()}==causal['before'],'whole exact staged export66 before all previous Source predicates')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('PRODUCTS','SELF')};C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all preceding export66 products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole preceding export66 selfseal')
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'bounded complete export66 inverse only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 transport=C.decode(C.read(root/'composition-parent.json',4*1024**2))['retained_complete574_transport']
 C.need(transport['schema']==1 and transport['parent_source']is None and transport['actual']is None and transport['publication_parent']=='0d49642fbbf02aaea49339b3829e166b83b6f984'and len(transport['before'])==66 and transport['acceptance']is False,'exact staged export66 before retained DATA route, no invented publication')
 prior={n:C.read(root/n,4*1024**2)for n in transport['before']}
 for name,rules in transport['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact retained transport source inverse');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('retained_complete574_transport')==transport,'complete transport parent inverse');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in transport['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode()
 for name,before in(('PRODUCTS',transport['guard_products_before']),('SELF',transport['guard_self_before'])):
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one retained transport guard seal inverse');text=text.replace(after,before,1)
 C.need(text.count(transport['guard_prefix'])==1,'one retained transport guard prefix inverse');text=text.replace(transport['guard_prefix'],transport['guard_anchor'],1);prior['source622.py']=text.encode();C.need({n:C.pin(raw)for n,raw in prior.items()}==transport['before'],'whole exact staged export66 before all previous Source predicates')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('PRODUCTS','SELF')};C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all preceding export66 products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole preceding export66 selfseal')
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'bounded complete export66 inverse only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 current=C.decode(C.read(root/'composition-parent.json',4*1024**2))['current_root_export']
 C.need(current['schema']==1 and current['parent_source']=='0d49642fbbf02aaea49339b3829e166b83b6f984'and current['parent_ref']=='codex/core622-baseline180-source-control-v2'and current['actual']is None and current['normal90_acceptance']is current['functional_acceptance']is current['native_acceptance']is current['acceptance']is False and len(current['before'])==66,'exact current-root original-byte export successor without transferred admission')
 prior={n:C.read(root/n,4*1024**2)for n in current['before']}
 C.need(set(current['edits'])=={'provision622.py','ownership622.py','run622.py','evidence.py','test_bridge622.py'},'finite five source export/control bodies')
 for name,rules in current['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact current-root export inverse');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('current_root_export')==current,'whole current-root export inverse record');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in current['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode()
 for name,before in(('PRODUCTS',current['guard_products_before']),('SELF',current['guard_self_before'])):
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one current-root product/selfseal inverse');text=text.replace(after,before,1)
 C.need(text.count(current['guard_prefix'])==1,'one exact current-root export prefix');text=text.replace(current['guard_prefix'],current['guard_anchor'],1);prior['source622.py']=text.encode();C.need({n:C.pin(b)for n,b in prior.items()}==current['before'],'entire published accepted diagnostic66 inverse before all previous guards')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('PRODUCTS','SELF')};C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all preceding diagnostic products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole preceding diagnostic selfseal')
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'bounded complete immediate diagnostic66 projection only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 control=C.decode(C.read(root/'composition-parent.json',4*1024**2))['baseline180_source_control_fix']
 C.need(control['schema']==1 and control['parent_source']=='633b0bb9eea48911076428981147310b8f543b7d'and control['parent_ref']=='codex/core622-baseline180-diagnostic-v1'and control['actual']is None and control['normal90_acceptance']is False and len(control['before'])==66,'exact test-only baseline180 source-control successor')
 prior={n:C.read(root/n,4*1024**2)for n in control['before']}
 C.need(set(control['edits'])=={'test_bridge622.py'},'sole source-control test body delta')
 for name,rules in control['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact source-control test inverse');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('baseline180_source_control_fix')==control,'whole test-only inverse record');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in control['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode()
 for name,before in(('PRODUCTS',control['guard_products_before']),('SELF',control['guard_self_before'])):
  node=next(n for n in ast.parse(text).body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one exact test-only guard seal inverse');text=text.replace(after,before,1)
 C.need(text.count(control['guard_prefix'])==1,'one exact test-only Source prefix');text=text.replace(control['guard_prefix'],control['guard_anchor'],1);prior['source622.py']=text.encode();C.need({n:C.pin(b)for n,b in prior.items()}==control['before'],'entire published diagnostic66 inverse, all runtime and budgets held')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and isinstance(n.targets[0],ast.Name)and n.targets[0].id in('PRODUCTS','SELF')};C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all preceding diagnostic products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole preceding diagnostic selfseal')
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'bounded complete diagnostic66 projection only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 current=C.decode(C.read(root/'composition-parent.json',4*1024**2))['baseline_capacity_diagnostic']
 C.need(current['schema']==1 and current['parent_source']=='1ffcf37d3fa3b112b7c03cf3f3725e2edb813d83'and current['parent_ref']=='codex/core622-image-marker-fix-v2'and current['profile']=='TCG_BASELINE_TRANSACTION_180_DIAGNOSTIC'and current['normal90_acceptance']is False and current['actual']is None and len(current['before'])==66,'explicit diagnostic source, never normal90 admission')
 prior={n:C.read(root/n,4*1024**2)for n in current['before']}
 for name,rules in current['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one counted baseline diagnostic integration inverse');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('baseline_capacity_diagnostic')==current,'complete diagnostic inverse record');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in current['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode();tree=ast.parse(text)
 for name,before in(('PRODUCTS',current['guard_products_before']),('SELF',current['guard_self_before'])):
  node=next(n for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one diagnostic product/selfseal inverse');text=text.replace(after,before,1);tree=ast.parse(text)
 C.need(text.count(current['guard_prefix'])==1,'one baseline diagnostic guard prefix');text=text.replace(current['guard_prefix'],current['guard_anchor'],1);prior['source622.py']=text.encode()
 C.need({n:C.pin(b)for n,b in prior.items()}==current['before'],'entire original normal66 byte inverse before existing assertions')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id in('PRODUCTS','SELF')};C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all normal66 products held');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole original normal66 selfseal')
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'exact bounded normal66 projection only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 current=C.decode(C.read(root/'composition-parent.json',4*1024**2))['image_marker_serialization']
 C.need(current['schema']==1 and current['parent_source']=='1d5b473d784e9574d2053eae276f8dd8f9e390af'and current['parent_freeze']=={'bytes':62194,'sha256':'314d80b67a4f2f68c2fd5bb17127ce245364a8f69ad92dba26fcc507203ecb34'}and current['actual']is None and len(current['before'])==66,'whole exact published66 serialization predecessor')
 prior={n:C.read(root/n,4*1024**2)for n in current['before']}
 for name,rules in current['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one closed image-marker serialization inverse');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('image_marker_serialization')==current,'complete serialization inverse record');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in current['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode();tree=ast.parse(text)
 for name,before in(('PRODUCTS',current['guard_products_before']),('SELF',current['guard_self_before'])):
  node=next(n for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one serialization product/selfseal inverse');text=text.replace(after,before,1);tree=ast.parse(text)
 C.need(text.count(current['guard_prefix'])==1,'one serialization guard prefix');text=text.replace(current['guard_prefix'],current['guard_anchor'],1);prior['source622.py']=text.encode()
 C.need({n:C.pin(b)for n,b in prior.items()}==current['before'],'entire exact published66 inverse before all existing source assertions')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id in('PRODUCTS','SELF')}
 C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all published66 fixed products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole published66 selfseal')
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'exact bounded published66 projection only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 current=C.decode(C.read(root/'composition-parent.json',4*1024**2))['transaction_progress']
 C.need(current['schema']==1 and current['parent_source']is None and current['parent_packet']=={'bytes': 165489, 'sha256': '1a6d8dcf5ba1e6964ad25f964bcc5d558b604f68911ce5dde99fa438fce05f60'}and current['actual']is None and len(current['before'])==66,'whole exact publicfrozen-unpublished-cleanup before owned transaction diagnostic')
 prior={n:C.read(root/n,4*1024**2)for n in current['before']}
 for name,rules in current['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact source-local transaction diagnostic seam');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('transaction_progress')==current,'complete finite owned transaction diagnostic operand');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in current['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode();tree=ast.parse(text)
 for name,before in(('PRODUCTS',current['guard_products_before']),('SELF',current['guard_self_before'])):
  node=next(n for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one current transaction-diagnostic product/seal DATA inverse');text=text.replace(after,before,1);tree=ast.parse(text)
 C.need(text.count(current['guard_prefix'])==1,'one owned transaction-diagnostic source guard prefix inverse');text=text.replace(current['guard_prefix'],current['guard_anchor'],1);prior['source622.py']=text.encode()
 C.need({n:C.pin(b)for n,b in prior.items()}==current['before'],'entire source66 frozen-unpublished-cleanup inverse, no historical result authority')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id in('PRODUCTS','SELF')}
 C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all oldfrozen-unpublished-cleanup fixed source products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole oldfrozen-unpublished-cleanup selfseal')
 # The existingfrozen-unpublished-cleanup media contract inverse consumes this exact DATA projection.
 # Current verify and original51 guards keep the original module-global C.
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'exact boundedfrozen-unpublished-cleanup DATA projection only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 current=C.decode(C.read(root/'composition-parent.json',4*1024**2))['vm_observer_cleanup']
 C.need(current['schema']==1 and current['parent_source']=='ad09020a776c93fad3c2625c836a99cbde0c83b9'and current['actual']is None and len(current['before'])==66,'whole exact publicad09 before owned owned cleanup')
 prior={n:C.read(root/n,4*1024**2)for n in current['before']}
 for name,rules in current['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact source-local owned cleanup seam');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('vm_observer_cleanup')==current,'complete finite owned owned cleanup operand');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in current['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode();tree=ast.parse(text)
 for name,before in(('PRODUCTS',current['guard_products_before']),('SELF',current['guard_self_before'])):
  node=next(n for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one current owned-cleanup product/seal DATA inverse');text=text.replace(after,before,1);tree=ast.parse(text)
 C.need(text.count(current['guard_prefix'])==1,'one owned owned-cleanup source guard prefix inverse');text=text.replace(current['guard_prefix'],current['guard_anchor'],1);prior['source622.py']=text.encode()
 C.need({n:C.pin(b)for n,b in prior.items()}==current['before'],'entire source66 ad09 inverse, no historical result authority')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id in('PRODUCTS','SELF')}
 C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all oldad09 fixed source products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole oldad09 selfseal')
 # The existingad09 media contract inverse consumes this exact DATA projection.
 # Current verify and original51 guards keep the original module-global C.
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'exact boundedad09 DATA projection only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 current=C.decode(C.read(root/'composition-parent.json',4*1024**2))['media_contract_inflate']
 C.need(current['schema']==1 and current['parent_source']=='f46ac9e7aeec170ba554255e3cda380ea0364e64'and current['actual']is None and len(current['before'])==66,'whole exact publicf46 before owned media contract')
 prior={n:C.read(root/n,4*1024**2)for n in current['before']}
 for name,rules in current['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact source-local media contract seam');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('media_contract_inflate')==current,'complete finite owned media contract operand');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in current['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode();tree=ast.parse(text)
 for name,before in(('PRODUCTS',current['guard_products_before']),('SELF',current['guard_self_before'])):
  node=next(n for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one current media-contract product/seal DATA inverse');text=text.replace(after,before,1);tree=ast.parse(text)
 C.need(text.count(current['guard_prefix'])==1,'one owned media-contract source guard prefix inverse');text=text.replace(current['guard_prefix'],current['guard_anchor'],1);prior['source622.py']=text.encode()
 C.need({n:C.pin(b)for n,b in prior.items()}==current['before'],'entire source66 f46 inverse, no historical result authority')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id in('PRODUCTS','SELF')}
 C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all oldf46 fixed source products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole oldf46 selfseal')
 # The existingf46 initialization inverse consumes this exact DATA projection.
 # Current verify and original51 guards keep the original module-global C.
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'exact boundedf46 DATA projection only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 current=C.decode(C.read(root/'composition-parent.json',4*1024**2))['owned_proof_output']
 C.need(current['schema']==1 and current['parent_source']=='358afcba2c1364b8954d753a631d001328367ee7'and current['actual']is None and len(current['before'])==66,'whole exact public358 before owned proof output')
 prior={n:C.read(root/n,4*1024**2)for n in current['before']}
 for name,rules in current['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact source-local proof output seam');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('owned_proof_output')==current,'complete finite owned proof output operand');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in current['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode();tree=ast.parse(text)
 for name,before in(('PRODUCTS',current['guard_products_before']),('SELF',current['guard_self_before'])):
  node=next(n for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one current proof-output product/seal DATA inverse');text=text.replace(after,before,1);tree=ast.parse(text)
 C.need(text.count(current['guard_prefix'])==1,'one owned proof-output source guard prefix inverse');text=text.replace(current['guard_prefix'],current['guard_anchor'],1);prior['source622.py']=text.encode()
 C.need({n:C.pin(b)for n,b in prior.items()}==current['before'],'entire source66 358 inverse, no historical result authority')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id in('PRODUCTS','SELF')}
 C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all old358 fixed source products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole old358 selfseal')
 # The existing358 initialization inverse consumes this exact DATA projection.
 # Current verify and original51 guards keep the original module-global C.
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'exact bounded358 DATA projection only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 current=C.decode(C.read(root/'composition-parent.json',4*1024**2))['owned_auxiliary_initialization']
 C.need(current['schema']==1 and current['parent_source']=='b7b1a04c1bc0172f2af271546641aa374569c898'and current['actual']is None and len(current['before'])==66,'whole exact publicb7 before owned auxiliary initialization')
 prior={n:C.read(root/n,4*1024**2)for n in current['before']}
 for name,rules in current['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact source-local owned initialization seam');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('owned_auxiliary_initialization')==current,'complete finite owned auxiliary initialization operand');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in current['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode();tree=ast.parse(text)
 for name,before in(('PRODUCTS',current['guard_products_before']),('SELF',current['guard_self_before'])):
  node=next(n for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one current auxiliary product/seal DATA inverse');text=text.replace(after,before,1);tree=ast.parse(text)
 C.need(text.count(current['guard_prefix'])==1,'one live auxiliary source guard prefix inverse');text=text.replace(current['guard_prefix'],current['guard_anchor'],1);prior['source622.py']=text.encode()
 C.need({n:C.pin(b)for n,b in prior.items()}==current['before'],'entire source66 b7 inverse, no historical result authority')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id in('PRODUCTS','SELF')}
 C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all oldb7 fixed source products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole oldb7 selfseal')
 # The existing b7 capability inverse consumes this exact DATA projection.
 # Current verify and original51 guards keep the original module-global C.
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'exact boundedb7 DATA projection only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 current=C.decode(C.read(root/'composition-parent.json',4*1024**2))['live_auxiliary']
 C.need(current['schema']==1 and current['parent_source']=='333f9b0a3f11bc2180557f7e9feedfa2f2359b98'and current['actual']is None and len(current['before'])==66,'whole exact public333f before live auxiliary diagnostic')
 prior={n:C.read(root/n,4*1024**2)for n in current['before']}
 for name,rules in current['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact source-local auxiliary diagnostic seam');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('live_auxiliary')==current,'complete finite live auxiliary diagnostic operand');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in current['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode();tree=ast.parse(text)
 for name,before in(('PRODUCTS',current['guard_products_before']),('SELF',current['guard_self_before'])):
  node=next(n for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one current auxiliary product/seal DATA inverse');text=text.replace(after,before,1);tree=ast.parse(text)
 C.need(text.count(current['guard_prefix'])==1,'one live auxiliary source guard prefix inverse');text=text.replace(current['guard_prefix'],current['guard_anchor'],1);prior['source622.py']=text.encode()
 C.need({n:C.pin(b)for n,b in prior.items()}==current['before'],'entire source66 333f inverse, no historical result authority')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id in('PRODUCTS','SELF')}
 C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all old333f fixed source products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole old333f selfseal')
 # The existing 333f capability inverse consumes this exact DATA projection.
 # Current verify and original51 guards keep the original module-global C.
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'exact bounded333f DATA projection only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 current=C.decode(C.read(root/'composition-parent.json',4*1024**2))['capability_boundary']
 C.need(current['schema']==1 and current['parent_source']=='09775710e2ad55d647993eab81890f1696572c86'and current['actual']is None and len(current['before'])==66,'whole exact public66 before capability anchor correction')
 prior={n:C.read(root/n,4*1024**2)for n in current['before']}
 for name,rules in current['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact whole exact capability derivation anchor');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('capability_boundary')==current,'complete finite capability anchor operand');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in current['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode();tree=ast.parse(text)
 for name,before in(('PRODUCTS',current['guard_products_before']),('SELF',current['guard_self_before'])):
  node=next(n for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one current product/seal DATA inverse');text=text.replace(after,before,1);tree=ast.parse(text)
 C.need(text.count(current['guard_prefix'])==1,'one existing source guard prefix inverse');text=text.replace(current['guard_prefix'],current['guard_anchor'],1);prior['source622.py']=text.encode()
 C.need({n:C.pin(b)for n,b in prior.items()}==current['before'],'entire source66 097757 inverse, no historical result authority')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id in('PRODUCTS','SELF')}
 C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all old 097757 fixed source products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole old 097757 selfseal')
 # The unchanged existing66→ae39 inverse below consumes this EXACT 097757 DATA
 # namespace. Current verify and original51 guard still use original global C.
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'exact bounded immediate source DATA projection only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 current=C.decode(C.read(root/'composition-parent.json',4*1024**2))['apparmor_environment']
 C.need(current['schema']==1 and current['parent_source']=='bbdf05888b8bacb8a7ee8dfde4def4d508cc812b'and current['actual']is None and len(current['before'])==66,'whole exact public66 before CI environment correction')
 prior={n:C.read(root/n,4*1024**2)for n in current['before']}
 for name,rules in current['edits'].items():
  text=prior[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one exact selected sanitized CI caller flag');text=text.replace(after,before,1)
  prior[name]=text.encode()
 parent=C.decode(prior['composition-parent.json']);C.need(parent.pop('apparmor_environment')==current,'complete finite CI environment operand');prior['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(prior['source-manifest.json']);manifest['files']={n:w for n,w in current['before'].items()if n not in('source-manifest.json',*ALIASES)};prior['source-manifest.json']=C.encoded(manifest)
 text=prior['source622.py'].decode();tree=ast.parse(text)
 for name,before in(('PRODUCTS',current['guard_products_before']),('SELF',current['guard_self_before'])):
  node=next(n for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one current product/seal DATA inverse');text=text.replace(after,before,1);tree=ast.parse(text)
 C.need(text.count(current['guard_prefix'])==1,'one existing source guard prefix inverse');text=text.replace(current['guard_prefix'],'',1);prior['source622.py']=text.encode()
 C.need({n:C.pin(b)for n,b in prior.items()}==current['before'],'entire source66 bbdf inverse, no historical result authority')
 tree=ast.parse(text);sealed={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id in('PRODUCTS','SELF')}
 C.need(all(C.pin(prior[n])==w for n,w in sealed['PRODUCTS'].items()),'all old bbdf fixed source products');seal=sealed['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole old bbdf selfseal')
 # The unchanged existing66→ae39 inverse below consumes this EXACT bbdf DATA
 # namespace. Current verify and original51 guard still use original global C.
 def prior_read(path,maximum=1024**2):
  name=Path(path).relative_to(root).as_posix();C.need(name in prior and len(prior[name])<=maximum,'exact bounded immediate source DATA projection only');return prior[name]
 C=__import__('types').SimpleNamespace(**dict(vars(C),read=prior_read))
 record=C.decode(C.read(root/'composition-parent.json',4*1024**2))['isolated_cache_import'];C.need(record['schema']==1 and record['parent_source']=='ae39c1ba4c613d6a86e5582c2ab4c2d5495b2bd7'and record['actual']is None and len(record['before'])==66,'exact isolated-cache source predecessor')
 out={n:C.read(root/n,4*1024**2)for n in record['before']}
 for name,rules in record['edits'].items():
  text=out[name].decode()
  for before,after in reversed(rules):C.need(text.count(after)==1,'one complete cache-import/CI-control inverse');text=text.replace(after,before,1)
  out[name]=text.encode()
 parent=C.decode(out['composition-parent.json']);C.need(parent.pop('isolated_cache_import')==record,'exact immediate source context operand');out['composition-parent.json']=C.encoded(parent)
 manifest=C.decode(out['source-manifest.json']);manifest['files']={n:w for n,w in record['before'].items()if n not in('source-manifest.json',*ALIASES)};out['source-manifest.json']=C.encoded(manifest)
 text=out['source622.py'].decode();tree=ast.parse(text)
 for name,before in(('PRODUCTS',record['guard_products_before']),('SELF',record['guard_self_before'])):
  node=next(n for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id==name);after=ast.get_source_segment(text,node);C.need(text.count(after)==1,'one exact current sourceguard DATA/seal');text=text.replace(after,before,1);tree=ast.parse(text)
 for before,after in reversed(record['guard_edits']):C.need(text.count(after)==1,'one whole immediate sourceguard inverse');text=text.replace(after,before,1)
 out['source622.py']=text.encode();C.need({n:C.pin(b)for n,b in out.items()}==record['before'],'all66 immediate source bytes reconstructed')
 tree=ast.parse(text);values={n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id in('PRODUCTS','SELF')};C.need(all(C.pin(out[n])==w for n,w in values['PRODUCTS'].items()),'all original66 fixed products held');seal=values['SELF'];C.need(text.count(seal)==1 and hashlib.sha256(text.replace(seal,'@SELF@').encode()).hexdigest()==seal,'whole original66 sourceguard selfseal held');return out

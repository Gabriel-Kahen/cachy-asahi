# SPDX-License-Identifier: MIT
"""Explicit exact Apps16 composition source849; old profiles and actors held."""
import ast,base64,importlib.util,json,os
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_apps16_prior_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
PROFILE={'bytes':517563,'sha256':'27f4b9f1930736b50e61bfab947a38dae32df22947d73104d510f9019294c3c3'}
I='latest/implementation/';MF='latest/source-manifest.json';GUARD=I+'latest_guard.py';PROOF=I+'apps16-successor.json';RUN=I+'latest_run.py';WFS=('.github/workflows/native-arm-current607-latest-tools.yml','.github/workflows/native-arm-build.yml');MARKER='\n# BEGIN_EXACT_APPS16_SIX_TOOL_SUCCESSOR\n'
pin,need=F.pin,F.need

def normalized(path):
 path=F.ordinary(path);F.need(path==path.resolve(),'canonical normalized input/output');return path

def closed(root,wanted):
 root=normalized(root);actual=F.files(root);expected={''}
 for n in wanted:expected.update(''if q==Path('.')else q.as_posix()for q in Path(n).parents)
 dirs={''}|{p.relative_to(root).as_posix()for p in root.rglob('*')if p.is_dir()and p.relative_to(root).parts[0]!='.git'}
 F.need(actual==wanted and dirs==expected,'whole closed source/input/support and directory membership');return{n:F.read(root/n)for n in wanted}

def inputs():
 F.need(not __import__('sys').flags.optimize,'optimized source guards refused');raw=F.read(HERE/'apps16-849-profile.json');F.need(F.pin(raw)==PROFILE,'whole hardpinned Apps16 profile');p=json.loads(raw);F.need(p['profile']=='apps16_849'and p['actual']is None and p['source_before']=='8b22845252d01e1a813ed078be60315a39a27a5f'and p['source_after']=='c64cee1167d2ff81f1de0128f57c275819e32868','exact source identities');raw=F.read(HERE/'apps16-849-maps.json');F.need(F.pin(raw)==p['maps'],'whole source maps');maps=json.loads(raw);F.need({n:len(v)for n,v in maps.items()}==dict(before=842,selected=849,unbound=849),'whole842/849 source variants');payload=closed(HERE/'apps16-849',p['payload']);F.need(p['proof']['before']==maps['before']and p['passive_caps']==dict(source=300,strict=900,collector=900,separate_current606=300),'exact inverse and distinct passive composition/input caps');return p,maps,payload

def footer(name,want):
 return "def verify():\n import apps16_successor\n return apps16_successor.verify(ROOT, "+repr(name)+', '+repr(want)+")\n\n_before_apps16_authorize=authorize\ndef authorize():\n import apps16_inputs\n apps16_inputs.qualification()\n return _before_apps16_authorize()\n"

def workflow(text,profiles):
 marker='      - name: Checkout exact accepted Apps8 additional product DATA\n';blocks=''
 for role,row in profiles.items():blocks+='      - name: Checkout exact Apps16 '+role+' public input DATA\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: '+row['source']+'\n          path: latest607-next-'+role+'-inputs\n          persist-credentials: false\n'
 need(text.count(marker)==1,'one held Apps8 checkout marker');text=text.replace(marker,blocks+marker,1)
 anchor='--apps10qualification-packet "$GITHUB_WORKSPACE/latest607-next-apps10qualification-inputs"';need(text.count(anchor)==2,'both original input/owner argument routes');extra=' '.join('--'+role+'-packet "$GITHUB_WORKSPACE/latest607-next-'+role+'-inputs"'for role in profiles);text=text.replace(anchor,anchor+' '+extra)
 command='LATEST607_APPS8_TEST_PACKET="$GITHUB_WORKSPACE/latest607-apps8-inputs" python3 -I -B expanded604-code/next/test_source.py';need(text.count(command)==1,'one original emitted test command');return text.replace(command,'APPS16_COMPOSITION_TEST_CARRIER="$GITHUB_WORKSPACE/latest607-next-apps16-inputs" APPS16_COMPOSITION_TEST_RECORD="$GITHUB_WORKSPACE/latest607-next-apps16qualification-inputs" APPS16_COMPOSITION_TEST_CURRENT606_RECORD="$GITHUB_WORKSPACE/latest607-next-apps16current606qualification-inputs" '+command,1)

def render(source,carrier,record,current606_record,null=False):
 F.need(type(null)is bool,'literal NULL choice');p,maps,payload=inputs();source=normalized(source);packets=dict(apps16=carrier,apps16qualification=record,apps16current606qualification=current606_record);F.need(all(v is not None for v in packets.values()),'explicit complete94/22/16 inputs required');packets={n:normalized(v)for n,v in packets.items()};profiles=json.loads(payload['apps16-null-inputs.json'if null else'apps16-inputs.json']);F.need([len(profiles['profiles'][n]['files'])for n in packets]==[94,22,16],'complete94/22/16 physical inputs')
 for role,root in packets.items():closed(root,profiles['profiles'][role]['files'])
 before=closed(source,maps['before']);bodies=dict(before);proof=dict(p['proof']);edits=proof['edits']
 for n,changes in edits.items():
  text=bodies[n].decode()
  for a,b in changes:F.need(text.count(a)==1,'one explicit Apps16 source seam '+n);text=text.replace(a,b,1)
  bodies[n]=text.encode()
 for n,src in [(I+'apps16_inputs.py','apps16_inputs.py'),(I+'apps16_successor.py','apps16_successor.py'),(I+'apps16-inputs.json','apps16-null-inputs.json'if null else'apps16-inputs.json'),(I+'apps16-source/apps.py','apps.py'),(I+'apps16-source/inventory.py','inventory.py'),('next/tests/test_apps16.py','test_emitted.py')]:bodies[n]=payload[src]
 changed={*edits,GUARD,MF,*WFS};added={n for n in bodies if n not in maps['before']}|{PROOF};proof['before_bodies']={n:base64.b64encode(before[n]).decode()for n in sorted(changed)};proof['helpers']={n:F.pin(bodies[n])for n in sorted((set(edits)|added)-{PROOF})};F.need(proof['added']==sorted(added),'exact seven added members');bodies[PROOF]=F.encoded(proof);bodies[GUARD]+=MARKER.encode()+footer(PROOF,F.pin(bodies[PROOF])).encode();mf=json.loads(bodies[MF]);mf['files']={n:F.pin(b)for n,b in bodies.items()if n not in{MF,*WFS}};bodies[MF]=F.encoded(mf)
 for n in WFS:
  text=bodies[n]
  for leaf in(MF,RUN):F.need(text.count(maps['before'][leaf]['sha256'].encode())==1,'one held workflow stamp');text=text.replace(maps['before'][leaf]['sha256'].encode(),F.pin(bodies[leaf])['sha256'].encode(),1)
  bodies[n]=workflow(text.decode(),profiles['profiles']).encode()
 expected=maps['unbound'if null else'selected'];F.need({n:F.pin(b)for n,b in bodies.items()}==expected,'whole exact849 before writes');F.need(len(changed)==10 and len(added)==7 and sum(expected.get(n)==w for n,w in maps['before'].items())==832,'whole832 held/10 changed/7 added inverse')
 for n,b in bodies.items():
  if n.endswith('.py'):ast.parse(b,filename=n)
 closed(source,maps['before'])
 for role,root in packets.items():closed(root,profiles['profiles'][role]['files'])
 F.need(inputs()==(p,maps,payload),'fresh whole operands revalidation');return bodies,p,maps

def emit(source,output,authorization,carrier,record,current606_record,null=False):
 source,output,authorization=map(normalized,(source,output,authorization));F.need(not os.path.lexists(output)and not os.path.lexists(authorization)and output.parent.is_dir()and authorization.parent.is_dir(),'fresh ordinary source and authorization');roots=[source,HERE]
 for inputroot in(carrier,record,current606_record):
  F.need(inputroot is not None,'explicit complete94/22/16 inputs required');roots.append(normalized(inputroot))
 for target in(output,authorization):
  for root in roots:F.need(not target.is_relative_to(root)and not root.is_relative_to(target),'disjoint input/factory/output/authorization')
 F.need(not authorization.is_relative_to(output)and not output.is_relative_to(authorization),'source/authorization disjoint');bodies,p,maps=render(source,carrier,record,current606_record,null);output.mkdir(mode=0o700)
 for n,b in sorted(bodies.items()):
  q=output/n;q.parent.mkdir(parents=True,exist_ok=True)
  with q.open('xb')as stream:stream.write(b)
 expected=maps['unbound'if null else'selected'];closed(output,expected);return dict(status='SOURCE_ONLY_EXACT849_APPS16_WITH_WHOLE_ACCEPTED842',files=expected,expected_fixture_source=p['source_after'],source=None,ref=None,actual=None,null_selection=null,native='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')

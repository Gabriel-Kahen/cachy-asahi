# SPDX-License-Identifier: MIT
"""Finite current607 root handoff into unchanged Core two-boot mechanisms."""
import inspect,json,os,sys,time,types
from pathlib import Path
import case as C,adapter,desktop622 as X

def replace(raw,old,new,count=1):
 C.need(raw.count(old)==count,'counted whole runtime source seam');out=raw.replace(old,new);C.need(out.replace(new,old)==raw,'whole runtime body inverse');return out

def assembly(original,args,report,command,deadline):
 body=inspect.getsource(original.assembly);body=replace(body,"for source,target in((HERE,'/runner'),(args.workspace,'/runtime'),", "for source,target in((args.case_source,'/core622'),(args.core_source,'/core-source'),(HERE,'/runner'),(args.workspace,'/runtime'),")
 body=replace(body,"'/runner/assemble.py'","'/core622/assembly622.py'");namespace=dict(vars(original));exec(compile(body,'whole-original-Core-assembly-with-current607-catalog','exec'),namespace);return namespace['assembly'](args,report,command,deadline)

def provision(args,report,command,deadline):
 import controller
 work=args.output/'vm-work';work.mkdir(mode=0o700);controller.prepare_work(args,work);public=args.output/'current607-public';public.mkdir(mode=0o700);args.provision_public=public
 end=min(deadline,time.monotonic()+C.BUDGET['media']);args.provision_deadline=end
 args._owner_report=report
 report['current607_actor']=controller.actor(args,command,work,args.output/'data','provision607');record=C.decode(C.read(public/'current607-formation.json',4*1024**2));C.need(record['status']=='PASS_COMPLETE607_SIGNED_PROVISIONING_GRAPH_DB_CAPS_AND_PRESERVATION'and record['nonce']==args.selected['nonce']and record['packages']==607,'actual complete607 formation, not a count/path projection')
 caps=C.decode(C.read(public/'current607-capabilities.json',4*1024**2));graph=C.decode(C.inflate(C.read(public/'current607-root.json.gz',64*1024**2)));db=C.decode(C.read(public/'current607-database.json',16*1024**2));plan=C.decode(C.read(args.case_source/'composition.json',4*1024**2));C.need({r['name']:r['version']for r in db}==plan['before607']and X.plan(plan)[0]==plan['before607'],'actual complete607 database and fixed current scope')
 import hashlib
 C.need(record['graph_nodes_sha256']==hashlib.sha256(json.dumps(graph['nodes'],sort_keys=True).encode()).hexdigest()and record['capabilities_sha256']==adapter.core(args.core_source).api['capabilities'].digest(caps),'complete actual node/capability source bindings');report['current607_snapshot']=dict(observation=dict(security_capabilities=caps,source_capabilities_sha256=record['capabilities_sha256'],node_sha256=record['graph_nodes_sha256']),formation=record)
 (args.output/'owner.json').write_bytes(C.encoded(report))

def binding(original,args,report):
 body=inspect.getsource(original.binding);body=replace(body,"report['source_snapshot']","report['current607_snapshot']",3);namespace=dict(vars(original),LOCK=X.plan(C.decode(C.read(args.case_source/'composition.json',4*1024**2)))and C.decode(C.read(args.case_source/'composition.json',4*1024**2))['fresh607']['sha256']);exec(compile(body,'whole-original-Core-binding-with-actual607-observation','exec'),namespace);return namespace['binding'](args,report)

def actor_text(body):
 body=replace(body,"role in('prepare','scrub','export')","role in('prepare','scrub','export','provision607','retire607')")
 body=replace(body," for dest,path in bindings.items():", " if role in('provision607','retire607'):\n  bindings.update({'/current607-inputs':args.current607_inputs,'/fresh607-source':args.fresh607_source,'/current607-code':args.current607_code,'/baseline-cache':args.base/'context/deps'})\n  bindings['/out']=args.provision_public\n elif role=='prepare':bindings.update({'/current607-root':args.output/'data/current607','/current607-proof':args.output/'current607-public'})\n for dest,path in bindings.items():")
 body=replace(body,"cmd+=['--mount','type=bind,src='+str(media)+',dst=/measurement'", "cmd+=['--env=CAA_CORE622_PHASE_END='+str(args.provision_deadline if role=='provision607'else args.retirement_deadline if role=='retire607'else 0),'--mount','type=bind,src='+str(media)+',dst=/measurement'")
 body=replace(body,"image,'-I','-B','/workspace/media.py',role]", "image,'-I','-B','/workspace/provision622.py'if role in('provision607','retire607')else'/workspace/media.py',role]")
 body=replace(body,"1900 if role=='prepare'else 120", "min(1900,max(.001,args.provision_deadline-time.monotonic()))if role=='provision607'else min(60,max(.001,args.retirement_deadline-time.monotonic()))if role=='retire607'else 1900 if role=='prepare'else 120")
 return body

def media_text(text):
 """Only the actual media prepare function changes its observed copy source."""
 import ast
 tree=ast.parse(text);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='prepare');lines=text.splitlines(keepends=True);before=''.join(lines[node.lineno-1:node.end_lineno]);count=before.count("Path('/')");C.need(count==7,'exact seven original source-root observations/copy operands');after=before.replace("Path('/')","Path('/current607-root')")
 anchor=" before,_=scope.source_manifest(Path('/current607-root'),budget,roots,policy)"
 addition=anchor+"\n proof=C.decode(C.read('/current607-proof/current607-formation.json',4*1024**2));actual=C.decode(C.inflate(C.read('/current607-proof/current607-root.json.gz',64*1024**2)));__import__('provision622').readonly(Path('/current607-root'),proof['root_identity']);C.need(proof['nonce']==s['nonce']and proof['status']=='PASS_COMPLETE607_SIGNED_PROVISIONING_GRAPH_DB_CAPS_AND_PRESERVATION'and before==actual['nodes'],'actual607 graph bound before full media copy')"
 first=(anchor,addition);after=replace(after,*first)
 anchor=" copy=copier.copy_data(Path('/current607-root')"
 addition=" C.need(mapping==C.decode(C.read('/current607-proof/current607-capabilities.json',4*1024**2)),'whole actual607 capability map bound before media copy')\n"+anchor
 second=(anchor,addition);after=replace(after,*second);inverse=after
 for old,new in (second,first):inverse=inverse.replace(new,old)
 C.need(inverse.replace("Path('/current607-root')","Path('/')")==before,'whole media prepare inverse')
 lines[node.lineno-1:node.end_lineno]=[after];return ''.join(lines)

def owner_text(text):
 text=replace(text,'deadline=time.monotonic()+14400','deadline=min(time.monotonic()+14400,args.outer_deadline)')
 return replace(text,"   index=binding(args,report)","   PROVISION607(args,report,command,deadline)\n   index=binding(args,report)")

def retire(args,report,command,end):
 import controller
 root=args.output/'data/current607'
 if not root.exists():
  C.need(not(args.output/'data/current607-lease.json').exists(),'unidentified/partial607 root kept for diagnosis');return
 args.retirement_deadline=end;args._owner_report=report;args.provision_public=args.output/'current607-public';controller.actor(args,command,args.output/'vm-work',args.output/'data','retire607');C.need(not root.exists(),'fresh independently checked owned607 root absence')

def old_cleanup(original,args):
 """The original cleanup body imports its exact original entry, then restores it."""
 path=args.core_source/'scripts/ci/core-native-lifecycle/entry.py';entry=C.load('_core622_original800_cleanup_entry',path);C.need(Path(entry.__file__).resolve()==path.resolve()and entry.C.HERE.resolve()==path.parent.resolve(),'exact original800 cleanup/source-guard namespace');missing=object();prior=sys.modules.get('entry',missing);sys.modules['entry']=entry
 try:return original.cleanup(args)
 finally:
  if prior is missing:sys.modules.pop('entry',None)
  else:sys.modules['entry']=prior

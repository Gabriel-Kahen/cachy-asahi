#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable exact43/44 DATA fixtures only; no actor, network or heavy reader."""
import argparse,ast,contextlib,copy,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--parent',type=Path,required=True);p.add_argument('--expected',type=Path,required=True);args,rest=p.parse_known_args();PARENT=args.parent.resolve();EXPECTED=args.expected.resolve()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
F=load('_maintained_journal44_factory',HERE/'prepare.py')
def command(args):return subprocess.run([sys.executable,'-I','-B','-Werror',*map(str,args)],capture_output=True,cwd='/',timeout=30)
@contextlib.contextmanager
def emitted_namespace(root):
 saved=dict(sys.modules);paths=sys.path[:]
 try:
  sys.path.insert(0,str(root))
  for path in root.glob('*.py'):sys.modules.pop(path.stem,None)
  yield
 finally:
  sys.path[:]=paths
  for name in set(sys.modules)-set(saved):sys.modules.pop(name,None)
  sys.modules.update(saved)
class Factory(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temp.cleanup);cls.root=Path(cls.temp.name);cls.p,cls.bodies=F.journal_acl1200_inputs(PARENT);cls.runtime=cls.root/'runtime';F.emit_journal_acl1200(PARENT,cls.runtime)
 def test_entire_published44_known_NULL_sources_and_receipts(self):
  self.assertEqual(F.source(EXPECTED,self.p['result']['files']),self.bodies)
  for null in(False,True):
   out=self.root/('mode'+str(null));receipt=self.root/('mode'+str(null)+'.json');result=F.emit_journal_acl1200(PARENT,out,null,receipt);self.assertEqual(F.source(out,self.p['result']['files']),self.bodies);self.assertEqual(json.loads(receipt.read_bytes()),result);self.assertEqual(result['source'],None if null else self.p['result']['source']);self.assertEqual(result['context_source'],None if null else self.p['parent']['source']);self.assertIsNone(result['actual']);self.assertIsNone(result['run']);self.assertFalse(result['acceptance'])
 def test_real_isolated_factory_and_full_emitted_source_entries(self):
  for null in(False,True):
   flag='--journal-acl1200-unbound'if null else'--journal-acl1200';base=[HERE/'prepare.py',flag,'--predecessor-root',PARENT];v=command([*base,'--source-only']);self.assertEqual((v.returncode,v.stderr),(0,b''));self.assertEqual(json.loads(v.stdout)['old600fit'],'NOT_ESTABLISHED');out=self.root/('cli'+str(null));receipt=self.root/('cli'+str(null)+'.json');v=command([*base,'--output',out,'--authorization',receipt]);self.assertEqual((v.returncode,v.stderr),(0,b''));self.assertEqual(json.loads(v.stdout),json.loads(receipt.read_bytes()));self.assertEqual(F.source(out,self.p['result']['files']),self.bodies)
   v=command([out/'entry.py','source']);self.assertEqual((v.returncode,v.stderr),(0,b''));facts=json.loads(v.stdout);self.assertEqual(facts['files'],44);self.assertIsNone(facts['actual']);self.assertEqual(facts['vm_validation_profile']['graph_seconds'],1200)
   with emitted_namespace(out):
    J=__import__('journal_acl');self.assertEqual(J.prove(out)['ancestor_files'],[42,41,41,40,39]);self.assertEqual(J.inverse(self.bodies),F.source(PARENT,self.p['parent']['files']))
 def test_all_ten_old_routes_defaults_functions_and_whole_main_held(self):
  routes=[F.inputs,F.virtio20_inputs,F.rollback_inputs,lambda:F.host_clock_inputs(False),lambda:F.host_clock_inputs(True),F.module_index_inputs,F.gzip1_inputs,F.fresh_graph_inputs,F.tpm_acl_inputs,F.observer_inputs]
  for route in routes:
   p,bodies=route();wanted=p['stages']['41']['after']if'stages'in p else p['after']if'after'in p else p['result']['files'];self.assertEqual({n:F.pin(b)for n,b in bodies.items()},wanted)
  value=command([HERE/'prepare.py','--source-only']);self.assertEqual((value.returncode,value.stderr),(0,b''));self.assertEqual(json.loads(value.stdout),F.result(F.inputs()[0]));text=(HERE/'prepare.py').read_text();tree=ast.parse(text);functions={n.name:F.pin(ast.get_source_segment(text,n).encode())for n in tree.body if isinstance(n,ast.FunctionDef)}
  for n,w in self.p['held_factory_functions'].items():self.assertEqual(functions[n],w)
  main=ast.get_source_segment(text,next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main'))
  for before,after in reversed(self.p['main_edits']):self.assertEqual(main.count(after),1);main=main.replace(after,before,1)
  self.assertEqual(F.pin(main.encode()),self.p['old_main'])
 def test_canonical_paths_receipt_overlap_modes_and_conflicting_routes(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'alias').symlink_to(root,target_is_directory=True)
   for output,receipt in((root/'alias/new',None),(root/'missing/../new',None),(HERE/'new',None),(PARENT/'new',None),(root/'new',root/'new/receipt'),(root/'new',HERE/'receipt'),(root/'new',PARENT/'receipt'),(root/'new',root/'alias/receipt')):
    with self.assertRaises(ValueError):F.emit_journal_acl1200(PARENT,output,False,receipt)
    self.assertFalse((root/'new').exists())
   for value in(None,0,1,'NULL'):
    with self.assertRaises(ValueError):F.emit_journal_acl1200(PARENT,root/'new',value)
   for flag in('--journal-acl1200-unbound','--unbound','--observer-efficient','--tpm-default-acl','--fresh-graph','--gzip1','--module-indexes','--host-clock','--virtio20','--automatic-rollback'):
    v=command([HERE/'prepare.py','--journal-acl1200',flag,'--predecessor-root',PARENT,'--output',root/'new']);self.assertNotEqual(v.returncode,0);self.assertFalse((root/'new').exists())
   for options in(('--journal-acl1200','--source-only'),('--source-only','--predecessor-root',PARENT)):
    v=command([HERE/'prepare.py',*options]);self.assertNotEqual(v.returncode,0)
 def test_wrong_substrate_payload_profile_helper_and_live_late_drift_refuse_prewrite(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);parent=root/'parent';shutil.copytree(PARENT,parent,ignore=shutil.ignore_patterns('.git'));out=root/'never'
   for name in('journal_acl1200.py','journal-acl1200-profile.json',*('journal-acl1200-payload/'+n for n in self.p['payload'])):
    leaf=factory/name;old=leaf.read_bytes();leaf.write_bytes(old+b'changed');v=command([factory/'prepare.py','--journal-acl1200','--predecessor-root',parent,'--output',out]);self.assertNotEqual(v.returncode,0);self.assertFalse(out.exists());leaf.write_bytes(old)
   leaf=parent/'guest.py';old=leaf.read_bytes();leaf.write_bytes(old+b'changed');v=command([factory/'prepare.py','--journal-acl1200','--predecessor-root',parent,'--output',out]);self.assertNotEqual(v.returncode,0);self.assertFalse(out.exists());leaf.write_bytes(old)
   G=load('_late_journal_factory',factory/'prepare.py');read_source=G.source;visits=0
   def late_source(path,wanted,*rest):
    nonlocal visits
    if Path(path)==parent:
     visits+=1
     if visits==2:(parent/'guest.py').write_bytes(old+b'late source drift')
    return read_source(path,wanted,*rest)
   with patch.dict(G.__dict__,source=late_source),self.assertRaises(ValueError):G.emit_journal_acl1200(parent,out)
   self.assertEqual(visits,2);self.assertFalse(out.exists());leaf.write_bytes(old)
   G=load('_late_journal_support',factory/'prepare.py');original_read=G.read;visits=0;payload=factory/'journal-acl1200-payload/runtime.py.in'
   def late_read(path,*rest):
    nonlocal visits
    if Path(path)==factory/'journal-acl1200-profile.json':
     visits+=1
     if visits==2:payload.write_bytes(payload.read_bytes()+b'late operand drift')
    return original_read(path,*rest)
   with patch.dict(G.__dict__,read=late_read),self.assertRaises(ValueError):G.emit_journal_acl1200(parent,out)
   self.assertEqual(visits,2);self.assertFalse(out.exists())
 def test_real_kernel_exact_journal_bytes_TPM_parser_and_closed_runtime_graph_guards(self):
  with emitted_namespace(self.runtime):
   A=__import__('acl_policy');J=__import__('journal_acl');node={n:dict(type='file',mode=0o644,uid=0,gid=0,**F.pin(raw))for n,raw in dict(A.DECLARATIONS,**J.DECLARATIONS).items()};node[A.PATH]=dict(type='directory',mode=0o2775,uid=972,gid=972);node[J.PATH]=dict(type='directory',mode=0o2755,uid=0,gid=981)
   for n in('etc/passwd','etc/group'):node[n]=dict(type='file',mode=0o644,uid=0,gid=0,**F.pin(b'complete source-shaped DATA\n'))
   for label in A.LABELS:
    value=dict(complete=True,nodes=copy.deepcopy(node),security_capabilities={},posix_acl_defaults={}if label==A.LABELS[0]else{A.PATH:A.typed(A.expected()),J.PATH:J.typed(J.expected(),J.DEFAULT)},posix_acl_access={}if label==A.LABELS[0]else{J.PATH:J.typed(J.expected(),J.ACCESS)},mounts={},excluded=[]);self.assertTrue(A.check_graph(value,label))
    if label==A.LABELS[0]:continue
    for mutate in(lambda v:v.pop('posix_acl_access'),lambda v:v['posix_acl_access'].clear(),lambda v:v['posix_acl_defaults'].pop(J.PATH),lambda v:v['posix_acl_defaults'].pop(A.PATH),lambda v:v['nodes'][J.PATH].update(gid=982),lambda v:v['posix_acl_access'][J.PATH]['entries'][0].update(tag=True),lambda v:v['nodes'].update({J.PATH+'/child':dict(type='directory',mode=0o2755,uid=0,gid=981)})):
     bad=copy.deepcopy(value);mutate(bad)
     with self.assertRaises(ValueError):A.check_graph(bad,label)
   for parser,raw in((A.typed,A.expected()),(lambda raw:J.typed(raw,J.ACCESS),J.expected())):
    for i in range(len(raw)):
     changed=bytearray(raw);changed[i]^=1
     with self.assertRaises(ValueError):parser(bytes(changed))
   with tempfile.TemporaryDirectory()as td:
    root=Path(td);root.chmod(0o2755);fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
    try:
     for attr in(J.ACCESS,J.DEFAULT):os.setxattr(fd,attr,J.expected());self.assertEqual(J.typed(os.getxattr(fd,attr),attr),J.typed(J.expected(),attr))
     self.assertEqual(set(os.listxattr(fd)),{J.ACCESS,J.DEFAULT})
    finally:os.close(fd)
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)

"""Four exact profiles, emitted supervisor/timing and pre-output drift controls."""
import argparse,ast,importlib.util,json,shutil,subprocess,sys,tempfile,time,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent;parser=argparse.ArgumentParser();parser.add_argument('--source',type=Path,required=True);parser.add_argument('--expected',type=Path,required=True);args,rest=parser.parse_known_args();SOURCE,EXPECTED=args.source.absolute(),args.expected.absolute();spec=importlib.util.spec_from_file_location('_layered_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
class Controls(unittest.TestCase):
 def emit(self,root):
  out=root/'source';F.emit(SOURCE,out,'layered4200');return out
 def test_all_four_profiles_exact_and_historical_fit_not_reclassified(self):
  _,_,_,_,_,_,p563,_=F.inputs();_,p566,_=F.ancestry_inputs();_,p2400,_=F.correctness_inputs();_,layered,_=F.layered_inputs();self.assertEqual(layered,F.files(EXPECTED))
  with tempfile.TemporaryDirectory()as tmp:
   for i,(profile,wanted)in enumerate((('fresh_descriptor563',p563),('fresh_ancestry566',p566),('correctness2400',p2400),('layered4200',layered))):
    out=Path(tmp)/str(i);v=F.emit(SOURCE,out,profile);self.assertEqual(F.files(out),wanted);self.assertEqual(v['files'],wanted)
    if profile=='layered4200':self.assertEqual((v['consumer_seconds'],v['component_seconds'],v['owner_seconds']),(4200,2400,6600));self.assertEqual(v['original1800_fit'],v['original2400_fit']);self.assertEqual(v['original2400_fit'],'FAILED_NOT_RECLASSIFIED');self.assertEqual(v['performance'],'NOT_CLAIMED')
 def test_actual_isolated_cli_exact_complete_authorization(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);out,auth=root/'source',root/'auth.json';r=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--source',str(SOURCE),'--output',str(out),'--authorization',str(auth),'--profile','layered4200'],capture_output=True,timeout=60,cwd='/tmp');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(F.files(out),F.files(EXPECTED));self.assertEqual(json.loads(auth.read_bytes())['files'],F.files(EXPECTED))
 def test_full_original_guard_emitted_owner_inverse_and_two_clocks(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);out=self.emit(root);lane=out/'latest/implementation';saved,paths=dict(sys.modules),sys.path[:]
   try:
    sys.path.insert(0,str(lane))
    for p in out.rglob('*.py'):sys.modules.pop(p.stem,None)
    def load(name):
     spec=importlib.util.spec_from_file_location('_layered_'+name,lane/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    G=load('latest_guard');fact=G.verify();self.assertEqual(fact['files'],568);self.assertEqual(fact['bounds']['consumer'],4200);self.assertEqual(fact['bounds']['component'],2400);O=load('latest_owner');original=G.original();_,_,_,adapter,_,_=original.original_context();raw=adapter.owner(G.BASE/'held606');text=O.owner(raw);self.assertIn('active.process.wait(timeout=4200)',text);self.assertIn('signal.setitimer(signal.ITIMER_REAL,6600)',text);back=text.replace('active.process.wait(timeout=4200)','active.process.wait(timeout=1800)',1)
    for old,new in reversed(O.OWNER_EDITS):back=back.replace(new,old,1)
    self.assertEqual(back,raw);tree=ast.parse((lane/'latest_component.py').read_bytes());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='exercise');deadlines=[n for n in fn.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='deadline'for t in n.targets)];self.assertEqual(len(deadlines),1);self.assertEqual(ast.literal_eval(deadlines[0].value.right),2400)
    T=load('latest_graph_timing');path=root/'latest607-graph-timing.json';T.GraphTiming(path,'a'*32,time.monotonic()+2400,lambda:'SOURCE_ONLY_CONTROL');timing=json.loads(path.read_bytes());self.assertEqual((timing['consumer_seconds'],timing['component_seconds'],timing['owner_seconds']),(4200,2400,6600));self.assertFalse(timing['actual_authority']);self.assertEqual(timing['observations'],[])
    p=lane/'latest_plan.py';p.write_bytes(p.read_bytes().replace(b'consumer=4200',b'consumer=4201',1))
    with self.assertRaises(ValueError):G.verify()
   finally:
    sys.path[:]=paths
    for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
    sys.modules.update(saved)
 def test_changed_input_or_support_refuses_before_output(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);copy=root/'factory';shutil.copytree(HERE,copy);p=copy/'layered4200/budget_successor.py';p.write_bytes(p.read_bytes()+b'\n# drift\n');out=root/'out';r=subprocess.run([sys.executable,'-I','-B',str(copy/'prepare.py'),'--source',str(SOURCE),'--output',str(out),'--authorization',str(root/'auth'),'--profile','layered4200'],capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertIn(b'whole layered4200 support before output',r.stderr);self.assertFalse(out.exists());self.assertFalse((root/'auth').exists())
   wrong=root/'wrong';wrong.mkdir()
   with self.assertRaisesRegex(ValueError,'entire original555'):F.emit(wrong,out,'layered4200')
   self.assertFalse(out.exists())
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)

# SPDX-License-Identifier: MIT
"""Portable inspect1800 source controls; no native actors or historical replay."""
import ast,base64,hashlib,importlib.util,json,os,shutil,stat,subprocess,sys,tempfile,types,unittest,zlib
from pathlib import Path
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
SOURCE=Path(os.environ['REPAIR_CAPACITY_INPUT']).absolute()
EXPECTED=Path(os.environ['REPAIR_CAPACITY_EXPECTED']).absolute()
PROFILE='REPAIR_GENERIC16K_OWNED_INSPECT_THREE_OBSERVATIONS_1800_V1'
LIFE='scripts/ci/apps7-full574-repair-native/lifecycle.py'

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

F=load('_portable_inspect1800_factory',HERE/'prepare.py')

def functions(raw):
    return {n.name:ast.dump(n,include_attributes=False)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}

def argv(helper,selected=True):
    result=['/usr/bin/python3','-I','-B',helper.PATH,'inspect']
    for key in helper.KEYS:
        result.extend((key,helper.FIXED.get(key,'/work/main'if key=='--workspace'else hashlib.sha256(key.encode()).hexdigest())))
    return result+([helper.FLAG,helper.PROFILE]if selected else[])

class Controls(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(dir=os.environ.get('REPAIR_CAPACITY_WORK'))
        self.addCleanup(temp.cleanup);self.work=Path(temp.name)

    def test_isolated_known_null_exact245_modes_and_receipts(self):
        expected=F.scan(EXPECTED)[0];self.assertEqual(len(expected),245)
        for context in('known','null'):
            output=self.work/context;receipt=self.work/(context+'.json');previous=os.umask(0o077)
            try:
                row=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--source',str(SOURCE),'--output',str(output),'--context',context,'--receipt',str(receipt)],capture_output=True,timeout=30)
            finally:os.umask(previous)
            self.assertEqual(row.returncode,0,row.stderr.decode());self.assertFalse(row.stderr)
            self.assertEqual(F.scan(output)[0],expected)
            self.assertTrue(all(stat.S_IMODE((output/n).stat().st_mode)==0o644 for n in expected))
            result=json.loads(row.stdout);self.assertEqual(result['source']is None,context=='null')
            self.assertIsNone(result['actual']);self.assertIsNone(result['Root_acceptance'])
            self.assertEqual(json.loads(receipt.read_bytes())['file_map'],{n:F.pin(raw)for n,raw in expected.items()})

    def test_whole245_inverse_current_guard_only242_boundary_stubbed(self):
        values,p=F.compose(SOURCE);before=F.scan(SOURCE)[0]
        self.assertEqual(values,F.scan(EXPECTED)[0]);self.assertEqual(F.inverse(values,p),before)
        self.assertEqual(p['counts'],dict(before=245,after=245,held=235,changed=10,added=0))
        self.assertEqual(set(values),set(before));self.assertEqual(values[F.H],before[F.H])
        guard=load('_portable_current_capacity_guard',EXPECTED/F.G)
        def historical242_only(old,descriptor):
            self.assertEqual({n:F.pin(raw)for n,raw in old.items()},descriptor['before'])
            self.assertEqual(len(old),242)
            return dict(source_files=242,actual=None,scope='PRIVATE_CALLBACK_NOT_HISTORICAL_QUALIFICATION')
        with patch.object(guard,'old_entry',side_effect=historical242_only)as old:
            result=guard.prove(EXPECTED)
        self.assertEqual(old.call_count,1);self.assertEqual(result['source_files'],245);self.assertIsNone(result['actual'])
        restored,prior=guard.capacity_before(values,json.loads(values[F.Q]))
        self.assertEqual(restored,before);self.assertNotIn('inspect_capacity',prior)
        self.assertLess(len(values[F.Q]),8*1024**2)
        calls={n.func.id for n in ast.walk(ast.parse((HERE/'prepare.py').read_bytes()))if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)}
        self.assertTrue(calls.isdisjoint({'exec','eval','__import__'}));self.assertNotIn('subprocess',(HERE/'prepare.py').read_text())

    def test_explicit1800_emission_default_legacy_and_outer_capacity_held(self):
        values,p=F.compose(SOURCE);old=load('_portable_parent_adapter',SOURCE/F.A)
        new=load('_portable_current_adapter',EXPECTED/F.A);legacy=load('_portable_legacy_helper',EXPECTED/F.H)
        helper,raw_helper=new._inspect_capacity_helper()
        self.assertEqual(new.INSPECT_CAPACITY_PROFILE,PROFILE);self.assertEqual(helper.PROFILE,PROFILE)
        self.assertEqual(new._INSPECT_VALIDATION_SOURCE,old._INSPECT_VALIDATION_SOURCE)
        self.assertEqual(new._INSPECT_VALIDATION_SOURCE.encode(),values[F.H])
        for mode in(False,True):
            self.assertEqual(old.rendered_backend(SOURCE,inspect_profile=mode),new.rendered_backend(EXPECTED,inspect_profile=mode))
            self.assertEqual(old.lifecycle(values[LIFE],inspect_profile=mode),new.lifecycle(values[LIFE],inspect_profile=mode))
        restored=raw_helper
        for before,after in reversed(new.INSPECT_CAPACITY_EDITS):
            self.assertEqual(restored.count(after),1);restored=restored.replace(after,before,1)
        self.assertEqual(restored,new._INSPECT_VALIDATION_SOURCE)
        self.assertEqual(helper.NOTE_DICTIONARY,legacy.NOTE_DICTIONARY)
        self.assertEqual(helper.NOTE_DICTIONARY_PIN,legacy.NOTE_DICTIONARY_PIN)
        with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_NATIVE_ACTORS')):
            receipt=new.execution(EXPECTED,self.work/'execution',json.loads(values[F.MANIFESTS[0]]),inspect_profile=PROFILE)
            target=F.MANIFESTS[0].replace('source-manifest.json','transaction.py')
            self.assertEqual((self.work/'execution'/target).read_bytes(),new.rendered_backend(EXPECTED,inspect_profile=PROFILE)[0])
        detail=receipt['derivation']['owned_inspect_validation']
        self.assertEqual((detail['backend_seconds'],detail['caller_seconds']),(1800,1810))
        self.assertEqual(receipt['changed'],[target]);self.assertTrue(receipt['original_source_preserved'])
        for key in('old600_fit','old1200_fit','new1800_fit'):self.assertEqual(detail[key],'NOT_ESTABLISHED')
        self.assertEqual(detail['M2_performance'],'NOT_RUN')
        self.assertEqual(functions(old.rendered_backend(SOURCE,inspect_profile=True)[0]),functions(new.rendered_backend(EXPECTED,inspect_profile=PROFILE)[0].replace(helper.PROFILE.encode(),legacy.PROFILE.encode())))
        before=F.scan(SOURCE)[0]
        for name in('scripts/apps/full574_closure.py','scripts/update/full_root.py','scripts/install/local_transaction.py','scripts/ci/apps7-full574-repair16k/job_clock.py'):
            self.assertEqual(values[name],before[name],name)
        remaining=next(n for n in ast.parse(values[F.V]).body if isinstance(n,ast.FunctionDef)and n.name=='remaining')
        scope=dict(C=types.SimpleNamespace(need=helper.need),time=types.SimpleNamespace(monotonic=lambda:100))
        exec(compile(ast.Module(body=[remaining],type_ignores=[]),'<ACTUAL_HELD_OUTER_REMAINING>','exec'),scope)
        self.assertEqual(scope['remaining'](1000,18000),900);self.assertEqual(scope['remaining'](40000,18000),18000)
        with self.assertRaises(ValueError):scope['remaining'](100,18000)

    def test_unknown_selectors_foreign_roles_and_failure_codec_no_grants(self):
        new=load('_portable_closed_adapter',EXPECTED/F.A);helper,_=new._inspect_capacity_helper()
        for mode in('foreign',1800,1,None,{},'REPAIR_GENERIC16K_OWNED_INSPECT_VALIDATION_1200_V1'):
            for method,args in((new.rendered_backend,(EXPECTED,)),(new.lifecycle,((EXPECTED/LIFE).read_bytes(),))):
                with self.subTest(mode=mode,method=method.__name__),self.assertRaises(ValueError):method(*args,inspect_profile=mode)
        self.assertTrue(helper.role(argv(helper),1810,selected=True));self.assertFalse(helper.role(argv(helper),1210,selected=True))
        base=dict(zip(helper.KEYS,argv(helper,False)[6::2]))
        for field,value in(('action','apply'),('worker',True),('confirm_disposable_transaction',True),('source','/foreign'),('release','foreign'),('workspace','/work/foreign'),('full574_policy','/foreign')):
            args=types.SimpleNamespace(action='inspect',tcg_owned_inspect_profile=PROFILE,**{k[2:].replace('-','_'):v for k,v in base.items()});setattr(args,field,value);calls=[]
            def original(arg):calls.append(arg);return 600
            with self.subTest(field=field),self.assertRaises(ValueError):helper.wrap(original)(args)
            self.assertEqual(calls,[args]) # Original authenticated policy runs first.
        life=new.lifecycle((EXPECTED/LIFE).read_bytes(),inspect_profile=PROFILE)
        note_source=ast.literal_eval(next(n.value for n in ast.parse(life).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='_VM_INSPECT_NOTE_SOURCE'for t in n.targets)))
        out=b'private synthetic stdout';err=b'private synthetic stderr\n'*80
        row=dict(argv=argv(helper),exit_code=1,seconds=1700.25,time_limit=1810,output_limit=1024**2,group_absence_verified=True,stdout_bytes=len(out),stdout_sha256=helper.pin(out)['sha256'],stderr_bytes=len(err),stderr_sha256=helper.pin(err)['sha256'])
        note=helper.note(note_source,row,out,err,None,0);self.assertLessEqual(len(note.encode()),1900)
        wire=json.loads(note[len('APPS574_INSPECT_FAILURE '):]);projected=helper.projected_record(wire)
        self.assertEqual(projected['complete_returned_streams'],dict(stdout=helper.pin(out),stderr=helper.pin(err)))
        self.assertFalse(projected['acceptance_authority']);self.assertFalse(projected['cleanup_authority'])
        for key,value in(('bytes',True),('bytes',16385),('base64','!'),('sha256','0'*64),('purpose','FOREIGN')):
            with self.subTest(key=key),self.assertRaises((ValueError,TypeError,zlib.error)):helper.projected_record(dict(wire,**{key:value}))

    def test_input_profile_operand_and_namespace_refusals_prewrite(self):
        for kind in('drift','missing','extra','empty','symlink','hardlink'):
            source=self.work/kind;shutil.copytree(SOURCE,source);leaf=source/F.H
            if kind=='drift':leaf.write_bytes(leaf.read_bytes()+b'\n')
            elif kind=='missing':leaf.unlink()
            elif kind=='extra':(source/'foreign').write_bytes(b'x')
            elif kind=='empty':(source/'foreign').mkdir()
            elif kind=='symlink':leaf.unlink();leaf.symlink_to(SOURCE/F.H)
            else:leaf.unlink();os.link(source/F.A,leaf)
            output=self.work/(kind+'-out')
            with self.subTest(kind=kind),self.assertRaises(ValueError):F.emit(source,output,'known')
            self.assertFalse(output.exists())
        with self.assertRaises(ValueError):F.emit(EXPECTED,self.work/'wrong-parent','known')
        p=json.loads((HERE/'profile.json').read_bytes());operands=p['operands']
        self.assertEqual(set(operands),{'file-edits.json','guard-edits.json','adapter-append.py.txt','guard-append.py.txt','vm-before-body.zlib.base64.txt'})
        data={name:(HERE/name).read_bytes()for name in operands};before=F.scan(SOURCE)[0]
        name='vm-before-body.zlib.base64.txt'
        for foreign in(base64.b64encode(zlib.compress(b'foreign VM metadata'))+b'\n',b'!\n'):
            with self.subTest(metadata=foreign[:20]),self.assertRaises(ValueError):
                F.transform(before,p,dict(data,**{name:foreign}))
        for name in('profile.json',*operands):
            factory=self.work/('changed-'+name);shutil.copytree(HERE,factory);(factory/name).write_bytes(b'foreign\n');output=self.work/(name+'-out')
            with self.subTest(name=name),patch.object(F,'HERE',factory),self.assertRaises(ValueError):F.emit(SOURCE,output,'known')
            self.assertFalse(output.exists())

    def test_canonical_fresh_disjoint_late_input_profile_operand_inode_refusals(self):
        alias=self.work/'alias';alias.symlink_to(SOURCE,target_is_directory=True)
        for source,output in((SOURCE,SOURCE/'nested'),(SOURCE,HERE/'nested'),(alias,self.work/'alias-out'),(SOURCE,'relative'),(SOURCE,str(self.work)+'/a/../out'),(SOURCE,'//tmp/foreign'),(SOURCE,self.work)):
            with self.subTest(output=str(output)),self.assertRaises(ValueError):F.emit(source,output,'known')
        for receipt in(SOURCE/'receipt',HERE/'receipt',self.work/'out'/'receipt'):
            with self.assertRaises(ValueError):F.emit(SOURCE,self.work/'out','known',receipt)
        with self.assertRaises(ValueError):F.emit(SOURCE,self.work/'out','foreign')
        source=self.work/'late-input';shutil.copytree(SOURCE,source);original_scan=F.scan;seen=[]
        def swapped(root):
            result=original_scan(root)
            if root==source and not seen:
                seen.append(True);leaf=source/F.H;swap=leaf.with_suffix('.swap');swap.write_bytes(leaf.read_bytes());swap.replace(leaf)
            return result
        with patch.object(F,'scan',side_effect=swapped),self.assertRaisesRegex(ValueError,'late'):F.emit(source,self.work/'late-out','known',self.work/'late-receipt')
        self.assertFalse((self.work/'late-out').exists());self.assertFalse((self.work/'late-receipt').exists())
        operands=json.loads((HERE/'profile.json').read_bytes())['operands']
        for name in('profile.json',*operands):
            factory=self.work/('late-'+name);shutil.copytree(HERE,factory);original_read=F.read_state;seen=[]
            def replaced(path):
                result=original_read(path)
                if Path(path)==factory/name and not seen:
                    seen.append(True);leaf=factory/name;swap=leaf.with_suffix('.swap');swap.write_bytes(leaf.read_bytes());swap.replace(leaf)
                return result
            output=self.work/('late-'+name+'-out')
            with self.subTest(name=name),patch.object(F,'HERE',factory),patch.object(F,'read_state',side_effect=replaced),self.assertRaisesRegex(ValueError,'late'):F.emit(SOURCE,output,'known')
            self.assertTrue(seen);self.assertFalse(output.exists())

if __name__=='__main__':unittest.main(verbosity=2)

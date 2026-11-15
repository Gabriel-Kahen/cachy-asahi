#!/usr/bin/env python3
"""Fenced synthetic volume DATA joins; never run Reader main/replay or Source code."""
import argparse
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

HERE=Path(__file__).resolve().parent
V2=HERE.parent/'v2'
FIXTURE_SHA='cab012cc06c3687cf314c11dec66fd9456d6c42e5fd9a7ec45160fc5a524bf8c'
INIT_SHA='476e7e543cfb9b63af018f3cec3286eb4a824390de802c677bb38631a542d138'
ACTUAL_SOURCE='365a763bc515a1b3550cc804536ddbf66353aac8'
ACTUAL_MAP='22f6f8a9d3eabf4de16c853cf67183b67beca4e702e26c5b492066e94194735c'
r=B=v=FIXTURE=None
INITIALIZER_LITERAL=None


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.posix_spawn')) or event in (
        'os.system','os.fork','os.forkpty','fcntl.flock','fcntl.lockf','os.unshare','os.setns','os.pidfd_open'):
        raise AssertionError('Reader volume DATA fence: '+event)


def fixture_functions():
    raw=(V2/'test_volume.py').read_bytes()
    if len(raw)>32768 or hashlib.sha256(raw).hexdigest()!=FIXTURE_SHA:
        raise AssertionError('whole frozen synthetic fixture definition pin')
    names={'life','store','statrow','fixture'}
    nodes=[copy.deepcopy(n) for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name in names]
    if {n.name for n in nodes}!=names:raise AssertionError('exact four fixture definitions')
    seams=0
    for function in nodes:
        if function.name!='fixture':continue
        for node in function.body:
            if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id=='code':
                # The original fixture's Source read becomes the one bounded,
                # inert INIT_CODE literal parsed before installing the fence.
                node.value=ast.Name(id='INITIALIZER_LITERAL',ctx=ast.Load());seams+=1
    if seams!=1:raise AssertionError('one explicit literal-read fixture seam')
    api=SimpleNamespace(**vars(v))
    actual_pins=v.load(HERE/'pins.json',65536)
    api.load=lambda path:copy.deepcopy(actual_pins) if path==V2/'pins.json' else v.load(path,65536)
    namespace={'__builtins__':__builtins__,'r':api,'HERE':V2,'Path':Path,'ast':ast,'copy':copy,
               'hashlib':hashlib,'json':json,'INITIALIZER_LITERAL':INITIALIZER_LITERAL}
    tree=ast.fix_missing_locations(ast.Module(body=nodes,type_ignores=[]))
    exec(compile(tree,'<frozen synthetic fixture definitions>','exec'),namespace)
    return namespace


class VolumeDataControls(unittest.TestCase):
    def setUp(self):
        if FIXTURE is None:raise AssertionError('use the explicit --source-root CLI')
        self.tmp=tempfile.TemporaryDirectory(prefix='llvm-reader-v4-SYNTHETIC-DATA-')
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.producer,self.actual,self.pins,self.rows=FIXTURE['fixture'](self.root)
        self.assertEqual(self.actual['source'],ACTUAL_SOURCE)
        self.assertEqual(self.pins['source_map_sha256'],ACTUAL_MAP)
        self.owner=v.volume_owner(self.actual)
        self.caps(['CAP_CHOWN'])

    def save_rows(self):FIXTURE['store'](self.root,'bootstrap/operations.json',self.rows)

    def put_raw(self,index,body,channel='stdout',repin=True):
        row=self.rows[index];path=self.root/row[channel];path.write_bytes(body)
        if repin:row[channel+'_pin']=v.hashed(path)
        self.save_rows()

    def update_inspect(self,name,index,mutate):
        path=self.root/'llvm-build'/name;doc=v.load(path);mutate(doc)
        path.write_bytes(v.canonical(doc));self.put_raw(index,v.canonical([doc]))

    def caps(self,capabilities):
        for name,index in [('initializer-before.json',3),('initializer-after.json',5)]:
            self.update_inspect(name,index,lambda row:row['HostConfig'].__setitem__('CapAdd',copy.deepcopy(capabilities)))

    def check(self,retirement=False):
        result=v.volume_initialization(self.root,self.producer,self.actual,self.pins)
        if retirement:v.retirement(self.root,self.producer,self.actual['image'])
        return result

    def test_both_singleton_capability_spellings_complete_raw_join_and_retirement(self):
        for capabilities in [['CHOWN'],['CAP_CHOWN']]:
            with self.subTest(capabilities=capabilities):
                self.caps(capabilities)
                self.assertEqual(self.check(retirement=True),self.producer['volume_initialization'])

    def test_clone_updates_global_lookup_without_changing_old_reader(self):
        self.assertIs(r.v,B.v)
        self.assertIsNot(v,B.frozen)
        self.assertIs(v.volume_initialization.__globals__,vars(v))
        self.assertIs(v.replay.__globals__,vars(v))
        initial=v.load(self.root/'llvm-build/initializer-before.json')
        v.initializer(initial,self.owner,self.actual['image'],self.pins)
        with self.assertRaisesRegex(ValueError,'CHOWN-only'):
            B.frozen.initializer(initial,self.owner,self.actual['image'],self.pins)
        initial['HostConfig']['CapAdd']=['CHOWN']
        B.frozen.initializer(initial,self.owner,self.actual['image'],self.pins)
        proof=B.initializer_projection_proof()
        self.assertEqual(proof['seams'],1)
        self.assertEqual(proof['inverse'],'EXACT_FUNCTION_BYTES')
        self.assertFalse(proof['actual_Source_ref_run_job_map_changes'])

    def test_bad_caps_refuse_at_initializer_guard_with_recomputed_raw_pins(self):
        for capabilities in [[],None,'CHOWN',['CHOWN','CHOWN'],['CAP_CHOWN','CAP_CHOWN'],
                ['CHOWN','CAP_CHOWN'],['CAP_CHOWN','CAP_FOWNER'],['CHOWN','DAC_OVERRIDE'],
                ['CAP_SYS_ADMIN'],['CAP_CAP_CHOWN'],['chown']]:
            with self.subTest(capabilities=capabilities):
                self.caps(capabilities)
                with self.assertRaisesRegex(ValueError,'CHOWN-only'):self.check()

    def test_drop_all_security_network_and_resources_remain_strict(self):
        original=v.load(self.root/'llvm-build/initializer-before.json')
        changes={'CapDrop':[], 'ReadonlyRootfs':False,'NetworkMode':'host','SecurityOpt':[],
                 'Privileged':True,'Devices':[{'PathOnHost':'/MODELED/device'}],
                 'DeviceRequests':[{'Driver':'MODELED'}],'Init':True,'UsernsMode':'host',
                 'Memory':536870913,'MemorySwap':536870913,'NanoCpus':1000000001,'PidsLimit':65}
        for key,value in changes.items():
            (self.root/'llvm-build/initializer-before.json').write_bytes(v.canonical(original))
            self.update_inspect('initializer-before.json',3,lambda row:row['HostConfig'].__setitem__(key,value))
            with self.subTest(key=key),self.assertRaises(ValueError):self.check()

    def test_initializer_identity_code_and_source_labels_remain_strict(self):
        original=v.load(self.root/'llvm-build/initializer-before.json')
        changes=[lambda row:row['Config'].__setitem__('User','1001:1001'),
                 lambda row:row.__setitem__('Image','sha256:'+'0'*64),
                 lambda row:row['Config']['Cmd'].__setitem__(3,INITIALIZER_LITERAL+'\n# drift'),
                 lambda row:row['Config']['Labels'].__setitem__('cachy-asahi.llvm-work.source','0'*40)]
        for change in changes:
            (self.root/'llvm-build/initializer-before.json').write_bytes(v.canonical(original))
            self.update_inspect('initializer-before.json',3,change)
            with self.subTest(change=change),self.assertRaises(ValueError):self.check()

    def test_nocopy_remains_required_for_both_containers(self):
        for name,index in [('initializer-before.json',3),('actor-inspect.json',1)]:
            original=v.load(self.root/'llvm-build'/name)
            self.update_inspect(name,index,lambda row:row['HostConfig']['Mounts'][0]['VolumeOptions'].__setitem__('NoCopy',False))
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'nocopy'):self.check()
            (self.root/'llvm-build'/name).write_bytes(v.canonical(original));self.put_raw(index,v.canonical([original]))

    def test_created_before_initialization_and_unique_start_order(self):
        original=copy.deepcopy(self.rows)
        self.rows[2],self.rows[4]=self.rows[4],self.rows[2];self.save_rows()
        with self.assertRaisesRegex(ValueError,'created before'):self.check()
        self.rows=copy.deepcopy(original);self.rows.append(copy.deepcopy(self.rows[4]));self.save_rows()
        with self.assertRaisesRegex(ValueError,'one actual'):self.check()

    def test_same_directory_stat_uid_gid_mode_inode_and_receipt_continuity(self):
        original=copy.deepcopy(self.producer['volume_initialization'])
        for key,value in [('uid',0),('gid',0),('mode',0o755),('inode',999),('device',99)]:
            observed=copy.deepcopy(original);observed['after'][key]=value
            self.producer['volume_initialization']=observed
            for name in ['volume-initialization.json','inputs/volume-initialization.json']:
                FIXTURE['store'](self.root,'llvm-build/'+name,observed)
            self.put_raw(4,v.canonical(observed))
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'same initialized'):self.check()
        self.producer['volume_initialization']=original
        FIXTURE['store'](self.root,'llvm-build/volume-initialization.json',original)
        with self.assertRaisesRegex(ValueError,'receipt continuity'):self.check()

    def test_preentry_uid_binding_and_write_probe_are_exact(self):
        original=json.loads((self.root/self.rows[6]['stdout']).read_bytes().split(b'\n',1)[0])
        changes=[lambda row:row['actual'].__setitem__('uid',0),
                 lambda row:row['actual'].__setitem__('inode',999),
                 lambda row:row.__setitem__('write_probe',True),
                 lambda row:row['binding'].__setitem__('source','0'*40)]
        for change in changes:
            row=copy.deepcopy(original);change(row)
            self.put_raw(6,json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\nMODELED_OUTPUT_NOT_EXECUTION\n')
            with self.subTest(change=change),self.assertRaisesRegex(ValueError,'preentry observation'):self.check()

    def test_raw_output_pins_and_raw_retained_inspect_continuity_are_independent(self):
        path=self.root/self.rows[3]['stdout'];raw=path.read_bytes()
        self.put_raw(3,raw+b' ',repin=False)
        with self.assertRaisesRegex(ValueError,'whole inspect raw output'):self.check()
        doc=v.decode(raw);doc[0]['Config']['User']='1001:1001'
        self.put_raw(3,v.canonical(doc),repin=True)
        with self.assertRaisesRegex(ValueError,'raw output/retained identity'):self.check()

    def test_initializer_timeout_forced_or_unknown_retirement_refuse(self):
        original=copy.deepcopy(self.rows[4]['lifecycle'])
        changes={'elapsed_seconds':121,'forced_cleanup':True,'ownership_lost':True,
                 'group_absent':False,'natural_exit':False,'retirement':'UNKNOWN'}
        for key,value in changes.items():
            self.rows[4]['lifecycle']={**original,key:value};self.save_rows()
            with self.subTest(key=key),self.assertRaises(ValueError):self.check()

    def test_retirement_absence_and_export_are_not_relaxed(self):
        self.check(retirement=True)
        self.producer['export']['lifecycle']['forced_cleanup']=True
        with self.assertRaisesRegex(ValueError,'retirement'):v.retirement(self.root,self.producer,self.actual['image'])
        self.producer['export']['lifecycle']['forced_cleanup']=False
        absence=next(i for i,row in enumerate(self.rows) if row['argv'][2:]==['container','ls','--all','--format','{{.Names}}'])
        self.put_raw(absence,(self.owner['actor']+'\n').encode())
        with self.assertRaisesRegex(ValueError,'resources remain'):v.retirement(self.root,self.producer,self.actual['image'])

    def test_kernel_capability_bits_initializer_sha_and_original_create_cli_unchanged(self):
        self.assertEqual(hashlib.sha256(INITIALIZER_LITERAL.encode()).hexdigest(),INIT_SHA)
        self.assertEqual(self.pins['initializer_code_sha256'],INIT_SHA)
        code=ast.unparse(ast.parse(INITIALIZER_LITERAL))
        for fragment in ["int(status[k].strip(), 16) == 1","('CapPrm', 'CapEff', 'CapBnd')",
                "int(status[k].strip(), 16) == 0","('CapInh', 'CapAmb')","status['NoNewPrivs'].strip() == '1'"]:
            self.assertIn(fragment,code)
        self.assertLess(code.index('os.fchmod(fd, 448)'),code.index('os.fchown(fd, 1001, 1001)'))
        self.assertIn('--cap-add=CHOWN',self.rows[2]['argv'])
        self.assertNotIn('--cap-add=CAP_CHOWN',self.rows[2]['argv'])


def main():
    global r,B,v,FIXTURE,INITIALIZER_LITERAL
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',type=Path,required=True)
    args,remaining=parser.parse_known_args()
    # Trusted Reader definitions only. No Source module is imported here.
    spec=importlib.util.spec_from_file_location('llvm_v4_volume_controls_reader',HERE/'reader.py')
    r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r);B=r.B;v=r.v
    source=args.source_root.resolve()/ 'hosted/volume.py'
    body=v.read(source,16384)
    assignments=[node.value for node in ast.parse(body).body if isinstance(node,ast.Assign)
        and any(isinstance(target,ast.Name) and target.id=='INIT_CODE' for target in node.targets)]
    if len(assignments)!=1:raise AssertionError('one inert Source INIT_CODE literal')
    INITIALIZER_LITERAL=ast.literal_eval(assignments[0])
    if hashlib.sha256(INITIALIZER_LITERAL.encode()).hexdigest()!=INIT_SHA:raise AssertionError('unchanged initializer DATA pin')
    FIXTURE=fixture_functions()
    sys.addaudithook(fence)
    unittest.main(argv=[sys.argv[0],*remaining])


if __name__=='__main__':main()

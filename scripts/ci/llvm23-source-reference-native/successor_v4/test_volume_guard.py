#!/usr/bin/env python3
"""Fenced AST-only initializer controls over retained253 code and synthetic Docker DATA."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest

HERE=Path(__file__).resolve().parent
OLD="h['CapAdd']==['CHOWN']"
NEW="h['CapAdd']in(['CHOWN'],['CAP_CHOWN'])"
VOLUME_SHA='5403e74515cf11aacb05fbd719d5e129549aa565b913b84d86d2b1ed608426bd'
PRODUCER_SHA='77170ff3cf518973cd663ca5e302e5710462055e07a6b8bd1599ec54a4ebebcc'


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.posix_spawn')) or event in (
        'os.system','os.fork','os.forkpty','fcntl.flock','fcntl.lockf','os.unshare','os.setns'):
        raise AssertionError('volume guard DATA-only fence: '+event)


def selected(raw):
    functions={'need','encode','labels','container_identity','inspect_init','receipt','init_options'}
    constants={'DOCKER','OP','INNER','INIT_CODE'}
    nodes=[];found=set()
    for node in ast.parse(raw).body:
        if isinstance(node,ast.FunctionDef) and node.name in functions:
            nodes.append(node);found.add(node.name)
        elif isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in constants:
            # INIT_CODE is assigned as an inert string; its body is never executed.
            nodes.append(node);found.add(node.targets[0].id)
    if found!=functions|constants:raise AssertionError('exact AST definition surface')
    namespace={'__builtins__':__builtins__,'json':json,'re':re}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<selected initializer DATA definitions>','exec'),namespace)
    return namespace


class VolumeGuardControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        raw=(HERE/'fixtures/volume-guard.DATA.json').read_bytes()
        if len(raw)>16384:raise AssertionError('tiny retained code DATA cap')
        cls.fixture=json.loads(raw)
        original=cls.fixture['volume_source']['text']
        if len(original.encode())!=5818 or hashlib.sha256(original.encode()).hexdigest()!=VOLUME_SHA:
            raise AssertionError('exact original253 volume Source DATA pin')
        if cls.fixture['producer_completion']['sha256']!=PRODUCER_SHA:raise AssertionError('producer provenance pin')
        if original.count(OLD)!=1 or NEW in original:raise AssertionError('single literal capability seam')
        cls.original=original;cls.corrected=original.replace(OLD,NEW)
        cls.old=selected(cls.original);cls.new=selected(cls.corrected)
        cls.completion=ast.parse(cls.fixture['producer_completion']['expression'],mode='eval')
        if any(isinstance(n,(ast.Call,ast.Attribute,ast.Lambda)) for n in ast.walk(cls.completion)):
            raise AssertionError('completion fixture must be a pure DATA predicate')
        if {n.id for n in ast.walk(cls.completion) if isinstance(n,ast.Name)}!={'final_init'}:
            raise AssertionError('only modeled initializer state may be read')
        cls.completion_code=compile(cls.completion,'<actual completion DATA predicate>','eval')

    def setUp(self):
        self.binding={'source':'f'*40,'run':'123','job':'456','operation':self.new['OP'],
                      'token':'MODELED_DATA_TOKEN','actor':'FIXTURE-builder','init':'FIXTURE-initializer','volume':'FIXTURE-work'}
        self.image='sha256:'+'a'*64
        self.row={'Name':'/'+self.binding['init'],'Id':'b'*64,'Image':self.image,
            'Config':{'User':'0:0','Entrypoint':['/usr/bin/python3'],
                'Cmd':['-I','-B','-c',self.new['INIT_CODE'],self.new['encode'](self.binding).decode()],
                'Labels':self.new['labels'](self.binding,'initializer')},
            'HostConfig':{'ReadonlyRootfs':True,'NetworkMode':'none','CapDrop':['ALL'],'CapAdd':['CAP_CHOWN'],
                'SecurityOpt':['no-new-privileges'],'Privileged':False,'Devices':[],'Init':False,
                'Memory':536870912,'MemorySwap':536870912,'NanoCpus':1000000000,'PidsLimit':64,'UsernsMode':'',
                'Mounts':[{'Type':'volume','Source':self.binding['volume'],'Target':'/work','VolumeOptions':{'NoCopy':True}}]},
            'Mounts':[{'Type':'volume','Name':self.binding['volume'],'Destination':'/work','RW':True}],
            'State':{'Status':'exited','ExitCode':0,'Running':False,'Pid':0,'OOMKilled':False}}

    def inspect(self,row=None):return self.new['inspect_init'](self.row if row is None else row,self.binding,self.image)

    def test_both_singleton_spellings_pass_and_original_reproduces(self):
        for cap in ['CHOWN','CAP_CHOWN']:
            self.row['HostConfig']['CapAdd']=[cap]
            with self.subTest(cap=cap):self.inspect()
        with self.assertRaisesRegex(ValueError,'minimal initializer domain'):
            self.old['inspect_init'](self.row,self.binding,self.image)

    def test_only_capability_predicate_differs_and_all_other_atomic_predicates_pass(self):
        old=next(n for n in ast.parse(self.original).body if isinstance(n,ast.FunctionDef) and n.name=='inspect_init')
        predicates=[]
        for call in (n for n in ast.walk(old) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='need'):
            condition=call.args[0]
            predicates.extend(condition.values if isinstance(condition,ast.BoolOp) else [condition])
        cap=[n for n in predicates if "h['CapAdd']" in ast.unparse(n)]
        self.assertEqual(len(cap),1)
        namespace={**self.old,'row':self.row,'b':self.binding,'image':self.image,
                   'h':self.row['HostConfig'],'c':self.row['Config'],'mounts':self.row['Mounts'],
                   'declared':self.row['HostConfig']['Mounts']}
        for predicate in predicates:
            if predicate in cap:continue
            with self.subTest(predicate=ast.unparse(predicate)):
                self.assertTrue(eval(compile(ast.Expression(predicate),'<unchanged inspect DATA predicate>','eval'),namespace))
        self.assertEqual(self.corrected.replace(NEW,OLD),self.original)

    def test_extra_duplicate_unknown_or_nonlist_capabilities_refuse(self):
        for caps in [[],None,'CHOWN',['CHOWN','CHOWN'],['CAP_CHOWN','CAP_CHOWN'],['CHOWN','CAP_CHOWN'],
                     ['CAP_CHOWN','CAP_FOWNER'],['CHOWN','DAC_OVERRIDE'],['CAP_SYS_ADMIN'],['CAP_CAP_CHOWN'],['chown']]:
            with self.subTest(caps=caps):
                self.row['HostConfig']['CapAdd']=caps
                with self.assertRaises(ValueError):self.inspect()

    def test_drop_all_rootless_domain_and_security_must_remain_exact(self):
        mutations={'CapDrop':[], 'NetworkMode':'host','ReadonlyRootfs':False,'Privileged':True,
                   'Devices':[{'PathOnHost':'/dev/FIXTURE'}],'Init':True,'UsernsMode':'host',
                   'SecurityOpt':[], 'CapAdd':['CAP_CHOWN','CAP_DAC_OVERRIDE']}
        for key,value in mutations.items():
            row=copy.deepcopy(self.row);row['HostConfig'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.inspect(row)

    def test_user_image_container_identity_and_role_labels_refuse(self):
        for mutate in [lambda r:r['Config'].__setitem__('User','1001:1001'),
                lambda r:r.__setitem__('Image','sha256:'+'0'*64),lambda r:r.__setitem__('Name','/foreign'),
                lambda r:r.__setitem__('Id','not-a-container-id'),
                lambda r:r['Config']['Labels'].__setitem__('cachy-asahi.llvm-work.role','builder'),
                lambda r:r['Config']['Labels'].__setitem__('cachy-asahi.llvm-work.source','0'*40)]:
            row=copy.deepcopy(self.row);mutate(row)
            with self.subTest(mutation=mutate),self.assertRaises(ValueError):self.inspect(row)

    def test_actual_mount_and_declared_nocopy_must_be_single_owned_volume(self):
        changes=[lambda r:r['Mounts'].append(copy.deepcopy(r['Mounts'][0])),
            lambda r:r['Mounts'][0].__setitem__('Type','bind'),lambda r:r['Mounts'][0].__setitem__('Name','foreign'),
            lambda r:r['Mounts'][0].__setitem__('Destination','/elsewhere'),lambda r:r['Mounts'][0].__setitem__('RW',False),
            lambda r:r['HostConfig']['Mounts'][0]['VolumeOptions'].__setitem__('NoCopy',False),
            lambda r:r['HostConfig']['Mounts'][0].__setitem__('Source','foreign'),
            lambda r:r['HostConfig']['Mounts'].append(copy.deepcopy(r['HostConfig']['Mounts'][0]))]
        for mutate in changes:
            row=copy.deepcopy(self.row);mutate(row)
            with self.subTest(mutation=mutate),self.assertRaises(ValueError):self.inspect(row)

    def test_each_resource_limit_drift_refuses(self):
        for key in ['Memory','MemorySwap','NanoCpus','PidsLimit']:
            row=copy.deepcopy(self.row);row['HostConfig'][key]+=1
            with self.subTest(key=key),self.assertRaises(ValueError):self.inspect(row)

    def test_initializer_code_interpreter_flags_and_binding_are_exact(self):
        for mutate in [lambda r:r['Config'].__setitem__('Entrypoint',['/usr/bin/bash']),
                lambda r:r['Config']['Cmd'].__setitem__(0,'-B'),
                lambda r:r['Config']['Cmd'].__setitem__(3,self.new['INIT_CODE']+'\n# drift'),
                lambda r:r['Config']['Cmd'].__setitem__(4,'{}')]:
            row=copy.deepcopy(self.row);mutate(row)
            with self.subTest(mutation=mutate),self.assertRaises(ValueError):self.inspect(row)

    def test_kernel_capability_and_initialization_code_stays_inert_unchanged(self):
        text=self.new['INIT_CODE']
        self.assertEqual(text,self.old['INIT_CODE'])
        tree=ast.parse(text);canonical=ast.unparse(tree)
        self.assertIn("int(status[k].strip(), 16) == 1",canonical)
        self.assertIn("('CapPrm', 'CapEff', 'CapBnd')",canonical)
        self.assertIn("int(status[k].strip(), 16) == 0",canonical)
        self.assertIn("('CapInh', 'CapAmb')",canonical)
        self.assertIn("status['NoNewPrivs'].strip() == '1'",canonical)
        self.assertLess(canonical.index('os.fchmod(fd, 448)'),canonical.index('os.fchown(fd, 1001, 1001)'))
        argv=self.new['init_options'](self.binding,self.image)
        self.assertIn('--cap-add=CHOWN',argv)
        self.assertNotIn('--cap-add=CAP_CHOWN',argv)
        self.assertEqual(argv[-2],text)

    def test_natural_completion_state_predicate_rejects_running_failed_or_oom(self):
        self.assertTrue(eval(self.completion_code,{'final_init':self.row}))
        for key,value in [('Status','running'),('ExitCode',1),('Running',True),('Pid',99),('OOMKilled',True)]:
            row=copy.deepcopy(self.row);row['State'][key]=value
            with self.subTest(key=key):self.assertFalse(eval(self.completion_code,{'final_init':row}))

    def test_before_after_initializer_receipt_identity_and_state(self):
        before={'device':1,'inode':2,'uid':0,'gid':0,'mode':0o755}
        after={**before,'uid':1001,'gid':1001,'mode':0o700}
        receipt={'schema':1,'status':'INITIALIZED_EMPTY_WORK_VOLUME','binding':self.binding,'recursive':False,
            'capabilities':'CHOWN_ONLY_CHMOD_BEFORE_CHOWN','before':before,'after':after,
            'limits':{'cpu.max':'100000 100000','memory.max':'536870912','memory.swap.max':'0','pids.max':'64'}}
        self.new['receipt'](receipt,self.binding)
        for mutate in [lambda r:r.__setitem__('status','running'),lambda r:r.__setitem__('recursive',True),
                lambda r:r['after'].__setitem__('inode',3),lambda r:r['after'].__setitem__('uid',0),
                lambda r:r['after'].__setitem__('mode',0o755),lambda r:r['limits'].__setitem__('memory.swap.max','1')]:
            row=copy.deepcopy(receipt);mutate(row)
            with self.subTest(mutation=mutate),self.assertRaises(ValueError):self.new['receipt'](row,self.binding)


if __name__=='__main__':
    sys.addaudithook(fence)
    unittest.main()

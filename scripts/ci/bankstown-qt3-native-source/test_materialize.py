#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Fenced MODEL tar/files and real maintained Build API; never an actual image."""
import copy
import importlib.util
import io
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in {'os.system','os.exec','os.posix_spawn','os.fork','fcntl.flock'}:
        raise AssertionError('MODEL operational event forbidden: '+event)

sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

M=load('bankstown_materialize_tests',HERE/'materialize.py')
B=load('bankstown_materialize_actual_Build_fixture',HERE/'test_image.py')
H=M.H


def archive(path,rows):
    with tarfile.open(path,'w',format=tarfile.GNU_FORMAT) as stream:
        for name,kind,data,mode in rows:
            item=tarfile.TarInfo(name);item.mode=mode;item.type=kind
            if kind==tarfile.REGTYPE:
                item.size=len(data);stream.addfile(item,io.BytesIO(data))
            else:
                if kind in (tarfile.SYMTYPE,tarfile.LNKTYPE):item.linkname=data
                stream.addfile(item)
    return path

class ExportExecutor(B.Executor):
    """Only export-file delivery added; the actual held Build validates vectors."""
    def __init__(self,module,fixture,tar_rows,context,mutation=None):
        super().__init__(module,fixture,mutation)
        self.deadline=time.monotonic()+600;self.alive_calls=0;self.tar_rows=tar_rows
        self.facts.update(code_pin=H.pin(b'MODEL_EXECUTOR'),engine_id='MODEL_ENGINE',
                          owner_domain={'pid':123},daemon_domain={'pid':456},
                          docker_endpoint='unix:///MODEL/'+context['nonce']+'/docker.sock')
    def live(self):self.alive_calls+=1
    def run(self,step,argv,timeout,expected=0):
        if argv[2:4]==['container','export']:
            self.commands.append((step,argv))
            assert argv[:2]==['/usr/bin/docker','--host='+self.facts['docker_endpoint']]
            assert len(argv)==7 and argv[4]=='--output' and argv[6] in self.containers
            archive(Path(argv[5]),self.tar_rows)
            return self.result(step,argv,timeout,b'',expected)
        return super().run(step,argv,timeout,expected)

class MaterializeControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='qt3-materialize-MODEL-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
    def unpack(self,rows,**kwargs):
        source=archive(self.root/'MODEL.tar',rows)
        return M.unpack_view(source,self.root/'view',deadline=time.monotonic()+10,**kwargs)
    def test_regular_modes_literal_symlinks_and_forward_hardlinks(self):
        rows=[('usr',tarfile.DIRTYPE,b'',0o755),('usr/lib',tarfile.DIRTYPE,b'',0o755),
              ('usr/lib/alias.a',tarfile.LNKTYPE,'usr/lib/real.a',0o644),
              ('usr/lib/real.a',tarfile.REGTYPE,b'MODEL_STATIC',0o644),
              ('lib',tarfile.SYMTYPE,'/usr/lib',0o777),
              ('relative',tarfile.SYMTYPE,'usr/lib',0o777),
              ('literal[,\\name',tarfile.REGTYPE,b'LITERAL',0o600)]
        data=self.unpack(rows);root=self.root/'view'
        self.assertTrue(data['data_only']);self.assertEqual(data['members'],7)
        self.assertEqual(os.readlink(root/'lib'),'/usr/lib')
        self.assertEqual(os.readlink(root/'relative'),'usr/lib')
        self.assertEqual((root/'literal[,\\name').read_bytes(),b'LITERAL')
        self.assertEqual((root/'usr/lib/alias.a').stat().st_ino,(root/'usr/lib/real.a').stat().st_ino)
        self.assertEqual((root/'usr/lib/real.a').stat().st_mode&0o777,0o644)
    def test_logical_target_no_host_resolution_and_escape_refused(self):
        self.assertEqual(M.link_target('usr/lib/link','/usr/lib/target'),'usr/lib/target')
        self.assertEqual(M.link_target('usr/lib/link','../target'),'usr/target')
        self.assertEqual(M.link_target('any/alias','usr/lib/target',hard=True),'usr/lib/target')
        for target in ('../../../../etc/passwd','/../../etc/passwd'):
            with self.assertRaises(ValueError):M.link_target('usr/lib/link',target)
    def test_traversal_absolute_control_and_duplicate_members_refuse(self):
        for i,name in enumerate(('../escape','/absolute','usr/../escape','a\nb')):
            source=archive(self.root/('bad'+str(i)),[(name,tarfile.REGTYPE,b'x',0o644)])
            with self.assertRaises(ValueError):M.unpack_view(source,self.root/('view'+str(i)),deadline=time.monotonic()+10)
        with self.assertRaises(ValueError):self.unpack([('same',tarfile.REGTYPE,b'x',0o644),('same',tarfile.REGTYPE,b'y',0o644)])
    def test_special_members_and_link_parent_write_refused(self):
        for i,kind in enumerate((tarfile.FIFOTYPE,tarfile.CHRTYPE,tarfile.BLKTYPE)):
            source=archive(self.root/('special'+str(i)),[('node',kind,b'',0o600)])
            with self.assertRaises(ValueError):M.unpack_view(source,self.root/('view-special'+str(i)),deadline=time.monotonic()+10)
        with self.assertRaises((ValueError,OSError)):
            self.unpack([('link',tarfile.SYMTYPE,'/usr/lib',0o777),('link/child',tarfile.REGTYPE,b'unsafe',0o644)])
    def test_missing_hardlink_cycles_bounds_and_deadlines_refuse(self):
        for i,rows in enumerate(([('missing',tarfile.LNKTYPE,'absent',0o644)],
                                 [('a',tarfile.LNKTYPE,'b',0o644),('b',tarfile.LNKTYPE,'a',0o644)])):
            source=archive(self.root/('links'+str(i)),rows)
            with self.assertRaises(ValueError):M.unpack_view(source,self.root/('view-links'+str(i)),deadline=time.monotonic()+10)
        source=archive(self.root/'bound.tar',[('file',tarfile.REGTYPE,b'MODEL',0o644)])
        for i,args in enumerate((dict(byte_cap=4),dict(member_cap=0),dict(deadline=0))):
            with self.assertRaises(ValueError):M.unpack_view(source,self.root/('view-bound'+str(i)),**(dict(deadline=time.monotonic()+10)|args))
    def test_file_reference_actual_hash_cap_alias_hardlink_and_fifo(self):
        p=self.root/'body';p.write_bytes(b'MODEL')
        self.assertEqual(M.file_reference(p,deadline=time.monotonic()+10),dict(path=str(p),**H.pin(b'MODEL')))
        for args in (dict(cap=4,deadline=time.monotonic()+10),dict(deadline=0)):
            with self.assertRaises(ValueError):M.file_reference(p,**args)
        alias=self.root/'alias';alias.symlink_to(p)
        with self.assertRaises(ValueError):M.file_reference(alias,deadline=time.monotonic()+10)
        hard=self.root/'hard';os.link(p,hard)
        with self.assertRaises(ValueError):M.file_reference(p,deadline=time.monotonic()+10)
        fifo=self.root/'fifo';os.mkfifo(fifo)
        with self.assertRaises(ValueError):M.file_reference(fifo,deadline=time.monotonic()+10)
    def runtime(self,mutation=None,tar_rows=None):
        f=B.F.Fixture(self.root)
        module=B.F.I.held(f.root,'image_current_v3.py')
        c=dict(nonce='a'*64,stage='qt3',delegation_pin=H.pin(b'UNISSUED_MODEL'),
               binding=dict(source='b'*40,ref='refs/heads/codex/MODEL',run='123',job='456',attempt=1,source_lock=H.pin(b'MODEL_SOURCE')))
        d=dict(capability=dict(total_seconds=600,max_command_seconds=300,command_rows=512),expires_epoch=int(time.time())+600)
        rows=tar_rows if tar_rows is not None else [('usr',tarfile.DIRTYPE,b'',0o755),('usr/MODEL',tarfile.REGTYPE,b'MODEL_IMAGE_DATA',0o644)]
        e=ExportExecutor(module,f,rows,c,mutation)
        image='sha256:'+'c'*64
        labels={module.LABEL+'.nonce':c['nonce'],module.LABEL+'.source':c['binding']['source'],module.LABEL+'.stage':c['stage']}
        e.images[image]=dict(Id=image,Os='linux',Architecture='arm64',Config=dict(Labels=labels))
        inventory=f.put('MODEL/final.inventory.lock',module.lock(f.expected))
        report=dict(status='PROVISIONAL_CURRENT_IMAGE_CONSTRUCTED_DATA_ONLY',binding=c['binding'],owner_executor_facts=copy.deepcopy(e.facts),cleanup={'errors':[]},image_id=image,packages=f.expected,inventory_pin=inventory)
        kwargs=dict(source_root=f.root,image_report=report,delegation=d,context=c,policy={},catalog_reference=f.request['catalog'],executor=e,output=self.root/'export')
        return e,kwargs
    def test_materialize_uses_actual_held_build_probe_export_and_retirement(self):
        e,kwargs=self.runtime()
        value,path=M.materialize_image(**kwargs)
        self.assertEqual(value['status'],'PASS_PRIVATE_IMAGE_DATA_ONLY')
        self.assertEqual(value['image']['inventory']['sha256'],H.EXPECTED477['sha256'])
        self.assertEqual(value['lifetime']['work_deadline_monotonic'],e.deadline)
        self.assertEqual(e.containers,{})
        self.assertEqual(set(e.images),{value['image']['id']})
        self.assertGreaterEqual(e.alive_calls,2)
        self.assertTrue(path.is_file())
        self.assertEqual((Path(value['filesystem']['root'])/'usr/MODEL').read_bytes(),b'MODEL_IMAGE_DATA')
        self.assertTrue(any(step=='export-image-data' for step,argv in e.commands))
        self.assertTrue(any(step.startswith('remove-') for step,argv in e.commands))
        self.assertIsNone(value['Root_final_acceptance'])
    def test_non_natural_actual_probe_refuses_and_owned_actor_retires(self):
        def mutate(step,row,e):
            if step=='start-probe':row['supervision']['timeout']=True
        e,kwargs=self.runtime(mutate)
        with self.assertRaises(ValueError):M.materialize_image(**kwargs)
        self.assertEqual(e.containers,{})
        self.assertFalse((kwargs['output']/'image-receipt.json').exists())
    def test_malformed_export_refuses_after_real_probe_and_cleanup(self):
        e,kwargs=self.runtime(tar_rows=[('../escape',tarfile.REGTYPE,b'x',0o644)])
        with self.assertRaises(ValueError):M.materialize_image(**kwargs)
        self.assertEqual(e.containers,{})
        self.assertFalse((kwargs['output']/'image-receipt.json').exists())
    def test_changed_image_facts_refuse_before_first_command(self):
        e,kwargs=self.runtime();kwargs['image_report']['owner_executor_facts']['engine_id']='different'
        with self.assertRaises(ValueError):M.materialize_image(**kwargs)
        self.assertEqual(e.commands,[])
    def test_inventory_file_tamper_blocks_receipt_after_cleanup(self):
        e,kwargs=self.runtime()
        Path(kwargs['image_report']['inventory_pin']['path']).write_bytes(b'changed actual inventory file')
        with self.assertRaises(ValueError):M.materialize_image(**kwargs)
        self.assertEqual(e.containers,{})
        self.assertFalse((kwargs['output']/'image-receipt.json').exists())

if __name__=='__main__':unittest.main()

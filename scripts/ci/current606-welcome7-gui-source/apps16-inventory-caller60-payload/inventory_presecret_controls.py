# SPDX-License-Identifier: MIT
"""Preserve all six original default35 controls AND explicit VM60 controls."""
import ast,base64,hashlib,importlib.util,json,os,types,unittest
from pathlib import Path
CALL=" load('_fixed_caller60_presecret_controls',D/'inventory_presecret_controls.py').run(globals())\n"
OLD=' unittest.main(verbosity=2)\n'
EDITS=(("self.assertEqual(calls[0][1]['timeout'],35)","self.assertEqual(calls[0][1]['timeout'],60)"),("self.assertEqual(kw['timeout'],35)","self.assertEqual(kw['timeout'],60)"))
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path):
 path=Path(path);need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary source-control input');s=path.lstat();need(__import__('stat').S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=16*1024**2,'bounded source-control input');raw=path.read_bytes();t=path.lstat();fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');need(len(raw)==s.st_size and all(getattr(s,k)==getattr(t,k)for k in fields),'whole stable source-control input');return raw
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def run(namespace):
 root=Path(namespace['__file__']).resolve().parent;parent=json.loads(read(root/'caller60-presecret-parent.json'));before=base64.b64decode(parent['before_bodies']['apps16_common.py'],validate=True);need(pin(before)==parent['files']['apps16_common.py']and before.count(OLD.encode())==1 and read(root/'apps16_common.py')==before.replace(OLD.encode(),CALL.encode(),1),'entire original source controls outside one main delegation')
 cp=json.loads(read(root/'inventory-vm-parent.json'));default=base64.b64decode(cp['before_bodies']['factory/current_products.py'],validate=True);cap=load('_exact_source_owned_inventory60_capacity',root/'factory/inventory_capacity.py');need(pin(default)==cap.profile()['original_helpers']['current_products.py'],'whole original default35 harness');selected=namespace['P'];need(selected.__dict__.get('_vm_inventory_capacity_installed')is True,'actual source-selected60 wrapper already installed')
 old=types.ModuleType('_whole_original_default35_current_products');old.__file__=str(root/'factory/current_products.py');exec(compile(default,old.__file__,'exec'),vars(old));tree=ast.parse(before);main=next(n for n in tree.body if isinstance(n,ast.If)and ast.get_source_segment(before.decode(),n.test)=="__name__=='__main__'");node=next(n for n in main.body if isinstance(n,ast.ClassDef)and n.name=='Controls');original=ast.get_source_segment(before.decode(),node);text=original
 for a,b in EDITS:need(text.count(a)==1,'one exact profile-specific timeout assertion');text=text.replace(a,b,1)
 inverse=text
 for a,b in reversed(EDITS):need(inverse.count(b)==1,'one exact original control inverse');inverse=inverse.replace(b,a,1)
 need(inverse==original,'entire original six-control class inverse')
 suite=unittest.TestSuite();loader=unittest.TestLoader()
 for name,source,products,schema in(('_held_default35_suite',original,old,namespace['S']),('_explicit_VM_caller60_suite',text,selected,cap.diagnostic())):
  scope=dict(namespace,__name__=name,P=products,S=schema);exec(compile(source,str(root/'apps16_common.py'),'exec'),scope);suite.addTests(loader.loadTestsFromTestCase(scope['Controls']))
 class FixedProfile(unittest.TestCase):
  def test_explicit_profile65_and_unchanged_default40_private_stage_FD(self):
   value=cap.profile();self.assertEqual((value['caller_seconds'],value['product_scan_seconds'],value['default_caller_seconds']),(60,30,35));self.assertEqual(value['profile'],'GUI_TCG_INVENTORY_CALLER_60_V1');self.assertIsNone(value['actual']);self.assertFalse(value['acceptance'])
   import tempfile
   with tempfile.TemporaryDirectory(dir=root)as td:
    home=Path(td);leaf=home/'inventory.json.stage.json';doc=dict(schema=1,status='DONE',phase='DONE',sequence=14,elapsed_seconds=55,authority='DIAGNOSTIC_ONLY_NOT_ACCEPTANCE');raw=(json.dumps(doc,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode();leaf.write_bytes(raw);leaf.chmod(0o600);fd=os.open(home,os.O_RDONLY|os.O_DIRECTORY)
    try:
     with self.assertRaises(ValueError):namespace['S'].retire(fd,home,leaf.name)
     self.assertTrue(leaf.exists());result=cap.diagnostic().retire(fd,home,leaf.name);self.assertTrue(result['retired']);self.assertEqual(result['file'],pin(raw));self.assertFalse(leaf.exists())
     for seconds in(65.001,True,float('inf')):
      with self.assertRaises(ValueError):cap.diagnostic().validate(dict(doc,elapsed_seconds=seconds))
    finally:os.close(fd)
 suite.addTests(loader.loadTestsFromTestCase(FixedProfile));result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(0 if result.wasSuccessful()else 1)

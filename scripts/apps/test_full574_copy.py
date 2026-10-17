# SPDX-License-Identifier: MIT
"""Real inert temporary copies and modeled mount metadata; no native acceptance."""
import contextlib,hashlib,importlib.util,io,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
sys.path.insert(0,str(ROOT/'scripts/update'))
spec=importlib.util.spec_from_file_location('scoped574_test',HERE/'full574_copy.py');S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)

def rows(source=b'/seed',work=b'/work',device=b'8:1',a=b'/owner/data/original574',b=b'/owner/work'):
    return b'11 1 '+device+b' '+a+b' '+source+b' ro,relatime - ext4 /dev/root rw\n12 1 '+device+b' '+b+b' '+work+b' rw,relatime - ext4 /dev/root rw\n'

def limits():return S.roots.Limits(deadline=time.monotonic()+20,max_nodes=100,max_bytes=1024**2,max_file_bytes=1024**2)

class Controls(unittest.TestCase):
    def setUp(self):
        guard=patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden'));guard.start();self.addCleanup(guard.stop)
    def test_disjoint_backing_roots_keep_distinct_mount_ids(self):
        result=S._rows(rows(),11,12,(8,1))
        self.assertEqual([r['mount_id'] for r in result],[11,12]);self.assertEqual([r['root'] for r in result],['/owner/data/original574','/owner/work'])
    def test_alias_ancestor_and_descendant_backing_roots_refuse(self):
        for a,b in [(b'/owner/work',b'/owner/work'),(b'/owner',b'/owner/work'),(b'/owner/work/root',b'/owner/work')]:
            with self.subTest(a=a,b=b),self.assertRaisesRegex(ValueError,'backing bind roots overlap'):S._rows(rows(a=a,b=b),11,12,(8,1))
    def test_missing_foreign_duplicate_nested_and_unsafe_mount_records_refuse(self):
        good=rows()
        for raw in (good.splitlines(True)[0],good+good.splitlines(True)[0],good.replace(b'/seed ',b'/other '),good.replace(b'/owner/data/original574',b'/owner/../data'),good.replace(b'/owner/data/original574',b'/owner/data\\040escape'),good.replace(b' ro,',b' rw,'),good.replace(b'12 1 8:1',b'12 1 8:2'),good.replace(b'- ext4 /dev/root rw\n',b'- xfs /dev/foreign rw\n',1),good+b'13 12 8:1 /other /work/child rw - ext4 /dev/root rw\n',good.replace(b' - ',b' invalid ')):
            with self.subTest(raw=raw),self.assertRaises(ValueError):S._rows(raw,11,12,(8,1))
        with self.assertRaises(ValueError):S._rows(good,11,11,(8,1))
    def test_proc_input_has_finite_byte_and_row_bounds(self):
        for raw in (b'x'*(4*1024**2+1),):
            with patch.object(Path,'open',return_value=io.BytesIO(raw)),self.assertRaisesRegex(ValueError,'byte bound'):S._mountinfo(limits())
        with self.assertRaisesRegex(ValueError,'row bound'):S._rows(b'\n'*32769,11,12,(8,1))
    @contextlib.contextmanager
    def fixture(self):
        with tempfile.TemporaryDirectory(prefix='apps-bind-scope-') as temporary:
            base=Path(temporary);source=base/'seed';work=base/'work';source.mkdir();work.mkdir(mode=0o700);parent=work/'main';parent.mkdir(mode=0o700)
            (source/'child').mkdir();(source/'child/a').write_bytes(b'inert never executed');os.link(source/'child/a',source/'child/b');(source/'relative').symlink_to('child/a')
            def mounted(fd,budget):
                budget.tick();name=Path(os.readlink('/proc/self/fd/'+str(fd)))
                return 11 if name==source or name.is_relative_to(source) else 12 if name==work or name.is_relative_to(work) else 99
            fstatvfs=os.fstatvfs
            def readonly(fd):
                value=fstatvfs(fd);name=Path(os.readlink('/proc/self/fd/'+str(fd)))
                fields=list(value);fields[8]=value.f_flag|os.ST_RDONLY
                return os.statvfs_result(fields) if name==source or name.is_relative_to(source) else value
            device=source.stat().st_dev;raw=rows(bytes(source),bytes(work),('%d:%d'%(os.major(device),os.minor(device))).encode())
            with patch.object(S,'SOURCE',source),patch.object(S,'WORK',work),patch.object(S,'_mountinfo',return_value=raw),patch.object(S.roots,'_mount_id',side_effect=mounted),patch.object(os,'fstatvfs',side_effect=readonly):yield source,work,parent,raw
    def test_held_named_identity_readonly_and_scope_changes_refuse(self):
        with self.fixture() as (source,work,parent,raw),S.aux_copy.measure_copy._descriptors() as held:
            src=S.roots._open_root(source);held.append(src);dst=S.roots._open_root(parent);held.append(dst);scope=S.Scope(held)
            scope.start(src,dst,source,parent,11,12,limits());scope.check();self.assertEqual(scope.checks,2)
            with patch.object(S,'_mountinfo',return_value=raw.replace(b'relatime',b'noatime')),self.assertRaisesRegex(ValueError,'scope changed'):scope.check()
            with patch.object(os,'fstatvfs',return_value=SimpleNamespace(f_flag=0)),self.assertRaisesRegex(ValueError,'readonly source'):scope.check()
            parent.rename(work/'old');parent.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError,'named/held'):scope.check()
    def test_scope_refuses_other_destination_and_closes_all_duplicate_fds(self):
        with self.fixture() as (source,work,parent,raw):
            before=len(os.listdir('/proc/self/fd'))
            with S.aux_copy.measure_copy._descriptors() as held:
                src=S.roots._open_root(source);held.append(src);dst=S.roots._open_root(parent);held.append(dst)
                with self.assertRaisesRegex(ValueError,'fixed leased'):S.Scope(held).start(src,dst,source,work/'unknown',11,12,limits())
            self.assertEqual(before,len(os.listdir('/proc/self/fd')))
    def binding(self,budget):
        # Only the synthetic plain-data tree uses the original strict facade;
        # the production Apps binding still adds its exact link/aux policy.
        return S.aux_copy._isolated(S.aux_copy.measure_copy.__file__,S.aux_copy.COPY_SHA256)
    def test_real_inert_copy_preserves_bytes_links_and_generic_refusal(self):
        with self.fixture() as (source,work,parent,raw):
            target=parent/'root';before=S.roots.observe(source,limits=limits(),hardlinks='generic-development-internal')['nodes'];fds=len(os.listdir('/proc/self/fd'))
            with self.assertRaisesRegex(ValueError,'ambiguous copy bind scope'):S.aux_copy.measure_copy.copy_data(source,target,limits=limits(),hardlinks='generic-development-internal')
            self.assertFalse(target.exists())
            with patch.object(S.aux_copy,'_copy_binding',side_effect=self.binding):result=S.copy_data(source,target,limits=limits())
            self.assertEqual(S.roots.observe(target,limits=limits(),hardlinks='generic-development-internal')['nodes'],before)
            self.assertEqual((target/'child/a').stat().st_ino,(target/'child/b').stat().st_ino);self.assertNotEqual((target/'child/a').stat().st_ino,(source/'child/a').stat().st_ino)
            self.assertEqual(os.readlink(target/'relative'),'child/a');self.assertEqual(result['apps_bind_scope']['checkpoints'],7);self.assertEqual(fds,len(os.listdir('/proc/self/fd')))
            self.assertEqual(result['apps_bind_scope']['original_copier_sha256'],S.aux_copy.COPY_SHA256)
    def test_drift_during_copy_refuses_and_closes_fds(self):
        with self.fixture() as (source,work,parent,raw):
            before=len(os.listdir('/proc/self/fd'));calls=[]
            def changed(budget):
                calls.append(True);return raw if len(calls)<4 else raw.replace(b'relatime',b'noatime')
            with patch.object(S.aux_copy,'_copy_binding',side_effect=self.binding),patch.object(S,'_mountinfo',side_effect=changed),self.assertRaisesRegex(ValueError,'scope changed'):S.copy_data(source,parent/'root',limits=limits())
            self.assertTrue((parent/'root/child/a').is_file())
            self.assertEqual((source/'child/a').read_bytes(),b'inert never executed')
            self.assertEqual(before,len(os.listdir('/proc/self/fd')))
    def test_original_source_pin_and_exact_guard_are_mandatory(self):
        with self.fixture() as (source,work,parent,raw),patch.object(S.aux_copy,'COPY_SHA256','0'*64),self.assertRaisesRegex(ValueError,'copier-source-pin'):S.copy_data(source,parent/'root',limits=limits())
        actual=Path(S.aux_copy.measure_copy.__file__).read_bytes();self.assertEqual(actual.count(S.ANCHOR),1)
        self.assertEqual(hashlib.sha256(actual).hexdigest(),S.aux_copy.COPY_SHA256)
        with self.fixture() as (source,work,parent,raw),patch.object(S,'ANCHOR',b'absent exact predicate'),self.assertRaisesRegex(ValueError,'exact original copier'):S.copy_data(source,parent/'root',limits=limits())

if __name__=='__main__':unittest.main(verbosity=2)

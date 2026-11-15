# SPDX-License-Identifier: MIT
"""Focused DATA/refusal controls; no downloads, daemon, guest or installation."""
import hashlib,io,json,os,resource,tarfile,tempfile,unittest
from pathlib import Path
import plan as P
HERE=Path(__file__).resolve().parent
BASE=json.loads((HERE/'baseline111.json').read_text());CONTRACT=json.loads((HERE/'inputs.json').read_text())
def reference(path):return {'path':str(path),'bytes':path.stat().st_size,'sha256':P.sha(path)}
class Controls(unittest.TestCase):
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name)
    def archive(self,arch='any',prefix=False,linked=False):
        path=self.work/'fixture.pkg.tar';body=('pkgname = fixture\npkgver = 1-1\narch = '+arch+'\ndepend = python>=3.11\n').encode()
        with tarfile.open(path,'w')as archive:
            if prefix:
                m=tarfile.TarInfo('large-first');m.size=300*1024;archive.addfile(m,io.BytesIO(b'0'*m.size))
            m=tarfile.TarInfo('.PKGINFO')
            if linked:m.type=tarfile.SYMTYPE;m.linkname='/etc/passwd';archive.addfile(m)
            else:m.size=len(body);archive.addfile(m,io.BytesIO(body))
        return path
    def test_actual111_metadata_is_pinned_and_frozen(self):
        ref=CONTRACT['baseline'];path=HERE/ref['filename'];self.assertEqual(path.stat().st_size,ref['bytes']);self.assertEqual(P.sha(path),ref['sha256'])
        rows=P.anchor_rows(BASE);self.assertEqual(len(rows),111);versions={r['name']:r['version']for r in rows}
        self.assertEqual(versions['glib2'],'2.88.3-1');self.assertEqual(versions['systemd'],'261.2-1');self.assertNotIn('python',versions)
        self.assertTrue(all(r['archive']is None for r in rows))
    def test_baseline_descriptor_drift_refused(self):
        value=json.loads(json.dumps(BASE));value['packages'][0]['version']='changed'
        with self.assertRaises(AssertionError):P.anchor_rows(value)
    def test_existing_resolver_protects_actual_baseline_version(self):
        R=P.load('test_ARM_existing_resolver',P.ROOT/'scripts/port/platform-residual-closure/resolve.py');anchors=P.anchor_rows(BASE);protected={r['name']:r['version']for r in anchors}
        row={'name':'glib2','version':'2.90.1-1','repo':'extra','arch':'aarch64','depends':[],'provides':[],'conflicts':[],'replaces':[],'archive':None,'files':None,'hooks':None,'review':None}
        result=R.resolve(anchors,[row],[{'name':'glib2','version':'2.90.1-1','repo':'extra'}],protected)
        self.assertTrue(any(v['code']=='protected-replacement'for v in result['blockers']));self.assertEqual(next(v['version']for v in result['selected']if v['name']=='glib2'),'2.88.3-1')
    def test_metadata_prefix_never_executes_payload(self):
        path=self.archive();meta,evidence=P.package_metadata(path);self.assertEqual(meta['arch'],['any']);self.assertLessEqual(evidence['compressed_prefix_bytes_read'],256*1024)
        self.assertFalse((self.work/'executed').exists())
    def test_large_prefix_and_linked_metadata_refused(self):
        with self.assertRaises(AssertionError):P.package_metadata(self.archive(prefix=True))
        with self.assertRaises(AssertionError):P.package_metadata(self.archive(linked=True))
    def test_candidate_requires_real_any_arch_hash_srcinfo_relations(self):
        parser=P.load('test_ARM_existing_srcinfo',P.ROOT/'scripts/port/supported-composition/compose.py');src=self.work/'.SRCINFO';src.write_text('pkgbase = fixture\npkgname = fixture\npkgver = 1\npkgrel = 1\narch = any\ndepends = python>=3.11\n');sig=self.work/'signature';sig.write_bytes(b'public signature DATA only')
        path=self.archive();ref={'archive':reference(path),'signature':reference(sig),'srcinfo':reference(src),'scope':'synthetic parser fixture; NOT authenticated'}
        row,evidence=P.candidate(ref,parser);self.assertEqual(row['arch'],'any');self.assertEqual(evidence['identity_arch_relations_hash_check'],'PASS');self.assertIn('NOT RUN',evidence['signature_authentication'])
        path=self.archive(arch='x86_64');ref['archive']=reference(path)
        with self.assertRaises(AssertionError):P.candidate(ref,parser)
    def test_exact_hash_and_unaliased_data_required(self):
        path=self.work/'input';path.write_bytes(b'public DATA');ref=reference(path);self.assertEqual(P.bound(ref),b'public DATA');path.write_bytes(b'altered')
        with self.assertRaises(AssertionError):P.bound(ref)
        path.unlink();path.symlink_to('/etc/passwd')
        with self.assertRaises(AssertionError):P.bound(ref)
    def test_wrong_cache_metadata_is_held_not_available(self):
        path=self.archive(arch='x86_64');row={'name':'fixture','version':'1-1','arch':'aarch64','depends':['python>=3.11'],'archive':{'filename':path.name,'bytes':path.stat().st_size,'sha256':P.sha(path),'signature_bytes':1,'signature_sha256':'a'*64}}
        result=P.retained(row,[self.work],1024**2);self.assertEqual(result[0]['status'],'HOLD_RETAINED_REFUSAL')
    def test_real_private_libalpm_boundary_or_explicit_tool_hold(self):
        # Exact retained baseline DATA, no new packages/archives/commit.
        old=resource.getrlimit(resource.RLIMIT_AS)
        supported=False
        try:
            source=P.load('test_ARM_existing_abi',P.ROOT/'scripts/platform/transaction.py');supported=source.Alpm().version=='16.0.1'
        except (OSError,ValueError):pass
        try:result=P.prepare_proposal(P.anchor_rows(BASE),[])
        finally:resource.setrlimit(resource.RLIMIT_AS,old)
        if supported and result['status']!='PASS_EXPLICIT_FINITE_METADATA_PREPARE':
            # Standalone CPython3.12 plus ICU can exceed the fixed96MiB child
            # address-space cap. This must be a named tool/memory HOLD, never
            # an alternative resolver or an ignored arbitrary worker failure.
            detail=json.loads(result['diagnostic']);self.assertEqual(detail['category'],'OSError');self.assertIn('failed to map segment',detail['message'])
        if result['status']=='PASS_EXPLICIT_FINITE_METADATA_PREPARE':
            self.assertEqual(result['prepare']['libalpm_version'],'16.0.1');self.assertEqual(result['final_count'],111);self.assertFalse(result['prepare']['add']);self.assertFalse(result['prepare']['remove'])
        else:self.assertTrue(result['status'].startswith('HOLD_'))
    def test_phased_memory_and_no_commit_api(self):
        source=(HERE/'prepare_metadata.py').read_text();self.assertIn('96*1024**2',source);self.assertIn('T.prepare(',source);self.assertNotIn('alpm_trans_commit',source)
        parent=(HERE/'plan.py').read_text();self.assertIn('160*1024**2',parent);self.assertIn('256*1024**2',parent)
if __name__=='__main__':unittest.main()

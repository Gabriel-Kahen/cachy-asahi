"""Closed public export controls with synthetic metadata; no native actors."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import caller as C


def life():
    rows=[dict(home='product-home-'+kind,no_overwrite='PASS',report_mode='0600',report_sha256='d'*64,
        welcome=dict(architecture='aarch64',page_size=4096,hardware_compatibility='not-assessed'),
        doctor=dict(tool=C.NAMES[1],scope='local observations only',version='0.2.0',checks=[dict(check='audio/default-output',state='unavailable',value=None)])) for kind in ('fresh','existing')]
    return dict(status='PASS_PRODUCTS_INSTALLED_CLI_LIFECYCLE',base_count=574,installed_count=576,
        user_config_preserved=True,user_reports_preserved=True,GUI='NOT_RUN',hardware='NOT_RUN',actual_page_size=4096,
        events=[dict(phase=name,status='PASS',inventory_count=count,config_preserved=True,**(
            dict(observations=rows) if count==576 else dict(reports_preserved=True)))
            for name,count in (('install',576),('same-version-reinstall',576),('remove',574),('reinstall-after-removal',576),('final-remove',574))])


class Caller(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
    def fixture(self):
        base=self.root/'base';runtime=self.root/'runtime';base.mkdir();runtime.mkdir();proof=self.root/'proof.json'
        proof.write_text(json.dumps(dict(status='SOURCE_PROOF_PASS',job_token='a'*16)))
        image='sha256:'+'b'*64
        original=dict(status='PASS_NATIVE_OFFLINE_574_TRANSACTION',image=image,ownership=dict(token='a'*16),
            owned_cleanup=dict(status='PASS',image=dict(id=image,absence_verified=True),probe=dict(absence_verified=True)))
        (base/'report.json').write_text(json.dumps(original));(base/'installed-packages.lock').write_text('fixture 1\n')
        report=dict(status='PASS_NATIVE_PRODUCTS_PAIR_CONTENTS_AND_INSTALLED_CLI_LIFECYCLE',base_image=image,base_count=574,
            lifecycle=life(),products={},cleanup=[dict(container='cachy-asahi-product-'+format(i,'032x'),status='PASS',absence_verified=True) for i in range(6)])
        for row in report['cleanup']:(runtime/('cleanup-'+row['container']+'.log')).write_text('retired\n')
        for product in C.NAMES:
            arch='aarch64' if product==C.NAMES[0] else 'any';name=product+('-0.2.0-1-'if product==C.NAMES[1]else'-0.1.0-1-')+arch+'.pkg.tar.xz'
            comparison=dict(status='contents-reproduced',errors=[],packages={name:dict(bytes_equal=False,installed_contents_equal=True)})
            (runtime/(product+'-comparison.json')).write_text(json.dumps(comparison));builds=[]
            for side in ('a','b'):
                directory=runtime/(product+'-'+side);(directory/'artifacts').mkdir(parents=True)
                for f in ('provenance.json','validation.json'):(directory/f).write_text('{}')
                (directory/'build.log').write_text('bounded native diagnostic\n');(directory/'expected-packages.lock').write_text('fixture 1\n')
                for f in ('environment.txt','packages.lock','config.sha256','makepkg.conf','pacman.conf','generated.SRCINFO'):
                    (directory/'artifacts'/f).write_text('fixture\n')
                archive=directory/'artifacts'/name;archive.write_bytes(b'synthetic archive bytes')
                builds.append(dict(archive=name,sha256=C.digest(archive)))
            report['products'][product]=dict(comparison=comparison,builds=builds)
        (runtime/'lifecycle.json').write_text(json.dumps(life()));(runtime/'report.json').write_text(json.dumps(report))
        (runtime/'private').mkdir();(runtime/'private/secret').write_text('excluded')
        return base,runtime,proof,original,report

    def test_exact_source_workflow_native_runner_and_source_file_pins(self):
        file=self.root/'source';file.write_text('fixed');manifest=dict(files={'source':dict(bytes=5,sha256=C.digest(file))})
        env=dict(SOURCE_SHA='a'*40,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,RUNNER_ARCH='ARM64',RUNNER_OS='Linux',GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1')
        self.assertEqual(C.prove(self.root,manifest,env)['status'],'SOURCE_PROOF_PASS')
        for change in (dict(GITHUB_WORKFLOW_SHA='b'*40),dict(RUNNER_ARCH='X64'),dict(SOURCE_SHA='main')):
            with self.assertRaises(ValueError):C.prove(self.root,manifest,env|change)
        file.write_text('drift')
        with self.assertRaises(ValueError):C.prove(self.root,manifest,env)

    def test_closed_export_retains_four_unsigned_candidates_and_explicit_byte_difference(self):
        base,runtime,proof,_,_=self.fixture();out=self.root/'public';result=C.retain(base,runtime,proof,out)
        self.assertEqual(result['status'],'PASS_NATIVE_PRODUCT_CANDIDATES_CLI_LIFECYCLE')
        self.assertEqual(len(list((out/'packages').rglob('*.pkg.tar.xz'))),4)
        self.assertFalse((out/'runtime/private').exists());self.assertEqual(result['hardware'],'NOT_RUN')
        self.assertTrue(all(not next(iter(row.values()))['bytes_equal'] for row in result['reproducibility'].values()))

    def test_missing_build_log_cannot_accept_native_pair(self):
        base,runtime,proof,_,_=self.fixture();(runtime/(C.NAMES[0]+'-a')/'build.log').unlink()
        self.assertEqual(C.retain(base,runtime,proof,self.root/'public')['status'],'NOT_ACCEPTED')

    def test_candidate_archive_hash_drift_refuses(self):
        base,runtime,proof,_,report=self.fixture();report['products'][C.NAMES[0]]['builds'][0]['sha256']='0'*64
        (runtime/'report.json').write_text(json.dumps(report))
        self.assertEqual(C.retain(base,runtime,proof,self.root/'public')['status'],'NOT_ACCEPTED')

    def test_builder_original_cleanup_is_required(self):
        base,runtime,proof,original,_=self.fixture();original['owned_cleanup']['image']['absence_verified']=False
        (base/'report.json').write_text(json.dumps(original))
        self.assertEqual(C.retain(base,runtime,proof,self.root/'public')['status'],'NOT_ACCEPTED')

    def test_six_cleanup_absences_and_complete_lifecycle_are_required(self):
        base,runtime,proof,_,report=self.fixture();report['cleanup'][0]['absence_verified']=False
        (runtime/'report.json').write_text(json.dumps(report))
        self.assertEqual(C.retain(base,runtime,proof,self.root/'public')['status'],'NOT_ACCEPTED')

    def test_missing_or_unordered_lifecycle_phase_refuses(self):
        base,runtime,proof,_,report=self.fixture();report['lifecycle']['events'].reverse()
        (runtime/'report.json').write_text(json.dumps(report))
        self.assertEqual(C.retain(base,runtime,proof,self.root/'public')['status'],'NOT_ACCEPTED')

    def test_symlink_extra_archive_and_total_cap(self):
        base,runtime,proof,_,_=self.fixture();extra=runtime/(C.NAMES[0]+'-a')/'artifacts/unrelated.pkg.tar.xz';extra.write_bytes(b'excluded')
        with patch.object(C,'MAX_TOTAL',100):result=C.retain(base,runtime,proof,self.root/'public')
        self.assertEqual(result['status'],'NOT_ACCEPTED');self.assertLessEqual(result['total_bytes'],100)
        self.assertFalse(any('unrelated' in name for name in result['files']))
        alias=self.root/'alias';alias.symlink_to(proof)
        with self.assertRaises(ValueError):C.regular(alias,1024)


if __name__=='__main__':unittest.main()

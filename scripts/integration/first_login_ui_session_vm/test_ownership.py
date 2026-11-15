# SPDX-License-Identifier: MIT
"""Actual r4 DATA fixtures plus bounded source controls; no VM/host syncfs."""
import ast,gzip,hashlib,io,json,os,tarfile,tempfile,unittest
from pathlib import Path
import ownership as O
import receipts as R
HERE=Path(__file__).resolve().parent
F=json.loads((HERE/'ownership-fixture.json').read_text())

class OwnershipControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.file=self.root/F['path'].lstrip('/');self.file.parent.mkdir(parents=True);self.file.write_bytes(b'')
        original={k:v for k,v in F['expected_archive'].items()if k not in ['package','mtime']};original['mtime_ns']=F['expected_archive']['mtime']*10**9
        self.tree=O.mtree(gzip.compress(F['exact_mtree_excerpt'].encode()))[F['path']]
        self.index={('gtk3',F['path']):{'package':'gtk3','path':F['path'],'archive':original,'mtree':self.tree}}
    def test_actual_mtree_and_postretirement_stat_fixture(self):
        self.assertEqual(self.tree['size'],7978);self.assertEqual(self.tree['mode'],0o644)
        self.assertEqual(self.tree['sha256'],self.index[('gtk3',F['path'])]['archive']['sha256'])
        self.assertEqual(F['actual_stat']['size'],0);self.assertEqual(F['actual_hash']['sha256'],hashlib.sha256(b'').hexdigest())
        self.assertIn('does NOT identify live Qkk',F['scope'])
    def test_constructed_warning_from_actual_path_is_structured(self):
        # Format exercise; r2 live warning text was not retained and is NOT claimed.
        line=('warning: gtk3: '+F['path']+' (Size mismatch)\n').encode()
        value=O.analyze(b'gtk3: 100 total files, 1 altered file\n',line,1,self.index,self.root)
        self.assertTrue(value['HOLD']);self.assertEqual(value['warning_count'],1);self.assertEqual(value['altered_file_count'],1)
        detail=value['warnings'][0];self.assertEqual(detail['category'],'size-mismatch');self.assertEqual(detail['actual']['size'],0);self.assertEqual(detail['actual']['sha256'],F['actual_hash']['sha256'])
        self.assertNotIn('warning:',json.dumps(value))
    def test_unknown_and_user_path_output_never_exported(self):
        private=b'warning: gtk3: /home/builder/private-input (Size mismatch)\nPRIVATE_SENTINEL\n'
        value=O.analyze(b'',private,0,self.index,self.root)
        self.assertTrue(value['HOLD']);self.assertEqual(value['unknown_count'],2);self.assertFalse(value['warnings'])
        encoded=json.dumps(value);self.assertNotIn('PRIVATE_SENTINEL',encoded);self.assertNotIn('/home/builder',encoded)
        self.assertEqual(value['unknown'][1]['sha256'],hashlib.sha256(b'PRIVATE_SENTINEL').hexdigest())
    def test_zero_exit_cannot_erase_warnings_or_unknown_lines(self):
        ok=O.analyze(b'gtk3: 100 total files, 0 altered files\n',b'',0,self.index,self.root);self.assertFalse(ok['HOLD'])
        self.assertTrue(O.analyze(b'',b'',1,self.index,self.root)['HOLD'])
        warning=('warning: gtk3: '+F['path']+' (Permissions mismatch)\n').encode()
        self.assertTrue(O.analyze(b'',warning,0,self.index,self.root)['HOLD'])
    def test_symlink_parent_is_not_followed(self):
        root=self.root/'other';root.mkdir();(root/'usr').symlink_to(self.root/'usr')
        row=O.observe(F['path'],root);self.assertEqual(row,{'state':'read-refusal'})
        self.assertFalse(O.allowed('/etc/shadow'));self.assertFalse(O.allowed('/home/builder/value'));self.assertFalse(O.allowed('/usr/share/pacman/keyrings/key.gpg'))
    def test_diagnostics_are_schema_bounded_and_durable(self):
        owner=(os.getuid(),os.getgid());writer=R.Writer(self.root/'receipts','a'*32,owner);writer.phase('installed-check')
        line=('warning: gtk3: '+F['path']+' (Size mismatch)\n').encode();value=O.analyze(b'',line,1,self.index,self.root);O.persist(writer,value)
        record=json.loads((writer.path/'ownership-warning-000.json').read_text());self.assertEqual(record['actual']['size'],0)
        record['actual']['contents']='not allowed'
        with self.assertRaises(ValueError):writer.write('ownership-warning-001.json',record)
    def test_actual_empty_mtree_has_explicit_missing_metadata_warning(self):
        path='/var/lib/pacman/local/gtk3-1:3.24.52-2/mtree';self.index[('gtk3',path)]={'package':'gtk3','path':path,'archive':{'type':'file','size':F['retained_package_mtree']['bytes'],'sha256':F['retained_package_mtree']['sha256']},'mtree':None}
        value=O.analyze(b'',b'warning: gtk3: no mtree file\n',1,self.index,self.root)
        self.assertEqual(value['warnings'][0]['category'],'missing-mtree');self.assertEqual(value['warnings'][0]['actual']['state'],'missing-path')
    def test_pinned_archive_data_index_and_drift_refusal(self):
        folder=self.root/'archives';folder.mkdir();path=folder/'fixture.pkg.tar';content=b'ABC';meta=gzip.compress(('#mtree\n./usr/share/fixture type=file uid=0 gid=0 mode=644 size=3 time=1.0 sha256digest='+hashlib.sha256(content).hexdigest()+'\n').encode())
        with tarfile.open(path,'w')as archive:
            for name,raw in [('.MTREE',meta),('usr/share/fixture',content)]:
                item=tarfile.TarInfo(name);item.size=len(raw);item.mode=0o644;item.mtime=1;archive.addfile(item,io.BytesIO(raw))
        rows=[{'filename':path.name,'name':'fixture','version':'1-1','sha256':O.sha(path)}];destination=self.root/'index';descriptor=O.build_index(folder,rows,destination);loaded=O.load_index(destination,descriptor,{'fixture'})
        self.assertEqual(loaded[('fixture','/usr/share/fixture')]['archive']['size'],3);self.assertEqual(loaded[('fixture','/usr/share/fixture')]['archive']['sha256'],hashlib.sha256(content).hexdigest())
        shard=destination/descriptor['shards'][0]['filename'];shard.write_bytes(b'changed')
        with self.assertRaises(AssertionError):O.load_index(destination,descriptor,{'fixture'})
    def test_syncfs_failure_prevents_terminal_pass_signal(self):
        closed=[];signals=[]
        def refusal(fd):closed.append(fd);self.assertTrue(os.fstat(fd));raise OSError('owned fixture sync refusal')
        with self.assertRaises(OSError):O.signal_after_sync(lambda:O.sync_filesystem(self.root,primitive=refusal),lambda:signals.append('PASS'))
        self.assertEqual(signals,[])
        with self.assertRaises(OSError):os.fstat(closed[0])
        O.signal_after_sync(lambda:O.sync_filesystem(self.root,primitive=lambda _:None),lambda:signals.append('PASS'));self.assertEqual(signals,['PASS'])
    def test_actual_query_and_removal_argv_omit_download_only_option(self):
        # Evaluate only the actual trusted source's assignment/argv expressions.
        tree=ast.parse((HERE/'root_fixture.py').read_text())
        assignment=next(n for n in ast.walk(tree)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='pacman'for t in n.targets))
        namespace={'conf':Path('/private/pacman.conf'),'rows':[{'name':'fixture'}]}
        exec(compile(ast.Module(body=[assignment],type_ignores=[]),'actual-ALPM-argv','exec'),namespace)
        for label,operation in [('installed-ownership','-Qkk'),('trusted-remove','-R')]:
            call=next(n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='call'and n.args and isinstance(n.args[0],ast.Constant)and n.args[0].value==label)
            argv=eval(compile(ast.Expression(call.args[1]),'actual-ALPM-argv','eval'),namespace)
            self.assertEqual(argv,['pacman','--config','/private/pacman.conf','--noconfirm',operation,'fixture'])
            self.assertNotIn('--noprogressbar',argv)
    def test_live_unknown_hash_is_exact_public_cli_error_and_still_holds(self):
        fixture=json.loads((HERE/'cli-error-fixture.json').read_text());line=fixture['public_error_line_without_newline'].encode()
        self.assertEqual(len(line),39);self.assertEqual(hashlib.sha256(line).hexdigest(),fixture['sha256']);self.assertFalse(line.endswith(b'\n'))
        self.assertEqual(fixture['live_summary']['exit'],1);self.assertEqual(fixture['live_summary']['warning_count'],0);self.assertEqual(fixture['live_summary']['summary_count'],0)
        # Recognizing the source bug does not whitelist failed Qkk output.
        diagnostic=O.analyze(b'',line+b'\n',1,self.index,self.root)
        self.assertTrue(diagnostic['HOLD']);self.assertEqual(diagnostic['unknown_count'],1)

    def test_latest_runtime_pins_match(self):
        pins=json.loads((HERE/'validation.json').read_text())['latest_source_pins']
        for name,pin in pins.items():
            path=HERE/name;self.assertEqual(path.stat().st_size,pin['bytes']);self.assertEqual(O.sha(path),pin['sha256'])

    def test_flush_order_and_strict_live_qkk_gate_are_connected(self):
        source=(HERE/'root_fixture.py').read_text()
        self.assertLess(source.index("sync('post-install')"),source.index("call('installed-ownership'"))
        self.assertIn("if diagnostic['HOLD']:raise FixtureFailure('ownership-refusal')",source)
        self.assertIn("ownership.signal_after_sync(lambda:sync('terminal-pass'),lambda:publish('removed.json',report))",source)
        self.assertLess(source.index("try:sync('terminal-hold')"),source.index("publish('failure.json',failure)"))
        self.assertIn("env={**os.environ,'LC_ALL':'C'}",source)

if __name__=='__main__':unittest.main()

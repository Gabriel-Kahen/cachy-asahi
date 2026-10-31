#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real bounded archive validators with modeled GPG; no native actor executes."""
import base64
import copy
from datetime import datetime, timezone
import io
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

PATH=Path(__file__).resolve().with_name('signed_archive_intake.py')
subject=types.ModuleType('_signed_intake_under_test');subject.__file__=str(PATH)
exec(compile(PATH.read_bytes(),str(PATH),'exec'),subject.__dict__)
NOW,SIGNER,OTHER=1700000000,'A'*40,'B'*40


def signature(signer=SIGNER,created=NOW-500,expires=0,digest='10',kind='00'):
    return (f'[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG AAAAAAAA MODELED ONLY\n'
            f'[GNUPG:] VALIDSIG {signer} 2023-11-14 {created} {expires} 4 0 1 {digest} {kind} {signer}\n').encode()


def armor(raw):
    crc=0xb704ce
    for byte in raw:
        crc^=byte<<16
        for _ in range(8):
            crc<<=1
            if crc&0x1000000:crc^=0x1864cfb
    return (b'-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n'+base64.b64encode(raw)+b'\n='
            +base64.b64encode((crc&0xffffff).to_bytes(3,'big'))+b'\n-----END PGP PUBLIC KEY BLOCK-----\n')


class SignedArchiveControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project=tempfile.TemporaryDirectory(prefix='signed-intake-sources-');cls.addClassCleanup(cls.project.cleanup)
        cls.projection=Path(cls.project.name)
        repo=next(parent for parent in PATH.parents if (parent/'scripts/platform/archive_intake_bundle.json').is_file())
        for relative,digest in subject.PINS.values():
            source=repo/relative;raw=source.read_bytes()
            if subject.sha(raw)!=digest:raise AssertionError('dependency pin changed: '+relative)
            target=cls.projection/relative;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(raw);target.chmod(source.stat().st_mode&0o7777)
        shutil.copy2(repo/'scripts/platform/archive_intake_bundle.json',cls.projection/'scripts/platform/archive_intake_bundle.json')
        shutil.copytree(repo/'scripts/platform/archive_intake_bundle',cls.projection/'scripts/platform/archive_intake_bundle')

    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix='signed-intake-fixture-');self.addCleanup(tmp.cleanup)
        self.directory=Path(tmp.name);self.calls=[]
        for context in [patch.object(subject,'ROOT',self.projection),
                        patch.object(subprocess,'Popen',side_effect=AssertionError('native actor in pure suite')),
                        patch.object(subject.time,'time',return_value=NOW),patch.object(subject,'command',side_effect=self.command)]:
            context.start();self.addCleanup(context.stop)
        self.services=subject.sources()
        self.selection=dict(schema_version=1,scope=subject.SELECTION,release_set=None,packages=[])
        self.policy=dict(schema_version=1,profile=subject.PROFILE,selection_sha256='',release_set=None,
            issued=NOW-100,expires=NOW+3600,signers=[dict(primary=SIGNER,signature_not_before=NOW-1000,not_after=NOW+10000)])
        for name,raw in [('gpg',b'MODEL EXECUTABLE NEVER RUN'),('public_keyring',b'\xc6\x01\x04'),
                         ('trusted',(SIGNER+':4:\n').encode()),('revoked',b'')]:
            path=self.directory/name;path.write_bytes(raw)
            if name=='gpg':path.chmod(0o700)
            self.policy[name]=dict(path=str(path),bytes=len(raw),sha256=subject.sha(raw))
        self.add_package('fixture-one');self.bind()

    def bind(self):self.policy['selection_sha256']=subject.sha(subject.encoded(self.selection))

    def key_operand(self,name,raw):
        Path(self.policy[name]['path']).write_bytes(raw)
        self.policy[name].update(bytes=len(raw),sha256=subject.sha(raw))

    def reference(self,path):
        info=path.lstat();fields=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
        return dict(path=str(path),size=info.st_size,sha256=subject.sha(path.read_bytes()),identity=[getattr(info,key) for key in fields])

    def archive(self,name,entries=None,pkginfo=None,format=tarfile.USTAR_FORMAT):
        if pkginfo is None:pkginfo=f'pkgname = {name}\npkgver = 1-1\narch = any\nlicense = MIT\n'.encode()
        if entries is None:entries=[('usr','directory',b''),('usr/share','directory',b''),('usr/share/'+name,'file',b'pristine bytes')]
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w',format=format) as archive:
            for name,kind,value,*extra in [('.PKGINFO','file',pkginfo)]+entries:
                info=tarfile.TarInfo(name);info.uid=info.gid=0;info.mtime=NOW
                info.mode=0o755 if kind=='directory' else 0o777 if kind=='symlink' else 0o644
                if extra:
                    if set(extra[0]) <= {'uid','gid','mode'}:
                        for key,attribute in extra[0].items():setattr(info,key,attribute)
                    else:info.pax_headers=extra[0]
                if kind=='file':info.size=len(value);archive.addfile(info,io.BytesIO(value))
                else:
                    info.type={'directory':tarfile.DIRTYPE,'symlink':tarfile.SYMTYPE,'hardlink':tarfile.LNKTYPE,'fifo':tarfile.FIFOTYPE}[kind]
                    if kind in ('symlink','hardlink'):info.linkname=value
                    archive.addfile(info)
        return lzma.compress(stream.getvalue(),format=lzma.FORMAT_XZ)

    def add_package(self,name,entries=None):
        path=self.directory/(name+'.pkg.tar.xz');path.write_bytes(self.archive(name,entries))
        sig=self.directory/(name+'.sig');sig.write_bytes(b'MODELED SIGNATURE '+name.encode())
        identity=dict(name=name,version='1-1',arch='any')
        row=dict(identity=identity,archive=self.reference(path),signature=self.reference(sig),primary_fingerprint=SIGNER,
            metadata=dict(identity,depends=[],provides=[],conflicts=[],replaces=[],license=['MIT']))
        self.selection['packages'].append(row);return row

    def replace_archive(self,entries=None,pkginfo=None,format=tarfile.USTAR_FORMAT):
        row=self.selection['packages'][0];path=Path(row['archive']['path'])
        path.write_bytes(self.archive(row['identity']['name'],entries,pkginfo,format));row['archive']=self.reference(path);self.bind()

    def command(self,owned,argv,home,logs,number,deadline):
        self.assertTrue(home.is_dir());self.assertEqual(home.stat().st_mode&0o7777,0o700)
        for flag in ('--no-autostart','--no-auto-key-retrieve','--disable-dirmngr'):self.assertIn(flag,argv)
        self.calls.append(list(argv))
        raw=('[GNUPG:] IMPORT_OK 1 '+SIGNER+'\n').encode() if '--import' in argv else signature()
        record=dict(argv=argv,model='NO_NATIVE_CRYPTOGRAPHY',number=number)
        for suffix,data in [('.stdout',raw),('.stderr',b''),('.json',subject.encoded(record))]:
            (logs/('%04d'%number+suffix)).write_bytes(data)
        return raw,record

    def execute(self,name='output'):return subject.run(self.selection,self.policy,self.directory/name,seconds=30)

    def refused(self,error,name='output',commands=None):
        with self.assertRaisesRegex((ValueError,OSError),error):self.execute(name)
        output=self.directory/name
        if output.exists():
            self.assertFalse((output/'receipt.json').exists());self.assertTrue((output/'INCOMPLETE.json').exists())
        if commands is not None:self.assertEqual(len(self.calls),commands)

    def test_real_parser_spool_assembler_and_pending_verifier_complete(self):
        receipt=self.execute();output=self.directory/'output'
        self.assertEqual(receipt['status'],subject.STATUS);self.assertEqual(len(self.calls),2)
        self.assertFalse((output/'spool').exists());self.assertFalse(list(output.glob('gpg-home-*')))
        self.assertFalse((output/'INCOMPLETE.json').exists())
        self.assertEqual(subject.decode((output/'staging-verification.json').read_bytes())['status'],'PASS_EVERY_SERIALIZED_NODE_AND_BODY')
        self.assertTrue(all(value is False for value in receipt['acceptance'].values()))

    def test_five_packages_verify_before_real_decoder_in_exact_command_order(self):
        for index in range(2,6):self.add_package('fixture-'+str(index))
        self.bind();seen=[];original=lzma.LZMADecompressor
        def decoder(*args,**kwargs):seen.append(len(self.calls));return original(*args,**kwargs)
        with patch.object(lzma,'LZMADecompressor',side_effect=decoder):receipt=self.execute()
        self.assertEqual(len(receipt['packages']),5);self.assertEqual(len(self.calls),6)
        self.assertIn('--import',self.calls[0]);self.assertTrue(all('--verify' in call for call in self.calls[1:]))
        self.assertEqual(seen,[6]*5)
        self.assertEqual([Path(call[-1]).name for call in self.calls[1:]],
                         [row['identity']['name']+'.archive' for row in self.selection['packages']])

    def test_last_signature_refusal_never_reaches_parser(self):
        self.add_package('fixture-two');self.bind();original=self.command
        def bad(*args):
            raw,record=original(*args);return (raw+b'[GNUPG:] BADSIG bad\n' if args[4]==2 else raw),record
        with patch.object(subject,'command',side_effect=bad),patch.object(lzma,'LZMADecompressor',side_effect=AssertionError('parser before all signatures')):
            self.refused('invalid/expired/revoked',commands=3)

    def test_policy_schema_selection_pin_and_release_binding_predispatch(self):
        mutations=[dict(extra=True),dict(schema_version=True),dict(selection_sha256='0'*64),
                   dict(release_set={'release_id':'other','record_sha256':'0'*64})]
        for index,values in enumerate(mutations):
            saved=copy.deepcopy(self.policy);self.policy.update(values)
            self.refused('policy|canonical-selection',name='bad-'+str(index),commands=0);self.policy=saved

    def test_policy_future_expired_and_excess_lifetime_predispatch(self):
        for index,(issued,expires) in enumerate([(NOW+1,NOW+100),(NOW-100,NOW),(NOW-100,NOW+7*86400)]):
            self.policy.update(issued=issued,expires=expires)
            self.refused('policy-expired-future-or-lifetime',name='bad-'+str(index),commands=0)

    def test_signer_window_duplicate_and_unapproved_signer_predispatch(self):
        original=copy.deepcopy(self.policy['signers'])
        mutations=[[dict(primary=SIGNER,signature_not_before=NOW+1,not_after=NOW+100)],
                   [dict(primary=SIGNER,signature_not_before=NOW-100,not_after=NOW)],original+original,
                   [dict(primary=OTHER,signature_not_before=NOW-1000,not_after=NOW+100)]]
        for index,signers in enumerate(mutations):
            self.policy['signers']=signers
            self.refused('signer-policy-window|unapproved-selected-signer',name='bad-'+str(index),commands=0)

    def test_trusted_and_revoked_constraints_predispatch(self):
        self.key_operand('trusted',(OTHER+':4:\n').encode())
        self.refused('signer-untrusted-or-revoked',name='untrusted',commands=0)
        self.key_operand('trusted',(SIGNER+':4:\n').encode());self.key_operand('revoked',(SIGNER+':revocation\n').encode())
        self.refused('signer-untrusted-or-revoked',name='revoked-output',commands=0)

    def test_key_and_archive_pins_predispatch(self):
        original=self.policy['public_keyring']['sha256'];self.policy['public_keyring']['sha256']='0'*64
        self.refused('input-or-source-pin',name='badkey',commands=0);self.policy['public_keyring']['sha256']=original
        self.selection['packages'][0]['archive']['sha256']='0'*64;self.bind()
        self.refused('snapshot-input-pin',name='badarchive',commands=0)

    def test_tuple_duplicate_package_and_operand_alias_predispatch(self):
        original=copy.deepcopy(self.selection)
        for index,kind in enumerate(('tuple','duplicate','alias')):
            if kind=='tuple':self.selection['packages'][0]['metadata']['version']='2-1'
            elif kind=='duplicate':self.selection['packages'].append(copy.deepcopy(self.selection['packages'][0]))
            else:self.selection['packages'][0]['signature']=self.selection['packages'][0]['archive']
            self.bind();self.refused('metadata-tuple-binding|duplicate-package|duplicate-operand-path',name='bad-'+str(index),commands=0)
            self.selection=copy.deepcopy(original)

    def test_secret_packet_and_armor_crc_predispatch(self):
        self.key_operand('public_keyring',b'\xc5\x01\x04');self.refused('secret',name='secret',commands=0)
        lines=armor(b'\xc6\x01\x04').splitlines();lines[-2]=b'=AAAA'
        self.key_operand('public_keyring',b'\n'.join(lines)+b'\n');self.refused('armor-crc24',name='crc',commands=0)

    def test_public_armor_and_existing_packet_parser_mutations(self):
        binary=b'\xc6\x01\x04';check=self.services['public_packets']
        for raw in (binary,armor(binary)):
            self.assertEqual(subject.public_only(raw,check)['decoded_sha256'],subject.sha(binary))
        for raw,error in [(b'\xc6\xe0x','partial'),(b'\xc6\x05x','truncated'),(b'\xcd\x01x','public primary'),
                          (armor(binary).replace(b'PUBLIC',b'PRIVATE'),'public-key-armor-only')]:
            with self.subTest(error=error),self.assertRaisesRegex(ValueError,error):subject.public_only(raw,check)

    def test_reused_signature_parser_accepts_sha2_primary(self):
        parsed=self.services['signature_status'](signature(),SIGNER,datetime.fromtimestamp(NOW,timezone.utc))
        self.assertEqual(parsed,dict(primary_fingerprint=SIGNER,signing_fingerprint=SIGNER,hash_algorithm='10'))

    def test_reused_signature_parser_rejects_bad_key_and_signature_markers(self):
        for marker in ['KEYEXPIRED','SIGEXPIRED','EXPKEYSIG','EXPSIG','REVKEYSIG','KEYREVOKED','BADSIG','ERRSIG','NO_PUBKEY','NODATA','FAILURE','ERROR','BADARMOR']:
            with self.subTest(marker=marker),self.assertRaisesRegex(ValueError,'invalid/expired/revoked'):
                self.services['signature_status'](signature()+('[GNUPG:] '+marker+' x\n').encode(),SIGNER,datetime.fromtimestamp(NOW,timezone.utc))

    def test_reused_signature_parser_rejects_weak_multiple_missing_wrong_time_or_signer(self):
        for raw in [signature(digest='2'),signature()+signature(),b'',signature(signer=OTHER),signature(created=NOW+1),
                    signature(expires=NOW),signature(kind='01'),signature().replace(b'[GNUPG:] NEWSIG\n',b'')]:
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                self.services['signature_status'](raw,SIGNER,datetime.fromtimestamp(NOW,timezone.utc))

    def test_import_status_rejects_secret_flags_unapproved_or_missing_primary(self):
        subject.import_status(('[GNUPG:] IMPORT_OK 1 '+SIGNER+'\n').encode(),{SIGNER:{}})
        for raw in [b'',('[GNUPG:] IMPORT_OK 17 '+SIGNER+'\n').encode(),('[GNUPG:] IMPORT_OK 1 '+OTHER+'\n').encode(),
                    ('[GNUPG:] IMPORT_OK 1 '+SIGNER+'\n[GNUPG:] IMPORT_PROBLEM 1\n').encode()]:
            with self.subTest(raw=raw),self.assertRaises(ValueError):subject.import_status(raw,{SIGNER:{}})

    def test_real_parser_path_extension_special_and_missing_parent_refusals(self):
        variants=[([('../escape','file',b'x')],tarfile.USTAR_FORMAT,'noncanonical-path'),
                  ([('usr','directory',b''),('usr/file','file',b'x',{'VENDOR.unknown':'x'})],tarfile.PAX_FORMAT,'archive-extension'),
                  ([('fifo','fifo',b'')],tarfile.USTAR_FORMAT,'archive-extension'),
                  ([('usr/share/file','file',b'x')],tarfile.USTAR_FORMAT,'explicit-directory-parent')]
        for index,(entries,format,error) in enumerate(variants):
            self.replace_archive(entries,format=format);before=len(self.calls)
            self.refused(error,name='bad-'+str(index));self.assertEqual(len(self.calls)-before,2)

    def test_real_parser_exact_expected_metadata_and_tuple(self):
        self.selection['packages'][0]['metadata']['depends']=['unprovided-dependency'];self.bind()
        self.refused('archive-signed-metadata',name='metadata',commands=2)
        self.selection['packages'][0]['metadata']['depends']=[]
        self.replace_archive(pkginfo=b'pkgname = different\npkgver = 1-1\narch = any\nlicense = MIT\n')
        self.refused('archive-tuple',name='tuple',commands=4)

    def test_real_hardlink_and_symlink_roundtrip(self):
        self.replace_archive([('usr','directory',b''),('usr/file','file',b'bytes'),
                              ('usr/hard','hardlink','usr/file'),('usr/link','symlink','file')])
        receipt=self.execute();nodes=subject.decode((self.directory/'output/assembly.json').read_bytes())['output_nodes']
        self.assertEqual(nodes['usr/hard']['target'],'usr/file');self.assertEqual(nodes['usr/link']['target'],'file')
        self.assertEqual(receipt['packages']['fixture-one']['nodes'],4)

    def test_real_hardlinks_refuse_missing_and_cycles(self):
        for index,entries in enumerate([[('usr','directory',b''),('usr/hard','hardlink','usr/missing')],
            [('usr','directory',b''),('usr/hard','hardlink','usr/other'),('usr/other','hardlink','usr/hard')]]):
            self.replace_archive(entries);self.refused('hardlink-same-package-file|hardlink-cycle',name='bad-'+str(index))

    def test_real_symlink_escape_and_symlink_parent_refuse(self):
        for index,entries in enumerate([[('usr','directory',b''),('usr/link','symlink','../../escape')],
                                       [('usr','symlink','target'),('usr/file','file',b'x')]]):
            self.replace_archive(entries);self.refused('virtual-link-root-escape|explicit-directory-parent',name='bad-'+str(index))

    def test_shared_regular_path_conflict_refuses_even_identical_bytes(self):
        entries=[('usr','directory',b''),('usr/shared','file',b'identical')]
        self.replace_archive(entries);self.add_package('fixture-two',entries);self.bind()
        self.refused('pristine-path-conflict',commands=3)

    def test_shared_directory_owner_conflict_and_hardlink_owner_conflict_refuse(self):
        self.add_package('fixture-two',[('usr','directory',b'',{'uid':42})]);self.bind()
        self.refused('pristine-path-conflict',name='owner-conflict',commands=3)
        self.selection['packages'].pop()
        self.replace_archive([('usr','directory',b''),('usr/file','file',b'x'),
                              ('usr/hard','hardlink','usr/file',{'uid':42})])
        self.refused('hardlink-metadata',name='hardlink-owner',commands=5)

    def test_duplicate_archive_member_and_symlink_cycle_refuse(self):
        variants=[([('usr','directory',b''),('usr/file','file',b'a'),('usr/file','file',b'b')],'duplicate-normalized-member'),
                  ([('usr','directory',b''),('usr/a','symlink','b'),('usr/b','symlink','a')],'virtual-link-hop-cap|unsafe-virtual-link')]
        for index,(entries,error) in enumerate(variants):
            self.replace_archive(entries);self.refused(error,name='bad-'+str(index))

    def test_signature_operand_pin_refuses_before_command(self):
        self.selection['packages'][0]['signature']['sha256']='0'*64;self.bind()
        self.refused('snapshot-input-pin',commands=0)

    def test_signed_timestamp_policy_lower_bound_refuses_before_parser(self):
        self.policy['signers'][0]['signature_not_before']=NOW-100
        with patch.object(lzma,'LZMADecompressor',side_effect=AssertionError('parser before time policy')):
            self.refused('signature-policy-time-or-revocation',commands=2)

    def test_release_set_reference_is_bound_but_never_accepted(self):
        selected=dict(record_sha256='0'*64,release_id='fixture-release')
        self.selection['release_set']=selected;self.policy['release_set']=copy.deepcopy(selected);self.bind()
        receipt=self.execute()
        self.assertEqual(receipt['release_set'],selected);self.assertFalse(receipt['acceptance']['complete_release_set'])

    def test_json_duplicate_nonfinite_and_input_shapes_refuse(self):
        for raw in [b'{"a":1,"a":2}',b'{"x":NaN}',b'{"x":Infinity}']:
            with self.subTest(raw=raw),self.assertRaisesRegex(ValueError,'duplicate-json-key|nonfinite-json'):subject.decode(raw)

    def test_generic_pending_verifier_requires_marker_and_own_status(self):
        self.execute();output=self.directory/'output'
        verify=subject.generic_verifier(self.services['verifier_raw'],pending=True)
        with self.assertRaisesRegex(ValueError,'incomplete-run'):verify(output)
        (output/'INCOMPLETE.json').write_bytes(b'{}')
        self.assertEqual(verify(output)['status'],'PASS_EVERY_SERIALIZED_NODE_AND_BODY')
        path=output/'verification-input.json';receipt=subject.decode(path.read_bytes())
        receipt['status']='PASS_EXACT_SELECTED_ARCHIVES_TO_STAGING_ONLY';path.write_bytes(subject.encoded(receipt))
        with self.assertRaisesRegex(ValueError,'receipt-status'):verify(output)

    def test_install_scriptlet_and_hook_payload_stay_inert_and_separate(self):
        self.replace_archive([('usr','directory',b''),('usr/share','directory',b''),('usr/share/libalpm','directory',b''),
            ('usr/share/libalpm/hooks','directory',b''),('usr/share/libalpm/hooks/fixture.hook','file',b'NEVER EXECUTE'),('.INSTALL','file',b'NEVER EXECUTE')])
        receipt=self.execute();row=receipt['separation']['fixture-one']
        self.assertEqual(row['scriptlets'],['.INSTALL']);self.assertFalse(row['hooks_executed']);self.assertFalse(row['generated_state_created'])
        self.assertNotIn('.INSTALL',subject.decode((self.directory/'output/assembly.json').read_bytes())['output_nodes'])

    def test_capacity_262_preserves_inherited_checks_and_live_constants(self):
        scratch=self.directory/'capacity';scratch.mkdir(mode=0o700)
        with self.services['intake'].runtime(scratch) as engine:
            policy=engine.load(engine.RUNTIME/'policy.py',engine.POLICY_SHA)
            with policy.snapshot() as (raws,check):
                parts=policy.sources(raws);identities=[dict(name='empty-'+str(i),version='1-1',arch='any') for i in range(262)]
                packages=[dict(identity=row,archive_sha256='0'*64,source_sha256='1'*64,nodes={},bodies={},metadata={},intake={}) for row in identities]
                store=types.SimpleNamespace(reference_check=lambda _:self.fail('no refs in empty maps'))
                with self.assertRaisesRegex(ValueError,'complete-spooled-selection'):
                    parts['bridge'].prepare(parts['core'],parts['assembler'],packages,identities,store)
                nodes,bodies,pristine=subject.generic_prepare(parts['bridge'])(parts['core'],parts['assembler'],packages,identities,store)
                self.assertEqual((nodes,bodies),({},{}));self.assertEqual(len(pristine['packages']),262)
                self.assertEqual(parts['assembler'].LIMITS['packages'],261);check()

    def test_existing_output_and_incomplete_reentry_preserve_evidence(self):
        output=self.directory/'existing';output.mkdir();(output/'keep').write_bytes(b'UNRELATED')
        with self.assertRaises(FileExistsError):self.execute('existing')
        self.assertEqual((output/'keep').read_bytes(),b'UNRELATED');self.assertEqual(self.calls,[])
        self.policy['expires']=NOW;self.refused('policy-expired',name='failed')
        with self.assertRaises(FileExistsError):self.execute('failed')
        self.assertTrue((self.directory/'failed/INCOMPLETE.json').exists())

    def test_source_check_failure_after_complete_staging_blocks_receipt(self):
        with patch.object(subject,'check_sources',side_effect=ValueError('modeled-source-drift')):
            self.refused('modeled-source-drift',commands=2)
        self.assertFalse(list((self.directory/'output').glob('gpg-home-*')))

    def test_original_operand_drift_after_snapshot_blocks_parent_receipt(self):
        original=self.command
        def change(*args):
            result=original(*args)
            if args[4]==1:
                with Path(self.selection['packages'][0]['archive']['path']).open('ab') as stream:stream.write(b'x')
            return result
        with patch.object(subject,'command',side_effect=change):self.refused('reference-identity|node-drift',commands=2)

    def test_public_home_cleanup_failure_prevents_parent_receipt(self):
        original=shutil.rmtree
        def fail_home(path,*args,**kwargs):
            if Path(path).name.startswith('gpg-home-'):raise OSError('modeled-home-cleanup')
            return original(path,*args,**kwargs)
        with patch.object(shutil,'rmtree',side_effect=fail_home):self.refused('modeled-home-cleanup',commands=2)

    def test_read_rejects_symlink_hardlink_fifo_without_blocking(self):
        original=self.directory/'ordinary';original.write_bytes(b'body')
        for kind in ('symlink','hardlink','fifo'):
            path=self.directory/kind
            if kind=='symlink':path.symlink_to(original)
            elif kind=='hardlink':os.link(original,path)
            else:os.mkfifo(path)
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'symlink|bounded-ordinary-input'):subject.read(path)
            path.unlink()


if __name__=='__main__':unittest.main(verbosity=2)

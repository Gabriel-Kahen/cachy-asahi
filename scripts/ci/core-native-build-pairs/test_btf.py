# SPDX-License-Identifier: MIT
"""Portable passive fixed-BTF input controls; no native/build/header authority."""
import importlib.util,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import prepare as F
ROOT=HERE/'runtime/effective-profile/systemd';spec=importlib.util.spec_from_file_location('maintained_fixed_btf_provider',ROOT/'cachy-asahi-btf.py');B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
class Controls(unittest.TestCase):
 def test_complete_fixed_raw_source_license_and_original_failure_joins_without_process(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')),patch.object(subprocess,'run',side_effect=AssertionError('NO_ACTORS')):p,availability=B.validate(ROOT)
  profile=F.profile();self.assertEqual(B.RAW,profile['fixed_btf']['raw']);self.assertEqual(B.POLICY,profile['fixed_btf']['provenance']);self.assertEqual(len(availability),2);self.assertEqual(p['diagnostic']['run'],39584141217);self.assertEqual(p['diagnostic']['CI'],'failure');self.assertFalse(p['authority']);self.assertEqual(p['source_bit_correspondence'],'NOT_ESTABLISHED_NO_REBUILD_CLAIM')
 def test_corrupt_or_missing_input_refuses_before_any_generator(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for n in('vmlinux.btf','vmlinux-input.json','BTF-COPYING'):shutil.copyfile(ROOT/n,root/n)
   with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_PROCESS_BEFORE_INPUT_PROOF')):
    raw=(root/'vmlinux.btf').read_bytes();(root/'vmlinux.btf').write_bytes(raw[:-1]+bytes([raw[-1]^1]))
    with self.assertRaises(ValueError):B.generate(root,root/'vmlinux.h',root/'receipt.json')
    self.assertFalse((root/'vmlinux.h').exists());self.assertFalse((root/'receipt.json').exists());(root/'vmlinux.btf').write_bytes(raw);(root/'vmlinux-input.json').unlink()
    with self.assertRaises(FileNotFoundError):B.generate(root,root/'vmlinux.h',root/'receipt.json')
 def test_real_prepare_argument_expansion_uses_regular_startdir_not_makepkg_source_links(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);src=root/'src';src.mkdir();record=root/'argv'
   for name in('vmlinux.btf','vmlinux-input.json','BTF-COPYING','cachy-asahi-btf.py'):
    shutil.copyfile(ROOT/name,root/name);(src/name).symlink_to(root/name)
   script=r'''source "$1"
startdir="$2"
srcdir="$3"
record="$4"
python3() { printf '%s\0' "$@" > "$record"; return 37; }
prepare
'''
   run=subprocess.run(['/bin/bash','-e','-c',script,'prepare-boundary-control',str(ROOT/'PKGBUILD'),str(root),str(src),str(record)],capture_output=True,timeout=10);self.assertEqual(run.returncode,37);argv=record.read_bytes().split(b'\0')[:-1];self.assertEqual([v.decode()for v in argv],['-I','-B',str(root/'cachy-asahi-btf.py'),'--root',str(root),'--header',str(root/'vmlinux.h'),'--receipt','/out/systemd-btf-input.json']);self.assertFalse((root/'vmlinux.h').exists())
   with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_GENERATOR')):B.validate(Path(argv[4].decode()))
   with self.assertRaisesRegex(ValueError,'ordinary whole input'):B.validate(src)
 def test_provided_mode_full_original_bpf_and_test_assertions_and_clocks_held(self):
  p=F.profile();recipe=F.read(ROOT/'PKGBUILD').decode();self.assertIn('-Dbpf-framework=enabled',recipe);self.assertIn('-Dvmlinux-h=provided',recipe);self.assertIn('-Dvmlinux-h-path="$startdir/vmlinux.h"',recipe);self.assertIn('python3 -I -B "${startdir}/cachy-asahi-btf.py" --root "$startdir" --header "$startdir/vmlinux.h" --receipt /out/systemd-btf-input.json',recipe)
  for n in('effective-profile/systemd/cachy-asahi-owned-userns.patch','lane/test_environment.py','lane/mechanism/probe.c'):self.assertEqual(p['base_files'][n],p['expected_sources']['selected'][n])
  self.assertEqual(p['bounds']['makepkg'],14400);self.assertEqual(p['bounds']['owner'],19680);self.assertEqual(p['bounds']['job_minutes'],360);self.assertIsNone(p['actual_run']);self.assertEqual(p['fixed_btf']['native_full4'],'REQUIRED_NOT_RUN_BY_FACTORY')
if __name__=='__main__':unittest.main(verbosity=2)

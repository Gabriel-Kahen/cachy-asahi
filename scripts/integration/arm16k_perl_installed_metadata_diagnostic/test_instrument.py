# SPDX-License-Identifier: MIT
"""Actual ordinary Bash/tree controls; no raw, actor, Root authority or VM."""
import hashlib
import importlib.util
import json
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent / 'arm16k_warm_control/source/arm16k_perl5423_vm'


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result


I = module('metadata_instrument', HERE / 'instrument.py')
T = module('original_metadata_controls', SOURCE / 'test_installed_metadata.py')
RAW = (SOURCE / 'guest/installed-metadata.sh').read_bytes()
GENERATED, MAP = I.instrument(RAW)
MARKER = re.compile(r'PERL5423_INSTALLED_METADATA_DIAGNOSTIC_V1 CATEGORY=(STAGE|PREDICATE|COMMAND) ORDINAL=([1-9][0-9]?)')


class Controls(unittest.TestCase):
    def test_reviewed_generated_helper_and_mapping_are_exact_transform_outputs(self):
        self.assertEqual((HERE/'guest/installed-metadata.sh').read_bytes(),GENERATED)
        mapping=json.loads((HERE/'mapping.DATA.json').read_bytes())
        self.assertEqual(mapping['returns'],MAP['returns'])
        self.assertEqual(mapping['stages'],{str(k):v for k,v in MAP['stages'].items()})
        self.assertEqual(mapping['generated'],dict(bytes=len(GENERATED),sha256=hashlib.sha256(GENERATED).hexdigest(),mode=0o644))

    def test_complete_exact_predicate_return_and_stage_mapping_has_full_inverse(self):
        self.assertEqual(I.inverse(RAW, GENERATED, MAP), RAW)
        self.assertEqual(len(MAP['returns']), len(list(I.RETURN.finditer(RAW.decode()))))
        for row in MAP['returns']:
            original = RAW.decode().splitlines()[row['line']-1]
            self.assertEqual(row['original'], original)
            self.assertIn('return', original)
            self.assertIn(f"_im_diagnostic {row['category']} {row['ordinal']};return", GENERATED.decode())
        restored = GENERATED.decode().split('_im_diagnostic STAGE 1\n', 1)[1]
        restored = re.sub(r'^ _im_diagnostic STAGE [0-9]+\n', '', restored, flags=re.M)
        for row in MAP['returns']:
            category, n, code = row['category'], row['ordinal'], row['return_code']
            replacement = (f'{{ _im_diagnostic {category} {n};return {code}; }}' if code != 'UNCHANGED' else
                           f'{{ local _im_diagnostic_rc=$?;_im_diagnostic {category} {n};return "$_im_diagnostic_rc"; }}')
            self.assertEqual(restored.count(replacement), 1)
            restored = restored.replace(replacement, 'return' + (f' {code}' if code != 'UNCHANGED' else ''))
        self.assertEqual(restored.encode(), RAW)
        self.assertEqual(len(MAP['stages']), 14)
        self.assertEqual(subprocess.run(['/usr/bin/bash', '-n'], input=GENERATED, capture_output=True).returncode, 0)

    def test_changed_predecessor_or_derivative_refuses(self):
        with self.assertRaises(ValueError): I.instrument(RAW + b'\n')
        with self.assertRaises(ValueError): I.inverse(RAW, GENERATED.replace(b'return 2', b'return 0'), MAP)

    def run_fixture(self, mutate=None, instrumented=True, surplus=False, shell_return2=False, missing_console=False, **options):
        fixture = T.Fixture(**options)
        self.addCleanup(fixture.close)
        if mutate: mutate(fixture)
        source = fixture.top / 'source'; (source / 'guest').mkdir(parents=True)
        (source / 'guest/case.sh').write_bytes((SOURCE / 'guest/case.sh').read_bytes() +
                                               (b'\nulimit() { return 2; }\n' if shell_return2 else b''))
        marker = fixture.top / ('missing/serial.log' if missing_console else 'serial.log')
        code = GENERATED if instrumented else RAW
        code = code.replace(b'/dev/ttyAMA0', shlex.quote(str(marker)).encode())
        (source / 'guest/installed-metadata.sh').write_bytes(code)
        old = T.HERE
        try:
            T.HERE = source
            result, calls = fixture.run(surplus=surplus)
        finally: T.HERE = old
        text = marker.read_text() if marker.exists() else ''
        for line in text.splitlines():
            if line:
                match = MARKER.fullmatch(line); self.assertIsNotNone(match, line)
                category, ordinal = match[1], int(match[2])
                if category == 'STAGE': self.assertIn(ordinal, MAP['stages'])
                else: self.assertIn((category, ordinal), {(r['category'], r['ordinal']) for r in MAP['returns']})
        self.assertLess(len(text), 4096)
        return result, calls, text

    def ordinal(self, fragment, source_line=None):
        rows = [r for r in MAP['returns'] if fragment in r['original'] and (source_line is None or r['line']==source_line)]
        self.assertEqual(len(rows), 1, rows)
        return f"CATEGORY={rows[0]['category']} ORDINAL={rows[0]['ordinal']}"

    def parity(self, mutate, fragment, expected=2, source_line=None, **options):
        before, _, _ = self.run_fixture(mutate, instrumented=False, **options)
        after, _, text = self.run_fixture(mutate, **options)
        self.assertEqual(before.returncode, expected, before.stderr)
        self.assertEqual(after.returncode, expected, after.stderr)
        self.assertIn(self.ordinal(fragment, source_line), text)
        self.assertNotIn('PRIVATE_SENTINEL', text)

    def test_success_has_only_fixed_stages_and_identical_query_surface(self):
        before, a, _ = self.run_fixture(instrumented=False)
        after, b, text = self.run_fixture()
        self.assertEqual(before.returncode, 0, before.stderr)
        self.assertEqual(after.returncode, 0, after.stderr)
        self.assertEqual(before.stdout, after.stdout)
        self.assertEqual([c[1:] for c in a if c[0]=='pacman'], [c[1:] for c in b if c[0]=='pacman'])
        self.assertEqual(len(MARKER.findall(text)), 14)
        self.assertNotIn('CATEGORY=PREDICATE', text)

    def test_actual_global_projection_malformed_duplicate_and_empty_predicates(self):
        self.parity(lambda f: f.global_rows.write_text('PRIVATE_SENTINEL\n'), "$line == *' '*")
        self.parity(lambda f: f.global_rows.write_text(f.global_rows.read_text()*2), 'entries[')
        self.parity(lambda f: self.query_output(f, 'sys.exit(0)'), 'global_count > 0')

    def query_output(self, fixture, replacement):
        path=fixture.bin/'pacman'; body=path.read_text()
        original="if args==['-Ql']:print('\\n'.join(rows));sys.exit(0)"
        self.assertEqual(body.count(original),1)
        path.write_text(body.replace(original,"if args==['-Ql']:"+replacement))

    def test_command_status_and_early_shell_return2_keep_exact_behavior(self):
        self.parity(lambda f:self.query_output(f, 'sys.exit(37)'), 'pacman -Ql >', expected=37)
        before,_,_=self.run_fixture(instrumented=False,shell_return2=True)
        after,_,text=self.run_fixture(shell_return2=True)
        self.assertEqual((before.returncode,after.returncode),(2,2))
        self.assertIn('CATEGORY=STAGE ORDINAL=2',text)
        self.assertIn('CATEGORY=STAGE ORDINAL=3',text)
        self.assertNotIn('CATEGORY=STAGE ORDINAL=4',text)

    def test_unavailable_console_does_not_change_success_or_command_status(self):
        result,_,text=self.run_fixture(missing_console=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(text,'')
        result,_,text=self.run_fixture(lambda f:self.query_output(f,'sys.exit(37)'),missing_console=True)
        self.assertEqual(result.returncode,37,result.stderr)
        self.assertEqual(text,'')

    def test_diagnostic_prefix_preserves_exact_five_field_HOLD_protocol(self):
        protocol=module('unchanged_metadata_protocol',SOURCE/'protocol.py')
        _,_,text=self.run_fixture(lambda f:f.global_rows.write_text('PRIVATE_SENTINEL\n'))
        nonce='a'*32
        frame=f'PERL5423_RESTORED_BEGIN {nonce}\nSTATUS=HOLD\nFAILED_PHASE=installed_metadata\nEXIT_STATUS=2\nPERL5423_RESTORED_END {nonce}\n'
        self.assertEqual(protocol.frame((text+frame).encode(),nonce,'RESTORED'),
                         dict(STATUS='HOLD',FAILED_PHASE='installed_metadata',EXIT_STATUS='2'))

    def test_metadata_scope_and_schema_refusals_report_exact_predicate(self):
        self.parity(lambda f: (f.packet/'payload-metadata.tsv').write_text('f\t888\t0\t0\t/PRIVATE_SENTINEL\t-\n'), '$mode =~')
        self.parity(lambda f: (f.packet/'payload-metadata.tsv').write_text('f\t644\t0\t0\t/PRIVATE_SENTINEL\t-\n'), '$path =~')

    def test_stat_stream_surplus_and_real_mode_change_remain_refused(self):
        self.parity(None, 'field <&7 || [[ -n $field ]];then', surplus=True, source_line=99)
        self.parity(lambda f: (f.usr/'lib/perl/a').chmod(0o600), '$actual_mode ==', expected=1)

    def test_ownership_hardlink_and_inventory_refusals_remain_exact(self):
        self.parity(None, 'owners[', expected=1, alias_counterfeit=True)
        def broken(f):
            p=f.usr/'lib/perl/b';p.unlink();p.write_bytes(b'Fiction candidate bytes\n')
        self.parity(broken, 'stat_dev[', expected=1)
        self.parity(lambda f:(f.top/'perl.rows').write_text('/PRIVATE_SENTINEL\n'), 'same_bytes "$expected" "$inventory"', expected=1)

    def test_arbitrary_arguments_cannot_escape_fixed_marker_whitelist(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/'serial'; code=GENERATED.decode().split('#!/usr/bin/bash',1)[0]
            code=code.replace('/dev/ttyAMA0', shlex.quote(str(out)))
            code+='\n_im_diagnostic PRIVATE_SENTINEL 1\n_im_diagnostic PREDICATE "1 PRIVATE_SENTINEL"\n_im_diagnostic STAGE 999\n_im_diagnostic STAGE 01\n'
            result=subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c',code],capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(out.read_text(),'\nPERL5423_INSTALLED_METADATA_DIAGNOSTIC_V1 CATEGORY=STAGE ORDINAL=1\n')


if __name__ == '__main__': unittest.main(verbosity=2)

# SPDX-License-Identifier: MIT
"""Finite Bash argv controls only; never invoke a compiler, linker or guest."""
from pathlib import Path
import subprocess
import unittest

HERE=Path(__file__).resolve().parent
SCRIPT=HERE/'guest/link-stage0.sh'


class GuestLinkControls(unittest.TestCase):
    def shell(self,command,args):
        # Source defines functions only. $0 differs from BASH_SOURCE. Even an
        # accidental main call cannot exec a tool through the fenced function.
        driver='exec() { return 97; }; source "$1"; shift; '+command
        return subprocess.run(['/usr/bin/bash','--noprofile','--norc','-c',driver,'FENCED_ARGV_ONLY',str(SCRIPT),*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=2,env=dict(PATH='/usr/bin:/bin',LC_ALL='C',BASH_ENV='/dev/null'))

    def rewrite(self,args):return self.shell('rewrite_link_args "$@"; printf "%s\\0" "${link_args[@]}"',args)

    def test_dynamic_token_replaced_in_place_and_other_bytes_order_preserved(self):
        args=['--as-needed','-Bstatic','/tmp/with spaces/one.rlib','-Bdynamic','-lgcc_s','-lutil','-lrt','-lpthread','-lm','-ldl','-lc','-z','max-page-size=16384','--dynamic-linker=/lib/ld-linux-aarch64.so.1','-o','/tmp/with spaces/output']
        row=self.rewrite(args);self.assertEqual(row.returncode,0,row.stderr)
        self.assertEqual(row.stdout.split(b'\0')[:-1],[s.encode() for s in [*args[:4],'/usr/lib/libgcc_s.so.1',*args[5:]]])

    def test_missing_duplicate_static_and_indirect_gcc_refuse(self):
        for args in ([],['-lc'],['-lgcc_s','-lgcc_s'],['-lgcc_s','-lgcc'],['-lgcc_s','-lgcc_eh'],['-Bstatic','-lgcc_s'],['-lgcc_s','@hidden'],['-static','-lgcc_s'],['-lgcc_s','/usr/lib/libgcc_s.so'],['-lgcc_s','-l:libgcc.a'],['-lgcc_s','/usr/lib/libgcc_s.so.1'],['-l','gcc_s']):
            with self.subTest(args=args):self.assertEqual(self.rewrite(args).returncode,2)

    def test_finite_argument_count_and_byte_limits(self):
        self.assertEqual(self.rewrite(['-lgcc_s']+['-x']*511).returncode,0)
        self.assertEqual(self.rewrite(['-lgcc_s']+['-x']*512).returncode,2)
        self.assertEqual(self.rewrite(['-lgcc_s']+['x'*32768]*4).returncode,2)

    def test_preexec_receipt_records_exact_original_and_rewritten_vectors(self):
        row=self.shell('rewrite_link_args "$@"; build_link_receipt "$@"; printf "%s" "$receipt_body"',['-Bdynamic','-lgcc_s','/tmp/with spaces/one.o','line\nbreak'])
        self.assertEqual(row.returncode,0,row.stderr)
        text=row.stdout.decode();self.assertIn('STATUS=REWRITE_APPROVED_BEFORE_EXEC\n',text)
        self.assertIn('ORIGINAL[1]=-lgcc_s\n',text);self.assertIn('REWRITTEN[1]=/usr/lib/libgcc_s.so.1\n',text)
        self.assertIn('ORIGINAL[2]=/tmp/with\\ spaces/one.o\n',text)
        self.assertIn("ORIGINAL[3]=$'line\\nbreak'\n",text)
        self.assertIn('ORIGINAL_COUNT=4\n',text);self.assertIn('REWRITTEN_COUNT=4\n',text)
        self.assertLessEqual(len(row.stdout),65536)
        refused=self.shell('if rewrite_link_args "$@"; then :; else link_args=(); fi; build_link_receipt "$@"; printf "%s" "$receipt_body"',['-lgcc_s','-lgcc'])
        self.assertEqual(refused.returncode,0,refused.stderr)
        self.assertIn(b'STATUS=REFUSED_BEFORE_EXEC\n',refused.stdout)
        self.assertIn(b'ORIGINAL[1]=-lgcc\n',refused.stdout)
        self.assertIn(b'REWRITTEN_COUNT=0\n',refused.stdout)

    def test_receipt_cap_and_missing_private_receipt_operand_refuse(self):
        command='rewrite_link_args "$@"; build_link_receipt "$@"'
        self.assertEqual(self.shell(command,['-lgcc_s','x'*20000,'y'*20000]).returncode,2)
        self.assertEqual(self.shell('main "$@"',['-lgcc_s']).returncode,2)

    def test_direct_and_cargo_select_same_private_adapter_and_fixed_ld(self):
        check=(HERE/'guest/check.sh').read_text();prepare=(HERE/'prepare_image.py').read_text();wrapper=SCRIPT.read_text()
        self.assertIn('flags=(--edition=2021 -C linker="$fixture/link-stage0.sh" -C linker-flavor=ld',check)
        self.assertIn('CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$fixture/link-stage0.sh"',check)
        self.assertIn("('check.sh','link-stage0.sh','Cargo.toml','Cargo.lock','main.rs')",prepare)
        self.assertIn('exec /usr/bin/ld "${link_args[@]}"',wrapper)
        self.assertEqual(wrapper.count('exec /usr/bin/ld'),1)
        self.assertNotIn('eval ',wrapper)
        self.assertIn('RUST_STAGE0_LD_RECEIPT_BEGIN %s %s',check)
        self.assertIn('CACHY_RUST_STAGE0_LINK_RECEIPT=$D/direct-ld.receipt',check)
        self.assertIn('CACHY_RUST_STAGE0_LINK_RECEIPT=$D/cargo-ld.receipt',check)
        self.assertIn('set -o noclobber',wrapper)


if __name__=='__main__':unittest.main()

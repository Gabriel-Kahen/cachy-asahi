#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Real HOST restoration-order controls on owned scratch only.

The old order deterministically compares running parent link counts with their
restored preboot values. This reproduces a source defect consistent with the
coarse case12 HOLD; it does not identify the unreported failing guest check.
No actor, ALPM, credential, image, lease, GPG or network is used.
"""
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('restoration_owned_HOST_fixture',HERE/'test_etc_mtime.py')
HOST=importlib.util.module_from_spec(spec);spec.loader.exec_module(HOST)
RUNTIME=(HERE/'frozen/guest-runtime.sh').read_text()
EQUALITY=RUNTIME[RUNTIME.index('procfs_guard() {\n'):]
CASE=(HERE/'guest/case.sh').read_text()
COMPARISON=CASE[CASE.index('same_bytes() {\n'):CASE.index('clock_valid() {')]
ROOT=(HERE/'guest/root.sh').read_text()

def root_function(name):
    start=ROOT.index(name+'() {\n')
    return ROOT[start:ROOT.index('\n}\n',start)+3]

RESTORATION_STEP=root_function('restoration_step')
ROOT_FINISH=root_function('finish')
LABELS=('snapshot','paths','hash','db-normalized','xattr','dbmeta','dbxattr','meta_equality',
        'users','log_prefix','log_shape','log_capture','preboot_cleanup','trust_cleanup','root_ssh_cleanup','sync','publish')

MODEL=r'''
model_snapshot() {
 local stage=$1
 stat --printf='%n\0%f\0%u\0%g\0%h\0%N\0' -- /proc/ "$MODEL_ETC/" "$MODEL_ETC/audit/" "$MODEL_ETC/udev/" "$MODEL_ETC/base.conf" "$MODEL_ETC/audit/base.conf" "$MODEL_ETC/udev/base.rules" "$HOME/userhome/" "$HOME/userhome/data" > "$O/$stage.meta"
 metadata_equality_view "$stage"
 sha256sum -- "$MODEL_ETC/base.conf" "$MODEL_ETC/audit/base.conf" "$MODEL_ETC/udev/base.rules" "$HOME/userhome/data" > "$O/$stage.hash"
 getfattr --no-dereference --absolute-names --dump --match='.*' -- "$MODEL_ETC/" "$MODEL_ETC/audit/" "$MODEL_ETC/udev/" "$MODEL_ETC/base.conf" "$HOME/userhome/" "$HOME/userhome/data" > "$O/$stage.xattr"
}
model_compare() {
 same_bytes "$O/before.hash" "$O/after.hash" || return
 same_bytes "$O/before.xattr" "$O/after.xattr" || return
 same_bytes "$O/before.meta-equality" "$O/after.meta-equality"
}
model_transaction() {
 cp -a -- "$MODEL_ETC/ld.so.cache" "$D/cache.saved"
 printf 'HOST normal hook replacement' > "$MODEL_ETC/new-cache"
 mv -- "$MODEL_ETC/new-cache" "$MODEL_ETC/ld.so.cache"
 cp -a -- "$D/cache.saved" "$MODEL_ETC/ld.so.cache"
}
'''


def records(path):
    values=path.read_bytes().split(b'\0')
    if values[-1:]!=[b'']or(len(values)-1)%6:
        raise AssertionError('complete six-field NUL stat records required')
    return {values[i].decode():values[i:i+6]for i in range(0,len(values)-1,6)}


class Controls(unittest.TestCase):
    def fixture(self):
        value=HOST.Fixture();self.addCleanup(value.close)
        user=value.top/'userhome';user.mkdir(mode=0o700);(user/'data').write_bytes(b'HOST user-owned data\n')
        value.boot()
        return value

    def run_model(self,value,body):
        return value.run(body,before=EQUALITY+'\n'+COMPARISON+'\n'+MODEL)

    def test_old_order_reproduces_only_certified_parent_link_row_mismatch(self):
        f=self.fixture()
        result=self.run_model(f,'''cache_etc_timestamp_capture
model_snapshot before
model_transaction
cache_etc_timestamp_restore
model_snapshot after
if model_compare;then printf BAD_UNEXPECTED_EQUAL;exit 9;fi
printf REPRODUCED_PARENT_LINK_MISMATCH
''')
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(result.stdout,b'REPRODUCED_PARENT_LINK_MISMATCH')
        before=records(f.run_dir/'before.meta-equality');after=records(f.run_dir/'after.meta-equality')
        changes={name for name in before if before[name]!=after[name]}
        self.assertEqual(changes,{str(f.etc)+'/',str(f.etc/'audit')+'/'})
        for parent,delta in ((f.etc,1),(f.etc/'audit',2)):
            name=str(parent)+'/'
            self.assertEqual(int(before[name][4])-int(after[name][4]),delta)
            self.assertEqual(before[name][:4]+before[name][5:],after[name][:4]+after[name][5:])
        self.assertEqual(before['/proc/'][4],b'VOLATILE_LIVE_PROCFS_NLINK')
        f.assert_baseline(self)

    def test_compare_running_state_before_cleanup_then_restore_exact_baseline(self):
        f=self.fixture()
        result=self.run_model(f,'''cache_etc_timestamp_capture
model_snapshot before
model_transaction
model_snapshot after
model_compare
printf RUNNING_METADATA_PASSED
cache_etc_timestamp_restore
printf EXACT_PREBOOT_RESTORED
''')
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(result.stdout,b'RUNNING_METADATA_PASSEDEXACT_PREBOOT_RESTORED')
        before=records(f.run_dir/'before.meta-equality');after=records(f.run_dir/'after.meta-equality')
        self.assertEqual(before,after)
        for name in HOST.PARENTS:
            row=before[str(f.top/name)+'/']
            self.assertNotIn(b'VOLATILE',row[4])
        f.assert_baseline(self)

    def assert_running_change_refuses(self,mutation):
        f=self.fixture()
        result=self.run_model(f,'''cache_etc_timestamp_capture
model_snapshot before
printf CAPTURED
'''+mutation+'''
model_snapshot after
model_compare
cache_etc_timestamp_restore
printf BAD_SUCCESS
''')
        self.assertNotEqual(result.returncode,0,result.stderr.decode())
        self.assertIn(b'CAPTURED',result.stdout)
        self.assertNotIn(b'BAD_SUCCESS',result.stdout)
        self.assertTrue((f.etc/'.updated').exists())
        self.assertTrue((f.etc/'audisp').exists())
        return f

    def test_baseline_file_body_change_remains_a_refusal(self):
        self.assert_running_change_refuses('printf CHANGED > "$MODEL_ETC/base.conf"')

    def test_parent_and_baseline_mode_changes_remain_refusals(self):
        for operand in ('"$MODEL_ETC/audit"','"$MODEL_ETC/base.conf"'):
            with self.subTest(operand=operand):self.assert_running_change_refuses('chmod 700 '+operand)

    def test_unrelated_directory_and_regular_file_link_changes_remain_refusals(self):
        for mutation in ('mkdir "$MODEL_ETC/unrelated-child"','ln "$MODEL_ETC/base.conf" "$D/unrelated-hardlink"'):
            with self.subTest(mutation=mutation):self.assert_running_change_refuses(mutation)

    def test_user_file_and_user_directory_changes_remain_refusals(self):
        for mutation in ('printf CHANGED > "$HOME/userhome/data"','chmod 755 "$HOME/userhome"'):
            with self.subTest(mutation=mutation):self.assert_running_change_refuses(mutation)

    def test_xattr_change_remains_a_refusal(self):
        f=self.fixture()
        try:os.setxattr(f.etc/'base.conf','user.HOST_restoration_control',b'initial')
        except OSError as error:
            if error.errno in(errno.ENOTSUP,errno.EOPNOTSUPP):self.skipTest('HOST filesystem has no user xattrs')
            raise
        result=self.run_model(f,'''cache_etc_timestamp_capture
model_snapshot before
setfattr -n user.HOST_restoration_control -v CHANGED "$MODEL_ETC/base.conf"
model_snapshot after
model_compare
cache_etc_timestamp_restore
printf BAD_SUCCESS
''')
        self.assertNotEqual(result.returncode,0,result.stderr.decode())
        self.assertNotIn(b'BAD_SUCCESS',result.stdout)
        self.assertTrue((f.etc/'.updated').exists())

    def test_only_live_proc_nlink_is_normalized(self):
        self.assertEqual(EQUALITY.count('links=VOLATILE_LIVE_PROCFS_NLINK'),1)
        self.assertNotIn('preboot',EQUALITY)
        self.assertNotIn('audit',EQUALITY)
        self.assertNotIn("allowed_dirs.add('etc')",(HERE/'image.py').read_text())
    def test_actual_fixed_restoration_step_labels_leave_checkpoint_budget_unchanged(self):
        f=self.fixture()
        body='root_phase_writes=11\nphase=unchanged\n'
        for label in LABELS:
            body+=f'restoration_step {label}\nprintf "%s\\n" "$phase"\n'
        body+='[[ $root_phase_writes == 11 && ! -e $D/root-phase.checkpoint && ! -e $D/.root-phase.checkpoint.tmp ]]\n'
        result=f.run(body,before=RESTORATION_STEP)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(result.stdout.decode().splitlines(),['restoration_'+value.replace('-','_')for value in LABELS])

    def test_actual_step_parser_refuses_unknown_arity_and_shell_text_without_evaluation(self):
        f=self.fixture()
        body='''phase=unchanged
root_phase_writes=11
for label in unknown '' '$(touch EVALUATED)' 'meta_equality;touch EVALUATED' 'paths hash';do
 if restoration_step "$label";then printf BAD_ACCEPTED;exit 9;fi
 [[ $phase == unchanged ]]
done
if restoration_step;then exit 9;fi
if restoration_step paths hash;then exit 9;fi
[[ $phase == unchanged && $root_phase_writes == 11 && ! -e EVALUATED ]]
printf FIXED_LABELS_ONLY
'''
        result=f.run(body,before=RESTORATION_STEP)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(result.stdout,b'FIXED_LABELS_ONLY')
        self.assertFalse((f.top/'EVALUATED').exists())

    def test_actual_finish_trap_relays_fine_failure_in_unchanged_five_line_HOLD_frame(self):
        f=self.fixture()
        before=COMPARISON+'\n'+RESTORATION_STEP+'\n'+ROOT_FINISH+'''
timeout() {
 [[ $# == 5 && $1 == --signal=KILL && $2 == 2 && $3 == sync && $4 == -f && $5 == "$D" ]] || return 97
 [[ -f $D/failure.env && ! -e $O/summary.env ]] || return 97
 printf MODELED_SYNC_ONLY > "$D/sync-stub"
}
'''
        result=f.run('''sync_seconds=2
[[ ! -d $D/trust && ! -d $O/official-import && ! -d $O/official-trust ]]
! declare -F retain_failure_data > /dev/null
printf LEFT > "$O/left"
printf RIGHT > "$O/right"
restoration_step meta_equality
trap finish EXIT
same_bytes "$O/left" "$O/right"
printf BAD_SUCCESS
''',before=before)
        self.assertEqual(result.returncode,1,result.stderr.decode())
        self.assertNotIn(b'BAD_SUCCESS',result.stdout)
        expected=(f'PERL5423_RESTORED_BEGIN {HOST.NONCE}\nSTATUS=HOLD\n'
                  f'FAILED_PHASE=restoration_meta_equality\nEXIT_STATUS=1\n'
                  f'PERL5423_RESTORED_END {HOST.NONCE}\n').encode()
        self.assertEqual((f.data/'failure.env').read_bytes(),expected)
        self.assertEqual((f.run_dir/'summary.env').read_bytes(),expected)
        self.assertEqual((f.data/'sync-stub').read_bytes(),b'MODELED_SYNC_ONLY')
        self.assertEqual((f.data/'failure.env').stat().st_mode&0o777,0o600)
        self.assertEqual((f.run_dir/'summary.env').stat().st_mode&0o777,0o644)
        self.assertNotIn(b'PASS',expected)

    def test_production_order_keeps_exact_running_comparisons_before_preboot_cleanup(self):
        start=ROOT.index('\ncheckpoint_phase restoration\n')
        section=ROOT[start:ROOT.index('restoration_step publish\n',start)]
        cleanup=section.index('\ncache_etc_timestamp_restore\n')
        for exact in ('payload_snapshot after\n',
                      'same_bytes "$S/before.$suffix" "$S/after.$suffix"\n',
                      'same_bytes "$S/before.meta-equality" "$S/after.meta-equality"\n',
                      'assert_users\n',
                      'same_bytes "$S/pacman-log-before" "$S/pacman-log-prefix"\n',
                      'chmod 600 "$S/pacman-log-after"\n'):
            self.assertLess(section.index(exact),cleanup,exact)
        self.assertLess(cleanup,section.index('restoration_step trust_cleanup\n'))
        self.assertLess(cleanup,section.index('restoration_step sync\n'))
        self.assertEqual(ROOT.count('same_bytes "$S/before.meta-equality" "$S/after.meta-equality"'),1)
        self.assertEqual(hashlib.sha256((HERE/'image.py').read_bytes().split(b'def preserve(',1)[1]).hexdigest(),
                         '7b4c232a584b412cfdc6804d7e27087ad569b8c779da10e2dc6dec8a853bed1c')
        self.assertEqual(hashlib.sha256((HERE/'frozen/guest-runtime.sh').read_bytes()).hexdigest(),
                         '639257a6637923b9f6ee8486fa580b0603b662863fdcb51a2187fc7864568463')


if __name__=='__main__':unittest.main(verbosity=2)

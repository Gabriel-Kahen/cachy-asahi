# SPDX-License-Identifier: MIT
"""Run the actual probe in private fixtures with fictional guest identity/tools.

Only fixed D/O/PATH literals are projected into scratch. Summary bytes are never
sourced or evaluated. No VM, ALPM, Root credentials, resource query or actor runs.
The installed functional-check tail must remain byte-identical to Source48.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
NONCE='a'*32
TAIL_SHA='b7ce4bbe1016daa2ab4f0e9df97a005ff4ac8cab376aee36c5045512681eaee3'


def hold(nonce=NONCE,phase='dependency_install',code=1):
    return (f'PERL5423_RESTORED_BEGIN {nonce}\nSTATUS=HOLD\nFAILED_PHASE={phase}\n'
            f'EXIT_STATUS={code}\nPERL5423_RESTORED_END {nonce}\n').encode()


STAT=r'''#!/usr/bin/bash
set -eu
format=$2;path=${@: -1}
value=$(/usr/bin/stat "$@")
if [[ $path == "$FIXTURE_O" ]];then
 [[ $format == '%u:%g:%a' ]];printf '0:0:%s\n' "${value##*:}"
elif [[ $path == "$FIXTURE_O/user" ]];then
 [[ $format == '%u:%g:%a' ]];printf '1000:1000:%s\n' "${value##*:}"
elif [[ $path == "$FIXTURE_O/summary.env" || $path == "$FIXTURE_O/installed" ]];then
 case "$format" in
  '%u:%g:%h:%a:%s:%d:%i:%y:%z')
   IFS=: read -r u g rest <<< "$value"
   if [[ ${FIXTURE_BAD_OWNER:-0} == 1 ]];then printf '1000:1000:%s\n' "$rest";else printf '0:0:%s\n' "$rest";fi
   if [[ ${FIXTURE_CHANGE:-0} != 0 ]];then
    count=0;[[ ! -f $FIXTURE_COUNTER ]] || read -r count < "$FIXTURE_COUNTER"
    printf '%s\n' "$((count+1))" > "$FIXTURE_COUNTER"
   fi;;
  '%u:%g:%a') printf '0:0:%s\n' "${value##*:}";;
  *) printf '%s\n' "$value";;
 esac
else printf '%s\n' "$value";fi
'''


def run_probe(summary=None,*,restored=False,mode=0o644,bad_owner=False,alias=None,
              publish=None,installed=False,change=False):
    with tempfile.TemporaryDirectory(prefix='perl-probe-readiness-DATA-') as name:
        root=Path(name);data=root/'packet';runtime=root/'run';tools=root/'bin'
        for p in (data,runtime,tools):p.mkdir(mode=0o755)
        summary_path=runtime/'summary.env'
        if summary is not None:summary_path.write_bytes(summary);summary_path.chmod(mode)
        if alias=='symlink':summary_path.rename(root/'original');summary_path.symlink_to(root/'original')
        if alias=='hardlink':os.link(summary_path,root/'alias')
        if installed:
            (runtime/'installed').write_text(NONCE+'\n');(runtime/'installed').chmod(0o644)
            (runtime/'user').mkdir(mode=0o700)
        # These helpers are explicit fixture Source, not artifact/summary input.
        (data/'case.sh').write_text('case_data() { nonce='+NONCE+';probe_wait_seconds=1; }\nclock_valid() { return 19; }\n')
        scripts={
            'id':'#!/usr/bin/bash\nprintf "1000\\n"\n',
            'uname':'#!/usr/bin/bash\nprintf "aarch64\\n"\n',
            'getconf':'#!/usr/bin/bash\nprintf "16384\\n"\n',
            'cat':'#!/usr/bin/bash\nif [[ $# == 1 && $1 == /proc/1/comm ]];then printf "systemd\\n";else exec /usr/bin/cat "$@";fi\n',
            'stat':STAT,
            'head':r'''#!/usr/bin/bash
if [[ ${FIXTURE_CHANGE:-0} != 0 && -f $FIXTURE_COUNTER ]];then
 read -r count < "$FIXTURE_COUNTER"
 if [[ $count == 1 ]];then
  if [[ $FIXTURE_CHANGE == 2 ]];then
   value=$(/usr/bin/cat "$FIXTURE_O/summary.env")
   printf '%s\n' "${value/dependency_install/dependency_cleanup}" > "$FIXTURE_O/summary.env"
  else printf 'CHANGED\n' >> "$FIXTURE_O/summary.env";fi
  printf '2\n' > "$FIXTURE_COUNTER"
 fi
fi
exec /usr/bin/head "$@"
''',
            'sleep':r'''#!/usr/bin/bash
set -eu
if [[ -n ${FIXTURE_PUBLISH:-} && ! -f $FIXTURE_PUBLISHED ]];then
 cp -- "$FIXTURE_PUBLISH" "$FIXTURE_O/summary.env"
 chmod 644 "$FIXTURE_O/summary.env"
 touch "$FIXTURE_PUBLISHED"
else exec /usr/bin/sleep "$@";fi
'''}
        for command,body in scripts.items():
            p=tools/command;p.write_text(body);p.chmod(0o755)
        source=(HERE/'guest/probe.sh').read_text()
        for old,new in [('D=/var/lib/arm16k-perl5423-vm','D='+str(data)),('O=/run/arm16k-perl5423-vm','O='+str(runtime)),
                        ('export PATH=/usr/bin:/bin LC_ALL=C TZ=UTC','export PATH='+str(tools)+':/usr/bin:/bin LC_ALL=C TZ=UTC')]:
            if source.count(old)!=1:raise AssertionError('fixed fixture projection anchor')
            source=source.replace(old,new)
        script=root/'probe.sh';script.write_text(source)
        env=dict(PATH='/usr/bin:/bin',HOME=str(root),LC_ALL='C',FIXTURE_O=str(runtime),FIXTURE_BAD_OWNER=str(int(bad_owner)),
                 FIXTURE_CHANGE=str(int(change)),FIXTURE_COUNTER=str(root/'counter'),FIXTURE_PUBLISHED=str(root/'published'))
        if publish is not None:
            p=root/'complete';p.write_bytes(publish);env['FIXTURE_PUBLISH']=str(p)
        result=subprocess.run(['/usr/bin/bash','--noprofile','--norc',str(script),NONCE,*(['restored'] if restored else [])],
                              env=env,cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8)
        return dict(exit=result.returncode,stdout=result.stdout,stderr=result.stderr,published=(root/'published').exists(),
                    evaluated=(root/'EVALUATED').exists(),probed=(runtime/'user/PROBED').exists())


class Controls(unittest.TestCase):
    def test_own_install_ready_timeout_is_explicit_and_has_no_pass_claim(self):
        result=run_probe()
        self.assertNotEqual(result['exit'],0)
        self.assertIn(b'FAILURE_SOURCE=PROBE\nFAILED_PHASE=install_ready_timeout\nROOT_SUMMARY_STATE=ABSENT\n',result['stdout'])
        self.assertNotIn(b'FUNCTIONAL=PASS',result['stdout']);self.assertNotIn(b'COMMANDS=PASS',result['stdout'])
        self.assertNotIn(b'PERL5423_RESTORED_BEGIN',result['stdout'])

    def test_own_restoration_ready_timeout_is_explicit(self):
        result=run_probe(restored=True)
        self.assertNotEqual(result['exit'],0);self.assertIn(b'FAILED_PHASE=restoration_ready_timeout\n',result['stdout'])
        self.assertNotIn(b'PERL5423_RESTORED_BEGIN',result['stdout']);self.assertNotIn(b'FUNCTIONAL=PASS',result['stdout'])

    def test_fully_published_root_hold_is_relayed_once_in_both_waits(self):
        for restored in (False,True):
            result=run_probe(hold(),restored=restored)
            self.assertNotEqual(result['exit'],0);self.assertEqual(result['stdout'],b'\n'+hold())
            self.assertNotIn(b'PERL5423_PROBE_BEGIN',result['stdout']);self.assertFalse(result['probed'])

    def test_unpublished_summary_waits_for_complete_publication(self):
        result=run_probe(b'PARTIAL_PRIVATE_PENDING',mode=0o600,publish=hold(),installed=True)
        self.assertTrue(result['published']);self.assertNotEqual(result['exit'],0);self.assertEqual(result['stdout'],b'\n'+hold())
        result=run_probe(b'PARTIAL_PRIVATE_PENDING',mode=0o600)
        self.assertIn(b'FAILED_PHASE=install_ready_timeout\nROOT_SUMMARY_STATE=UNPUBLISHED\n',result['stdout'])
        self.assertNotIn(b'PARTIAL_PRIVATE_PENDING',result['stdout'])

    def test_root_hold_takes_precedence_over_stale_installed_marker(self):
        result=run_probe(hold(),installed=True)
        self.assertEqual(result['stdout'],b'\n'+hold());self.assertNotEqual(result['exit'],0);self.assertFalse(result['probed'])

    def test_invalid_nonce_frames_fields_bytes_and_exit_status_are_not_relayed(self):
        cases=[hold('b'*32),hold(code=0),hold(code=256),hold().replace(b'STATUS=HOLD',b'STATUS=HOLD\nSTATUS=PASS'),
               hold().replace(b'EXIT_STATUS=1\n',b'EXTRA=DATA\nEXIT_STATUS=1\n'),hold()[:-1],hold()+hold(),
               hold().replace(b'STATUS=HOLD',b'STATUS=H\0OLD'),hold(phase='$(touch EVALUATED)'),
               hold().replace(b'FAILED_PHASE=',b'$(touch EVALUATED)='),b'X'*16385]
        for data in cases:
            with self.subTest(data=data[:64]):
                result=run_probe(data)
                self.assertNotEqual(result['exit'],0);self.assertIn(b'FAILED_PHASE=root_summary_invalid\n',result['stdout'])
                self.assertNotIn(b'PERL5423_RESTORED_BEGIN',result['stdout']);self.assertFalse(result['evaluated'])

    def test_wrong_owner_mode_links_and_changed_content_refuse_relay(self):
        for values in (dict(bad_owner=True),dict(mode=0o666),dict(alias='symlink'),dict(alias='hardlink'),dict(change=True),dict(change=2)):
            with self.subTest(values=values):
                result=run_probe(hold(),**values)
                self.assertNotEqual(result['exit'],0);self.assertIn(b'FAILED_PHASE=root_summary_invalid\n',result['stdout'])
                self.assertNotIn(b'PERL5423_RESTORED_BEGIN',result['stdout'])

    def test_restored_pass_relay_preserves_bytes_but_cannot_satisfy_install_wait(self):
        # Relay is not host acceptance: the unchanged host checks the full PASS
        # certificate/frame. This fixture tests only trusted publication bytes.
        data=(f'PERL5423_RESTORED_BEGIN {NONCE}\nSTATUS=PASS\nPACKAGE=perl\nPERL5423_RESTORED_END {NONCE}\n').encode()
        result=run_probe(data,restored=True);self.assertEqual((result['exit'],result['stdout']),(0,b'\n'+data))
        result=run_probe(data);self.assertNotEqual(result['exit'],0);self.assertIn(b'FAILED_PHASE=root_summary_unexpected_pass\n',result['stdout'])
        self.assertNotIn(b'PERL5423_RESTORED_BEGIN',result['stdout'])

    def test_installed_ready_still_reaches_unchanged_functional_guards(self):
        result=run_probe(installed=True)
        self.assertIn(b'PERL5423_INSTALLED_BEGIN '+NONCE.encode(),result['stdout'])
        self.assertEqual(result['exit'],19);self.assertIn(b'FAILED_PHASE=probe_checks\n',result['stdout'])
        self.assertNotIn(b'FUNCTIONAL=PASS',result['stdout']);self.assertFalse(result['probed'])
        source=(HERE/'guest/probe.sh').read_bytes();anchor=b'[[ ! -e $U/PROBED && ! -L $U/PROBED ]]\n'
        self.assertEqual(hashlib.sha256(source[source.index(anchor):]).hexdigest(),TAIL_SHA)


if __name__=='__main__':unittest.main(verbosity=2)

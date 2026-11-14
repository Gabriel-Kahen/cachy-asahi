#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise genuine staged scripts through PATH in a read-only bwrap overlay.

Requires an already-built/extracted package and installed bubblewrap. No host
installation, dependency acquisition, service or device access is performed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from stage_commands import COMMANDS


def inside():
    results = []

    def run(args, data='', expected=0):
        result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=30)
        results.append(dict(args=args, exit=result.returncode, stdout=result.stdout, stderr=result.stderr))
        if result.returncode != expected:
            raise AssertionError(results[-1])
        return result.stdout

    assert os.environ['PATH'] == '/usr/bin:/bin'
    version = run(['perl', '-MConfig', '-e', 'print "$^V\n$INC{q(Config.pm)}\n"'])
    assert version == 'v5.42.3\n/usr/lib/perl5/5.42/core_perl/Config.pm\n'
    for name in COMMANDS:
        assert shutil.which(name) == '/usr/bin/'+name
        assert os.readlink('/usr/bin/'+name) == 'core_perl/'+name
        run(['perl', '-c', '/usr/bin/'+name])

    # These are direct PATH/shebang calls, including prove's child interpreter.
    with tempfile.TemporaryDirectory(prefix='perl-cli-') as temporary:
        os.chdir(temporary)
        Path('candidate.t').write_text('''use strict;
use warnings;
use Config;
use Test::More tests => 5;
use List::Util;
is("$^V", 'v5.42.3', 'candidate interpreter');
is($^X, '/usr/bin/perl', 'installed interpreter path');
is($INC{'Config.pm'}, '/usr/lib/perl5/5.42/core_perl/Config.pm', 'candidate Config');
is($Config{scriptdir}, '/usr/bin/core_perl', 'historical script path retained');
ok(grep(m{^/usr/lib/perl5/5[.]42/core_perl/auto/List/Util/Util[.]so$}, @DynaLoader::dl_shared_objects), 'candidate XS');
''')
        assert 'Result: PASS' in run(['prove', '-v', 'candidate.t'])
        assert 'Perl v5.42.3' in run(['prove', '--version'])
        assert 'Perl v5.42.3' in run(['/usr/bin/core_perl/prove', '--version'])
        assert json.loads(run(['json_pp'], '{"z":2,"a":1}')) == dict(z=2,a=1)
        assert run(['piconv', '-f', 'UTF-8', '-t', 'UTF-8'], 'plain text\n') == 'plain text\n'
        payload = b'candidate payload\n'
        Path('data.txt').write_bytes(payload)
        assert run(['shasum', '-a', '256', 'data.txt']).split()[0] == hashlib.sha256(payload).hexdigest()
        Path('sample.pod').write_text('=head1 NAME\n\nsample - candidate document\n\n=cut\n')
        assert 'candidate document' in run(['pod2text', 'sample.pod'])
        assert 'candidate document' in run(['pod2man', 'sample.pod'])
        assert 'candidate document' in run(['pod2html', '--infile=sample.pod'])
        run(['podchecker', 'sample.pod'])
        run(['ptar', '-cf', 'sample.tar', 'data.txt'])
        assert 'data.txt' in run(['ptar', '-tf', 'sample.tar'])
        dependency = subprocess.run(['perl', '-MText::Diff', '-e', '1'], capture_output=True, timeout=30)
        if dependency.returncode == 0:
            run(['ptardiff', 'sample.tar', 'sample.tar'])
            ptardiff = 'PASS_ARCHIVE_COMPARISON'
        else:
            run(['ptardiff', 'sample.tar', 'sample.tar'], expected=2)
            assert "requires the 'Text::Diff' module" in results[-1]['stderr']
            ptardiff = 'EXPECTED_REFUSAL_OPTIONAL_TEXT_DIFF_ABSENT_COMPARISON_NOT_RUN'
        assert 'data.txt' in run(['ptargrep', '-l', 'candidate', 'sample.tar'])
        assert 'ASCII' in run(['encguess', 'data.txt'])
        run(['pod2usage', '-exit', '0', '-verbose', '2', 'sample.pod'])
        assert 'undefined value' in run(['splain'], 'Use of uninitialized value $x in print at example.pl line 1.\n')
        assert 'FILEHANDLE' in run(['perldoc', '-T', '-t', '-f', 'print'])
        run(['instmodsh'], 'q\n')
        Path('sample.h').write_text('#define CANDIDATE_VALUE 42\n')
        run(['h2ph', '-d', '.', 'sample.h'])
        assert '42' in Path('sample.ph').read_text()
        Path('Sample.pl').write_text('package Sample;\nsub value { 42 }\n1;\n')
        run(['pl2pm', './Sample.pl'])
        assert Path('Sample.pm').is_file()
        run(['h2xs', '-X', '-n', 'Candidate::Smoke'])
        assert Path('Candidate-Smoke/lib/Candidate/Smoke.pm').is_file()
        mapping = ''.join(f'<U{c:04X}> \\x{c:02X} |0\n' for c in range(32,127))
        Path('smoke.ucm').write_text('<code_set_name> "Smoke"\n<mb_cur_min> 1\n<mb_cur_max> 1\n<subchar> \\x3F\nCHARMAP\n'+mapping+'END CHARMAP\n')
        run(['enc2xs', '-o', 'smoke.c', 'smoke.ucm'])
        assert Path('smoke.c').stat().st_size > 0
        assert '5.42.3' in run(['corelist', '-v', '5.42.3'])
        assert run(['xsubpp', '-v']).startswith('xsubpp version ')
        for args in (['cpan', '-v'], ['perldoc', '-V'], ['perlivp', '-h'],
                     ['libnetcfg', '-h'], ['perlbug', '-h'], ['perlthanks', '-h'],
                     ['streamzip', '-version'], ['zipdetails', '--version']):
            run(args)
    invoked = {row['args'][0] for row in results}
    assert set(COMMANDS) <= invoked
    print(json.dumps(dict(status='PASS_STAGED_PATH_SHEBANG_ONLY', interpreter=version.splitlines()[0],
                          path_resolutions=len(COMMANDS), syntax_checks=len(COMMANDS),
                          commands_invoked_through_PATH=len(set(COMMANDS) & invoked),
                          ptardiff=ptardiff,
                          invocations=results, installation='NOT_RUN', native_ARM='NOT_RUN', M2='NOT_RUN'), sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.inside:
        inside()
        return
    if args.root is None:
        parser.error('--root must name a genuine already-built/extracted package')
    root = args.root.resolve()
    if root == Path('/') or not (root/'usr/bin/core_perl').is_dir():
        parser.error('a separate staged Perl root is required')
    command = ['bwrap', '--unshare-net', '--die-with-parent', '--ro-bind', '/', '/',
               '--tmpfs', '/tmp', '--tmpfs', '/run', '--proc', '/proc', '--dev', '/dev',
               '--dir', '/run/probe-bin', '--ro-bind', '/usr/bin', '/run/probe-bin']
    for path in ('usr/bin', 'usr/lib/perl5/5.42/core_perl', 'usr/share/perl5/core_perl'):
        command += ['--ro-bind', str(root/path), '/'+path]
    command += ['--clearenv', '--setenv', 'PATH', '/usr/bin:/bin', '--setenv', 'HOME', '/tmp',
                '--setenv', 'LC_ALL', 'C', '--setenv', 'TZ', 'UTC', '--chdir', '/tmp',
                '/run/probe-bin/python3', '-B', str(Path(__file__).resolve()), '--inside']
    subprocess.run(command, check=True, timeout=180)


if __name__ == '__main__':
    main()

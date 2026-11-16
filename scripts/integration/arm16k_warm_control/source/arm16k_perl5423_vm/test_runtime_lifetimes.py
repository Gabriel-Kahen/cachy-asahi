# SPDX-License-Identifier: MIT
"""Bounded HOST core-module API/lifetime checks; never candidate/ARM acceptance."""
from pathlib import Path
import resource
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def limits():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2,) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))


def host(program):
    with tempfile.TemporaryDirectory(prefix='perl-runtime-host-API-') as directory:
        root = Path(directory)
        (root / 'probe.pl').write_text(program)
        with (root / 'stdout').open('wb') as stdout, (root / 'stderr').open('wb') as stderr:
            result = subprocess.run(['/usr/bin/perl', str(root / 'probe.pl')], cwd=root,
                env=dict(PATH='/usr/bin:/bin', HOME=str(root), LC_ALL='C'),
                stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                timeout=6, preexec_fn=limits)
        return result.returncode, (root / 'stdout').read_bytes(), (root / 'stderr').read_bytes()


class RuntimeLifetimes(unittest.TestCase):
    def test_actual_host_roundtrips_destroy_all_streams_before_thread_clone(self):
        source = (HERE / 'guest/runtime.pl').read_text()
        body = source[source.index('my $text ='):source.index("die 'JSON'")]
        # Weak references observe destruction without extending native-object lifetime.
        # Inject immediately after construction; all four must expire before clone.
        for variable, declaration in (('def', 'my ($def,$status)'), ('inf', 'my ($inf,$s)'),
                                      ('bz', 'my ($bz,$bs)'), ('bi', 'my ($bi,$is)')):
            line = next(line for line in body.splitlines() if line.startswith(declaration))
            body = body.replace(line, line + '\npush @streams,$' + variable + ';weaken($streams[-1]);')
        body = body.replace('my $shared :shared=',
            'die "live native stream before clone" if grep { defined } @streams;\nmy $shared :shared=')
        program = ('use strict;use warnings;use DB_File;use GDBM_File;use Fcntl qw(O_RDWR O_CREAT);'
            'use Compress::Raw::Zlib;use Compress::Raw::Bzip2;use threads;use threads::shared;'
            'use Scalar::Util qw(weaken);my @streams;\n' + body + 'print "HOST_API_LIFETIMES_OK\\n";\n')
        self.assertEqual(host(program), (0, b'HOST_API_LIFETIMES_OK\n', b''))
        # Deliberately restore live lexical scope: refuse before unsafe thread creation.
        mutant = program.replace('{\nmy ($def,$status)', 'my ($def,$status)', 1)
        mutant = mutant.replace('}\ndie "live native stream before clone"',
                                 'die "live native stream before clone"', 1)
        rc, out, err = host(mutant)
        self.assertNotEqual(rc, 0)
        self.assertEqual(out, b'')
        self.assertIn(b'live native stream before clone', err)

    def test_complete_target_checks_and_success_contract_remain(self):
        source = (HERE / 'guest/runtime.pl').read_text()
        self.assertIn('Compress::Raw::Bzip2->new(1,9,30,0)', source)
        for check in ("die 'DB_File roundtrip'", "die 'GDBM roundtrip'", "die 'inflate'",
                      "die 'bunzip'", "die 'threads'", "die 'JSON'", "die 'SHA'",
                      "die 'actual shared libperl mapping required'", "die 'shared/threaded'"):
            self.assertIn(check, source)
        self.assertIn('PERL5423_FUNCTIONAL_OK\\nDB_FILE=ROUNDTRIP\\nGDBM=ROUNDTRIP\\n'
                      'ZLIB=ROUNDTRIP\\nBZIP2=ROUNDTRIP\\nTHREADS=JOIN_SHARED\\nLIBPERL=SHARED\\n', source)


if __name__ == '__main__':
    unittest.main(verbosity=2)

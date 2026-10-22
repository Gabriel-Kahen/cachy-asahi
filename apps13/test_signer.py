# SPDX-License-Identifier: MIT
"""Exact original owned TEST signer body; no actor or key operation on import."""
import argparse,re,subprocess

def sign(inputs, root, packages):
    home = root / 'test-signing'; home.mkdir(mode=0o700)
    gpg = ['gpg', '--batch', '--no-options', '--homedir', str(home), '--no-auto-key-retrieve',
           '--pinentry-mode', 'loopback', '--passphrase', '']
    subprocess.run(gpg + ['--quick-generate-key', 'TEST ONLY composition <composition@test.invalid>',
                         'ed25519', 'sign', '1d'], check=True, capture_output=True, timeout=30)
    listing = subprocess.check_output(gpg + ['--with-colons', '--list-keys'], text=True, timeout=30)
    fingerprints = [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
    assert len(fingerprints) == 1 and re.fullmatch('[0-9A-F]{40}', fingerprints[0])
    (inputs / 'TEST-public.asc').write_bytes(subprocess.check_output(gpg + ['--armor', '--export', fingerprints[0]], timeout=30))
    for path in packages:
        subprocess.run(gpg + ['--output', str(path) + '.sig', '--detach-sign', str(path)], check=True, capture_output=True, timeout=30)
    return fingerprints[0]

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.parse_args();p.error('internal signing API, use source-bound entry.py')

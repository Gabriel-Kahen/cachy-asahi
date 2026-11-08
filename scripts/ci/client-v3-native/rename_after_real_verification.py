"""Host-only instrumentation of the unchanged staged v3 CLI; no crypto bypass."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

source, output, state, detached, targets = map(Path, sys.argv[1:6])
arguments = sys.argv[6:]
need_pin = '4cf428452d08ea212d8bb92d899329f3445d15877c5b79e5ff5f138b0a696e76'
assert hashlib.sha256(source.read_bytes()).hexdigest() == need_pin
assert state.is_dir() and not detached.exists() and state.parent == detached.parent
spec = importlib.util.spec_from_file_location('real_staged_v3', source)
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
original_run = subprocess.run
records = []

def recorded_run(argv, *args, **kwargs):
    result = original_run(argv, *args, **kwargs)
    index = len(records)
    row = dict(argv=[str(x) for x in argv], exit=result.returncode)
    for role in ('stdout', 'stderr'):
        raw = getattr(result, role)
        assert isinstance(raw, bytes)
        (output / f'gpg-{index:02d}.{role}').write_bytes(raw)
        row[role] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    records.append(row)
    return result

class ObservedVerifier(client.Verifier):
    verified = []
    bundles = 0
    renamed = False

    def verify(self, data_path, signature):
        result = super().verify(data_path, signature)
        self.verified.append(dict(data_sha256=hashlib.sha256(Path(data_path).read_bytes()).hexdigest(), result=result))
        return result

    def bundle(self, root, ref, signature_sha256):
        result = super().bundle(root, ref, signature_sha256)
        type(self).bundles += 1
        if self.bundles == int(targets.name):
            assert len(self.verified) == int(targets.name) + 2
            state.rename(detached)
            state.mkdir(mode=0o700)
            type(self).renamed = True
        return result

subprocess.run = recorded_run
client.Verifier = ObservedVerifier
sys.argv = [str(source), *arguments]
exit_code = 0
try:
    client.main()
except (client.Error, OSError, ValueError, TypeError, KeyError, OverflowError, subprocess.SubprocessError) as error:
    print('offline development client refused: ' + str(error), file=sys.stderr)
    exit_code = 1
finally:
    (output / 'real-verifier-record.json').write_text(json.dumps(dict(
        product_sha256=need_pin, actual_GPG_commands=records,
        actual_verified_signatures=ObservedVerifier.verified,
        completed_bundle_targets=ObservedVerifier.bundles,
        state_renamed_after_all_real_signatures=ObservedVerifier.renamed,
        crypto_success_mocks=0, exit=exit_code), sort_keys=True, indent=2) + '\n')
sys.exit(exit_code)

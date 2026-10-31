#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned synthetic TEST-signature rootless image controls, never a host image.

Run with the launcher's Python interpreter and an already staged, moved prefix.
The only executed source is this harness and the exact installed project graph.
RSA test signing is ephemeral Python arithmetic; no agent or secret key file.
"""
import argparse
import copy
import hashlib
import io
import json
import math
import os
from pathlib import Path
import secrets
import stat
import struct
import subprocess
import sys
import tarfile
import time
import types
import lzma

OWNER_SHA = '83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
BRIDGE_SHA = '467cbb9562189b79926deb9d15d9b027d7c73d2a27ba07bc01d6740941567227'
SIGNED_KIND = 'cachy-asahi-policy-signed-payload-ext4-v1'
LEGACY_KIND = 'cachy-asahi-pristine-payload-ext4-v1'
EPOCH = 1700000000
GUARDED_RUNNER = r'''
import json, os, runpy, sys
from pathlib import Path
denied, allowed, record, launcher, *arguments = sys.argv[1:]
denied, allowed = os.path.realpath(denied), os.path.realpath(allowed)
def within(path, root):
    return path == root or path.startswith(root + os.sep)
def access(event, arguments):
    if event not in ('open', 'os.listdir', 'os.scandir'):
        return
    path = arguments[0] if arguments else '.'
    if path is None:
        path = '.'
    if isinstance(path, int):
        return
    path = os.path.realpath(os.fsdecode(path))
    if within(path, denied) and not within(path, allowed):
        raise PermissionError('checkout Python source access denied: ' + path)
sys.addaudithook(access)
probe = os.path.join(denied, 'scripts/platform/release_image.py')
try:
    open(probe, 'rb')
except PermissionError:
    Path(record).write_text(json.dumps(dict(status='PASS_DELIBERATE_CHECKOUT_OPEN_DENIED',
        denied=denied, allowed_work=allowed, probe=probe,
        scope='Python open/listdir/scandir audit only; not filesystem namespace isolation')) + '\n')
else:
    raise SystemExit('checkout denial control failed')
sys.argv = [launcher] + arguments
runpy.run_path(launcher, run_name='__main__')
'''


def need(value, reason):
    if not value:
        raise ValueError(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    raw = encoded(value)
    path.write_bytes(raw)
    return sha(raw)


def module(path, digest):
    raw = path.read_bytes()
    need(sha(raw) == digest, 'installed-source-pin:' + str(path))
    result = types.ModuleType('_owned_synthetic_' + path.stem)
    result.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), result.__dict__)
    return result


def prime(bits):
    """Ephemeral TEST key material; bounded Miller-Rabin probable prime search."""
    small = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if any(candidate % p == 0 for p in small) or math.gcd(candidate - 1, 65537) != 1:
            continue
        exponent, shifts = candidate - 1, 0
        while exponent % 2 == 0:
            exponent //= 2
            shifts += 1
        for _ in range(32):
            base = secrets.randbelow(candidate - 3) + 2
            value = pow(base, exponent, candidate)
            if value in (1, candidate - 1):
                continue
            for _ in range(shifts - 1):
                value = pow(value, 2, candidate)
                if value == candidate - 1:
                    break
            else:
                break
        else:
            return candidate
    raise TimeoutError('TEST prime search cap')


def mpi(value):
    return struct.pack('>H', value.bit_length()) + value.to_bytes((value.bit_length() + 7) // 8, 'big')


def packet(tag, body):
    return bytes([0xc0 | tag, 255]) + struct.pack('>I', len(body)) + body


def subpacket(tag, body):
    need(len(body) < 190, 'small TEST signature subpacket')
    return bytes([len(body) + 1, tag]) + body


class TestSigner:
    """Finite RSA/SHA256 OpenPGP v4 fixture author, not a product signer API."""
    def __init__(self, now):
        p, q = prime(1024), prime(1024)
        while q == p:
            q = prime(1024)
        self.n, self.e = p * q, 65537
        self.d = pow(self.e, -1, math.lcm(p - 1, q - 1))
        self.created = now - 30
        body = b'\x04' + struct.pack('>I', now - 120) + b'\x01' + mpi(self.n) + mpi(self.e)
        public_frame = b'\x99' + struct.pack('>H', len(body)) + body
        self.fingerprint = hashlib.sha1(public_frame).hexdigest().upper()
        uid = b'TEST ONLY image-tools synthetic fixture <image-tools-test@invalid>'
        certification = self.sign(public_frame + b'\xb4' + struct.pack('>I', len(uid)) + uid, 0x13)
        self.public = packet(6, body) + packet(13, uid) + certification

    def sign(self, raw, kind=0):
        fingerprint = bytes.fromhex(self.fingerprint)
        hashed = subpacket(2, struct.pack('>I', self.created)) + subpacket(33, b'\x04' + fingerprint)
        if kind == 0x13:
            hashed += subpacket(27, b'\x03')
        header = bytes([4, kind, 1, 8]) + struct.pack('>H', len(hashed)) + hashed
        digest = hashlib.sha256(raw + header + b'\x04\xff' + struct.pack('>I', len(header))).digest()
        digest_info = bytes.fromhex('3031300d060960864801650304020105000420') + digest
        width = (self.n.bit_length() + 7) // 8
        framed = b'\x00\x01' + b'\xff' * (width - len(digest_info) - 3) + b'\x00' + digest_info
        signed = pow(int.from_bytes(framed, 'big'), self.d, self.n)
        unhashed = subpacket(16, fingerprint[-8:])
        return packet(2, header + struct.pack('>H', len(unhashed)) + unhashed + digest[:2] + mpi(signed))


def archive(name, links=False):
    body = (name + ': owned synthetic payload only\n').encode()
    rows = [('.PKGINFO', 'file', f'pkgname = {name}\npkgver = 1-1\narch = any\nlicense = MIT\n'.encode()),
            ('usr', 'directory', None), ('usr/share', 'directory', None),
            ('usr/share/image-tools-test', 'directory', None),
            ('usr/share/image-tools-test/' + name, 'file', body)]
    if links:
        rows += [('usr/share/image-tools-test/' + name + '-hard', 'hardlink', 'usr/share/image-tools-test/' + name),
                 ('usr/share/image-tools-test/' + name + '-sym', 'symlink', name)]
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as target:
        for path, kind, value in rows:
            info = tarfile.TarInfo(path)
            info.uid = info.gid = 0
            info.mtime = EPOCH
            info.mode = 0o755 if kind == 'directory' else 0o777 if kind == 'symlink' else 0o644
            if kind == 'file':
                info.size = len(value)
                target.addfile(info, io.BytesIO(value))
            else:
                info.type = {'directory': tarfile.DIRTYPE, 'hardlink': tarfile.LNKTYPE, 'symlink': tarfile.SYMTYPE}[kind]
                if kind != 'directory':
                    info.linkname = value
                target.addfile(info)
    return lzma.compress(stream.getvalue(), format=lzma.FORMAT_XZ)


def reference(path):
    info = path.lstat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    return dict(path=str(path), size=info.st_size, sha256=sha(path.read_bytes()),
                identity=[getattr(info, key) for key in fields])


def operand(path):
    return dict(path=str(path), bytes=path.stat().st_size, sha256=sha(path.read_bytes()))


class Controls:
    def __init__(self, prefix, work, deny_checkout=None):
        self.prefix, self.work = prefix, work
        self.deny_checkout = deny_checkout
        scripts = prefix / 'lib/cachy-asahi/image-tools/scripts'
        self.owner = module(scripts / 'virtual/owned_process.py', OWNER_SHA)
        self.bridge = module(scripts / 'platform/metadata_gated_ext4.py', BRIDGE_SHA)
        self.modules = self.bridge.sources()
        self.records = []
        self.sequence = 0
        self.environment = dict(PATH='/usr/bin:/bin', HOME=str(work), LC_ALL='C', TZ='UTC', PYTHONDONTWRITEBYTECODE='1')
        self.logs = work / 'control-commands'
        self.logs.mkdir(mode=0o700)

    def command(self, argv, name, expected=0):
        self.owner.prepare()
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True, cwd=self.work, env=self.environment)
        result = self.owner.supervise(child, cap=150, retirement=1.0, grace=.2, group=True, max_output=1024**2)
        raw = result.pop('output')
        self.sequence += 1
        stem = f'{self.sequence:02d}-{name}'
        (self.logs / (stem + '.log')).write_bytes(raw)
        save(self.logs / (stem + '.json'), dict(argv=[str(x) for x in argv], environment=self.environment,
                                               supervision=result, sha256=sha(raw), bytes=len(raw), owner_sha256=OWNER_SHA))
        need(result['reaped'] and result['ownership'] == 'REAPED' and not result['timeout'] and not result['signals'],
             'control-command-ownership-or-timeout:' + stem)
        need((result['exit'] == 0) if expected == 0 else (result['exit'] != 0), 'control-unexpected-exit:' + stem)
        self.records.append(dict(name=name, expected_exit=expected, actual_exit=result['exit'], log=stem))
        if expected != 0:
            return raw
        return json.loads(raw)

    def cli(self, mode, recipe, output=None, receipt=None, name=None, expected=0):
        args = [str(self.prefix / 'bin/cachy-asahi-image-tools'), mode, '--recipe', str(recipe),
                '--recipe-sha256', sha(recipe.read_bytes())]
        if output is not None:
            args += ['--output', str(output)]
        if receipt is not None:
            args += ['--receipt-sha256', receipt]
        if self.deny_checkout is not None:
            record = self.logs / f'{self.sequence + 1:02d}-source-access-denial.json'
            args = [sys.executable, '-IB', '-c', GUARDED_RUNNER, str(self.deny_checkout),
                    str(self.work), str(record)] + args
        return self.command(args, name or mode, expected)

    def recipe(self, name, selection, policy, kind=SIGNED_KIND):
        target = self.work / name
        target.mkdir(mode=0o700)
        recipe = dict(schema_version=1, kind=kind, epoch=EPOCH, inputs={})
        for key, value in dict(selection=selection, authentication=policy, tool_pins=self.tool_pins,
                               metadata_pins=self.metadata_pins, root_policy=dict(mode=0o755, uid=0, gid=0, acl=None, xattrs={})).items():
            path = target / (key + '.json')
            recipe['inputs'][key] = dict(path=str(path), sha256=save(path, value))
        save(target / 'recipe.json', recipe)
        return target / 'recipe.json'

    def run(self):
        encoder, metadata = self.modules['encoder'], self.modules['metadata']
        encoder.ACTOR_DIRECTORY = self.work / 'profile-actors'
        encoder.ACTOR_DIRECTORY.mkdir(mode=0o700)
        self.tool_pins = encoder.tool_pins(dict(interface=encoder.TOOL_INTERFACE, ldd='/usr/bin/ldd',
                    tools={name: '/usr/bin/' + name for name in encoder.TOOL_NAMES}))
        candidates = (Path('/usr/lib/libarchive.so'), Path('/usr/lib/x86_64-linux-gnu/libarchive.so.13'),
                      Path('/usr/lib/aarch64-linux-gnu/libarchive.so.13'))
        library = next((x for x in candidates if x.exists()), None)
        need(library is not None, 'explicit-supported-libarchive-not-found')
        self.metadata_pins = metadata.pins(dict(interface=metadata.SUPPORTED_INTERFACE, library=str(library.resolve()),
                                               ldd='/usr/bin/ldd', headers=[]))
        now = int(time.time())
        signer = TestSigner(now)
        operands = self.work / 'synthetic-operands'
        operands.mkdir(mode=0o700)
        public = operands / 'public.gpg'
        public.write_bytes(signer.public)
        trusted = operands / 'trusted.txt'
        trusted.write_text(signer.fingerprint + ':4:\n')
        revoked = operands / 'revoked.txt'
        revoked.write_bytes(b'')
        selection = dict(schema_version=1, scope='EXACT_LOCAL_SIGNED_ARCHIVE_SELECTION_V1', release_set=None, packages=[])
        for index, name in enumerate(('image-tools-test-one', 'image-tools-test-two')):
            path = operands / (name + '.pkg.tar.xz')
            path.write_bytes(archive(name, links=index == 0))
            signature = operands / (name + '.sig')
            signature.write_bytes(signer.sign(path.read_bytes()))
            identity = dict(name=name, version='1-1', arch='any')
            selection['packages'].append(dict(identity=identity, archive=reference(path), signature=reference(signature),
                primary_fingerprint=signer.fingerprint,
                metadata=dict(identity, depends=[], provides=[], conflicts=[], replaces=[], license=['MIT'])))
        # Drop signing factors before executing the installed production verifier.
        del signer.d
        policy = dict(schema_version=1, profile='operator-policy-offline-signed-pristine-v1',
            selection_sha256=sha(encoded(selection)), release_set=None, issued=now - 60, expires=now + 3600,
            signers=[dict(primary=signer.fingerprint, signature_not_before=now - 180, not_after=now + 3600)],
            gpg=operand(Path('/usr/bin/gpg')), public_keyring=operand(public), trusted=operand(trusted), revoked=operand(revoked))
        recipe = self.recipe('good-inputs', selection, policy)
        output = self.work / 'assembled'
        plan = self.cli('plan', recipe)
        need('NO_ARCHIVE_OR_NATIVE_ACTOR' in plan['status'], 'plan-status')
        assembled = self.cli('assemble', recipe, output)
        need(assembled['status'] == 'PASS_RECIPE_BOUND_PRISTINE_PAYLOAD_IMAGE', 'assemble-status')
        receipt = sha((output / 'receipt.json').read_bytes())
        before = {str(p.relative_to(output)): sha(p.read_bytes()) for p in output.rglob('*') if p.is_file()}
        for mode in ('verify', 'resume'):
            result = self.cli(mode, recipe, output, receipt)
            need(result['status'] == 'VERIFIED_COMPLETED_PRISTINE_PAYLOAD_IMAGE' and result['actors_rerun'] is False,
                 mode + '-actor-free')
        after = {str(p.relative_to(output)): sha(p.read_bytes()) for p in output.rglob('*') if p.is_file()}
        need(before == after, 'verify-resume-changed-output')
        self.cli('assemble', recipe, output, name='existing-output-refusal', expected=1)
        self.cli('resume', recipe, output, '0' * 64, name='wrong-receipt-refusal', expected=1)
        legacy = self.recipe('legacy-inputs', selection, policy, kind=LEGACY_KIND)
        self.cli('plan', legacy, name='unsigned-kind-refusal', expected=1)
        changed = self.recipe('tampered-inputs', selection, policy)
        (changed.parent / 'selection.json').write_bytes(b'{}\n')
        no_output = self.work / 'tampered-output'
        self.cli('assemble', changed, no_output, name='input-pin-refusal', expected=1)
        need(not no_output.exists(), 'input-tamper-created-output')
        invalid = copy.deepcopy(selection)
        bad_signature = operands / 'invalid.sig'
        raw = Path(invalid['packages'][0]['signature']['path']).read_bytes()
        bad_signature.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        invalid['packages'][0]['signature'] = reference(bad_signature)
        bad_policy = copy.deepcopy(policy)
        bad_policy['selection_sha256'] = sha(encoded(invalid))
        bad_recipe = self.recipe('bad-signature-inputs', invalid, bad_policy)
        failed = self.work / 'signature-refused'
        self.cli('assemble', bad_recipe, failed, name='genuine-signature-refusal', expected=1)
        need((failed / 'INCOMPLETE.json').is_file() and not (failed / 'receipt.json').exists()
             and not (failed / 'pipeline/encoded/root.ext4').exists(), 'signature-refusal-output-state')
        self.cli('resume', bad_recipe, failed, '0' * 64, name='incomplete-resume-refusal', expected=1)
        inventory = json.loads((output / 'pipeline/encoded/inventory.json').read_bytes())
        nodes = inventory['nodes']
        need(nodes['usr/share/image-tools-test/image-tools-test-one']['inode'] ==
             nodes['usr/share/image-tools-test/image-tools-test-one-hard']['inode'], 'real-hardlink-readback')
        need(nodes['usr/share/image-tools-test/image-tools-test-one-sym']['type'] == 'symlink', 'real-symlink-readback')
        result = dict(status='PASS_HOST_OWNED_SYNTHETIC_RELOCATED_IMAGE_CONTROLS',
            commands=self.records, image=assembled['image'], receipt_sha256=receipt,
            prefix=str(self.prefix), interpreter=sys.executable, signer_fingerprint=signer.fingerprint,
            checkout_source_access=dict(denied=str(self.deny_checkout) if self.deny_checkout else None,
                scope='Python open/listdir/scandir audit only; not filesystem namespace isolation'),
            signing='EPHEMERAL_STDLIB_TEST_RSA_2048_OPENPGP_V4_NO_AGENT_NO_SECRET_KEY_FILE',
            payload_nodes=len(nodes), source_sha256=sha(Path(__file__).read_bytes()),
            no_actor_verify_resume=True, positive_artifacts_preserved=True,
            boundaries=dict(package_transaction='NOT_RUN', native_ARM='NOT_RUN', M2='NOT_RUN', boot='NOT_RUN', release='NOT_ACCEPTED'))
        save(self.work / 'functional-result.json', result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', required=True, type=Path)
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--deny-checkout', type=Path)
    args = parser.parse_args()
    prefix, work = args.prefix.absolute(), args.work.absolute()
    need(prefix == prefix.resolve() and work.parent == work.parent.resolve(), 'canonical-paths-required')
    work.mkdir(mode=0o700)
    os.chmod(work, 0o700)
    denied = args.deny_checkout.absolute() if args.deny_checkout else None
    if denied is not None:
        need(denied == denied.resolve() and prefix != denied and denied not in prefix.parents,
             'moved-prefix-must-be-outside-denied-checkout')
    print(json.dumps(Controls(prefix, work, denied).run(), sort_keys=True))


if __name__ == '__main__':
    main()

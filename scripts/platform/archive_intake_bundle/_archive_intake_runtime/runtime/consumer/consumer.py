"""Closed recovered-two association consumer; readiness only, never assembly."""
import ast
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

BASE = Path(__file__).absolute().parent
FILE_ROWS = (('assembler.py', 21554, 420, 'ae6aa9acbfc2aa84e5bb1095235b2060d8637bafeae57510aab579a5a46f526e'), ('inputs/validate_plan.py', 16890, 420, 'c2ba2c6bd183ce4f300aec16757707017d273a7119b45072b1d2667d07ae0776'), ('inputs/assembly-plan.json', 153773, 420, 'c1f3379385d210b8464d28b9e876141bec9dd45768c58ab5157c8580fabf92fe'), ('inputs/package-reference-index.json', 108229, 420, '498078ecae47dc3cfa53a0c5580b2d4b1d4d4fd4dbaaa88772372f3240b00a68'), ('two-associations.json', 9676, 420, '99178987d84a503c56a30c392812b80b3a8491f800e1f880d6427d9defd57203'), ('inputs/image-inventory.json', 340100, 420, '5c1630b5cdf07898118979895682c3a3b705e416c9840ada4e1a5193dccd6941'), ('config/fstab.ext4.txt', 220, 420, '7e64abac2c07f61a3c4f420c381e5b1ed719dd72654dfb98ed5598eaab208675'), ('proof/proposal-receipt.json', 23187, 420, '4b6921dee5fa3d223e7aa3657f257f3d9362c6c270053c8128fe43fa6c8e8925'), ('proof/proposal-peer-receipt.json', 12141, 420, 'e435889658b54127626b4023f0a149b6c59bee4e803ffabc25af28cd573ebbc2'), ('proof/actual-receipt.json', 8182, 384, '53747d29b02c11517d3c330530f9a6de57afcd9575e0c75c8f23f2dbd7fb6b3c'), ('proof/capture-receipt.json', 9409, 420, '08895fac45c29fb67f37b78687f6bfffd2f61f0e66dbec1cf3cc7634b0a2e156'), ('proof/execution-plan.json', 7808, 420, 'fb97ce77914c8646770929750f8fc838fdf2353c1fc26f6a965ef22695e20a19'), ('proof/process-observations.json', 38593, 384, '8d19c8f6b70218007b1ce06766913c48b4fdeabe5fe6796fb44b6d09f59ef02e'), ('proof/retained-0.json', 42147, 420, '63a4292184dd80c67e2b735d0221f0117fc5d860e59d4ebe043be73cbb862250'), ('proof/retained-1.json', 42474, 420, 'f9649bbed45f89f5214a318d2214ae70cc5a11d6485354a252cf752168b4465b'), ('proof/retained-2.json', 11274, 420, '9407330375b60db80180abdbfffdd50bdd811c3269a9e665f8696efb8cbe223e'), ('proof/retained-3.json', 1531, 420, '0c4c8e7755195c6f33f83df9de746c4406520806e0e4856315444d0e23f68205'), ('proof/metadata-networkmanager.json', 16698, 384, 'b9c1c51c6f264acdafc8589d960443c6644a9c50b705835e177e747f2ef2184c'), ('proof/metadata-perl.json', 13058, 384, 'b7ff2f4c6a7e3fda9859603ec4f81e34f358d7c869b7ae56333dfa4cbb751057'), ('proof-source/authenticate_missing.py', 23070, 420, '6af079cf10f8ebcc9416bf64bca4336ea03dbbf13f99ebd98a83808365f2fe59'), ('proof-source/candidate-urls.json', 3056, 420, 'ee75d860bed4bec5f6709a52624585beb2215a165968c9522d844f64090d0975'), ('proof-source/capture.py', 26406, 420, 'ce73314eb5a75b8afb963217fba15065106ae3f6ee081599a1ba7ab620b044c8'), ('proof-source/lifecycle.py', 53288, 420, 'e408a540765ede2350a57abd311e8814d516ab379351fe28751a20250a3a8461'), ('proof-source/operator-networkmanager.txt', 31474, 420, 'fe90fc61a1cb008f822a67ff141b6ff005deb0d92a63e1dfae6be33fcc3571da'), ('proof-source/operator-perl.txt', 29072, 420, '813812414d26ac3c8890ece66e6f988f486e8a07e5ba9951cbc4dde770f2a964'), ('proof-source/package_checks.py', 17706, 420, 'e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8'), ('proof-source/metadata_child.py', 2476, 420, '29cd63c5b70ba351d6d1d63260e3bbed89bde5b24a34a58c62c4b39e43c8f715'), ('proof-source/recover.py', 9272, 420, '45c99099f4a2c94b7ed0091914539c8c8e113739fece56c9a6a1b291e2561c82'))
FP = '68B3537F39A313B3E574D06777193F152BDBE6A6'
CERT = '6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f'


def need(value, code):
    if not value:
        raise ValueError(code)


def decode(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'association-duplicate-json-key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'association-nonfinite-json'))


def state(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


@contextmanager
def snapshot():
    """No input paths: fixed names, owned directories and pinned regular leaves."""
    need(BASE == BASE.resolve(), 'association-source-directory')
    need(type(FILE_ROWS) is tuple and len(FILE_ROWS) == 28, 'association-source-union')
    dirs = {}
    held = []
    raws = {}
    try:
        for name in ('', 'inputs', 'config', 'proof', 'proof-source'):
            p = BASE / name
            before = p.lstat()
            need(stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid()
                 and stat.S_IMODE(before.st_mode) == 0o700, 'association-directory-owner-mode')
            fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            held.append((p, fd, state(before)))
            need(state(os.fstat(fd)) == state(before), 'association-directory-identity')
            dirs[name] = fd
        need(sum(row[1] for row in FILE_ROWS) <= 2 * 1024**2, 'association-total-bound')
        for name, size, mode, digest in FILE_ROWS:
            need(type(name) is str and type(size) is type(mode) is int
                 and 0 < size <= 1024**2 and type(digest) is str
                 and re.fullmatch('[0-9a-f]{64}', digest), 'association-source-row')
            parent, leaf = name.rsplit('/', 1) if '/' in name else ('', name)
            need(parent in dirs and leaf not in ('', '.', '..') and '/' not in leaf
                 and name not in raws, 'association-source-name')
            p = BASE / name
            before = os.stat(leaf, dir_fd=dirs[parent], follow_symlinks=False)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and before.st_uid == os.getuid() and before.st_size == size
                 and stat.S_IMODE(before.st_mode) == mode, 'association-file-owner-type-mode-size')
            fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=dirs[parent])
            held.append((p, fd, state(before)))
            need(state(os.fstat(fd)) == state(before), 'association-file-identity')
            data = bytearray()
            while len(data) <= size:
                part = os.read(fd, min(65536, size + 1 - len(data)))
                if not part:
                    break
                data.extend(part)
            raw = bytes(data)
            need(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest,
                 'association-file-pin')
            raws[name] = raw
        def check():
            need(all(state(os.fstat(fd)) == before == state(p.lstat())
                     for p, fd, before in held), 'association-held-drift')
        check()
        yield raws, check
        check()
    except OSError:
        raise ValueError('association-custody-read-refused') from None
    finally:
        for _, fd, _ in reversed(held):
            os.close(fd)


def loaded(name, raw):
    module = types.ModuleType('_recovered_two_' + name)
    module.__file__ = str(BASE / name)
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def associations(raws, plan, index):
    """Bind precisely two retained data facts, without reading any archive/tool."""
    side = decode(raws['two-associations.json'])
    actual = decode(raws['proof/actual-receipt.json'])
    recovery = decode(raws['proof/retained-2.json'])
    peer = decode(raws['proof/retained-3.json'])
    execution = decode(raws['proof/execution-plan.json'])
    observations = decode(raws['proof/process-observations.json'])
    need(side['schema_version'] == 2 and side['certificate_sha256'] == CERT
         and side['primary_fingerprint'] == FP and side['Root_selection_required'] is True
         and side['all261_accepted'] is side['image_issuer_accepted'] is False,
         'association-scope')
    need(actual['status'] == 'PASS_TWO_EXACT_SIGNED_ARCHIVE_DATA_ONLY'
         and actual['failures'] == [] and actual['public_certificate']['source_sha256'] == CERT
         and actual['public_certificate']['primary_fingerprint'] == execution['primary_fingerprint'] == FP,
         'association-retained-actual')
    need(peer['author_receipt_sha256'] == hashlib.sha256(raws['proof/retained-2.json']).hexdigest()
         and peer['authenticated_rows'] == 28 and peer['all261_accepted'] is False,
         'association-independent-proof')
    pins = {name: (size, mode, digest) for name, size, mode, digest in FILE_ROWS}
    for field, name in (('plan', 'inputs/assembly-plan.json'), ('index', 'inputs/package-reference-index.json'),
                        ('actual_receipt', 'proof/actual-receipt.json'), ('execution_plan', 'proof/execution-plan.json'),
                        ('process_observations', 'proof/process-observations.json'),
                        ('source_capture_receipt', 'proof/capture-receipt.json')):
        r = side[field]
        need((r['bytes'], r['mode'], r['sha256']) == pins[name], 'association-side-reference')
    need(side['captured_tools'] == execution['tools'] and side['execution_sources'] == execution['execution_sources'],
         'association-execution-proof')
    for original, r in side['execution_sources'].items():
        if original.endswith('/keys/certificate.gpg'):
            need(r['sha256'] == CERT, 'association-certificate-source')
            continue
        name = 'proof-source/' + original.rsplit('/', 1)[1]
        need(name in pins and (r['bytes'], r['mode'], r['sha256']) == pins[name],
             'association-proof-source')
    tree = ast.parse(raws['proof-source/authenticate_missing.py'])
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'signature_status')
    scope = {'need': need}
    exec(compile(ast.Module(body=[function], type_ignores=[]), 'captured-signature-status', 'exec'), scope)
    tree = ast.parse(raws['proof-source/metadata_child.py'])
    nodes = []
    started = False
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Tuple)
            and [x.id for x in t.elts] == ['pkg', 'bld'] for t in node.targets):
            started = True
        if started and isinstance(node, (ast.Assign, ast.Assert)):
            nodes.append(node)
    need(len(nodes) == 4, 'association-metadata-predicate-source')
    metadata_code = compile(ast.Module(body=nodes, type_ignores=[]), 'captured-metadata-predicates', 'exec')
    need(len(side['associations']) == 2 and {p['identity']['name'] for p in side['associations']}
         == {'networkmanager', 'perl'}, 'association-two-closure')
    for association in side['associations']:
        identity = association['identity']
        name = identity['name']
        need(identity == dict(name=name, arch='aarch64',
             version={'networkmanager': '1.58.1-1', 'perl': '5.42.2-2'}[name]), 'association-exact-tuple')
        p = next(p for p in actual['packages'] if p['identity'] == identity)
        for field in ('archive', 'signature'):
            r = association[field]
            need(r == dict(path=p[field]['path'], size=p[field]['bytes'], sha256=p[field]['sha256'])
                 and p[field]['identity'] == identity, 'association-artifact-pair')
            held = recovery['indexed_artifacts'][r['path'].split('/cachy-asahi/', 1)[1]]
            need(held['bytes'] == r['size'] and held['sha256'] == r['sha256'], 'association-retained-artifact-pin')
        need(association['signed_database_association'] is association['independent_owner_trust_accepted'] is False,
             'association-owner-or-database-promotion')
        r = association['metadata']; leaf = 'proof/metadata-' + name + '.json'
        need((r['bytes'], r['mode'], r['sha256']) == pins[leaf]
             and r['sha256'] == p['metadata_reference']['sha256'], 'association-metadata-pin')
        metadata = decode(raws[leaf]); need(metadata['identity'] == identity, 'association-metadata-tuple')
        exec(metadata_code, {'found': metadata['metadata'], 'expected': identity, 're': re})
        commands = [r for r in observations if r['argv'][0] == execution['tools_by_name']['gpgv']
                    and r['argv'][-2:] == [p['signature']['path'], p['archive']['path']]]
        need(len(commands) == 1 and commands[0]['returncode'] == 0
             and commands[0]['cleanup']['reaped'] is True and commands[0]['cleanup']['errors'] == [],
             'association-retained-signature-exit')
        result = scope['signature_status'](commands[0]['stdout'].encode('ascii'), FP)
        need(result == p['signature_verification'] == association['retained_signature_verification'],
             'association-retained-signature-status')
        for rows in (plan['packages'], index['packages']):
            r = next(r for r in rows if r['identity']['name'] == name)
            need(r['identity'] == identity and r['archive'] == association['archive'], 'association-selected-reference')
    return 'EXACT_TWO_RETAINED_SIGNED_DATA_ASSOCIATIONS'


def readiness():
    with snapshot() as (raws, check):
        plan = decode(raws['inputs/assembly-plan.json'])
        index = decode(raws['inputs/package-reference-index.json'])
        verified = associations(raws, plan, index)
        check()
        assembler = loaded('assembler.py', raws['assembler.py'])
        result = assembler.readiness()
        check()
        contract = result['contract']
        need(len(contract['missing_inputs']) == 18 and contract['retained_archive_metadata'] == 261
             and len(contract['acceptance']) == 9 and all(v is False for v in contract['acceptance'].values()),
             'association-acceptance-or-missing-promotion')
        return dict(status='ASSOCIATION_CONSUMER_VALID_ASSEMBLY_BLOCKED18',
                    retained_association=verified, readiness=result, all259_crypto_accepted=False,
                    all261_accepted=False, source_grant='NOT_RUN', actual_assembly='NOT_RUN')


if __name__ == '__main__':
    need(len(sys.argv) == 1, 'association-cli-no-input-paths')
    print(json.dumps(readiness(), sort_keys=True, allow_nan=False))

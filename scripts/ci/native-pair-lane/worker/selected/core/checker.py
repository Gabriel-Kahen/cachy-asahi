# SPDX-License-Identifier: MIT
"""Private checker bridge. Live adapter, loaded Source and ABI grants are external.

This module never selects a loader or creates an OS/process/native actor. Root
must load this exact held Source closure before issuing an explicit grant. The
proposal controls use inert Ops and a substituted entire ctypes API.
"""
import hashlib
import re
import artifact_custody as custody
import pair_archive
import pair_compare
import zstd_owner

SOURCES = ('authority.py', 'artifact_custody.py', 'zstd_owner.py',
           'pair_archive.py', 'pair_compare.py', 'checker.py')
INVENTORY_BYTES = 6674


def need(ok, code):
    if not ok:
        raise ValueError(code)


def record(authority, error):
    try:
        authority.record_failure(error)
    except BaseException:
        pass


class HelperGrant:
    """Bind six held Source files, selected19 and exact inventory to one Owner.

    `admitted` defaults False. Setting it is a Root policy decision, not proof of
    ABI/platform/loading compatibility. expected_rows/binding must originate in
    Root's authenticated Source registration, never from an output's claims.
    """
    def __init__(self, owner, sources, recipes, inventory, expected_rows,
                 expected_binding, *, admitted=False):
        self.owner, self.authority = owner, owner.authority
        self.sources, self.recipes, self.inventory = sources, recipes, inventory
        self.rows, self.binding = expected_rows, expected_binding
        self.admitted = admitted is True
        self._issued, self._outputs = {}, {}
        if self.admitted:
            self.authority.claim_checker(self, owner)

    def held(self, artifact):
        need(type(artifact) is custody.Artifact and artifact._owner is self.owner
             and self.owner.authority is self.authority, 'checker-held-owner')
        artifact.verify()

    def verify(self):
        try:
            self.authority.check()
            need(self.admitted and self.authority.execution_granted is True,
                 'checker-root-grant-pending')
            need(self.authority._checker is self and self.authority._custody is self.owner,
                 'checker-original-grant-binding')
            need(type(self.sources) is dict and set(self.sources) == set(SOURCES),
                 'checker-source-membership')
            expected = custody.rows(self.rows, count=6, total=custody.SOURCE_BYTES,
                                    each=custody.SOURCE_BYTES)
            need(set(expected) == set(SOURCES) and pair_compare.digest(expected) == self.binding,
                 'checker-source-binding')
            for name in SOURCES:
                item = self.sources[name]; self.held(item)
                need({'bytes': item.size, 'mode': item.mode, 'sha256': item.sha256} == expected[name],
                     'checker-source-pin')
            need(type(self.recipes) is dict and set(self.recipes) == set(custody.SOURCE19),
                 'checker-source19-membership')
            for name, row in custody.SOURCE19.items():
                item = self.recipes[name]; self.held(item)
                need({'bytes': item.size, 'mode': item.mode, 'sha256': item.sha256} == row,
                     'checker-source19-pin')
            self.held(self.inventory)
            need(self.inventory.size == INVENTORY_BYTES and self.inventory.mode == 0o644
                 and self.inventory.sha256 == pair_compare.INVENTORY, 'checker-inventory-pin')
            self.owner.verify_all()
            self.authority.check()
            return True
        except BaseException as error:
            record(self.authority, error)
            raise

    def installed(self):
        """Read the exact small inventory through its retained authenticated handle."""
        self.held(self.inventory); self.inventory.rewind()
        raw = bytearray()
        while len(raw) < INVENTORY_BYTES:
            data = self.inventory.read(INVENTORY_BYTES - len(raw))
            need(type(data) is bytes and data, 'checker-inventory-short')
            raw.extend(data)
        need(self.inventory.read(1) == b'' and hashlib.sha256(raw).hexdigest() == pair_compare.INVENTORY,
             'checker-inventory-body')
        lines = bytes(raw).decode('ascii').splitlines()
        need(len(lines) == 341 and len(set(lines)) == 341
             and all(re.fullmatch(r'[A-Za-z0-9@+_.-]+ [^\s\x00-\x1f\x7f]+', s) for s in lines),
             'checker-inventory-shape')
        self.held(self.inventory)
        return sorted(s.replace(' ', '-', 1) for s in lines)


def check_artifact(artifact, library, grant, *, package, label, loader):
    """Return the seven-key pair summary only after all held rechecks pass."""
    authority = grant.authority
    try:
        grant.verify(); grant.held(artifact); grant.held(library)
        need(package in pair_compare.PAIRS, 'checker-package')
        need(label in pair_compare.PAIRS[package] and label not in grant._issued
             and all((artifact._identity.device, artifact._identity.inode) !=
                     (prior._identity.device, prior._identity.inode)
                     for prior in grant._outputs.values()), 'checker-four-fresh-outputs')
        need(getattr(artifact, '_output', False) is True
             and grant.owner.ops.output_owned(artifact.path) is True,
             'checker-positive-output-lease')
        name = 'cachy-asahi-' + ('topmem' if package == 'topmem' else 'fish-bang-bang')
        artifact_name = name + '-0.1.0-1-any.pkg.tar.zst'
        need(artifact.path.rsplit('/', 1)[-1] == artifact_name, 'checker-output-name')
        # Decoder hashes compressed bytes through the very same held descriptor.
        decoded = zstd_owner.decode(artifact, library, authority, loader=loader)
        report = pair_archive.interpret(decoded, name, pair_compare.EPOCH,
                                        pair_archive.RECIPE_PIN[name], authority)
        need(sorted(report['BUILDINFO']['installed']) == grant.installed(),
             'checker-exact-buildinfo-inventory')
        summary = {'artifact': artifact_name, 'compressed_sha256': artifact.sha256,
                   **{k: report[k] for k in ('payload_sha256', 'pkginfo_sha256', 'buildinfo_sha256')},
                   'checker_source_sha256': grant.binding,
                   'decoded_metadata_source_sha256': grant.rows['pair_archive.py']['sha256']}
        grant.held(artifact); grant.held(library); grant.verify(); authority.check()
        grant._issued[label], grant._outputs[label] = dict(summary), artifact
        return summary
    except BaseException as error:
        record(authority, error)
        raise


def finalize_pairs(grant, expected, builds, comparisons):
    """Recheck all held inputs before/after pure equality; cleanup is caller-owned.

    A result must remain private until Root proves cleanup/publication under the
    same original J. This function cannot attest a container journal or turn
    the private gate into a baseline-eight-build or hardware acceptance receipt.
    """
    try:
        grant.verify()
        pair_compare.validate_expected(expected, grant.authority)
        pair_compare.bounded(builds, grant.authority)
        pair_compare.bounded(comparisons, grant.authority)
        need(expected['checker_source_sha256'] == grant.binding
             and expected['decoded_metadata_source_sha256'] == grant.rows['pair_archive.py']['sha256'],
             'checker-summary-source-binding')
        need(type(builds) is dict and set(builds) == set(pair_compare.LABELS)
             and set(grant._issued) == set(pair_compare.LABELS), 'checker-four-issued-summaries')
        for label in pair_compare.LABELS:
            pair_compare.closed(builds[label], pair_compare.BUILD, 'checker-build-shape')
            need(builds[label]['summary'] == grant._issued[label], 'checker-issued-summary-binding')
            grant.held(grant._outputs[label])
        result = pair_compare.check_pair_set(expected, builds, comparisons, grant.authority)
        grant.verify(); grant.authority.check()
        return result
    except BaseException as error:
        record(grant.authority, error)
        raise

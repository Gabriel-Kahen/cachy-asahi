#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit one-package data-leaf update with held auxiliary/link state.

Python API only, on the existing guarded disposable-root path. An authenticated
prior archive is mandatory. No default adapter, native code update or recovery.
"""
import importlib.util
from dataclasses import asdict
import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace

import aux_checkpoint as aux
import internal_runtime as strict
import linked_runtime
import root_link_selection as links
import scale_update as scale

# A separate instance of the existing bounded decoder, with a narrower control
# allowlist. Never change either existing archive module or its caller globals.
_spec = importlib.util.spec_from_file_location('_prior_aux_archive_policy', Path(__file__).with_name('archive_stream.py'))
archives = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = archives
_spec.loader.exec_module(archives)
archives.CONTROLS = archives.CONTROLS - {'.INSTALL'}


class _DataDigest:
    """Retain real hashing while refusing Linux native/script file prefixes."""
    def __init__(self):
        self.digest, self.prefix = hashlib.sha256(), b''

    def update(self, block):
        self.prefix = (self.prefix + block[:4])[:4]
        strict.need(not self.prefix.startswith((b'\x7fELF', b'#!')), 'native ELF or script payload unsupported')
        self.digest.update(block)

    def hexdigest(self):
        return self.digest.hexdigest()


# This facade belongs only to the private parser instance, not hashlib itself.
archives.hashlib = SimpleNamespace(sha256=_DataDigest)


class Runtime(linked_runtime.Runtime):
    def __init__(self, args, config, *, comparator_path):
        strict.need(getattr(args, 'prior_archive', None) is not None, 'explicit authenticated prior archive required')
        super().__init__(args, config, comparator_path=comparator_path)
        self.selected_package = None
        self.control_accounting = {}
        self.control_limits = archives.Limits(**asdict(self.archive_limits))

    def tree(self, root):
        self.recheck_prior()
        nodes = super().tree(root)
        self.recheck_prior()
        return nodes

    def selection(self, snapshot, before, desired):
        strict.need(self.baseline is not None, 'complete auxiliary baseline required')
        rows = snapshot['release']['packages']
        strict.need(len(rows) == 1 and desired == {rows[0]['name']: rows[0]['version']},
                    'one exact authenticated release package required')
        self.selected_package = rows[0]['name']
        strict.Runtime.selection(self, snapshot, before, desired)
        path = snapshot['bundle'].parent.parent / 'prior-package/archive'
        audited = archives.archive_payload(path, self.control_limits, self.control_accounting)
        strict.need(audited == self.prior['payload'], 'prior control audit payload differs')
        self._leaves(self.prior['payload'], self.baseline['nodes'], old=True)
        self.recheck_prior()

    def archive_payload(self, path, accounting):
        strict.need(self.prior is not None, 'authenticated prior selection required before new archive')
        payload = super().archive_payload(path, accounting)
        audited = archives.archive_payload(path, self.control_limits, self.control_accounting)
        strict.need(audited == payload, 'new control audit payload differs')
        self.recheck_prior()
        return payload

    def _leaves(self, payload, seed, *, old=False):
        """Conservative data-only namespace; ordinary shared ancestors stay held."""
        strict.need(self.prior is not None and self.selected_package is not None, 'authenticated prior selection required')
        prefixes = tuple('usr/share/' + suffix for suffix in
                         (self.selected_package, 'doc/' + self.selected_package, 'licenses/' + self.selected_package))
        def data_path(name):
            return any(name.startswith(prefix + '/') for prefix in prefixes)
        combined = dict(seed, **payload)
        protected = set(self.aux_before['closure']) | set(links.LINK_NODES)
        protected.update(links.RESOLVED_ENDPOINTS.values())
        protected.update(links.DATA_ONLY_ENDPOINTS.values())
        endpoint_dirs = {path for path in links.RESOLVED_ENDPOINTS.values()
                         if seed.get(path, {}).get('type') == 'directory'}
        def endpoint(nodes, name):
            parent, _, leaf = name.rpartition('/')
            parent = self.resolve_nodes(nodes, parent)
            literal = parent + '/' + leaf if parent else leaf
            return self.resolve_nodes(nodes, literal) if literal in nodes else literal
        foreign = set(self.prior['foreign'])
        for name in self.prior['foreign']:
            self.root_limits.tick()
            foreign.add(endpoint(seed, name))
        for name, node in payload.items():
            self.root_limits.tick()
            if node['type'] == 'directory':
                strict.need(seed.get(name) == node, 'directory creation or metadata change unsupported')
                continue
            strict.need(node['type'] in ('file', 'symlink') and 'hardlink_group' not in node,
                        'only ordinary file/symlink leaves supported')
            strict.need(seed.get(name, {}).get('type') != 'directory', 'selected directory replacement unsupported')
            strict.need(data_path(name) and not name.endswith(('.hook', '.service', '.socket', '.desktop')),
                        'only package data/documentation leaves supported')
            strict.need(node['type'] != 'file' or not node['mode'] & 0o7111,
                        'executable or special-mode leaf update unsupported')
            parent = name.rpartition('/')[0]
            strict.need(self.resolve_nodes(seed, parent) == parent, 'selected leaf parent alias unsupported')
            endpoints = {name, endpoint(seed, name), endpoint(combined, name)}
            strict.need(not endpoints & protected and not any(
                endpoint.startswith(directory + '/') for endpoint in endpoints for directory in endpoint_dirs),
                'payload touches auxiliary or selected-link closure')
            strict.need(not endpoints & foreign, 'selected leaf has foreign ownership')
            if node['type'] == 'symlink':
                strict.need(all(data_path(endpoint) for endpoint in endpoints), 'data leaf link escapes package namespace')
            if old:
                strict.need(seed.get(name) == node, 'prior leaf modified or hardlinked')
                strict.need(self.node(self.root / name) == node, 'live prior leaf differs')
            elif name in seed:
                strict.need(name in self.old_paths, 'new leaf overwrites unselected ownership')

    def projected_paths(self, seed, payload):
        strict.need(self.baseline is not None and seed == self.baseline['nodes'], 'observed raw seed required')
        strict.need(self.prior is not None, 'authenticated prior selection required')
        self.recheck_prior()
        self._leaves(self.prior['payload'], seed, old=True)
        self._leaves(payload, seed)
        # Strict projection needs the same private eligible view used by the
        # frozen auxiliary adapter. Raw baseline/live maps always retain literals.
        baseline = self.baseline
        try:
            self.baseline = self.view(baseline)
            projected = strict.Runtime.projected_paths(self, self.baseline['nodes'], payload)
        finally:
            self.baseline = baseline
        self.projected = links.restore_literals(projected, seed)
        self.recheck_prior()
        return self.projected

    def precommit(self):
        self.recheck_prior()
        scale.Runtime.precommit(self)
        aux.need(self.projected is not None, 'complete-projected-root')
        state = aux.checkpoint(self.root, self.observation, self.root_limits)
        joined = aux.live_keys(state, self.comparator)
        check = aux.compare(self.aux_before, state, self.comparator, committed=False)
        self.recheck_prior()  # Last refusal precedes the commit-ready flag.
        self.aux_precommit = state
        self.auxiliary_checks.append(dict(checkpoint='precommit', live_cache_keys=joined, **check))
        self.commit_ready = True


def apply(args, *, comparator_path):
    delegated, result, runtime = False, None, None
    try:
        scale.bound.guard(Path(args.root), Path(args.workspace))
        config = scale.configuration(args.scale, args.scale_sha256)
        runtime = Runtime(args, config, comparator_path=comparator_path)
        delegated = True
        result = scale.bound.apply(args, adapter=runtime)
        result.update(scope='opt-in-prior-data-leaves-auxiliary-selected-links-disposable-root',
                      auxiliary_checks=runtime.auxiliary_checks,
                      selected_link_variant=links.variant_report(runtime.baseline['nodes'] if runtime.baseline else None),
                      control_audit_accounting=dict(runtime.control_accounting),
                      auxiliary_exit_status='NOT OBSERVED', full587_composition='NOT ESTABLISHED',
                      apple_acceptance='NOT ESTABLISHED', hardware='NOT RUN', rollback='NOT IMPLEMENTED')
        if runtime.prior is not None:
            result['prior_archive'] = dict(runtime.prior['evidence'])
        return result
    except BaseException as error:
        failure = dict(result) if type(result) is dict else {}
        for field in ('commit_started', 'packages_committed', 'checkpoint_changed'):
            failure.setdefault(field, 'UNKNOWN' if delegated else False)
        failure.update(status='FAIL', phase='prior-auxiliary-runtime', error_type=type(error).__name__,
                       error=str(error)[:256], auxiliary_exit_status='NOT OBSERVED',
                       full587_composition='NOT ESTABLISHED', rollback='NOT IMPLEMENTED')
        if runtime is not None and runtime.prior is not None:
            failure['prior_archive'] = dict(runtime.prior['evidence'])
        return failure

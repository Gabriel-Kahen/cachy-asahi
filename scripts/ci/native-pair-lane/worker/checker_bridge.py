# SPDX-License-Identifier: MIT
"""Concrete private checker binding; Root alone admits Source and containment.

Runtime's input/evidence descriptors are distinct from these adapter descriptors.
Four completed output leases must exist before constructing this bridge. A held
library mapping is retained until the original guardian proves worker absence;
closing its input descriptor does not prove unmapping or permit publication.
"""
from types import MappingProxyType, ModuleType

API = 'sealed-checker-bridge-v1'
SOURCE_BINDING = 'e436b9c3d3046db3b05b1731400c9f8cbe06197ba39109ce62b595ccd29c3fca'
LABEL_MAP = MappingProxyType({
    'topmem-1': 'topmem-current-1', 'topmem-2': 'topmem-current-2',
    'fish-1': 'fish-current-1', 'fish-2': 'fish-current-2'})
LABELS = tuple(LABEL_MAP.values())
CORE = ('authority', 'artifact_custody', 'zstd_owner', 'pair_archive',
        'pair_compare', 'checker')
ADAPTERS = ('admission', 'descriptor_ops', 'source_library_loader')
ROLES = {'sources', 'recipes', 'inventory', 'library', 'dependencies',
         'packages', 'locks'}
DIGEST_FIELDS = ('compressed_sha256', 'payload_sha256', 'pkginfo_sha256',
                 'buildinfo_sha256')


class BridgeRefusal(ValueError):
    pass


def need(value, code):
    if not value:
        raise BridgeRefusal(code)


def canonical_label(label):
    need(type(label) is str, 'bridge-label-type')
    value = LABEL_MAP.get(label, label)
    need(value in LABELS, 'bridge-label-membership')
    return value


class CheckerBridge:
    """One original Authority, custody owner, grant and four retained outputs.

    recovery_check is Root's shared, nonrenewable recovery guard; it takes no
    arguments and must raise on expiry. failure_callback observes the
    original exception, recording Root's earliest failure clock. Neither callback
    is selected by data. Root binds their authenticated implementation.
    """
    @classmethod
    def from_loaded(cls, authority, modules6, adapters3, admission, expected,
                    routes, *, descriptor_backend=None, library_backend=None,
                    recovery_check=None, failure_callback=None,
                    descriptor_type=None, output_membership=None):
        bridge = cls.__new__(cls)
        bridge.authority = authority
        bridge.modules, bridge.adapters, bridge.admission = modules6, adapters3, admission
        bridge.recovery_check, bridge.failure_callback = recovery_check, failure_callback
        bridge.ops = bridge.owner = bridge.grant = bridge.library = bridge.loader = None
        bridge.sources, bridge.recipes, bridge.dependencies = {}, {}, {}
        bridge.packages, bridge.locks, bridge.builds = {}, {}, {}
        bridge.first_failure = None
        bridge._closed = False
        bridge._result = bridge._close_result = None
        try:
            bridge._validate(modules6, adapters3, admission, expected, routes)
            bridge.expected = bridge._copy(expected)
            bridge.routes = {k: dict(v) if type(v) is dict else v for k, v in routes.items()}
            base = adapters3['descriptor_ops'].DescriptorOps
            selected = base if descriptor_type is None else descriptor_type
            need(type(selected) is type and (selected is base or
                 (issubclass(selected, base) and selected.__pair_base__ is base)),
                 'bridge-selected-descriptor-type')
            need(type(output_membership) is dict and set(output_membership) == set(LABELS),
                 'bridge-output-membership-labels')
            membership = {}
            for label in LABELS:
                names = output_membership[label]
                need(type(names) is list and 2 <= len(names) <= 64
                     and all(type(n) is str and 0 < len(n) <= 256
                             and n not in ('.', '..') and '/' not in n for n in names)
                     and len(set(names)) == len(names), 'bridge-closed-output-membership')
                need({routes['packages'][label].split('/')[-1],
                      routes['locks'][label].split('/')[-1]} <= set(names),
                     'bridge-required-output-membership')
                membership[label] = tuple(sorted(names))
            bridge._adopt('ops', selected,
                          authority, admission, backend=descriptor_backend)
            bridge._adopt('owner', modules6['artifact_custody'].Owner,
                          authority, bridge.ops, enabled=True)
            rows = {n: dict(r) for n, r in admission.source_rows.items()}
            for name in modules6['checker'].SOURCES:
                bridge.sources[name] = bridge._acquire(routes['sources'][name], rows[name])
            for name, row in modules6['artifact_custody'].SOURCE19.items():
                bridge.recipes[name] = bridge._acquire(routes['recipes'][name], dict(row))
            bridge.inventory = bridge._acquire(routes['inventory'], {
                'bytes': 6674, 'mode': 0o644,
                'sha256': modules6['pair_compare'].INVENTORY})
            pin = dict(admission.library_row)
            bridge.library = bridge._acquire(routes['library'], bridge._row(pin),
                                              uid=pin['uid'], gid=pin['gid'])
            for name in sorted(admission.dependencies):
                pin = dict(admission.dependencies[name])
                bridge.dependencies[name] = bridge._acquire(routes['dependencies'][name],
                    bridge._row(pin), uid=pin['uid'], gid=pin['gid'])
            # All four output bindings already exist; admission re-observes every
            # lease. No caller-supplied hash or completion time supplies a grant.
            for label in LABELS:
                listed = bridge._action(bridge.ops.list_names, label, 64)
                need(type(listed) is tuple and listed == membership[label],
                     'bridge-exact-output-enumeration')
                bridge.packages[label] = bridge._output(routes['packages'][label])
                lock = bridge._output(routes['locks'][label], max_bytes=6674)
                need(lock.size == 6674 and lock.mode == 0o644
                     and lock.sha256 == modules6['pair_compare'].INVENTORY,
                     'bridge-output-lock-pin')
                bridge.locks[label] = lock
            bridge._register_holders()
            bridge._adopt('grant', modules6['checker'].HelperGrant,
                bridge.owner, bridge.sources, bridge.recipes, bridge.inventory,
                rows, SOURCE_BINDING, admitted=True)
            need(bridge._action(bridge.grant.verify) is True, 'bridge-positive-grant')
            bridge._adopt('loader', adapters3['source_library_loader'].LibraryLoader,
                bridge.library, bridge.dependencies, authority, admission,
                backend=library_backend)
            bridge._gate()
            return bridge
        except BaseException as error:
            bridge._fail(error)
            bridge._retain(error)
            raise bridge.first_failure

    def _validate(self, modules, adapters, admission, expected, routes):
        need(type(modules) in (dict, MappingProxyType) and set(modules) == set(CORE)
             and all(type(m) is ModuleType for m in modules.values()), 'bridge-six-modules')
        need(type(adapters) in (dict, MappingProxyType) and set(adapters) == set(ADAPTERS)
             and all(type(m) is ModuleType for m in adapters.values()), 'bridge-three-adapters')
        am, dm, lm = (adapters[n] for n in ADAPTERS)
        need(am.ROOT_AUTHORITY_TYPE is not None
             and type(self.authority) is am.ROOT_AUTHORITY_TYPE
             and self.authority.execution_granted is True, 'bridge-original-authority')
        need(type(admission) is am.Admission and admission.authority is self.authority
             and admission.enabled is True, 'bridge-typed-admission')
        need(callable(self.recovery_check) and callable(self.failure_callback),
             'bridge-root-recovery-bindings')
        self._gate()
        need(dm.ROOT_ADMISSION_TYPE is am.Admission and lm.ROOT_ADMISSION_TYPE is am.Admission,
             'bridge-adapter-class-anchors')
        need(admission.identity_type is modules['artifact_custody'].Identity
             and admission.directory_identity_type is modules['artifact_custody'].DirectoryIdentity,
             'bridge-custody-class-anchors')
        checker = modules['checker']
        need(checker.custody is modules['artifact_custody']
             and checker.pair_compare is modules['pair_compare']
             and checker.pair_archive is modules['pair_archive']
             and checker.zstd_owner is modules['zstd_owner'], 'bridge-private-module-graph')
        compare = modules['pair_compare']
        need(tuple(compare.LABELS) == LABELS and len(set(LABEL_MAP.values())) == 4,
             'bridge-label-bijection')
        self._action(compare.validate_expected, expected, self.authority)
        need(admission.source_binding == SOURCE_BINDING
             and expected['checker_source_sha256'] == SOURCE_BINDING
             and expected['decoded_metadata_source_sha256'] == admission.source_rows['pair_archive.py']['sha256'],
             'bridge-corrected-source-binding')
        need(type(routes) is dict and set(routes) == ROLES, 'bridge-route-roles')
        memberships = {'sources': set(checker.SOURCES),
            'recipes': set(modules['artifact_custody'].SOURCE19),
            'dependencies': set(admission.dependencies), 'packages': set(LABELS),
            'locks': set(LABELS)}
        need(0 < len(memberships['dependencies']) <= 32, 'bridge-dependency-bound')
        names = []
        for role, keys in memberships.items():
            need(type(routes[role]) is dict and set(routes[role]) == keys,
                 'bridge-route-membership-' + role)
            names.extend(routes[role].values())
        names.extend((routes['inventory'], routes['library']))
        need(all(type(n) is str for n in names) and len(set(names)) == len(names)
             and set(admission.routes) == set(names) | set(LABELS), 'bridge-exact-route-closure')
        need(routes['library'] == admission.library_row['path']
             and all(routes['dependencies'][n] == n for n in admission.dependencies),
             'bridge-library-route-name')
        outputs = set(routes['packages'].values()) | set(routes['locks'].values()) | set(LABELS)
        need(set(admission.output_bindings) == outputs, 'bridge-twelve-output-bindings')
        for label in LABELS:
            package = label.split('-')[0]
            need(routes['packages'][label].split('/')[-1] == expected['packages'][package]['artifact'],
                 'bridge-package-basename')
            directory = admission.routes[label]
            need(type(directory) is am.Route and directory.relative == ''
                 and directory.output is True, 'bridge-output-directory-route')
            for name in (routes['packages'][label], routes['locks'][label], label):
                binding = admission.output_bindings[name]
                need(type(binding) is am.LeaseBinding and binding.label == label
                     and binding.container_id == expected['reservations'][label]
                     and binding.image_id == expected['image_id']
                     and binding.context_sha256 == expected['context_sha256']
                     and binding.output_root == admission.routes[name].root_identity,
                     'bridge-output-job-binding')
        for name in names:
            self._gate()
            route = admission.routes[name]
            need(type(route) is am.Route and route.output is (name in outputs),
                 'bridge-route-type-role')
        need((admission._holder_verifier is None or type(admission._holder_verifier) is am.HolderVerifier)
             and admission._holder_verifier_type is am.HolderVerifier,
             'bridge-original-holder-verifier')
        self._gate()

    def _register_holders(self):
        am = self.adapters['admission']
        custody = self.modules['artifact_custody']
        previous = self.admission._holder_verifier
        bindings = [] if previous is None else list(previous.bindings)
        for kind, items in (('source', self.sources.values()),
                            ('library', (self.library,)),
                            ('dependency', self.dependencies.values())):
            for item in items:
                self._gate()
                bindings.append(am.HolderBinding(kind, item, self.owner,
                                                custody.Artifact, custody.Owner))
        verifier = self._action(am.HolderVerifier, self.authority,
                               am.digest(self.admission.job),
                               tuple(bindings))
        # Explicit trusted transition from bootstrap byte holders to final typed
        # Artifacts. No Source-selected arbitrary protocol or raw FD is admitted.
        self._gate()
        self.admission._holder_verifier = verifier
        self.admission._holder_verifier_type = am.HolderVerifier
        self._gate()

    @staticmethod
    def _row(pin):
        return {k: pin[k] for k in ('bytes', 'mode', 'sha256')}

    def _acquire(self, name, pin, **kw):
        return self._action(self.owner.acquire, name, pin, **kw)

    def _output(self, name, *, max_bytes=4 * 1024 * 1024):
        need(self._action(self.admission.output_owned, name) is True,
             'bridge-positive-output-lease')
        return self._action(self.owner.acquire_output, name, mode=0o644, max_bytes=max_bytes)

    def _copy(self, data):
        self._gate()
        if type(data) is dict:
            return {k: self._copy(v) for k, v in data.items()}
        if type(data) is list:
            return [self._copy(v) for v in data]
        need(type(data) in (str, int, bool), 'bridge-plain-data')
        return data

    def _gate(self, cleanup=False):
        need(not self._closed, 'bridge-already-closed')
        if self.recovery_check is not None:
            self.recovery_check()
        self.authority.check(cleanup=cleanup)
        if self.recovery_check is not None:
            self.recovery_check()

    def _action(self, fn, *args, **kwargs):
        self._gate()
        value = fn(*args, **kwargs)
        self._gate()
        return value

    def _adopt(self, name, fn, *args, **kwargs):
        self._gate()
        value = fn(*args, **kwargs)
        setattr(self, name, value)
        self._gate()
        return value

    def _fail(self, error, cleanup=False):
        prior = getattr(self.authority, '_primary', None)
        if self.first_failure is None:
            self.first_failure = prior if prior is not None else error
        try:
            self.authority.record_failure(error, cleanup=cleanup)
        except BaseException:
            pass
        if self.failure_callback is not None:
            try:
                self.failure_callback(self.first_failure)
            except BaseException:
                pass

    def _retain(self, error):
        try:
            error.retained_checker_bridge = self
        except BaseException:
            pass

    def check(self, label, package_artifact_route, record):
        try:
            self._gate()
            label = canonical_label(label)
            need(self._result is None and label not in self.builds, 'bridge-single-check')
            compare = self.modules['pair_compare']
            self._action(compare.bounded, record, self.authority)
            need(type(record) is dict and set(record) == compare.BUILD - {'summary'},
                 'bridge-record-shape')
            build = self._copy(record)
            need(canonical_label(build['label']) == label, 'bridge-record-label')
            build['label'] = label
            package = label.split('-')[0]
            need(type(package_artifact_route) is str
                 and package_artifact_route == self.routes['packages'][label], 'bridge-selected-output')
            need(all(type(build[k]) is type(self.expected[k])
                     and build[k] == self.expected[k] for k in compare.COMMON)
                 and build['container_id'] == self.expected['reservations'][label]
                 and build['mode'] == 'native' and type(build['exit_code']) is int
                 and build['exit_code'] == 0, 'bridge-observed-build-binding')
            selected = self.expected['packages'][package]
            need(build['recipe_inputs'] == selected['recipe_inputs']
                 and build['recipe_metadata'] == selected['recipe_metadata'], 'bridge-exact-recipe')
            need(self._action(self.admission.output_owned, package_artifact_route) is True,
                 'bridge-fresh-finished-lease')
            summary = self._action(self.modules['checker'].check_artifact,
                self.packages[label], self.library, self.grant, package=package,
                label=label, loader=self.loader)
            self._action(compare.bounded, summary, self.authority)
            need(type(summary) is dict and set(summary) == compare.SUMMARY,
                 'bridge-summary-shape')
            build['summary'] = self._copy(summary)
            self._gate()
            self.builds[label] = build
            return self._copy(build)
        except BaseException as error:
            self._fail(error)
            self._retain(self.first_failure)
            raise self.first_failure

    def finish(self):
        try:
            self._gate()
            need(self._result is None and set(self.builds) == set(LABELS), 'bridge-four-checks')
            compare = self.modules['pair_compare']
            comparisons = {}
            for package, labels in compare.PAIRS.items():
                self._gate()
                a, b = (self.builds[label]['summary'] for label in labels)
                comparisons[package] = {'schema_version': 1, 'labels': list(labels),
                    'artifact': self.expected['packages'][package]['artifact'],
                    'equalities': {k: a[d] == b[d]
                                  for k, d in zip(compare.EQUALITIES, DIGEST_FIELDS)}}
            result = self._action(self.modules['checker'].finalize_pairs,
                                 self.grant, self.expected, self.builds, comparisons)
            self._action(compare.bounded, result, self.authority)
            self._result = self._copy(result)
            # Private result only: no publication/absence claim is made here.
            return self._copy(self._result)
        except BaseException as error:
            self._fail(error)
            self._retain(self.first_failure)
            raise self.first_failure

    def close(self):
        if self._closed:
            if self.first_failure is not None:
                raise self.first_failure
            return self._close_result
        errors = self.cleanup_failures = []
        for item, method in ((self.owner, 'close'), (self.ops, 'cleanup_all')):
            if item is None:
                continue
            try:
                self._gate(cleanup=True)
            except BaseException as error:
                self._fail(error, cleanup=True)
                errors.append(error)
                break
            try:
                need(getattr(item, method)() is True, 'bridge-positive-' + method)
            except BaseException as error:
                self._fail(error, cleanup=True)
                errors.append(error)
            try:
                self._gate(cleanup=True)
            except BaseException as error:
                self._fail(error, cleanup=True)
                errors.append(error)
                break
        try:
            self._gate(cleanup=True)
            mappings = tuple(self.loader.mappings) if self.loader is not None else ()
            uncertainties = tuple(self.loader.uncertainties) if self.loader is not None else ()
            contexts = tuple(getattr(self.modules['zstd_owner'], 'RETAINED_CONTEXTS', ()))
            if uncertainties or (self.loader is not None and self.loader.failed):
                raise BridgeRefusal('bridge-loader-uncertain')
            if self.loader is not None and not mappings:
                need(self.loader.close() is True, 'bridge-positive-unmapped-loader-close')
                self._gate(cleanup=True)
            self._gate(cleanup=True)
            self._close_result = {'status': 'CONTAINMENT_REQUIRED' if mappings or contexts else 'CLOSED_NO_MAPPING',
                'publication_allowed': False, 'retained_mappings': mappings,
                'retained_uncertainties': uncertainties,
                'retained_contexts': contexts, 'bridge': self}
        except BaseException as error:
            self._fail(error, cleanup=True)
            errors.append(error)
        self._closed = True
        if self.first_failure is not None:
            self._retain(self.first_failure)
            raise self.first_failure
        return self._close_result

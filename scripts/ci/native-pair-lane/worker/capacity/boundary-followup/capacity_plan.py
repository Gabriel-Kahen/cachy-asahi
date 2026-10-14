"""Pure lifetime planner for the selected split; no actor/import/grant adapter.

All sizes, physical roots and dependency rows must be Root-observed before the
one DescriptorOps lifetime begins. A plan is a bound, never native acceptance.
Work callback accounting follows the sealed recursive DescriptorOps contract.
"""
import math
import re

FIELDS = ('files', 'directories', 'mkdir_reservations', 'noacquisition_attempts',
          'scanners', 'mask_reservations', 'backend_calls', 'read_requests', 'write_requests')
CHUNK = 65536
LIMITS = {'files': 128, 'tokens': 256, 'mask_reservations': 1024,
          'backend_calls': 65536, 'cleanup_calls': 2048,
          'read_requests': 1024**3, 'write_requests': 1024**3,
          'routes': 128, 'grant_checks': 131072, 'retained_journals': 128}
LABELS = ('topmem-current-1', 'topmem-current-2', 'fish-current-1', 'fish-current-2')


class CapacityRefusal(ValueError):
    pass


def need(value, reason):
    if not value:
        raise CapacityRefusal(reason)


def parts(path):
    need(type(path) is str and path.startswith('/') and len(path.encode()) <= 4096,
         'canonical-physical-root')
    names = () if path == '/' else tuple(path[1:].split('/'))
    need(len(names) <= 32 and all(re.fullmatch('[A-Za-z0-9_.-]{1,255}', name) and
         name not in ('.', '..') for name in names), 'canonical-physical-root')
    return names


def valid_row(row, *, maximum=64*1024**2):
    need(type(row) is dict and set(row) == {'bytes', 'mode', 'sha256'} and
         type(row['bytes']) is int and 0 <= row['bytes'] <= maximum and
         type(row['mode']) is int and row['mode'] in (0o600, 0o644, 0o755) and
         type(row['sha256']) is str and len(row['sha256']) == 64 and
         all(c in '0123456789abcdef' for c in row['sha256']), 'exact-observed-row')


def warm_verify_cost(root_depth, relative_parent_depth=0, *, output=False, optimized=False):
    """Exact backend callbacks of warm Artifact.verify, excluding observers."""
    R, Q = root_depth, relative_parent_depth
    need(type(R) is int and type(Q) is int and 0 <= R <= 32 and 0 <= Q <= 7, 'depth')
    anchor = 2*R+1 if optimized else R*R + 4*R + 2
    parent = anchor + (2*(R+Q)+1 if Q else 0) if optimized else anchor + 2*R*Q + Q*Q + 2*Q
    file_verify = 2*(R+Q+1)+1
    ancestors = sum(2*(R+q)+1 for q in range(Q+1))
    return file_verify + (parent+1) + (parent+ancestors) + (2*anchor if output else 0)


def bind_descriptor_type(base_class):
    """Root explicitly supplies the authenticated sealed DescriptorOps class.

    Cached tokens select the retained chain without repeatedly verifying each
    prefix. A fresh inherited recursive _verify then checks the complete selected
    root/parent chain, including every FD and named link. No across-operation
    identity cache, new allocator, syscall, cleanup policy or eligibility exists.
    The caller must bind the returned exact class in its Admission/bridge anchors.
    """
    need(isinstance(base_class, type) and all(callable(getattr(base_class, name, None))
         for name in ('_dir','_verify','_directory_identity','_anchor','_parent')),
         'explicit-authenticated-descriptor-class')
    namespace = base_class._call.__globals__
    Refused = namespace['Refused']
    NoAcquisition = namespace['NoAcquisition']
    need(namespace['MAX_HANDLES'] == 256 and namespace['MAX_CALLS'] == 65536,
         'unchanged-sealed-backend-caps')

    def fast_check(owner, cleanup):
        # Private _call bodies are authenticated Source, not arbitrary actor
        # capabilities. They retain the same original clock/cause eligibility.
        # Every actual backend invocation below also performs fresh Admission.
        if cleanup and owner._cleanup_stopped:
            raise Refused('descriptor cleanup stopped')
        if owner.failed and not cleanup:
            raise Refused('descriptor owner failed')
        try:
            if owner.authority is not owner.admission.authority:
                raise Refused('original descriptor Authority changed')
            owner.authority.check(cleanup=cleanup)
        except BaseException:
            if cleanup:
                owner._cleanup_stopped = True
            raise

    class RootDescriptorOps(base_class):
        def _call(self, fn, cleanup=False, allow_noacq=False):
            previous = self._cleanup_mode
            cleanup = cleanup or previous
            self._cleanup_mode = cleanup
            try:
                fast_check(self, cleanup)
                result = fn()
                fast_check(self, cleanup)
                return result
            except BaseException as error:
                if type(error) is NoAcquisition and allow_noacq:
                    raise
                self._fail(error, cleanup)
                raise
            finally:
                self._cleanup_mode = previous

        def _backend(self, fn, *args, allow_noacq=False):
            # Charge exactly as the sealed base, including pre-call refusal.
            cleanup = self._cleanup_mode
            if cleanup:
                if self.cleanup_calls >= 2048:
                    raise Refused('cleanup callback budget')
                self.cleanup_calls += 1
            else:
                if self.backend_calls >= 65536:
                    raise Refused('backend callback budget')
                self.backend_calls += 1
            def primitive():
                self._check(cleanup)  # Original full typed Admission/observer.
                result = fn(*args)
                self._check(cleanup)
                return result
            return self._call(primitive, cleanup=cleanup, allow_noacq=allow_noacq)

        def _anchor(self, row):
            root = self._dirs.get(())
            if root is None:
                root = self._dir(None, '/', ())
            key = ()
            # Inherited __init__ already validates every root through the sealed
            # route validator. Revalidation here rejects post-binding tampering.
            names = parts(row.root)
            for name in names:
                key += (name,)
                next_root = self._dirs.get(key)
                root = self._dir(root,name,key) if next_root is None else next_root
            actual = self._verify(root)
            if self._directory_identity(actual) != row.root_identity:
                raise CapacityRefusal('admitted root changed')
            return root

        def _parent(self, row, *, create=False):
            token = self._anchor(row)
            chain = [token]
            names = tuple(row.relative.split('/')) if row.relative else ()
            need(len(names) <= 8 and all(re.fullmatch('[A-Za-z0-9_.-]{1,64}', name) and
                 name not in ('.', '..') for name in names),
                 'admitted relative shape')
            for index,name in enumerate(names[:-1]):
                key = ('relative',row.root) + names[:index+1]
                next_token = self._dirs.get(key)
                token = self._dir(token,name,key,create=create) if next_token is None else next_token
                chain.append(token)
            if len(names) > 1:
                self._verify(token)
            return token, names[-1] if names else None, tuple(chain)
    RootDescriptorOps.__pair_base__ = base_class
    return RootDescriptorOps


class Tape:
    def __init__(self, *, optimized=False):
        self.plan = dict.fromkeys(FIELDS, 0)
        self.dirs = {}
        self.routes = {}
        self.cleanup_calls = 0
        self.events = []
        self.phase = 'allocation'
        self.optimized = optimized

    def charge(self, field, amount, operation, name=''):
        need(type(amount) is int and amount >= 0, 'nonnegative-exact-charge')
        self.plan[field] += amount
        if amount:
            self.events.append({'phase': self.phase, 'operation': operation,
                                'name': name, 'field': field, 'amount': amount})

    def backend(self, n, operation, name=''):
        self.charge('backend_calls', n, operation, name)

    def V(self, depth):
        return 2*depth+1

    def directory(self, key, depth):
        if key in self.dirs:
            self.backend(self.V(depth), 'cached-directory-verify', repr(key))
        else:
            self.dirs[key] = depth
            self.charge('directories', 1, 'directory-allocation', repr(key))
            self.charge('mask_reservations', 1, 'directory-allocation-mask', repr(key))
            self.backend(2, 'directory-allocate-and-fstat', repr(key))

    def anchor(self, row):
        names = parts(row['root'])
        if not self.optimized or () not in self.dirs:
            self.directory((), 0)
        for i in range(1, len(names)+1):
            if not self.optimized or names[:i] not in self.dirs:
                self.directory(names[:i], i)
        self.backend(self.V(len(names)), 'anchor-identity', row['name'])
        return len(names)

    def parent(self, row):
        R = self.anchor(row)
        q = row['relative'].split('/')[:-1]
        for i in range(1, len(q)+1):
            key = ('relative', row['root'], *q[:i])
            if not self.optimized or key not in self.dirs:
                self.directory(key, R+i)
        if self.optimized and q:
            self.backend(self.V(R+len(q)), 'complete-selected-parent-verify', row['name'])
        return R+len(q)

    def verify(self, name):
        row = self.routes[name]
        if row['output']:
            self.anchor(row)
        D = len(parts(row['root'])) + len(row['relative'].split('/'))-1
        self.backend(self.V(D+1), 'artifact-stat-handle', name)
        self.parent(row)
        self.backend(1, 'artifact-stat-named', name)
        self.parent(row)
        R = len(parts(row['root']))
        self.backend(sum(self.V(d) for d in range(R, D+1)), 'artifact-ancestors', name)
        if row['output']:
            self.anchor(row)

    def rewind(self, name):
        self.verify(name)
        row = self.routes[name]
        D = len(parts(row['root']))+len(row['relative'].split('/'))
        self.backend(2*self.V(D)+1, 'descriptor-rewind-pre-post-verify', name)
        self.verify(name)

    def read(self, name, requested):
        need(type(requested) is int and 0 < requested <= CHUNK, 'requested-chunk')
        self.verify(name)
        row = self.routes[name]
        D = len(parts(row['root']))+len(row['relative'].split('/'))
        self.charge('read_requests', requested, 'artifact-read-request', name)
        self.backend(2*self.V(D)+1, 'descriptor-read-pre-post-verify', name)
        self.verify(name)

    def body(self, name, *, acquisition=False):
        remaining = self.routes[name]['bytes']
        while remaining:
            requested = min(CHUNK, remaining + (1 if acquisition else 0))
            self.read(name, requested)
            remaining -= min(requested, remaining)
        self.read(name, 1)

    def acquire(self, row):
        name = row['name']
        need(name not in self.routes, 'one-fresh-holder-per-route')
        self.routes[name] = row
        if row['output']:
            self.anchor(row)
        D = self.parent(row)+1
        self.charge('files', 1, 'new-core-and-adapter-file-handle', name)
        self.charge('mask_reservations', 1, 'file-allocation-mask', name)
        self.backend(2+self.V(D), 'file-allocate-fstat-validate', name)
        self.backend(self.V(D), 'core-acquire-stat-handle', name)
        self.parent(row)
        R = len(parts(row['root']))
        self.backend(sum(self.V(d) for d in range(R,D)), 'core-acquire-ancestors', name)
        self.body(name, acquisition=True)
        if row['output']:
            self.anchor(row)
        self.rewind(name)

    def verify_all(self):
        for name in self.routes:
            self.verify(name)

    def grant(self, grant_names):
        for name in grant_names:
            self.verify(name)
        self.verify_all()

    def scan_output(self, root, count, label):
        row = {'root': root, 'relative': label + '.unused', 'name': label}
        R = self.parent(row)
        self.charge('scanners', 1, 'flat-output-scanner-token', label)
        self.charge('mask_reservations', 2, 'scanner-open-and-close-mask', label)
        self.backend(1+count+self.V(R), 'scan-and-all-member-stats-postverify', label)
        # Scanner close is guarded inside OSBackend, not a second _backend call.

    def cleanup(self):
        self.phase = 'eligible-original-J-cleanup'
        # Core close: verify_close_identity, close (identity+dispose). No retries
        # after ambiguous disposal. Adapter cleanup then closes cached directories.
        n = self.plan['files'] + self.plan['directories']
        self.cleanup_calls = 3*n
        self.charge('mask_reservations', n, 'one-mask-per-eligible-fd-dispose')


def make_plan(selected, dependencies, roots, outputs, *, failed_noacquisitions=1, optimized=True,
              canonical_routes=None):
    """Return a full named lifetime tape; capacity violations stay explicit.

    roots={'source':Root_flat_authenticated_copy_root,
           'outputs':{canonical_label:actual_root4}}
    outputs={label:{'package':observed_row,'lock':observed_row,'members':count}}
    Native dependency rows are fixed root-relative paths -> observed rows. Core6
    and Source19 are flat physical copies, but virtual grant keys stay original.
    Bootstrap core6/adapter3 and Runtime files never share/retire these new FDs.
    """
    need(type(selected) is dict and {'core','adapter','recipes19','inventory','library_reference'} <= set(selected),
         'selected-authenticated-Source')
    need(type(dependencies) is dict and 1 <= len(dependencies) <= 32, 'current-native-dependency-selection-required')
    need(type(roots) is dict and set(roots) == {'source','outputs'} and type(roots['outputs']) is dict and
         set(roots['outputs']) == set(LABELS), 'physical-roots')
    parts(roots['source'])
    need(type(outputs) is dict and set(outputs) == set(LABELS), 'fourfinished-observed-output-rows')
    need(type(failed_noacquisitions) is int and 0 <= failed_noacquisitions <= 1, 'first-failure-noacquisition-reserve')
    need(len(selected['core']) == 6 and len(selected['adapter']) == 3 and len(selected['recipes19']) == 19,
         'fixed-Source-cardinality')
    need(type(optimized) is bool, 'explicit-integration-descriptor-policy')
    t = Tape(optimized=optimized)
    def acquire(name, row, root, relative, role, output=False):
        valid_row(row)
        t.acquire({'name': name, **row, 'root': root, 'relative': relative,
                   'role': role, 'output': output})
    for name, row in selected['core'].items():
        acquire(name, row, roots['source'], 'core-'+name, 'core')
    for name, row in selected['recipes19'].items():
        family = 'fish' if '/shells/' in name else 'topmem'
        acquire(name, row, roots['source'], family+'-'+name.rsplit('/',1)[-1], 'recipe')
    acquire('inventory', selected['inventory'], roots['source'], 'inventory.lock', 'inventory')
    library = selected['library_reference']
    librow = {key: library[key] for key in ('bytes','mode','sha256')}
    # Root selects the actual canonical parent; virtual Artifact names retain
    # the full root-relative canonical path used by the sealed library grant.
    lib_parent, lib_leaf = library['path'].rsplit('/',1)
    canonical_names = (library['path'], *dependencies)
    if canonical_routes is not None:
        need(type(canonical_routes) is dict and set(canonical_routes) == set(canonical_names) and
             all(type(route) is dict and set(route) == {'root','relative'} and
                 route['root'].rstrip('/')+'/'+route['relative'] == '/'+name
                 for name,route in canonical_routes.items()), 'actual-canonical-route-layout')
    def canonical_layout(name,parent,leaf):
        return (canonical_routes[name]['root'],canonical_routes[name]['relative']) if canonical_routes is not None else ('/'+parent,leaf)
    physical_root, physical_relative = canonical_layout(library['path'],lib_parent,lib_leaf)
    acquire(library['path'], librow, physical_root, physical_relative, 'library')
    for name, row in dependencies.items():
        need(type(name) is str and not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')),
             'canonical-dependency-path')
        parent,leaf = name.rsplit('/',1)
        physical_root, physical_relative = canonical_layout(name,parent,leaf)
        acquire(name, row, physical_root, physical_relative, 'dependency')
    for label in LABELS:
        row = outputs[label]
        need(type(row) is dict and set(row) == {'package','lock','members'} and
             type(row['members']) is int and 7 <= row['members'] <= 64, 'full-flat-output-members')
        valid_row(row['package'], maximum=4*1024**2)
        need(row['package']['bytes'] >= 6 and row['lock'] == selected['inventory'], 'package-and-exact-inventory-lock')
        root = roots['outputs'][label];parts(root)
        t.scan_output(root, row['members'], label)
        acquire(label+'/package', row['package'], root, 'package.pkg.tar.zst', 'package', True)
        acquire(label+'/lock', row['lock'], root, 'packages.lock', 'lock', True)
    grant_names = tuple(selected['core']) + tuple(selected['recipes19']) + ('inventory',)
    library_names = (library['path'], *dependencies)
    def library_verify():
        for name in library_names:
            for _ in range(9):  # verify_held + four held_attribute before/after.
                t.verify(name)
    t.phase = 'initial-helper-grant-admission'
    t.grant(grant_names)
    t.phase = 'library-loader-constructor'
    library_verify()
    for i,label in enumerate(LABELS):
        t.phase = 'check-artifact-'+label
        t.grant(grant_names)
        package = label+'/package'
        for name in (package,library['path']):t.verify(name)
        t.anchor(t.routes[package])  # explicit checker output_owned predicate.
        # Decoder: retained exact compressed body, four direct artifact checks,
        # four direct library checks; fd getters preserve identity too.
        for _ in range(4):t.verify(package)
        t.rewind(package);t.body(package)
        for _ in range(10):t.verify(library['path'])
        libdepth=len(library['path'].split('/'))
        t.backend(2*t.V(libdepth), 'two-library-fd-borrows', library['path'])
        for _ in range(4 if i == 0 else 2):library_verify()
        # checker's BUILDINFO exact341 read through the original inventory handle.
        t.verify('inventory');t.rewind('inventory');t.body('inventory');t.verify('inventory')
        for name in (package,library['path']):t.verify(name)
        t.grant(grant_names)
    t.phase = 'finalize-four-build-two-comparison'
    t.grant(grant_names)
    for label in LABELS:t.verify(label+'/package')
    t.grant(grant_names)
    t.cleanup()
    t.charge('noacquisition_attempts', failed_noacquisitions, 'one-first-failure-retired-token-reserve')
    t.charge('mask_reservations', failed_noacquisitions, 'failed-allocation-mask-reserve')
    t.backend(1*failed_noacquisitions, 'failed-allocation-callback-reserve')
    plan = t.plan
    tokens = sum(plan[k] for k in FIELDS[:5])
    checks = {key:plan[key] <= LIMITS[key] for key in ('files','mask_reservations','backend_calls','read_requests','write_requests')}
    checks.update(tokens=tokens <= LIMITS['tokens'], cleanup_calls=t.cleanup_calls <= LIMITS['cleanup_calls'],
                  routes=len(t.routes)+4 <= LIMITS['routes'])
    return {'allocation_plan':plan,'tokens':tokens,'routes':len(t.routes)+4,'cleanup_calls':t.cleanup_calls,
            'cap_checks':checks,'capacity_fits':all(checks.values()),'operation_tape':t.events,
            'adapter_file_holders':len(t.routes), 'physical_routes':t.routes,
            'separate_owner_operations':{'bootstrap_core6':6,'bootstrap_adapter3':3,
                'source19_snapshot_and_flat_copies':'Runtime.files; no adapter snapshot/create/reopen',
                'cache_objects':501,'cache_signatures':249,'full_build_evidence_and_logs':'Runtime.files'},
            'external_unmetered_dependencies':['typed holder/lease/mapping inspector backend calls',
                'Admission grant checks and retained journal counters','bootstrap source-loader20closure rereads'],
            'actual_Release_capacity_or_grant_proven':False,
            'descriptor_policy':'explicit-chain-and-primitive-admission-subclass' if optimized else 'sealed-original-prefix-walk',
            'qualification':'Direct selected DescriptorOps tape; external verifier callbacks may add work and must be metered before whole-operation capacity PASS.'}


def make_plan_for_routes(dependencies, selected_routes, bounds, *, selected, optimized=True):
    """Parent convenience ABI over its actual admitted route table.

    bounds={label:{all_actual_evidence_filenames:{bytes,mode,sha256}}}.
    Route virtual keys: six core basenames, nineteen original package paths,
    'inventory.lock', canonical library/dependency paths and label+'/package-basename'
    or label+'/packages.lock'. Four enumeration-root keys are canonical labels.
    Only flat Source copies are supported; mismatched layout refuses planning.
    """
    need(type(selected_routes) is dict or hasattr(selected_routes, 'items'), 'explicit-route-table')
    sources = (*selected['core'], *selected['recipes19'], 'inventory.lock')
    need(all(name in selected_routes for name in sources), 'complete-source-route-membership')
    roots = {selected_routes[name].root for name in sources}
    need(len(roots) == 1 and all('/' not in selected_routes[name].relative and
         selected_routes[name].relative for name in sources), 'flat-authenticated-source-routes')
    need(len({selected_routes[name].relative for name in sources}) == len(sources),
         'no-flat-source-physical-aliases')
    canonical = (selected['library_reference']['path'], *dependencies)
    need(all(name in selected_routes and selected_routes[name].root.rstrip('/')+'/'+
         selected_routes[name].relative == '/'+name for name in canonical),
         'actual-canonical-library-dependency-routes')
    need(type(bounds) is dict and set(bounds) == set(LABELS), 'four-complete-evidence-bounds')
    output_roots, outputs = {}, {}
    for label in LABELS:
        evidence = bounds[label]
        need(type(evidence) is dict and 7 <= len(evidence) <= 64 and
             all(type(name) is str and '/' not in name and name not in ('', '.', '..')
                 for name in evidence), 'complete-flat-evidence-members')
        packages = [name for name in evidence if name.endswith('.pkg.tar.zst')]
        need(len(packages) == 1 and 'packages.lock' in evidence and label in selected_routes and
             label+'/'+packages[0] in selected_routes and label+'/packages.lock' in selected_routes,
             'complete-four-output-routes')
        for row in evidence.values(): valid_row(row)
        rows = [selected_routes[label+'/'+packages[0]], selected_routes[label+'/packages.lock'],
                selected_routes[label]]
        need(len({row.root for row in rows}) == 1 and rows[2].relative == '' and
             all(row.relative and '/' not in row.relative for row in rows[:2]), 'flat-output-routes')
        output_roots[label] = rows[0].root
        outputs[label] = {'package': evidence[packages[0]], 'lock': evidence['packages.lock'],
                          'members':len(evidence)}
    normalized_dependencies = {}
    for name,row in dependencies.items():
        need(type(row) is dict and set(row) in ({'bytes','mode','sha256'},
             {'bytes','mode','sha256','uid','gid'}), 'native-dependency-row')
        if 'uid' in row:
            need(type(row['uid']) is int and type(row['gid']) is int and row['uid'] == row['gid'] == 0,
                 'root-native-dependency-owner')
        normalized_dependencies[name] = {key:row[key] for key in ('bytes','mode','sha256')}
    result = make_plan(selected,normalized_dependencies,
                       {'source':next(iter(roots)),'outputs':output_roots},outputs,optimized=optimized,
                       canonical_routes={name:{'root':selected_routes[name].root,
                                              'relative':selected_routes[name].relative}for name in canonical})
    result['parent_route_abi'] = 'inventory.lock+canonical-label+actual-package-basename+packages.lock'
    need(result['capacity_fits'], 'direct-required-operation-capacity-refusal')
    direct = dict(result['allocation_plan'])
    # Selected HolderVerifier.verify performs Artifact.verify. The sealed loader
    # has 1 constructor + 4 first-map + 3*2 cached-map _verify calls; each does
    # 9 verify_held calls/item, each with two extra typed holder verifications.
    # Its per-check held fd getter adds four holder rechecks of the library.
    # Mapping preflight + five proofs borrow every library/dependency fd once.
    items = []
    for name in canonical:
        route = selected_routes[name]
        R = len(parts(route.root))
        Q = len(route.relative.split('/'))-1
        cost = warm_verify_cost(R,Q,optimized=optimized)
        items.append({'name':name,'verify_backend_calls':cost,'fd_verify_backend_calls':2*(R+Q+1)+1})
    holder = 18*11*sum(item['verify_backend_calls'] for item in items)
    library_getter = 4*4*items[0]['verify_backend_calls']
    inspector_getters = 6*sum(2*item['verify_backend_calls']+item['fd_verify_backend_calls']for item in items)
    projected = direct['backend_calls']+holder+library_getter+inspector_getters
    need(projected <= 65536, 'known-full-callback-projection-capacity-refusal')
    result['full_callback_projection'] = {
        'direct_required_callbacks':direct['backend_calls'],
        'library_verify_passes':11,'typed_holder_extra_verifies_per_pass_item':18,
        'typed_holder_extra_callbacks':holder,'four_library_getter_holder_rechecks':library_getter,
        'six_mapping_holder_fd_passes':inspector_getters,'known_callback_upper_projection':projected,
        'selected_library_dependencies':items,
        'extra_Root_runtime_files_callbacks':'Separate FD table; must meter independently',
        'universal_success_claim':False}
    # The concrete typed holder/loader/inspector callbacks share the same original
    # immutable _backend cap. Their work must never be mislabeled as the direct
    # projection. Declare the existing entire callback envelope before allocation;
    # it is enforced per primitive, not inferred from one past model's count.
    result['direct_allocation_plan'] = direct
    result['allocation_plan'] = dict(direct, backend_calls=65536)
    result['whole_extra_backend_reserve'] = 65536-direct['backend_calls']
    result['whole_callback_bound'] = 'original-per-primitive-65536-cap-no-renewal'
    result['whole_success_projection_proven'] = False
    result['required_whole_operation_admission_checks_cap'] = 131072
    result['required_completed_loader_proofs'] = {
        'four_check_artifact':4, 'finalize_pairs':1, 'mapping_preflight':1,
        'mapping_proofs':5, 'fd_mapping':1,
        'callback_capacity':'all callbacks charged under the same original owner and Authority'}
    return result


def verify_whole_counters(planned, measured):
    """Admit counter coverage only after the complete current model/run finishes.

    No historical counter/PASS creates a grant. Root independently binds this
    record to its full same-job operation tape and original cleanup/publication.
    """
    fields = set(FIELDS) | {'grant_checks','cleanup_calls','mapping_preflight',
                           'mapping_proofs','fd_mapping','check_artifact','finalize_pairs'}
    need(type(measured) is dict and set(measured) == fields and
         all(type(value) is int and value >= 0 for value in measured.values()),
         'closed-complete-whole-operation-counters')
    need(all(measured[name] <= planned['allocation_plan'][name] for name in FIELDS),
         'whole-operation-exceeds-declared-plan')
    need(measured['grant_checks'] <= 131072 and measured['cleanup_calls'] <= 2048,
         'same-original-guard-cleanup-caps')
    need((measured['mapping_preflight'],measured['mapping_proofs'],measured['fd_mapping'],
          measured['check_artifact'],measured['finalize_pairs']) == (1,5,1,4,1),
         'complete-four-build-library-operation-membership')
    return True

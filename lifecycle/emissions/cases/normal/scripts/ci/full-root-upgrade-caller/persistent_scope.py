#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Materialize the persistent data of one owned container; never grant an update."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

RUNTIME = frozenset(('proc', 'sys', 'dev', 'run', 'tmp'))
INFRASTRUCTURE = frozenset(('inputs', 'out', 'source', 'workspace', 'measurement',
    'measurement-source', 'footprint.py', 'runner.py', 'lifecycle.py', 'setup4.py',
    'upgrade-code', 'upgrade-config.json', 'upgrade-pair', 'upgrade-hook.py',
    'persistent_scope.py', 'upgrade-signing'))
MOUNT_FILES = frozenset(('etc/hosts', 'etc/hostname', 'etc/resolv.conf'))
NON_DISK = frozenset(('tmpfs', 'ramfs', 'proc', 'sysfs', 'devtmpfs', 'devpts',
    'cgroup', 'cgroup2', 'mqueue', 'securityfs', 'debugfs', 'tracefs', 'hugetlbfs'))

_NORMAL_REASON_LITERALS = ('341-package inventory differs', 'ALPM owned file count limit', 'ALPM package inventory limit', 'Docker overrides refused', 'GPG_HOME_SOCKET_PATH_TOO_LONG', 'Python compression.zstd is unavailable', 'Root must freeze the complete actual87 literal link selection before dispatch', 'absolute archive link refused', 'absolute canonical scope paths required', 'absolute contained copy paths required', 'absolute contained root required', 'absolute database root required', 'absolute payload link', 'absolute-comparator-source', 'actual base trust differs from pinned configuration', 'actual baseline differs from exact 604-package lock', 'actual before/after inventory differs', 'actual composition inventory required', 'actual composition lock differs', 'actual copied base differs from authenticated release', 'actual namespace identity/map refused', 'actual package-owned kernel modules required', 'actual post-update lock differs', 'actual protected platform packages absent', 'actual reduced capabilities differ', 'actual release requires explicit generic disposable update selection', 'actual root is not initial signed604/updater-v2 checkpoint', 'actual user-file baseline not exercised', 'actual user-file baseline required before commit', 'aggregate accounting exceeds limits', 'aggregate compressed byte limit exceeded', 'aggregate deadline exhausted', 'aggregate decoded archive bound', 'aggregate decoded archive byte bound', 'aggregate decoded byte limit exceeded', 'aggregate input bytes exceeded', 'aggregate member limit exceeded', 'aggregate owned file count limit', 'aggregate package inputs exceed tiny-root limit', 'aggregate package ownership bound', 'ambient capability clearing refused', 'ambiguous copy bind scope', 'apps-directory-inode-links-size-metadata', 'apps-directory-node-metadata', 'apps-directory-scan-row', 'apps604-selected-postcommit-only', 'archive deadline exhausted', 'archive exceeds tiny-root caller limit', 'archive input changed during inspection', 'archive node/sparse bound', 'archive payload overlap', 'archive special/hardlink member refused', 'authenticated result changed', 'authenticated snapshot drifted', 'aux-changed-before-commit', 'bare retained evidence directory required', 'base pacman configuration/trust required', 'base trust changed after commit', 'base trust changed before commit', 'boolean absolute path diagnostic required', 'bootstrap started without immutable image ID', 'bound evidence node identities required', 'bound worker/runtime/evidence identity required', 'bounded cleanup budgets required', 'bounded command failed', 'bounded declared release required', 'bounded decoder read required', 'bounded evidence file required', 'bounded existing local database required', 'bounded hardlink groups required', 'bounded inventory/depth/diagnostics required', 'bounded mount table required', 'bounded ordinary database record required', 'bounded ordinary source required', 'bounded original node metadata', 'bounded original observation reasons', 'bounded original stage maps', 'bounded owned package names required', 'bounded path collection required', 'bounded persistent stage diagnostic', 'bounded receipt file required', 'bounded regular reference required', 'bounded scan diagnostic', 'bounded scan maps', 'bounded scan path', 'bounded scan row', 'bounded shape samples required', 'bounded tracked source archive required', 'bounded unique copied package inventory', 'bundle has missing or undeclared members', 'cache-file', 'cache-parent', 'canonical owned paths required', 'canonical private path required', 'canonical relative root query required', 'canonical single-mount verification required', 'capability bounding reduction refused', 'capability reduction refused', 'capacity check missing', 'captured engine specification required', 'captured runtime bytes differ', 'captured worker launch required', 'changed archive required', 'changed copy source', 'checkout differs from product', 'clean standard command environment required', 'closed add row required', 'closed engine specification required', 'closed namespace identity required', 'closed transaction contract required', 'closure-changed', 'code source pin shape', 'comparator-binding', 'comparator-source-drift', 'comparator-source-pin', 'comparator-source-shape', 'complete CLI arguments required', 'complete byte-identical supplied-source copy required', 'complete declared protected versions required', 'complete driver commit truth required', 'complete explicit code closure required', 'complete generic fixture selection required', 'complete persistent stage differs', 'complete projected root required', 'complete single-mount copy scope required', 'complete-absolute-chain-set-differs', 'complete-link-observation', 'complete-observation', 'complete-projected-root', 'complete-selected-copy-scope', 'complete604 lock required', 'compressed archive size/type limit exceeded', 'config-metadata', 'consumed input byte bound', 'contained declared repository alias required', 'contained exclusions required', 'copied baseline bytes changed', 'copied package database differs from actual587 lock', 'copier-source-pin-or-drift', 'copier-source-shape', 'copy anchor drift', 'copy byte limit', 'copy depth limit', 'copy descriptor cleanup failed', 'copy destination alias drift', 'copy destination file mount drift', 'copy destination mount drift', 'copy destination nodes differ', 'copy directory drift', 'copy file byte limit', 'copy metadata differs', 'copy mount crossing', 'copy node limit', 'copy parent path drift', 'copy parent rebound', 'copy root path drift', 'copy source alias drift', 'copy source content drift', 'copy source group differs', 'copy source group drift', 'copy source nodes changed', 'copy source parent differs', 'copy source parent drift', 'copy source symlink drift', 'copy write made no progress', 'counts', 'cross-device node', 'cross-device node parent', 'current evidence directory metadata differs', 'current evidence namespace identity differs', 'cyclic payload link', 'database changed during observation', 'database mount crossing refused', 'database package directory changed', 'database record absent from root observation', 'database record changed', 'database record differs from root observation', 'database root alias refused', 'database section absent', 'declared full after map differs', 'declared parent is not a directory', 'declared release file differs', 'declared repository alias differs', 'decoded archive byte bound', 'decoder window budget below gzip minimum', 'descriptor mount identity APIs differ', 'descriptor statx mount identity unavailable', 'device identity refused', 'directory changed during inventory', 'directory content drift', 'directory depth limit', 'directory entry drift', 'directory-shape', 'disjoint-initialization-source', 'disk-backed persistent stage required', 'driver data/copy/source overlap refused', 'driver exit/status disagreement', 'duplicate ALPM package', 'duplicate JSON key', 'duplicate actual package', 'duplicate add or signer refused', 'duplicate database field', 'duplicate database section', 'duplicate hardlink membership', 'duplicate installed ownership', 'duplicate installed package', 'duplicate inventory entry', 'duplicate-key', 'duplicate/nonroot archive member', 'engine deadline refused', 'engine receipt execution identity differs', 'engine receipt refused', 'escaped mount names require explicit review', 'escaping existing filesystem link', 'escaping payload link', 'evidence byte bound', 'evidence descriptor cleanup incomplete', 'evidence descriptor lease replaced; foreign descriptor not closed', 'evidence descriptor lease unavailable; cleanup refused', 'evidence descriptor mount identity changed', 'evidence descriptor mount identity missing', 'evidence descriptor mount outside current namespace', 'evidence directory identity refused', 'evidence file changed', 'evidence file identity refused', 'evidence file pathname replaced', 'evidence pathname identity differs', 'evidence pathname replaced', 'evidence view changed during validation', 'exact caller configuration required', 'exact external helper closure required', 'exact file reference required', 'exact finite scale budgets required', 'exact initial signed604/updater-v2 inventory required', 'exact input digest required', 'exact inventory digest required', 'exact inventory drift', 'exact product commit required', 'exact release record required', 'exact repository selection required', 'exact setup/updater-v2 lock required', 'exact single prepared setup upgrade required', 'exact updater-v2/setup4 scale required', 'exact-apps5-to6-transition', 'exact-apps6-authenticated-archive', 'exact-apps604-after-lock-and-other603', 'exact-apps604-before-lock', 'exact-apps604-scale-locks', 'exact-eight-apps6-files', 'exclusive initial604 full-root route required', 'existing ancestor escapes root', 'existing bound/runtime update did not pass', 'existing copied package database required', 'existing external ephemeral TEST signer required', 'existing package-manager lock refused', 'existing suite case count differs', 'expected post-update lock differs', 'expected-length', 'expected-record', 'expected-string', 'explicit TEST release declarations required', 'explicit absolute driver paths required', 'explicit actual updater-v2→setup4 scale selection required', 'explicit archive limits required', 'explicit boolean release synthetic selection required', 'explicit bound-update nonce required', 'explicit comparator path required', 'explicit disposable namespace/container required', 'explicit disposable release configuration required', 'explicit finite future capacity budget required', 'explicit generic development policy required', 'explicit generic development runtime required', 'explicit generic development selection required', 'explicit initial604 upgrade selection required', 'explicit owned container marker required', 'explicit platform mode required', 'explicit release and platform configuration required', 'explicit scaled disposable configuration required', 'export database entry refused', 'export duplicate package', 'export local database absent', 'export ownership outside mapping', 'export package lock differs', 'export package metadata incomplete', 'export package ownership differs', 'export protected ownership differs', 'export protected payload differs', 'export root ownership refused', 'extended header byte limit exceeded', 'external input changed', 'externally pinned input differs', 'failed receipt bound', 'failed stage predicate only', 'fakeroot-config', 'fd-exec-unavailable', 'file content drift', 'file entry drift', 'file grew during observation', 'file-content', 'file-list bound', 'file-shape', 'filesystem byte bound', 'filesystem node bound', 'finite absolute monotonic deadline required', 'finite caller time budget required', 'finite copy bounds required', 'finite copy deadline required', 'finite deadline required', 'finite nonempty add set required', 'finite original stage clock', 'finite package map required', 'finite positive limit required', 'finite root path limits required', 'finite source bytes required', 'finite source capsule registry required', 'finite timeout required', 'finite total driver deadline required', 'finite worker bounds required', 'finite-source-link-selection', 'fixed evidence filename required', 'fresh disjoint stage required', 'fresh driver data directory required', 'fresh output required', 'fresh private copy required', 'full configuration digest required', 'full supported primary signer required', 'generic exact before/after locks differ', 'generic fixture Source data differs', 'generic fixture Source reference differs', 'generic fixture VM data differs', 'generic fixture duplicate proc field', 'generic fixture exact VM contract required', 'generic fixture fixed tool-profile data differs', 'generic fixture fixed worker location required', 'generic fixture input bytes changed', 'generic fixture input reference refused', 'generic fixture library profile differs', 'generic fixture ordinary guest required', 'generic fixture proc bound', 'generic fixture protected file required', 'generic fixture protected parent required', 'generic fixture real guest marker required', 'generic fixture tool alias differs', 'generic fixture tool closure differs', 'generic fixture worker/runtime pin differs', 'generic fixture zero-capability NNP parent required', 'generic kernel ownership changed', 'generic kernels must be protected', 'generic package-manager/runtime protection required', 'generic policy changed', 'generic policy phase refused', 'generic policy/configuration locks differ', 'generic protected package versions changed or absent', 'generic protected selection differs from authenticated release', 'growing copy source', 'guarded engine did not complete', 'guest device identity differs', 'hardlink alias limit', 'hardlink final drift', 'hardlink group limit', 'hardlink group not closed', 'hardlink groups changed', 'hardlink identity drift', 'hardlink member changed', 'hardlink member differs', 'hardlink member limit', 'hardlink named entry drift', 'hardlink observation required', 'hardlink or oversized file refused', 'hardlink parent changed', 'hardlink parent drift', 'hardlink parent missing or redirected', 'hardlink projection requires explicit mode', 'hardlink retained entry drift', 'hardlinked or oversized node', 'header', 'helper-alias', 'helper-hardlink', 'helper-pin', 'hwcaps-child', 'hwcaps-shape', 'include-content', 'include-directory', 'include-file', 'incomplete provisional receipt', 'incomplete tar zero padding', 'incomplete worker result', 'independent engine specification pin required', 'independently reviewed worker source pin required', 'initial inventory changed before quiescence', 'initial inventory changed before staging', 'initial keyring endpoints reappeared', 'initial signed587 source inventory differs', 'initial-string', 'initial604 keyring checkpoint required', 'initialization-cache-parent-or-temp', 'initialization-deadline', 'initialization-helper-mount', 'initialization-helper-pin', 'initialization-root-shape', 'initialization-source-changed', 'initialization-unrelated-root-change', 'initialization-worker-failed', 'initialized-cache-metadata', 'input bytes differ', 'input file type/mode/size refused', 'installed directory/architecture differs', 'installed package identity missing', 'installed package ownership differs', 'installed payload differs', 'insufficient disposable transaction capacity', 'insufficient future transaction bytes/inodes', 'insufficient or unknown filesystem free inode count', 'internal hardlinks require one device', 'invalid aggregate accounting', 'invalid aggregate counter', 'invalid copy hardlink mode', 'invalid hardlink content', 'invalid hardlink group record', 'invalid hardlink membership', 'invalid hardlink metadata', 'invalid hardlink observation mode', 'invalid installed identity', 'invalid owned package name', 'invalid package identity', 'invalid package path', 'invalid projected symlink', 'invalid release identity', 'invalid root path encoding', 'invalid root path text', 'isolated public transaction keyring failed', 'isolated source/workspace mounts required', 'layout', 'libalpm ABI changed', 'libalpm binary changed', 'libalpm list bound', 'link-target', 'listing-bound', 'listing-directory', 'listing-drift', 'listing-identity', 'listing-mount', 'live transaction observation required', 'loaded package identity differs', 'magic', 'main-cache-content-changed', 'main-config-pin', 'malformed database field', 'mapped disposable Linux root required', 'mapped x86 Linux namespace required', 'marked native owned container required', 'measured precommit capacity insufficient', 'member changed during inventory', 'member file byte limit exceeded', 'missing complete tar end marker', 'missing-fakeroot-config', 'missing-fakeroot-directory', 'mount crossing refused', 'mount identity byte limit', 'mount identity inventory refused', 'mount identity unavailable', 'mount propagation is not private', 'named copy source drift', 'named entry drift', 'named node drift', 'named retained evidence metadata differs', 'named-map', 'named-node-drift', 'namespace metadata byte bound', 'native fixture suite failed', 'native libalpm pin differs', 'native profile admits inert fixture identities only', 'native receiver profile differs', 'native receiver source grant absent', 'native root container required', 'native source/phase selection differs', 'native tiny checks failed', 'network-isolated disposable caller required', 'network-none clean container required', 'network-none container required', 'new fixed evidence output required', 'no original scan difference', 'node depth limit', 'node parent path drift', 'node-or-mount-drift', 'noncanonical payload path', 'nonfinite JSON', 'nonnegative finite capacity demand required', 'nonselected database changed', 'observed directory differs', 'observed file content changed', 'observed file differs', 'observed node changed', 'observed node drift', 'observed node missing', 'observed seed required', 'observed symlink differs', 'observed-node-missing', 'observed-seed', 'one committed disposed-copy upgrade required', 'one exact public primary certificate required', 'one existing changed package required', 'one selected604 root package limit', 'one selected607 package default', 'one-shot copied-root initialization did not pass', 'only bounded gzip/xz fixture archives supported', 'only failed evidence may be revoked', 'only gzip/xz/zstd archives supported', 'only pinned x86 synthetic engine supported', 'only retained setup3→4 permitted', 'ordinary absolute source required', 'ordinary explicit parent required', 'ordinary mount file changed', 'ordinary mount file grew', 'ordinary mount file hardlink refused', 'ordinary mount file required', 'ordinary native ARM coordinator required', 'ordinary package descriptor required', 'ordinary tracked source required', 'original bundle drifted', 'original input bytes drifted', 'original input identity drifted', 'outer inventory changed during staging', 'outer source inventory changed during copied upgrade', 'overlapping copy roots', 'overlapping installed file ownership', 'overlapping installed ownership', 'owned cleanup depth limit', 'owned cleanup node limit', 'owned cleanup output required', 'owned cleanup parent drift', 'owned cleanup path or mount drift', 'owned container name required', 'owned container remains', 'owned copied root required', 'owned copy descriptor cleanup failed', 'owned copy disposal not confirmed', 'owned evidence file mode required', 'owned image remains', 'owned immutable image ID required', 'owned initial keyring agent endpoints remain', 'owned non-writable-by-others copy parent required', 'owned persistent payload absent', 'owned private copy parent required', 'owned private staging parent required', 'owned private volume required', 'owned private workspace required', 'owned seeded cache required', 'owned separate measurement volume required', 'owned source capsules pending disposal', 'owned workspace identity unavailable; retained', 'package descriptor bound', 'package downgrade refused', 'package identity refused', 'package inventory changed during copy', 'package inventory limit', 'package ownership bound', 'package payload overlap', 'package writes protected platform/trust path', 'package writes protected service', 'package-manager handle release failed', 'package-manager transaction lock release failed', 'packages committed but checkpoint durability uncertain', 'path depth limit', 'payload exceeds declared file size', 'payload hardlink marker refused', 'payload-touches-auxiliary-closure', 'pending evidence identity changed', 'persistent baseline changed after staging', 'persistent copy skipped special nodes', 'persistent directory changed', 'persistent directory drift', 'persistent directory mount crossing', 'persistent file byte limit', 'persistent file mount crossing', 'persistent hardlink alias limit', 'persistent hardlink drift', 'persistent hardlink group limit', 'persistent hardlink group not closed', 'persistent initial keyring/database changed', 'persistent named entry drift', 'persistent outer source preservation refused', 'persistent root path drift', 'persistent scope byte limit', 'persistent scope depth limit', 'persistent scope node limit', 'persistent source changed during materialization', 'persistent source changed during verification', 'persistent source coverage refused', 'persistent special node refused', 'persistent verification stage differs', 'pinned exact composition lock required', 'positive finite scale limit required', 'postcommit actual database differs', 'precommit-checkpoint-required', 'private authentication command failed', 'private container environment required', 'private directory ownership required', 'private key directory type refused', 'private key material refused', 'private libalpm initialize failed', 'private writable mounts missing', 'projected byte limit', 'projected depth limit', 'projected file byte limit', 'projected file content observation missing', 'projected input limit', 'projected node limit', 'projected node/byte bound', 'projected parent missing or not directory', 'protected delta refused', 'protected package absent', 'protected package file changed', 'protected payload changed after commit', 'protected payload changed before commit', 'public certificate inspection failed', 'public certificate must not contain secret key packets', 'public log bound', 'public result bound', 'read-bound', 'read-only actual package query failed', 'read-size', 'real candidate/unadopted inputs are not authorized by this initial worker', 'real committed durable update required', 'receipt bound', 'receipt changed while reading', 'recursive read-only barrier refused', 'regular source capsule required', 'release changed during snapshot', 'release exceeds tiny-root package limit', 'release selects protected platform package', 'remove identity differs or overlaps add', 'remove package absent', 'remove version differs', 'required protected unit names must be preserved', 'retained evidence inode changed', 'retained evidence inode required', 'retained evidence required', 'retained inherited evidence FD required', 'reviewed copied-root initialization API required before updater baseline', 'reviewed mount encoding required', 'root byte limit', 'root changed before commit', 'root changed while constructing TEST repository', 'root file byte limit', 'root identity drift', 'root mount drift', 'root node limit', 'root observation deadline', 'root observation required', 'root path byte limit', 'root path depth limit', 'root path drift', 'root path escapes observed root', 'root path node limit', 'root path parent is not directory', 'root path symlink cycle', 'root path symlink expansion limit', 'root path trace limit', 'root path work limit', 'root-changed-before-commit', 'runtime directory required', 'runtime or mount-file alias refused', 'sanitized test log bound', 'scale configuration changed', 'scan-alias', 'scan-byte-bound', 'scan-directory', 'scan-entry-bound', 'secret key material refused', 'secret key record refused', 'seed ownership outside namespace mapping', 'selected external helper bytes changed', 'selected generic fixture required', 'selected hardlink path touched', 'selected installed version differs from release baseline', 'selected native fixture profile required', 'selected native profile absent', 'selected old path missing', 'selected old removal missing', 'selected package removes actual protected ownership', 'selected package writes actual protected ownership', 'selected payload removal unsupported', 'selected release digest differs', 'selected release synthetic label or identity differs', 'selected root required', 'selected scope API origin differs', 'selected-data-endpoint-drift', 'selected-data-link-drift', 'selected-data-parent-shape', 'selected-link-endpoint-drift', 'selected-literal-link-drift', 'selected-payload-removal-unsupported', 'selected-root', 'selected-var-lock-data-shape', 'self-referential release refused', 'semantic release selection differs', 'separate TEST signer mount required', 'service IPC seccomp guard refused', 'setup-parent-metadata', 'setup-payload-path', 'signature signer/status refused', 'single-mount staged copy required', 'size', 'snapshot member bound exceeded', 'snapshot root changed during inventory', 'snapshot total byte bound exceeded', 'source capsule cleanup incomplete; ownership retained', 'source capsule close did not close owned descriptor', 'source capsule descriptor identity changed', 'source capsule identity unavailable; ownership retained', 'source capsule write made no progress', 'source directory content drift', 'source directory drift', 'source file drift', 'source mount table changed', 'source root drift', 'source/output/cache must be separate', 'sparse archive member refused', 'special filesystem node refused', 'special node refused', 'special snapshot member refused', 'stage must be outside persistent source data', 'stage parent changed or aliased', 'staged ownership coverage differs', 'staged package records differ', 'stale-or-unobserved-aux-key', 'strict-auxiliary-only-observation', 'string file reference path required', 'string-coverage', 'string-offset', 'string-termination', 'target-budget', 'target-parent', 'target-pin', 'temporary-cache', 'trailing or concatenated compressed frame refused', 'trailing or concatenated tar data refused', 'trial-copied-root', 'trial-root-workspace', 'truncated compressed frame', 'truncated member payload', 'typed original node maps', 'unaccounted removal', 'unambiguous mount table required', 'unaudited auxiliary executable or alias refused', 'unaudited auxiliary executable refused', 'unaudited auxiliary ldconfig alias refused', 'unaudited auxiliary ldconfig refused', 'unexcluded cross-device source', 'unexpected control member', 'unexpected exposed device', 'unexpected local database node', 'unexpected owned container query', 'unexpected secret-listing record', 'unexpected writable inherited mount', 'unexpected-node', 'unique package descriptor identity required', 'unknown fixture selection', 'unknown hardlink member', 'unowned evidence name refused', 'unrecognized source mount refused', 'unrelated root content changed', 'unrelated-root-content-changed', 'unsafe package database directory', 'unsafe package path', 'unselected-absolute-link', 'unselected-root-shape', 'unsupported local database version', 'unsupported or incomplete root observation', 'unsupported projected shape', 'unsupported scale ceilings', 'unsupported seccomp architecture', 'unsupported update operation', 'unsupported update operations', 'unsupported-link-chain', 'update configuration changed', 'updater-v2 baseline required', 'user files changed', 'verification mount table changed', 'verified initial587 inventory differs', 'verified selection differs', 'verified staged database differs', 'whole original cost copier source', 'whole original inner relative validator source', 'whole original lifetime source', 'whole original relative validator source', 'whole persistent observation API source', 'workspace required', 'xz archive incomplete/concatenated or oversized')

def _normal_primary_record(error, where, path=None):
    """Source literal reasons and relative names only; no content/locals dump."""
    try:
        import base64,hashlib
        def part(value):
            raw=value.encode('utf-8','surrogatepass')
            return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),prefix_base64=base64.b64encode(raw[:256]).decode(),prefix_bytes=min(len(raw),256),truncated=len(raw)>256)
        message=str(error);allowed=type(error) is ValueError and message in _NORMAL_REASON_LITERALS
        if path is None:
            trace=error.__traceback__
            while trace is not None:
                frame=trace.tb_frame
                if frame.f_code.co_name=='walk' and frame.f_code.co_filename.endswith(('/full_root.py','/persistent_scope.py')):
                    candidate=frame.f_locals.get('name',frame.f_locals.get('prefix'))
                    if type(candidate) is str:path=candidate
                trace=trace.tb_next
        valid=type(path) is str and not path.startswith('/') and '\0' not in path and all(x not in('.','..') for x in path.split('/'))
        value=dict(schema_version=1,status='NORMAL_PRIMARY_EXCEPTION_DATA_NOT_ACCEPTANCE',where=where,error_type=type(error).__name__[:64],message=part(message) if allowed else None,message_disposition='SOURCE_LITERAL_EXACT_OR_PREFIX' if allowed else 'UNREVIEWED_TEXT_OMITTED',path=part(path) if valid else None,path_disposition='OBSERVED_RELATIVE_NAME' if valid else 'UNKNOWN_OR_ABSOLUTE_OMITTED',cleanup_authority=False,transaction_authority=False)
        if len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())<=1800:return value
    except BaseException:pass
    return None

def _normal_primary_valid(value):
    try:
        import base64,hashlib
        keys={'schema_version','status','where','error_type','message','message_disposition','path','path_disposition','cleanup_authority','transaction_authority'}
        if type(value)is not dict or set(value)!=keys or type(value['schema_version'])is not int or value['schema_version']!=1 or value['status']!='NORMAL_PRIMARY_EXCEPTION_DATA_NOT_ACCEPTANCE' or value['cleanup_authority']is not False or value['transaction_authority']is not False:return False
        if value['where']not in ('NORMAL_ROOT_OBSERVATION','COPIED_ROOT_INITIALIZATION','DRIVER_CATCH','CALLER_SOURCE_WALK','CALLER_SOURCE_HARDLINKS','CALLER_CATCH','INITIALIZER_WORKER'):return False
        if type(value['error_type'])is not str or not 0<len(value['error_type'])<=64 or not value['error_type'].isascii() or not all(c.isalnum()or c=='_'for c in value['error_type']):return False
        for key in ('message','path'):
            row=value[key]
            if row is None:continue
            if type(row)is not dict or set(row)!={'bytes','sha256','prefix_base64','prefix_bytes','truncated'}:return False
            if type(row['bytes'])is not int or not 0<=row['bytes']<2**63 or type(row['prefix_bytes'])is not int or row['prefix_bytes']!=min(row['bytes'],256) or type(row['truncated'])is not bool or row['truncated']!=(row['bytes']>256):return False
            if type(row['sha256'])is not str or len(row['sha256'])!=64 or any(c not in '0123456789abcdef'for c in row['sha256'])or type(row['prefix_base64'])is not str:return False
            raw=base64.b64decode(row['prefix_base64'],validate=True)
            if len(raw)!=row['prefix_bytes'] or base64.b64encode(raw).decode()!=row['prefix_base64'] or (not row['truncated']and hashlib.sha256(raw).hexdigest()!=row['sha256']):return False
            if key=='message':
                expected=[]
                for literal in _NORMAL_REASON_LITERALS:
                    encoded=literal.encode('utf-8','surrogatepass')
                    expected.append(dict(bytes=len(encoded),sha256=hashlib.sha256(encoded).hexdigest(),prefix_base64=base64.b64encode(encoded[:256]).decode(),prefix_bytes=min(len(encoded),256),truncated=len(encoded)>256))
                if value['error_type']!='ValueError' or row not in expected:return False
            if key=='path'and (raw.startswith(b'/')or b'\0'in raw or any(x in(b'.',b'..')for x in raw.split(b'/'))):return False
        if value['message_disposition']!=('SOURCE_LITERAL_EXACT_OR_PREFIX'if value['message']is not None else'UNREVIEWED_TEXT_OMITTED')or value['path_disposition']!=('OBSERVED_RELATIVE_NAME'if value['path']is not None else'UNKNOWN_OR_ABSOLUTE_OMITTED'):return False
        return len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())<=1800
    except BaseException:return False

def _normal_worker_summary(value):
    try:
        keys={'status','returncode','termination','direct_child_reaped','stderr','primary','unframed_stderr','authority'}
        if type(value)is not dict or set(value)!=keys or value['status']!='ORIGINAL_INITIALIZER_WORKER_FAILURE_DATA_NOT_ACCEPTANCE'or value['unframed_stderr']!='OMITTED_NO_TRACEBACK_OR_CONTENT_EXPORT'or value['authority']!='DIAGNOSTIC_ONLY':return None
        if value['returncode']is not None and (type(value['returncode'])is not int or not -255<=value['returncode']<=255):return None
        if value['termination']not in (None,'timeout','output-limit','interrupted')or type(value['direct_child_reaped'])is not bool:return None
        row=value['stderr']
        if type(row)is not dict or set(row)!={'bytes','sha256'}or type(row['bytes'])is not int or not 0<=row['bytes']<=65536 or type(row['sha256'])is not str or len(row['sha256'])!=64 or any(c not in '0123456789abcdef'for c in row['sha256']):return None
        if value['primary']is not None and not _normal_primary_valid(value['primary']):return None
        return {key:val for key,val in value.items()if key!='primary'}
    except BaseException:return None


def need(ok, reason):
    if not ok: raise ValueError(reason)


def _apis(code):
    directory = Path(code) / 'scripts/update'
    sys.path.insert(0, str(directory))
    try:
        import full_root
        import measure_copy
        import root_path
    finally: sys.path.pop(0)
    path = Path(code) / 'scripts/ci/full-root-upgrade/root_upgrade.py'
    spec = importlib.util.spec_from_file_location('_persistent_scope_driver', path)
    driver = importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)
    need(Path(full_root.__file__).resolve() == (directory / 'full_root.py').resolve()
         and Path(measure_copy.__file__).resolve() == (directory / 'measure_copy.py').resolve()
         and Path(root_path.__file__).resolve() == (directory / 'root_path.py').resolve(),
         'selected scope API origin differs')
    return persistent_apis(full_root, measure_copy, root_path, driver)


def mounts(raw):
    need(type(raw) is str and len(raw.encode()) <= 1024**2, 'bounded mount table required')
    result = []
    for line in raw.splitlines():
        left, right = line.split(' - ', 1); fields, tail = left.split(), right.split()
        need(len(fields) >= 6 and len(tail) >= 3 and fields[0].isdigit()
             and fields[4].startswith('/') and '\\' not in fields[4], 'reviewed mount encoding required')
        result.append(dict(id=int(fields[0]), path=fields[4], fs=tail[0]))
    need(result and len({r['path'] for r in result}) == len(result), 'unambiguous mount table required')
    return result


def _mount_table():
    with Path('/proc/self/mountinfo').open('r') as stream: raw = stream.read(1024**2 + 1)
    need(len(raw.encode()) <= 1024**2, 'bounded mount table required')
    return raw


def mount_policy(source, target, rows):
    """Only literal container infrastructure and runtime submounts may be omitted."""
    def containing(path):
        hits = [r for r in rows if path == Path(r['path']) or path.is_relative_to(Path(r['path']))]
        need(hits, 'mount identity unavailable')
        return max(hits, key=lambda r: len(Path(r['path']).parts))
    source_mount, output = containing(source), containing(target.parent)
    need(output['fs'] not in NON_DISK, 'disk-backed persistent stage required')
    if target.is_relative_to(source):
        need(target.relative_to(source).parts[0] == 'measurement', 'stage must be outside persistent source data')
    selected = []
    for row in rows:
        point = Path(row['path'])
        if point == source or not point.is_relative_to(source): continue
        relative = point.relative_to(source).as_posix()
        first = relative.split('/')[0]
        need(first in RUNTIME or relative in INFRASTRUCTURE or relative in MOUNT_FILES,
             'unrecognized source mount refused')
        selected.append(relative)
    if source == Path('/'):
        need('upgrade-signing' in selected, 'separate TEST signer mount required')
        need(output['path'] == '/measurement' and output['id'] != source_mount['id'],
             'owned separate measurement volume required')
    return dict(source_mount=source_mount['id'], target_mount=output['id'],
                observed_mounts=sorted(selected))


@contextmanager
def _parent(roots, source, name, limits):
    """Nofollow parent traversal; final symlinks are read as literal data."""
    roots.installer.relative(name); fd = roots._open_root(source); held = [fd]
    try:
        for part in name.split('/')[:-1]:
            limits.tick()
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            held.append(fd)
        yield fd, name.split('/')[-1]
    finally:
        for fd in reversed(held): os.close(fd)


SOURCE_MANIFEST_HASH_PROFILE = 'SOURCE_MANIFEST_FD_HELD_ONCE_PER_INODE_V1'

def source_manifest(source, limits, roots, policy):
    """Fresh observation; each hardlink inode hash retains its exact FD locally."""
    nodes, groups, excluded = {}, {}, []
    total_bytes = 0
    hardlink_aliases = 0
    _normal_scope_path = ''
    source = Path(source)
    infrastructure = INFRASTRUCTURE & set(policy['observed_mounts'])
    def walk(fd, prefix='', depth=0):
        nonlocal total_bytes, _normal_scope_path, hardlink_aliases
        _normal_scope_path = prefix.rstrip('/')
        limits.tick(); need(depth <= limits.max_depth, 'persistent scope depth limit')
        initial = roots._identity(os.fstat(fd)); names = sorted(os.listdir(fd))
        need(roots._mount_id(fd, limits) == policy['source_mount'], 'persistent directory mount crossing')
        for leaf in names:
            _normal_scope_path = prefix + leaf
            limits.tick(); name = prefix + leaf
            roots.installer.relative(name)
            if name in infrastructure:
                excluded.append(name); continue
            info = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            node = dict(mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)
            need(len(nodes) < limits.max_nodes, 'persistent scope node limit')
            if stat.S_ISDIR(info.st_mode):
                node['type'] = 'directory'; nodes[name] = node
                if name in RUNTIME:
                    excluded.append(name + '/*')
                else:
                    child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        need(roots._identity(os.fstat(child)) == roots._identity(info), 'persistent directory drift')
                        walk(child, name + '/', depth + 1)
                    finally: os.close(child)
            elif stat.S_ISREG(info.st_mode):
                need(info.st_size <= limits.max_file_bytes, 'persistent file byte limit')
                total_bytes += info.st_size
                need(total_bytes <= limits.max_bytes, 'persistent scope byte limit')
                child = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                try:
                    need(name in MOUNT_FILES or roots._mount_id(child, limits) == policy['source_mount'],
                         'persistent file mount crossing')
                    if name in MOUNT_FILES: need(info.st_nlink == 1, 'ordinary mount file hardlink refused')
                    if info.st_nlink > 1:
                        need(hardlink_aliases < limits.max_hardlink_aliases,
                             'persistent hardlink alias limit')
                        need(2 <= info.st_nlink <= limits.max_hardlink_members,
                             'persistent hardlink group not closed')
                        inode = (info.st_dev, info.st_ino)
                        group = groups.get(inode)
                        if group is None:
                            need(len(groups) < limits.max_hardlink_groups, 'persistent hardlink group limit')
                            digest = roots._file_hash(child, info, limits)
                            group = dict(nlink=info.st_nlink, members=[], fd=child,
                                         identity=roots._identity(info), sha256=digest)
                            groups[inode] = group
                        else:
                            need(roots._identity(os.fstat(child)) == roots._identity(info)
                                 == group['identity'] == roots._identity(os.fstat(group['fd'])),
                                 'persistent hardlink identity drift')
                        need(group['nlink'] == info.st_nlink, 'persistent hardlink drift')
                        need(len(group['members']) < limits.max_hardlink_members,
                             'persistent hardlink group not closed')
                        hardlink_aliases += 1
                        group['members'].append(name)
                        node.update(type='file', bytes=info.st_size, sha256=group['sha256'])
                    else:
                        node.update(type='file', bytes=info.st_size, sha256=roots._file_hash(child, info, limits))
                finally:
                    # The inserted group owns its FD immediately, including async failure.
                    if groups.get((info.st_dev, info.st_ino), {}).get('fd') != child:
                        os.close(child)
                nodes[name] = node
            elif stat.S_ISLNK(info.st_mode):
                need(name not in RUNTIME and name not in MOUNT_FILES, 'runtime or mount-file alias refused')
                node.update(type='symlink', target=os.readlink(leaf, dir_fd=fd)); nodes[name] = node
            else: raise ValueError('persistent special node refused')
            need(name not in RUNTIME or node['type'] == 'directory', 'runtime directory required')
            _normal_scope_path = name
            need(roots._identity(os.stat(leaf, dir_fd=fd, follow_symlinks=False)) == roots._identity(info),
                 'persistent named entry drift')
        _normal_scope_path = prefix.rstrip('/')
        need(names == sorted(os.listdir(fd)) and roots._identity(os.fstat(fd)) == initial,
             'persistent directory changed')
    try:
        with _updater_phase('SOURCE_WALK'):
            fd = roots._open_root(source)
            try:
                initial = roots._identity(os.fstat(fd)); walk(fd)
                rebound = roots._open_root(source)
                try:
                    need(roots._identity(os.fstat(rebound)) == roots._identity(os.fstat(fd)) == initial
                         and roots._mount_id(rebound, limits) == policy['source_mount'], 'persistent root path drift')
                finally: os.close(rebound)
            except BaseException as error:
                try:error._normal_primary_failure = _normal_primary_record(error, 'CALLER_SOURCE_WALK', _normal_scope_path)
                except BaseException:pass
                raise
            finally: os.close(fd)
        with _updater_phase('SOURCE_HARDLINKS'):
            need(len(groups) <= limits.max_hardlink_groups, 'persistent hardlink group limit')
            aliases = 0
            for group in groups.values():
                limits.tick()
                need(roots._identity(os.fstat(group['fd'])) == group['identity']
                     and roots._mount_id(group['fd'], limits) == policy['source_mount'],
                     'persistent hardlink retained entry drift')
                members = sorted(group['members']); aliases += len(members)
                need(len(members) == group['nlink'] and len(members) <= limits.max_hardlink_members,
                     'persistent hardlink group not closed')
                for name in members: nodes[name]['hardlink_group'] = members[0]
            need(aliases <= limits.max_hardlink_aliases, 'persistent hardlink alias limit')
        return nodes, sorted(excluded)
    finally:
        # Close each original descriptor once, including failure paths; never retry.
        active = sys.exception()
        cleanup_error = None
        for group in groups.values():
            try: os.close(group['fd'])
            except BaseException as error:
                if cleanup_error is None: cleanup_error = error
        if cleanup_error is not None:
            if active is None: raise cleanup_error


def _restore_boundaries(source, target, nodes, roots, copier, limits):
    """Only empty runtime directory nodes and three literal ordinary files."""
    for name in sorted(RUNTIME & nodes.keys()):
        node = nodes[name]; path = target / name
        path.mkdir(mode=0o700)
        os.chown(path, node['uid'], node['gid']); os.chmod(path, node['mode'])
    for name in sorted(MOUNT_FILES & nodes.keys()):
        node = nodes[name]; need(node['type'] == 'file', 'ordinary mount file required')
        with _parent(roots, source, name, limits) as (old_parent, leaf), _parent(roots, target, name, limits) as (new_parent, _):
            old = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=old_parent)
            try:
                initial = roots._identity(os.fstat(old))
                new = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=new_parent)
                try:
                    total, digest = 0, hashlib.sha256()
                    while True:
                        limits.tick(); block = os.read(old, min(1024**2, node['bytes'] - total + 1))
                        if not block: break
                        total += len(block); need(total <= node['bytes'], 'ordinary mount file grew')
                        digest.update(block); copier._write(new, block, limits)
                    need(total == node['bytes'] and digest.hexdigest() == node['sha256']
                         and roots._identity(os.fstat(old)) == initial, 'ordinary mount file changed')
                    os.fchown(new, node['uid'], node['gid']); os.fchmod(new, node['mode'])
                finally: os.close(new)
            finally: os.close(old)


def owned_coverage(packages, nodes, resolver, limits):
    owners = {}
    for package in packages:
        for name in package['files']:
            limits.tick(); need(name not in owners, 'overlapping installed ownership')
            parent, _, leaf = name.rpartition('/')
            endpoint, _ = resolver.resolve(nodes, parent, limits=limits)
            actual = endpoint + '/' + leaf if endpoint else leaf
            need(actual in nodes and nodes[actual]['type'] != 'directory', 'owned persistent payload absent')
            owners[name] = package['name']
    return len(owners)


def _mount600(original):
    import ctypes
    import errno
    import os
    import sys
    # Linux statx UAPI: mask offset0, mnt_id offset144, fixed256-byte record.
    # Request ordinary STATX_MNT_ID, never the distinct MNT_ID_UNIQUE namespace.
    class Statx600(ctypes.Structure):
        _fields_=[('mask',ctypes.c_uint32),('prefix',ctypes.c_ubyte*140),
                  ('mnt_id',ctypes.c_uint64),('reserved',ctypes.c_ubyte*104)]
    supported=(sys.platform=='linux' and sys.byteorder=='little' and ctypes.sizeof(ctypes.c_void_p)==8 and
               os.uname().machine in ('aarch64','x86_64') and ctypes.sizeof(Statx600)==256 and Statx600.mnt_id.offset==144)
    libc=ctypes.CDLL(None,use_errno=True) if supported else None
    call=getattr(libc,'statx',None)
    if call is not None:
        call.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_uint,ctypes.POINTER(Statx600))
        call.restype=ctypes.c_int
    checked=False
    def query(descriptor,limits):
        nonlocal call,checked
        limits.tick()
        if call is None:return original(descriptor,limits)
        result=Statx600()
        if call(descriptor,b'',0x1000,0x1000,ctypes.byref(result))!=0:
            error=ctypes.get_errno()
            if error in (errno.ENOSYS,errno.EINVAL,errno.EOPNOTSUPP,errno.EPERM):
                call=None;return original(descriptor,limits)
            raise OSError(error,'descriptor statx mount query failed')
        if not result.mask&0x1000:
            call=None;return original(descriptor,limits)
        if not result.mnt_id:raise ValueError('descriptor statx mount identity unavailable')
        if not checked:
            if result.mnt_id!=original(descriptor,limits):raise ValueError('descriptor mount identity APIs differ')
            checked=True
        return result.mnt_id
    return query

def persistent_apis(roots,copier,resolver,driver):
    """Private APIs only; held walkers/copy/hash/check code and fresh FDs remain."""
    import types
    def held(module,size,digest):
        raw=Path(module.__file__).read_bytes()
        if module is roots:
            for added, original in ((b"        report['primary_failure'] = _normal_primary_record(error, 'NORMAL_ROOT_OBSERVATION', _normal_path)\n        # Existing refusal/counts unchanged; raw OS exception text omitted.", b'        # Fixed error text only; never emit raw OS exception/path diagnostics.'), (b"        _normal_path = ''\n        need(_identity(os.fstat(descriptor)) == _identity(root_info), 'root identity drift')", b"        need(_identity(os.fstat(descriptor)) == _identity(root_info), 'root identity drift')"), (b'        for name, node in nodes.items():\n            _normal_path = name\n            limits.tick()', b'        for name, node in nodes.items():\n            limits.tick()'), (b'            for name in members:\n                _normal_path = name\n                limits.tick()', b'            for name in members:\n                limits.tick()'), (b"    def validate_groups():\n        nonlocal _normal_path\n        _normal_path = ''\n        result = {}", b'    def validate_groups():\n        result = {}'), (b'            _normal_path = auxiliary\n            limits.tick()\n            try:\n                resolved=installer.resolve_nodes(nodes,auxiliary)', b'            limits.tick()\n            try:\n                resolved=installer.resolve_nodes(nodes,auxiliary)'), (b"        _normal_path = ''\n        for auxiliary in (", b'        for auxiliary in ('), (b"        for group in groups.values():\n            _normal_path = ''\n            limits.tick()", b'        for group in groups.values():\n            limits.tick()'), (b"        _normal_path = prefix.rstrip('/')\n        need(_identity(os.fstat(directory)) == _identity(before_directory), 'directory content drift')", b"        need(_identity(os.fstat(directory)) == _identity(before_directory), 'directory content drift')"), (b'                _normal_path = prefix + entry.name\n                need(_identity(os.stat(entry.name, dir_fd=directory, follow_symlinks=False))', b'                need(_identity(os.stat(entry.name, dir_fd=directory, follow_symlinks=False))'), (b'            for entry in entries:\n                _normal_path = prefix + entry.name\n                limits.tick()', b'            for entry in entries:\n                limits.tick()'), (b"        nonlocal aliases, _normal_path\n        _normal_path = prefix.rstrip('/')\n", b'        nonlocal aliases\n'), (b"    aliases = 0\n    _normal_path = ''\n", b'    aliases = 0\n'), (b'\n_NORMAL_REASON_LITERALS = (\'341-package inventory differs\', \'ALPM owned file count limit\', \'ALPM package inventory limit\', \'Docker overrides refused\', \'GPG_HOME_SOCKET_PATH_TOO_LONG\', \'Python compression.zstd is unavailable\', \'Root must freeze the complete actual87 literal link selection before dispatch\', \'absolute archive link refused\', \'absolute canonical scope paths required\', \'absolute contained copy paths required\', \'absolute contained root required\', \'absolute database root required\', \'absolute payload link\', \'absolute-comparator-source\', \'actual base trust differs from pinned configuration\', \'actual baseline differs from exact 604-package lock\', \'actual before/after inventory differs\', \'actual composition inventory required\', \'actual composition lock differs\', \'actual copied base differs from authenticated release\', \'actual namespace identity/map refused\', \'actual package-owned kernel modules required\', \'actual post-update lock differs\', \'actual protected platform packages absent\', \'actual reduced capabilities differ\', \'actual release requires explicit generic disposable update selection\', \'actual root is not initial signed604/updater-v2 checkpoint\', \'actual user-file baseline not exercised\', \'actual user-file baseline required before commit\', \'aggregate accounting exceeds limits\', \'aggregate compressed byte limit exceeded\', \'aggregate deadline exhausted\', \'aggregate decoded archive bound\', \'aggregate decoded archive byte bound\', \'aggregate decoded byte limit exceeded\', \'aggregate input bytes exceeded\', \'aggregate member limit exceeded\', \'aggregate owned file count limit\', \'aggregate package inputs exceed tiny-root limit\', \'aggregate package ownership bound\', \'ambient capability clearing refused\', \'ambiguous copy bind scope\', \'apps-directory-inode-links-size-metadata\', \'apps-directory-node-metadata\', \'apps-directory-scan-row\', \'apps604-selected-postcommit-only\', \'archive deadline exhausted\', \'archive exceeds tiny-root caller limit\', \'archive input changed during inspection\', \'archive node/sparse bound\', \'archive payload overlap\', \'archive special/hardlink member refused\', \'authenticated result changed\', \'authenticated snapshot drifted\', \'aux-changed-before-commit\', \'bare retained evidence directory required\', \'base pacman configuration/trust required\', \'base trust changed after commit\', \'base trust changed before commit\', \'boolean absolute path diagnostic required\', \'bootstrap started without immutable image ID\', \'bound evidence node identities required\', \'bound worker/runtime/evidence identity required\', \'bounded cleanup budgets required\', \'bounded command failed\', \'bounded declared release required\', \'bounded decoder read required\', \'bounded evidence file required\', \'bounded existing local database required\', \'bounded hardlink groups required\', \'bounded inventory/depth/diagnostics required\', \'bounded mount table required\', \'bounded ordinary database record required\', \'bounded ordinary source required\', \'bounded original node metadata\', \'bounded original observation reasons\', \'bounded original stage maps\', \'bounded owned package names required\', \'bounded path collection required\', \'bounded persistent stage diagnostic\', \'bounded receipt file required\', \'bounded regular reference required\', \'bounded scan diagnostic\', \'bounded scan maps\', \'bounded scan path\', \'bounded scan row\', \'bounded shape samples required\', \'bounded tracked source archive required\', \'bounded unique copied package inventory\', \'bundle has missing or undeclared members\', \'cache-file\', \'cache-parent\', \'canonical owned paths required\', \'canonical private path required\', \'canonical relative root query required\', \'canonical single-mount verification required\', \'capability bounding reduction refused\', \'capability reduction refused\', \'capacity check missing\', \'captured engine specification required\', \'captured runtime bytes differ\', \'captured worker launch required\', \'changed archive required\', \'changed copy source\', \'checkout differs from product\', \'clean standard command environment required\', \'closed add row required\', \'closed engine specification required\', \'closed namespace identity required\', \'closed transaction contract required\', \'closure-changed\', \'code source pin shape\', \'comparator-binding\', \'comparator-source-drift\', \'comparator-source-pin\', \'comparator-source-shape\', \'complete CLI arguments required\', \'complete byte-identical supplied-source copy required\', \'complete declared protected versions required\', \'complete driver commit truth required\', \'complete explicit code closure required\', \'complete generic fixture selection required\', \'complete persistent stage differs\', \'complete projected root required\', \'complete single-mount copy scope required\', \'complete-absolute-chain-set-differs\', \'complete-link-observation\', \'complete-observation\', \'complete-projected-root\', \'complete-selected-copy-scope\', \'complete604 lock required\', \'compressed archive size/type limit exceeded\', \'config-metadata\', \'consumed input byte bound\', \'contained declared repository alias required\', \'contained exclusions required\', \'copied baseline bytes changed\', \'copied package database differs from actual587 lock\', \'copier-source-pin-or-drift\', \'copier-source-shape\', \'copy anchor drift\', \'copy byte limit\', \'copy depth limit\', \'copy descriptor cleanup failed\', \'copy destination alias drift\', \'copy destination file mount drift\', \'copy destination mount drift\', \'copy destination nodes differ\', \'copy directory drift\', \'copy file byte limit\', \'copy metadata differs\', \'copy mount crossing\', \'copy node limit\', \'copy parent path drift\', \'copy parent rebound\', \'copy root path drift\', \'copy source alias drift\', \'copy source content drift\', \'copy source group differs\', \'copy source group drift\', \'copy source nodes changed\', \'copy source parent differs\', \'copy source parent drift\', \'copy source symlink drift\', \'copy write made no progress\', \'counts\', \'cross-device node\', \'cross-device node parent\', \'current evidence directory metadata differs\', \'current evidence namespace identity differs\', \'cyclic payload link\', \'database changed during observation\', \'database mount crossing refused\', \'database package directory changed\', \'database record absent from root observation\', \'database record changed\', \'database record differs from root observation\', \'database root alias refused\', \'database section absent\', \'declared full after map differs\', \'declared parent is not a directory\', \'declared release file differs\', \'declared repository alias differs\', \'decoded archive byte bound\', \'decoder window budget below gzip minimum\', \'descriptor mount identity APIs differ\', \'descriptor statx mount identity unavailable\', \'device identity refused\', \'directory changed during inventory\', \'directory content drift\', \'directory depth limit\', \'directory entry drift\', \'directory-shape\', \'disjoint-initialization-source\', \'disk-backed persistent stage required\', \'driver data/copy/source overlap refused\', \'driver exit/status disagreement\', \'duplicate ALPM package\', \'duplicate JSON key\', \'duplicate actual package\', \'duplicate add or signer refused\', \'duplicate database field\', \'duplicate database section\', \'duplicate hardlink membership\', \'duplicate installed ownership\', \'duplicate installed package\', \'duplicate inventory entry\', \'duplicate-key\', \'duplicate/nonroot archive member\', \'engine deadline refused\', \'engine receipt execution identity differs\', \'engine receipt refused\', \'escaped mount names require explicit review\', \'escaping existing filesystem link\', \'escaping payload link\', \'evidence byte bound\', \'evidence descriptor cleanup incomplete\', \'evidence descriptor lease replaced; foreign descriptor not closed\', \'evidence descriptor lease unavailable; cleanup refused\', \'evidence descriptor mount identity changed\', \'evidence descriptor mount identity missing\', \'evidence descriptor mount outside current namespace\', \'evidence directory identity refused\', \'evidence file changed\', \'evidence file identity refused\', \'evidence file pathname replaced\', \'evidence pathname identity differs\', \'evidence pathname replaced\', \'evidence view changed during validation\', \'exact caller configuration required\', \'exact external helper closure required\', \'exact file reference required\', \'exact finite scale budgets required\', \'exact initial signed604/updater-v2 inventory required\', \'exact input digest required\', \'exact inventory digest required\', \'exact inventory drift\', \'exact product commit required\', \'exact release record required\', \'exact repository selection required\', \'exact setup/updater-v2 lock required\', \'exact single prepared setup upgrade required\', \'exact updater-v2/setup4 scale required\', \'exact-apps5-to6-transition\', \'exact-apps6-authenticated-archive\', \'exact-apps604-after-lock-and-other603\', \'exact-apps604-before-lock\', \'exact-apps604-scale-locks\', \'exact-eight-apps6-files\', \'exclusive initial604 full-root route required\', \'existing ancestor escapes root\', \'existing bound/runtime update did not pass\', \'existing copied package database required\', \'existing external ephemeral TEST signer required\', \'existing package-manager lock refused\', \'existing suite case count differs\', \'expected post-update lock differs\', \'expected-length\', \'expected-record\', \'expected-string\', \'explicit TEST release declarations required\', \'explicit absolute driver paths required\', \'explicit actual updater-v2\xe2\x86\x92setup4 scale selection required\', \'explicit archive limits required\', \'explicit boolean release synthetic selection required\', \'explicit bound-update nonce required\', \'explicit comparator path required\', \'explicit disposable namespace/container required\', \'explicit disposable release configuration required\', \'explicit finite future capacity budget required\', \'explicit generic development policy required\', \'explicit generic development runtime required\', \'explicit generic development selection required\', \'explicit initial604 upgrade selection required\', \'explicit owned container marker required\', \'explicit platform mode required\', \'explicit release and platform configuration required\', \'explicit scaled disposable configuration required\', \'export database entry refused\', \'export duplicate package\', \'export local database absent\', \'export ownership outside mapping\', \'export package lock differs\', \'export package metadata incomplete\', \'export package ownership differs\', \'export protected ownership differs\', \'export protected payload differs\', \'export root ownership refused\', \'extended header byte limit exceeded\', \'external input changed\', \'externally pinned input differs\', \'failed receipt bound\', \'failed stage predicate only\', \'fakeroot-config\', \'fd-exec-unavailable\', \'file content drift\', \'file entry drift\', \'file grew during observation\', \'file-content\', \'file-list bound\', \'file-shape\', \'filesystem byte bound\', \'filesystem node bound\', \'finite absolute monotonic deadline required\', \'finite caller time budget required\', \'finite copy bounds required\', \'finite copy deadline required\', \'finite deadline required\', \'finite nonempty add set required\', \'finite original stage clock\', \'finite package map required\', \'finite positive limit required\', \'finite root path limits required\', \'finite source bytes required\', \'finite source capsule registry required\', \'finite timeout required\', \'finite total driver deadline required\', \'finite worker bounds required\', \'finite-source-link-selection\', \'fixed evidence filename required\', \'fresh disjoint stage required\', \'fresh driver data directory required\', \'fresh output required\', \'fresh private copy required\', \'full configuration digest required\', \'full supported primary signer required\', \'generic exact before/after locks differ\', \'generic fixture Source data differs\', \'generic fixture Source reference differs\', \'generic fixture VM data differs\', \'generic fixture duplicate proc field\', \'generic fixture exact VM contract required\', \'generic fixture fixed tool-profile data differs\', \'generic fixture fixed worker location required\', \'generic fixture input bytes changed\', \'generic fixture input reference refused\', \'generic fixture library profile differs\', \'generic fixture ordinary guest required\', \'generic fixture proc bound\', \'generic fixture protected file required\', \'generic fixture protected parent required\', \'generic fixture real guest marker required\', \'generic fixture tool alias differs\', \'generic fixture tool closure differs\', \'generic fixture worker/runtime pin differs\', \'generic fixture zero-capability NNP parent required\', \'generic kernel ownership changed\', \'generic kernels must be protected\', \'generic package-manager/runtime protection required\', \'generic policy changed\', \'generic policy phase refused\', \'generic policy/configuration locks differ\', \'generic protected package versions changed or absent\', \'generic protected selection differs from authenticated release\', \'growing copy source\', \'guarded engine did not complete\', \'guest device identity differs\', \'hardlink alias limit\', \'hardlink final drift\', \'hardlink group limit\', \'hardlink group not closed\', \'hardlink groups changed\', \'hardlink identity drift\', \'hardlink member changed\', \'hardlink member differs\', \'hardlink member limit\', \'hardlink named entry drift\', \'hardlink observation required\', \'hardlink or oversized file refused\', \'hardlink parent changed\', \'hardlink parent drift\', \'hardlink parent missing or redirected\', \'hardlink projection requires explicit mode\', \'hardlink retained entry drift\', \'hardlinked or oversized node\', \'header\', \'helper-alias\', \'helper-hardlink\', \'helper-pin\', \'hwcaps-child\', \'hwcaps-shape\', \'include-content\', \'include-directory\', \'include-file\', \'incomplete provisional receipt\', \'incomplete tar zero padding\', \'incomplete worker result\', \'independent engine specification pin required\', \'independently reviewed worker source pin required\', \'initial inventory changed before quiescence\', \'initial inventory changed before staging\', \'initial keyring endpoints reappeared\', \'initial signed587 source inventory differs\', \'initial-string\', \'initial604 keyring checkpoint required\', \'initialization-cache-parent-or-temp\', \'initialization-deadline\', \'initialization-helper-mount\', \'initialization-helper-pin\', \'initialization-root-shape\', \'initialization-source-changed\', \'initialization-unrelated-root-change\', \'initialization-worker-failed\', \'initialized-cache-metadata\', \'input bytes differ\', \'input file type/mode/size refused\', \'installed directory/architecture differs\', \'installed package identity missing\', \'installed package ownership differs\', \'installed payload differs\', \'insufficient disposable transaction capacity\', \'insufficient future transaction bytes/inodes\', \'insufficient or unknown filesystem free inode count\', \'internal hardlinks require one device\', \'invalid aggregate accounting\', \'invalid aggregate counter\', \'invalid copy hardlink mode\', \'invalid hardlink content\', \'invalid hardlink group record\', \'invalid hardlink membership\', \'invalid hardlink metadata\', \'invalid hardlink observation mode\', \'invalid installed identity\', \'invalid owned package name\', \'invalid package identity\', \'invalid package path\', \'invalid projected symlink\', \'invalid release identity\', \'invalid root path encoding\', \'invalid root path text\', \'isolated public transaction keyring failed\', \'isolated source/workspace mounts required\', \'layout\', \'libalpm ABI changed\', \'libalpm binary changed\', \'libalpm list bound\', \'link-target\', \'listing-bound\', \'listing-directory\', \'listing-drift\', \'listing-identity\', \'listing-mount\', \'live transaction observation required\', \'loaded package identity differs\', \'magic\', \'main-cache-content-changed\', \'main-config-pin\', \'malformed database field\', \'mapped disposable Linux root required\', \'mapped x86 Linux namespace required\', \'marked native owned container required\', \'measured precommit capacity insufficient\', \'member changed during inventory\', \'member file byte limit exceeded\', \'missing complete tar end marker\', \'missing-fakeroot-config\', \'missing-fakeroot-directory\', \'mount crossing refused\', \'mount identity byte limit\', \'mount identity inventory refused\', \'mount identity unavailable\', \'mount propagation is not private\', \'named copy source drift\', \'named entry drift\', \'named node drift\', \'named retained evidence metadata differs\', \'named-map\', \'named-node-drift\', \'namespace metadata byte bound\', \'native fixture suite failed\', \'native libalpm pin differs\', \'native profile admits inert fixture identities only\', \'native receiver profile differs\', \'native receiver source grant absent\', \'native root container required\', \'native source/phase selection differs\', \'native tiny checks failed\', \'network-isolated disposable caller required\', \'network-none clean container required\', \'network-none container required\', \'new fixed evidence output required\', \'no original scan difference\', \'node depth limit\', \'node parent path drift\', \'node-or-mount-drift\', \'noncanonical payload path\', \'nonfinite JSON\', \'nonnegative finite capacity demand required\', \'nonselected database changed\', \'observed directory differs\', \'observed file content changed\', \'observed file differs\', \'observed node changed\', \'observed node drift\', \'observed node missing\', \'observed seed required\', \'observed symlink differs\', \'observed-node-missing\', \'observed-seed\', \'one committed disposed-copy upgrade required\', \'one exact public primary certificate required\', \'one existing changed package required\', \'one selected604 root package limit\', \'one selected607 package default\', \'one-shot copied-root initialization did not pass\', \'only bounded gzip/xz fixture archives supported\', \'only failed evidence may be revoked\', \'only gzip/xz/zstd archives supported\', \'only pinned x86 synthetic engine supported\', \'only retained setup3\xe2\x86\x924 permitted\', \'ordinary absolute source required\', \'ordinary explicit parent required\', \'ordinary mount file changed\', \'ordinary mount file grew\', \'ordinary mount file hardlink refused\', \'ordinary mount file required\', \'ordinary native ARM coordinator required\', \'ordinary package descriptor required\', \'ordinary tracked source required\', \'original bundle drifted\', \'original input bytes drifted\', \'original input identity drifted\', \'outer inventory changed during staging\', \'outer source inventory changed during copied upgrade\', \'overlapping copy roots\', \'overlapping installed file ownership\', \'overlapping installed ownership\', \'owned cleanup depth limit\', \'owned cleanup node limit\', \'owned cleanup output required\', \'owned cleanup parent drift\', \'owned cleanup path or mount drift\', \'owned container name required\', \'owned container remains\', \'owned copied root required\', \'owned copy descriptor cleanup failed\', \'owned copy disposal not confirmed\', \'owned evidence file mode required\', \'owned image remains\', \'owned immutable image ID required\', \'owned initial keyring agent endpoints remain\', \'owned non-writable-by-others copy parent required\', \'owned persistent payload absent\', \'owned private copy parent required\', \'owned private staging parent required\', \'owned private volume required\', \'owned private workspace required\', \'owned seeded cache required\', \'owned separate measurement volume required\', \'owned source capsules pending disposal\', \'owned workspace identity unavailable; retained\', \'package descriptor bound\', \'package downgrade refused\', \'package identity refused\', \'package inventory changed during copy\', \'package inventory limit\', \'package ownership bound\', \'package payload overlap\', \'package writes protected platform/trust path\', \'package writes protected service\', \'package-manager handle release failed\', \'package-manager transaction lock release failed\', \'packages committed but checkpoint durability uncertain\', \'path depth limit\', \'payload exceeds declared file size\', \'payload hardlink marker refused\', \'payload-touches-auxiliary-closure\', \'pending evidence identity changed\', \'persistent baseline changed after staging\', \'persistent copy skipped special nodes\', \'persistent directory changed\', \'persistent directory drift\', \'persistent directory mount crossing\', \'persistent file byte limit\', \'persistent file mount crossing\', \'persistent hardlink alias limit\', \'persistent hardlink drift\', \'persistent hardlink group limit\', \'persistent hardlink group not closed\', \'persistent initial keyring/database changed\', \'persistent named entry drift\', \'persistent outer source preservation refused\', \'persistent root path drift\', \'persistent scope byte limit\', \'persistent scope depth limit\', \'persistent scope node limit\', \'persistent source changed during materialization\', \'persistent source changed during verification\', \'persistent source coverage refused\', \'persistent special node refused\', \'persistent verification stage differs\', \'pinned exact composition lock required\', \'positive finite scale limit required\', \'postcommit actual database differs\', \'precommit-checkpoint-required\', \'private authentication command failed\', \'private container environment required\', \'private directory ownership required\', \'private key directory type refused\', \'private key material refused\', \'private libalpm initialize failed\', \'private writable mounts missing\', \'projected byte limit\', \'projected depth limit\', \'projected file byte limit\', \'projected file content observation missing\', \'projected input limit\', \'projected node limit\', \'projected node/byte bound\', \'projected parent missing or not directory\', \'protected delta refused\', \'protected package absent\', \'protected package file changed\', \'protected payload changed after commit\', \'protected payload changed before commit\', \'public certificate inspection failed\', \'public certificate must not contain secret key packets\', \'public log bound\', \'public result bound\', \'read-bound\', \'read-only actual package query failed\', \'read-size\', \'real candidate/unadopted inputs are not authorized by this initial worker\', \'real committed durable update required\', \'receipt bound\', \'receipt changed while reading\', \'recursive read-only barrier refused\', \'regular source capsule required\', \'release changed during snapshot\', \'release exceeds tiny-root package limit\', \'release selects protected platform package\', \'remove identity differs or overlaps add\', \'remove package absent\', \'remove version differs\', \'required protected unit names must be preserved\', \'retained evidence inode changed\', \'retained evidence inode required\', \'retained evidence required\', \'retained inherited evidence FD required\', \'reviewed copied-root initialization API required before updater baseline\', \'reviewed mount encoding required\', \'root byte limit\', \'root changed before commit\', \'root changed while constructing TEST repository\', \'root file byte limit\', \'root identity drift\', \'root mount drift\', \'root node limit\', \'root observation deadline\', \'root observation required\', \'root path byte limit\', \'root path depth limit\', \'root path drift\', \'root path escapes observed root\', \'root path node limit\', \'root path parent is not directory\', \'root path symlink cycle\', \'root path symlink expansion limit\', \'root path trace limit\', \'root path work limit\', \'root-changed-before-commit\', \'runtime directory required\', \'runtime or mount-file alias refused\', \'sanitized test log bound\', \'scale configuration changed\', \'scan-alias\', \'scan-byte-bound\', \'scan-directory\', \'scan-entry-bound\', \'secret key material refused\', \'secret key record refused\', \'seed ownership outside namespace mapping\', \'selected external helper bytes changed\', \'selected generic fixture required\', \'selected hardlink path touched\', \'selected installed version differs from release baseline\', \'selected native fixture profile required\', \'selected native profile absent\', \'selected old path missing\', \'selected old removal missing\', \'selected package removes actual protected ownership\', \'selected package writes actual protected ownership\', \'selected payload removal unsupported\', \'selected release digest differs\', \'selected release synthetic label or identity differs\', \'selected root required\', \'selected scope API origin differs\', \'selected-data-endpoint-drift\', \'selected-data-link-drift\', \'selected-data-parent-shape\', \'selected-link-endpoint-drift\', \'selected-literal-link-drift\', \'selected-payload-removal-unsupported\', \'selected-root\', \'selected-var-lock-data-shape\', \'self-referential release refused\', \'semantic release selection differs\', \'separate TEST signer mount required\', \'service IPC seccomp guard refused\', \'setup-parent-metadata\', \'setup-payload-path\', \'signature signer/status refused\', \'single-mount staged copy required\', \'size\', \'snapshot member bound exceeded\', \'snapshot root changed during inventory\', \'snapshot total byte bound exceeded\', \'source capsule cleanup incomplete; ownership retained\', \'source capsule close did not close owned descriptor\', \'source capsule descriptor identity changed\', \'source capsule identity unavailable; ownership retained\', \'source capsule write made no progress\', \'source directory content drift\', \'source directory drift\', \'source file drift\', \'source mount table changed\', \'source root drift\', \'source/output/cache must be separate\', \'sparse archive member refused\', \'special filesystem node refused\', \'special node refused\', \'special snapshot member refused\', \'stage must be outside persistent source data\', \'stage parent changed or aliased\', \'staged ownership coverage differs\', \'staged package records differ\', \'stale-or-unobserved-aux-key\', \'strict-auxiliary-only-observation\', \'string file reference path required\', \'string-coverage\', \'string-offset\', \'string-termination\', \'target-budget\', \'target-parent\', \'target-pin\', \'temporary-cache\', \'trailing or concatenated compressed frame refused\', \'trailing or concatenated tar data refused\', \'trial-copied-root\', \'trial-root-workspace\', \'truncated compressed frame\', \'truncated member payload\', \'typed original node maps\', \'unaccounted removal\', \'unambiguous mount table required\', \'unaudited auxiliary executable or alias refused\', \'unaudited auxiliary executable refused\', \'unaudited auxiliary ldconfig alias refused\', \'unaudited auxiliary ldconfig refused\', \'unexcluded cross-device source\', \'unexpected control member\', \'unexpected exposed device\', \'unexpected local database node\', \'unexpected owned container query\', \'unexpected secret-listing record\', \'unexpected writable inherited mount\', \'unexpected-node\', \'unique package descriptor identity required\', \'unknown fixture selection\', \'unknown hardlink member\', \'unowned evidence name refused\', \'unrecognized source mount refused\', \'unrelated root content changed\', \'unrelated-root-content-changed\', \'unsafe package database directory\', \'unsafe package path\', \'unselected-absolute-link\', \'unselected-root-shape\', \'unsupported local database version\', \'unsupported or incomplete root observation\', \'unsupported projected shape\', \'unsupported scale ceilings\', \'unsupported seccomp architecture\', \'unsupported update operation\', \'unsupported update operations\', \'unsupported-link-chain\', \'update configuration changed\', \'updater-v2 baseline required\', \'user files changed\', \'verification mount table changed\', \'verified initial587 inventory differs\', \'verified selection differs\', \'verified staged database differs\', \'whole original cost copier source\', \'whole original inner relative validator source\', \'whole original lifetime source\', \'whole original relative validator source\', \'whole persistent observation API source\', \'workspace required\', \'xz archive incomplete/concatenated or oversized\')\n\ndef _normal_primary_record(error, where, path=None):\n    """Source literal reasons and relative names only; no content/locals dump."""\n    try:\n        import base64,hashlib\n        def part(value):\n            raw=value.encode(\'utf-8\',\'surrogatepass\')\n            return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),prefix_base64=base64.b64encode(raw[:256]).decode(),prefix_bytes=min(len(raw),256),truncated=len(raw)>256)\n        message=str(error);allowed=type(error) is ValueError and message in _NORMAL_REASON_LITERALS\n        if path is None:\n            trace=error.__traceback__\n            while trace is not None:\n                frame=trace.tb_frame\n                if frame.f_code.co_name==\'walk\' and frame.f_code.co_filename.endswith((\'/full_root.py\',\'/persistent_scope.py\')):\n                    candidate=frame.f_locals.get(\'name\',frame.f_locals.get(\'prefix\'))\n                    if type(candidate) is str:path=candidate\n                trace=trace.tb_next\n        valid=type(path) is str and not path.startswith(\'/\') and \'\\0\' not in path and all(x not in(\'.\',\'..\') for x in path.split(\'/\'))\n        value=dict(schema_version=1,status=\'NORMAL_PRIMARY_EXCEPTION_DATA_NOT_ACCEPTANCE\',where=where,error_type=type(error).__name__[:64],message=part(message) if allowed else None,message_disposition=\'SOURCE_LITERAL_EXACT_OR_PREFIX\' if allowed else \'UNREVIEWED_TEXT_OMITTED\',path=part(path) if valid else None,path_disposition=\'OBSERVED_RELATIVE_NAME\' if valid else \'UNKNOWN_OR_ABSOLUTE_OMITTED\',cleanup_authority=False,transaction_authority=False)\n        if len(json.dumps(value,sort_keys=True,separators=(\',\',\':\')).encode())<=1800:return value\n    except BaseException:pass\n    return None\n\ndef _normal_primary_valid(value):\n    try:\n        import base64,hashlib\n        keys={\'schema_version\',\'status\',\'where\',\'error_type\',\'message\',\'message_disposition\',\'path\',\'path_disposition\',\'cleanup_authority\',\'transaction_authority\'}\n        if type(value)is not dict or set(value)!=keys or type(value[\'schema_version\'])is not int or value[\'schema_version\']!=1 or value[\'status\']!=\'NORMAL_PRIMARY_EXCEPTION_DATA_NOT_ACCEPTANCE\' or value[\'cleanup_authority\']is not False or value[\'transaction_authority\']is not False:return False\n        if value[\'where\']not in (\'NORMAL_ROOT_OBSERVATION\',\'COPIED_ROOT_INITIALIZATION\',\'DRIVER_CATCH\',\'CALLER_SOURCE_WALK\',\'CALLER_SOURCE_HARDLINKS\',\'CALLER_CATCH\',\'INITIALIZER_WORKER\'):return False\n        if type(value[\'error_type\'])is not str or not 0<len(value[\'error_type\'])<=64 or not value[\'error_type\'].isascii() or not all(c.isalnum()or c==\'_\'for c in value[\'error_type\']):return False\n        for key in (\'message\',\'path\'):\n            row=value[key]\n            if row is None:continue\n            if type(row)is not dict or set(row)!={\'bytes\',\'sha256\',\'prefix_base64\',\'prefix_bytes\',\'truncated\'}:return False\n            if type(row[\'bytes\'])is not int or not 0<=row[\'bytes\']<2**63 or type(row[\'prefix_bytes\'])is not int or row[\'prefix_bytes\']!=min(row[\'bytes\'],256) or type(row[\'truncated\'])is not bool or row[\'truncated\']!=(row[\'bytes\']>256):return False\n            if type(row[\'sha256\'])is not str or len(row[\'sha256\'])!=64 or any(c not in \'0123456789abcdef\'for c in row[\'sha256\'])or type(row[\'prefix_base64\'])is not str:return False\n            raw=base64.b64decode(row[\'prefix_base64\'],validate=True)\n            if len(raw)!=row[\'prefix_bytes\'] or base64.b64encode(raw).decode()!=row[\'prefix_base64\'] or (not row[\'truncated\']and hashlib.sha256(raw).hexdigest()!=row[\'sha256\']):return False\n            if key==\'message\':\n                expected=[]\n                for literal in _NORMAL_REASON_LITERALS:\n                    encoded=literal.encode(\'utf-8\',\'surrogatepass\')\n                    expected.append(dict(bytes=len(encoded),sha256=hashlib.sha256(encoded).hexdigest(),prefix_base64=base64.b64encode(encoded[:256]).decode(),prefix_bytes=min(len(encoded),256),truncated=len(encoded)>256))\n                if value[\'error_type\']!=\'ValueError\' or row not in expected:return False\n            if key==\'path\'and (raw.startswith(b\'/\')or b\'\\0\'in raw or any(x in(b\'.\',b\'..\')for x in raw.split(b\'/\'))):return False\n        if value[\'message_disposition\']!=(\'SOURCE_LITERAL_EXACT_OR_PREFIX\'if value[\'message\']is not None else\'UNREVIEWED_TEXT_OMITTED\')or value[\'path_disposition\']!=(\'OBSERVED_RELATIVE_NAME\'if value[\'path\']is not None else\'UNKNOWN_OR_ABSOLUTE_OMITTED\'):return False\n        return len(json.dumps(value,sort_keys=True,separators=(\',\',\':\')).encode())<=1800\n    except BaseException:return False\n\ndef _normal_worker_summary(value):\n    try:\n        keys={\'status\',\'returncode\',\'termination\',\'direct_child_reaped\',\'stderr\',\'primary\',\'unframed_stderr\',\'authority\'}\n        if type(value)is not dict or set(value)!=keys or value[\'status\']!=\'ORIGINAL_INITIALIZER_WORKER_FAILURE_DATA_NOT_ACCEPTANCE\'or value[\'unframed_stderr\']!=\'OMITTED_NO_TRACEBACK_OR_CONTENT_EXPORT\'or value[\'authority\']!=\'DIAGNOSTIC_ONLY\':return None\n        if value[\'returncode\']is not None and (type(value[\'returncode\'])is not int or not -255<=value[\'returncode\']<=255):return None\n        if value[\'termination\']not in (None,\'timeout\',\'output-limit\',\'interrupted\')or type(value[\'direct_child_reaped\'])is not bool:return None\n        row=value[\'stderr\']\n        if type(row)is not dict or set(row)!={\'bytes\',\'sha256\'}or type(row[\'bytes\'])is not int or not 0<=row[\'bytes\']<=65536 or type(row[\'sha256\'])is not str or len(row[\'sha256\'])!=64 or any(c not in \'0123456789abcdef\'for c in row[\'sha256\']):return None\n        if value[\'primary\']is not None and not _normal_primary_valid(value[\'primary\']):return None\n        return {key:val for key,val in value.items()if key!=\'primary\'}\n    except BaseException:return None\n\n\ndef need(', b'\n\ndef need(')):
                need(raw.count(added)==1, 'one exact normal diagnostic inverse')
                raw=raw.replace(added,original,1)
        if module is roots and b'max_packages: int = 607' in raw:
            # Current604's exact selected source changes this sole typed default.
            # Reverse it before the existing whole original source proof; every
            # observation/copy/security predicate remains byte held.
            selected=b'max_packages: int = 607'
            need(raw.count(selected)==1,'one selected604 root package limit')
            raw=raw.replace(selected,b'max_packages: int = 587',1)
        need(len(raw)==size and hashlib.sha256(raw).hexdigest()==digest,'whole persistent observation API source')
    held(roots,35970,'cece1c597b2e2eb98b0e3087cc7e7c148b54332f8a1c4f18e04e4552a71fb51d')
    held(copier,25734,'e582245bd114b0b9d83f2de4fdc81a35d2f48493ba6147879871af794476813b')
    def clone(function,namespace):
        result=types.FunctionType(function.__code__,namespace,function.__name__,function.__defaults__,function.__closure__)
        result.__kwdefaults__=function.__kwdefaults__
        return result
    def relative_api(module,digest):
        import ast,os
        text=Path(module.__file__).read_text()
        nodes=[n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='relative']
        need(len(nodes)==1 and hashlib.sha256(ast.get_source_segment(text,nodes[0]).encode()).hexdigest()==digest,'whole original relative validator source')
        original=module.relative
        if os.name!='posix':return original
        def relative(value):
            # No filesystem/graph results or strings are retained. Canonical
            # positive POSIX components need no pathlib normalization; every
            # uncertain operand takes the entire unchanged original validator.
            if type(value)is str and value and '\0'not in value and all(p not in('','.','..')for p in value.split('/')):return value
            return original(value)
        return relative
    private_installer=types.SimpleNamespace(**vars(roots.installer))
    private_installer.relative=relative_api(roots.installer,'486c47ebbe2e6cfc392bde908003baf7559fd70d2f6ed17684f2ba34340fac41')
    private_roots=types.SimpleNamespace(**vars(roots))
    private_roots._mount_id=_mount600(roots._mount_id)
    private_roots.installer=private_installer
    private_roots.observe=clone(roots.observe,dict(roots.observe.__globals__,_mount_id=private_roots._mount_id,installer=private_installer))
    from contextlib import contextmanager
    copy_scope=dict(copier.copy_data.__globals__,roots=private_roots)
    for name in ('_parent','_root_check','_source_alias','_copy_internal','copy_data'):
        original=getattr(copier,name)
        copy_scope[name]=(contextmanager(clone(original.__wrapped__,copy_scope))
                          if name=='_parent' else clone(original,copy_scope))
    private_copier=types.SimpleNamespace(**copy_scope)
    private_driver=driver
    if driver is not None:
        private_driver=types.SimpleNamespace(**vars(driver))
        private_driver.relative=relative_api(driver,'382ec23738149e6f6ebb9a35d399f9a7e1366f6352ab7a2a64d734e3244f9ead')
        private_driver.database=clone(driver.database,dict(driver.database.__globals__,relative=private_driver.relative))
    return private_roots,private_copier,resolver,private_driver


def persistent_stage_failure(before, staged, limits):
    """Existing map DATA only. Equality and incomplete observation still refuse."""
    try:
        import math, time
        actual = staged['nodes']
        need(type(before) is dict and type(actual) is dict and max(len(before), len(actual)) <= 200000, 'bounded original stage maps')
        need(all(type(n) is str and type(v) is dict for rows in (before,actual) for n,v in rows.items()), 'typed original node maps')
        need(type(staged['complete']) is bool and not (staged['complete'] is True and actual == before), 'failed stage predicate only')
        common = before.keys() & actual.keys()
        changed = {n for n in common if before[n] != actual[n]}
        missing, extra = before.keys() - actual.keys(), actual.keys() - before.keys()
        examples = []
        def node_pin(value):
            raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
            need(len(raw) <= 32768, 'bounded original node metadata')
            return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        for name in sorted(changed | missing | extra)[:5]:
            old, new = before.get(name), actual.get(name)
            fields = sorted(k for k in (old or {}).keys() | (new or {}).keys() if (old or {}).get(k) != (new or {}).get(k))
            examples.append(dict(path=name[:256], path_truncated=len(name)>256, path_sha256=hashlib.sha256(name.encode()).hexdigest(), kind='changed' if name in changed else 'missing' if name in missing else 'extra', fields=[n[:64] for n in fields[:16]], fields_truncated=len(fields)>16, before=None if old is None else node_pin(old), after=None if new is None else node_pin(new)))
        reasons = staged['unsupported_counts']
        need(type(reasons) is dict and len(reasons) <= 64 and all(type(k) is str and type(v) is int and 0 < v <= 200000 for k,v in reasons.items()), 'bounded original observation reasons')
        remaining = limits.deadline - time.monotonic()
        need(math.isfinite(remaining), 'finite original stage clock')
        value = dict(schema_version=1, status='PERSISTENT_STAGE_FAILURE_DATA_NOT_ACCEPTANCE', observation_complete=staged['complete'], node_maps_equal=actual==before, comparison_scope='COMPLETE_MAPS' if staged['complete'] else 'PARTIAL_OBSERVATION_NOT_EVIDENCE_OF_SOURCE_DRIFT', expected_nodes=len(before), observed_nodes=len(actual), missing_nodes=len(missing), extra_nodes=len(extra), changed_nodes=len(changed), examples=examples, omitted_examples=max(0,len(changed|missing|extra)-len(examples)), unsupported_counts={k[:96]:v for k,v in sorted(reasons.items())[:8]}, unsupported_reasons_omitted=max(0,len(reasons)-8), stage_remaining_seconds=remaining, stage_deadline_exhausted=remaining<=0, cleanup_authority=False, acceptance_authority=False)
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
        need(len(raw.encode()) <= 6144, 'bounded persistent stage diagnostic')
        print('APPS6_PERSISTENT_STAGE_FAILURE '+raw, file=sys.stderr, flush=True)
    except Exception:
        pass  # Diagnostic loss never replaces the unchanged original refusal.


_UPDATER_PHASE_BYTES = 4096
_UPDATER_PHASE_LABELS = ('PATHS', 'APIS', 'PARENT', 'MOUNTS', 'SOURCE_BEFORE', 'SOURCE_DB', 'SELECTION', 'OWN_BEFORE', 'COPY', 'RESTORE', 'STAGED_OBSERVE', 'STAGED_EQUALITY', 'STAGED_DB', 'OWN_AFTER', 'SOURCE_AFTER', 'SOURCE_EQUALITY', 'MOUNT_EQUALITY', 'MANIFEST', 'SOURCE_WALK', 'SOURCE_HARDLINKS')

def _updater_phase_write(state, label):
    global _UPDATER_PHASE_BYTES
    if state not in ('BEGIN','END','FAIL') or label not in _UPDATER_PHASE_LABELS:
        return
    raw = ('UPDATER489_STAGE_PHASE '+state+' '+label+'\n').encode('ascii')
    if len(raw) > _UPDATER_PHASE_BYTES:
        return
    _UPDATER_PHASE_BYTES -= len(raw)
    try:
        os.write(2, raw)
    except OSError:
        pass

@contextmanager
def _updater_phase(label):
    _updater_phase_write('BEGIN', label)
    try:
        yield
    except BaseException as error:
        if label in ('SOURCE_WALK','SOURCE_HARDLINKS'):
            try:error._normal_primary_failure = getattr(error, '_normal_primary_failure', None) or _normal_primary_record(error, 'CALLER_'+label)
            except BaseException:pass
        _updater_phase_write('FAIL', label)
        raise
    else:
        _updater_phase_write('END', label)


def materialize(source: Path, target: Path, code: Path, limits):
    """Return PASS only for complete persistent coverage, before any update actor."""
    with _updater_phase('PATHS'):
        source, target, code = Path(source), Path(target), Path(code)
        need(source.is_absolute() and target.is_absolute() and code.is_absolute()
             and '..' not in source.parts + target.parts + code.parts, 'absolute canonical scope paths required')
        need(not source.is_relative_to(target) and not target.exists() and not target.is_symlink(), 'fresh disjoint stage required')
        need(not limits.allow_cross_device, 'single-mount staged copy required')
        parent = target.parent.stat()
        need(parent.st_uid == os.geteuid() and not stat.S_IMODE(parent.st_mode) & 0o077,
             'owned private staging parent required')
    with _updater_phase('APIS'):
        roots, copier, resolver, driver = _apis(code)
    with _updater_phase('PARENT'):
        fd = roots._open_root(target.parent)
        try:
            need(roots._identity(os.fstat(fd)) == roots._identity(parent), 'stage parent changed or aliased')
        finally: os.close(fd)
    with _updater_phase('MOUNTS'):
        raw = _mount_table()
        policy = mount_policy(source, target, mounts(raw))
    with _updater_phase('SOURCE_BEFORE'):
        before, excluded = source_manifest(source, limits, roots, policy)
    with _updater_phase('SOURCE_DB'):
        packages = driver.database(source, max_packages=limits.max_packages, max_files=limits.max_package_files,
                                   max_nodes=limits.max_nodes, observed=before)
    with _updater_phase('SELECTION'):
        expected, _ = driver.selection(code)
        need({p['name']: p['version'] for p in packages} == expected, 'initial signed587 source inventory differs')
    with _updater_phase('OWN_BEFORE'):
        owned = owned_coverage(packages, before, resolver, limits)
    with _updater_phase('COPY'):
        report = copier.copy_data(source, target, limits=limits,
            excluded=RUNTIME | (INFRASTRUCTURE & set(policy['observed_mounts'])) | MOUNT_FILES, absolute_paths=True)
        need(not report['unsupported_counts'], 'persistent copy skipped special nodes')
    with _updater_phase('RESTORE'):
        _restore_boundaries(source, target, before, roots, copier, limits)
    with _updater_phase('STAGED_OBSERVE'):
        staged = roots.observe(target, limits=limits, hardlinks='generic-development-internal', absolute_paths=True)
    with _updater_phase('STAGED_EQUALITY'):
        try:
            need(staged['complete'] is True and staged['nodes'] == before, 'complete persistent stage differs')
        except ValueError:
            persistent_stage_failure(before, staged, limits)
            raise
    with _updater_phase('STAGED_DB'):
        need(driver.database(target, max_packages=limits.max_packages, max_files=limits.max_package_files,
                             max_nodes=limits.max_nodes, observed=staged['nodes']) == packages, 'staged package records differ')
    with _updater_phase('OWN_AFTER'):
        need(owned_coverage(packages, staged['nodes'], resolver, limits) == owned, 'staged ownership coverage differs')
    with _updater_phase('SOURCE_AFTER'):
        after, final_excluded = source_manifest(source, limits, roots, policy)
    with _updater_phase('SOURCE_EQUALITY'):
        need(after == before and final_excluded == excluded, 'persistent source changed during materialization')
    with _updater_phase('MOUNT_EQUALITY'):
        need(mounts(_mount_table()) == mounts(raw), 'source mount table changed')
    with _updater_phase('MANIFEST'):
        digest = hashlib.sha256(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        return dict(status='PASS', scope='complete-persistent-data-materialization',
            whole_container_root=False, whole_root_copy=False, excluded=excluded,
            runtime_directories='PRESERVED_EMPTY', ordinary_mount_files=sorted(MOUNT_FILES & before.keys()),
            source_nodes=len(before), source_manifest_sha256=digest, source_inventory_count=len(packages),
            package_owned_nondirectory_paths=owned, source_preserved=True, persistent_nodes_identical=True,
            staged_single_mount=True, stage_ready_for_selected_copy=True,
            copy=report, mount_scope=policy, update_eligibility='NOT ESTABLISHED',
            copied_metadata='contents, modes, UID/GID, literal symlinks, closed internal hardlinks; xattrs/timestamps omitted',
            consistency='bounded per-file identity and before/after node equality; not an atomic snapshot',
            transaction_acceptance='NOT ESTABLISHED', hardware='NOT RUN')


def verify(source: Path, stage: Path, code: Path, limits):
    """Reobserve both unchanged baselines; caller must also match initial digest."""
    source, stage, code = Path(source), Path(stage), Path(code)
    need(source.is_absolute() and stage.is_absolute() and code.is_absolute()
         and '..' not in source.parts + stage.parts + code.parts and not limits.allow_cross_device,
         'canonical single-mount verification required')
    roots, _copier, resolver, driver = _apis(code)
    raw = _mount_table()
    policy = mount_policy(source, stage, mounts(raw))
    before, excluded = source_manifest(source, limits, roots, policy)
    observation = roots.observe(stage, limits=limits, hardlinks='generic-development-internal', absolute_paths=True)
    need(observation['complete'] is True and observation['nodes'] == before, 'persistent verification stage differs')
    packages = driver.database(source, max_packages=limits.max_packages, max_files=limits.max_package_files,
                               max_nodes=limits.max_nodes, observed=before)
    expected, _ = driver.selection(code)
    need({p['name']: p['version'] for p in packages} == expected, 'verified initial587 inventory differs')
    need(driver.database(stage, max_packages=limits.max_packages, max_files=limits.max_package_files,
                         max_nodes=limits.max_nodes, observed=observation['nodes']) == packages,
         'verified staged database differs')
    owned = owned_coverage(packages, before, resolver, limits)
    after, final_excluded = source_manifest(source, limits, roots, policy)
    need(after == before and final_excluded == excluded, 'persistent source changed during verification')
    need(mounts(_mount_table()) == mounts(raw), 'verification mount table changed')
    digest = hashlib.sha256(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return dict(status='PASS', whole_container_root=False, source_preserved=True,
        persistent_nodes_identical=True, source_manifest_sha256=digest, excluded=excluded,
        source_nodes=len(before), source_inventory_count=len(packages), package_owned_nondirectory_paths=owned,
        initial_digest_match='CALLER MUST CHECK', transaction_acceptance='NOT ESTABLISHED', hardware='NOT RUN')

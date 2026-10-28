#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One declared copied-root cache initialization, before any update baseline."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import aux_checkpoint as aux
import full_root as roots
import measure_copy as copy
import scale_update as scale
import supervision

CACHES = {aux.MAIN_CACHE, aux.AUX_CACHE}

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

def _normal_worker_failure(row):
    """Exact original helper capture; only our fixed framed diagnostic is decoded."""
    try:
        raw=row['stderr']
        if type(raw)is not bytes or len(raw)>65536:return None
        prefix=b'UPDATER607_INITIALIZER_PRIMARY '
        lines=[line[len(prefix):] for line in raw.splitlines() if line.startswith(prefix)]
        details=None
        if len(lines)==1 and len(lines[0])<=1800:
            value=json.loads(lines[0])
            if _normal_primary_valid(value):details=value
        return dict(status='ORIGINAL_INITIALIZER_WORKER_FAILURE_DATA_NOT_ACCEPTANCE',returncode=row.get('returncode'),termination=row.get('termination'),direct_child_reaped=row.get('direct_child_reaped'),stderr=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),primary=details,unframed_stderr='OMITTED_NO_TRACEBACK_OR_CONTENT_EXPORT',authority='DIAGNOSTIC_ONLY')
    except BaseException:return None


def observe(root, limits):
    value = roots.observe(root, limits=limits, hardlinks='generic-development-internal')
    try:
        aux.need(value['complete'] is True and set(value['unsupported_counts']) <= {'absolute-symlink','auxiliary-present'}, 'initialization-root-shape')
    except BaseException as error:
        error._normal_primary_failure = value.get('primary_failure')
        raise
    return value


def limits_from(config):
    value = config['limits']
    return roots.Limits(deadline=time.monotonic()+value['seconds'],max_nodes=value['root_nodes'],
        max_bytes=value['root_bytes'],max_file_bytes=value['file_bytes'],max_package_files=value['package_files'])


def exec_helper(root, workspace):
    """Worker only: pin static ELF, chroot through retained FD, then exec by FD."""
    scale.bound.guard(root, workspace)
    aux.need(os.execve in os.supports_fd, 'fd-exec-unavailable')
    limits = roots.Limits(deadline=time.monotonic()+150)
    observation = observe(root, limits)
    aux.checkpoint(root, observation, limits)  # Includes exact helper/config/scan closure.
    rootfd = roots._open_root(root)
    helper = None
    try:
        root_id, mount = roots._identity(os.fstat(rootfd)), roots._mount_id(rootfd, limits)
        with copy._parent(rootfd, aux.HELPER_NODE, mount, {}, limits, observation['nodes']) as (parent, base):
            helper = os.open(base, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            info = os.fstat(helper)
            aux.need(info.st_nlink == 1 and info.st_size == aux.HELPER[1]
                     and roots._file_hash(helper,info,limits) == aux.HELPER[0], 'initialization-helper-pin')
            copy._metadata_equal(info, observation['nodes'][aux.HELPER_NODE])
            aux.need(roots._mount_id(helper,limits) == mount, 'initialization-helper-mount')
        copy._root_check(root,rootfd,root_id,mount,limits)
        # No -r fallback: failure to chroot is terminal. No source-root FD is open.
        os.fchdir(rootfd); os.chroot('.'); os.chdir('/')
        os.close(rootfd); rootfd = None
        os.execve(helper, ['/usr/bin/ldconfig'], {'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','HOME':'/','TMPDIR':'/tmp'})
    finally:
        if helper is not None: os.close(helper)
        if rootfd is not None: os.close(rootfd)


def initialize(args, source, *, comparator_path):
    """Source is the complete supplied pre-copy tree, never a command target."""
    result = dict(status='FAIL',phase='configuration',initialization_started=False,root_initialized=False,
        source_preserved='NOT CHECKED',copy_byte_identical_after_initialization=False,
        transaction_acceptance='NOT ESTABLISHED',hardware='NOT RUN')
    original = None
    try:
        root,workspace,source = Path(args.root),Path(args.workspace),Path(source)
        scale.bound.guard(root,workspace)
        aux.need(source.is_absolute() and not root.is_relative_to(source) and not source.is_relative_to(workspace), 'disjoint-initialization-source')
        config = scale.configuration(args.scale,args.scale_sha256); limits = limits_from(config)
        comparator = aux.load_comparator(comparator_path,limits)
        original = observe(source,limits)
        result['phase'] = 'before-initialization'
        before = observe(root,limits); old = aux.checkpoint(root,before,limits)
        # One exclusive marker prevents a failed/unknown attempt from being retried.
        with copy._descriptors() as held:
            fd = roots._open_root(workspace); held.append(fd)
            marker = os.open('aux-initialization-started',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd); held.append(marker)
        result.update(phase='initialization-worker',initialization_started=True,root_initialized='UNKNOWN')
        remaining = limits.deadline-time.monotonic(); aux.need(remaining > 0,'initialization-deadline')
        row = supervision.run([sys.executable,'-B',str(Path(__file__).absolute()),'--worker','--root',str(root),'--workspace',str(workspace)],
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','HOME':str(workspace),'TMPDIR':str(workspace),
                 'PYTHONDONTWRITEBYTECODE':'1','CACHY_ASAHI_BOUND_UPDATE':os.environ.get('CACHY_ASAHI_BOUND_UPDATE','')},
            cwd=str(workspace),timeout=min(180,remaining),output_limit=65536)
        result['helper_exit_status'] = 0 if row['termination'] is None and row['returncode'] == 0 else 'NOT OBSERVED'
        result['worker'] = {key:row[key] for key in ('returncode','termination','direct_child_reaped','group_kill_sent')}
        if not (row['termination'] is None and row['returncode'] == 0 and row['direct_child_reaped'] is True):
            result['initializer_worker_failure'] = _normal_worker_failure(row)
            if result['initializer_worker_failure'] is not None:
                result['primary_failure'] = result['initializer_worker_failure']['primary']
        aux.need(row['termination'] is None and row['returncode'] == 0 and row['direct_child_reaped'] is True,'initialization-worker-failed')
        result['phase'] = 'after-initialization'
        after = observe(root,limits); new = aux.checkpoint(root,after,limits)
        aux.need({k:v for k,v in before['nodes'].items() if k not in CACHES}
                 == {k:v for k,v in after['nodes'].items() if k not in CACHES}
                 and before['hardlink_groups'] == after['hardlink_groups'],'initialization-unrelated-root-change')
        # Only generated cache bytes/size/inodes may differ in this preparation.
        for name,mode in ((aux.MAIN_CACHE,0o644),(aux.AUX_CACHE,0o600)):
            node = new['caches'][name]['node']
            aux.need(node['type']=='file' and (node['uid'],node['gid'],node['mode'])==(0,0,mode),'initialized-cache-metadata')
        for field in ('helper','configs','aliases','scan','targets','closure','scan_directories'):
            aux.need(old[field] == new[field],'initialization-'+field+'-changed')
        # Cache parent inode/metadata and both temporary absences stay fixed.
        for name in set(old['caches'])-CACHES:
            aux.need(old['caches'][name] == new['caches'][name],'initialization-cache-parent-or-temp')
        result.update(status='PASS',phase='completed',root_initialized=True,helper_exit_status=0,
            scope='one-copied-root-cache-initialization-before-update-baseline',
            cache_hashes={name:dict(before=old['caches'][name]['node']['sha256'],after=new['caches'][name]['node']['sha256']) for name in sorted(CACHES)},
            live_cache_keys=aux.live_keys(new,comparator))
    except BaseException as error:
        result['primary_failure'] = result.get('primary_failure') or getattr(error, '_normal_primary_failure', None) or _normal_primary_record(error, 'COPIED_ROOT_INITIALIZATION')
        result.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:256])
    finally:
        if original is not None:
            try:
                current = observe(source,limits)
                result['source_preserved'] = (original['nodes']==current['nodes'] and original['hardlink_groups']==current['hardlink_groups'])
                aux.need(result['source_preserved'],'initialization-source-changed')
            except BaseException as error:
                if result['source_preserved'] == 'NOT CHECKED': result['source_preserved'] = 'UNKNOWN'
                result.update(status='FAIL',source_check_error=type(error).__name__)
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--worker',action='store_true',required=True)
    parser.add_argument('--root',type=Path,required=True); parser.add_argument('--workspace',type=Path,required=True)
    args=parser.parse_args()
    try:exec_helper(args.root,args.workspace)
    except BaseException as error:
        try:
            value=getattr(error, '_normal_primary_failure', None) or _normal_primary_record(error, 'INITIALIZER_WORKER')
            if value is not None:
                raw=('UPDATER607_INITIALIZER_PRIMARY '+json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
                if len(raw)<=1900:os.write(2,raw)
        except BaseException:pass
        raise

#!/usr/bin/env python3
"""Verify a finite recipe/source evidence plan. Never run publisher code or fetch inputs."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import resource
import tomllib

resource.setrlimit(resource.RLIMIT_AS, (128 * 1024**2, 128 * 1024**2))
HERE = Path(__file__).resolve().parent
COMMIT = 'b940084d7eb6a299eb4bfeb8e34901bc051e7ac4'
PINS_SHA256 = 'f6619c5de9a25c9d69fc022047dc6ac30671b3f60bc545a0e317fdf0da2b8591'
ORIGINAL_RECIPES = {
    'rust': 'ef3fac9176e2a3698314d616e56d88b2df64d057ee7e9dfa13c98eb980a345fa',
    'compiler-rt': 'a08be2c30265ea1dcf95931d8e03f08dd5ff90e1cc1f092bd659f2687aa5d06c',
    'llvm/llvm-libs': '7c6a21c0d9b125e981011016635541c970552776caa52b58c88b61d32feee5c9',
    'lld': '96344e325a4cb35f32f316a36e3e23507abb8b0c3ffe1c4b615f7f804fc9fb06',
}

def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_bytes())


def verify_inputs():
    pins = HERE / 'records/pins.json'
    if sha(pins.read_bytes()) != PINS_SHA256:
        raise ValueError('evidence manifest changed')
    for name, expected in read_json(pins).items():
        path = HERE / name
        if HERE not in path.resolve().parents or sha(path.read_bytes()) != expected:
            raise ValueError(f'evidence changed: {name}')
    for name, expected in read_json(HERE / 'records/inputs.json').items():
        path = HERE.parent / name
        if sha(path.read_bytes()) != expected:
            raise ValueError(f'parent input changed: {name}')
    # Retained full metadata can be verified against original Git blob OIDs offline.
    for entry in read_json(HERE / 'records/source-files.json'):
        data = (HERE / entry['retained_path']).read_bytes()
        if entry['retention'].startswith('FULL_'):
            oid = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            if oid != entry['oid'] or sha(data) != entry['sha256']:
                raise ValueError(f'Git blob identity changed: {entry["alias"]}')


def recipe_config():
    # Delimit and parse the literal TOML body as data; no shell substitution.
    text = (HERE.parent / 'recipes/rust.PKGBUILD').read_text()
    body = text.split('  cat >bootstrap.toml <<END\n', 1)[1].split('\nEND\n', 1)[0]
    explicit = tomllib.loads(body)
    profile = tomllib.loads((HERE / 'sources/profile.txt').read_text())
    result = copy.deepcopy(profile)
    for key, value in explicit.items():
        if isinstance(value, dict):
            result.setdefault(key, {}).update(value)
        else:
            result[key] = value
    return result


def classify(config, rows):
    """Reviewed rules for this install path, not a general Rust bootstrap interpreter."""
    tools = config['build']['tools']
    extended = config['build']['extended']
    backend = config['rust'].get('codegen-backends', ['llvm'])
    result = []
    for source in rows:
        row = {k: source[k] for k in ['path', 'gitlink_commit', 'archive_regular_members_under_path']}
        path = row['path']
        if path.startswith('src/doc/'):
            status = 'REQUIRED_IF_DOCS_ENABLED' if config['build']['docs'] else 'NOT_SELECTED_DOCS_DISABLED'
            reason = 'Install Docs predicate is build.docs; rustdoc executable is a separate compiler component.'
        elif path == 'src/tools/cargo':
            status = 'ACTIVE_ARCHIVE_PATHS_OBSERVED' if extended and 'cargo' in tools else 'NOT_SELECTED_TOOL'
            reason = 'Install Cargo selects the Cargo workspace; 2949 regular archive members observed, payload identity still held.'
        elif path == 'library/backtrace':
            status = 'ACTIVE_ARCHIVE_PATHS_OBSERVED'
            reason = 'Bootstrap startup requires backtrace; std includes its source; 101 regular archive members observed.'
        elif path == 'src/llvm-project':
            external = config['target']['aarch64-unknown-linux-gnu'].get('llvm-config')
            status = 'REPLACED_EXTERNAL_LLVM_SOURCE_STILL_REQUIRED' if external else 'RUST_LLVM_SOURCE_REQUIRED'
            reason = 'prepare replaces this fork with llvm-project 23.1.1 source; llvm-config avoids LLVM rebuild, not compiler-rt/libunwind source use.'
        elif path == 'src/tools/rustc-perf':
            status = 'NOT_SELECTED_INSTALL_PATH'
            reason = 'Install step list does not select RustcPerf/OptimizedDist; rust-src invokes library-only Vendor, bypassing general vendor workspace list.'
        elif path == 'src/tools/enzyme':
            status = 'REQUIRED_IF_ENZYME_ENABLED' if config['llvm'].get('enzyme', False) else 'NOT_SELECTED_ENZYME_DISABLED'
            reason = 'llvm.enzyme defaults false; compile/LLVM Enzyme steps are conditional.'
        elif path == 'src/gcc':
            status = 'MISSING_PAYLOAD_IF_GCC_BACKEND_SELECTED' if 'gcc' in backend else 'NOT_SELECTED_LLVM_BACKEND'
            reason = 'Default backend is llvm; download-ci-gcc=false alone does not disable GCC. At least 45 direct root files missing if GCC source is needed.'
        else:
            raise ValueError(f'unreviewed submodule: {path}')
        row.update(classification=status, reason=reason, exact_payload_and_license_completeness='HELD')
        result.append(row)
    if len(result) != 12:
        raise ValueError('expected twelve source identities')
    return result


def make_plan():
    verify_inputs()
    config = recipe_config()
    old = read_json(HERE.parent / 'submodule-closure/report.json')
    ledger = read_json(HERE / 'records/request-ledger.json')
    requests = ledger['requests']
    query_hashes = {sha(p.read_bytes()) for p in (HERE / 'records').glob('*query.graphql')}
    if query_hashes != {r['query_sha256'] for r in requests}:
        raise ValueError('request/query provenance mismatch')
    if any(r['url'] != 'https://api.github.com/graphql' or r['method'] != 'POST_READ_ONLY_QUERY' or r['status'] != 'RECEIVED' for r in requests):
        raise ValueError('unexpected collection operation')
    total = sum(x['bytes'] for x in requests)
    if len(requests) > 12 or total > 4 * 1024**2 or old['rust_commit'] != COMMIT:
        raise ValueError('scope/pin changed')
    return {
        'schema': 1, 'status': 'PROPOSED_RECIPE_SOURCE_PLAN_ONLY', 'rust_commit': COMMIT,
        'source_audited_not_built': True,
        'original_binary_recipe_correspondence': {k: {'original_sha256': v, 'status': 'UNRESOLVED'} for k, v in ORIGINAL_RECIPES.items()},
        'effective_config_literal_shell_variables_unexpanded': config,
        'install_trace': {
            'command': 'DESTDIR="$srcdir/dest-rust" python ./x.py install -j $jobs',
            'stage': 2, 'default_backend': 'llvm',
            'selected_install_components': ['rustc', 'std', 'cargo', 'clippy', 'rustfmt', 'src'],
            'bundled_with_rustc': ['rustdoc', 'rust-analyzer-proc-macro-srv'],
            'analysis': 'Requested tool string has no standalone Install step. Dist Analysis is a removed-component placeholder, not evidence of installed save-analysis output.',
            'source_mode_requirement': 'Preserve release git-commit-info and no .git; bootstrap then treats it as tarball and avoids automatic submodule updates. Archive stamp not checked here.',
        },
        'submodules': classify(config, old['submodules']),
        'required_external_llvm': {
            'version': '23.1.1', 'llvm_config': '/usr/bin/llvm-config',
            'source_paths': ['src/llvm-project/compiler-rt', 'src/llvm-project/libunwind'],
            'consumers': ['profiler=true, no prebuilt profiler path', 'stable optimized-compiler-builtins defaults BuildLLVMFuncs for aarch64', 'rust-src copies libunwind'],
            'source_archive_member_and_license_closure': 'HELD',
            'fork_and_release_identity': 'Rust gitlink is rust-lang fork; prepare intentionally substitutes distinct llvm/llvm-project release. No identity equivalence claimed.',
        },
        'bootstrap': {
            'configured': {'rustc': '/usr/bin/rustc', 'cargo': '/usr/bin/cargo', 'rustfmt': '/usr/bin/rustfmt', 'implicit_rustdoc': '/usr/bin/rustdoc'},
            'sysroot': 'Read from initial rustc --print sysroot; std and sysroot libraries must match the pinned initial compiler and AArch64 host.',
            'python_stage0_download': 'Configured /usr/bin rustc/cargo do not satisfy bin_root prefix test, so this fallback download branch is not selected.',
            'fallback_stage0_metadata': {'compiler_version': '1.98.0', 'compiler_date': '2026-08-20', 'compiler_git_commit_hash': '88d9e12ae178fab0fb5cc050a94da85685d449ea'},
            'initial_provider_versions_bytes_arch_and_compatibility': 'UNPINNED_UNTESTED',
            'patch_0003': 'Old lib sysroot copy preimage observed at compile.rs:821. Patch application and resulting behavior NOT_TESTED.',
        },
        'network': {
            'rustc_ci': 'Disabled by dist download-rustc=false',
            'llvm_ci': 'Disabled explicitly', 'gcc_ci': 'Disabled explicitly',
            'bootstrap_and_normal_cargo': 'locked-deps=true appends --locked; vendor=true appends --frozen. Correct source replacement config and complete vendored payload required.',
            'rust_src_vendor': 'Runs initial cargo vendor --versioned-dirs --respect-source-config --config <src>/library/.cargo/config.toml with RUSTC_BOOTSTRAP=1 and initial RUSTC; only_library_workspace=true skips general vendor workspace/submodule list. No explicit --frozen/--offline here.',
            'offline_build_proof': 'NOT_ESTABLISHED: no Cargo execution, network sandbox, source-config/payload closure or environment audit',
        },
        'lock_declaration_cross_check': read_json(HERE / 'records/archive-cross-check.json'),
        'next_inputs': [
            'Review an explicit AArch64 recipe derivation: raw PKGBUILD arch is x86_64; SRCINFO lists extra architectures/packages/patches absent from it. Do not merge them as a recovered original.',
            'Pin compatible initial AArch64 rustc/cargo/rustdoc/rustfmt plus sysroot/std; verify bytes, versions and bootstrap compatibility, not just unversioned makedepends=rust.',
            'Pin AArch64 LLVM/clang/lld/compiler-rt 23.1.1 binaries and native build/link dependencies; check LLVM config/version/features and source provider compatibility.',
            'Verify consumed archive bootstrap/root/Cargo/library manifests/locks, git-commit-info, root and library Cargo config, vendor payload/checksum files and applicable licenses. Git library/.cargo/config.toml lookup was null; release archive membership remains unexamined.',
            'Verify compiler-rt and libunwind member coverage and notices in substituted LLVM archive, rather than fetching the unused Rust LLVM fork.',
            'Check all six retained patches against exact source and review applicability/output; only patch 0003 preimage was inspected here.',
            'Freeze ambient Cargo/bootstrap inputs and source mode, then design a bounded no-network build; do not infer offline behavior from download flags alone.',
        ],
        'limits_and_actual_work': {'metadata_requests': len(requests), 'response_bytes': total, 'memory_limit_bytes': 128 * 1024**2, 'archive_scans': 0, 'source_checkouts': 0, 'publisher_code_executions': 0, 'builds': 0, 'installations': 0},
        'native_ARM_M2_16K_performance_release': 'NOT_TESTED_OR_ADMITTED',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='write only this directory/report.json')
    args = parser.parse_args()
    output = (json.dumps(make_plan(), indent=2, sort_keys=True) + '\n').encode()
    path = HERE / 'report.json'
    if args.write:
        path.write_bytes(output)
    elif path.read_bytes() != output:
        raise ValueError('report differs; review then regenerate with --write')
    print('PASS: pinned evidence and deterministic source plan; build/offline/license/binary correspondence held')


if __name__ == '__main__':
    main()

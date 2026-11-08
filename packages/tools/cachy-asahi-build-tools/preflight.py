#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check reviewed recipe/source-plan/cache binding without starting a builder."""
import argparse
import hashlib
import json
from pathlib import Path
import signal
import sys

ROOT = Path(__file__).resolve().parents[3]


def check(recipe_path, plan_path, plan_sha256, catalog_path, cache_path, *, repo_root=None):
    root = ROOT if repo_root is None else Path(repo_root)
    sys.path.insert(0, str(root / 'scripts/build'))
    sys.path.insert(0, str(root / 'scripts/checks'))
    import source_materials
    from package_checks import recipe

    report = recipe(Path(recipe_path) / 'PKGBUILD')
    source_materials.need(not report['errors'], 'recipe static validation failed')
    prepared = source_materials.prepare(report, plan_path, plan_sha256, catalog_path, cache_path)
    # Existing validator checks every remote input, recipe pin, license notice,
    # cached object and receipt; this command adds no acquisition/staging path.
    return dict(schema_version=1, status='VERIFIED_OFFLINE_SOURCE_BINDING_ONLY',
                plan_sha256=hashlib.sha256(prepared['plan_raw']).hexdigest(),
                catalog_sha256=prepared['plan']['catalog_sha256'],
                recipe_inputs=report['input_sha256'],
                sources=[dict(id=item['record']['material']['id'], filename=item['filename'],
                              revision=item['record']['revision'],
                              bytes=item['record']['material']['bytes'],
                              sha256=item['record']['material']['sha256'])
                         for item in prepared['selected']],
                network_fetches=0, cache_writes=False, extraction=False,
                source_execution=False, builder_started=False,
                build_status='NOT RUN', hardware_status='NOT RUN',
                legal_acceptance=False, source_completeness_accepted=False)


def main(argv=None, *, repo_root=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('recipe', 'source-plan', 'source-catalog', 'source-cache'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--source-plan-sha256', required=True)
    args = parser.parse_args(argv)
    if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
        parser.error('an existing real-time alarm must not be replaced')
    previous = signal.getsignal(signal.SIGALRM)
    def expired(signum, frame):
        raise ValueError('offline source preflight exceeded120seconds')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 120)
    try:
        result = check(args.recipe, args.source_plan, args.source_plan_sha256,
                       args.source_catalog, args.source_cache, repo_root=repo_root)
    except (OSError, ValueError, KeyError):
        print(json.dumps(dict(status='REFUSED_OFFLINE_SOURCE_BINDING', network_fetches=0,
                              cache_writes=False, builder_started=False)))
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

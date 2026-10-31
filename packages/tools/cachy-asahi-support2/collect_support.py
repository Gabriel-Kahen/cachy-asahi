#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Collect current read-only Doctor/session observations and a local sanitized bundle."""
import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import signal
import sys
from types import SimpleNamespace, ModuleType


def load_bundle():
    path = next(p / 'scripts/support/support_bundle.py' for p in Path(__file__).resolve().parents
                if (p / 'scripts/support/support_bundle.py').is_file())
    module = ModuleType('collection_bundle')
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


def doctor_runner(session):
    """Keep Doctor2's exact argv/env contract; use the custody-aware query API."""
    def run(argv, seconds, bus=None, *, audio=None):
        env = dict(PATH='/usr/bin:/bin', LC_ALL='C', SYSTEMD_PAGER='', SYSTEMD_COLORS='0')
        if bus:
            env.update(XDG_RUNTIME_DIR=str(Path(bus).parent), DBUS_SESSION_BUS_ADDRESS='unix:path=' + bus)
        if audio:
            env.update(XDG_RUNTIME_DIR=audio, PIPEWIRE_RUNTIME_DIR=audio, PIPEWIRE_REMOTE='pipewire-0',
                       XDG_CONFIG_HOME='/nonexistent', XDG_CONFIG_DIRS='/etc/xdg',
                       WIREPLUMBER_CONFIG_DIR='/usr/share/wireplumber')
        reason, code, out, err = session.query(argv, seconds, env)
        # These reasons describe a completed transport. Doctor2 validates the
        # exit code/stdout/stderr itself (pacman exit 1 includes known absences).
        complete = reason in ('observed', 'query-warning', 'query-failed', 'query-denied') and code is not None
        state = 'checked' if complete and len(out) + len(err) <= 65536 else 'unavailable' if reason == 'command-absent' else 'unknown'
        return state, code, out, err
    return run


def write_private(bundle, directory, name, raw, *, replace=False):
    """Durable private receipt updates, anchored to an ordinary directory."""
    fd = bundle.directory_fd(directory)
    temporary = name + '.pending'
    made = False
    try:
        target = temporary if replace else name
        out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        made = True
        with os.fdopen(out, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        if replace:
            os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
            made = False
        os.fsync(fd)
    finally:
        if replace and made:
            os.unlink(temporary, dir_fd=fd)
        os.close(fd)


def collect(args, bundle=None):
    bundle = bundle or load_bundle()
    identity = dict(release_id=args.release_id, release_sha256=bundle.hex_value(args.release_sha256),
                    source_commit=bundle.hex_value(args.source_commit, (40, 64)))
    bundle.require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+-]{0,95}', args.release_id))
    session, session_pin = bundle.load_current('scripts/hardware/session_probe.py', 'collection_session')
    doctor, doctor_pin = bundle.load_current('packages/tools/cachy-asahi-doctor2/cachy-asahi-doctor', 'collection_doctor')
    if args.baseline_sha256:
        bundle.hex_value(args.baseline_sha256)
    health_raw = None
    if args.reviewed_health:
        health_path, health_sha = args.reviewed_health
        health_raw = bundle.read_file(health_path)
        bundle.require(bundle.digest(health_raw) == bundle.hex_value(health_sha))
        bundle.health_projection(bundle.decode(health_raw), identity)
    receipt = dict(schema_version=1, tool='cachy-asahi-support-collection', status='COLLECTING',
                   started_utc=datetime.now(timezone.utc).isoformat(), release=identity, inputs={},
                   implementation_dependencies=dict(doctor=doctor_pin, session=session_pin,
                       support_bundle=bundle.pin(bundle.read_file(bundle.__file__)),
                       collector=bundle.pin(bundle.read_file(__file__))),
                   limitations='Local observations only; release identity is operator supplied. No upload, repair, acceptance or health verdict.')
    if health_raw is not None:
        receipt['inputs']['health'] = bundle.pin(health_raw)
    instructions = ("PRIVATE collection directory. doctor.private.json and session.private.json are original reports.\n"
                    "Do not share this whole directory. Only share/support-bundle.tar is sanitized.\n"
                    "Verify and extract the archive with support_bundle.py using the archive SHA256 in collection.json.\n"
                    "Review extracted summary.txt and reports before manually sharing. No upload was performed.\n")
    bundle.publish(args.output_dir, {'collection.json': bundle.encoded(receipt), 'README.txt': instructions.encode()})
    output = Path(os.path.abspath(args.output_dir))
    stage = 'doctor'
    try:
        report = doctor.collect(run=doctor_runner(session))
        doctor.validate_report(report)
        raw = bundle.encoded(report)
        write_private(bundle, output, 'doctor.private.json', raw)
        receipt['inputs']['doctor'] = bundle.pin(raw)
        write_private(bundle, output, 'collection.json', bundle.encoded(receipt), replace=True)
        stage = 'session'
        report = session.collect(dict(declared_model_id=args.model_id, source_revision=args.source_commit,
            baseline_sha256=args.baseline_sha256, execution_context=args.execution_context))
        bundle.session_projection(report, session, identity)
        raw = bundle.encoded(report)
        write_private(bundle, output, 'session.private.json', raw)
        receipt['inputs']['session'] = bundle.pin(raw)
        write_private(bundle, output, 'collection.json', bundle.encoded(receipt), replace=True)
        stage = 'bundle'
        if health_raw is not None:
            bundle.require(bundle.read_file(args.reviewed_health[0]) == health_raw)
        # Refuse source drift between collection and publication.
        for module, expected in ((session, session_pin), (doctor, doctor_pin)):
            bundle.require(bundle.pin(bundle.read_file(module.__file__)) == {k: expected[k] for k in ('bytes', 'sha256')})
        for path, expected in ((bundle.__file__, receipt['implementation_dependencies']['support_bundle']),
                               (__file__, receipt['implementation_dependencies']['collector'])):
            bundle.require(bundle.pin(bundle.read_file(path)) == expected)
        result = bundle.create(SimpleNamespace(**identity, output_dir=str(output / 'share'),
            doctor=[str(output / 'doctor.private.json'), receipt['inputs']['doctor']['sha256']],
            session=[str(output / 'session.private.json'), receipt['inputs']['session']['sha256']],
            health=args.reviewed_health, doctor_before=None, doctor_after=None, doctor_comparison=None))
        bundle.verify(SimpleNamespace(archive=str(output / 'share/support-bundle.tar'), sha256=result['sha256'], extract_to=None))
        receipt.update(status='CREATED', archive=result, archive_path='share/support-bundle.tar')
    except BaseException as error:
        receipt.update(status='INTERRUPTED' if isinstance(error, KeyboardInterrupt) else 'FAILED', failed_stage=stage)
        raise
    finally:
        receipt['finished_utc'] = datetime.now(timezone.utc).isoformat()
        write_private(bundle, output, 'collection.json', bundle.encoded(receipt), replace=True)
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog='Return 0 means a bundle was created, not that observations passed. Review share/ before sharing.')
    for flag in ('release-id', 'release-sha256', 'source-commit', 'output-dir'):
        parser.add_argument('--' + flag, required=True)
    parser.add_argument('--reviewed-health', nargs=2, metavar=('JSON', 'SHA256'), help='Optional existing health report selected by exact digest; never run health automatically')
    parser.add_argument('--model-id', choices=('apple,j413', 'apple,j415'))
    parser.add_argument('--baseline-sha256')
    parser.add_argument('--execution-context', choices=('physical', 'virtual', 'emulated', 'unknown'), default='unknown')
    args = parser.parse_args(argv)
    def interrupt(*_):
        raise KeyboardInterrupt()
    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        result = collect(args)
        print('CREATED share/support-bundle.tar SHA256=' + result['archive']['sha256'])
        print('Review the sanitized archive before sharing; keep private originals local. No acceptance verdict.')
        return 0
    except KeyboardInterrupt:
        print('support collection: interrupted; inspect private collection.json if output was created', file=sys.stderr)
        return 130
    except Exception:
        print('support collection: refused or failed; inspect private collection.json if output was created; no report contents echoed', file=sys.stderr)
        return 2
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == '__main__':
    raise SystemExit(main())
